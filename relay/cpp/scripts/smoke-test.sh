#!/usr/bin/env bash
# End-to-end check of a built relay: two nodes, both protocols, the dead drop,
# invite codes, the wss->ws bridge and a two-hop onion route.
#
#   ./scripts/smoke-test.sh [path/to/build]
#
# Uses ports 18787/18788 and 19787/19788 so it never touches a live 8787/8788.
#
# The two relays need not be the same program. RELAY_A and RELAY_B override the
# binary for each node, so a cross-compiled build (under qemu) or a port of the
# relay in another language can be checked against the reference build:
#
#   RELAY_B=dist/r2r-relay-aarch64 ./scripts/smoke-test.sh build
#   RELAY_B=/path/to/r2r-relay-go  ./scripts/smoke-test.sh build
#
# KEEP=1 leaves the workspace (relay logs included) behind for inspection.
#
# Node B is the one that dials A, answers the bridge test and carries the
# second onion hop, so a port sitting there is exercised as both a peer and a
# storage node. Swap the two to test it as the node clients talk to.
set -uo pipefail

BUILD="${1:-build}"
RELAY="$BUILD/r2r-relay"
PROBE="$BUILD/r2r-probe"
RELAY_A="${RELAY_A:-$RELAY}"
RELAY_B="${RELAY_B:-$RELAY}"
WORK="$(mktemp -d /tmp/r2r-smoke.XXXXXX)"
A_WS=18787; A_WSS=18788
B_WS=19787; B_WSS=19788
A_PID=""; B_PID=""
PASS=0; FAIL=0

cleanup() {
    [ -n "$A_PID" ] && kill "$A_PID" 2>/dev/null
    [ -n "$B_PID" ] && kill "$B_PID" 2>/dev/null
    [ -n "${C_PID:-}" ] && kill "$C_PID" 2>/dev/null
    [ -n "${D_PID:-}" ] && kill "$D_PID" 2>/dev/null
    # The relays checkpoint SQLite on the way out; removing the workspace while
    # they are still writing leaves the directory non-empty.
    for _ in $(seq 1 20); do
        kill -0 "$A_PID" 2>/dev/null || kill -0 "$B_PID" 2>/dev/null || break
        sleep 0.25
    done
    if [ "${KEEP:-0}" = "1" ]; then echo "logs kept in $WORK"; else rm -rf "$WORK"; fi
}
trap cleanup EXIT

ok()   { PASS=$((PASS+1)); printf '  \033[32mok\033[0m   %s\n' "$1"; }
bad()  { FAIL=$((FAIL+1)); printf '  \033[31mFAIL\033[0m %s\n' "$1"; [ $# -gt 1 ] && printf '       %s\n' "$2"; }
check() { # check <description> <expected-substring> <actual>
    if printf '%s' "$3" | grep -qF -- "$2"; then ok "$1"; else bad "$1" "expected to find '$2' in: $(printf '%s' "$3" | head -c 300)"; fi
}

for f in "$RELAY" "$PROBE" "$RELAY_A" "$RELAY_B"; do
    [ -x "$f" ] || { echo "missing $f -- build first"; exit 1; }
done

echo "R2R smoke test"
echo "workspace: $WORK"
[ "$RELAY_A" != "$RELAY" ] && echo "relay A: $RELAY_A"
[ "$RELAY_B" != "$RELAY" ] && echo "relay B: $RELAY_B"

# --- TLS material -----------------------------------------------------------
mkdir -p "$WORK/a/tls" "$WORK/b/tls"
openssl req -x509 -newkey rsa:2048 -sha256 -days 1 -nodes \
    -keyout "$WORK/a/tls/key.pem" -out "$WORK/a/tls/cert.pem" \
    -subj "/CN=r2r-smoke" >/dev/null 2>&1
cp "$WORK/a/tls"/*.pem "$WORK/b/tls/"

# B starts already knowing A, so the two link without waiting for gossip.
printf '{"version":1,"peers":[{"address":"127.0.0.1:%s","tls":false}]}\n' "$A_WS" > "$WORK/b/peers.json"

mkdir -p "$WORK/a/assets"
printf 'r2r-client-v1.0.0 (test payload)\n' > "$WORK/a/assets/client.bin"

start_relay() { # start_relay <binary> <dir> <ws> <wss> <dial-target>
    local bin="$1"; shift
    "$bin" --data-dir "$1" --ws-port "$2" --wss-port "$3" \
        --cert "$1/tls/cert.pem" --key "$1/tls/key.pem" \
        --advertise "127.0.0.1:$2" --peer-dial-target "$4" \
        --allow-private-peers --assets "$1/assets" \
        --log-level debug > "$1/relay.log" 2>&1 &
    echo $!
}

wait_for_health() { # wait_for_health <port>
    for _ in $(seq 1 40); do
        curl -sf "http://127.0.0.1:$1/health" >/dev/null 2>&1 && return 0
        sleep 0.25
    done
    return 1
}

# A comes up first and is confirmed listening before B starts. B dials A the
# moment it boots; if A were not accepting yet that dial would fail and B would
# sit out its 15-second retry backoff before trying again.
A_PID=$(start_relay "$RELAY_A" "$WORK/a" "$A_WS" "$A_WSS" 0)
wait_for_health "$A_WS" || { echo "relay A never became healthy"; exit 1; }
B_PID=$(start_relay "$RELAY_B" "$WORK/b" "$B_WS" "$B_WSS" 1)
wait_for_health "$B_WS" || { echo "relay B never became healthy"; exit 1; }

echo
echo "HTTP surface"
check "landing page renders"        "R2R relay"       "$(curl -s http://127.0.0.1:$A_WS/)"
check "peers.json seeded"           "92.113.147.233"  "$(curl -s http://127.0.0.1:$A_WS/peers.json)"
check "node.json exposes x25519"    "x25519"          "$(curl -s http://127.0.0.1:$A_WS/node.json)"
check "status.json over TLS"        "node_id"         "$(curl -sk https://127.0.0.1:$A_WSS/status.json)"
check "robots.txt disallows all"    "Disallow: /"     "$(curl -s http://127.0.0.1:$A_WS/robots.txt)"
check "unknown route 404s"          "not_found"       "$(curl -s http://127.0.0.1:$A_WS/nope)"

echo
echo "Asset distribution"
EXPECT_SHA=$(sha256sum "$WORK/a/assets/client.bin" | cut -d' ' -f1)
check "asset manifest lists the file" "client.bin"    "$(curl -s http://127.0.0.1:$A_WS/assets/)"
check "manifest carries sha256"       "$EXPECT_SHA"   "$(curl -s http://127.0.0.1:$A_WS/assets/)"
check "asset downloads intact"        "$EXPECT_SHA"   \
    "$(curl -s http://127.0.0.1:$A_WS/assets/client.bin | sha256sum | cut -d' ' -f1)"
check "asset served over TLS too"     "test payload"  \
    "$(curl -sk https://127.0.0.1:$A_WSS/assets/client.bin)"
check "path traversal refused"        "bad_name"      \
    "$(curl -s --path-as-is http://127.0.0.1:$A_WS/assets/..%2f..%2fetc%2fpasswd)"
check "subdirectory escape refused"   "bad_name"      \
    "$(curl -s --path-as-is 'http://127.0.0.1:'$A_WS'/assets/../peers.json')"

echo
echo "WebSocket, both protocols"
check "ping over ws://"             "nonce matches"   "$($PROBE --url ws://127.0.0.1:$A_WS ping 2>&1)"
check "ping over wss://"            "nonce matches"   "$($PROBE --url wss://127.0.0.1:$A_WSS ping 2>&1)"

echo
echo "Identities"
# An identity is an ed25519 key; its fingerprint is a hash of the public half.
ALICE=$($PROBE --key "$WORK/alice.key" whoami 2>/dev/null)
MALLORY=$($PROBE --key "$WORK/mallory.key" whoami 2>/dev/null)
BOBLOCAL=$($PROBE --key "$WORK/boblocal.key" whoami 2>/dev/null)
check "key yields a fingerprint"    "$(printf '%s' "$ALICE" | wc -c)" "64"
check "distinct keys differ"        "different"       \
    "$([ "$ALICE" != "$MALLORY" ] && echo different || echo same)"

echo
echo "Invite codes"
CODE_A=$(grep -v '^#' "$WORK/a/genesis-invites.txt" | sed -n 1p)
CODE_A2=$(grep -v '^#' "$WORK/a/genesis-invites.txt" | sed -n 2p)
CLAIM=$($PROBE --url wss://127.0.0.1:$A_WSS --key "$WORK/alice.key" claim "$CODE_A" 2>/dev/null)
check "claim returns 3 codes"       "three fresh"     "$CLAIM"
check "claim burns the code"        "invite_used"     \
    "$($PROBE --url ws://127.0.0.1:$A_WS --key "$WORK/alice.key" claim "$CODE_A" 2>&1)"
check "check reports burned"        '"open": false'   "$(curl -s http://127.0.0.1:$A_WS/invite/check/$CODE_A)"
check "check reports open"          '"open": true'    "$(curl -s http://127.0.0.1:$A_WS/invite/check/$CODE_A2)"
check "exactly 3 codes issued"      "3"               "$(printf '%s' "$CLAIM" | grep -cE '^  (R2R(-[0-9A-Z]{4}){3,5}|[0-9a-f-]{36})$')"
# An unsigned HTTP claim must be refused: registering a home relay for someone
# else's fingerprint would redirect their mail.
check "unsigned HTTP claim refused" "not_authorised"  \
    "$(curl -s -X POST http://127.0.0.1:$A_WS/invite/claim -H 'Content-Type: application/json' \
        -d "{\"code\":\"$CODE_A2\",\"id\":\"$ALICE\"}")"

# A member's own codes start locked, and an identity registers only once.
KID=$(printf '%s' "$CLAIM" | grep -oE 'R2R(-[0-9A-Z]{4}){3,5}' | sed -n 1p)
check "member codes start locked"   '"locked": true'  "$(curl -s http://127.0.0.1:$A_WS/invite/check/$KID)"
check "locked code cannot be claimed" "invite_locked" \
    "$($PROBE --url ws://127.0.0.1:$A_WS --key "$WORK/carol.key" claim "$KID" 2>&1)"
check "one registration per identity" "already_registered" \
    "$($PROBE --url ws://127.0.0.1:$A_WS --key "$WORK/alice.key" claim "$CODE_A2" 2>&1)"
# Genesis-invited member: received traffic alone unlocks.
DAVE=$($PROBE --key "$WORK/dave.key" whoami 2>/dev/null)
$PROBE --url ws://127.0.0.1:$A_WS --key "$WORK/dave.key" claim "$CODE_A2" >/dev/null 2>&1
for i in 1 2 3; do $PROBE --url ws://127.0.0.1:$A_WS send "$DAVE" "hello $i" >/dev/null 2>&1; done
check "status before traffic"       '"active":false'  \
    "$($PROBE --url ws://127.0.0.1:$A_WS --key "$WORK/dave.key" frame '{"t":"invite_status"}' 2>&1 | tr -d ' ')"
$PROBE --url ws://127.0.0.1:$A_WS --key "$WORK/dave.key" fetch >/dev/null 2>&1
check "traffic activates member"    '"active":true'   \
    "$($PROBE --url ws://127.0.0.1:$A_WS --key "$WORK/dave.key" frame '{"t":"invite_status"}' 2>&1 | tr -d ' ')"
# Identity-invited member: also needs the inviter's vouch.
$RELAY_A --data-dir "$WORK/a" --owner-add "$ALICE" >/dev/null 2>&1
OCODE=$($PROBE --url ws://127.0.0.1:$A_WS --key "$WORK/alice.key" mkinvites 1 2>&1 | grep -oE 'R2R(-[0-9A-Z]{4}){3,5}' | sed -n 1p)
ERIN=$($PROBE --key "$WORK/erin.key" whoami 2>/dev/null)
check "claim names the inviter"     "$ALICE"          \
    "$($PROBE --url ws://127.0.0.1:$A_WS --key "$WORK/erin.key" frame "{\"t\":\"invite_status\"}" 2>&1; \
       $PROBE --url ws://127.0.0.1:$A_WS --key "$WORK/erin.key" claim "$OCODE" >/dev/null 2>&1; \
       $PROBE --url ws://127.0.0.1:$A_WS --key "$WORK/erin.key" frame '{"t":"invite_status"}' 2>&1)"
for i in 1 2 3; do $PROBE --url ws://127.0.0.1:$A_WS send "$ERIN" "hi $i" >/dev/null 2>&1; done
$PROBE --url ws://127.0.0.1:$A_WS --key "$WORK/erin.key" fetch >/dev/null 2>&1
check "traffic alone is not enough" '"active":false'  \
    "$($PROBE --url ws://127.0.0.1:$A_WS --key "$WORK/erin.key" frame '{"t":"invite_status"}' 2>&1 | tr -d ' ')"
check "only the inviter may vouch"  "not_authorised"  \
    "$($PROBE --url ws://127.0.0.1:$A_WS --key "$WORK/dave.key" frame "{\"t\":\"vouch\",\"id\":\"$ERIN\"}" vouch_ok 2>&1)"
check "inviter's vouch activates"   '"active":true'   \
    "$($PROBE --url ws://127.0.0.1:$A_WS --key "$WORK/alice.key" frame "{\"t\":\"vouch\",\"id\":\"$ERIN\"}" vouch_ok 2>&1 | tr -d ' ')"
check "unlocked codes are open"     '"state":"open"'  \
    "$($PROBE --url ws://127.0.0.1:$A_WS --key "$WORK/erin.key" frame '{"t":"invite_status"}' 2>&1 | tr -d ' ')"

echo
echo "Dead drop"
check "retention is 7 days"         "expires $(date -u -d '+7 days' +%Y-%m-%d)" \
    "$($PROBE --url ws://127.0.0.1:$A_WS send "$ALICE" "ttl check" 2>&1)"
$PROBE --url ws://127.0.0.1:$A_WS --key "$WORK/alice.key" fetch >/dev/null 2>&1
$PROBE --url wss://127.0.0.1:$A_WSS send "$ALICE" "stored via tls" >/dev/null 2>&1
$PROBE --url ws://127.0.0.1:$A_WS  send "$ALICE" "stored via plaintext" >/dev/null 2>&1
FETCH=$($PROBE --url ws://127.0.0.1:$A_WS --key "$WORK/alice.key" fetch 2>&1)
check "payload sent over wss is held"  "stored via tls"        "$FETCH"
check "payload sent over ws is held"   "stored via plaintext"  "$FETCH"
check "acknowledge empties the mailbox" "acknowledged 2"       "$FETCH"
check "mailbox is now empty"           "fetched 0"             \
    "$($PROBE --url ws://127.0.0.1:$A_WS --key "$WORK/alice.key" fetch 2>&1)"

echo
echo "Identity is proved, not asserted"
$PROBE --url ws://127.0.0.1:$A_WS send "$ALICE" "only alice may read this" >/dev/null 2>&1
check "another valid key sees nothing" "fetched 0" \
    "$($PROBE --url ws://127.0.0.1:$A_WS --key "$WORK/mallory.key" fetch 2>&1)"
check "the owner's key sees it"        "only alice may read this" \
    "$($PROBE --url ws://127.0.0.1:$A_WS --key "$WORK/alice.key" fetch 2>&1)"

echo
echo "Per-user storage the owner controls"
check "default allowance is 1 MB"   "of 1048576 bytes" \
    "$($PROBE --url ws://127.0.0.1:$A_WS --key "$WORK/alice.key" fetch 2>&1)"
check "owner raises an allowance"   "may now store 25 MB" \
    "$("$RELAY_A" --data-dir "$WORK/a" --set-quota "$ALICE" 25 2>/dev/null)"
check "new allowance is in effect"  "of 26214400 bytes" \
    "$($PROBE --url ws://127.0.0.1:$A_WS --key "$WORK/alice.key" fetch 2>&1)"
check "allowance is listed"         "$ALICE" \
    "$("$RELAY_A" --data-dir "$WORK/a" --list-quotas 2>/dev/null)"
check "owner restores the default"  "back on the relay default" \
    "$("$RELAY_A" --data-dir "$WORK/a" --clear-quota "$ALICE" 2>/dev/null)"

echo
echo "History that follows you to a new browser"
$PROBE --url ws://127.0.0.1:$A_WS --key "$WORK/alice.key" journal "first conversation" >/dev/null 2>&1
JOURNAL=$($PROBE --url ws://127.0.0.1:$A_WS --key "$WORK/alice.key" journal "second conversation" 2>&1)
check "entries append in order"     "seq 2"              "$JOURNAL"
check "a fresh session replays it"  "first conversation" "$JOURNAL"
check "and the later entry too"     "second conversation" "$JOURNAL"

echo
echo "Voice and video messages"
head -c 400000 /dev/urandom > "$WORK/voice.opus"
"$RELAY_A" --data-dir "$WORK/a" --set-quota "$ALICE" 50 >/dev/null 2>&1
BLOB=$($PROBE --url ws://127.0.0.1:$A_WS --key "$WORK/alice.key" blob "$WORK/voice.opus" 2>&1)
check "400 KB upload beats the frame limit" "uploaded 400000 bytes" "$BLOB"
check "download matches the content hash"   "content hash matches"  "$BLOB"
check "identical content stored once"       "already stored"        \
    "$($PROBE --url ws://127.0.0.1:$A_WS --key "$WORK/alice.key" blob "$WORK/voice.opus" 2>&1)"
check "unauthenticated fetch refused"       "401"                   \
    "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:$A_WS/blob/$(printf 'a%.0s' $(seq 1 64)))"
# A blob big enough to blow the per-user allowance must be refused, not stored.
head -c 900000 /dev/urandom > "$WORK/big.opus"
"$RELAY_A" --data-dir "$WORK/a" --set-quota "$ALICE" 1 >/dev/null 2>&1
check "allowance is enforced on blobs too"  "quota"                 \
    "$($PROBE --url ws://127.0.0.1:$A_WS --key "$WORK/alice.key" blob "$WORK/big.opus" 2>&1)"
"$RELAY_A" --data-dir "$WORK/a" --set-quota "$ALICE" 50 >/dev/null 2>&1

echo
echo "Calls: signalling and presence"
check "ICE servers offered"          "stun:"    \
    "$($PROBE --url ws://127.0.0.1:$A_WS --key "$WORK/alice.key" ice 2>&1)"
check "an absent peer reads offline" "offline"  \
    "$($PROBE --url ws://127.0.0.1:$A_WS --key "$WORK/alice.key" watch "$BOBLOCAL" 2>&1)"
$PROBE --url ws://127.0.0.1:$A_WS --key "$WORK/boblocal.key" listen 9 > "$WORK/listen.out" 2>/dev/null &
LISTEN_PID=$!
sleep 2
check "a connected peer reads online" "online"  \
    "$($PROBE --url ws://127.0.0.1:$A_WS --key "$WORK/alice.key" watch "$BOBLOCAL" 2>&1)"
check "offer reaches the callee"      "delivered to" \
    "$($PROBE --url ws://127.0.0.1:$A_WS --key "$WORK/alice.key" sig "$BOBLOCAL" "v=0 sdp-offer" 2>&1)"
sleep 2
check "callee received the offer"     "SIG from $ALICE" "$(cat "$WORK/listen.out" 2>/dev/null)"
kill "$LISTEN_PID" 2>/dev/null; wait "$LISTEN_PID" 2>/dev/null
check "signalling an offline peer errors" "not_online" \
    "$($PROBE --url ws://127.0.0.1:$A_WS --key "$WORK/alice.key" sig "$MALLORY" "offer" 2>&1)"

echo
echo "Relay to relay"
# B dials A on startup and retries on its maintain timer, so the link can take
# a few seconds to appear. Wait for it rather than sampling once.
for _ in $(seq 1 40); do
    grep -q 'is linked' "$WORK/a/relay.log" 2>/dev/null && break
    sleep 1
done
check "A and B linked"              "is linked"       "$(grep -h 'is linked' "$WORK/a/relay.log" 2>/dev/null)"
# B's inbound link only tells A that someone holds B's key. A verifies the
# address B advertises by dialling it on its next maintain tick (15 s); only
# then is B published, gossiped and usable as an onion hop.
for _ in $(seq 1 60); do
    curl -s http://127.0.0.1:$A_WS/peers.json | tr -d ' \n' | grep -q "\"address\":\"127.0.0.1:$B_WS\",[^}]*\"verified\":true" && break
    sleep 0.5
done
check "B is verified in A's table"  '"verified": true' \
    "$(curl -s http://127.0.0.1:$A_WS/peers.json)"
BOB=$($PROBE --key "$WORK/bob.key" whoami 2>/dev/null)
CODE_B=$(grep -v '^#' "$WORK/b/genesis-invites.txt" | sed -n 1p)
check "identity homed on B"         "127.0.0.1:$B_WS" \
    "$($PROBE --url ws://127.0.0.1:$B_WS --key "$WORK/bob.key" claim "$CODE_B" 2>&1)"
check "wss in, ws out: forwarded"   "forwarded via 127.0.0.1:$B_WS" \
    "$($PROBE --url wss://127.0.0.1:$A_WSS send "$BOB@127.0.0.1:$B_WS" "across the bridge" 2>&1)"
sleep 1
check "B holds the bridged payload" "across the bridge" \
    "$($PROBE --url ws://127.0.0.1:$B_WS --key "$WORK/bob.key" fetch 2>&1)"

echo
echo "Onion routing"
ONION=$($PROBE --url wss://127.0.0.1:$A_WSS --http http://127.0.0.1:$A_WS \
    --hops "127.0.0.1:$A_WS,127.0.0.1:$B_WS" onion "$BOB" "two sealed hops" 2>&1)
check "two layers sealed"           "sealed 2 layer"  "$ONION"
check "route accepted"              "onion accepted"  "$ONION"
sleep 1
check "terminal payload reached B"  "two sealed hops" \
    "$($PROBE --url ws://127.0.0.1:$B_WS --key "$WORK/bob.key" fetch 2>&1)"
check "A peeled a layer"            '"onion_peeled": 1' "$(curl -s http://127.0.0.1:$A_WS/status.json)"
check "B peeled a layer"            '"onion_peeled": 1' "$(curl -s http://127.0.0.1:$B_WS/status.json)"

echo
echo "Store and forward across a peer restart"
# B goes away, a payload for it is accepted anyway, B comes back: the frame must
# survive in A's queue and flush when the link returns -- here via the link B
# dials to A, which no dial of A's own would ever have flushed.
kill "$B_PID" 2>/dev/null; wait "$B_PID" 2>/dev/null; B_PID=""
sleep 1
check "accepted while B is down"    "forwarded via 127.0.0.1:$B_WS" \
    "$($PROBE --url wss://127.0.0.1:$A_WSS send "$BOB@127.0.0.1:$B_WS" "queued while down" 2>&1)"
B_PID=$(start_relay "$RELAY_B" "$WORK/b" "$B_WS" "$B_WSS" 1)
DELIVERED=""
for _ in $(seq 1 25); do
    sleep 2
    if $PROBE --url ws://127.0.0.1:$B_WS --key "$WORK/bob.key" fetch 2>&1 | grep -q "queued while down"; then
        DELIVERED=yes; break
    fi
done
if [ -n "$DELIVERED" ]; then ok "delivered after B returned";
else bad "delivered after B returned" "the queued frame never arrived"; fi

echo
echo "Link hygiene"
# A quiet link is the point: an unrecognised frame must never provoke a reply
# that the other node also finds unrecognisable.
FRAMES=$(curl -s http://127.0.0.1:$A_WS/status.json | \
         python3 -c 'import json,sys; print(json.load(sys.stdin)["frames_in"])')
if [ "$FRAMES" -lt 500 ]; then ok "no frame storm (A saw $FRAMES frames)";
else bad "no frame storm" "A saw $FRAMES frames -- a reply loop is likely"; fi

echo
echo "Peer table hygiene"
# Anyone with a key may join as a relay; nobody may steer this relay's dials by
# merely claiming to be one. The rogue advertises a port nothing listens on and
# offers two more addresses. The hello is welcomed, the list is ignored, and
# the only dial that follows is the one that checks the rogue's own claim.
ROGUE_ADV="127.0.0.1:19998"; INJECT_1="127.0.0.1:19999"; INJECT_2="127.0.0.1:19997"
ROGUE=$($PROBE --url ws://127.0.0.1:$A_WS rogue "$ROGUE_ADV" "$INJECT_1,$INJECT_2" 2>&1)
check "self-signed relay may join"      "welcomed as relay"     "$ROGUE"
check "its peer list is ignored"        "has not been verified" \
    "$(grep -h 'ignoring a peer list' "$WORK/a/relay.log" 2>/dev/null)"
check "unverified claim is not published" "none" \
    "$(curl -s http://127.0.0.1:$A_WS/peers.json | grep -q "$ROGUE_ADV" && echo listed || echo none)"
# The claim itself is checked by one dial, on the maintain timer (15 s).
for _ in $(seq 1 40); do
    grep -q "verifying $ROGUE_ADV by dialling it" "$WORK/a/relay.log" 2>/dev/null && break
    sleep 0.5
done
check "the claimed address is verified by dialling it" "verifying $ROGUE_ADV" \
    "$(grep -h "verifying $ROGUE_ADV" "$WORK/a/relay.log" 2>/dev/null)"
check "the offered addresses are never dialled" "none" \
    "$(grep -qE "dialling peer ws://($INJECT_1|$INJECT_2)|verifying ($INJECT_1|$INJECT_2)" \
        "$WORK/a/relay.log" 2>/dev/null && echo dialled || echo none)"
# Without --allow-private-peers, loopback and private ranges are refused
# everywhere an address can come from: peers.json, a hello, gossip.
D_WS=20787
mkdir -p "$WORK/d"
printf '{"version":1,"peers":[{"address":"127.0.0.1:%s","tls":false}]}\n' "$A_WS" > "$WORK/d/peers.json"
"$RELAY" --data-dir "$WORK/d" --ws-port "$D_WS" --peer-dial-target 0 \
    --log-level debug > "$WORK/d/relay.log" 2>&1 &
D_PID=$!
wait_for_health "$D_WS"
check "private peer in peers.json is dropped" "ignoring non-public peer 127.0.0.1:$A_WS" \
    "$(grep -h 'ignoring non-public peer' "$WORK/d/relay.log" 2>/dev/null)"
check "private advertise in a hello is refused" "not public" \
    "$($PROBE --url ws://127.0.0.1:$D_WS rogue 10.0.0.7:8787 "$INJECT_1" 2>&1)"
kill "$D_PID" 2>/dev/null; wait "$D_PID" 2>/dev/null

echo
echo "Storage market"
# A third relay sells storage; the reservation, the voucher cycle and the
# never-oversell rule are exercised end to end. Chain signatures are opaque
# to the relay, so a zero signature of the right shape is enough here.
C_WS=8797
MK_PAYOUT=0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
MK_PAYKEY=0xcccccccccccccccccccccccccccccccccccccccc
MK_SIG=0x$(printf '0%.0s' $(seq 1 130))
mkdir -p "$WORK/c"
"$RELAY" --data-dir "$WORK/c" --ws-port "$C_WS" --open-registration \
    --pool-market-mb 2 --market-price 500000 --payout-address "$MK_PAYOUT" \
    --log-level debug > "$WORK/c/relay.log" 2>&1 &
C_PID=$!
wait_for_health "$C_WS"
MPROBE="$PROBE --url ws://127.0.0.1:$C_WS --key $WORK/c/probe.key"
RENT_OUT=$($MPROBE frame "{\"t\":\"rent\",\"bytes\":1500000,\"payment_key\":\"$MK_PAYKEY\"}" rent_ok 2>&1)
check "rent reserves market bytes"    '"t": "rent_ok"'        "$RENT_OUT"
check "rent quotes the epoch price"   '"price_epoch_micro": 699' "$RENT_OUT"
MK_RENTAL=$(printf '%s' "$RENT_OUT" | sed -n 's/.*"rental": "\([0-9a-f-]*\)".*/\1/p' | head -1)
[ -z "$MK_RENTAL" ] && MK_RENTAL=$(printf '%s' "$RENT_OUT" | tr -d ' \n' | sed -n 's/.*"rental":"\([0-9a-f-]*\)".*/\1/p')
check "second rent cannot oversell"   'market_full' \
    "$($MPROBE frame "{\"t\":\"rent\",\"bytes\":1100000,\"payment_key\":\"$MK_PAYKEY\"}" rent_ok 2>&1)"
check "voucher extends the rental"    '"t": "voucher_ok"' \
    "$($MPROBE frame "{\"t\":\"voucher\",\"rental\":\"$MK_RENTAL\",\"payment_key\":\"$MK_PAYKEY\",\"payout\":\"$MK_PAYOUT\",\"cumulative_micro\":699,\"sig\":\"$MK_SIG\"}" voucher_ok 2>&1)"
check "replayed voucher refused"      'must exceed the previous' \
    "$($MPROBE frame "{\"t\":\"voucher\",\"rental\":\"$MK_RENTAL\",\"payment_key\":\"$MK_PAYKEY\",\"payout\":\"$MK_PAYOUT\",\"cumulative_micro\":699,\"sig\":\"$MK_SIG\"}" voucher_ok 2>&1)"
check "status.json shows the market"  '"committed_bytes": 1500000' \
    "$(curl -s http://127.0.0.1:$C_WS/status.json)"
kill "$C_PID" 2>/dev/null; wait "$C_PID" 2>/dev/null

echo
printf 'passed %d, failed %d\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || exit 1
