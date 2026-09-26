# Porting the relay to another language

The relay is one C++ program. This note is for anyone who wants a second
implementation — in Go, Rust, Python or anything else — that other relays and
the wallet cannot tell apart from the original. It says what "compatible"
covers, how to prove it step by step, roughly what each language costs, and
what to reach for first.

There is no second implementation today. What exists is the reference relay,
the protocol specification, a set of known-answer vectors generated from the
reference code, and a black-box test harness that can run a port next to the
reference. Together they are the contract a port is held to.

## What "compatible" covers

A port must be indistinguishable on the wire. Everything else — storage
engine, process model, admin tooling — is its own business, as long as the
same operator commands exist.

| Area | Specification | Reference code |
|---|---|---|
| Encodings, primitives, domain tags, addresses | white paper §3 | `src/util.cpp`, `src/crypto.cpp` |
| Identities, fingerprints, `R2R_…` addresses, proof of possession | §4 | `src/crypto.cpp`, `src/protocol.cpp` |
| Ports, WebSocket subprotocol `r2r.v1`, framing, limits, session state | §6 | `src/http_session.hpp`, `src/ws_channel.hpp` |
| Every client frame, `hello` through `admin_*` | §7, §13 | `src/hub.cpp`, names in `src/protocol.hpp` |
| Dead drops, `seq` cursors, quotas, TTL, journal, blobs, pools | §8 | `src/db.cpp`, `src/hub.cpp` |
| Addressing, forwarding, pending queue, pointers, deposit/collect | §9 | `src/hub.cpp`, `src/peer_manager.cpp` |
| Onion layers, sealed boxes, relay processing | §10 | `src/onion.cpp`, `src/crypto.cpp` |
| Relay handshake, pinning, gossip, `peers.json`, seeds, timers | §11 | `src/peers.cpp`, `src/peer_manager.cpp` |
| Invite codes, claiming, activation, revocation | §12 | `src/db.cpp`, `src/hub.cpp` |
| Storage market frames (may answer `market_off`) | §14 | `src/hub.cpp` |
| HTTP routes: `/peers.json`, `/node.json`, `/status.json`, `/health`, `/invite/*`, `/assets/` | README "HTTP endpoints" | `src/http_routes.cpp` |

The white paper is `R2R-WHITEPAPER.md` in this directory; the reference relay is `../cpp/` (all `src/`, `tools/` and `scripts/` paths below are relative to it); the section numbers above are
its headings. Its §16 is the HTTP API reference, §17 lists every protocol
constant, §19 is the normative conformance checklist (what a relay MUST and
SHOULD do), §20 records the reference implementation's quirks, and Appendix A
holds hand-checked test vectors. Where the paper and the code disagree, the
code is what the network runs, and the paper should be corrected.

**Not part of the protocol** and free to differ or be left out: the doorway
web site and the admin console (both are optional builds of the reference
too), the metrics sync, the on-chain settlement contract, and the SQLite
schema. A port may store data any way it likes.

### Rules that are easy to get wrong

White paper §19.1 is the full list. These are the entries that a port which
"mostly works" is most likely to have missed, because nothing local breaks
when they are wrong — only the network does.

- **An `err` frame is terminal.** Never answer an error with an error. Two
  relays that do will saturate the link between them.
- **`seq` is the only cursor.** `fetch` must return a monotonically increasing
  `seq` per drop and a `cursor` in `fetch_done`; timestamps are not usable.
- **Canonical strings are exact bytes.** The four signing strings
  (`r2r-hello-v1`, `r2r-client-v1`, `r2r-pointer-v1`, `r2r-collect-v1`) join
  their fields with a single `\n`, the timestamp is decimal, and there is no
  trailing newline. Fingerprints are 64 lowercase hex characters. Base64 is
  standard, padded.
- **Identity is proved, never asserted.** `hello` without a valid signature
  leaves the session anonymous; `fetch`, `ack`, `deposit`, journal and owner
  frames must then refuse.
- **Claiming an invite is atomic:** burn the code, register the identity and
  mint exactly three successors in one transaction, or do nothing.
- **Verified means dialled.** A signed `hello` on an inbound link proves a
  key, not an address. An entry becomes verified only when *your* relay
  dialled the address and the node there proved its key; only then is it
  published, gossiped, used for rendezvous, or allowed to send you `peers`
  lists (capped at 64 new addresses per session). Unverified entries get at
  most two verification dials per maintain tick, and never to loopback or
  private ranges. The pin is set by that dial, not by the inbound hello, and
  a key learned from gossip is a hint that must never reject anyone. Seed
  entries are never pruned. (§11.2–11.4.)
- **Pointers and presence are gated.** A pointer is accepted only from a
  verified relay session and only about a holder your relay has verified at
  that exact address with that exact key; `watch` answers only sessions that
  proved an identity. (§9.5, §7.11.)
- **Vouchers are verified, not just stored.** Recover the secp256k1 signer of
  every voucher over the §14.4 digest (Keccak-256, EIP-191 prefix, low-s) and
  require it to be the rental's payment key before extending `paid_until`.
  `protocol-vectors.json` has a known-answer voucher; the reference probe's
  `voucher-sign` and `voucher-check` commands produce and check them.
- **Proofs are single-use.** Remember every accepted client proof's
  `(id, nonce)` for longer than the ±600 s window and refuse a repeat, on the
  socket and in `X-R2R-Auth`. `collect` is accepted from verified relay
  sessions only. (§4.4, §9.6.)
- **Never echo `Host` raw.** Validate it as an address, escape it in HTML, and
  escape JSON for script context. (§16.)
- **Onion silence.** A relay that accepts a layer sends nothing back. Only
  failures travel back. The layer's tag covers the whole slot header, so
  slots cannot be reordered or dropped.
- **Limits are behaviour.** 1 MiB frame cap, 40 frames/s with a burst of
  120 per connection, 256 KiB default payload, ten-minute skew on `ts`.

### The operator contract

`install.sh`, the systemd unit and the smoke test drive the binary through
its command line, so a port that keeps these works with every script in
this repository unchanged:

- Flags: `--data-dir`, `--ws-port`, `--wss-port`, `--cert`, `--key`,
  `--no-tls`, `--advertise`, `--seed`, `--peer-dial-target`, `--assets`,
  `--log-level`, `--open-registration`, `--mint-invites N`,
  `--owner-add/--owner-remove/--list-owners`,
  `--set-quota/--clear-quota/--list-quotas`, `--version`, `--help`.
  `r2r-relay --help` on the reference lists the rest.
- Environment: `R2R_ADVERTISE`, `R2R_SEEDS`, `R2R_LOG_LEVEL`,
  `R2R_ASSETS_DIR`, `R2R_PUBLIC_WS_URL`, `TURN_URL`, `TURN_SECRET_FILE`.
- Data directory: `node.key` (the 32-byte seed as 64 hex characters plus a
  newline; 32 raw bytes are accepted on read), `peers.json` (§11.4; a plain
  array of `"host:port"` strings is accepted and upgraded on the next write),
  `genesis-invites.txt` (mode 0600, written once on first start).
- Signals: `SIGHUP` re-reads the TLS certificate in place; `SIGTERM` exits
  cleanly after flushing state.

## Proving it: the conformance ladder

Climb it in order. Each rung is cheap to run and catches a different class of
mistake.

### 1. Known-answer vectors

`protocol-vectors.json` (this directory) is generated from the reference code by
`tools/protocol-vectors.cpp`:

```sh
cmake -S . -B build -DR2R_BUILD_VECTORS=ON
cmake --build build --target r2r-vectors -j1
./build/r2r-vectors > ../protocol/protocol-vectors.json
```

Every value in it is deterministic from the inputs stored beside it: key
derivations, fingerprints and `R2R_…` addresses, node ids, the four canonical
strings with their ed25519 signatures, complete `hello` frames that must be
accepted and ones that must be rejected, HMAC and TURN credential
construction, a sealed box with every intermediate value exposed and a
multi-recipient layer that must open (and a key that must fail to open it),
two onion routes with what each hop must see after peeling, and `parse_target`
and `parse_address` cases. It reproduces the white paper's Appendix A values
and the generator asserts them, so the paper, the library and the file cannot
silently drift apart. A port's own test suite should load the file and assert
every entry before touching a socket. Getting these right first turns the rest
of the work from debugging into implementation.

Things the generator turned up that a port author would not guess from the
paper alone (the file's `notes` fields say the same next to each value):

- The relay's X25519 key is `HKDF-SHA256(seed, salt="", info="r2r-x25519-v1")`;
  the wallet's identity uses the Ed25519-to-X25519 birational map instead. Two
  different constructions for two different keys.
- `node_id` is the first 16 bytes of `SHA-256("r2r-node-v1" || pub)`, as 32
  hex characters — not the whole digest.
- The `R2R_…` address checksum is SHA3-256 of `pub || "R2R"` (tag as suffix).
  The decoder strips only `_`, `-` and spaces before decoding.
- The sealed box binds the recipient key twice: in the HKDF salt
  (`eph_pub || recipient_pub`) and in the AAD (`0x01 || eph_pub || recipient_pub`).
- The pointer signing string carries no nonce, and the relay lowercases and
  trims `id` before building any signing string, so clients must sign the
  lowercase fingerprint.
- The base64 decoder accepts unpadded and URL-safe input but rejects non-zero
  leftover bits; the reference emits standard padded base64.
- Terminal onion records are JSON with keys in sorted order (`hint`, `id`,
  `to`); routing addresses are carried verbatim and canonicalised by the
  receiver (default port 8787).
- `parse_target` rejects `fp@wss://host/` (a trailing slash), although
  paper §3.4 says to strip one. The code wins until the paper is corrected.

### 2. The smoke test, with the port as one of the two nodes

`scripts/smoke-test.sh` starts two relays on private ports and exercises the
HTTP surface and asset distribution, both transports, identity proofs,
invites and activation, the dead drop and its cursor, quotas, the journal,
voice and video blobs, call signalling and presence, relay-to-relay links
and the wss-to-ws bridge, a two-hop onion route, store-and-forward across a
peer restart, link hygiene and the storage market, using `r2r-probe` (the
reference client) as the client. It accepts a different binary for each
node:

```sh
RELAY_B=/path/to/port ./scripts/smoke-test.sh build   # port as the peer/storage node
RELAY_A=/path/to/port ./scripts/smoke-test.sh build   # port as the node clients talk to
```

Node A is where the probe connects and where the operator commands run; node
B dials A, answers the bridge test and carries the second onion hop. Run both
ways. Every check must pass in both positions. (The third, market-only relay
the script starts near the end always uses the reference build.)

### 3. Live interop on a test network

Run the port with `--seed` pointing at a reference relay on a private
network. Within a minute `peers.json` on both sides must list the other with
`"verified": true`, and `r2r-probe --url ws://<port>:8787 send` to an
identity homed on the reference relay must be collectable there, and the
reverse. Leave it for an hour: gossip, pings, pruning and the five-minute
`peers.json` rewrite all have to keep behaving.

### 4. The wallet

Point the browser wallet (`../../wallets/r2r-web/dist/`, or the copy any relay
serves) at the port, claim an invite, exchange messages with someone on a reference relay,
place a call, restore from the journal in a second browser. The wallet is
the client that matters: the probe sends single frames, the wallet runs the
whole flows (envelopes, groups, calls, multi-device restore, rentals) in the
order and at the pace real users do.

## What each language costs

The reference is about 12,500 lines of C++, of which roughly a third is the
doorway site, admin console and market. A port that skips those and stores
data its own way is smaller. The estimates below are for one experienced
developer reaching rung 2 in both positions; rungs 3 and 4 add a week or two
of soak and fixes.

| | Go | Rust | Python |
|---|---|---|---|
| One static binary per architecture | Built in (`GOOS`/`GOARCH`), no toolchain work | Yes, via musl targets or `cargo-zigbuild` | No; bundlers produce large, fragile per-arch archives |
| ed25519, x25519, HKDF, AES-GCM, SHA-3 | standard library plus `golang.org/x/crypto` | `ed25519-dalek`, `x25519-dalek`, `hkdf`, `aes-gcm`, `sha3` | `cryptography` or PyNaCl |
| WebSocket + TLS server and client | `nhooyr.io/websocket` or `gorilla`, `crypto/tls` | `tokio-tungstenite` + `rustls` | `websockets` |
| SQLite without a C compiler on the target | `modernc.org/sqlite` (pure Go) | `rusqlite` with `bundled` | stdlib `sqlite3` |
| Concurrency model for thousands of links | goroutines, natural fit | tokio, natural fit | asyncio, adequate |
| Time to rung 2 | 3–5 weeks | 5–8 weeks | 2–3 weeks for a subset |
| Fit for "download one file and run it" | best | good | poor |

**Go is the right first port.** It removes the architecture question
permanently (one `go build` per target, no OpenSSL to cross-compile), its
standard library covers the cryptography, and the resulting binary is the
same "copy it and run it" experience the C++ one has now. Rust gives a
stronger security posture for a longer investment and is the better second
port. Python is the fastest way to prototype a protocol change or to write a
test client, and the wrong thing to ask operators to install.

**Recommendation: not yet.** Every hour spent on a port before the mini
network exists is an hour of protocol drift risk with nothing to test it
against. Stand the network up on the C++ builds (they now cover x86-64 and
ARM64 as static binaries, see `toolchain/build-cross.sh`), let the wallet
and the probe shake out the protocol, freeze the white paper against the
code, and then start a Go port against the ladder above. Until then, the
vectors and the `RELAY_A`/`RELAY_B` harness cost nothing to keep current and
are what make the port possible when it happens.
