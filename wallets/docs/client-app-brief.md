# Brief for the app designer — R2Я client and Setup app

Hand this to whoever maintains `R2Я.htm` and `R2Я - Setup.htm`.

---

## 1. The Setup app now has one install instruction, not four

Today the Setup app offers four ways to stand up a relay — PHP, Python, Node,
and a compiled binary — each a `systemd` unit running `relay-server.php`,
`relay-server.py`, `relay-server.js` or `~/r2r-relay` out of the operator's home
directory.

**Delete all four.** Replace them with this, which is the entire instruction:

> **Run your own relay**
>
> On any Linux server, as root:
>
> ```sh
> curl -sSLO https://r2r.homes/assets/r2r-relay
> curl -sSLO https://r2r.homes/assets/install.sh
> curl -sSLO https://r2r.homes/assets/setup-tls.sh
> curl -sSLO https://r2r.homes/assets/r2r-relay.service
> chmod +x r2r-relay install.sh setup-tls.sh
> ./install.sh YOUR.SERVER.IP:8787
> ```
>
> Open ports **8787** and **8788**. That is all — there is nothing else to
> install, no PHP, Python, Node, database server or web server. Your invite
> codes are in `/var/lib/r2r/genesis-invites.txt`.

Why this replaces four options: the relay is now a single statically linked
binary with SQLite and OpenSSL compiled in. It has no runtime dependencies at
all — not even a matching glibc — so there is no reason to offer a choice of
language, and no reason for the operator to pick one. Every relay on the network
runs the identical binary.

Anything in the Setup app that asks the operator to choose a runtime, or that
mentions `relay-server.php` / `.py` / `.js`, should go. The checksum of each
published file is listed at `https://r2r.homes/assets/` if you want to show a
verification step.

---

## 2. The client has to change: the wire protocol is different

This is the part that needs real work. The new relay does **not** speak the old
protocol, so the existing client cannot talk to it at all. Since nothing has
launched, updating the client is the right move — but it is not a small edit.

### Identity and authentication

Old: `?pub=<64 hex>&ts=<unix>&sig=<128 hex>` on the query string, signature over
`"R2R-AUTH|" + ts`, `pub` being the raw ed25519 public key.

New: still ed25519, but the identity is a **fingerprint** —
`SHA-256("r2r-id-v1" || public_key)`, lowercase hex — and the proof travels
inside the first WebSocket frame:

```json
{ "t":"hello", "role":"client",
  "id":"<fingerprint>", "pubkey":"<base64 ed25519 public key>",
  "ts":1754331000, "nonce":"<hex, 16-64 chars>",
  "sig":"<base64 signature>" }
```

The signed bytes are `"r2r-client-v1\n" + fingerprint + "\n" + ts + "\n" + nonce`.
The relay checks the timestamp is within ten minutes, that the fingerprint is
the hash of the presented key, and the signature. Get any of it wrong and the
session stays anonymous: it can send to others but cannot read any mailbox.

For HTTP requests (blobs, ICE) the same JSON object goes in an `X-R2R-Auth`
header, base64-encoded.

**Sending does not require identifying yourself.** Anyone may leave a message
for a fingerprint; only the key holder can collect it.

### Frame-by-frame mapping

| Old | New | Note |
|---|---|---|
| `{type:'send', to, id, payload}` | `{t:'send', to, id, body}` | `body` is base64; `to` may be `fingerprint@host:port` to reach another relay |
| `{type:'msg', ...}` pushed on delivery | `{t:'mail', pending:N}` then `{t:'fetch'}` → `{t:'drop'}` frames | **behaviour change, see below** |
| `{type:'ack', id}` | `{t:'ack', ids:[...]}` | takes a list |
| `{type:'sig', to, payload}` | `{t:'sig', to, body}` | unchanged in spirit; `to` may cross relays |
| `{type:'watch', pubs:[...]}` | `{t:'watch', ids:[...]}` | |
| `{type:'presence', state}` | `{t:'presence', state}` | |
| `{type:'ping'}` | `{t:'ping', nonce}` → `{t:'pong', nonce}` | |
| `GET /ice` | `GET /ice` or `{t:'ice'}` | same shape: `{iceServers:[...], ttl}` |
| `POST /blob` → `{id}` | `POST /blob` → `{ok, id, size, expires_at}` | id is now the full SHA-256 (64 hex, was 32) |
| `GET /blob/<id>` | `GET /blob/<id>` | |
| `POST /journal` → `{seq}` | `{t:'journal_append', data}` → `{t:'journal_ok', seq}` | now a WebSocket frame |
| `GET /journal?since=` | `{t:'journal_read', since, max}` → `{t:'journal', entries:[...]}` | `data` is base64 |
| `GET /usage` | `{t:'quota'}` → `{quota_bytes, used_bytes, ...}` | also in the `welcome` frame |
| `/admin/quota` + `X-Admin-Key` | `{t:'admin_set_quota'}` — no admin key | see "Owner panel" |
| `/admin/accounts` | `{t:'admin_accounts'}` | |
| `/admin/ttl` | not implemented | retention is relay-wide for now |

The WebSocket endpoint is `/ws` (or `/r2r`); connect with the subprotocol
`r2r.v1`. Every frame is a JSON text frame keyed on `t`.

### Two behaviour changes worth designing around

**Live delivery is not implemented yet.** The old relay pushed `msg` straight to
a connected recipient. The new one stores the payload and sends
`{t:'mail', pending:N}`; the client then sends `{t:'fetch'}` and receives `drop`
frames. Send `{t:'subscribe'}` after `hello` to get those notifications. From
the user's point of view a message still arrives immediately, but the client has
to do the fetch. There are also no `delivered` receipts yet. Both are on the
list; design the UI so adding them later is not a rewrite.

**Addressing can cross relays.** `to` accepts `fingerprint@host:port`. A contact
card should carry the fingerprint *and* the home relay, because a bare
fingerprint only resolves for identities registered on the relay you are talking
to. The home relay comes back in the `invite_ok` response when a user joins.

### What is unchanged

Calls still work the same way: `sig` carries opaque SDP and ICE candidates
between the two clients, `/ice` supplies STUN/TURN, and once the peer connection
is up audio and video flow **directly between the two browsers** and never touch
a relay. Nothing about the WebRTC layer needs redesigning — only the transport
the signalling rides on.

Message bodies, blobs and journal entries are still ciphertext the client
produces. The relay cannot read any of it and nothing in the new protocol
changes that.

### New things worth surfacing in the UI

- **Storage.** Each identity gets 1 MB by default. `welcome` carries
  `quota_bytes` and `used_bytes`, and `{t:'quota'}` asks any time. Show it, and
  show a clear message when `err: quota` comes back — the user has to ask their
  relay operator for more.
- **Invites.** Joining still burns a single-use UUID and returns three new ones.
- **Multi-hop privacy.** The network now supports onion routing: a message can
  be sealed for a chain of relays so no single one knows both ends. If you want
  to expose it, `{t:'onion', blob}` takes a layered sealed blob and each relay's
  x25519 key is published in `/peers.json`. Optional, and no UI exists for it.

---

## 3. The owner panel: rebuild it, do not delete it

The old screen asked the operator to paste an **admin key** that the relay
printed at startup. That key is gone, and nothing replaces it — there is no
shared secret in the new design at all.

Instead the relay keeps a list of identities that may administer it. The
operator names their own identity once, on the server:

```sh
sudo r2r-relay --owner-add <their 64-char fingerprint>
```

From then on the wallet's existing connection is already authorised, because it
proves that identity on every `hello`. So:

- **Remove the "paste your admin key" field entirely.** There is nothing to
  paste and no key to lose.
- **Show the panel when `welcome` contains `"owner": true`**, and hide it
  otherwise. That flag is the whole authorisation check the UI needs.
- If the operator has not been added yet, the panel is simply absent. Worth a
  line of help text: *"Ask the relay operator to run `r2r-relay --owner-add`
  with your fingerprint."*

Three frames drive the panel. All of them return `err: not_authorised` for a
non-owner — deliberately the same error whether or not the fingerprint exists,
so an arbitrary client cannot enumerate who owns a relay.

**List accounts** — `{"t":"admin_accounts","max":100,"offset":0}` returns

```json
{ "t":"admin_accounts", "default_quota_bytes":1048576, "offset":0,
  "accounts":[ { "id":"<fingerprint>", "home_relay":"1.2.3.4:8787",
                 "used_bytes":41231, "quota_bytes":1048576,
                 "custom_quota":false, "pending":3, "online":true,
                 "registered_at":1754331000, "last_seen":1754400000 } ] }
```

`used_bytes` is everything that identity stores — waiting messages, journal and
voice/video together — against the one `quota_bytes` allowance. Paging is
`offset`; `max` caps at 500.

**Change an allowance** — `{"t":"admin_set_quota","id":"<fingerprint>","mb":250}`,
or `"mb":null` to put them back on the relay default. Replies
`{"t":"admin_ok","action":"set_quota","id":…,"quota_bytes":…,"used_bytes":…,"custom":true}`.
Going over the limit refuses new payloads; nothing already stored is deleted,
so lowering an allowance is safe.

**Mint invites** — `{"t":"admin_invites","count":5}` replies
`{"t":"admin_invites","invites":[ "uuid", … ]}`. Useful: the operator can hand
out codes from their phone instead of reading a file over SSH.

`r2r-probe accounts`, `r2r-probe setquota <fp> <MB>` and `r2r-probe mkinvites`
are a working reference implementation of all three.

---

## 4. What to test first

1. Sign up with an invite code, from a browser, against `wss://r2r.homes/ws`.
2. Sign in again in a **fresh browser profile** with the same key and confirm
   the journal replays the history.
3. Send a voice message (upload a blob, reference its id in the message).
4. Place a call between two browsers, one of them behind mobile data.

Number 4 will need a TURN server configured on the relay — STUN alone does not
get through symmetric NAT, and that is the most likely reason a call fails.
