# R2R relay

A privacy-first peer-to-peer messaging relay, written in C++20 on Boost.Beast
with a statically linked SQLite3.

One process serves two ports with the same application logic behind them:

| Port | Protocol | Who uses it |
|---|---|---|
| 8787 | `ws://` + HTTP | relay-to-relay gossip, desktop and file clients on trusted networks |
| 8788 | `wss://` + HTTPS | remote clients, browsers, anything crossing a hostile network |

A relay accepts encrypted payloads it cannot read, holds them for seven days,
forwards what belongs to another node, and gossips a peer list so the network
can find itself. It collects no personal data and writes no IP addresses
anywhere — not to disk, not to the log.

---

## What the relay knows, and what it does not

Being explicit about this matters more than any feature list.

**It never learns:**

- message contents — payloads arrive as ciphertext produced by the client, and
  nothing in this codebase can decrypt them;
- who is talking to whom, when onion routing is used — an intermediate hop sees
  only its predecessor and its successor;
- any IP address, in any durable form. Remote addresses are never written to
  the database, never logged, and never retained after a socket closes. Inbound
  connections are identified in logs by a random per-connection id that is
  discarded on disconnect.

**It does learn, and you should design around it:**

- the recipient fingerprint of every payload it stores. A dead drop has to be
  filed under something. The *terminal* relay of an onion route learns this too;
  the hops before it do not.
- coarse liveness: `identities.last_seen` is rounded down to the hour, which is
  enough to expire dormant rows and too coarse to be a presence log.
- peer relay addresses. These are public infrastructure, published in
  `peers.json` on purpose.

**Out of scope for a relay:** traffic analysis by a global passive observer.
Message sizes, timing and connection patterns are visible to whoever watches the
wire. Padding and cover traffic belong in the client.

---

## Building

Needs a C++20 compiler, CMake ≥ 3.16, OpenSSL ≥ 1.1.1 and Boost ≥ 1.74 headers
(Beast and Asio are header-only — no compiled Boost libraries are linked).
SQLite is vendored in `third_party/sqlite3` and always linked statically.

```sh
sudo apt install -y build-essential cmake ninja-build libssl-dev \
                    libboost-dev nlohmann-json3-dev

cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

> **On a small VPS, build with `cmake --build build -j 1`.** Instantiating the
> Beast templates for both the plain and TLS stream types costs roughly 1.5 GB
> per translation unit; two parallel jobs will get the compiler OOM-killed on a
> 2 GB droplet.

Useful options: `-DR2R_BUILD_PROBE=OFF` (skip the diagnostic client),
`-DR2R_ASAN=ON` (sanitizers), `-DR2R_STATIC_CXX=OFF` (link libstdc++
dynamically; it is static by default so the binary is portable across distros).

Verify the result end to end — two relays, both protocols, the dead drop,
invites, the bridge and a two-hop onion route:

```sh
./scripts/smoke-test.sh
```

## Installing

```sh
sudo ./scripts/install.sh 203.0.113.10:8787   # the address peers should dial
```

That creates the `r2r` service user, installs `/usr/local/bin/r2r-relay`, lays
out `/etc/r2r` and `/var/lib/r2r`, generates a self-signed certificate if none
exists, and enables the systemd unit. The script checks that the binary it
finds (in `./build`, or next to itself) is built for the machine it runs on;
with none at hand it downloads the published `r2r-relay-$(uname -m)` and
verifies it against the SHA-256 the origin lists. The unit is sandboxed: no capabilities,
`ProtectSystem=strict`, and write access to `/var/lib/r2r` only.

Certificates live at `/etc/r2r/tls/cert.pem` and `/etc/r2r/tls/key.pem`. If the
pair is missing the relay logs a warning and runs `ws://`-only rather than
refusing to start — a node with no certificate is still a useful gossip and
forwarding participant.

**The private key is deliberately unreadable except to the relay's own user.**
`/etc/r2r/tls` is `0750 root:r2r` and the key is `0640 root:r2r`, and the
systemd unit sets both `User=r2r` and `Group=r2r` so the service runs with that
group. A login shell whose primary group is something else — which is the normal
case, since `install.sh` reuses an existing account rather than changing its
groups — cannot read the key, and `r2r-relay` started by hand from that shell
will report the key as unreadable and start `ws://`-only.

That is working as intended, not a fault, and the fix is **not** to copy the key
somewhere more permissive. Either start the relay through systemd, or for a
hand-run test point `--cert` and `--key` at a throwaway pair you generated
yourself:

```sh
openssl req -x509 -newkey rsa:2048 -days 1 -nodes -subj /CN=local \
    -keyout /tmp/t/key.pem -out /tmp/t/cert.pem
r2r-relay --data-dir /tmp/t --cert /tmp/t/cert.pem --key /tmp/t/key.pem
```

The first run mints five invite codes into `/var/lib/r2r/genesis-invites.txt`
(mode 0600). They are deliberately **not** written to the log. Mint more at any
time with `r2r-relay --mint-invites 10`.

## Deployment topology

Every node runs the same binary with the same unit file and the same two ports.
The central node (`r2r.homes`) adds two host-specific pieces on top; the relay
itself is not configured differently there.

```
                 browser / client
                        |
                   Cloudflare edge          (terminates TLS, proxies 443 only)
                        |  443
              +---------v---------+
              |      nginx        |  static portal + reverse proxy
              +---------+---------+
                        |  127.0.0.1:8787
              +---------v---------+          8787/8788
              |    r2r-relay      | <--------------------> other seed relays
              +---------+---------+
                        |  SQLite (authoritative)
              +---------v---------+
              | metrics-sync (1/min)
              +---------+---------+
                        |  unix socket
                   MariaDB  (dashboard reads only)
```

**Why nginx rather than binding 443 in the relay.** The relay must keep serving
8787/8788 regardless — Cloudflare cannot proxy those ports, so relay-to-relay
traffic bypasses the CDN entirely. Binding 443 natively would therefore mean a
third listener, `CAP_NET_BIND_SERVICE` punched through an otherwise
capability-free unit, and a change to the C++ HTTP router so a static portal
could live at `/` where the status page currently is — a code change shipped to
every seed to solve a problem only one host has. nginx keeps the relay identical
everywhere and does static files properly. Deploy `deploy/nginx-r2r.homes.conf`;
since 2026-08-31 nginx proxies everything to the relay, which serves the site
itself from the doorway bundle (see below). `web/index.html` is the retired
static portal.

### The doorway site

The web site is a template bundle the relay serves from `/var/lib/r2r/doorway`
(`--doorway`). Its editable source is `web/doorway/`:

```
web/doorway/templates/en/*.html   one file per page; {{HOST}}, {{BASE}}, {{SCHEME}} are substituted at request time
web/doorway/i18n/*.json           37 language catalogs for the server-rendered pages (/redeem, /m)
web/doorway/assets/               sippis-shell.css, logo, favicon, js/
```

Any extra `templates/<lang>/<name>.html` is served at `/<name>` (lower-case
`[a-z0-9-]`, relay routes such as `/status` cannot be shadowed), so a bundle
revision can add a page without a relay release. `/paper` is generated from
`../protocol/R2R-WHITEPAPER.md` by `tools/build-paper-page.py`. After editing:

```sh
python3 tools/build-paper-page.py             # only when the white paper changed
python3 scripts/build-doorway-bundle.py        # manifest + deploy/r2r-doorway-bundle.zip + docs/translations.zip
sudo python3 scripts/build-doorway-bundle.py --install && sudo systemctl restart r2r-relay
```

The manifest hash versions every asset URL (`?v=…`), so caches roll over on
each bundle. `install.sh` fetches the bundle from `https://r2r.homes/assets/`
on fresh installs.

**Two things about that edge are worth being deliberate about.**

*nginx must not log.* The config sets `access_log off` and never sets
`X-Forwarded-For` or `X-Real-IP`. Turn either back on and the client addresses
this whole design avoids retaining start landing in a file on disk. With it off,
a client address exists nowhere but kernel socket state.

*Cloudflare can see the bridge traffic.* `wss://r2r.homes/ws` is convenient and
works from a browser, but TLS terminates at the CDN edge, so Cloudflare observes
frame timing, sizes and recipient fingerprints — everything except payload
contents, which stay end-to-end ciphertext. Clients that care about metadata
should connect straight to `wss://<ip>:8788`, which the portal advertises
alongside the bridge. Relay-to-relay links never touch Cloudflare.

## The dashboard database

The relay stays on SQLite. A one-minute systemd timer
(`r2r-metrics-sync.timer`) reads the aggregate counters the relay already
publishes and writes them to MariaDB, where the frontend can run whatever
queries it likes without a second process touching a live relay's database.

```sh
sudo mariadb < deploy/mariadb-schema.sql
sudo install -m0755 scripts/r2r-metrics-sync.py /usr/local/bin/r2r-metrics-sync
sudo install -m0644 systemd/r2r-metrics-sync.* /etc/systemd/system/
sudo systemctl enable --now r2r-metrics-sync.timer
```

It polls `/status.json` on this node *and every peer in the table*, so
`node_directory` and `network_summary` describe the whole network, not just the
local relay. Authentication is MariaDB's `unix_socket` plugin — the identity is
the OS user, so there is no password on disk. The web tier gets `r2r_dash`,
which has `SELECT` and nothing else.

Tables: `node_metrics` (time series, 30-day retention), `node_directory`
(current state per relay), `network_summary` (single-row rollup for the front
page), `sync_runs` (so a silently dead timer is visible).

**It reads the HTTP endpoint rather than opening `r2r.db` directly.** That
avoids a second reader on a WAL database — no lock contention on the message
path, no `-shm`/`-wal` permission problems — and means the syncer *cannot* read
message rows even by accident, because the endpoint does not expose them. If
the dashboard needs an aggregate that is not published yet, add it to
`/status.json` rather than pointing a second process at the database file. Only
the explicit whitelist in `METRIC_FIELDS` is copied: counters and gauges, never
fingerprints, payloads, invite codes or addresses.

### What porting the relay itself to MariaDB would take

Roughly a week of work and a permanent operational tax, which is why it is not
the recommended path. The storage layer is well isolated — `src/db.hpp` exposes
no SQLite types, so callers would not change — but `db.cpp` is ~600 lines that
are SQLite-specific throughout: `INSERT … ON CONFLICT` becomes
`ON DUPLICATE KEY UPDATE`, `WITHOUT ROWID` has no equivalent, the `rowid` fetch
cursor needs an `AUTO_INCREMENT` column, `PRAGMA`s go away, `sqlite3_changes()`
becomes `mysql_affected_rows()`, and the single-connection-plus-mutex model has
to become a pool with reconnection and retry.

The real cost is architectural. A relay is a P2P node: today it needs a
directory and nothing else, which is what makes a seed node a single binary and
a systemd unit. Requiring every node to run and maintain a database server to
hold its dead drops is a large regression in operability for a network meant to
grow by people standing up relays. And it is on the hot path — a local SQLite
write is microseconds, a MariaDB round trip is a fraction of a millisecond, per
stored payload. Keep MariaDB where it is genuinely better: aggregate reporting
for a dashboard, on one machine.

## Configuration

Every option has an `R2R_*` environment equivalent; `/etc/r2r/relay.env` is the
usual place for them. `r2r-relay --help` prints the full list.

| Option | Default | Notes |
|---|---|---|
| `--advertise HOST:PORT` | *(none)* | The address this relay publishes. **Without it, peers cannot route to this node** — it can still dial out, gossip and serve local clients. |
| `--ws-port` / `--wss-port` | 8787 / 8788 | |
| `--cert` / `--key` | `/etc/r2r/tls/*.pem` | |
| `--no-tls` | off | Skip the `wss://` listener entirely. |
| `--data-dir` | `/var/lib/r2r` | Holds `peers.json`, `r2r.db`, `node.key`. |
| `--ttl-days` | 7 | Dead-drop retention. |
| `--peer-dial-target` | 8 | Outbound relay links to maintain. |
| `--allow-private-peers` | off | Accept and dial peers on loopback, private and link-local ranges. For test benches only; a public relay must never be told to dial its own network. Env `R2R_ALLOW_PRIVATE_PEERS=1`. |
| `--max-payload` | 262144 | Largest single payload, in bytes. |
| `--assets PATH` | *(none)* | Publish a directory under `GET /assets/`. |
| `--open-registration` | off | Register identities without an invite code. Identities are still recorded and callers still receive three codes, so one client works against either kind of relay. |
| `--peer-tls-verify` | off | Require a CA-valid certificate from `wss://` peers. See "Why relays do not verify each other's certificates" below. |
| `--user NAME` | *(none)* | Drop privileges after binding, if started as root. |

## HTTP endpoints

Served on both ports.

| Route | Purpose |
|---|---|
| `GET /` | Status page: active nodes, uptime, payloads held, frames relayed. |
| `GET /peers.json` | The verified peer list. This is the bootstrap file — new nodes fetch it. |
| `GET /node.json` | This node's id and public keys. |
| `GET /status.json` | Machine-readable counters. |
| `GET /health` | Liveness probe. |
| `GET /invite/check/<uuid>` | Is this code still open? Does **not** burn it. |
| `POST /invite/claim` | Burn a code, register an identity, receive three new codes. |
| `GET /assets/` | Manifest of published files: name, size, SHA-256. Requires `--assets`. |
| `GET /assets/<name>` | The file itself, with its digest in `X-Content-Sha256`. |

`--assets DIR` turns any relay into a distribution point for client binaries.
Only regular files directly inside `DIR` are reachable — the request name must
be a single safe component, so there is nothing to traverse out of — and files
above `--max-payload`-independent 64 MiB are omitted. Digests are computed once
and re-used until the file changes, so a client can verify a download without
making the relay re-hash on every request.

All JSON routes send `Access-Control-Allow-Origin: *` so a browser client can
bootstrap, and `Cache-Control: no-store` so nothing lingers in an intermediary.

## The wire protocol

Every frame is a JSON text object with a `t` field. Binary data travels
base64-encoded inside it, so one protocol serves browsers, native clients and
other relays with no content negotiation. Frames are capped at 1 MiB and each
connection gets a token bucket (40 frames/second, burst 120).

**Client to relay**

| `t` | Fields | Effect |
|---|---|---|
| `hello` | `role:"client"`, `id` | Announce an identity. Answered with `welcome`. |
| `send` | `id`, `to`, `body`, `hint?`, `hops?` | Store or forward one payload. |
| `fetch` | `since?`, `max?` | Collect waiting payloads. |
| `ack` | `ids[]` | Delete collected payloads. |
| `subscribe` | — | Receive `mail` notifications while connected. |
| `onion` | `blob`, `hops?` | Submit a sealed route. |
| `invite_claim` | `code`, `id`, `pubkey?`, `home_relay?` | Burn an invite. |
| `ping` | `nonce?` | Answered with `pong`. |

**Relay to client**

`welcome` (signed, carries the node's keys), `sent`, `drop`, `fetch_done`,
`mail`, `invite_ok`, `pong`, `err`.

**Relay to relay** adds `hello`/`welcome` with `role:"relay"` and an ed25519
signature, plus `peers_req` / `peers` for gossip.

An `err` frame is always terminal: a relay never answers an error with another
error. This is not a stylistic rule. Two nodes that each reply "I don't
recognise that" to the other's reply will saturate the link between them —
during development this produced 2.4 million frames on an idle pair of relays
before anything else was noticed.

### Fetching correctly

`fetch` returns a `seq` on every `drop` and a `cursor` in `fetch_done`. **`seq`
is the only safe cursor.** Timestamps are not: two payloads stored in the same
second would make a timestamp-based client skip one. Acknowledging is
authoritative — an acked payload is deleted, so `since: 0` is always correct.

### Identity is proved, never asserted

A client identity is an ed25519 key. Its fingerprint is
`SHA-256("r2r-id-v1" || public_key)`, and binding a connection to that mailbox
requires a signature:

```json
{ "t":"hello", "role":"client",
  "id":"<fingerprint>", "pubkey":"<base64 ed25519>",
  "ts":1754331000, "nonce":"<hex, 16-64 chars>",
  "sig":"<base64 ed25519 over the string below>" }
```

The signed string is `"r2r-client-v1\n" + fingerprint + "\n" + ts + "\n" + nonce`,
and the relay checks three things: the timestamp is within ten minutes, the
fingerprint really is the hash of the presented key, and the signature verifies
under that key. Any failure leaves the session anonymous and `fetch` refuses to
run.

**Sending does not require an identity.** Anyone may leave a payload for a
fingerprint; only the holder of the matching key can collect it. The same proof
is required to claim an invite, because registering a home relay for someone
else's fingerprint would silently redirect their mail.

`r2r-probe --key <file> whoami` creates a key and prints its fingerprint.

### Per-user storage the owner controls

Every identity gets `--default-quota-mb` (default 1 MB, matching the previous
relay's `DEFAULT_QUOTA_MB`). When a user asks for more, the operator raises it
without restarting anything — the admin commands open the same SQLite database
the running relay uses, which WAL mode makes safe:

```sh
r2r-relay --set-quota <fingerprint> 250     # give this user 250 MB
r2r-relay --list-quotas                     # every individual allowance
r2r-relay --clear-quota <fingerprint>       # back to the relay default
```

Only exceptions are stored, so the table stays small however many identities
register. Clients see their own allowance in the `welcome` frame
(`quota_bytes` / `used_bytes`) and can ask any time with `{"t":"quota"}`.
Going over the limit refuses new payloads with `err: quota`; nothing already
stored is deleted.

### Addressing

A recipient is a fingerprint, optionally qualified with a home relay:

```
5f3a…e91c                       # this relay, or wherever it is registered
5f3a…e91c@203.0.113.10:8787     # explicitly, on that relay
```

When the relay is unqualified, the node looks the fingerprint up in its own
`identities` table and forwards to the registered home relay if it is not this
one. Home relays are recorded at invite time and are **not** gossiped — the
network deliberately has no global directory of who lives where. Clients learn
their own home relay from the `invite_ok` response and share the qualified form
out of band, the same way they share the fingerprint itself.

If the destination relay is not currently linked, the frame is queued and the
node dials it — retrying every 15 seconds for five minutes, and flushing the
queue the moment a link appears in *either* direction. Only after that grace
period is the frame given up on, with a warning in the log. If forwarding is
impossible outright (nowhere to dial), the relay keeps the payload locally
instead of dropping it; the recipient can still collect it by asking this node
directly.

## The wss-to-ws bridge

The outgoing hop's protocol is decided by the *peer*, never by how the payload
arrived. A frame that entered over `wss://` leaves over `ws://` when the next
relay only speaks plaintext. That is the intended behaviour: it lets a
TLS-terminating edge node serve remote clients while the mesh behind it runs
plain WebSocket.

What this costs: on a `ws://` hop a network observer sees the routing metadata —
recipient fingerprint and destination relay. It never sees message contents,
which are ciphertext end to end. If that trade is wrong for your deployment, run
peers on `wss://` and the bridge never engages.

## Onion routing

Every relay publishes an x25519 key in `peers.json`. A route is a list of
positions; each position names 1–3 candidate relays, any of which can open its
layer (format v2):

```
layer     0x02 ‖ n ‖ n × seal(candidate_i, K)[93] ‖ nonce[12] ‖ AES-256-GCM(K, plaintext)
routing   0x01 ‖ n ‖ n × (len8 ‖ "host:port") ‖ inner layer      -- candidates for the next position
terminal  0x02 ‖ len16 ‖ {"to":"fp@home","id":"…"} ‖ body          -- store, or forward to home
```

`seal` is an anonymous sealed box: ephemeral x25519 → HKDF-SHA256 →
AES-256-GCM, with the recipient's public key bound in as additional data. A
relay opens its own layer and learns the socket it arrived on and the
candidates for the next position -- not the sender, not the recipient, not how
many hops remain. It forwards to the first candidate it can reach, moving on at
once when a dial fails; a terminal *standby* forwards to the recipient's relay
named in `to`, or parks the payload with a pointer if that relay is down.

A relay stays **silent** when it accepts a layer. Acknowledging would tell the
previous hop that the route ended here, which is precisely what the construction
hides. Only failures travel back.

Loops are prevented by a hop counter and by a 15-minute cache of blob digests.
`r2r-probe onion` builds real routes (`|` separates alternatives):

```sh
r2r-probe --url ws://relay-a:8787 --http http://relay-a:8787 \
          --hops relay-a:8787,relay-b:8787\|relay-c:8787,relay-d:8787 \
          onion <recipient-fingerprint> "message"
```

The wallet sends every stored payload this way by default; see
`../protocol/R2R-WHITEPAPER.md` §10.

## Invite codes

Registration is closed by default. A code is a v4 UUID, single use, burned
inside one `BEGIN IMMEDIATE` transaction together with the identity
registration and the minting of exactly three successors — so a race between two
claimants has exactly one winner, and a failed claim mints nothing.

```sh
curl -X POST https://relay:8788/invite/claim -H 'Content-Type: application/json' \
     -d '{"code":"<uuid>","id":"<fingerprint>","pubkey":"<base64>"}'
```

Burned codes are kept forever — a UUID and a timestamp, no personal data — so a
code can never be replayed. Run with `--open-registration` to accept anyone;
identities are still recorded, and clients still receive three codes, so the
same client works against either kind of relay.

## peers.json and gossip

On first start the peer table is seeded from six bootstrap nodes compiled into
the binary. `peers.json` is rewritten atomically every five minutes with the
pruned, verified list, and read back on restart. A hand-written file may be a
plain array of `"host:port"` strings; the relay upgrades it to the full form on
the next write. Seed entries are never pruned away, however long they stay
unreachable.

Every 60 seconds the node swaps peer lists with a few random connected relays;
every 30 seconds it pings its links. A peer is pruned after five consecutive
failures and an hour without contact.

### Peer authentication

A relay's identity is an ed25519 key derived from `node.key`, a single 32-byte
seed. Its `hello` carries `node_id`, advertised address, timestamp, nonce and a
signature over all of them, and `node_id` is itself a hash of the public key —
so a node cannot claim an id it has no key for.

Anyone with a key may open a relay session; there is no allowlist. What a
session may *do* depends on whether this relay has verified it, and
**verified means "this relay dialled the advertised address and the node
answering there proved that key"**. A signed hello arriving on an inbound
connection proves that someone holds a key, not that a relay lives at the
address it names, so:

- The advertised address is recorded as an unverified claim. The peer manager
  dials it on its own timer — at most two such verification dials every 15
  seconds, over the whole table — and only a matching handshake there marks it
  verified.
- Only verified relays are published on `/peers.json`, gossiped onward, counted
  as active and used as rendezvous nodes.
- A `peers` list is accepted only from a verified relay, and one session may
  add at most 64 new addresses. Lists from anyone else are ignored, so a
  self-signed session cannot make this relay open connections to addresses of
  its choosing.
- Addresses on loopback, private, link-local, CGNAT and other non-routable
  ranges are refused wherever they come from: peers.json, a hello, gossip, or a
  client's `fingerprint@host:port` destination. Hostnames are checked again
  after DNS resolution. `--allow-private-peers` turns this off for test benches.

The first verified handshake pins the key against the address in `peers.json`;
a later handshake presenting a different key for a pinned address is rejected
as impersonation, and any inbound session that was squatting on that address
with another key is closed. Keys seen in gossip or in an unverified hello are
hints only: they can never lock a genuine relay out of its own address, and they
are replaced by whatever the address itself proves when dialled. A `peers.json`
written by a build older than 1.0.1 has its `verified` flags cleared on load,
since under the old rules a claim alone could set them.

### Why relays do not verify each other's certificates

Relays run self-signed certificates, so chain validation would fail everywhere
or force a CA dependency onto every operator. Instead TLS provides transport
encryption and the ed25519 pin above provides identity — which is strictly
stronger than a certificate for this purpose, because it binds the *node*, not
the hostname. Set `--peer-tls-verify` if your deployment issues real
certificates to every relay.

## Operations

- Expired payloads are swept every 15 minutes; `secure_delete` is on, so freed
  pages holding ciphertext are overwritten.
- Each recipient's mailbox is capped at 4096 payloads and 64 MiB. Over that, new
  payloads are refused with `err: quota` rather than silently dropped.
- The database runs in WAL mode. `SIGTERM` checkpoints and closes it cleanly.
- Logs go to stdout for journald. `--log-level debug` is safe to leave on: the
  privacy contract at the top of `src/log.hpp` binds every call site.

## Layout

```
src/
  main.cpp          startup, signals, privilege drop
  config.*          defaults, environment, command line
  crypto.*          node identity, ed25519 signing, x25519 sealed boxes
  db.*              SQLite: drops, invites, identities
  peers.*           peer table and peers.json
  hub.*             routing, dead drops, gossip, invites -- transport-blind
  ws_channel.hpp    WebSocket pump, templated over plain/TLS stream
  http_session.hpp  inbound connection: upgrade to WebSocket or answer HTTP
  http_routes.*     the HTTP endpoints
  listener.*        acceptor, one per port
  peer_manager.*    outbound links, health, gossip and persistence timers
  onion.*           layer format, sealing and peeling
tools/probe.cpp     r2r-probe diagnostic client
```

The one structural idea worth knowing: `Hub` never sees a socket, only the
`Connection` interface. `WsChannel<Stream>` is instantiated once for
`beast::tcp_stream` and once for `beast::ssl_stream`, and everything above that
line is written exactly once. That is why the two ports cannot drift apart in
behaviour, and why the bridge is a property of the peer table rather than a
special case in the routing code.

## Migrating from the previous relay

The previous relay shipped in four interchangeable implementations (PHP,
Python, Node and a compiled binary), all installed as
`/etc/systemd/system/r2r-relay.service` with the application at
`~/relay-server.*` and data at `~/r2r-relay-data`. `scripts/find-old-relay.sh`
identifies which one a host is running, prints the exact application and data
paths, and with `--purge --yes` stops it and removes both — archiving the data
directory to `/var/backups/r2r` first, because users' stored messages, voice
notes and video live there.

The old environment block is honoured directly, so a carried-over unit keeps
working: `PORT`, `DATA_DIR`, `DEFAULT_QUOTA_MB`, `QUEUE_TTL_DAYS` and
`BLOB_TTL_DAYS` are all read. (There is one retention setting here rather than
two: payloads are opaque, so this relay cannot tell a voice note from a text
message. The longer of the two values wins.)

### Capability gap

`../legacy-v1/relay-server.js` is the readable reference for what the previous relay
did.

| Capability | Previous relay | Here |
|---|---|---|
| ed25519 identity proof | yes | yes |
| Offline message queue | `queue/<pub>.json`, 500 cap | SQLite dead drops |
| Per-account quota, owner-adjustable | `POST /admin/quota` | `--set-quota` |
| WebRTC signalling | `sig` relayed between peers | `sig`, and across relays |
| ICE/TURN configuration | `GET /ice` | `GET /ice`, or the `ice` frame |
| Presence / watch lists | online, away, offline, last-seen | same |
| Blobs for voice and video | `POST /blob`, 17 MB | `POST /blob`, 24 MB, deduplicated |
| Per-account message journal | `POST`/`GET /journal` | `journal_append` / `journal_read` |
| Peer gossip, onion routing, invites | no | yes |
| **Live delivery to an online recipient** | `msg` pushed immediately | **no** — a `mail` notification, then `fetch` |
| **Delivery receipts** | `delivered` to the sender | **no** |
| **Per-account TTL** | `POST /admin/ttl` | relay-wide only |
| Admin interface | HTTP + `admin.key` | CLI on the host |

Three rows are still open. Live delivery is the one users would notice: a
recipient who is connected gets told mail is waiting and has to ask for it,
rather than being handed it.

## Calls, voice messages and history

These are the parts that make it a messenger rather than a mailbox.

**Calls never touch the relay.** `sig` carries opaque WebRTC offers, answers and
ICE candidates between two clients; `GET /ice` (or the `ice` frame) hands out
the STUN and TURN servers they need to find each other. Once the peer
connection is up, audio and video flow directly between the two ends. The relay
sees the negotiation and none of the call.

Signalling routes across relays: address the peer as `fingerprint@their.relay`
and it is forwarded the same way a message would be. If the peer is not
connected, the sender gets `err: not_online` — there is nothing useful to store
for a call.

```sh
r2r-relay --turn turn:turn.example.org:3478 --turn-user U --turn-pass P
```

**Without a TURN server, calls between two symmetric NATs will fail to
connect.** STUN alone is not enough for a meaningful share of real networks.
The previous relay had the same three settings and they are read from the
environment too, so a carried-over unit keeps working.

**Presence** is `watch` with a list of fingerprints; the relay replies with
`presence` for each and pushes updates as those identities come and go. It
covers identities on this relay — for someone on another relay, place the call
and let it fail.

**Voice and video messages** go over HTTP, not WebSocket frames, because they
are far too big for one: `POST /blob` up to `--max-blob` (24 MB by default),
`GET /blob/<id>` to fetch. The id is the SHA-256 of the content, so the same
recording sent to five people is stored once, and a client can verify what it
downloaded. Both ends authenticate with an `X-R2R-Auth` header carrying the
same signed proof the `hello` frame uses.

**History** is the `journal`: an append-only log of ciphertext the client writes
about its own conversations. Signing in from a new browser means replaying it
with `journal_read` from sequence 0. `journal_append` returns the sequence
number; entries are capped at 640 KB each and paged 200 at a time.

All three count against the same per-user allowance, so `--set-quota` governs
messages, recordings and history together.

## One binary

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DR2R_STATIC_SSL=ON
cmake --build build
ldd build/r2r-relay        # libc and the loader, nothing else
```

SQLite, OpenSSL and libstdc++ are all linked in: a single file that runs on
any glibc Linux of the same or older vintage. Copy it to a machine and start
it. It needs `libzstd-dev libjitterentropy3-dev zlib1g-dev` present at
*build* time (Ubuntu's static libcrypto depends on them); CMake says so
explicitly if they are missing. This is the quick local variant; the files
other operators download are the fully static cross builds below.

### Other architectures: fully static builds

The published binaries are not the build above. They come from
`toolchain/build-cross.sh`, which uses [zig](https://ziglang.org) as a C/C++
cross compiler (clang plus musl, one apt package) and produces a fully static
binary per architecture — no glibc version requirement at all, so the same
file runs on Ubuntu 18.04 and on tomorrow's Fedora:

```sh
sudo apt install -y zig cmake libboost-dev nlohmann-json3-dev perl
toolchain/build-cross.sh                      # x86_64 and aarch64
toolchain/build-cross.sh armv7l riscv64       # the other two, if wanted
ls dist/                                      # r2r-relay-<arch>, r2r-probe-<arch>, SHA256SUMS
```

Targets are named after `uname -m` on the machine that will run them, which
is how `install.sh` picks the right file. OpenSSL is built once per target
into `toolchain/sysroot/` (about ten minutes each); Boost and nlohmann_json
are header-only and come from the host. Static glibc would have lost hostname
resolution (NSS plugins cannot be loaded into a static binary); musl resolves
names from `resolv.conf` directly, so nothing is lost.

To test a foreign build on the build host, `apt install qemu-user-binfmt`
and run the smoke test against it — see the `RELAY_A`/`RELAY_B` note at the
top of `scripts/smoke-test.sh`. The plain `r2r-relay` published at
`/assets/` is the x86_64 file under its old name.

Windows is not covered: `src/util.cpp` uses `unistd.h`, `dirent.h` and
`fchmod`, and `main.cpp` drops privileges through `setuid`.

## What the relay deliberately does not do

- **Encrypt messages.** Payloads must already be ciphertext when they arrive.
  The relay is a dead drop, not a key server; `r2r-probe send` writes plaintext
  precisely because it is a wire probe, not a client.
- **Distribute public keys.** `identities.pubkey` is stored if a client offers
  one, but nothing verifies it. Key exchange belongs out of band.
- **Resist traffic analysis.** See the top of this file.
