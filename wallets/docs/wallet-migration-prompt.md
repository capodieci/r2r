# Wallet change request: migrate to the R2R relay network protocol (v2)

**To:** the wallet design project (`R-2-R Chat & Calls` / `app/core.js`)
**From:** the relay session (C++ relay at `~/r2r-relay`, binary `r2r-relay`)
**Format:** per WALLET-GUIDE.md §11 — (a) protocol delta, (b) implementation status, (c) required wallet behavior, (d) backward compatibility.

**Why.** The relay was reimplemented as a peer-to-peer *network* (single C++ binary replacing the five reference servers). Messages now route between relays, mail parked on the wrong relay is discoverable, and consolidation is a signed one-liner. Every behavior in this document is **implemented and shell-testable today** — nothing here is speculative. Reference test tools ship with the relay (`r2r-probe`), and the relay's embedded `/admin` page contains a browser-verified JS implementation of the new auth (view its source: the "crypto core" block).

---

## (a) Protocol delta

### a.1 Identity: the address is now the fingerprint

- **Account id = fingerprint** = lowercase hex of `sha256("r2r-id-v1" ‖ ed25519_pubkey)` — 64 hex chars. It is *not* the raw pubkey hex any more.
- Contacts, message targets, watch lists, admin targets: all fingerprints.
- The shareable `R2R_…` base32 id should keep encoding the **pubkey** (+checksum) exactly as today — the fingerprint is derived from it locally, and the pubkey is still needed for e2e crypto. No format change; only the derived address changes.
- Message ids MUST be UUID v4 (`crypto.randomUUID()` shape). The current 16-hex `newId()` is **rejected** by the relay.

### a.2 Connect and authenticate (replaces `GET /ws?pub&ts&sig` + `R2R-AUTH|ts`)

Open a WebSocket to `wss://host[:8788]/ws` (any path works; through a reverse proxy use `<base>/ws`). Then send a `hello` **frame**:

```json
{"t":"hello","id":"<fp>","pubkey":"<b64 ed25519 pub>","ts":<unix>,
 "nonce":"<16..64 chars>","sig":"<b64>"}
```
`sig` = ed25519-detached over the UTF-8 string `"r2r-client-v1\n" + fp + "\n" + ts + "\n" + nonce`. Clock skew ±600 s.

Reply — `welcome`:
```json
{"t":"welcome","you":"<fp>","pending":N,"ttl_days":7,"max_payload":262144,
 "peers":N,"quota_bytes":N,"used_bytes":N,"owner":bool,"push":true,
 "node_id":"…","proto":1, …}
```
`owner:true` ⇒ show the relay-owner panel. `push:true` ⇒ live delivery available (feature-detect, see a.4).

**HTTP auth** (blobs, ICE): header `X-R2R-Auth: base64(JSON{id,pubkey,ts,nonce,sig})` — same fields, same signing string.

All frames use `"t"` as the type key (was `"type"`).

### a.3 Registration is invite-gated (new)

A fresh identity registers by claiming an invite:
```json
→ {"t":"invite_claim","code":"R2R-XXXX-XXXX-XXXX", …hello proof fields…,
   "home_relay":"host:port"?}
← {"t":"invite_ok","invites":["R2R-…","R2R-…","R2R-…"],"home_relay":"…","node_id":"…"}
```
- Codes: `R2R-` + Crockford base32 groups; hinted form `R2R-AAAA-BBBB-XXXX-XXXX-XXXX` embeds the minting relay's IPv4 (first 8 hex chars). Legacy lowercase UUIDs remain claimable. Canonical share URL: `https://<relay>[<base>]/<code>`.
- Errors: `invite_invalid`, `invite_used`, `invite_revoked`.
- **Setup cards / locator accounts work unchanged**: `R2RSC1:<cardKeyHex64>:<ws-url>` (two fields — drop the old third `bot_pub` field). The journal works for any hello-proved key without registration, so the wrong-PIN-looks-like-new-user invariant holds. Relays may enforce quota defaults (1 MB) on unregistered identities.

### a.4 Messaging (replaces push `msg` + `delivered`)

| Action | Frame |
|---|---|
| send | `{"t":"send","id":"<uuidv4>","to":"<fp>" or "<fp>@host:port","body":"<b64 ciphertext>","hint":"<opaque ≤128>"?}` → `{"t":"sent","id","status":"stored"\|"forwarded"\|"duplicate", …}` |
| subscribe | `{"t":"subscribe","push":true}` → `{"t":"mail","pending":N}` |
| live delivery | `{"t":"drop","id","seq","body","hint"?,"created_at","expires_at"}` pushed as mail arrives (only with `push:true`) |
| catch-up | `{"t":"fetch","since":<seq>,"max":N}` → `drop`× then `{"t":"fetch_done","count","cursor","more"}` |
| ack | `{"t":"ack","ids":["<uuid>",…]}` → `{"t":"ack_ok","removed":N}` — ack **only after decrypt + persist**; unacked drops are redelivered by fetch, so a missed push loses nothing |
| notify | `{"t":"mail","pending":N}` still arrives on store (harmless alongside push) |

- Sending to `fp@host:port` routes across relays; a bare `fp` is stored where the relay thinks best and **found via pointers** (a.5).
- **`delivered` receipts no longer exist.** Implement read/delivered state client-side (an encrypted ack inside a reply payload) — more honest end-to-end anyway. `sent{status}` still drives the single-check.
- `from` on old `msg` frames is gone; the sender's identity rides **inside** your encrypted payload (you already carry `rr`; add the sender fp the same way if not present).

### a.5 Discovery: pointers and `locate` (new — this fixes lost messages)

Mail parked for you on a relay that isn't your home emits a signed **pointer** toward your home relay (or your rendezvous relays). To ask "where is my mail?":

```json
→ {"t":"locate"}
← {"t":"located","pending":N,"pointers":[{"address":"1.2.3.4:8787","count":N,"ts":…}]}
```
Live nudge while connected: `{"t":"mail_at","address":"…","count":N}`.

Wallet behavior: `locate` after every connect; for each pointer either fetch directly (short authenticated WS to that address, `fetch`+`ack`) **or use consolidation (a.6)**. Rendezvous set (for advanced use): the 3 lowest `sha256("r2r-rdv-v1"+fp+node_id)` over the verified peers in `/peers.json` — the same list the relay computes.

### a.6 Consolidation: safe deposit (new)

One frame gathers your mail home. For each holding relay, sign a **single-use, holder-bound** authorization:

signing string: `"r2r-collect-v1\n"+fp+"\n"+holder_address+"\n"+scope+"\n"+ts+"\n"+nonce`
scope: `"collect"` (copy) or `"collect-delete"` (holder deletes after handover — safe: the instruction is signed by you, replay is refused, and it never names the collector, so your home stays private).

```json
→ {"t":"deposit","id":"<fp>","pubkey":"<b64>","scope":"collect-delete",
   "targets":[{"address":"1.2.3.4:8787","ts":…,"nonce":"…","sig":"<b64>"}]}
← {"t":"deposit_ok","targets":N}
```
Collected mail then arrives in your home mailbox (and via push if connected). Batches of 200; re-issue a fresh authorization when a holder reported `more`. UI: a "gather my messages" action, and offer it automatically when `locate` shows pointers.

### a.7 Journal (transport swap only — semantics identical)

```json
→ {"t":"journal_append","data":"<b64>"}          ← {"t":"journal_ok","seq":N}
→ {"t":"journal_read","since":N,"max":200}       ← {"t":"journal","entries":[{"seq","data","created_at"}],"more":bool}
```
Strictly increasing seq, `since` = strictly-greater, ≤640 KB/entry — the restore loop ports as-is. Quota errors arrive as `{"t":"err","code":"quota"}`.

### a.8 Blobs, ICE, calls, presence

- `POST /blob` (X-R2R-Auth header, raw bytes ≤ **24 MB**) → `{id,size,expires_at,duplicate}`; `GET /blob/<id>` (header auth). Content-addressed, deduplicated. Per-account blob TTL is owner-set relay-side; drop the per-upload TTL UI.
- `GET /ice` (header auth) or frame `{"t":"ice"}` → `{"t":"ice","iceServers":[…],"ttl":600}`.
- `sig`: `{"t":"sig","to":"<fp>" or "<fp>@relay","body":"<b64>", …}` — now routes **across relays**; volatile as before; offline target ⇒ `err not_online`.
- Presence: `{"t":"watch","ids":["<fp>",…]}` (replaces `pubs`); `{"t":"presence","id","state","seen"}` both ways; states online/away/offline.

### a.9 Relay info + errors + multi-relay hygiene

- `GET /status.json` (public counters), `GET /node.json` (`node_id`, keys, `advertise`, `base`, ports), `GET /peers.json` (verified peers). `/info`, `/stats`, `/usage`, `/credit` are gone — usage lives in `welcome` and the `quota` frame `{"t":"quota"}`.
- **Key the relay list by `node_id`** (from `node.json`/`welcome`) — an IP and a domain for the same relay are one entry with two routes; a domain upgrade must not split history.
- **Sub-path installs**: `status.json`/`node.json` carry `"base"` (e.g. `"/R2R"`); prefix all HTTP calls and the WS path with it.
- Errors are frames: `{"t":"err","code":"…","msg":"…","ref":"<msg id>"?}`; codes: `bad_frame, bad_field, too_big, rate_limited, not_authorised, unknown_type, no_route, quota, invite_invalid, invite_used, invite_revoked, internal, hop_limit, not_online`.

### a.10 Owner admin (replaces `X-Admin-Key` + `/admin/*` HTTP)

All owner actions are frames on the authenticated WS (gated by `welcome.owner`):

| Frame | Reply |
|---|---|
| `{"t":"admin_accounts","max","offset"}` | account rows (`id, home_relay, used_bytes, quota_bytes, custom_quota, pending, online, last_seen, registered_at`) |
| `{"t":"admin_search_accounts","q"}` | same rows |
| `{"t":"admin_set_quota","id","mb":N\|null}` | `admin_ok` |
| `{"t":"admin_set_ttl","id","days":N\|-1\|null}` | `admin_ok` (`-1` = keep forever) |
| `{"t":"admin_delete_account","id"}` | `admin_ok` (owners refused) |
| `{"t":"admin_invites","count"}` | `{"t":"admin_invites","invites":[…]}` |
| `{"t":"admin_list_invites","state":"open\|burned\|revoked\|all","max","offset"}` | invite rows with lineage |
| `{"t":"admin_revoke_invite","code","cascade":true}` | `admin_ok {revoked,cascaded}` |
| `{"t":"admin_set_advertise","host"}` | `admin_ok {advertise}` |
| `{"t":"admin_list_rentals"}` | `admin_ok {rentals:[…],committed_bytes,pool_bytes}` |
| `{"t":"admin_list_vouchers"}` | `admin_ok {vouchers:[…],cumulative_total_micro,payout,vault,chain_id}` — the settlement export |

The relay also serves its own `/admin` web console; the wallet panel remains the nicer surface — reuse these frames.

### a.11 One addition to send us back (coordinate, don't block)

Register an **x25519 public key** per identity (new optional field on `invite_claim`/`hello`, e.g. `"x25519":"<b64>"`). The wallet already derives curve keys; once identities carry one, relays will seal pointer contents to the recipient so even rendezvous relays can't see *where* your mail waits. Propose the field name and we'll add it relay-side within a day.

## (b) Implementation status

Everything in (a) and (e) is implemented in the single C++ relay (`r2r-relay` 1.0.0, schema v3) and covered by its smoke suite (61 checks) plus live multi-relay tests of pointers, deposit (including replay refusal), push, and the rent/voucher cycle. The five old reference servers are **retired** — remove their embedded downloads from Settings (the relay's doorway `/downloads` page replaces them).

## (c) Required wallet behavior (summary of UI surfaces)

1. Auth layer rewrite (a.2) — the `/admin` page source on any full relay is a working browser reference.
2. Onboarding: invite claim + new code formats; forge emits 2-field `R2RSC1`.
3. Delivery: subscribe with push, keep fetch/ack as catch-up; UUID v4 message ids; client-side delivered receipts.
4. Discovery/consolidation: `locate` on connect, `mail_at` handling, "gather my messages" via `deposit`.
5. Journal transport swap; port `migrateJournal` to frames (old-relay → new-relay migration path for existing users).
6. Relay manager keyed by node_id; base-path support.
7. Owner panel on the new admin frames.
8. Update embedded relay-server downloads → link the relay's own `/downloads`.
9. Storage market (section e): relay picker, rent flow, monthly audit + voucher signing, vault deposit guide.

## (d) Backward compatibility

Detect per relay URL: `GET /node.json` ok ⇒ new protocol; else `GET /info` ok ⇒ old. Recommendation: keep the old stack behind that switch during the transition (old relays are being retired; drop the code path once the fleet is gone). New-protocol fields are stable; absent optional fields mean "older new-relay".

## (e) Storage market — paid replicas the user picks (design: relay repo `docs/settlement-design.md`)

The user chooses 1–5 relays from a directory and rents replica space on each;
payment is USDC on an EVM chain through the `R2RStorageVault` contract
(ABI: relay repo `contracts/StorageVault.abi.json`). Everything below is live
relay behavior you can test today; the contract is compiled and ready but not
yet deployed, so the on-chain calls can be built against a local fork.

**Discovery.** A selling relay advertises in `welcome`:
`"market":{"price_gb_epoch_micro":N,"available_bytes":N}` and in
`/status.json`: `"market":{enabled,price_gb_epoch_micro,epoch_days,pool_bytes,
committed_bytes,available_bytes,payout,vault,chain_id}`. No `market` object =
relay doesn't sell. Directory columns to show per relay: price, free space,
and — read from the chain, not from the relay — registration age
(`relays[nodeId].registeredAt`), bond present, `lifetimeEarned[payout]`.
**Trust rule: a payout address the relay advertises must match the chain
registry for its node id; on mismatch, warn and refuse to rent.**

**Payment key.** Generate a secp256k1 keypair (plus keccak-256) — deliberately
NOT derived from the R2R identity, so nothing on-chain links to the
fingerprint; optionally one key per relay for stronger unlinkability. Suggested
libs to vendor: `@noble/secp256k1` + `js-sha3` (both tiny, no deps).

**Rent** (session must have a proved hello):
`{"t":"rent","bytes":N,"payment_key":"0x…"}` →
`{"t":"rent_ok","rental":"<uuid>","bytes":N,"price_epoch_micro":N,
"epoch_days":31,"paid_until":ts,"payout":"0x…","vault":"0x…","chain_id":8453}`.
Min 1 MB. Errors: `market_off`, `market_full`, `bad_field`. The first epoch
runs on a 35-day grace; the first voucher must arrive before it ends.

**Monthly cycle — audit, then voucher.** Each epoch, per rented relay:
1. Audit: read back a random sample of what you stored there (`journal_read`
   at a random historical seq, blob existence/size) and compare with local
   data. If the relay fails, DON'T sign — re-rent that replica elsewhere.
2. Voucher: `cumulative_micro` is the lifetime total ever promised to that
   relay's payout from this payment key — always `best_previous + price_epoch`
   (track `best_previous` locally; the relay also refuses stale or short
   increments). Sign EIP-191 personal-sign over the 32-byte
   `keccak256("r2r-voucher-v1" ‖ vault_addr_20 ‖ chain_id_uint256_32 ‖
   payout_addr_20 ‖ cumulative_uint256_32)`; send
   `{"t":"voucher","rental","payment_key","payout","cumulative_micro","sig":"0x<130 hex>"}`
   → `voucher_ok {rental,paid_until,cumulative_micro}` (extensions cap at 3
   epochs ahead).

**Vault (user side).** `deposit(amount)` after a one-time USDC `approve`;
`requestWithdraw`/`withdraw` (40-day delay) for unused balance. Guide the user
to a few cents of gas + USDC on the target chain (help page will cover it).
**The only address the wallet ever approves or pays is the compiled-in vault
address — never one from a web page or a frame.**

**Replica diversity (picker policy).** Never two replicas sharing a payout
address, advertise host, or /16; at most one replica on a relay with zero
`lifetimeEarned`; prefer older registrations. Re-replicate automatically when
a relay lapses, fails audit, or shows `ExitStarted` on-chain.

**Rendering rule (restating a hard requirement):** message plaintext is
always inserted as text nodes, never as HTML — a "message" that is really
markup must render inert.

## Test rig (all commands real)

```sh
cmake -S . -B build && cmake --build build -j1          # in ~/r2r-relay
./build/r2r-relay --data-dir /tmp/r2r --ws-port 8787 --no-tls --advertise 127.0.0.1:8787
./build/r2r-relay --db /tmp/r2r/r2r.db --mint-invites 3 # codes to claim
./build/r2r-probe --key /tmp/me.key claim <code>        # register
./build/r2r-probe --key /tmp/me.key listen 30           # watch live push
./build/r2r-probe --key /tmp/me.key frame '{"t":"locate"}' located
./build/r2r-probe --key /tmp/me.key deposit 1.2.3.4:8787 collect-delete
# market (relay started with --pool-market-mb 100 --payout-address 0x…):
./build/r2r-probe --key /tmp/me.key frame \
  '{"t":"rent","bytes":10000000,"payment_key":"0x<40 hex>"}' rent_ok
./build/r2r-probe --key /tmp/me.key frame \
  '{"t":"voucher","rental":"<uuid>","payment_key":"0x…","payout":"0x…","cumulative_micro":4657,"sig":"0x<130 hex>"}' voucher_ok
```
`r2r-probe` source (`tools/probe.cpp`) is the canonical client reference for every frame.
