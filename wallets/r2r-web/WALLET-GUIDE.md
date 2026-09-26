# R2Я Wallet — how it works (for relay developers) · protocol v2

Companion to `RELAY-SPEC.md` (v2 summary; the relay repo is authoritative).
This documents the client side after the v2 migration (September 2026).

## 1. What the wallet is
Single self-contained HTML file (`R-2-R Chat & Calls.html`), no server or build;
state in encrypted localStorage (`r2r1_*`). Surfaces: Chat (1:1 + groups), Calls
(1:1 + mesh group calls, screen share), Mail (≤8 recipients), Files, Settings
(identity, relays, PIN, mail pickup, invites, storage market, relay-owner panel).
Companion: Setup Card Forge (mints `R2RSC1:<key>:<relays>` QR cards, unchanged).

## 2. Identity & crypto
- ed25519 keypair; relay-side id = fingerprint `sha256("r2r-id-v1"‖pub)`;
  the shareable `R2R_…` string still encodes the pubkey (+sha3 checksum).
- Wire body = `b64(senderEdPub32 ‖ nonce24 ‖ nacl.box)` — the box authenticates
  the sender, replacing v1's relay-verified `from`. Payloads also carry `rr`
  (sender's relay ws-url) and `ra` (advertise host:port) for reply routing.
- hello/`X-R2R-Auth` per spec; `x25519` (b64 curve pub) is sent on hello and
  invite_claim — this is our proposed field name for a.11 (sealed pointers).
- Message ids: UUID v4. PIN KDF unchanged (60k SHA3). Vault/pepper unchanged.
- New: `app/eth.js` — self-contained sha256/HMAC/RFC6979, keccak-256,
  secp256k1, EIP-191 personal-sign, minimal eth_call (storage-market vouchers).

## 3. Connections & routing
- Persistent WS to every relay in use (mine + contacts'); hello → welcome marks
  a connection live; then subscribe(push), watch(fps), presence, fetch/ack
  catch-up, and on the primary: locate, journal pull/flush, stats.
- Sends prefer the contact's own relay directly; if only my primary is up they
  route as `fp@advertise` through the network. `sig` frames route the same way.
- Delivery state: relay `sent{status}` drives the single check; the double
  check is a client-side encrypted `{t:"dack",ids}` payload (batched ~1 s).
- Pointers/consolidation: `locate` after every connect and on `mail_at`;
  pointers trigger an automatic `deposit` (scope collect-delete). Manual
  "Gather my messages" button in Settings → Mail pickup.
- Relay records: wallet stores per-URL meta from `node.json`/`welcome`
  (`node_id`, `advertise`, `base`); sub-path installs work (URL keeps the path).

## 3b. Onion routing (default on; Settings → Privacy)
- Every stored payload (text, files, mail, group, dack) leaves on a fresh ANONYMOUS socket
  (no hello) as a sealed onion: entry → middle → recipient's relay. Pure-JS sealing in
  `core.js` (X25519 via nacl, HKDF via eth.js HMAC, own AES-256-GCM) — byte-identical to the
  relay's `crypto::seal` (checked against the relay's test vector).
- Hop keys: `welcome.x25519`, `/node.json`, primary's `/peers.json` (cached 10 min).
- Accepted onion ⇒ ✓ sent; outbox keeps it until the `dack` (✓✓). Direct `send` fallback if
  no route / entry `err`, or once after 15 min without a receipt (same wire id ⇒ deduped).
- Calls (`sig`) stay direct. `R2R.onionEnabled() / setOnionEnabled(b) / onionInfo()`.

- v2 (2026-09-23): up to 3 candidates per position, Standard/Extra route length, entry failover.
- Keys from PINs/passphrases: scrypt N=2^16 r=8 p=1 (`kdf` in `r2r1_wrap`); PIN policy in
  `R2R.pinCheck`; private keys are 64-hex only (no brain wallets).

## 4. Journal / restore / migration
Same append-only encrypted journal, now over `journal_append`/`journal_read`
frames. Restore, setup cards, PIN change (all-or-nothing locator move + old-PIN
revocation record), and old→new relay migration (`migrateJournal`) all ported to
one-shot authenticated WS sessions. Wrong-PIN ≡ new-user invariant preserved.

## 5. Registration / invites
- Onboarding gained "Use an invite code": generates a fresh identity, claims the
  code (`invite_claim` with hello proof + x25519), stores the 3 returned codes
  (Settings → Invite codes, shareable as `https://<relay>/<code>`).
- Hinted `R2R-…` codes: wallet decodes the embedded IPv4 (first 8 hex chars,
  port 8787 assumed) when no relay is given. Legacy UUID codes accepted.
- Manual setup (no invite) still works — 1 MB unregistered quota, stated in UI.

## 5b. Invite activation
- A member's 3 codes are locked until: ≥3 messages received on the relay AND (when an identity
  invited them) the inviter's `vouch`. Settings → Invite codes shows each code's state and what is
  still missing. `R2R.inviteStatus() / refreshInviteStatus()`.
- After a claim the inviter becomes the first contact ("Invited me") and gets a `vouchreq` payload;
  the inviter's wallet vouches automatically after one message each way.
- An identity registers once per relay (`already_registered`).

## 6. Owner panel & relay hosting
- Admin is frame-based, gated by `welcome.owner` (no admin key in the wallet).
  Panel: account list/search (usage, quota, pending, online, last_seen), quota,
  file TTL, delete account, mint/list/revoke invites, vouchers view.
- The five embedded v1 relay sources are REMOVED; hosting instructions point at
  any relay's `/downloads` page and the r2r-relay flags
  (`--data-dir --ws-port --no-tls --advertise`, `--mint-invites`).

## 7. Storage market (fully implemented client-side)
- Directory: own relay `status.json` + `peers.json` fan-out; shows price/GB/epoch
  and free space; replica-diversity warnings (payout / host / /16 collisions).
- Rent: fresh secp256k1 payment key per rental (unlinkable from identity);
  `rent` frame; vault-address trust rule enforced against the compiled-in
  `VAULT_ADDR` (currently EMPTY — contract not deployed; UI shows a red
  "do not deposit yet" warning and rentals run on the 35-day grace epoch).
- Replication: the wallet ferries its journal ciphertext to each rented relay
  (cursor per rental), on unlock, after flushes, and every 6 h.
- Monthly cycle (auto when <7 days paid remain, or manual "Audit & pay"):
  audit = read random journal sample back from the replica and verify it
  decrypts with the local journal key; only on success sign the EIP-191
  voucher (`cumulative = best_previous + price_epoch`, tracked locally) and
  send it. Failed audit ⇒ no payment, red flag in UI.
- Optional EVM RPC url (Settings) enables best-effort chain reads
  (`lifetimeEarned(address)`), inert until `VAULT_ADDR` is pinned.

## 8. For the relay team
- a.11 answer: field name **`x25519`**, b64-encoded curve25519 public key,
  present on both `hello` and `invite_claim`. Already sent by this wallet.
- When the vault contract deploys, send address + chain id; we pin `VAULT_ADDR`
  in `app/core.js` and drop the "do not deposit" warning.
- Assumed reply shapes where the change request was terse (flag if wrong):
  `admin_accounts` → `{accounts:[…]}`; `admin_invites` → `{invites:[{code,…}|str]}`;
  `journal` entries carry `data` (b64) + `seq`; `quota` frame reply
  `{"t":"quota",used_bytes,quota_bytes}`; `peers.json` = array (or `{peers:[…]}`)
  of `{address,node_id,base?}` or bare "host:port" strings.

## 9. Change-request format (unchanged)
Send: (a) protocol delta, (b) implementation status, (c) required wallet
behavior, (d) compatibility notes. The wallet, forge and docs get updated and
`dist/` rebundled from that.
