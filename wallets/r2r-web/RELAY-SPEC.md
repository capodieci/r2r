# R2R Relay network — protocol v2 (wallet-side summary)

The protocol is owned by the relay repository (`~/r2r-relay`, binary `r2r-relay`);
its `tools/probe.cpp` is the canonical client reference. This file is the wallet
project's working summary of v2 as implemented in `app/core.js`. The five v1
reference servers are retired and removed from this project.

## Identity
- Account id = **fingerprint**: hex `sha256("r2r-id-v1" ‖ ed25519_pub)` (64 chars).
- The shareable `R2R_…` base32 string still encodes the **pubkey** + 3-byte sha3
  checksum (unchanged); the fingerprint is derived locally.
- Message ids MUST be UUID v4.

## Connect / auth
- WS `wss://host[:8788][<base>]/ws`, then frame
  `{"t":"hello","id":fp,"pubkey":b64,"ts":unix,"nonce":str,"sig":b64,"x25519":b64?}`;
  `sig` = ed25519 over `"r2r-client-v1\n"+fp+"\n"+ts+"\n"+nonce` (±600 s).
- Reply `{"t":"welcome", you, pending, ttl_days, max_payload, peers, quota_bytes,
  used_bytes, owner, push, node_id, proto}`.
- HTTP (blobs, ice): header `X-R2R-Auth: base64(JSON{id,pubkey,ts,nonce,sig})`.
- All frames use `"t"` as the type key. Errors:
  `{"t":"err","code","msg","ref"?}` — codes: bad_frame, bad_field, too_big,
  rate_limited, not_authorised, unknown_type, no_route, quota, invite_invalid,
  invite_used, invite_revoked, internal, hop_limit, not_online.

## Registration (invite-gated)
- `{"t":"invite_claim","code":"R2R-XXXX-…", …hello fields…, "home_relay"?}` →
  `{"t":"invite_ok","invites":[3 codes],"home_relay","node_id"}`.
- Hinted codes `R2R-AAAA-BBBB-…` embed the minting relay's IPv4 in the first
  8 hex chars. Share URL: `https://<relay><base>/<code>`.
- Setup cards unchanged: `R2RSC1:<cardKeyHex64>:<relay[,relay…]>`; locator
  accounts are ordinary hello-proved accounts, no registration needed
  (wrong-PIN ≡ new-user invariant holds). Unregistered default quota 1 MB.

## Invite activation (2026-09-23)
- One registration per identity per relay (`err already_registered`).
- Claimed codes come back `locked:true`; `invite_ok` also has `unlock{received_needed,vouch_needed}` and
  `inviter{id,pubkey}` when an identity issued the code. Claiming a locked code ⇒ `err invite_locked`.
- Unlock = ≥3 payloads received+acked on that relay AND (if an identity invited) its `vouch {id}`
  → `vouch_ok {id, active}`. Progress: `{"t":"invite_status"}` → `{registered, active, received,
  received_needed, vouch_needed, vouched, inviter?, invites:[{code,state}]}`.
- Wallet: adds the inviter as a contact and sends it `{"t":"vouchreq","relay":url}` (E2E payload);
  the inviter's wallet vouches once ≥1 message went each way.

## Messaging
- `{"t":"send","id":uuid,"to":fp or "fp@host:port","body":b64,"hint"?}` →
  `{"t":"sent","id","status":"stored"|"forwarded"|"duplicate"}`.
- `{"t":"subscribe","push":true}`; live `{"t":"drop",id,seq,body,created_at,…}`;
  catch-up `{"t":"fetch","since","max"}` → drops + `{"t":"fetch_done",more}`;
  `{"t":"ack","ids":[…]}` after decrypt+persist → `ack_ok`.
- No relay `delivered` receipts, no relay-verified `from`: the wallet's wire
  body is `b64(senderEdPub32 ‖ nonce24 ‖ nacl.box)` — opening the box
  authenticates the sender; delivery/read state is a client-side encrypted
  `{t:"dack",ids:[…]}` payload.
- Discovery: `{"t":"locate"}` → `{"t":"located",pending,pointers:[{address,count,ts}]}`;
  live nudge `{"t":"mail_at",address,count}`.
- Consolidation: `{"t":"deposit",id,pubkey,scope:"collect"|"collect-delete",
  targets:[{address,ts,nonce,sig}]}` with sig over
  `"r2r-collect-v1\n"+fp+"\n"+address+"\n"+scope+"\n"+ts+"\n"+nonce` → `deposit_ok`.

## Onion routing (wallet default)
- Relay keys: `x25519` from `welcome`, `GET /node.json`, and the primary's `GET /peers.json`
  (`node` + verified `peers[]`).
- Layer v2 = `0x02 ‖ n ‖ n × seal(candidate, K)[93] ‖ nonce12 ‖ AES-256-GCM(K, pt, aad=head)`, n = 1..3;
  seal = `0x01 ‖ eph_pub32 ‖ nonce12 ‖ AES-GCM(HKDF(X25519), K)` (info "r2r-seal-v1").
  Plaintexts (binary): routing `0x01 ‖ n ‖ n×(len8 ‖ host:port) ‖ inner`;
  terminal `0x02 ‖ len16 ‖ {"to":"fp@home","id"} ‖ body`.
- Submit `{"t":"onion","blob":b64}` on a fresh socket with NO hello. Relays are silent on
  success; only an `err` comes back (wallet waits 2.5 s).
- Route: entry set → 1 middle set (Standard) or 3 (Extra) → terminal set [recipient's relay + ≤2
  standbys]; ≤3 candidates per set; relays heard from by the primary in the last 3 min.
- Everything stored goes this way (text, files, mail, groups, dack); `sig` stays direct.
  Fallback to direct `send` on route/seal/entry failure, or after 15 min without a `dack`.

## Journal (semantics unchanged from v1)
- `{"t":"journal_append","data":b64}` → `{"t":"journal_ok","seq"}`;
  `{"t":"journal_read","since","max"}` → `{"t":"journal","entries":[{seq,data,created_at}],"more"}`.
- Strictly increasing seq; `since` strictly-greater; ≤640 KB/entry; quota → err.

## Blobs / ICE / presence / sig
- `POST /blob` (header auth, ≤24 MB) → `{id,size,expires_at,duplicate}`;
  `GET /blob/<id>` (header auth). Content-addressed, deduplicated.
- `{"t":"ice"}` or `GET /ice` → `{"t":"ice","iceServers",ttl}`.
- `{"t":"sig","to":fp or fp@relay,"body":b64}` — routes across relays, volatile;
  offline ⇒ `err not_online`.
- `{"t":"watch","ids":[fp…]}`; `{"t":"presence","id","state","seen"}` both ways.

## Info / node identity
- `GET /status.json` (public counters + `market` object when selling),
  `GET /node.json` (`node_id`, `advertise`, `base`, ports), `GET /peers.json`.
- Key relay records by `node_id`; prefix HTTP and WS paths with `base`.
- Old `/info`, `/stats`, `/usage`, `/credit` are gone; usage rides `welcome`
  and the `{"t":"quota"}` frame.

## Owner admin (frames, gated by `welcome.owner`)
`admin_accounts`, `admin_search_accounts`, `admin_set_quota {id,mb|null}`,
`admin_set_ttl {id,days|-1|null}`, `admin_delete_account`, `admin_invites {count}`,
`admin_list_invites {state}`, `admin_revoke_invite {code,cascade}`,
`admin_set_advertise {host}`, `admin_list_rentals`, `admin_list_vouchers`.

## Storage market (see relay repo docs/settlement-design.md)
- Discovery: `welcome.market` / `status.json.market`
  (`price_gb_epoch_micro`, `epoch_days`, `available_bytes`, `payout`, `vault`, `chain_id`).
- `{"t":"rent","bytes","payment_key":"0x…"}` → `rent_ok {rental,bytes,
  price_epoch_micro,epoch_days,paid_until,payout,vault,chain_id}`; min 1 MB;
  first epoch has a 35-day grace.
- Voucher: EIP-191 personal-sign over
  `keccak256("r2r-voucher-v1" ‖ vault20 ‖ chainId_u256 ‖ payout20 ‖ cumulative_u256)`;
  `{"t":"voucher",rental,payment_key,payout,cumulative_micro,sig}` → `voucher_ok`.
  `cumulative_micro` = lifetime total (best_previous + price_epoch); ≤3 epochs ahead.
- Wallet policy: audit before every voucher (read own ciphertext back); payment
  key is secp256k1, never derived from the R2R identity; the only vault address
  ever trusted for deposits is the one compiled into the wallet
  (`VAULT_ADDR` in `app/core.js` — empty until the contract is deployed).
- Replica diversity: never two replicas sharing payout, host, or /16.

## Wallet-side invariants kept
- Wrong PIN on a setup card is indistinguishable from a new user.
- Message plaintext renders as text nodes, never as HTML.
- ack only after decrypt + persist; redelivery via fetch is idempotent.
- Groups / multi-recipient mail stay pure client-side fan-out.
