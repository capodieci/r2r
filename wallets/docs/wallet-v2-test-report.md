# Wallet v2 review — live test results & change request

Relay team, 2026-09-01. We drove your actual `app/core.js` + `app/eth.js`
(unmodified, in a browser-shimmed harness) against two live `r2r-relay`
binaries — relay A invite-gated, relay B selling storage, peered. **27 of 27
end-to-end checks passed on first contact.** No frame-shape mismatches. The
protocol rewrite is right.

## What was proven live

- Onboarding: `invite_claim` with real `R2R-…` codes (claim, 3 child codes,
  duplicate-claim refusal), vault create/unlock.
- Messaging: `subscribe {push:true}` live delivery, batched `ack`, your
  encrypted `dack` receipts round-tripping to "delivered", `watch`/`presence`.
- Blobs: 200 KB attachment via `POST /blob` with `X-R2R-Auth`, downloaded and
  decrypted on the receiving side.
- Journal: append/read paging, and a **fresh-browser restore** — a second
  context with only the seed rebuilt contacts and threads from the relay.
- Owner panel: accounts, search, mint, list, revoke-cascade, set-quota (by
  R2R_ address), all against the live frames. Your assumed reply shapes in
  WALLET-GUIDE §8 were all correct.
- Storage market: `rent` on relay B, journal replication to the replica,
  audit-then-voucher, `voucher_ok` extending `paid_until` ~2 epochs; the
  diversity checker flagged a same-host second rental.
- **Your hand-rolled crypto is verified independently.** We re-implemented
  keccak-256 + secp256k1 ecrecover from scratch (no shared code) and checked
  the voucher your wallet signed, as stored on the relay: it recovers to the
  payment key exactly, low-s, correct EIP-191 wrap, correct digest layout —
  identical to what `R2RStorageVault.redeem()` computes. On-chain redemption
  will work as-is.
- Parked mail, the whole chain through public APIs only: a send landed on the
  wrong relay (B) → B emitted a pointer → the home relay pushed `mail_at` →
  your auto-gather issued the signed `deposit` → B handed the payload over →
  live `drop` push → message rendered. Zero manual steps.

## Relay-side changes we made for you (deployed)

- **a.11 accepted as proposed: field name `x25519`.** The relay now stores a
  valid 32-byte b64 `x25519` from both `hello` and `invite_claim`
  (schema v4). You are already sending it — nothing to change. Sealed
  pointers will build on this; we'll send a change request when they land.
- `invite_ok` now carries `node_id`, so `registeredOn[u].node` fills properly
  (it was empty in the test run).

## Fixes for the wallet (all small)

1. **Invite IPv4-hint decode fires on codes that carry no hint.**
   `parseInviteCode` treats the first 8 chars of ANY code as a hex IP if they
   happen to be hex. Only the **5-group** form (`R2R-AAAA-BBBB-XXXX-XXXX-XXXX`,
   28 chars) carries a hint, in groups 1–2. A plain 3-group code has hex-only
   first groups ~1 time in 256 — the wallet then dials a bogus relay and the
   claim stalls/fails confusingly. Gate the hint decode on
   `code has exactly 5 groups`; while there, tighten the accept regex to
   3-or-5 groups (`{2}|{4}` after the first) — the relay mints no other shapes.
2. **Map relay errors by `code`, not message text.** On a refused claim the
   relay sends `{"t":"err","code":"invite_used","msg":"invite could not be
   claimed"}`. Your `oneShot`/`settlePend` reject with `m.msg`, so the
   `/invite_used/` regexes in `claimInvite` never match and the user sees the
   generic line (we hit this live on the duplicate-claim test). Prefer
   `m.code` when building the Error, or test the regexes against
   `m.code + ' ' + m.msg`.
3. **`inviteShareUrl` forces `https://`.** For a relay reached as
   `ws://1.2.3.4:8787` that URL serves nothing. Keep the scheme the relay's
   HTTP base actually has (`httpBase(p) + '/' + code`); relays behind TLS
   already yield https there.

Nothing else. Points 2–3 are polish; point 1 is the one we'd call a bug.

## Still pending on our side

- Vault deploy: address + chain id will come from Roberto; until then your
  "do not deposit" guard is correct and we confirmed it refuses to sign
  vouchers when a relay names no vault (exactly right).
- Sealed pointers (using the x25519 you now register): future change request.

## Addendum 2026-09-24: relay-side text patch, please carry it over

The relay side patched two pieces of copy directly in the published bundle
(`dist/R-2-R Chat & Calls.html`) and in the template, because the install
flow changed and no rebundler is available on the relay host:

- setup page "Set up your own relay": the `rlSteps` array now has five steps
  (pick a server; install with one command via `install.sh`; claim one of the
  five genesis invites; `--owner-add`; add `ws://IP:8787` to Relays);
- Settings "Run your own relay": the "Setup on a fresh Ubuntu server" block
  now shows the four `curl -sSLO https://r2r.homes/assets/…` lines and
  `sudo ./install.sh YOUR-SERVER-IP:8787`, then genesis invites and owner-add.

Both are in the updated `r2r.zip` (`R-2-R Chat & Calls.dc.html` + dist) with a
note in its `CLAUDE.md`. Take them into the design project before the next
rebundle so they are not lost. The installer itself is `scripts/install.sh`
in the relay repo; the authoritative page is `https://r2r.homes/run-a-relay`.
