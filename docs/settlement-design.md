# R2R storage market & settlement — design v1

Agreed with Roberto 2026-08-31. This document is normative for the three
implementations: the `R2RStorageVault` contract (`contracts/`), the relay
(`src/`), and the wallet (change request in `wallet-migration-prompt.md` §12).

## Principles (the short version)

1. **The user chooses the relays.** Storage is never randomly assigned. The
   wallet rents space on 1–5 relays the user picked from a directory, by
   price, location, age, and history. The risk of a bad pick is the user's,
   bounded by replication.
2. **Everything stored is ciphertext.** A malicious relay can delete, never
   read. The market trades *availability*, not access.
3. **Payment sits behind performance.** Funds are prepaid into a contract the
   user controls, but a relay can only collect month by month, after the
   wallet has audited it. Prepaid from the user's view, post-paid from the
   relay's view.
4. **No chain keys on the server.** The relay stores signed vouchers as
   opaque strings. Settlement is submitted from the operator's own browser
   wallet via the admin console (or any tool). A fully compromised relay
   server yields no funds and cannot redirect anyone's payment.
5. **Nothing to hack that moves money.** The only address a user ever pays
   or approves is the vault contract, compiled into the wallet — never
   scraped from a web page. Relay payout addresses are bound on-chain at
   registration; vouchers are written against the chain registry, not
   against what a relay (or a hacked doorway page) claims at runtime.
6. **Reputation is computed, not voted.** Registration age, bond, and
   cumulative settled earnings are on-chain facts anyone can verify. The
   wallet's replica picker reads them directly. No registrar, no reviews as
   protocol (a human review page may exist as advice).

## Parameters (locked for v1)

| Parameter | Value | Where |
|---|---|---|
| Chain | any EVM; deploy target **Base** (chain id 8453) | contract |
| Token | USDC (6 decimals; amounts below are micro-USDC) | contract |
| Relay bond | 10 USDC (`BOND = 10_000_000`) | contract |
| Exit notice (bond refund delay) | 60 days | contract |
| Deposit withdrawal delay | 40 days (> one epoch, so monthly settlement cannot be front-run) | contract |
| Epoch | 31 days (`--rent-epoch-days`) | relay |
| First-epoch grace (before the first voucher) | 35 days (`--rent-grace-days`) | relay |
| Default price | 500 000 micro-USDC per GB-epoch (`$0.50/GB-month`) — operator-changeable, chosen above the priciest surveyed VPS ($0.40/GB-mo) so honest operators profit anywhere | relay |
| Prepay cap | a rental can be paid at most 3 epochs ahead | relay |
| Min rental | 1 MB | relay |

## The contract: `R2RStorageVault`

Ownerless, non-upgradeable, no pause switch. One instance per chain.

State:
- `relays[nodeId] -> {payout, registeredAt, exitAt}` — relay registry + bond.
- `registeredPayout[addr] -> count` — reverse index; only registered payout
  addresses can redeem.
- `balances[payer]` — user deposits, per payment key.
- `settled[payer][payout]` — cumulative micro-USDC already redeemed.
- `lifetimeEarned[payout]` — public reputation counter.

Functions:
- `register(bytes32 nodeId)` — pulls the 10 USDC bond, binds
  `msg.sender` as the payout address for that relay node id. The
  registration timestamp is the verifiable "months alive".
- `startExit(nodeId)` / `withdrawBond(nodeId)` — orderly de-listing: bond
  returns only after the 60-day notice, during which wallets see the exit
  on-chain and re-replicate. An exit-scammer's bond outlives their income.
- `deposit(amount)` — user credits their payment key.
- `requestWithdraw(amount)` / `withdraw()` — refund of unused balance after
  the 40-day delay; redemptions keep working during the window.
- `redeem(payer, cumulative, sig)` and `redeemBatch(...)` — anyone may
  submit (the payee gets the money, so gas can be paid by a helper). The
  signature recovers `payer`; the contract pays
  `min(cumulative - settled, balance)` to the payee and advances `settled`
  (partial settlement stays redeemable after the payer tops up).

**Voucher signature** (EIP-191 personal-sign, so any EVM signer works):

```
digest = keccak256(
  "\x19Ethereum Signed Message:\n32" ||
  keccak256("r2r-voucher-v1" || vault_address(20) || chain_id(uint256,32)
            || payee_address(20) || cumulative_micro(uint256,32)))
```

Vault address and chain id in the payload make a voucher worthless on any
other deployment; `payee` binds it to one relay; `cumulative` (not a
per-payment amount) makes vouchers **aggregating**: the relay keeps only the
newest one per payer and one redemption settles everything owed, replay-safe
without nonces (`settled` only moves forward).

## Relay side

New config (env / flag): `--market-price` (`R2R_MARKET_PRICE_MICRO`,
micro-USDC per GB-epoch), `--payout-address` (`R2R_PAYOUT_ADDRESS`),
`--vault-address` (`R2R_VAULT_ADDRESS`, informational for wallets to
cross-check), `--chain-id` (`R2R_CHAIN_ID`, default 8453),
`--rent-epoch-days`, `--rent-grace-days`. The market is enabled iff
`--pool-market-mb > 0` **and** a payout address is set.

**Reservations, never overselling.** A rental is a row
`{id, fingerprint, bytes, price_micro, payment_key, paid_until, state}`.
Inventory = `pool_market − SUM(bytes of active rentals)`; a `rent` that
does not fit is refused. The relay sells only bytes it has budgeted.

**Rented bytes are real quota.** The storage allowance of an identity is
`(custom quota | relay default) + SUM(bytes of its active paid rentals)`,
applied in all three store paths (drops, journal, blobs). An identity with
an active rental is exempt from the common-good pool (its storage is
market-accounted), symmetrical with custom-quota identities.

**Frames** (session must have a proved hello):
- `rent {bytes, payment_key}` → `rent_ok {rental, bytes,
  price_epoch_micro, epoch_days, paid_until, payout, vault, chain_id}`.
  First epoch is provisional: `paid_until = now + grace`. A renter who
  never pays costs the relay at most one epoch of one slice — the exact
  mirror of the user's own exposure, by design.
- `voucher {rental, payment_key, payout, cumulative_micro, sig}` →
  `voucher_ok {rental, paid_until, cumulative_micro}`. The relay checks the
  payout matches its own, the rental belongs to the session identity, and
  `cumulative` rises by at least the rental's epoch price over the highest
  voucher already held for that `(payment_key, payout)`; then extends
  `paid_until` one epoch (cap: 3 epochs ahead) and stores the voucher
  verbatim for settlement. The signature is opaque to the relay — only the
  contract verifies it; a garbage voucher just fails to redeem, and the
  rental lapses next epoch.
- Lapse: the sweep marks rentals with `paid_until < now` lapsed; their
  quota contribution stops instantly, stored data then decays under normal
  TTL rules. No punitive deletion.

**Admin frames** (owner-gated, like the rest): `admin_list_rentals`,
`admin_list_vouchers` (newest voucher per payer, plus payout/vault/chain
context — the settlement export the console hands to the operator's browser
wallet). Granting free space to a friend or yourself is the existing
`admin_set_quota`; per-account retention is `admin_set_ttl`.

**Publication.** `/status.json` gains a `market` object: `enabled, price,
payout, vault, chain_id, pool_bytes, committed_bytes, available_bytes,
rentals_active`. The `welcome` frame advertises `market {price, available}`
when enabled. The directory (wallet picker, and later a `/relays` doorway
page) is rendered from these plus the chain — cached/regenerated, never
authoritative: the `rent` call against the live relay is what actually
reserves.

## Wallet side (summary; normative text in wallet-migration-prompt.md §12)

- Generates a **payment key** (secp256k1) unlinked to the R2R identity;
  optionally one per relay for stronger unlinkability. On-chain observers
  see "some key paid relay Y", never who.
- Rents on the user's chosen relays, deposits USDC to the vault (guided
  flow; explains gas), then monthly: **audit → voucher**. The audit reads
  back a random sample of what it stored (journal ranges, blob heads) and
  compares with local copies; only then does it sign the next cumulative
  voucher. No answer → no voucher → re-rent that replica elsewhere. The
  wallet is the oracle because it is the only party that both paid for the
  data and can cheaply verify it.
- Replica diversity: refuse to place two copies on relays sharing a payout
  address, advertise host, or /16; weight by on-chain age and
  `lifetimeEarned`; at most one replica on a relay with no settlement
  history.

## Threat notes (Roberto's injection scenario, addressed)

- *"Someone changes the address on a page."* No page ever carries a payment
  address. Wallet pays the compiled-in vault; vouchers name the payout
  address **read from the chain registry** for that node id. A relay-side or
  doorway-side compromise can alter advertised strings, and the wallet
  treats a mismatch between advertised payout and chain-registered payout
  as a red flag, not a redirect.
- *"A message that's supposedly encrypted but isn't, causing code
  injection."* Relay: payloads are opaque blobs, never parsed or rendered;
  doorway pages carry a strict CSP and the bundle is hash-verified.
  Wallet: renders message plaintext as text nodes only — restated as a hard
  requirement in the wallet prompt.
- *"Hack the server, steal the money."* The server has no chain keys, and
  vouchers are only redeemable to the chain-registered payout. Worst case
  of a full server compromise: the attacker deletes data — which is the
  availability failure replication already prices in.

## Deploy checklist (operator-facing, when we go live)

1. Deploy `R2RStorageVault` once per chain (constructor: USDC address);
   publish the address in the wallet build and on the help page.
2. Relay operator: create an EVM address, `register(nodeId)` with 10 USDC,
   set `--payout-address`, `--vault-address`, `--pool-market-mb`, price.
3. Help page (r2r.homes): how to get a few cents of gas on Base + USDC,
   how the deposit works, and the one safety rule — *the only address you
   ever approve is the vault*.
