# Doorway → relay integration: progress tracker

Working sequence agreed 2026-08-29; bundle `r2r-doorway-bundle-latest.zip`
verified 26/26 against its manifest. Kept current by the working session —
update the status column as stages land.

| Stage | What | Status |
|---|---|---|
| ① | v2 DB migration: `R2R-…` invite format (+IPv4 hint), `revoked_at/by`, `parent_code`, `contact_token`, `cards` table, `admin_revoke_invite` cascade, `invites_revoked` counter | **done** 2026-08-30, smoke 61/61 + unit tests |
| — | queue-expiry → `store_locally` promotion (FAQ un-hedge) | **done** 2026-08-29 |
| ② | Build profiles (`full`/`adminOnly`/`headless` via `R2R_WITH_DOORWAY`, `R2R_WITH_ADMIN_UI` + CMakePresets) and config plumbing (`R2R_DOORWAY_DIR`, `R2R_BASE_PATH`, `R2R_PRIMARY_COLOR`, `R2R_SECONDARY_COLOR`) | **done** 2026-08-30 |
| ③ | Doorway module: template loader + sentinel substituter, per-language templates with en fallback, nested-path static handler, per-route CSP/robots/cache | **done** 2026-08-30 — all 7 pages live-tested, headless profile verified |
| ④ | Dynamic pages: `/redeem` (4-state), `/m/<token>`, `/card?fmt=json`, `/api/stats`, `/api/contact/{token}`, `/R2R-…` + `/i/…` short URLs with wrong-relay hint redirect | **done** 2026-08-30 — live-tested incl. contact-token chain and 2-QR card |
| ⑤ | Admin frames: `admin_list_invites`, `admin_set_ttl`, `admin_search_accounts`, `admin_delete_account`, `admin_set_advertise` (revoke_invite landed in ①) | **done** 2026-08-30 — all five wire-tested via new `r2r-probe frame` command |
| ⑤b | `/admin` web console page (JS-over-WSS client for the frames above; needs an ed25519 signer in the browser — nacl.js from the wallet project) | **done** 2026-08-30 — embedded page + nacl.js; JS crypto core verified against the relay (fingerprint match + accepted signature); requires a secure context (https or localhost) |
| ⑥ | Sub-path mount: strip `base_path` in `handle_http_request`, `{{BASE}}` in emitted URLs, `"base"` field in `/status.json` + `/node.json` | **done** 2026-08-30 — live-tested at `/R2R`, incl. `/R2R-code` vs `/R2R/` disambiguation |
| ⑦ | `install.sh`: fetch bundle (URL or local zip), verify manifest, extract to `/var/lib/r2r/doorway`, merge `docs/translations.zip` | **done** 2026-08-30 — good bundle installs (99 files), tampered bundle refused |

## Deltas vs HANDOFF.md (already agreed or discovered)

- Cascade BFS walks *through* claimed intermediates (ref-php stops at them);
  claimed codes / identities are never touched.
- Confusable folding (O→0, I/L→1) applies to the hex hint groups too.
- Claiming a revoked code → `invite_revoked`, HTTP 410 on `/invite/claim`.
- Translations: 37 languages validated (410/410 keys each), staged from
  `docs/translations.zip`.
- Bundle templates still carried `.php` links, `/auth/login.php` (retired
  account system), form actions and prose mentions; the loader rewrites all of
  them deterministically at load (`normalize_links` in `src/doorway.cpp`).
  register → `/redeem`, login → `/downloads`.
- Manifest verification is strict for templates/assets but tolerant for
  `i18n/*.json` — operators legitimately replace catalogs as fuller
  translations arrive (that is how the 37-language set installs over the
  bundle's partial `it.json`).
- Doorway statics serve at root level (`/sippis-shell.css`, `/favicon.svg`,
  `/sippis-logo.svg`) and `/js/*`, exactly as the pages link them; `/assets/`
  remains the relay's downloads endpoint, no collision.
- Built-in status landing page moves to `/status` when the doorway is active.
- Setup cards use the RELAY-SPEC format `R2RSC1:<keyHex64>:<ws-url>` (2 fields);
  the PHP's third `bot_pub_hex` field was an r2r.help-only extension and the
  embedded relay has no bot.
- Web redemption burns the code immediately (`burned_by = card:<hash16>`,
  cards row in the same transaction); the PHP's `locked` intermediate state
  does not exist here. No child codes are minted at web redemption (matches
  ref-php) — how card-onboarded users later obtain invites of their own is an
  open wallet-milestone question.
- `/api/contact/{token}` returns `pubkey` = the minter's identity fingerprint
  (the addressable id in the new protocol) plus an `ed25519` b64 extra.
- Per-account retention lives in its own `account_ttls` table (not `quotas`,
  whose absent-row-means-default semantics must stay intact); `-1` = keep
  forever (rendered as a 100-year expiry). Applies to drops and blob uploads.
- `admin_set_advertise` persists to the `meta` table (`advertise_override`)
  and wins over the environment at startup — logged loudly when it shadows a
  differing `R2R_ADVERTISE`.
- `admin_delete_account` refuses relay owners (host-side `--owner-remove`
  first), closes the target's live sessions, and deletes orphaned blob bytes.
- `r2r-probe frame '<json>'` sends any signed frame and prints the reply —
  the shell-level test harness for admin work.

### Live-site fixes to fold into the next bundle rev (2026-08-31)

- Dynamic pages (`/redeem`, `/m`) now reuse the real site topbar, lifted per
  language from the index template at load; `?lang=` works site-wide (cookie
  `lang`, 1 year) — relay-side, no bundle change needed.
- `assets/sippis-shell.css`: appended `html{scrollbar-gutter:stable}` and
  `.layout{width:100%}` (the centered flex body sized docs layouts to their
  content — the FAQ accordion "drunk width"). Manifest hash updated in place.
- `assets/favicon.svg` replaced: was the full 360×250 animated mesh; now a
  64×64 static mesh miniature (hub + ring + 4 peers, brand palette). New
  `assets/favicon.ico` (16+32 px) served at `/favicon.ico` for browsers
  without SVG-favicon support. Manifest updated; scratchpad bundle mirrored.
- Asset links are now stamped `?v=<manifest-hash8>` at load (replacing any
  baked-in `?v=<timestamp>` from the old site tooling), so hard-cached CDN
  edges roll over the moment a bundle changes. Relay-side (`version_assets`
  in doorway.cpp); the next bundle rev should drop its own timestamps.

## After the doorway sequence (this session's own roadmap)

| Item | Status |
|---|---|
| Mail pointers + signed `locate` | **done** 2026-08-30 — end-to-end two-relay test: bare-fingerprint send on the wrong relay found via `locate` and fetched |
| `subscribe {push:true}` live delivery | **done** 2026-08-30 — drop pushed live (same frame as fetch, same seq cursor), unacked pushes redelivered by fetch; `welcome.push=true` advertises the capability; `r2r-probe listen` shows it |
| Signed collect/delete authorizations (safe deposit) | **done** 2026-08-30 — `deposit`/`collect`/`collect_item`/`collect_done`; consolidation + signed deletion + replay refusal all live-tested |
| Storage pools (common-good cap + declared budgets) | **done** 2026-08-30 — `--pool-common-mb` caps total free-tier storage (custom-quota identities exempt), enforced in drops/journal/blobs, reported in `/status.json`; market/personal budgets declared, not yet enforced |
| Storage market: rentals, vouchers, vault contract | **done** 2026-08-31 — design green-lit by Roberto; `docs/settlement-design.md`, `contracts/StorageVault.sol` (compiles, ABI in repo, **not yet deployed**), relay `rent`/`voucher` frames + market pool enforcement live-tested (reservation refusal, allowance, lapse, replay/short-voucher refusal, 3-epoch prepay cap), admin console Market tab, wallet prompt §e, help-page brief `storage-payments-help-brief.md`. Remaining: deploy the vault (needs Roberto's chain account), wallet implements §e |
| Wallet-migration prompt for the design project | **done** 2026-08-30 — `docs/wallet-migration-prompt.md`, §11 format, every frame shape verified against the handlers; ready to paste into the design project |
| **Wallet v2 live verification** | **done** 2026-09-01 — designer's rebuilt wallet (`newwallet-2026-09-01/`) driven unmodified against two live relays: 27/27 e2e checks (claim, push+dack, blobs, journal restore, owner panel, market cycle, full parked-mail chain), voucher sig independently verified via from-scratch keccak+ecrecover. Reply + 3 small wallet fixes: `docs/wallet-v2-test-report.md`. Relay met a.11: `x25519` stored from hello/invite_claim (schema v4), `invite_ok` +node_id |
| **Relay input hardening** | **done** 2026-09-23 — a single wrong-typed JSON field (e.g. `hello` with `"ts":"x"`, pre-auth) threw an uncaught `json::type_error` and killed the process; every frame and HTTP request is now guarded (`bad_field` / HTTP 400), worker threads survive any escaped exception, malformed `peers.json` entries are skipped. Also: peers are recorded as plain `ws://` at their advertise address (a `tls:true` hello no longer makes others dial TLS on the plain port), `journal.more` is true when a page is cut by the 2 MiB cap. Smoke 67/67 |
| **Wallet onion routing** | **done** 2026-09-23 — default-on (Settings → Privacy); every stored payload leaves on a fresh anonymous socket through entry → middle → recipient's relay; pure-JS seal byte-identical to `crypto::seal`; ✓ on entry acceptance, ✓✓ on `dack`; retry another entry, then direct fallback (route failure, or 15 min without receipt). Live-tested with 3 relays incl. one relay down. Wallet in `newwallet-2026-09-01/` (zip sources + rebuilt `r2r.html`) |
| **Invite activation + new seed network** | **done** 2026-09-23 — one registration per identity (`already_registered`); members' 3 codes minted locked, unlocked by ≥3 received+acked payloads plus the inviter's `vouch` (inviter's wallet sends it after one message each way; genesis/operator codes need traffic only); `invite_status` frame; wallet adds the inviter as first contact and shows lock progress. Seed list reset to r2r.homes only, `--seed`/`R2R_SEEDS` added, stale `seed` flags in peers.json ignored. Schema v5. Smoke 77/77; wallet flow live-tested |
| **Onion v2 + scrypt wallet keys** | **done** 2026-09-23 — onion layers name 1–3 candidates each (multi-recipient seal, binary layers, no base64 compounding); relays fall through to the next candidate on dial failure; terminal standbys forward to `fp@home` or park with pointers to home + rendezvous. Wallet: Standard (3) / Extra (5) positions, up to 3 candidates each, entry failover, relays filtered to those the primary heard from in 3 min. Wallet PIN/passphrase keys now scrypt N=2^16 r=8 (64 MiB), PIN policy on every path, brain-wallet keys refused, old vaults auto-upgrade. Cross-checked wallet↔relay library; smoke 77/77; 6-relay outage tests |
| **Site content refresh** | **done** 2026-09-23 — all 7 doorway pages audited and corrected (onion by default, invite activation, PIN/passphrase, real glibc requirement, seeds, no old-relay migration, no account system in the top bar); 9 served catalog strings updated in all 37 languages; contact page `/m` now shows the inviter's `r2r:R2R_…?relay=` link (was the fingerprint, which wallets cannot add) and `/api/contact` gains `address`; redeem gets its own `redeem.err.inactive` key (the old `redeem.err.locked` meant something else). Downloads: portable relay/probe rebuilt (static OpenSSL, glibc ≥ 2.38), obsolete migration files moved to `/var/lib/r2r/assets-retired`, site bundle published as `/assets/r2r-doorway-bundle.zip` and `install.sh` now fetches it from r2r.homes instead of r2r.help. Needs a relay restart to go live |
| **White paper page, wallet published, relay-first onboarding** | **done** 2026-09-24 — `/paper` is a doorway page generated from `docs/R2R-WHITEPAPER.md` (`tools/build-paper-page.py`: sticky contents sidebar with scroll-spy, hero, abstract, inline paper, download card with SHA-256 confirmed live from `/assets/`), linked from a "View/Download the Paper" button on the home page and a "Paper" nav item; PDF + Markdown served from `/assets/`. Relay: bundle may carry extra `templates/<lang>/<name>.html` pages (reserved routes protected), "Status" nav injection is idempotent (bundle now carries Paper + Status natively), `.md` assets are `text/markdown`. Wallet published: `/assets/r2r-wallet.html` (designer build of 2026-09-23, `<title>` set), `r2r-setup-card-forge.html`, `r2r-wallet-src.zip` (clean sources, no uploads/); home + Downloads pages link "open in browser" and "download". Onboarding copy pushes running a relay as the permissionless way in (home hero card, "Two ways in" steps, new FAQ, relay-page callout, `redeem.form.no_code_html` + `redeem.done.step4_html` in all 37 languages). Doorway source now lives in `web/doorway/`, packaged by `scripts/build-doorway-bundle.py`; bundle 1.1.0. Smoke 77/77 |
| **Follow-ups 2026-09-24 (pm)** | **done** — install wording says where the command runs and whose IP goes in (run-a-relay, home, install-a-relay.md); `/paper` sidebar has a drop-zone SHA-256 verifier against `/assets/`; Downloads page has a white-paper section with PDF/MD buttons (its verifier already covers every served file). `install.sh` now mirrors the source relay's `/assets/` into `/var/lib/r2r/assets` (hash-verified, local copies reused) and sets `R2R_ASSETS_DIR`, so a fresh relay serves site + downloads + paper with no web server. Wallet: the "Set up your own relay" steps and the Settings "Run your own relay" block were rewritten to the install.sh flow (template + dist patched by region in the bundle, scripts parse-checked; `newwallet-2026-09-01/` updated, CLAUDE.md note inside the zip for the design project). Vault: compiled with solc 0.8.26 via soljson in node (ABI identical), `contracts/StorageVault.bin`, `deploy-base.json` (calldata incl. Base USDC ctor arg) and `docs/vault-deploy.md`; deployment itself needs Roberto's Base account. Old network: five v1 relays identified (IPs in the August builds, all still up, SSH open, no key here); runbook `docs/old-network-replacement.md`, `find-old-relay.sh` + `remove-old-relay.md` republished to `/assets` |
| **Owner/quota commands accept the wallet address** | **done** 2026-09-24 — `--owner-add`, `--owner-remove`, `--set-quota`, `--clear-quota` take the `R2R_…` address the wallet shows in Settings as well as a 64-hex fingerprint (`crypto::pubkey_from_contact_address`: base32 + SHA3-256 checksum, the inverse of `contact_address`; `resolve_identity` in main.cpp). Tested against a Python-derived vector, corrupted checksum refused; smoke 77/77. Site, install guide and wallet text now say "paste the R2R_ address". Deployed to r2r.homes and republished at `/assets/r2r-relay`. Note: the build box needs swap for `session_tls.cpp` (a 2 GB `/swapfile` was added, not in fstab); an invite `R2R-75ZG-6YGD-0HEV` was minted for Roberto's first identity. Site brief for the relay-map/discussion site: `docs/relay-map-site-brief.md` |
| **/status redesign + site nav** | **done** 2026-09-01 — `/status` is now a doorway-styled live page (stats grid, node info, peers, endpoint links opening in new tabs, 10 s refresh); "Status" injected into every page's site-nav at load (`inject_status_nav`; next bundle rev should carry it natively + i18n the label) |
| **Deploy to r2r.homes** | **done** 2026-08-31 — new binary (schema v3) live as the service, doorway serving the whole site (nginx now proxies everything to the relay; old static portal retired, config backup `/etc/nginx/r2r.homes.pre-doorway.bak`). Cloudflare-fronted: peers keep dialing `92.113.147.233:8787`, wallets get `wss://r2r.homes/ws` (`R2R_PUBLIC_WS_URL`), scheme via `X-Forwarded-Proto`, doorway `{{HOST}}` now follows the request Host. `/assets` downloads refreshed (relay, probe, install.sh) + `r2r-market-kit.zip`. Note: bundle carries EN templates only — per-language templates remain with the doorway design project |

### Pointer design as implemented (v1)

- Emission: after any successful local store for an identity that is not
  homed here and not connected here (`emit_pointer_if_remote`). Skipped when
  the relay has no advertise address.
- Statement: `r2r-pointer-v1\n<fp>\n<holder address>\n<ts>`, signed with the
  holder's node key; carried with `node_id` + `ed25519` and verified by every
  relay that handles it, including a contradiction check against the gossip
  pin for that node id.
- Routing: to the fingerprint's home relay when known, else to its
  rendezvous set — the `k=3` lowest `sha256("r2r-rdv-v1" + fp + node_id)`
  over the verified peer set plus self. Hop-limited (4), deduped via the
  seen cache.
- Storage: `pointers` table, upsert per (fp, holder), newest statement wins,
  expiry follows drop TTL, pruned in the sweep cycle.
- `locate` (session must have a proved hello) → `located {pending,
  pointers:[{address,count,ts}]}`; a pointer arriving for a subscribed live
  session is pushed as `mail_at {address, count}`.
- Privacy note: the holder address is cleartext in v1. Sealing it to the
  recipient needs an x25519 key the relay does not have for client
  identities — goes into the wallet-migration prompt (identities register
  an x25519 alongside ed25519).

### Storage market as implemented (v1)

- Normative design: `docs/settlement-design.md` (parameters table, voucher
  byte format, threat notes). Schema v3 adds `rentals` + `vouchers`.
- User picks relays; `rent {bytes, payment_key}` reserves from
  `--pool-market-mb` (never oversold: committed is subtracted from
  inventory). Rented bytes are real allowance in all three store paths;
  renters are exempt from the common pool. First epoch on grace (35 d).
- `voucher` = cumulative micro-USDC, EIP-191-signed by the wallet's payment
  key; relay stores it verbatim (opaque), enforces monotonic + full-epoch
  increments, extends `paid_until` (≤ 3 epochs ahead). Lapse via sweep;
  lapsed rentals confer nothing (verified byte-exact).
- Settlement: `admin_list_vouchers` → console **Market** tab → operator's
  own browser wallet redeems against `R2RStorageVault` (no chain keys on
  the server, contract pays only chain-registered payout addresses, $10
  refundable bond, 60-day exit notice, 40-day deposit-withdraw delay).
- Discovery: `welcome.market` + `/status.json` `market` object.

### Safe deposit as implemented (v1)

- Authorization: `r2r-collect-v1\n<fp>\n<holder addr>\n<scope>\n<ts>\n<nonce>`
  signed by the identity key. **Holder-bound** (a capture is useless anywhere
  else) and **single-use** (the holder burns the nonce in `used_authz`;
  replay is refused and logged). Freshness window 7 days. Deliberately
  silent about the collector, so gathering mail never reveals where an
  identity lives.
- Scopes: `collect` (copy) and `collect-delete` (the holder deletes the
  handed-over payloads in one transaction after `collect_done`).
- Flow: client sends its relay `deposit {id, pubkey, scope, targets:[{address,
  ts, nonce, sig}]}` (session identity must match); the relay presents each
  authorization over its peer links; `collect_item`s stream back and are
  stored through the normal path (so live push and pointers fire); the guard
  map `collecting_` only accepts items this relay actually requested from
  that peer. `collect_done` clears the matching pointer.
- Batch 200 per authorization; `more:true` tells the wallet to issue a fresh
  authorization for the remainder.
- `r2r-probe deposit <holder[,holder…]> [scope]` drives it from a shell.
