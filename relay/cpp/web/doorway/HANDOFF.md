# R2R doorway → relay integration handoff

**From:** doorway-side session (PHP repo at `92.113.147.177:/usr/local/lsws/home/r2r.help/`)
**To:** relay-side session (C++ repo at `92.113.147.233:~/r2r-relay`)
**Purpose:** everything needed to package the r2r.help doorway into the R2R relay binary itself. Once integrated, `r2r.help` as a standalone site goes away — every relay serves the doorway from its own domain/IP.
**Companion doc:** [`relay-codebase-survey.md`](https://r2r.help/handoff/serve.php?f=relay-codebase-survey.md) — the architecture survey your side wrote up earlier. Both sides agreed on the decisions summarized at the bottom of that doc.

---

## Bundle contents

```
templates/en/*.html        pre-rendered static pages (English)
                           with sentinels for host-substitution
i18n/en.json               canonical string catalog (410 keys)
i18n/it.json               partial Italian (fallback to en for missing)
i18n/languages.json        list of supported languages + display metadata
assets/sippis-shell.css    shared stylesheet
assets/favicon.svg         site favicon
assets/sippis-logo.svg     legacy logo (used by dynamic pages)
assets/js/qrcode.min.js    QR renderer (davidshimjs/qrcodejs)
assets/js/card.js          client-side setup-card canvas renderer
partials/mesh.php.inline   the mesh SVG (raw SVG — port to your templater)
ref-php/redeem.php         reference impl of the redeem flow (state machine)
ref-php/m.php              reference impl of the /m/<token> contact-add page
ref-php/admin.php          reference impl of the operator admin console
ref-php/card.php           reference impl of the setup-card JSON endpoint
ref-php/lib/card.php       reference impl of the server-side PNG renderer
                           (ImageMagick — skip; card.js does this client-side)
ref-php/auth/_topbar.php   reference impl of the topbar nav
ref-php/lib/_docs_head.php reference impl of docs-page header
ref-php/lib/_docs_foot.php reference impl of docs-page footer
manifest.json              per-file SHA-256s
HANDOFF.md                 this file
```

## Static pages ready to serve

These 7 HTML files are ready to serve as-is, with sentinel substitution at request time:

| File | Route | Notes |
|---|---|---|
| `templates/en/index.html` | `/` or `/index.html` | homepage. Stats block hidden below threshold |
| `templates/en/privacy.html` | `/privacy` | what a relay knows / never knows |
| `templates/en/faq.html` | `/faq` | frequently asked |
| `templates/en/network.html` | `/network` | how the mesh works |
| `templates/en/run-a-relay.html` | `/run-a-relay` | operator install guide |
| `templates/en/homes.html` | `/homes` | known-relays list (JS fetches `/peers.json`) |
| `templates/en/downloads.html` | `/downloads` | asset downloads + hash-verify widget |

## Sentinels

Every pre-rendered HTML file contains these placeholders. Substitute at request time (or once per (page, lang) at startup and cache):

| Sentinel | Meaning | Source |
|---|---|---|
| `{{HOST}}` | this relay's public hostname/IP as visitors see it | `R2R_ADVERTISE` config, admin-changeable via new WS frame `admin_set_advertise` |
| `{{SCHEME}}` | `https` or `http` per request | request's `X-Forwarded-Proto` or `req.https` |
| `{{BASE}}` | URL prefix for sub-path installs (`""` for root, `"/R2R"` for sub-path) | `R2R_BASE_PATH` config, defaults to `""` |
| `{{LANG}}` | language code (e.g. `en`, `it`) | picked from cookie/`Accept-Language` |
| `{{LANG_DIR}}` | `ltr` or `rtl` per language | `i18n/languages.json` |
| `{{PRIMARY}}` | primary brand color hex | `R2R_PRIMARY_COLOR` config, default `#0EADB5` |
| `{{SECONDARY}}` | secondary brand color hex | `R2R_SECONDARY_COLOR` config, default `#F26430` |
| `{{BG_TINT}}` | darkened primary for gradient (compute at load) | 30% darkened primary |

**Note on the current bundle:** the pre-rendered HTML files were rendered with `HOST = r2r.help` (they came out of the live PHP box). Do a global search-and-replace of any remaining resolved hostname to `{{HOST}}` before serving. The sed on the packaging side already caught `r2r.help` mentions in prose, but do a final pass in case anything slipped.

## i18n runtime

`i18n/en.json` is the canonical catalog. Keys follow `page.section.element_type` (e.g. `privacy.never.no_pii.title`). Values with the suffix `_html` contain markup and must not be HTML-escaped again on output; plain keys are safe to escape.

Interpolation: `{{NAMED}}` placeholders in string values (distinct from the page-level sentinels above — same syntax, different substitution stage).

For non-English languages: pass the `en.json` file to any capable translation LLM to produce `<lang>.json` copies (Roberto's chosen path — no human translators involved). Missing keys fall back to English cleanly, so partial translations don't break rendering.

At runtime, either:
- **Serve pre-rendered templates per language** (what you recommended in the survey): produce `templates/<lang>/<page>.html` at build time by re-rendering with `_sippis_lang = <lang>` and drop them next to `templates/en/`. Cache these; substitute sentinels per request.
- **Server-side JSON substitution**: keep only `templates/en/*.html` in the bundle, add a `{{t:key}}` sentinel form, substitute at request time from the language catalog. Slower but smaller bundle.

The pre-rendered path fits your "no logic in templates" recommendation.

## Dynamic pages — port from reference PHP

Four pages require server-side logic; the PHP reference implementations are in `ref-php/`. Port to your C++ HTTP handlers.

### 1. `redeem.php` — invite redemption

State machine with 4 views:
- `form` (default, no code) → landing form asking for the code
- `confirm` (code passes validation, invite is `unused`) → confirmation button before consuming
- `done` (POST redeems) → shows the branded setup card (client-side render via `assets/js/card.js`)
- `err` (all other cases) → shows a friendly error, offers try-again

Endpoints touched: `POST /invite/claim` (already exists on the relay per survey item 9). The mint side generates a `card_key` (32 random bytes), stores its SHA-256, and returns the `R2RSC1:<cardKeyHex>:<relay_ws_url>:<bot_pub_hex>` string.

Card gen: **fully client-side** now (`assets/js/card.js`). No ImageMagick needed. The relay just returns the card string and the client draws the branded card on a canvas.

Error copy is in i18n keys `redeem.err.*`. See `ref-php/redeem.php` for the full state machine.

### 2. `m.php` — contact-add token page

`GET /m/<token>` looks up the token in the invites table (`contact_token` column), returns the pubkey + relay WS URL for the identity that minted the invite. The page shows those to the visitor with Copy buttons.

Reference: `ref-php/m.php`. i18n keys: `m.*`.

### 3. `admin.php` — operator admin console

Owner-only. Actions: mint N root codes, revoke a code (with descendant-tree cascade), download ZIP of recent cards.

**Per survey decision:** admin becomes a **thin JS client over WSS** using the existing `admin_accounts` / `admin_set_quota` / `admin_invites` WS frames, plus new frames to add: `admin_list_invites`, `admin_revoke_invite(cascade=true)`, `admin_set_ttl`, `admin_search_accounts`, `admin_delete_account`.

Reference `ref-php/admin.php` shows the UI shape and the revoke-cascade BFS logic (port that logic to the relay's `admin_revoke_invite` implementation). i18n keys: `admin.*`.

**New admin frame requirement from the doorway side:** `admin_set_advertise(new_host)` — lets operators change the advertised host without restarting the relay. The doorway needs this because `{{HOST}}` is substituted at startup and stays stable.

### 4. `card.php` — setup-card JSON endpoint

Currently PHP; port to a C++ handler:
- `GET /card?code=…&fmt=json` → `{code, redeem_url, contact_url?, host}`
- `GET /card?code=…` (or `fmt=png`) → **drop this on the relay** (no ImageMagick). `card.js` renders client-side; JSON-only is enough for the wallet to draw the card.

Reference: `ref-php/card.php`.

## JSON endpoint contracts

The doorway JS talks to these relay endpoints. Field names below are what the JS expects.

### `GET /peers.json` (already exists per survey #10)

Shape confirmed:
```json
{
  "version": 1,
  "updated_at": <unix>,
  "node": {"id": "…", "advertise": "host:port", "ed25519": "…", "x25519": "…"},
  "peers": [
    {"address": "1.2.3.4:8787", "url": "wss://relay.example/ws", "tls": true,
     "verified": true, "node_id": "…", "x25519": "…", "last_ok": <unix>}
  ],
  "count": <int>
}
```

Consumed by: `homes.html` (verified-peers table), `downloads.html` (cross-relay hash check).

### `GET /assets/` (already exists per survey #3)

Shape (currently returned by the C++ relay per survey — array of file records with SHA-256):
```json
[
  {"name": "r2r-relay", "size": 25165824, "modified": <unix>,
   "sha256": "abc…", "url": "/assets/r2r-relay"}
]
```

Consumed by: `downloads.html` (file listing + hash verification).

**CORS on `/assets/` must send `Access-Control-Allow-Origin: *`** so the "cross-check against other relays" widget can fetch peer `/assets/` listings from the browser. Survey #15 confirmed this is already the case.

### `GET /api/stats` (new — thin wrapper around existing SQL)

```json
{"identities": <int>, "invites_unused": <int>, "invites_claimed": <int>}
```

Consumed by: `index.html` (below-threshold check hides the block). Not urgent — until the numbers are meaningful you can omit or return zeros; the JS hides the block gracefully.

### `GET /api/contact/{token}` (new — replaces `m.php` DB query)

```json
{"pubkey": "…hex", "relay_url": "wss://…", "revoked": false}
```
or `404` for unknown / non-existent contact. Consumed by: `m.html`.

## Per-page CSP / robots / cache policy

The relay currently sends `default-src 'none'; style-src 'unsafe-inline'` and `Disallow: /` (survey #18). These break the doorway. Per-page overrides needed:

| Page | robots | Cache-Control | CSP (Content-Security-Policy) |
|---|---|---|---|
| `/` (index) | `index,follow` | `public, max-age=300` | `default-src 'self'; script-src 'self' 'unsafe-inline' https://www.youtube.com; frame-src https://www.youtube.com; img-src 'self' data:; style-src 'self' 'unsafe-inline'` |
| `/privacy`, `/faq`, `/network`, `/run-a-relay` | `index,follow` | `public, max-age=3600` | `default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'` |
| `/homes`, `/downloads` | `noindex,follow` | `no-store` | `default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self' https://*` (cross-relay fetches) |
| `/redeem`, `/m/*` | `noindex,nofollow` | `no-store` | `default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'` |
| `/admin*` | `noindex,nofollow` | `no-store` | `default-src 'self'; script-src 'self' 'unsafe-inline'; connect-src 'self' wss://* ; style-src 'self' 'unsafe-inline'` |
| `/assets/*`, `/js/*`, `*.css`, `*.svg` | (irrelevant) | `public, max-age=86400, immutable` | (as today) |

The `'unsafe-inline'` allowances for scripts are because `card.js` bootstrap on `/redeem` and the fetch loops on `/homes`/`/downloads` are inline. Refactor to external only if you want a stricter policy.

## Invite format migration (survey #9)

Codes today are lowercase UUID v4 (RFC-generated, 36 chars with dashes). We're moving to `R2R-XXXX-XXXX-XXXX` (short bare) and `R2R-<8-hex-IPv4>-XXXX-XXXX-XXXX` (with routing hint).

Format details:
- **Last 3 groups: 60-bit invite entropy** in Crockford base32 (alphabet: `0123456789ABCDEFGHJKMNPQRSTVWXYZ`, no I/L/O/U). 4 chars per group × 3 = 60 bits. Ample for single-use codes behind rate limiting.
- **Optional hint groups (before the entropy) encode routing info.** Length-as-discriminator:
  - **0 hint groups** (`R2R-XXXX-XXXX-XXXX`) — bare code, only redeemable on the minting relay. Wrong-relay redemption → 404 with "this code was minted elsewhere; use the full URL your friend sent."
  - **2 hex hint groups** (`R2R-AAAA-BBBB-XXXX-XXXX-XXXX`, 8 hex chars = 4 bytes) — IPv4 hint. Wrong-relay redemption decodes the hint, redirects to `https://<ip>/redeem?code=<full>`.
  - **Longer** (IPv6, domain) — not typeable. QR/URL form only.
- **Canonical invite URL** (what QRs encode and what setup cards contain): `https://<relay>/R2R-XXXX-XXXX-XXXX` (or with hint groups). Wallet parses the URL, extracts code, calls `POST /invite/claim`.

Migration plan (agreed per survey #9):
1. Widen `is_uuid_v4()` validators in `http_routes.cpp:429` and `hub.cpp:1199` to accept both UUID-v4 (legacy) and the new `R2R-…` format.
2. Store the canonical full string as the PK; codes are opaque TEXT, no schema change.
3. Bump `PRAGMA user_version` to 2.
4. Switch `mint_invites` in the relay to the new generator.
5. Optionally add `relay_hint TEXT NULL` column (nice for debugging; not required).
6. Doorway `/redeem` accepts both formats (regex `[A-Z0-9-]{6,64}` — already widened).

## Revoke-cascade migration (survey #9b)

Add two columns to `invites` in the same `user_version=2` bump:
```sql
ALTER TABLE invites ADD COLUMN revoked_at INTEGER NULL;
ALTER TABLE invites ADD COLUMN revoked_by TEXT NULL;
```

"Open" becomes `burned_at IS NULL AND revoked_at IS NULL`. Add:
- `admin_revoke_invite(code, cascade=true)` WS frame — implements the BFS in `ref-php/admin.php:154-201` natively.
- Cascade rule (confirmed): revokes unclaimed descendants only — does NOT unregister identities already created from claimed ones.

Reflect `revoked` count in `/status.json` as a distinct counter.

## Sub-path mount (survey #11-12)

`R2R_BASE_PATH=/R2R` config option — strip the prefix at the top of `handle_http_request()`, thread `{{BASE}}` into every URL the doorway emits. All templates in this bundle expect `{{BASE}}` to be substituted (empty string is fine for root install).

**Caveat to bake into copy:** sub-path installs serve the doorway but the relay still needs its native ports (8787/8788) exposed to be a routable peer. `run-a-relay.html` already documents this in the TLS section.

Announce `{"base": "/R2R"}` (empty for root) in `GET /status.json` and `GET /node.json` so wallet JS can prefix its own API calls.

## Copy audit — resolved

Four claims in the doorway prose were verified against the code (your session's response):

1. **Onion routing (privacy)** — CONFIRMED live. Copy unhedged.
2. **Coarse liveness (privacy)** — REWRITTEN to reflect on-disk hour + in-RAM precise presence for owner and watchers.
3. **Store-and-forward failover (faq)** — SOFTENED. Current copy: "If your home relay is briefly unreachable, mail waits a few minutes at the forwarding relay and are retried; if it stays down, delivery fails." Your side offered to promote queue-expiry to `store_locally` on dial-failure to make the promise true — awaiting go/no-go from Roberto.
4. **Revoke-cascade (index FAQ, run-a-relay)** — copy PRESERVED; you agreed to add the frame in this milestone.

## What survives from your survey unchanged

Confirmed and load-bearing:

- Templates load from disk (`/var/lib/r2r/doorway/`), sentinel-substitute once per (page, lang), cache.
- Doorway static handler needs nested paths (assets/js/) — not the flat `serve_asset` handler used for `/assets/`.
- Card generation is client-side (canvas + qrcode.js). `card.js` in this bundle. `card.php`'s PNG path can be dropped from the relay build.
- Admin is a JS-over-WSS client, not new HTTP endpoints (except for the JSON reads listed above).
- Bundle intake is operator-side (curl + unzip in `install.sh`).
- Three build profiles: `r2r-relay-full` (this bundle + admin), `r2r-relay-adminOnly` (admin only), `r2r-relay-headless` (no doorway).

## Verifying the bundle

```
manifest.json                per-file SHA-256s
```

Compute and compare on intake. Refuse partial bundles loudly.

## Companion URLs

- Survey (published from the doorway side): https://r2r.help/handoff/serve.php?f=relay-codebase-survey.md
- This bundle: https://r2r.help/handoff/r2r-doorway-bundle.zip
- Live PHP reference (going away once the relay-embedded version replaces it): https://r2r.help/

## Open items for the doorway side (Roberto to decide)

- **Queue-expiry → store_locally on dial-failure?** Your side offered to promote. Yes lets us un-hedge the FAQ copy about failover. Contained change on your side, no doorway churn.
- **Translations for `i18n/*.json`.** Roberto is passing `en.json` to a translation LLM; each new `<lang>.json` gets dropped alongside `en.json`. Fallback-to-English works fine while these trickle in.

---

*Bundle assembled 2026-08-29 by the doorway-side session. When the bundle is regenerated, bump the version stamp in `manifest.json`.*
