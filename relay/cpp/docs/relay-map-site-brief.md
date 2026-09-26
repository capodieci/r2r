# R2R network site: live relay map + community discussion

Brief for the agent building the site. Written 2026-09-24 from the relay code
and the live r2r.homes deployment; every endpoint and field below was checked
against the running relay.

## 1. What to build

A public web site, separate from the relay's own pages, with two jobs:

1. **A world map of the R2R network.** One small house per relay, placed by
   geolocating the relay's public IP address. Anyone can look at it; nobody
   needs to install a relay or a wallet to see it. It is the network's
   "how big are we today" page and the first thing a curious visitor sees.
2. **A place to discuss and analyse the network.** Threads about the
   protocol, the relays, the wallet, the storage market and the white paper;
   charts of how the network grows; a discussion thread per relay.

Audience: people deciding whether to run a relay, operators comparing notes,
and technical readers of the white paper. Tone matches r2r.homes: plain,
concrete, no marketing gloss.

## 2. Rules that are not negotiable

The relay network's whole point is that nobody watches. The site must hold
itself to the same standard, or it undermines what it shows.

- **No visitor tracking.** No analytics, no cookies beyond what a login
  strictly needs, no fingerprinting. The web server must not log client IP
  addresses (`access_log off` in nginx, or an equivalent).
- **No third-party resources at view time.** No CDN scripts, no Google Fonts,
  no external map tiles, no external geolocation calls from the browser.
  Everything the page loads comes from the site's own host. (A tile server
  or a geolocation API called from the visitor's browser would hand every
  visitor's IP to a third party.)
- **Only relay addresses are geolocated.** Relay addresses are public
  infrastructure, published on purpose by every relay. Never geolocate,
  store or display anything about visitors.
- **Publish only what relays already publish.** The fields in section 3.
  Never identity fingerprints, invite codes, payloads or anything from a
  relay's database. The aggregator in section 4 reads public HTTP endpoints
  only.
- **Read without an account.** Map and discussions are readable by anyone.
  Posting may need a login (section 6), never an email address or phone
  number.

## 3. Where the data comes from

Every relay serves the same JSON endpoints on its plain port (8787, HTTP)
and its TLS port (8788, HTTPS with a self-signed certificate). The seed
relay r2r.homes is also reachable at `https://r2r.homes/` through nginx and
Cloudflare with a real certificate. All JSON routes send
`Access-Control-Allow-Origin: *` and `Cache-Control: no-store`.

### 3.1 `GET /peers.json`: the relay list

What this relay has verified through direct contact, plus the compiled-in
seeds. Relays gossip these lists every minute, so any relay's view converges
to the whole network. Live sample from r2r.homes (peers empty at the time of
writing; five more relays are being installed this week):

```json
{
  "count": 0,
  "node": {
    "advertise": "92.113.147.233:8787",
    "ed25519": "ymWUT87Gmln4gb/8vXPKjrTFqYOAUQ8pfO9FQ+WFqYM=",
    "id": "c2f1fe40e29f2c4f60bc648e2a6c4b22",
    "x25519": "JYS4fPOVXssLcS3NSHPW2Z7piX/PXdwJo1qpIJoZigA="
  },
  "peers": [],
  "updated_at": 1790275402,
  "version": 1
}
```

Each entry of `peers` has exactly these fields (only verified peers and seeds
are published):

| Field | Meaning |
|---|---|
| `address` | `host:port` other relays dial. Usually an IPv4 and port 8787. This is what you geolocate. |
| `url` | The WebSocket URL for that address (`ws://host:8787` or `wss://…`). |
| `tls` | Whether the peer was reached over TLS. |
| `verified` | The peer completed a signed handshake with this relay. |
| `node_id` | 32-hex id derived from the peer's signing key. Stable across restarts and IP changes. |
| `x25519` | Onion-routing key. Not needed by the site. |
| `last_ok` | Unix time of the last successful contact. |

`node` describes the relay you asked. Its `advertise` is its own address.

### 3.2 `GET /status.json`: one relay's counters

```json
{
  "version": "1.0.0", "uptime": 10389, "node_id": "c2f1fe40e29f2c4f60bc648e2a6c4b22",
  "peers_active": 0, "peers_known": 0, "connections": 0, "clients": 0,
  "relay_links": 0, "tls_connections": 0,
  "identities": 2, "invites_open": 10, "invites_burned": 2, "invites_revoked": 0,
  "drops_stored": 0, "drop_bytes": 0, "drops_accepted": 0, "drops_rejected": 0,
  "frames_in": 0, "frames_out": 0, "frames_forwarded": 0, "onion_peeled": 0,
  "ttl_days": 7, "base": "",
  "pools": { "common_cap_bytes": 0, "common_used_bytes": 0, "market_cap_bytes": 0, "personal_cap_bytes": 0 }
}
```

Fields worth showing per house: `version`, `uptime` (seconds), `identities`
(accounts homed there), `drops_stored` (messages waiting), `peers_active`.
A `market` object appears when a relay sells storage.

### 3.3 `GET /node.json` and `GET /health`

`node.json` = identity and ports (`advertise`, `node_id`, `ws_port`,
`wss_port`, `version`, `proto`). `health` answers `{"ok":true,…}` and is the
cheapest liveness probe. Old v1 relays answer `{"error":"not_found"}` on both;
the site should treat anything without `node_id` as not an R2R v2 relay.

### 3.4 Optional: the metrics database on r2r.homes

r2r.homes already runs a one-minute job that polls every known relay's
`/status.json` and writes it to MariaDB (database `r2r_main`, read-only user
`r2r_dash`, authentication by unix socket, so only a process on that host
can read it). Tables:

- `node_directory`: current state per relay (`address`, `node_id`,
  `reachable`, `version`, `latency_ms`, `uptime_seconds`, `identities`,
  `drops_stored`, `peers_active`, `first_seen`, `last_checked`,
  `last_reachable_at`, `consecutive_failures`).
- `node_metrics`: the same counters as a time series, 30-day retention.
- `network_summary`: one row of network totals.

If the site is hosted on r2r.homes this is the easiest source for history
charts ("relays over time", "identities over time", per-relay uptime). If it
is hosted elsewhere, run the aggregator below instead; do not open MariaDB to
the network.

## 4. Architecture: a server-side aggregator and a static front end

Browsers cannot fetch most relays directly: an `https://` page may not call
`http://IP:8787`, and `https://IP:8788` has a self-signed certificate. And
geolocation must not be done from the visitor's browser (section 2). So:

```
 every 5 min                                            visitor's browser
 ┌──────────────────────────┐   writes    ┌──────────────┐   GET     ┌───────────┐
 │ aggregator (cron/timer)  │ ──────────▶ │ relays.json  │ ◀──────── │  map page │
 │  · relay list            │             │ (static)     │           │  (static) │
 │  · per-relay status      │             └──────────────┘           └───────────┘
 │  · offline IP geolocation│
 └──────────────────────────┘
```

The page is static files; the only dynamic piece is one JSON file rewritten
by a small script. Nothing on the site touches a relay database.

### 4.1 The aggregator, step by step

Python 3 is fine (it is what the existing metrics job uses). Run it every 5
minutes from cron or a systemd timer, with a total time budget of about a
minute, and never let a failure leave a broken file: write to a temp file and
rename, and keep the last good `relays.json` when a run fails.

1. **Start from the seed.** `GET https://r2r.homes/peers.json`. Take
   `node.advertise` (r2r.homes itself) plus every `peers[].address`.
2. **Widen the view.** For each address found, `GET http://ADDRESS/peers.json`
   (5-second timeout) and add every address you have not seen yet. Two or
   three rounds are enough; the network is small. This makes the map show
   what the network knows, not only what one relay knows.
3. **Poll each relay once.** `GET http://ADDRESS/status.json` (5-second
   timeout). Reachable = answered with a `node_id`. Keep `version`, `uptime`,
   `identities`, `drops_stored`, `peers_active`. For r2r.homes use
   `https://r2r.homes/status.json` (its origin IP is behind Cloudflare and
   nginx, so the bare address may not answer on 8787 from outside; that is
   expected).
4. **Geolocate the host part of each address** with an offline database, not
   an API: MaxMind GeoLite2-City (free, needs an account and attribution) or
   DB-IP Lite (free, attribution). Refresh the database monthly. Resolve a
   hostname to an IP first. Keep city, country code, latitude and longitude;
   round coordinates to two decimals (about 1 km) because that is all the
   data is good for anyway. IP geolocation is datacenter-level: a VPS shows
   up in the provider's city, which is honest enough for "where are the
   relays".
5. **Remember first sightings.** Keep a small state file
   (`address → first_seen`) so the map can say "since 23 Sep 2026". The
   public endpoints only give `last_ok`.
6. **Write `relays.json`:**

```json
{
  "generated_at": "2026-09-24T18:50:00Z",
  "sources": ["https://r2r.homes/peers.json", "per-relay /peers.json and /status.json"],
  "geo_attribution": "IP geolocation by DB-IP (https://db-ip.com)",
  "relays": [
    {
      "address": "92.113.147.233:8787",
      "node_id": "c2f1fe40e29f2c4f60bc648e2a6c4b22",
      "reachable": true,
      "version": "1.0.0",
      "uptime_seconds": 10389,
      "identities": 2,
      "messages_held": 0,
      "peers_active": 0,
      "first_seen": "2026-09-23T11:27:00Z",
      "last_ok": "2026-09-24T18:49:40Z",
      "site": "https://r2r.homes/",
      "geo": { "lat": 52.37, "lon": 4.90, "city": "Amsterdam", "country": "NL" }
    }
  ]
}
```

   `site` is `http://ADDRESS/` for ordinary relays (every relay serves its
   own home page there) and the public host name when one is known
   (r2r.homes). Leave `geo` null when lookup fails; the map lists the relay
   without a house.

7. **Publish** the file where the static site is served, with
   `Cache-Control: public, max-age=60`.

Keep the aggregator's own logs free of anything but relay addresses and
timings; it runs on infrastructure, not on visitors.

### 4.2 The map page, step by step

1. **Base map with no tile server.** Bundle a world countries outline
   (Natural Earth 1:110m, public domain, as GeoJSON or TopoJSON, ~100 KB
   simplified) and draw it client-side. Either `d3-geo` with the
   Natural Earth or Equal Earth projection on an SVG, or Leaflet with
   `L.geoJSON` and no tile layer. Land in a dark teal, borders a faint line,
   sea the page background. This keeps every request on the site's own host.
2. **One house per relay.** Inline SVG marker in the site palette
   (section 7). Suggested glyph, 22 px wide: teal roof and walls
   (`#0EADB5` stroke, fill `rgba(14,173,181,0.18)`), an orange door
   (`#F26430`), a small chimney. States:
   - reachable and verified: full colour;
   - unreachable at the last poll: same glyph at 40 % opacity, no door;
   - first seen in the last 7 days: a thin orange ring behind the house
     ("new").
3. **Overlaps.** Several relays in one datacenter city will share
   coordinates. Draw them as one house with a count badge; clicking expands
   them into a small ring, or opens the list filtered to that city.
4. **Hover and click.** Tooltip: city, country, address, version, up for
   (uptime, human units), accounts, messages waiting, since date, link to the
   relay's own site, link to its discussion thread (section 6).
5. **The list beside the map** (below it on phones): the same relays as
   rows, sortable by city, uptime, accounts, first seen; a text filter. The
   list is the accessible version of the map, so it must carry everything
   the tooltips do.
6. **Totals strip above the map:** relays reachable / known, accounts
   network-wide, messages waiting, and "as of HH:MM UTC". Refresh
   `relays.json` every 60 seconds while the tab is visible; never more often.
7. **Call to action on the page:** "No relay near you? Run one" linking to
   `https://r2r.homes/run-a-relay`. Growing the map is the point of the map.
8. **Works without JavaScript** as far as reasonable: server-render the list
   from the same `relays.json` at build time or in a tiny template, so the
   data is readable even when the map cannot draw.

## 5. Analysis pages

Once `relays.json` has been written for a while (keep every generated file,
or one row per run in SQLite), the site can chart:

- relays known and reachable over time;
- identities and messages waiting over time (network totals);
- per-relay uptime and reachability history;
- version spread (how fast operators upgrade).

If hosted on r2r.homes, the `node_metrics` table already holds 30 days of
this at one-minute resolution. Charts are drawn client-side from JSON files
produced by the aggregator; no charting service.

## 6. Discussion

Requirements rather than a stack, since the builder should choose what they
can run well:

- Threads grouped by area: protocol and white paper, running a relay, the
  wallet, storage market, one thread per relay (linked from the map, titled
  by address and city, created automatically the first time a relay is
  seen).
- Anonymous reading. Posting requires a login, but **no email or phone**.
  Two acceptable ways, either or both:
  1. Local accounts with a chosen name and a password. Nothing else asked.
  2. **Sign in with an R2R identity.** The wallet's identity is an ed25519
     key; its public form is the `R2R_…` address shown in the wallet's
     Settings. The site issues a random challenge, the user signs it in the
     wallet (or pastes a signature), the site verifies with TweetNaCl and
     treats the address as the handle. The relay's own `/admin` console
     already does exactly this in the browser with `nacl.js`, so the pattern
     is proven. This is the more "R2R" option and worth doing second.
- Moderation by the site operator; report button; rate limits per account
  rather than per IP (the server does not keep IPs).
- Markdown posts, code blocks, image uploads optional and stored on the
  site's own host.

A self-hosted forum that can be configured to these rules is acceptable
(Flarum, Discourse) as long as it makes no external calls from the visitor's
browser and its access logs are off; a small custom app is also fine.

## 7. Look and feel

Match r2r.homes so the two feel like one project. The relay site's stylesheet
is public at `https://r2r.homes/sippis-shell.css` and can be copied (not
hot-linked); the logo is `https://r2r.homes/sippis-logo.svg`.

| Token | Value |
|---|---|
| Primary (teal) | `#0EADB5` |
| Accent (orange) | `#F26430` |
| Background | `radial-gradient(ellipse at top, #09797E 0%, #11313e 55%, #1A2B3C 100%)` |
| Text | `#f4f7f8`; muted `rgba(255,255,255,0.72)`; dim `rgba(255,255,255,0.55)` |
| Panels | `rgba(0,0,0,0.20)` fill, `1px solid rgba(255,255,255,0.08)` border, 10 to 12 px radius |
| Buttons | pill shaped, teal fill or teal outline |
| Font | system sans (`-apple-system, "Segoe UI", system-ui, sans-serif`), monospace for addresses and ids |
| Light mode | `prefers-color-scheme: light`: background `linear-gradient(180deg, #f6fafb, #e6eff2)`, text `#16232a`, panels `rgba(0,0,0,0.04)` |

The relay's own pages (home, `/paper`, `/downloads`, `/run-a-relay`) are the
reference for spacing and tone. Phone width first: the map fits the viewport
width with a 16 px gutter and the list stacks under it.

## 8. Hosting and operations

- Static files plus the aggregator; any Linux host. If it lives on
  r2r.homes: an nginx `location` for the site with `access_log off`, and the
  aggregator as a systemd timer next to the existing `r2r-metrics-sync`.
- No CDN analytics, no "web vitals" beacons, no error-reporting SaaS.
- Serve `relays.json` with `Cache-Control: public, max-age=60`; pages and
  assets with long cache and content-hashed file names.
- Keep the geolocation database file out of the web root.

## 9. Acceptance checklist

- [ ] Opening the site with the browser's network panel open shows requests
      to the site's own host only.
- [ ] `relays.json` regenerates every 5 minutes; a relay switched off shows
      as unreachable within 10 minutes and disappears from the "reachable"
      count.
- [ ] A relay installed fresh (it dials r2r.homes on start) appears on the
      map within 10 minutes with a house in the right city.
- [ ] Two relays in one city render as one house with a "2" badge.
- [ ] The list view carries every field the tooltips show and works with
      JavaScript disabled.
- [ ] Web server access logs are off; the aggregator's log contains relay
      addresses and timings only.
- [ ] Posting needs no email or phone; reading needs nothing.
- [ ] Every page passes at 360 px width without horizontal scrolling.

## 10. Test data and references

- Live relay today: `92.113.147.233:8787` (r2r.homes, Cloudflare-fronted).
  Five more relays are being installed on `143.110.227.46`, `164.90.207.73`,
  `164.92.156.207`, `165.22.204.117` and `165.232.132.110`; expect six houses
  soon and use `https://r2r.homes/homes` and `https://r2r.homes/status` to
  compare against.
- Protocol and endpoint reference: `https://r2r.homes/paper` (sections 11
  and 16 cover the mesh and the HTTP API).
- Installing a relay: `https://r2r.homes/run-a-relay`.
- Relay source and README: the `r2r-relay` repository (`README.md`, "HTTP
  endpoints" and "The dashboard database").
