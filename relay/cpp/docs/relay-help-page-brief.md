# Brief for the website designer — "Run your own relay" help page

This is the complete brief for a new page in the R2R help section. Its job: a
visitor with a Linux server should be able to stand up their own relay with one
command, know how to administer it, and understand — honestly, without
marketing gloss — how the peer-to-peer network works and why it collects
nothing about them.

Every command and fact below is taken from the shipped relay and its
documentation. **Reproduce commands verbatim.** Do not shorten flags, rename
paths, or "clean up" output examples — operators paste these into root shells,
and a prettified command that doesn't work costs us their trust.

---

## 1. Context you need before designing

R2R is a privacy-first peer-to-peer messaging network. It is not an app talking
to a company's servers: it is a mesh of independent **relays**, run by anyone,
all executing the identical open binary. A relay is a dead drop — it holds
encrypted payloads it cannot read, forwards what belongs elsewhere, and gossips
a peer list so the network can find itself. There is no company database, no
account system, and no server that matters more than the others. `r2r.homes`
is a convenience portal and one seed node among equals, not an authority; the
network keeps working without it.

The audience for this page is two people at once:

1. **The operator** — comfortable with SSH and `sudo`, wants the command, the
   ports, and the admin reference. Serve them fast: the install block should be
   visible without scrolling past prose.
2. **The curious reader** — wants to understand what running a relay means,
   what data they'd hold, and why the network is built this way. Serve them
   with the "How the network works" and "What a relay knows" sections.

Match the look of the existing portal (`web/index.html` — the status page at
`r2r.homes`): same typography, same restrained tone. The page's footer line on
the portal is the voice to aim for everywhere: *"no personal data, no IP logs,
payloads expire automatically."* Plain statements, no exclamation marks, no
"military-grade encryption" language.

---

## 2. Page structure

Build the page in this order, with a sticky table of contents (anchor links)
on wide screens. Every section heading below is a suggested `<h2>`.

### 2.1 Hero — "Run your own relay"

One short paragraph, then the install command. Suggested copy:

> Every R2R relay is the same single binary — statically linked, with SQLite
> and OpenSSL compiled in. There is nothing to install first: no PHP, no
> Python, no Node, no database server, no web server. It runs on any x86-64
> Linux. Open ports **8787** and **8788**, run one command as root, and your
> server is part of the network.

Then the one-liner, in a large copyable block. Highlight the placeholder
(`YOUR.SERVER.IP`) visually — colored token, not just a comment — because the
single most common install mistake is leaving it unreplaced. It must be **that
node's own public IP**: it is the address other relays will dial.

```sh
curl -sSLO https://r2r.homes/assets/r2r-relay && \
curl -sSLO https://r2r.homes/assets/install.sh && \
curl -sSLO https://r2r.homes/assets/setup-tls.sh && \
curl -sSLO https://r2r.homes/assets/r2r-relay.service && \
chmod +x r2r-relay install.sh setup-tls.sh && \
sudo ./install.sh YOUR.SERVER.IP:8787
```

Immediately under it, a collapsible/secondary "verify the download first"
block — `https://r2r.homes/assets/` publishes the SHA-256 of every file:

```sh
curl -s https://r2r.homes/assets/ | grep -A2 '"r2r-relay"'
sha256sum r2r-relay
```

Then one paragraph stating exactly what the installer does, so nobody has to
trust it blindly: it creates the `r2r` service user, installs the binary to
`/usr/local/bin/r2r-relay`, lays out `/etc/r2r` and `/var/lib/r2r`, issues a
self-signed TLS certificate, and enables a sandboxed systemd unit
(`ProtectSystem=strict`, no capabilities, write access to `/var/lib/r2r`
only). If something else is already listening on port 8787 — for example a
previous-generation relay — the installer stops it and prints what it was, but
does not touch its data.

### 2.2 Requirements and ports

Keep it to a table plus two sentences. Requirements: any x86-64 Linux server
(the binary is fully static — no glibc version to match), root access, and two
open inbound ports. A small, cheap VPS is plenty; the relay is a single ~24 MB
binary with an embedded SQLite database.

| Port | Protocol | Who needs to reach it |
|---|---|---|
| 8787 | `ws://` + HTTP | other relays, and clients on trusted networks |
| 8788 | `wss://` (TLS) | remote clients connecting directly |

Both must be open inbound. Nothing else is required — no nginx, no reverse
proxy, no database server.

Add an info callout: a **domain name is optional**. Relays authenticate each
other with ed25519 signatures, not certificates, so a bare IP with the
self-signed certificate is a fully functioning node. A domain plus a real
certificate is only needed if browsers will connect *directly* to this relay
(see §2.6).

### 2.3 Check that it works

Three commands, each with a line saying what good output looks like:

```sh
systemctl status r2r-relay
curl -s http://127.0.0.1:8787/status.json
r2r-probe --url ws://127.0.0.1:8787 ping
```

And discovery — within a minute or two the node finds the others via gossip:

```sh
curl -s http://127.0.0.1:8787/peers.json | grep -c '"verified": true'
```

Mention that the relay also serves a human-readable status page at
`http://YOUR.SERVER.IP:8787/` — active nodes, uptime, payloads held, frames
relayed — so the operator can point a browser at their own node.

### 2.4 Your invite codes

Registration on a relay is closed by default and works by invite code. On
first start the relay mints **five genesis codes** into
`/var/lib/r2r/genesis-invites.txt` (mode 0600, deliberately never written to
the log). Each code is a single-use UUID; claiming one registers an identity
and mints exactly three new codes for that person to pass on, so the network
grows person-to-person.

```sh
sudo cat /var/lib/r2r/genesis-invites.txt
r2r-relay --mint-invites 10        # mint more at any time
```

Callout: a burned code is stored forever as a UUID and a timestamp — **no name,
no email, no phone number, nothing to identify the person who used it**. An
operator who wants a fully open relay can set `--open-registration` (or the
equivalent in `/etc/r2r/relay.env`); identities are still recorded and
newcomers still receive three codes, so clients behave identically either way.

### 2.5 Administering your relay

Two subsections, and this framing sentence first: day-to-day administration
happens **from your own wallet, not over SSH** — the server-side CLI exists for
setup and for operators who prefer the shell.

**a) From your wallet — the owner panel.** There is no admin key or password.
The wallet already proves an ed25519 identity on every connection, so the relay
simply keeps a list of identities allowed to administer it. Once, on the
server:

```sh
sudo r2r-relay --owner-add YOUR-64-CHARACTER-FINGERPRINT
sudo r2r-relay --list-owners
sudo r2r-relay --owner-remove YOUR-64-CHARACTER-FINGERPRINT   # revoke
```

The fingerprint is shown in the wallet — it is the same identity the operator
already messages with. From the next connection the owner panel appears
automatically in the wallet, and from it the operator can **list accounts**
(usage, quota, pending messages, online state), **change any account's storage
allowance**, and **mint invite codes from their phone** instead of reading a
file over SSH. Emphasise the design point in a callout: *there is no shared
secret at all — nothing to paste, nothing to leak, and revoking access is one
command.*

**b) From the shell.** These are safe to run while the relay is live (the
database is in WAL mode; no restart needed):

```sh
r2r-relay --set-quota FINGERPRINT 250    # give this user 250 MB
r2r-relay --list-quotas                  # every individual allowance
r2r-relay --clear-quota FINGERPRINT     # back to the relay default
r2r-relay --mint-invites 10
```

Every identity gets 1 MB by default; the allowance covers messages, voice/video
recordings and encrypted history together. Going over it refuses *new*
payloads — nothing already stored is ever deleted by a quota change, so
lowering one is safe.

**c) Settings reference.** A table of `/etc/r2r/relay.env` variables
(`r2r-relay --help` prints the full list; every flag has an `R2R_*`
environment equivalent):

| Variable | Meaning |
|---|---|
| `R2R_ADVERTISE` | `host:port` other relays dial. **Without it, nobody can route to you.** |
| `DEFAULT_QUOTA_MB` | Storage each identity gets (default 1). |
| `QUEUE_TTL_DAYS` / `BLOB_TTL_DAYS` | Retention; the longer of the two wins (default 7 days). |
| `TURN_URL` / `TURN_USER` / `TURN_PASS` | Needed for calls to connect through strict NATs. |
| `R2R_ASSETS_DIR` | Publish a directory at `/assets/` — turns the relay into a verified download mirror. |

### 2.6 TLS certificates

Three facts, in this order, because operators consistently get this wrong:

1. **The self-signed certificate from the installer is genuinely enough for
   the relay network.** Relays never check each other's certificate chains —
   they authenticate with an ed25519 signature pinned per address, which binds
   the *node* rather than a hostname and is stronger than a certificate for
   that job.
2. **A browser-trusted certificate is needed for exactly one thing**: a
   browser connecting straight to this relay. If users arrive through
   `r2r.homes`, this relay does not need one. If wanted, point a DNS name at
   the node and run (port 80 must be reachable):

   ```sh
   ./setup-tls.sh relay1.example.org
   ```

   Renewal never restarts the relay — the hook sends `SIGHUP`, the certificate
   is re-read in place, and no client connection or peer link drops.
3. **The private key is unreadable to your login shell on purpose**
   (`/etc/r2r/tls/key.pem` is `0640 root:r2r`). Warning callout: the fix is
   *not* to copy the key somewhere more permissive — start the relay through
   systemd, or point `--cert`/`--key` at a throwaway pair for hand-run tests.

### 2.7 Calls: STUN and TURN

Explain in two short paragraphs (this is the setting operators skip and then
wonder why calls fail):

Calls are peer-to-peer — audio and video flow directly between the two
clients, end-to-end encrypted, and **never through a relay**. STUN and TURN
only help the two ends find each other. STUN is free and usually enough; TURN
is the fallback for symmetric NATs (common on mobile carriers and corporate
networks), where the encrypted media must bounce off a server. **Without a
TURN server, calls work in testing and fail for a real share of users on
mobile data.**

```sh
sudo apt install coturn
# then set TURN_URL and TURN_SECRET_FILE in /etc/r2r/relay.env
```

The relay mints a fresh, expiring credential per client (HMAC of an expiry
timestamp) rather than a fixed password, so a leaked credential is worthless
within minutes. Honest caveat, in a callout: TURN carries the media, so
whoever runs it can see both endpoints' IPs and the call's timing and size —
never its contents.

### 2.8 Upgrading from the previous relay

For operators running the old PHP/Python/Node/binary relay. The installer
already stops whatever holds port 8787 without touching its data, and old
environment settings (`PORT`, `DATA_DIR`, `DEFAULT_QUOTA_MB`,
`QUEUE_TTL_DAYS`, `BLOB_TTL_DAYS`, TURN settings) are honoured, so a
carried-over unit keeps working. To identify and remove the old install:

```sh
curl -sSLO https://r2r.homes/assets/find-old-relay.sh && chmod +x find-old-relay.sh
./find-old-relay.sh                 # report only, changes nothing
./find-old-relay.sh --purge --yes   # archives the old data to /var/backups/r2r first
```

### 2.9 Removing your relay

Show it plainly — being easy to leave is part of being trustworthy:

```sh
sudo systemctl disable --now r2r-relay
sudo rm /etc/systemd/system/r2r-relay.service /usr/local/bin/r2r-relay
sudo rm -rf /var/lib/r2r /etc/r2r    # deletes stored messages and the node identity
```

Warning callout: `/var/lib/r2r/node.key` is the relay's permanent identity.
Delete it and a reinstalled node returns as a stranger every peer must re-pin.

### 2.10 How the network works — no centre, no directory

This section carries the philosophy and deserves a diagram (see §3). Cover, in
plain prose:

- **Every node is the same.** One binary, one systemd unit, two ports,
  everywhere. No master server, no coordinator. `r2r.homes` is a web portal
  and one seed among several — the network does not depend on it.
- **The network finds itself.** A new relay starts from a handful of bootstrap
  addresses compiled into the binary, fetches `peers.json`, then swaps peer
  lists with random connected relays every minute. Dead peers are pruned;
  the verified list is republished at `/peers.json` on every node, so any
  relay can bootstrap any other.
- **Relays are dead drops.** A message arrives as ciphertext produced by the
  sender's device; the relay files it under the recipient's fingerprint, holds
  it at most seven days, and hands it over only to someone who
  cryptographically proves they hold the matching key. Nothing on the relay
  can decrypt anything.
- **Relays authenticate each other with keys, not certificates or names** —
  each node's ed25519 key is pinned on first contact, and gossip can introduce
  new relays but can never overwrite an established pin. Impersonating a
  known relay fails.
- **Messages can cross relays.** An address is a fingerprint, optionally
  qualified with a home relay (`fingerprint@host:port`). There is
  deliberately **no global directory of who lives where** — home relays are
  recorded only where the person registered, never gossiped.
- **Multi-hop privacy.** A sender can seal a message in onion layers across a
  chain of relays; each hop learns only the previous hop and the next one —
  not the sender, not the recipient, not how many hops remain — so no single
  relay knows both ends of a conversation.
- **Calls never touch relays.** Relays only pass the initial call setup;
  the audio/video itself flows directly between the two devices.

### 2.11 What a relay knows — and what it can never know

Present as two honest lists side by side. This exact honesty is the brand;
resist any urge to keep only the flattering half.

**No relay — and no one at all — ever collects:**

- **phone numbers, email addresses, names, or any personal detail.** There is
  no sign-up form anywhere in the network. An identity is an encryption
  keypair generated on your own device; your "address" is its fingerprint, a
  string of hex. Joining burns an anonymous invite code — a UUID and a
  timestamp is all that is ever stored about it.
- **message contents.** Payloads arrive already encrypted by the sender's
  device; nothing in the relay can decrypt them, and calls flow directly
  between devices.
- **IP addresses, in any durable form.** Never written to the database, never
  written to the log, never retained after a socket closes. Connections
  appear in logs as a random id discarded on disconnect. (On `r2r.homes`
  even the web server's access log is off.)
- **who talks to whom, when onion routing is used** — an intermediate hop sees
  only its neighbours in the chain.

**What a relay does hold — say it plainly:**

- the recipient fingerprint of each stored payload (a dead drop must be filed
  under something), held at most seven days and then securely erased;
- coarse liveness — a last-seen time rounded down to the hour, used only to
  expire dormant entries;
- the public addresses of other relays, which are public infrastructure by
  design;
- and, out of scope for any relay: an observer watching the wire itself can
  see message sizes and timing. Encryption hides content, not the fact that
  traffic exists.

### 2.12 FAQ

Short answers, accordion layout is fine:

- **Do I need a domain name?** No — only if browsers will connect directly to
  your relay (§2.6).
- **Can I read the messages my relay stores?** No. They arrive encrypted by
  the sender's device and only the recipient's key can open them. The relay
  is a locked mailbox it has no key to.
- **What am I storing, legally speaking?** Opaque ciphertext filed under
  pseudonymous fingerprints, auto-deleted within seven days, with no IPs and
  no personal data on disk. (State facts only — do not phrase as legal advice.)
- **How big a server do I need?** Small. One static binary, an embedded
  database, modest RAM. The cheapest VPS tier is fine.
- **How do people join through my relay?** Hand them an invite code; each
  person who joins gets three more. Or run `--open-registration`.
- **Does it need to stay online?** Ideally yes — it's other people's mailbox.
  If it goes down, mail addressed to identities homed on it waits elsewhere
  or fails to route; peers re-link automatically when it returns.
- **Can I build it from source instead?** Yes — the repository README covers
  it (C++20, CMake, one `smoke-test.sh` to verify). The download above is the
  same code, prebuilt and checksummed.

---

## 3. Design and interaction requirements

- **Copy buttons on every code block.** The hero one-liner is the page's whole
  point; it must copy correctly in one click, including line continuations.
- **Placeholder highlighting.** `YOUR.SERVER.IP`, `FINGERPRINT`,
  `relay1.example.org` render as visually distinct tokens. If you add an
  interactive touch, the best one is a small input above the hero block that
  substitutes the visitor's IP into the command before they copy it — nothing
  is sent anywhere; note that.
- **Callout styles.** Three levels used above: info (grey), important (accent),
  warning (red/amber — reserved for: unreplaced advertise address, copying the
  TLS key, deleting `node.key`, missing TURN).
- **One diagram** in §2.10: a ring/mesh of identical relay nodes, encrypted
  payloads hopping between them, devices at the edge, and a crossed-out
  "central server" to make the absence explicit. Keep it monochrome + one
  accent, matching the portal.
- **Tables** for ports and env settings only; everything else is prose.
- **Mobile:** code blocks scroll horizontally inside their own container;
  the page never scrolls sideways. The TOC collapses.
- **Anchors** on every `<h2>` so operators can link each other straight to
  "TURN" or "TLS".
- **Dark and light** both supported, matching the portal.

## 4. Tone and accuracy rules

- Voice: calm, technical, first-principles. The existing docs say things like
  *"that is working as intended, not a fault"* — keep that register.
- **Never oversell privacy.** Every claim in §2.11 is engineering fact; do not
  add superlatives, do not drop the "what a relay does hold" half. Honesty
  about limits is deliberately part of the design and the pitch.
- No dark patterns, no newsletter capture, no analytics on this page — a page
  about not collecting data must not collect data. Static assets only, no
  third-party fonts or scripts.
- Commands are sacred: copy them from this brief character-for-character.

## 5. Source material

- `README.md` in the relay repository — full technical reference.
- `docs/install-a-relay.md` — the operator instructions this page presents.
- `docs/client-app-brief.md` — owner-panel behaviour and wallet frames.
- `web/index.html` — the portal whose look and voice this page must match.
- Live checksums and downloads: `https://r2r.homes/assets/`.
