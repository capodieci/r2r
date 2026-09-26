# Installing an R2R relay

Four commands on a fresh server. The binary carries SQLite, OpenSSL and its C++
runtime inside it and is fully static, so there is nothing to install first and
no minimum distribution version. It runs on any Linux on **x86-64** or
**ARM64** (a Raspberry Pi 4 or 5, an Apple-silicon VM, an Ampere or Graviton
server), and there are builds for 32-bit ARM (`armv7l`) and RISC-V too.

## The install

Log in to the server that will run the relay (SSH, as root or any user with
`sudo`) and run this there, not on your own computer. Replace the address with
**that server's own public IP** (`curl -4 ifconfig.me` prints it); it is what
other relays will dial.

```sh
curl -sSLO https://r2r.homes/assets/r2r-relay-$(uname -m)
curl -sSLO https://r2r.homes/assets/install.sh
curl -sSLO https://r2r.homes/assets/setup-tls.sh
curl -sSLO https://r2r.homes/assets/r2r-relay.service

chmod +x r2r-relay-* install.sh setup-tls.sh
sudo ./install.sh 203.0.113.10:8787       # <- this node's public IP
```

`$(uname -m)` picks the file for this machine: `r2r-relay-x86_64`,
`r2r-relay-aarch64`, `r2r-relay-armv7l` or `r2r-relay-riscv64`. (The plain
`r2r-relay` in older instructions is the x86-64 file under its old name and
still works.) `install.sh` checks that whatever binary it finds is built for
the machine it is running on, and if none is, downloads the right one and
verifies it against the SHA-256 the origin publishes — so the first line is
optional.

Verify the download first if you like — `https://r2r.homes/assets/` lists the
SHA-256 of every file:

```sh
curl -s https://r2r.homes/assets/ | grep -A2 "\"r2r-relay-$(uname -m)\""
sha256sum r2r-relay-*
```

That is the whole install. It creates the `r2r` service user, puts the binary in
`/usr/local/bin`, makes `/etc/r2r` and `/var/lib/r2r`, issues a self-signed
certificate, and enables the systemd unit.

If something else already listens on port 8787, `install.sh` stops it and prints
what it was, but does not touch its data.

The new relay finds the network by itself: `r2r.homes` is compiled in as the
seed. To bootstrap from other relays as well, add them to `/etc/r2r/relay.env`
as `R2R_SEEDS=host:port,host:port`.

## Checking it

```sh
systemctl status r2r-relay
curl -s http://127.0.0.1:8787/status.json
r2r-probe --url ws://127.0.0.1:8787 ping
```

Within a minute or two the node should find the others (the seed, and every
relay the seed knows):

```sh
curl -s http://127.0.0.1:8787/peers.json | grep -c '"verified": true'
```

The first-run invite codes are in `/var/lib/r2r/genesis-invites.txt` (mode
0600). They are deliberately not written to the log. Each works once; mint more
with `r2r-relay --mint-invites 10`. People who join get three codes of their
own, which unlock once they have received a few messages and chatted with
whoever invited them.

**This is also how you get in when nobody can invite you.** Claim one of the
five codes in your own wallet (Use an invite code), hand the other four to
friends, and mint more whenever you like. From then on you are the person
people ask for an invite, and each person you bring in gets three codes to
pass on.

## Certificates

`install.sh` issues a self-signed certificate, and that is genuinely enough for
the relay network. Relays do not check each other's certificate chain — they
authenticate with the ed25519 signature in `hello`, pinned per address in
`peers.json`, which binds the *node* rather than a hostname and is stronger than
a certificate for that job.

A browser-trusted certificate is needed for exactly one thing: a **browser
connecting straight to this relay**. Browsers refuse self-signed certificates
and refuse `ws://` from an `https://` page. If your users arrive through
`r2r.homes` instead, you do not need one.

If you do want one, point a DNS name at the node and:

```sh
./setup-tls.sh relay1.example.org
```

That obtains a Let's Encrypt certificate (port 80 must be reachable), installs
it, and adds a renewal hook. **Renewal does not restart the relay** — the hook
sends `SIGHUP`, which re-reads the certificate in place, so no client connection
or peer link is dropped. You can trigger it by hand at any time:

```sh
sudo systemctl kill -s HUP r2r-relay
```

### Why you cannot read the key yourself

`/etc/r2r/tls/key.pem` is `0640 root:r2r` and the unit sets `Group=r2r`, so only
the relay can read it. A login shell in a different group cannot — that is
intended, not a fault. If you start the relay by hand from such a shell it will
say so plainly and run `ws://`-only. Start it through systemd, or for a hand-run
test pass `--cert`/`--key` pointing at a throwaway pair of your own. Do not copy
the production key somewhere more readable.

## Settings

`/etc/r2r/relay.env` is read by the unit (`r2r-relay --help` lists every flag):

| Variable | Meaning |
|---|---|
| `R2R_ADVERTISE` | `host:port` other relays dial. Without it, nobody can route to you. |
| `R2R_SEEDS` | Extra relays to bootstrap from, `host:port,host:port`. |
| `DEFAULT_QUOTA_MB` | Storage each identity gets (default 1). |
| `QUEUE_TTL_DAYS` / `BLOB_TTL_DAYS` | Retention. The longer of the two wins. |
| `TURN_URL` / `TURN_USER` / `TURN_PASS` | Needed for calls to connect through strict NATs. |
| `R2R_ASSETS_DIR` | Publish a directory at `/assets/`. |

Give an individual user more room without restarting anything:

```sh
r2r-relay --set-quota <fingerprint> 250
r2r-relay --list-quotas
```

## Managing the relay from your wallet

Do this once and you never need to log into the server to manage storage again:

```sh
sudo r2r-relay --owner-add R2R_YOUR_ADDRESS      # the address in the wallet's Settings
sudo r2r-relay --list-owners
```

The address is in the wallet's Settings; it is the same identity you already
use (a 64-character fingerprint is accepted as well). The owner panel then
appears automatically the next time you connect, and from it you can list
accounts, change anyone's storage allowance, and mint invite codes.

There is **no admin key** and no shared secret at all. Your wallet already
proves its ed25519 identity on every connection, so the relay just checks
whether that identity is on its owners list. Nothing to copy, nothing to leak,
and revoking access is `--owner-remove`.

## Calls: STUN and TURN

Calls are peer-to-peer — audio and video go straight between the two clients and
never through a relay. STUN and TURN only help the two ends *find* each other:

- **STUN** tells each client what its public address looks like from outside, so
  the two can try to connect directly. Free, and enough most of the time.
- **TURN** is the fallback for when they cannot. Behind a symmetric NAT — common
  on mobile carriers and corporate networks — there is no direct path, and the
  media has to bounce off a server. That is TURN.

Without TURN, calls work in testing and fail for a real share of users on mobile
data, with no obvious reason why. With it, they connect.

```sh
sudo apt install coturn
sudo r2r-relay ... # set TURN_URL and TURN_SECRET_FILE in /etc/r2r/relay.env
```

Point `TURN_URL` at your coturn and give the relay the same
`static-auth-secret`. The relay then mints a **fresh, expiring credential** for
each client rather than handing out a fixed password: the username is its own
expiry timestamp and the password is an HMAC of it, so a leaked credential is
worthless within minutes and the secret never leaves the server.

Be aware of what TURN sees: it carries the media, so it learns both endpoints'
IP addresses and the size and timing of the call. It cannot decrypt anything —
WebRTC media is encrypted end to end — but "who called whom, for how long" is
visible to whoever runs it. Only calls that cannot connect directly use it.

## Ports

| Port | Purpose | Who needs to reach it |
|---|---|---|
| 8787 | `ws://` + HTTP | other relays, and local clients |
| 8788 | `wss://` | remote clients connecting directly |

Both must be open inbound. Nothing else is required — no nginx, no database
server, no reverse proxy. Only `r2r.homes` runs those, because it also serves
the web portal.

## Removing it

```sh
sudo systemctl disable --now r2r-relay
sudo rm /etc/systemd/system/r2r-relay.service /usr/local/bin/r2r-relay
sudo rm -rf /var/lib/r2r /etc/r2r        # deletes stored messages and the node identity
```

`/var/lib/r2r/node.key` is the relay's permanent identity. Delete it and the
node comes back as a stranger that every peer has to re-pin.
