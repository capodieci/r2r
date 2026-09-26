# Replacing the five v1 relays (state on 2026-09-24)

The previous network's seed list (still baked into the August builds in
`build-portable/` and `build-headless/`) names five DigitalOcean hosts besides
r2r.homes. All five still answer on port 8787 with the **old** relay (a JSON
`{"error":"not_found"}` for `/`, `/status.json` and `/health`; the new relay
answers `/health`), none has the `wss://` port 8788 open, and all have SSH open:

| Host | Old relay on 8787 | SSH | Notes |
|---|---|---|---|
| 143.110.227.46 | yes | open | `wiki`; runs the compiled binary as `/root/r2r` under its own unit, which respawned it after the first install attempt on 2026-09-24 |
| 164.90.207.73 | yes | open | |
| 164.92.156.207 | yes | open | |
| 165.22.204.117 | yes | open | |
| 165.232.132.110 | yes | open | JSON has a space after the colon: the Python variant |

They are also what causes the occasional `rejecting relay handshake` line in
r2r.homes' journal: the old relays dial the seed with a handshake the new
relay does not accept.

There is no SSH key on r2r.homes for these hosts, so the replacement is run
from a machine that has one, host by host. Each host takes two or three
minutes. Steps, per host (see the chat transcript of 2026-09-24 for the
annotated version):

```sh
ssh root@HOST
apt-get install -y curl unzip python3          # usually already there
curl -sSLO https://r2r.homes/assets/find-old-relay.sh && chmod +x find-old-relay.sh
./find-old-relay.sh                             # report only
./find-old-relay.sh --purge --yes --no-archive  # stop + remove the old relay and its data
curl -sSLO https://r2r.homes/assets/r2r-relay-$(uname -m)
curl -sSLO https://r2r.homes/assets/install.sh
curl -sSLO https://r2r.homes/assets/setup-tls.sh
curl -sSLO https://r2r.homes/assets/r2r-relay.service
chmod +x r2r-relay-* install.sh setup-tls.sh
./install.sh THIS.HOSTS.IP:8787                 # the IP you just logged in to
ufw status | grep -q "Status: active" && ufw allow 8787/tcp && ufw allow 8788/tcp
curl -s http://127.0.0.1:8787/health; echo      # {"ok":true,...}
cat /var/lib/r2r/genesis-invites.txt            # five invite codes for this relay
```

Then, from anywhere, `https://r2r.homes/status` should show one more active
peer within a minute or two, and `https://r2r.homes/homes` lists the relay.

Two things learned on the first host (2026-09-24): the binaries are fully
static since 22:30 UTC that day, so the `GLIBC_2.38 not found` failure of the
earlier download is gone (these hosts run Ubuntu 22.04, glibc 2.35); and the
old relay on `wiki` is supervised by a unit with its own name, so the old
`find-old-relay.sh` reported "nothing to remove" and the relay respawned after
`install.sh` stopped it. The finder now inspects the process on port 8787 and
its unit; always run it before `install.sh`, and check `/health` afterwards.

## After they are back

All five were replaced on 2026-09-25 and verified from r2r.homes the same
day: every one answers `/health`, serves the doorway, mirrors the downloads,
and is a verified peer of the other five. Step 1 below was done then; the
binaries published since carry all six addresses.

1. Add the five addresses to `kSeedPeers` in `src/config.cpp` and to `SEEDS`
   in `scripts/deploy-seeds.sh`, rebuild, republish `/assets/r2r-relay`, so a
   fresh install can bootstrap even when r2r.homes is down. (Done 2026-09-25.)
2. Each host prints five genesis invite codes into
   `/var/lib/r2r/genesis-invites.txt`; `--owner-add <fingerprint>` makes your
   wallet the owner of each relay.
3. Drop the old hosts' DNS names, if any pointed at them, or point them at the
   new relays and run `setup-tls.sh` there for `wss://`.

Old-relay removal details: `docs/remove-old-relay.md`
(`https://r2r.homes/assets/remove-old-relay.md`).
