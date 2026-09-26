#!/usr/bin/env bash
# Installs a built relay as a system service.
#
#   sudo ./scripts/install.sh [advertise-address]
#
# Creates the r2r service user, installs the binaries, lays out /etc/r2r and
# /var/lib/r2r, and enables the systemd unit. Uses a binary from ./build or
# from next to this script when one matches this machine's architecture, and
# otherwise downloads and verifies the published r2r-relay-<uname -m>.
set -euo pipefail

ADVERTISE="${1:-}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$(cd "$HERE/.." && pwd)"
BUILD="${BUILD:-${SRC}/build}"

# Works either from a git checkout (binary in ./build, unit in ./systemd) or
# from a flat directory of downloaded files sitting next to this script, which
# is what installing on a fresh node looks like.
UNIT="${SRC}/systemd/r2r-relay.service"
[ -f "$UNIT" ] || UNIT="${HERE}/r2r-relay.service"
CERT_SCRIPT="${SRC}/scripts/setup-tls.sh"
[ -f "$CERT_SCRIPT" ] || CERT_SCRIPT="${HERE}/setup-tls.sh"

[ "$(id -u)" -eq 0 ] || { echo "run this with sudo" >&2; exit 1; }

# Where the doorway bundle and downloads come from; also where a missing
# binary is fetched from (below).
BUNDLE_URL="${R2R_DOORWAY_BUNDLE_URL:-https://r2r.homes/assets/r2r-doorway-bundle.zip}"
ORIGIN="${R2R_MIRROR_URL:-${BUNDLE_URL%/assets/*}}"

# ---------------------------------------------------------------------------
# Picking the binary for this machine
#
# Binaries are published per architecture as r2r-relay-<uname -m>: x86_64,
# aarch64, armv7l, riscv64 (plain "r2r-relay" is the x86_64 one, kept under
# that name for the four-line install everyone already has). All are static,
# so the only thing that can go wrong is the architecture, and "Exec format
# error" from systemd is a poor way to find that out. So the ELF header of
# whatever binary is found is checked against this machine, and when nothing
# usable is at hand the right file is downloaded and verified against the
# SHA-256 that ORIGIN publishes.
#
#   R2R_NO_DOWNLOAD=1   never fetch; fail if no matching binary is present
# ---------------------------------------------------------------------------
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64|amd64)   ARCH=x86_64 ;;
    aarch64|arm64)  ARCH=aarch64 ;;
    armv7l|armv8l)  ARCH=armv7l ;;
    riscv64)        ARCH=riscv64 ;;
    *) echo "no relay binary is published for '$ARCH'; build from source (README: Building)" >&2; exit 1 ;;
esac

elf_arch() { # prints the architecture an ELF file was built for, or "unknown"
    case "$(od -An -tx1 -j18 -N2 "$1" 2>/dev/null | tr -d ' \n')" in
        3e00) echo x86_64 ;;
        b700) echo aarch64 ;;
        2800) echo armv7l ;;
        f300) echo riscv64 ;;
        *)    echo unknown ;;
    esac
}

published_sha256() { # published_sha256 <name>: the digest ORIGIN lists for it, or ""
    curl -fsSL --max-time 30 -H 'Accept: application/json' "${ORIGIN}/assets/" 2>/dev/null \
        | tr -d ' \n\r\t' \
        | grep -oE "\{[^{}]*\"name\":\"$1\"[^{}]*\}" \
        | grep -oE '"sha256":"[0-9a-f]{64}"' | head -1 | cut -d'"' -f4
}

fetch_binary() { # fetch_binary <name> <destination>
    local want got
    command -v curl >/dev/null 2>&1 || { echo "curl is needed to download $1" >&2; return 1; }
    want="$(published_sha256 "$1")"
    [ -n "$want" ] || { echo "${ORIGIN}/assets/ does not list $1" >&2; return 1; }
    echo "downloading ${ORIGIN}/assets/$1"
    curl -fsSL --max-time 600 -o "$2.part" "${ORIGIN}/assets/$1" || { rm -f "$2.part"; return 1; }
    got="$(sha256sum "$2.part" | cut -d' ' -f1)"
    if [ "$got" != "$want" ]; then
        echo "  $1: SHA-256 mismatch (got $got, origin says $want); not using it" >&2
        rm -f "$2.part"; return 1
    fi
    chmod 0755 "$2.part" && mv "$2.part" "$2"
    echo "  verified $1 (sha256 $want)"
}

# Beyond the architecture, the binary has to actually start here: an older
# download was linked against a newer glibc than some hosts have, which the
# ELF header cannot show and systemd only reports after the install. Running
# --version settles it in a few milliseconds.
runs_here() { # runs_here <binary>: prints the reason it does not, if it does not
    local out
    chmod +x "$1" 2>/dev/null || true
    if out="$(timeout 20 "$1" --version 2>&1)"; then return 0; fi
    local rc=$?
    out="$(printf '%s' "$out" | grep -v '^$' | tail -1 | cut -c1-200)"
    printf '%s' "${out:-exit status $rc (no error text)}"
    return 1
}

RELAY_BIN=""; PROBE_BIN=""
for cand in "$BUILD/r2r-relay" "$HERE/r2r-relay-$ARCH" "$HERE/r2r-relay"; do
    [ -f "$cand" ] || continue
    have="$(elf_arch "$cand")"
    if [ "$have" != "$ARCH" ]; then
        echo "$cand is built for $have; this machine is $ARCH -- skipping it"
        continue
    fi
    if why="$(runs_here "$cand")"; then
        RELAY_BIN="$cand"; break
    fi
    echo "$cand does not run on this machine -- skipping it"
    echo "  ${why:-no error text}"
done
if [ -z "$RELAY_BIN" ]; then
    if [ "${R2R_NO_DOWNLOAD:-0}" = "1" ]; then
        echo "no r2r-relay binary for $ARCH here (R2R_NO_DOWNLOAD=1, so not fetching one)" >&2; exit 1
    fi
    DL="$HERE"; [ -w "$DL" ] || DL="$(mktemp -d)"
    fetch_binary "r2r-relay-$ARCH" "$DL/r2r-relay-$ARCH" \
        || { echo "could not obtain a relay binary for $ARCH; put r2r-relay-$ARCH next to this script" >&2; exit 1; }
    if why="$(runs_here "$DL/r2r-relay-$ARCH")"; then :; else
        echo "the downloaded r2r-relay-$ARCH does not run on this machine either:" >&2
        echo "  ${why:-no error text}" >&2
        exit 1
    fi
    RELAY_BIN="$DL/r2r-relay-$ARCH"
    fetch_binary "r2r-probe-$ARCH" "$DL/r2r-probe-$ARCH" || true
fi
chmod +x "$RELAY_BIN" 2>/dev/null || true
if [ -z "$PROBE_BIN" ]; then
    for cand in "$(dirname "$RELAY_BIN")/r2r-probe-$ARCH" "$(dirname "$RELAY_BIN")/r2r-probe" \
                "$BUILD/r2r-probe" "$HERE/r2r-probe-$ARCH" "$HERE/r2r-probe"; do
        [ -f "$cand" ] && [ "$(elf_arch "$cand")" = "$ARCH" ] && { PROBE_BIN="$cand"; break; }
    done
fi
echo "installing $RELAY_BIN ($ARCH)"

# ---------------------------------------------------------------------------
# Freeing the relay ports
#
# Deliberately scoped by PORT, not by process name. A deploy script that runs
# `pkill node` (or python, or php) on a shared host kills whatever else that
# host happens to run -- and these seed nodes are not dedicated. Whatever is
# holding 8787 gets stopped no matter what language it was written in; nothing
# else is touched. The command line of every process signalled is printed, so
# the deploy log shows exactly what was replaced.
#
# Set R2R_SKIP_PORT_CLEANUP=1 to disable.
# ---------------------------------------------------------------------------
listeners_on() { # prints the PIDs listening on TCP port $1
    { ss -lntpH "sport = :$1" 2>/dev/null || true; } \
        | grep -oE 'pid=[0-9]+' | cut -d= -f2 | sort -u
    # Fallback for hosts whose ss lacks process lookup.
    if command -v lsof >/dev/null 2>&1; then
        lsof -ti "TCP:$1" -sTCP:LISTEN 2>/dev/null || true
    fi
}

free_port() {
    local port="$1" pid cmd exe leftover
    [ "${R2R_SKIP_PORT_CLEANUP:-0}" = "1" ] && return 0

    for pid in $(listeners_on "$port" | sort -u); do
        [ -z "$pid" ] && continue
        # Never signal init, this script, or the SSH session running the deploy.
        if [ "$pid" -eq 1 ] 2>/dev/null; then
            echo "  refusing to signal PID 1" >&2
            continue
        fi
        [ "$pid" = "$$" ] && continue
        exe="$(basename "$(readlink -f "/proc/$pid/exe" 2>/dev/null || echo unknown)")"
        case "$exe" in
            sshd|systemd|init)
                echo "  refusing to kill ${exe} (PID ${pid}) -- free port ${port} by hand" >&2
                continue
                ;;
        esac
        cmd="$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)"
        echo "  port ${port} held by PID ${pid} (${exe}): ${cmd:-unknown}"
        # A process systemd started comes straight back after a signal, so its
        # unit is stopped instead. It stays enabled: removing the old relay is
        # find-old-relay.sh's job, and this script deletes nothing.
        unit="$(sed -n 's|.*/\([^/]*\.service\)$|\1|p' "/proc/$pid/cgroup" 2>/dev/null | head -1)"
        if [ -n "$unit" ] && [ "$unit" != "r2r-relay.service" ]; then
            echo "  started by systemd unit ${unit}; stopping the unit (find-old-relay.sh --purge removes it)"
            systemctl stop "$unit" 2>/dev/null || true
            continue
        fi
        kill -TERM "$pid" 2>/dev/null || true
    done

    # Give anything signalled a moment to close its listeners cleanly.
    for _ in $(seq 1 20); do
        leftover="$(listeners_on "$port" | sort -u | tr -d '[:space:]')"
        [ -z "$leftover" ] && return 0
        sleep 0.5
    done

    for pid in $(listeners_on "$port" | sort -u); do
        [ -z "$pid" ] && continue
        [ "$pid" -eq 1 ] 2>/dev/null && continue
        echo "  PID ${pid} ignored SIGTERM; sending SIGKILL"
        kill -KILL "$pid" 2>/dev/null || true
    done
    sleep 1
}

# A running instance of our own service is stopped properly first: it
# checkpoints SQLite and rewrites peers.json on the way out, which a signal to
# a bare PID would skip.
if systemctl is-active --quiet r2r-relay 2>/dev/null; then
    echo "stopping the running r2r-relay service"
    systemctl stop r2r-relay || true
fi

echo "freeing relay ports"
free_port 8787
free_port 8788

if ! getent group r2r >/dev/null; then
    groupadd --system r2r
    echo "created group r2r"
fi
if ! getent passwd r2r >/dev/null; then
    useradd --system --gid r2r --home-dir /var/lib/r2r \
            --shell /usr/sbin/nologin --comment "R2R relay" r2r
    echo "created user r2r"
fi

install -m 0755 "$RELAY_BIN" /usr/local/bin/r2r-relay
if [ -n "$PROBE_BIN" ]; then
    install -m 0755 "$PROBE_BIN" /usr/local/bin/r2r-probe
    echo "installed r2r-relay and r2r-probe into /usr/local/bin"
else
    echo "installed r2r-relay into /usr/local/bin (no r2r-probe found; optional)"
fi

install -d -m 0755 -o root -g root /etc/r2r
install -d -m 0750 -o root -g r2r  /etc/r2r/tls
install -d -m 0700 -o r2r  -g r2r  /var/lib/r2r
install -d -m 0755 /usr/local/share/doc/r2r-relay
install -m 0644 "${SRC}/README.md" /usr/local/share/doc/r2r-relay/README.md 2>/dev/null || true

# ---------------------------------------------------------------------------
# Doorway bundle -- the web site the relay serves from /var/lib/r2r/doorway.
#
# The binary re-verifies the bundle against its manifest at startup and falls
# back to the built-in status page when it is absent or damaged, so a failed
# fetch here degrades the install, never breaks it.
#
#   R2R_DOORWAY_BUNDLE=path/to.zip     use a local zip instead of fetching
#   R2R_DOORWAY_BUNDLE_URL=https://…   fetch from a different location
#   R2R_SKIP_DOORWAY=1                 do not install a doorway at all
# ---------------------------------------------------------------------------
DOORWAY_DIR=/var/lib/r2r/doorway
BUNDLE_LOCAL="${R2R_DOORWAY_BUNDLE:-}"
TRANSLATIONS="${SRC}/docs/translations.zip"

install_doorway() {
    local tmp zip root
    tmp="$(mktemp -d)"
    zip="$tmp/bundle.zip"
    if [ -n "$BUNDLE_LOCAL" ] && [ -f "$BUNDLE_LOCAL" ]; then
        cp "$BUNDLE_LOCAL" "$zip"
        echo "using local doorway bundle ${BUNDLE_LOCAL}"
    elif command -v curl >/dev/null 2>&1 && curl -fsSL --max-time 60 -o "$zip" "$BUNDLE_URL"; then
        echo "fetched doorway bundle from ${BUNDLE_URL}"
    else
        echo "no doorway bundle available (set R2R_DOORWAY_BUNDLE=… for a local zip);"
        echo "the relay serves its built-in status page until one is installed"
        rm -rf "$tmp"; return 0
    fi
    if ! command -v unzip >/dev/null 2>&1; then
        echo "unzip is not installed; skipping the doorway"
        rm -rf "$tmp"; return 0
    fi
    unzip -oq "$zip" -d "$tmp/x"
    root="$(dirname "$(find "$tmp/x" -maxdepth 2 -name manifest.json | head -1)")"
    if [ -z "$root" ] || [ ! -f "$root/manifest.json" ]; then
        echo "bundle has no manifest.json; not installing it"
        rm -rf "$tmp"; return 0
    fi
    # Belt and braces: the relay is the real gate, but a corrupt download is
    # cheaper to notice now. i18n catalogs are operator-replaceable data and
    # are exempt, matching the relay's own policy.
    if command -v python3 >/dev/null 2>&1; then
        if ! python3 - "$root" <<'PY'
import hashlib, json, os, sys
root = sys.argv[1]
m = json.load(open(os.path.join(root, "manifest.json")))
bad = 0
for rel, info in m["files"].items():
    if rel.startswith("i18n/"):
        continue
    p = os.path.join(root, rel)
    if not os.path.exists(p):
        print("missing:", rel); bad += 1; continue
    if hashlib.sha256(open(p, "rb").read()).hexdigest() != info["sha256"]:
        print("hash mismatch:", rel); bad += 1
sys.exit(1 if bad else 0)
PY
        then
            echo "bundle failed verification; NOT installing it"
            rm -rf "$tmp"; return 0
        fi
    else
        echo "python3 not found; skipping pre-verification (the relay verifies at startup)"
    fi
    rm -rf "$DOORWAY_DIR"
    mkdir -p "$DOORWAY_DIR"
    cp -r "$root/." "$DOORWAY_DIR/"
    if [ -f "$TRANSLATIONS" ]; then
        unzip -oq "$TRANSLATIONS" -d "$DOORWAY_DIR/i18n" \
            && echo "installed translation catalogs from docs/translations.zip"
    fi
    chown -R r2r:r2r "$DOORWAY_DIR"
    chmod -R u+rwX,go-rwx "$DOORWAY_DIR"
    echo "doorway installed at ${DOORWAY_DIR} ($(find "$DOORWAY_DIR" -type f | wc -l) files)"
    rm -rf "$tmp"
}
if [ "${R2R_SKIP_DOORWAY:-0}" != "1" ]; then
    install_doorway || true
fi

# ---------------------------------------------------------------------------
# Downloads mirror -- /var/lib/r2r/assets, served by the relay at /assets/.
#
# Every relay redistributes what it was installed from: the binary, this
# script, the site bundle, the wallet and the white paper, so the Downloads
# and Paper pages work on a fresh node and the next person can install from
# it. Files come from the same origin as the doorway bundle and are verified
# against the SHA-256 that origin publishes; a file already next to this
# script (just downloaded) is reused when its hash matches.
#
#   R2R_MIRROR_URL=https://…   mirror from a different relay
#   R2R_SKIP_MIRROR=1          do not mirror anything (R2R_ASSETS_DIR stays unset)
# ---------------------------------------------------------------------------
ASSETS_DIR=/var/lib/r2r/assets
MIRROR_URL="$ORIGIN"

install_mirror() {
    local listing n
    command -v curl >/dev/null 2>&1 || { echo "curl not found; not mirroring downloads"; return 0; }
    command -v python3 >/dev/null 2>&1 || { echo "python3 not found; not mirroring downloads"; return 0; }
    local listing_file
    listing_file="$(mktemp)"
    if ! curl -fsSL --max-time 30 -H 'Accept: application/json' -o "$listing_file" "${MIRROR_URL}/assets/" 2>/dev/null; then
        rm -f "$listing_file"
        echo "could not read ${MIRROR_URL}/assets/; not mirroring downloads"; return 0
    fi
    install -d -m 0755 -o r2r -g r2r "$ASSETS_DIR"
    # The listing goes in as a file: python's own script arrives on stdin.
    n="$(python3 - "$ASSETS_DIR" "$MIRROR_URL" "$HERE" "$BUILD" "$(dirname "$RELAY_BIN")" "$listing_file" <<'PY'
import hashlib, json, os, shutil, subprocess, sys
assets, origin, here, build, bindir, listing_path = sys.argv[1:7]
with open(listing_path) as fh:
    listing = json.load(fh)
files = listing.get("assets") if isinstance(listing, dict) else listing
LIMIT = 64 * 1024 * 1024
def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()
done = 0
for f in files or []:
    name, want, size = f.get("name", ""), (f.get("sha256") or "").lower(), int(f.get("size") or 0)
    if not name or "/" in name or name.startswith(".") or not want or size > LIMIT:
        continue
    dst = os.path.join(assets, name)
    if os.path.exists(dst) and sha(dst) == want:
        done += 1; continue
    src = None
    for cand in (os.path.join(here, name), os.path.join(build, name), os.path.join(bindir, name)):
        if os.path.isfile(cand) and sha(cand) == want:
            src = cand; break
    tmp = dst + ".part"
    try:
        if src:
            shutil.copyfile(src, tmp)
        else:
            subprocess.run(["curl", "-fsSL", "--max-time", "600", "-o", tmp, origin + "/assets/" + name],
                           check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if sha(tmp) != want:
            print("  hash mismatch for %s; skipped" % name, file=sys.stderr); os.unlink(tmp); continue
        os.chmod(tmp, 0o644); os.replace(tmp, dst); done += 1
    except Exception as e:
        print("  could not mirror %s: %s" % (name, e), file=sys.stderr)
        if os.path.exists(tmp): os.unlink(tmp)
print(done)
PY
)"
    rm -f "$listing_file"
    chown -R r2r:r2r "$ASSETS_DIR"
    echo "downloads mirrored from ${MIRROR_URL}: ${n:-0} files in ${ASSETS_DIR}"
}
if [ "${R2R_SKIP_MIRROR:-0}" != "1" ]; then
    install_mirror || true
fi

if [ ! -f /etc/r2r/relay.env ]; then
    if [ -z "$ADVERTISE" ]; then
        # Best guess: the address of the default route's interface.
        GUESS="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{print $7; exit}')"
        ADVERTISE="${GUESS:-127.0.0.1}:8787"
        echo "no advertise address given; guessing ${ADVERTISE}"
    fi
    cat > /etc/r2r/relay.env <<EOF
# Address other relays should dial to reach this node. Peers cannot route to a
# relay that does not advertise one.
R2R_ADVERTISE=${ADVERTISE}
R2R_LOG_LEVEL=info
EOF
    chmod 0644 /etc/r2r/relay.env
    echo "wrote /etc/r2r/relay.env (advertising ${ADVERTISE})"
fi
# Serve the mirrored downloads at /assets/ (only when the mirror exists and
# the setting is not already there, so an operator's own value is kept).
if [ -d "$ASSETS_DIR" ] && ! grep -q '^R2R_ASSETS_DIR=' /etc/r2r/relay.env; then
    printf '\n# Downloads served at /assets/ (Downloads and Paper pages, next installs).\nR2R_ASSETS_DIR=%s\n' "$ASSETS_DIR" >> /etc/r2r/relay.env
    echo "enabled downloads at /assets/ (R2R_ASSETS_DIR in /etc/r2r/relay.env)"
fi

if [ ! -f /etc/r2r/tls/cert.pem ]; then
    if [ -x "$CERT_SCRIPT" ] || [ -f "$CERT_SCRIPT" ]; then
        echo "no certificate yet; generating a self-signed one"
        bash "$CERT_SCRIPT" 2>/dev/null || bash "$CERT_SCRIPT" "$(hostname -f 2>/dev/null || hostname)" /etc/r2r/tls
    else
        echo "no certificate and no cert script; the relay will run ws:// only"
    fi
else
    echo "keeping the existing certificate at /etc/r2r/tls/cert.pem"
fi

# The relay runs as an unprivileged user, so it has to be able to read the key
# it was told to use. A key left at 0600 root:root is the usual reason the
# wss:// listener silently fails to start.
if [ -f /etc/r2r/tls/key.pem ]; then
    chown root:r2r /etc/r2r/tls/key.pem /etc/r2r/tls/cert.pem 2>/dev/null || true
    chmod 0640 /etc/r2r/tls/key.pem
    chmod 0644 /etc/r2r/tls/cert.pem
fi

[ -f "$UNIT" ] || { echo "cannot find r2r-relay.service next to this script" >&2; exit 1; }
install -m 0644 "$UNIT" /etc/systemd/system/r2r-relay.service
systemctl daemon-reload
systemctl enable r2r-relay
systemctl restart r2r-relay

sleep 2
systemctl --no-pager --lines=15 status r2r-relay || true

echo
echo "The first-run invite codes are in /var/lib/r2r/genesis-invites.txt"
echo "Check the node with: r2r-probe --url ws://127.0.0.1:8787 status"
