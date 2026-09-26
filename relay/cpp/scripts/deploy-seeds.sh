#!/usr/bin/env bash
# Pushes a built relay to the seed nodes and installs it there.
#
#   ./scripts/deploy-seeds.sh                 # all seeds in SEEDS below
#   ./scripts/deploy-seeds.sh 203.0.113.10    # just one
#   DRY_RUN=1 ./scripts/deploy-seeds.sh       # show what would happen
#
# Each node is given its own IP as --advertise, since a relay that does not
# advertise a reachable address cannot be routed to. Any host that is this
# machine is skipped: deploying to yourself over SSH mid-run is a good way to
# kill the deploy.
#
# BINARY COMPATIBILITY
#   The default ./build links libssl/libcrypto dynamically, so that binary must
#   be built on the same major distro release as the target; the script checks
#   and refuses a mismatch rather than shipping something that will not start.
#   The fully static cross builds have no such limit: point BUILD at one of
#   them (BUILD=build-cross/x86_64) or let install.sh on the target fetch the
#   published r2r-relay-<arch> itself.
set -uo pipefail

# The v2 network. Add each new seed relay here (and to kSeedPeers in
# src/config.cpp, or pass --seed on the relays) as it comes online.
SEEDS=(
    92.113.147.233   # r2r.homes
    143.110.227.46
    164.90.207.73
    164.92.156.207
    165.22.204.117
    165.232.132.110
)

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD="${BUILD:-$SRC/build}"
SSH_USER="${SSH_USER:-root}"
SSH_OPTS="${SSH_OPTS:--o ConnectTimeout=10 -o BatchMode=yes -o StrictHostKeyChecking=accept-new}"
REMOTE_DIR="/tmp/r2r-deploy"
DRY_RUN="${DRY_RUN:-0}"

[ -x "${BUILD}/r2r-relay" ] || { echo "build ${BUILD}/r2r-relay first" >&2; exit 1; }

targets=("$@")
[ ${#targets[@]} -eq 0 ] && targets=("${SEEDS[@]}")

LOCAL_IPS="$(hostname -I 2>/dev/null) 127.0.0.1"
LOCAL_RELEASE="$( . /etc/os-release 2>/dev/null && echo "${ID}${VERSION_ID}" )"

ok=0; failed=0; skipped=0

for host in "${targets[@]}"; do
    echo "=============================================================="
    echo "seed ${host}"

    if [[ " ${LOCAL_IPS} " == *" ${host} "* ]]; then
        echo "  this is the machine running the deploy -- skipping."
        echo "  install locally instead: sudo ./scripts/install.sh ${host}:8787"
        skipped=$((skipped+1))
        continue
    fi

    if [ "$DRY_RUN" = "1" ]; then
        echo "  would push $(basename "${BUILD}/r2r-relay") and run install.sh ${host}:8787"
        continue
    fi

    if ! ssh ${SSH_OPTS} "${SSH_USER}@${host}" true 2>/dev/null; then
        echo "  UNREACHABLE over SSH -- skipping"
        failed=$((failed+1))
        continue
    fi

    remote_release="$(ssh ${SSH_OPTS} "${SSH_USER}@${host}" \
        '. /etc/os-release 2>/dev/null && echo "${ID}${VERSION_ID}"' 2>/dev/null)"
    # A static binary (no NEEDED entries at all) runs on any release.
    if ! ldd "${BUILD}/r2r-relay" 2>&1 | grep -q '=>' ; then
        remote_release="$LOCAL_RELEASE"
    fi
    if [ -n "$LOCAL_RELEASE" ] && [ -n "$remote_release" ] && \
       [ "$LOCAL_RELEASE" != "$remote_release" ]; then
        echo "  REFUSING: built on ${LOCAL_RELEASE}, target runs ${remote_release}."
        echo "  Build on a matching release (or statically link OpenSSL) first."
        failed=$((failed+1))
        continue
    fi

    echo "  pushing binaries and install scripts"
    ssh ${SSH_OPTS} "${SSH_USER}@${host}" "mkdir -p ${REMOTE_DIR}/build ${REMOTE_DIR}/scripts ${REMOTE_DIR}/systemd" || {
        echo "  could not prepare ${REMOTE_DIR}"; failed=$((failed+1)); continue; }

    if ! scp ${SSH_OPTS} -q \
            "${BUILD}/r2r-relay" "${BUILD}/r2r-probe" \
            "${SSH_USER}@${host}:${REMOTE_DIR}/build/" ; then
        echo "  binary upload FAILED"; failed=$((failed+1)); continue
    fi
    scp ${SSH_OPTS} -q "${SRC}/scripts/install.sh" "${SRC}/scripts/gen-self-signed-cert.sh" \
        "${SSH_USER}@${host}:${REMOTE_DIR}/scripts/" || true
    scp ${SSH_OPTS} -q "${SRC}/systemd/r2r-relay.service" \
        "${SSH_USER}@${host}:${REMOTE_DIR}/systemd/" || true
    scp ${SSH_OPTS} -q "${SRC}/README.md" "${SSH_USER}@${host}:${REMOTE_DIR}/" || true

    echo "  installing (this stops whatever holds 8787 first)"
    if ssh ${SSH_OPTS} "${SSH_USER}@${host}" \
        "chmod +x ${REMOTE_DIR}/scripts/*.sh ${REMOTE_DIR}/build/* && \
         ${REMOTE_DIR}/scripts/install.sh ${host}:8787" 2>&1 | sed 's/^/    /'; then
        :
    else
        echo "  install FAILED"; failed=$((failed+1)); continue
    fi

    sleep 2
    health="$(ssh ${SSH_OPTS} "${SSH_USER}@${host}" \
        "curl -sf -m 5 http://127.0.0.1:8787/health" 2>/dev/null)"
    if [ -n "$health" ]; then
        echo "  HEALTHY: ${health//[$'\n']/ }"
        ok=$((ok+1))
    else
        echo "  installed but /health did not answer -- check: journalctl -u r2r-relay -n 50"
        failed=$((failed+1))
    fi
done

echo "=============================================================="
printf 'deployed %d, failed %d, skipped %d\n' "$ok" "$failed" "$skipped"
[ "$failed" -eq 0 ]
