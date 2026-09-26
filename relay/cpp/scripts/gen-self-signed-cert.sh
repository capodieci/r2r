#!/usr/bin/env bash
# Generates the TLS material for the wss:// listener.
#
#   sudo ./scripts/gen-self-signed-cert.sh [common-name] [output-dir]
#
# A self-signed certificate is the normal case for an R2R relay. Peer relays do
# not check the certificate chain: they authenticate each other with the ed25519
# signature inside `hello`, pinned per address in peers.json. TLS is here to
# encrypt the transport, not to prove who is on the other end.
#
# Browser clients are the exception -- they will refuse a self-signed
# certificate. If real clients connect from a browser, use a CA-issued
# certificate instead (certbot writes exactly the two files this script does):
#
#   certbot certonly --standalone -d relay.example.org
#   ln -sf /etc/letsencrypt/live/relay.example.org/fullchain.pem /etc/r2r/tls/cert.pem
#   ln -sf /etc/letsencrypt/live/relay.example.org/privkey.pem   /etc/r2r/tls/key.pem
set -euo pipefail

CN="${1:-$(hostname -f 2>/dev/null || hostname)}"
OUT="${2:-/etc/r2r/tls}"
DAYS=825

command -v openssl >/dev/null || { echo "openssl is required" >&2; exit 1; }

mkdir -p "$OUT"

# Name every address a peer might dial, so the certificate stays usable if the
# relay is reached by IP as well as by name.
SAN="DNS:${CN}"
for ip in $(hostname -I 2>/dev/null || true); do SAN="${SAN},IP:${ip}"; done
SAN="${SAN},DNS:localhost,IP:127.0.0.1"

echo "generating a self-signed certificate"
echo "  common name : ${CN}"
echo "  names       : ${SAN}"
echo "  output      : ${OUT}"

openssl req -x509 -newkey rsa:4096 -sha256 -days "$DAYS" -nodes \
    -keyout "${OUT}/key.pem" \
    -out "${OUT}/cert.pem" \
    -subj "/CN=${CN}" \
    -addext "subjectAltName=${SAN}" \
    -addext "basicConstraints=critical,CA:FALSE" \
    -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
    -addext "extendedKeyUsage=serverAuth" 2>/dev/null

chmod 644 "${OUT}/cert.pem"
chmod 640 "${OUT}/key.pem"

# The relay runs unprivileged, so the key has to be group-readable by it.
if getent group r2r >/dev/null 2>&1; then
    chown root:r2r "${OUT}/key.pem" "${OUT}/cert.pem" 2>/dev/null || true
    echo "  key is readable by group 'r2r'"
else
    echo "  note: group 'r2r' does not exist yet; re-run after creating the service user"
fi

echo
openssl x509 -in "${OUT}/cert.pem" -noout -subject -dates -ext subjectAltName
echo
echo "done. Restart the relay to pick it up: systemctl restart r2r-relay"
