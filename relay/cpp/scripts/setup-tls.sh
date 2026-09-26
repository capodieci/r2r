#!/usr/bin/env bash
# Gives a relay a working certificate, one command, on any node.
#
#   sudo ./setup-tls.sh                     self-signed (relay-to-relay, native clients)
#   sudo ./setup-tls.sh relay1.example.org  Let's Encrypt (browsers trust it)
#
# WHICH ONE DO I NEED?
#
#   Self-signed is enough for the relay network itself. Relays do not check
#   each other's certificate chain -- they authenticate with the ed25519
#   signature in `hello`, pinned per address in peers.json, which binds the
#   *node* rather than a hostname and is stronger than a certificate for that
#   purpose. Native clients that pin the same way are fine too.
#
#   A real certificate is needed for exactly one thing: a browser connecting
#   straight to this relay. Browsers refuse self-signed certificates and refuse
#   ws:// from an https:// page. If browser users reach you through another
#   node's portal instead, you do not need this.
#
# Renewal is wired to SIGHUP, so a renewed certificate is picked up without
# restarting the relay or dropping a single connection.
set -euo pipefail

DOMAIN="${1:-}"
TLS_DIR="${TLS_DIR:-/etc/r2r/tls}"
GROUP="${R2R_GROUP:-r2r}"

[ "$(id -u)" -eq 0 ] || { echo "run this with sudo" >&2; exit 1; }

install -d -m 0755 /etc/r2r
install -d -m 0750 "$TLS_DIR"

# The relay runs unprivileged; only its group may read the key.
harden() {
    if getent group "$GROUP" >/dev/null 2>&1; then
        chown root:"$GROUP" "$TLS_DIR" "$TLS_DIR/cert.pem" "$TLS_DIR/key.pem" 2>/dev/null || true
        chmod 0750 "$TLS_DIR"
        chmod 0640 "$TLS_DIR/key.pem"
        chmod 0644 "$TLS_DIR/cert.pem"
        echo "  key readable by group '$GROUP' only"
    else
        chmod 0600 "$TLS_DIR/key.pem"
        echo "  NOTE: group '$GROUP' does not exist yet. Run scripts/install.sh first,"
        echo "        then re-run this script so the relay's user can read the key."
    fi
}

reload_relay() {
    # SIGHUP re-reads the certificate in place; no connection is dropped.
    if systemctl is-active --quiet r2r-relay 2>/dev/null; then
        systemctl kill -s HUP r2r-relay && echo "  signalled r2r-relay to reload it"
    fi
}

# ---------------------------------------------------------------- self-signed
if [ -z "$DOMAIN" ]; then
    CN="$(hostname -f 2>/dev/null || hostname)"
    SAN="DNS:${CN},DNS:localhost,IP:127.0.0.1"
    for ip in $(hostname -I 2>/dev/null || true); do SAN="${SAN},IP:${ip}"; done

    echo "issuing a self-signed certificate for ${CN}"
    openssl req -x509 -newkey rsa:4096 -sha256 -days 825 -nodes \
        -keyout "$TLS_DIR/key.pem" -out "$TLS_DIR/cert.pem" \
        -subj "/CN=${CN}" \
        -addext "subjectAltName=${SAN}" \
        -addext "basicConstraints=critical,CA:FALSE" \
        -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
        -addext "extendedKeyUsage=serverAuth" 2>/dev/null
    harden
    reload_relay
    echo
    openssl x509 -in "$TLS_DIR/cert.pem" -noout -subject -dates -ext subjectAltName
    echo
    echo "Done. wss:// will start on 8788 the next time the relay starts."
    echo "Browsers will refuse this certificate -- that is expected; see the note above."
    exit 0
fi

# -------------------------------------------------------------- Let's Encrypt
echo "requesting a certificate for ${DOMAIN} from Let's Encrypt"

# Port 80 has to be free and reachable from the internet for the HTTP-01
# challenge. On the node that runs nginx, use the webroot instead of standalone.
if ! command -v certbot >/dev/null 2>&1; then
    echo "  installing certbot"
    DEBIAN_FRONTEND=noninteractive apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq certbot
fi

if systemctl is-active --quiet nginx 2>/dev/null && [ -d /var/www ]; then
    WEBROOT="$(ls -d /var/www/* 2>/dev/null | head -1)"
    echo "  nginx is running; using the webroot challenge at ${WEBROOT}"
    certbot certonly --webroot -w "${WEBROOT:-/var/www/html}" -d "$DOMAIN" \
        --non-interactive --agree-tos --register-unsafely-without-email
else
    echo "  using the standalone challenge (port 80 must be free and reachable)"
    certbot certonly --standalone -d "$DOMAIN" \
        --non-interactive --agree-tos --register-unsafely-without-email
fi

LIVE="/etc/letsencrypt/live/${DOMAIN}"
[ -f "$LIVE/fullchain.pem" ] || { echo "certbot did not produce a certificate" >&2; exit 1; }

# Symlinks rather than copies, so a renewal is visible immediately and there is
# only ever one copy of the private key on disk.
ln -sf "$LIVE/fullchain.pem" "$TLS_DIR/cert.pem"
ln -sf "$LIVE/privkey.pem"   "$TLS_DIR/key.pem"

# certbot writes privkey.pem 0600 root:root; the relay's group needs to read it.
if getent group "$GROUP" >/dev/null 2>&1; then
    chgrp -R "$GROUP" /etc/letsencrypt/live /etc/letsencrypt/archive 2>/dev/null || true
    chmod -R g+rX /etc/letsencrypt/live /etc/letsencrypt/archive 2>/dev/null || true
fi

# Reload on every future renewal instead of restarting.
install -d -m 0755 /etc/letsencrypt/renewal-hooks/deploy
cat > /etc/letsencrypt/renewal-hooks/deploy/r2r-reload <<'HOOK'
#!/bin/sh
# Tell the relay to re-read its certificate. SIGHUP reloads it in place, so no
# client connection or peer link is dropped by a renewal.
if command -v systemctl >/dev/null 2>&1; then
    systemctl is-active --quiet r2r-relay && systemctl kill -s HUP r2r-relay
    systemctl is-active --quiet nginx && systemctl reload nginx
fi
exit 0
HOOK
chmod 0755 /etc/letsencrypt/renewal-hooks/deploy/r2r-reload

reload_relay
echo
openssl x509 -in "$TLS_DIR/cert.pem" -noout -subject -issuer -dates
echo
echo "Done. Renewal is automatic and reloads the relay in place."
