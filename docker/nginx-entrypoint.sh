#!/bin/sh
set -e

mkdir -p /etc/nginx/certs

if [ ! -f /etc/nginx/certs/honeyforge.crt ] || [ ! -f /etc/nginx/certs/honeyforge.key ]; then
    echo "Static-Edge: Generating TLS certificate with clean SAN (MASK-1 & MASK-7)..."
    openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/nginx/certs/honeyforge.key \
        -out /etc/nginx/certs/honeyforge.crt \
        -subj "/CN=static-edge" \
        -addext "subjectAltName=DNS:static-edge,DNS:mgmt-gateway,DNS:nginx-proxy,DNS:localhost,IP:127.0.0.1,IP:172.28.0.3,IP:172.29.0.3,IP:172.29.0.4"
    cp -f /etc/nginx/certs/honeyforge.crt /etc/nginx/certs/static-edge.crt 2>/dev/null || true
    chmod 644 /etc/nginx/certs/honeyforge.crt /etc/nginx/certs/static-edge.crt 2>/dev/null || true
    chmod 600 /etc/nginx/certs/honeyforge.key
    echo "Static-Edge: TLS certificates successfully generated."
else
    cp -f /etc/nginx/certs/honeyforge.crt /etc/nginx/certs/static-edge.crt 2>/dev/null || true
fi

exec "$@"
