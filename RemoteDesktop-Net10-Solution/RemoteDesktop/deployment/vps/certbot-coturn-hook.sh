#!/usr/bin/env bash
set -euo pipefail

# Certbot deploy hook to copy renewed Let's Encrypt certs into /etc/coturn/certs with turnserver read permissions.
if [ -n "${RENEWED_LINEAGE:-}" ] && [ -d /etc/coturn/certs ]; then
  cp "${RENEWED_LINEAGE}/fullchain.pem" /etc/coturn/certs/fullchain.pem
  cp "${RENEWED_LINEAGE}/privkey.pem" /etc/coturn/certs/privkey.pem
  chown -R root:turnserver /etc/coturn/certs
  chmod 640 /etc/coturn/certs/fullchain.pem /etc/coturn/certs/privkey.pem
  systemctl restart coturn || true
fi
