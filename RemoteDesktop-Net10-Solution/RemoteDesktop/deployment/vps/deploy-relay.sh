#!/usr/bin/env bash
set -euo pipefail

# Provisions Coturn TURN relay with TLS certificates and server-only TURN_SHARED_SECRET.
# Usage: sudo ./deploy-relay.sh <turn-domain> [turn-port] [turn-realm]
TURN_HOST_VALUE="${1:?Provide public TURN domain name}"
TURN_PORT_VALUE="${2:-3478}"
TURN_REALM_VALUE="${3:-$TURN_HOST_VALUE}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ENV_DIR="/etc/remotedesktop"
ENV_FILE="${ENV_DIR}/server.env"
CERT_SRC_DIR="/etc/letsencrypt/live/${TURN_HOST_VALUE}"
COTURN_CERT_DIR="/etc/coturn/certs"

if [ ! -f "${CERT_SRC_DIR}/fullchain.pem" ] || [ ! -f "${CERT_SRC_DIR}/privkey.pem" ]; then
  echo "TLS certificate not found at ${CERT_SRC_DIR}. Obtain a Let's Encrypt cert first:"
  echo "  sudo certbot certonly --nginx -d ${TURN_HOST_VALUE}"
  exit 1
fi

mkdir -p "${COTURN_CERT_DIR}"
cp "${CERT_SRC_DIR}/fullchain.pem" "${COTURN_CERT_DIR}/fullchain.pem"
cp "${CERT_SRC_DIR}/privkey.pem" "${COTURN_CERT_DIR}/privkey.pem"
chown -R root:turnserver "${COTURN_CERT_DIR}"
chmod 750 "${COTURN_CERT_DIR}"
chmod 640 "${COTURN_CERT_DIR}/fullchain.pem" "${COTURN_CERT_DIR}/privkey.pem"

TURN_SECRET="$(openssl rand -hex 32)"

mkdir -p "${ENV_DIR}"
chown root:remotedesktop "${ENV_DIR}" || true
chmod 750 "${ENV_DIR}"

sed \
  -e "s|{{TURN_PORT}}|${TURN_PORT_VALUE}|g" \
  -e "s|{{TURN_SHARED_SECRET}}|${TURN_SECRET}|g" \
  -e "s|{{TURN_REALM}}|${TURN_REALM_VALUE}|g" \
  "${SCRIPT_DIR}/turnserver.conf.template" > /etc/turnserver.conf

chown root:turnserver /etc/turnserver.conf
chmod 640 /etc/turnserver.conf

# Enable coturn daemon in /etc/default/coturn on Debian/Ubuntu
if [ -f /etc/default/coturn ]; then
  sed -i 's/^#*TURNSERVER_ENABLED=.*/TURNSERVER_ENABLED=1/' /etc/default/coturn
fi

# Synchronize server-side environment values for ASP.NET Core backend (never distributed to clients)
touch "${ENV_FILE}"
chown root:remotedesktop "${ENV_FILE}" || true
chmod 640 "${ENV_FILE}"
grep -v -E '^(TURN_HOST|TURN_PORT|TURN_REALM|TURN_SHARED_SECRET)=' "${ENV_FILE}" > "${ENV_FILE}.tmp" || true
{
  cat "${ENV_FILE}.tmp"
  echo "TURN_HOST=${TURN_HOST_VALUE}"
  echo "TURN_PORT=${TURN_PORT_VALUE}"
  echo "TURN_REALM=${TURN_REALM_VALUE}"
  echo "TURN_SHARED_SECRET=${TURN_SECRET}"
} > "${ENV_FILE}"
rm -f "${ENV_FILE}.tmp"

install -m 750 "${SCRIPT_DIR}/certbot-coturn-hook.sh" /etc/letsencrypt/renewal-hooks/deploy/coturn-cert-sync.sh 2>/dev/null || true

systemctl enable coturn
systemctl restart coturn
echo "Coturn provisioned for ${TURN_HOST_VALUE}:${TURN_PORT_VALUE} (TLS 5349, realm=${TURN_REALM_VALUE})."
