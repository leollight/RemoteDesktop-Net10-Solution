#!/usr/bin/env bash
set -euo pipefail

# Publishes RemoteDesktop.Backend, runs EF Core migrations, configures Nginx reverse proxy, and starts systemd service.
# Usage: sudo ./deploy-backend.sh <backend-domain>
BACKEND_DOMAIN="${1:?Provide public backend domain name (e.g. rdp.your-domain.example)}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SOLUTION_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
PUBLISH_DIR="/opt/remotedesktop/backend"
ENV_DIR="/etc/remotedesktop"
ENV_FILE="${ENV_DIR}/server.env"

mkdir -p "${ENV_DIR}" "${PUBLISH_DIR}"
chown root:remotedesktop "${ENV_DIR}"
chmod 750 "${ENV_DIR}"
touch "${ENV_FILE}"
chown root:remotedesktop "${ENV_FILE}"
chmod 640 "${ENV_FILE}"

if ! grep -q '^SESSION_SECRET=' "${ENV_FILE}"; then
  echo "SESSION_SECRET=$(openssl rand -hex 48)" >> "${ENV_FILE}"
fi
if ! grep -q '^ASPNETCORE_ENVIRONMENT=' "${ENV_FILE}"; then
  echo "ASPNETCORE_ENVIRONMENT=Production" >> "${ENV_FILE}"
fi
if ! grep -q '^ASPNETCORE_URLS=' "${ENV_FILE}"; then
  echo "ASPNETCORE_URLS=http://127.0.0.1:5000" >> "${ENV_FILE}"
fi
if ! grep -q '^Relay__PublicBaseUrl=' "${ENV_FILE}"; then
  echo "Relay__PublicBaseUrl=https://${BACKEND_DOMAIN}" >> "${ENV_FILE}"
fi

# Load REMOTEDESKTOP_DB for EF Core migration execution
set -a
# shellcheck source=/dev/null
source "${ENV_FILE}"
set +a

dotnet publish "${SOLUTION_ROOT}/src/RemoteDesktop.Backend/RemoteDesktop.Backend.csproj" \
  -c Release \
  -o "${PUBLISH_DIR}"

export PATH="${PATH}:/root/.dotnet/tools"
if ! command -v dotnet-ef >/dev/null 2>&1; then
  dotnet tool install --global dotnet-ef --version 10.0.0 || dotnet tool install --global dotnet-ef
fi

dotnet ef database update \
  --project "${SOLUTION_ROOT}/src/RemoteDesktop.Infrastructure/RemoteDesktop.Infrastructure.csproj" \
  --startup-project "${SOLUTION_ROOT}/src/RemoteDesktop.Backend/RemoteDesktop.Backend.csproj"

chown -R remotedesktop:remotedesktop "${PUBLISH_DIR}"

cp "${SCRIPT_DIR}/remotedesktop-backend.service.template" /etc/systemd/system/remotedesktop-backend.service
systemctl daemon-reload
systemctl enable remotedesktop-backend
systemctl restart remotedesktop-backend

sed -e "s|{{BACKEND_DOMAIN}}|${BACKEND_DOMAIN}|g" \
  "${SCRIPT_DIR}/nginx-remotedesktop.conf.template" > /etc/nginx/sites-available/remotedesktop
ln -sf /etc/nginx/sites-available/remotedesktop /etc/nginx/sites-enabled/remotedesktop
nginx -t
systemctl reload nginx

echo "RemoteDesktop.Backend published, migrated, and running behind Nginx for https://${BACKEND_DOMAIN}."
echo "If TLS is not yet configured on Nginx, run: sudo certbot --nginx -d ${BACKEND_DOMAIN}"
