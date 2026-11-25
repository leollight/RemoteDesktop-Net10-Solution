#!/usr/bin/env bash
set -euo pipefail

# Ubuntu 24.04 LTS VPS bootstrap for RemoteDesktop.Backend (.NET 10 + PostgreSQL + Coturn + Nginx + Certbot)
# Usage: sudo ./install-vps.sh

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y curl gnupg lsb-release ca-certificates ufw postgresql postgresql-contrib coturn nginx certbot python3-certbot-nginx

# Install Microsoft package repository for .NET 10 SDK / ASP.NET Core Runtime
UBUNTU_VERSION="$(lsb_release -rs)"
curl -fsSL "https://packages.microsoft.com/config/ubuntu/${UBUNTU_VERSION}/packages-microsoft-prod.deb" -o /tmp/packages-microsoft-prod.deb
dpkg -i /tmp/packages-microsoft-prod.deb
rm -f /tmp/packages-microsoft-prod.deb
apt-get update
apt-get install -y dotnet-sdk-10.0 aspnetcore-runtime-10.0

if ! command -v dotnet-ef >/dev/null 2>&1; then
  dotnet tool install --global dotnet-ef --version 10.0.0 || dotnet tool install --global dotnet-ef
  if [ -x /root/.dotnet/tools/dotnet-ef ]; then
    ln -sf /root/.dotnet/tools/dotnet-ef /usr/local/bin/dotnet-ef
  fi
fi

# Create dedicated unprivileged service user for ASP.NET Core backend
if ! id -u remotedesktop >/dev/null 2>&1; then
  useradd --system --home-dir /opt/remotedesktop --shell /usr/sbin/nologin remotedesktop
fi

mkdir -p /opt/remotedesktop /etc/remotedesktop
chown root:remotedesktop /etc/remotedesktop
chmod 750 /etc/remotedesktop

ENV_FILE="/etc/remotedesktop/server.env"
touch "${ENV_FILE}"
chown root:remotedesktop "${ENV_FILE}"
chmod 640 "${ENV_FILE}"

# Provision PostgreSQL database & dedicated least-privilege application role
if ! grep -q '^REMOTEDESKTOP_DB=' "${ENV_FILE}"; then
  DB_PASS="$(openssl rand -hex 24)"
  su - postgres -c "psql -tAc \"SELECT 1 FROM pg_roles WHERE rolname='remotedesktop_app'\"" | grep -q 1 || \
    su - postgres -c "psql -c \"CREATE USER remotedesktop_app WITH PASSWORD '${DB_PASS}';\""
  su - postgres -c "psql -tAc \"SELECT 1 FROM pg_database WHERE datname='remotedesktop_prod'\"" | grep -q 1 || \
    su - postgres -c "psql -c \"CREATE DATABASE remotedesktop_prod OWNER remotedesktop_app;\""

  echo "REMOTEDESKTOP_DB=Host=127.0.0.1;Port=5432;Database=remotedesktop_prod;Username=remotedesktop_app;Password=${DB_PASS}" >> "${ENV_FILE}"
  echo "Provisioned PostgreSQL role/database and stored connection string in ${ENV_FILE}."
fi

echo "Configuring UFW firewall (SSH rate-limited, HTTPS, TURN 3478/5349, and relay UDP port range)..."
ufw default deny incoming
ufw default allow outgoing
ufw limit 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 3478/udp
ufw allow 3478/tcp
ufw allow 5349/tcp
ufw allow 5349/udp
ufw allow 49152:65535/udp
ufw --force enable

echo "VPS dependencies, PostgreSQL, .NET 10, and firewall configured."
echo "Next: obtain TLS certificates via Certbot, run deploy-relay.sh, and run deploy-backend.sh."
