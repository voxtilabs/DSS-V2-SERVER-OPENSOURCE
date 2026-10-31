#!/bin/bash
set -e

echo "=== DSS V2 Harness Ubuntu Lab Deployment ==="
echo "Target: 10.10.20.120"
echo ""

# Check if running as root
if [ "$EUID" -eq 0 ]; then
  echo "Please do not run as root. Run as user 'bruno'."
  exit 1
fi

echo "[1/6] Updating package lists..."
sudo apt-get update

echo "[2/6] Installing prerequisites..."
sudo apt-get install -y ca-certificates curl gnupg lsb-release

echo "[3/6] Installing Node.js 20..."
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs

echo "[4/6] Installing Docker..."
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo $VERSION_CODENAME) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker $USER
sudo systemctl enable docker
sudo systemctl start docker

echo "[5/6] Generating TLS certificates..."
mkdir -p ~/certs
openssl req -x509 -newkey rsa:2048 -nodes -keyout ~/certs/key.pem -out ~/certs/cert.pem -days 365 -subj '/CN=10.10.20.120'
sudo chown $USER:$USER ~/certs/*.pem

echo "[6/6] Setting up DSS V2 Harness..."
mkdir -p ~/dss-v2-harness
cd ~/dss-v2-harness

echo "Deployment complete!"
echo ""
echo "Next steps:"
echo "1. Log out and back in for docker group changes to take effect"
echo "2. Copy the harness code to ~/dss-v2-harness/"
echo "3. Run: cd ~/dss-v2-harness && docker compose up -d"
echo "3. Test with: npm test (from brms-gateway directory)"
echo ""
echo "Ports used:"
echo "  1443/tcp  - BRMS Gateway HTTPS"
echo "  11443/tcp - BRMS Gateway HTTP (internal)"
echo "  9100/tcp  - MTS RTSP (to be implemented)"
echo "  18800/udp - Alarm Ingest"
echo "  19800/udp - Alarm Ingest Backup"