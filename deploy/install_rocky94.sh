#!/usr/bin/env bash
# ==============================================================================
# AI Packet Anomaly Guard - One-Click Deployment Script for Rocky Linux 9.4
# Target OS: Rocky Linux 9.4 (x86_64 / aarch64)
# ==============================================================================

set -e

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${CYAN}====================================================================${NC}"
echo -e "${CYAN}🚀 Starting AI Packet Anomaly Guard Installation for Rocky Linux 9.4 ${NC}"
echo -e "${CYAN}====================================================================${NC}"

# 1. Check Root Privileges
if [ "$EUID" -ne 0 ]; then
  echo -e "${RED}❌ Error: This installation script must be run as root (sudo ./install_rocky94.sh)${NC}"
  exit 1
fi

# 2. Determine Installation Path
APP_DIR="$(cd "$(dirname "$0")/.." && pwd)"
echo -e "${YELLOW}📂 Target Application Directory: ${APP_DIR}${NC}"

# 3. Enable CRB & EPEL repository on Rocky Linux 9.4
echo -e "${CYAN}📦 Configuring Repositories & Installing Dependencies...${NC}"
dnf install -y epel-release || true
dnf config-manager --set-enabled crb || true

# Try installing packages; fallback if libpcap-devel is not in active repos
dnf install -y \
  python3 \
  python3-pip \
  python3-devel \
  gcc \
  gcc-c++ \
  make \
  libpcap \
  libpcap-devel \
  nginx \
  firewalld \
  curl \
  procps-ng || \
dnf install -y \
  python3 \
  python3-pip \
  python3-devel \
  gcc \
  gcc-c++ \
  make \
  libpcap \
  firewalld \
  curl \
  procps-ng

# 4. Create Virtual Environment
echo -e "${CYAN}🐍 Setting up Python 3 Virtual Environment...${NC}"
VENV_DIR="${APP_DIR}/venv"
if [ ! -d "$VENV_DIR" ]; then
  python3 -m venv "$VENV_DIR"
fi

# 5. Install Python Dependencies
echo -e "${CYAN}⚡ Installing Python Package Dependencies...${NC}"
"${VENV_DIR}/bin/pip" install --upgrade pip setuptools wheel
"${VENV_DIR}/bin/pip" install -r "${APP_DIR}/backend/requirements.txt"

# 6. Ensure /DATA.TRAIN Directory Exists
DATA_TRAIN_DIR="${APP_DIR}/DATA.TRAIN"
echo -e "${CYAN}📂 Creating /DATA.TRAIN Storage Directory...${NC}"
mkdir -p "$DATA_TRAIN_DIR"
chmod -R 775 "$DATA_TRAIN_DIR"

# 7. Configure Systemd Services
echo -e "${CYAN}⚙️ Installing Systemd Service Units...${NC}"

# Backend Service
cat << EOF > /etc/systemd/system/ai-pkt-backend.service
[Unit]
Description=AI Packet Anomaly Guard - FastAPI Backend
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${APP_DIR}/backend
ExecStart=${VENV_DIR}/bin/python3 -m uvicorn main:app --host 0.0.0.0 --port 8000
Restart=always
RestartSec=3
Environment=PYTHONUNBUFFERED=1

[Install]
WantedBy=multi-user.target
EOF

# Frontend Service
cat << EOF > /etc/systemd/system/ai-pkt-frontend.service
[Unit]
Description=AI Packet Anomaly Guard - Frontend Web Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=${APP_DIR}/frontend
ExecStart=/usr/bin/python3 -m http.server 3000
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

# Reload Systemd
systemctl daemon-reload

# 8. Configure Firewalld Ports
echo -e "${CYAN}🔥 Configuring Firewalld Ports (3000, 8000, 80)...${NC}"
systemctl enable --now firewalld || true
firewall-cmd --permanent --add-port=3000/tcp || true
firewall-cmd --permanent --add-port=8000/tcp || true
firewall-cmd --permanent --add-port=80/tcp || true
firewall-cmd --reload || true

# 9. Configure SELinux (Permissive for Network Ports & Web Server)
if command -v setenforce &> /dev/null; then
  echo -e "${CYAN}🛡️ Adjusting SELinux Network Policies...${NC}"
  setsebool -P httpd_can_network_connect 1 || true
fi

# 10. Enable and Start Services
echo -e "${CYAN}🚀 Enabling and Starting AI Packet Guard Services...${NC}"
systemctl enable --now ai-pkt-backend.service
systemctl enable --now ai-pkt-frontend.service

echo -e "${GREEN}====================================================================${NC}"
echo -e "${GREEN}✅ AI Packet Anomaly Guard Installed Successfully on Rocky Linux 9.4! ${NC}"
echo -e "${GREEN}====================================================================${NC}"
echo -e "${CYAN}🌐 Web Dashboard URL  : http://<SERVER_IP>:3000${NC}"
echo -e "${CYAN}⚡ Backend API URL    : http://<SERVER_IP>:8000${NC}"
echo -e "${CYAN}📂 Model Directory    : ${DATA_TRAIN_DIR}${NC}"
echo -e "${CYAN}📊 Service Commands   : sudo systemctl status ai-pkt-backend ai-pkt-frontend${NC}"
echo -e "${GREEN}====================================================================${NC}"
