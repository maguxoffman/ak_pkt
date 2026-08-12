#!/usr/bin/env bash
# One-touch Start Script for AI Packet Anomaly Guard

APP_DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo "🚀 Starting AI Packet Anomaly Guard Services..."

if command -v systemctl &> /dev/null && [ "$EUID" -eq 0 ]; then
  systemctl start ai-pkt-backend.service
  systemctl start ai-pkt-frontend.service
  echo "✅ Systemd services started successfully."
else
  pkill -9 -f "uvicorn main:app" || true
  pkill -9 -f "http.server 3000" || true

  nohup "${APP_DIR}/venv/bin/python3" -m uvicorn main:app --host 0.0.0.0 --port 8000 --directory "${APP_DIR}/backend" > "${APP_DIR}/backend.log" 2>&1 &
  nohup python3 -m http.server 3000 --directory "${APP_DIR}/frontend" > "${APP_DIR}/frontend.log" 2>&1 &

  echo "✅ Application started in background mode."
fi

sleep 1
bash "$(dirname "$0")/status.sh"
