#!/usr/bin/env bash
# One-touch Stop Script for AI Packet Anomaly Guard

echo "🛑 Stopping AI Packet Anomaly Guard Services..."

if command -v systemctl &> /dev/null && [ "$EUID" -eq 0 ]; then
  systemctl stop ai-pkt-backend.service || true
  systemctl stop ai-pkt-frontend.service || true
  echo "✅ Systemd services stopped."
fi

pkill -9 -f "uvicorn main:app" || true
pkill -9 -f "http.server 3000" || true

echo "✅ All processes cleanly terminated."
