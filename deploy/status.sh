#!/usr/bin/env bash
# Status Checker Script for AI Packet Anomaly Guard

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo "===================================================================="
echo "📊 Checking AI Packet Anomaly Guard Status..."
echo "===================================================================="

# Check Port 8000 (Backend)
if curl -s http://127.0.0.1:8000/health | grep -q "ok"; then
  echo -e "Backend (Port 8000)  : ${GREEN}● RUNNING (200 OK)${NC}"
else
  echo -e "Backend (Port 8000)  : ${RED}○ STOPPED / UNREACHABLE${NC}"
fi

# Check Port 3000 (Frontend)
if curl -sI http://127.0.0.1:3000/ | grep -q "200 OK"; then
  echo -e "Frontend (Port 3000) : ${GREEN}● RUNNING (200 OK)${NC}"
else
  echo -e "Frontend (Port 3000) : ${RED}○ STOPPED / UNREACHABLE${NC}"
fi

echo "===================================================================="
