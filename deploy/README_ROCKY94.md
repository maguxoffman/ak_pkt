# 🚀 Rocky Linux 9.4 배포 및 운용 가이드 (AI Packet Anomaly Guard v2.8)

본 문서는 **Rocky Linux 9.4 (x86_64 / aarch64)** 엔터프라이즈 환경에서 **AI Packet Anomaly Guard (10-Feature Vector & RTT 응답시간 탐지 엔진)** 시스템을 한 번의 클릭(One-Click)으로 자동 설치 및 Systemd 데몬 서비스로 등록하고 운용하는 절차를 설명합니다.

---

## 📂 1. 배포 디렉토리 구성 (`/deploy`)

```text
/deploy/
├── install_rocky94.sh    # Rocky Linux 9.4 전용 1-Click 자동 설치 스크립트
├── ai-pkt-backend.service # FastAPI 백엔드 데몬 Systemd 서비스 파일 (Port 8000)
├── ai-pkt-frontend.service# 프론트엔드 웹 데몬 Systemd 서비스 파일 (Port 3000)
├── nginx_ai_pkt.conf     # Nginx 리버스 프록시 운영 설정 파일 (Option)
├── start.sh              # 원터치 수동 서비스 시작 스크립트
├── stop.sh               # 원터치 수동 서비스 중지 스크립트
└── status.sh             # 서버 헬스체크 및 포트 상태 점검 스크립트
```

---

## 🛠️ 2. Rocky Linux 9.4 서버 자동 설치

서버의 권장 디렉토리(`/var/ai_pkt`)에 전체 소스코드를 복사한 후, 루트(root) 권한으로 자동 설치 스크립트를 실행합니다.

```bash
# 1. 설치 디렉토리 권한 부여 및 이동
cd /var/ai_pkt/deploy

# 2. 실행 권한 부여
chmod +x install_rocky94.sh start.sh stop.sh status.sh

# 3. Rocky Linux 9.4 자동 설치 실행 (Root 권한 필요)
sudo ./install_rocky94.sh
```

### ⚙️ `install_rocky94.sh` 스크립트 자동 처리 내역
1. **DNF 시스템 패키지 자동 설치**: `python3`, `python3-pip`, `python3-devel`, `gcc`, `gcc-c++`, `make`, `libpcap-devel`, `nginx`, `firewalld`
2. **Python Virtualenv 가상환경 구성**: `/var/ai_pkt/venv` 생성 및 `backend/requirements.txt` 자동 다운로드 설치
3. **`/PCAP` & `/DATA.TRAIN` 저장소 자동 생성**: PCAP 패킷 파일 및 모델 저장 디렉토리 생성
4. **Systemd 데몬 서비스 자동 등록**: `ai-pkt-backend.service`, `ai-pkt-frontend.service` 자동 등록 및 부팅 시 자동 시작(`enable --now`)
5. **Firewalld 방화벽 포트 자동 개방**: Port 3000(웹 UI), Port 8000(FastAPI API/WebSocket), Port 80(Nginx)

---

## 🎮 3. 서비스 운용 및 상태 관리 명령어

### ① Systemd 서비스 상태 확인 및 제어
```bash
# 백엔드/프론트엔드 서비스 상태 확인
sudo systemctl status ai-pkt-backend ai-pkt-frontend

# 서비스 재시작
sudo systemctl restart ai-pkt-backend ai-pkt-frontend

# 서비스 중지
sudo systemctl stop ai-pkt-backend ai-pkt-frontend
```

### ② 실시간 헬스체크 및 상태 확인 스크립트
```bash
./deploy/status.sh
```

---

## 🌐 4. 접속 경로 및 시스템 사양

| 구 분 | 접속 URL | 서비스 설명 |
| :--- | :--- | :--- |
| **웹 대시보드 UI** | `http://<SERVER_IP>:3000` | React 실시간 패킷 탐지 및 10-Feature 4단계 분석 UI |
| **백엔드 REST API** | `http://<SERVER_IP>:8000/api/models` | FastAPI Isolation Forest anomaly detection 백엔드 엔진 |
| **WebSocket 스트림** | `ws://<SERVER_IP>:8000/ws/packets` | 실시간 0.1% 이상치 및 RTT 응답시간 수신 채널 |
| **PCAP 패킷 저장소** | `/var/ai_pkt/PCAP` | 분석 대상 `.pcap` 대용량 패킷 파일 저장 디렉토리 |
| **학습 모델 저장소** | `/var/ai_pkt/DATA.TRAIN` | Isolation Forest 10-Feature `.pkl` 머신러닝 모델 파일 |

---

## 🔒 5. (선택사항) Nginx 80번 포트 통합 운영 (Reverse Proxy)

웹 대시보드(3000)와 백엔드(8000) 포트를 80번 포트로 통합하여 운영하고자 하는 경우:

```bash
# 1. Nginx 설정 파일 복사
sudo cp /var/ai_pkt/deploy/nginx_ai_pkt.conf /etc/nginx/conf.d/ai_pkt.conf

# 2. Nginx 설정 구문 검사 및 재시작
sudo nginx -t
sudo systemctl restart nginx

# 3. 브라우저 접속 (포트 번호 없이 접속 가능)
http://<SERVER_IP>/
```
