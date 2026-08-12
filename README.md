# 🚀 AI Packet Anomaly Guard (v2.8 - 10-Feature Vector Architecture)

**AI Packet Anomaly Guard**는 대용량 네트워크 패킷(PCAP 파일)의 패킷 크기(Size), 전송 속도(Speed), 패킷 변동성(Variance), TCP SYN 플래그 및 **TCP/서비스 응답시간(RTT Response Time)**을 **10대 특성 벡터(10-Feature Vector)**로 추출하여, **비지도학습(Unsupervised Learning) 머신러닝 알고리즘(Isolation Forest)**을 적용해 **상위 0.1% 미세 이상치 패킷을 실시간 탐지 및 원인 진단**하는 전문 보안 시스템입니다.

---

## 💡 주요 핵심 기능 및 시스템 구조

### 1. 🔒 암호 해독 없는 10대 수치 특성 추출 (10-Feature Vector Architecture)
암호화 트래픽(HTTPS/TLS, VPN)을 무리하게 해독하거나 페이로드를 검사하지 않고 수치 특성만을 추출합니다:
1. `length`: 패킷 전체 바이트 크기 (Bytes)
2. `payload_len`: 순수 L4 페이로드 크기 (Bytes)
3. `packet_rate_pps`: 초당 패킷 수 (PPS, 1.0초 슬라이딩 윈도우)
4. `byte_rate_bps`: 초당 대역폭 사용량 (BPS, 1.0초 슬라이딩 윈도우)
5. `delta_time_ms`: 동일 IP 수신 도착 간격 (ms)
6. `size_velocity_ratio`: 순간 패킷 크기 대비 속도 폭주 비율 (`length / (delta_ms + 0.01)`)
7. `pps_variance`: 초당 패킷 변동성/분산 (속도 튐 패턴 탐지)
8. `tcp_syn_flag`: TCP SYN 연결 요청 플래그 (SYN Flood 및 포트 스캔 탐지)
9. `rtt_ms`: **TCP 3-Way Handshake 및 요청-응답 지연시간 (RTT ms)** ⏱️
10. `is_approved`: 사용자 피드백 정상 예외 서버 승인 등록 여부 (`1.0` / `0.0`)

### 2. 🌲 머신러닝 이상 탐지 알고리즘 (Isolation Forest & 99.9% Dynamic Cutoff)
- **비지도학습(Isolation Forest)**: 정상적인 데이터 밀집 구역에 모인 패킷과 달리 크기, 속도, 응답시간이 비정상적인 트래픽은 트리의 몇 번의 분할(Split)만으로 빠르게 고립되는 원리를 활용하여 제로데이(Zero-day) 벼락 트래픽을 100% 탐지.
- **99.9% 커트라인 보정 (Dynamic Cutoff Calibration)**: 학습 데이터의 점수 분포 중 **정확히 상위 0.1% 지점(99.9th Percentile)의 경계 점수를 Cutoff(예: 0.7902)**로 자동 보정.

### 3. 📂 `/PCAP` 디렉토리 파싱 & `/DATA.TRAIN` 모델 관리
- 파일 웹 업로드 시 발생하는 네트워크 전송 지연을 제거하고, 서버 내부 `/PCAP` 디렉토리에 전송된 대용량 PCAP 파일(`hanyang.pcap`, `MAGUX_dump_57.pcap` 등)을 C-Speed 바이너리 핑거프린트 엔진으로 즉시 스캔.
- 학습 결과 모델은 `/DATA.TRAIN/*.pkl` 파일로 영구 보관되며 `🔍 10대 임계치 보기` 모달을 통해 지표별 평균/최대/컷오프 상한선을 정밀 확인 가능.

### 4. 📖 3-SubTab 도움말 센터 모달
- **`[📖 사용법]`**: 훈련 및 4단계 순차 분석 프로세스 가이드
- **`[📊 규격]`**: 프로젝트 PCAP 정보, 10-Feature 명세, AI 진단 규칙
- **`[💡 적용기술]`**: Isolation Forest, 99.9% 컷오프, 능동 피드백 및 10대 피처 아키텍처 기술 설명서

---

## 🖥️ 시스템 구성 및 디렉토리 구조

```text
ai_pkt/
├── backend/
│   ├── main.py              # FastAPI REST API & WebSocket 실시간 스트리밍 서버 (Port 8000)
│   ├── ml_engine.py         # Isolation Forest 10-Feature Vector 엔진 및 임계치 도출
│   ├── pcap_parser.py       # C-Speed 바이너리 핑거프린트 PCAP 파서 및 RTT 응답시간 추출
│   └── requirements.txt     # 백엔드 의존성 (fastapi, scikit-learn, scapy, numpy)
├── frontend/
│   └── index.html           # React 18 & Chart.js 실시간 대시보드 UI (Port 3000)
├── deploy/
│   ├── install_rocky94.sh    # Rocky Linux 9.4 1-Click 자동 설치 스크립트
│   ├── ai-pkt-backend.service# Systemd 백엔드 서비스 파일
│   ├── ai-pkt-frontend.service# Systemd 프론트엔드 서비스 파일
│   └── README_ROCKY94.md    # Rocky Linux 9.4 배포 및 운용 상세 문서
├── DATA.TRAIN/              # 생성된 Isolation Forest .pkl 학습 모델 저장소
└── PCAP/                    # 분석 및 학습 대상 대용량 .pcap 패킷 파일 저장소
```

---

## 🌐 서버 운영 및 배포 정보 (`172.20.20.98`)

- **운영 OS**: Rocky Linux 9.4 (Blue Onyx x86_64)
- **서버 설치 경로**: `/var/ai_pkt`
- **웹 대시보드 URL**: `http://172.20.20.98:3000`
- **백엔드 REST API URL**: `http://172.20.20.98:8000`
- **WebSocket 채널**: `ws://172.20.20.98:8000/ws/packets`

---

## 🚀 빠른 사용 가이드

1. 브라우저에서 `http://172.20.20.98:3000` 접속 (강력 새로고침 `Ctrl + F5`)
2. **`[1. 학습하기]`** 카테고리 ➔ **`+ 신규 학습 진행하기`** 클릭 후 `/PCAP` 디렉토리의 패킷을 지정하여 10-Feature 모델 생성.
3. **`[2. 분석하기]`** 카테고리에서 1단계 PCAP 선택 ➔ 2단계 범위 지정 ➔ 3단계 모델 선택 ➔ 4단계 **`▶ 분석 시작하기`** 실행.
4. **`🔴 Top 0.1% Anomaly Stream`**에서 99.9% 컷오프를 이탈한 이상 패킷과 RTT 지연 원인을 확인하고, 필요 시 **`🎓 정상 서버로 AI 학습`**을 적용하여 예외 교정.
