import asyncio
import os
import tempfile
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, UploadFile, File, HTTPException, Form
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List

from stream_manager import stream_manager
from pcap_parser import parse_pcap_range, preview_pcap_info
from ml_engine import PacketAnomalyDetector

# Dynamic PCAP Storage Directory Path
PCAP_DIR = os.environ.get("PCAP_DIR", "")
if not PCAP_DIR:
    candidates = [
        "/var/ai_pkt/PCAP",
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "PCAP"),
        "/PCAP"
    ]
    for cand in candidates:
        if os.path.exists(cand):
            PCAP_DIR = os.path.abspath(cand)
            break
    if not PCAP_DIR:
        PCAP_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "PCAP")
        os.makedirs(PCAP_DIR, exist_ok=True)

app = FastAPI(
    title="AI Network Packet Anomaly Guard",
    version="2.4.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class StreamControlRequest(BaseModel):
    action: str
    speed: Optional[float] = 1.0

class InjectAttackRequest(BaseModel):
    attack_type: Optional[str] = None

class PcapInfoRequest(BaseModel):
    pcap_filename: str

class TrainModelRequest(BaseModel):
    pcap_filename: str
    custom_model_name: Optional[str] = "learning_model_1"
    from_pkt: Optional[int] = 1
    to_pkt: Optional[int] = 1000

class AnalyzePcapRequest(BaseModel):
    pcap_filename: str
    model_filename: str
    from_pkt: Optional[int] = 1
    to_pkt: Optional[int] = 2500

class FeedbackLearnRequest(BaseModel):
    ip: str
    label: Optional[str] = "approved_server"

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(stream_manager.stream_loop())
    print(f"[FastAPI] Packet stream producer started. PCAP Storage Dir: {PCAP_DIR}")

@app.get("/")
@app.head("/")
def root_check():
    return {"status": "ok", "service": "AI Packet Anomaly Guard"}

@app.get("/health")
@app.head("/health")
def health_check():
    return {"status": "ok", "service": "AI Packet Anomaly Guard"}

@app.get("/api/stats")
def get_stats():
    return stream_manager.get_stats()

@app.get("/api/server-report")
def get_server_report():
    return stream_manager.get_server_report()

@app.get("/api/models")
def get_learning_models():
    """List all trained model .pkl files stored in /DATA.TRAIN directory."""
    models = PacketAnomalyDetector.list_saved_models()
    return {
        "status": "ok",
        "count": len(models),
        "DATA.TRAIN_dir": "/DATA.TRAIN",
        "models": models
    }

@app.get("/api/model-details/{model_filename}")
def get_model_details(model_filename: str):
    """Get complete threshold calibration metrics and feature vector statistics for a specific model."""
    details = PacketAnomalyDetector.get_model_details(model_filename)
    if "error" in details:
        raise HTTPException(status_code=404, detail=details["error"])
    return details

@app.get("/api/pcap-files")
def get_pcap_files():
    """List all .pcap, .pcapng, .cap files stored in /PCAP directory."""
    pcap_files = []
    if os.path.exists(PCAP_DIR):
        for f in sorted(os.listdir(PCAP_DIR)):
            if f.endswith((".pcap", ".pcapng", ".cap")):
                full_path = os.path.join(PCAP_DIR, f)
                size_mb = round(os.path.getsize(full_path) / (1024 * 1024), 2)
                pcap_files.append({
                    "filename": f,
                    "filepath": full_path,
                    "size_mb": size_mb
                })
    return {
        "status": "ok",
        "count": len(pcap_files),
        "pcap_dir": PCAP_DIR,
        "files": pcap_files
    }

@app.post("/api/pcap-info")
def get_pcap_file_info(req: PcapInfoRequest):
    """Fast preview packet count for a selected file in /PCAP directory."""
    filename = req.pcap_filename.strip()
    filepath = os.path.join(PCAP_DIR, filename)
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail=f"/PCAP 디렉토리에 파일이 존재하지 않습니다: {filename}")
    
    info = preview_pcap_info(filepath)
    info["filename"] = filename
    info["filepath"] = filepath
    return info

@app.post("/api/train-model")
def train_model(req: TrainModelRequest):
    """Train ML model using selected PCAP file in /PCAP directory."""
    pcap_filename = req.pcap_filename.strip()
    filepath = os.path.join(PCAP_DIR, pcap_filename)
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail=f"/PCAP 디렉토리에 파일이 존재하지 않습니다: {pcap_filename}")

    from_pkt = req.from_pkt if (req.from_pkt and req.from_pkt > 0) else 1
    to_pkt = req.to_pkt if (req.to_pkt and req.to_pkt >= from_pkt) else 1000

    model_name = req.custom_model_name.strip() if req.custom_model_name else f"model_{pcap_filename}"
    if not model_name.endswith(".pkl"):
        model_name = f"{model_name}.pkl"

    packets, total_in_file = parse_pcap_range(filepath, start_idx=from_pkt, end_idx=to_pkt)
    if not packets:
        raise HTTPException(status_code=400, detail=f"학습 패킷 범위 [{from_pkt} ~ {to_pkt}] 추출에 실패했습니다.")

    stream_manager.reset_all_data()
    stream_manager.detector.fit(packets)
    
    saved_path = stream_manager.detector.save_trained_model(model_name)
    
    stream_manager.saved_model_filename = model_name
    stream_manager.saved_model_path = saved_path
    stream_manager.last_trained_filename = pcap_filename
    stream_manager.warmup_count = len(packets)

    return {
        "status": "trained_and_saved",
        "message": f"학습 데이터가 /DATA.TRAIN/{model_name} 로 정상 저장되었습니다. (범위: {from_pkt} ~ {to_pkt}번, 총 {len(packets)}개)",
        "model_filename": model_name,
        "saved_model_path": saved_path,
        "from_pkt": from_pkt,
        "to_pkt": to_pkt,
        "train_packet_count": len(packets),
        "total_packets_in_file": total_in_file,
        "score_threshold": stream_manager.detector.score_threshold,
        "stats": stream_manager.get_stats()
    }

@app.post("/api/analyze-pcap")
def analyze_pcap(req: AnalyzePcapRequest):
    """Stream packet analysis using selected PCAP file in /PCAP directory."""
    if not req.model_filename:
        raise HTTPException(status_code=400, detail="/DATA.TRAIN 디렉토리에서 분석에 사용할 학습 모델을 선택해 주세요.")

    loaded_ok = stream_manager.detector.load_trained_model(req.model_filename)
    if not loaded_ok:
        raise HTTPException(status_code=404, detail=f"/DATA.TRAIN 디렉토리에서 모델 '{req.model_filename}'을 로드하지 못했습니다.")

    stream_manager.saved_model_filename = req.model_filename

    pcap_filename = req.pcap_filename.strip()
    filepath = os.path.join(PCAP_DIR, pcap_filename)
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail=f"/PCAP 디렉토리에 분석 PCAP 파일이 존재하지 않습니다: {pcap_filename}")

    from_pkt = req.from_pkt if (req.from_pkt and req.from_pkt > 0) else 1
    to_pkt = req.to_pkt if (req.to_pkt and req.to_pkt >= from_pkt) else 2500

    packets, total_in_file = parse_pcap_range(filepath, start_idx=from_pkt, end_idx=to_pkt)
    if not packets:
        raise HTTPException(status_code=400, detail=f"패킷 범위 [{from_pkt} ~ {to_pkt}] 추출에 실패했습니다.")

    stream_manager.calibrate_session_threshold(packets)

    stream_manager.total_packets = 0
    stream_manager.anomalies_01_count = 0
    stream_manager.analyzed_history.clear()
    stream_manager.saved_inspection_packets = list(packets)
    stream_manager.pcap_queue = list(packets)

    stream_manager.current_filename = f"PCAP: {pcap_filename} (범위: {from_pkt} ~ {to_pkt}번)"
    stream_manager.total_packets_in_file = total_in_file
    stream_manager.analysis_target_count = len(packets)
    stream_manager.is_pcap_session = True

    return {
        "status": "ready_for_analysis",
        "message": f"모델 '{req.model_filename}'으로 파일 [{pcap_filename}] 범위 [{from_pkt} ~ {to_pkt}] 분석 준비 완료.",
        "filename": pcap_filename,
        "from_pkt": from_pkt,
        "to_pkt": to_pkt,
        "analysis_packet_count": len(packets),
        "total_packets_in_file": total_in_file,
        "loaded_model_filename": req.model_filename,
        "score_threshold": stream_manager.detector.score_threshold,
        "stats": stream_manager.get_stats()
    }

@app.post("/api/feedback-learn")
def feedback_learn(req: FeedbackLearnRequest):
    stream_manager.learn_feedback_ip(req.ip)
    return {
        "status": "learned",
        "approved_ip": req.ip,
        "stats": stream_manager.get_stats()
    }

@app.post("/api/control")
def control_stream(req: StreamControlRequest):
    if req.action == "play":
        stream_manager.set_playing(True)
    elif req.action == "pause":
        stream_manager.set_playing(False)
    elif req.action == "set_speed":
        if req.speed:
            stream_manager.set_speed(req.speed)
    elif req.action == "reset":
        stream_manager.reset_all_data()
    return {
        "is_playing": stream_manager.is_playing,
        "speed": stream_manager.speed,
        "stats": stream_manager.get_stats()
    }

@app.post("/api/inject-attack")
async def inject_attack(req: InjectAttackRequest):
    pkt = stream_manager.inject_attack(req.attack_type)
    await stream_manager.broadcast_packet(pkt)
    return {"status": "injected", "packet": pkt}

@app.websocket("/ws/packets")
async def websocket_packets(websocket: WebSocket):
    await stream_manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        stream_manager.disconnect(websocket)
