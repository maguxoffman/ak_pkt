import os
import asyncio
from typing import Optional, List
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from stream_manager import stream_manager
from pcap_parser import parse_pcap_range, preview_pcap_info, extract_sessions_from_packets
from server_analyzer import generate_server_analysis_report

app = FastAPI(
    title="AI Packet Anomaly Guard API (10-Feature Vector with RTT & 5-Tuple Session Flow)",
    version="2.8"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

PCAP_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "PCAP")

class ControlRequest(BaseModel):
    action: str
    speed: Optional[float] = 1.0

class StreamControlRequest(BaseModel):
    action: str
    speed: Optional[float] = 1.0

class FeedbackLearnRequest(BaseModel):
    ip: str
    label: str = "approved_server"

class PcapInfoRequest(BaseModel):
    pcap_filename: str

class TrainModelRequest(BaseModel):
    pcap_filename: str
    custom_model_name: Optional[str] = None
    from_pkt: Optional[int] = 1
    to_pkt: Optional[int] = 1000

class AnalyzePcapRequest(BaseModel):
    pcap_filename: str
    model_filename: str
    from_pkt: Optional[int] = 1
    to_pkt: Optional[int] = 2500

class InjectAttackRequest(BaseModel):
    attack_type: str = "size_anomaly"

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(stream_manager.start_streaming_loop())
    print("[FastAPI Startup] AI Packet Anomaly Guard (10-Feature + 5-Tuple Session Flow) Started.")

@app.get("/")
def read_root():
    return {
        "status": "online",
        "service": "AI Packet Anomaly Guard API (10-Feature Vector with RTT & 5-Tuple Session Flow)",
        "version": "2.8",
        "pcap_dir": PCAP_DIR,
        "is_fitted": stream_manager.detector.is_fitted,
        "score_threshold": stream_manager.detector.score_threshold
    }

@app.get("/api/stats")
def get_stats():
    return stream_manager.get_stats()

@app.get("/api/server-report")
def get_server_report():
    return generate_server_analysis_report(stream_manager.analyzed_history)

@app.get("/api/models")
def list_trained_models():
    models = stream_manager.detector.list_saved_models()
    return {"status": "ok", "count": len(models), "models": models}

@app.get("/api/model-details/{model_filename}")
def get_model_details(model_filename: str):
    details = stream_manager.detector.get_model_details(model_filename)
    if "error" in details:
        raise HTTPException(status_code=404, detail=details["error"])
    return details

@app.get("/api/sessions")
def get_sessions():
    """Returns extracted 5-Tuple Network Sessions and summary statistics."""
    return {
        "status": "ok",
        "total_sessions": len(stream_manager.sessions_history),
        "session_anomalies_count": stream_manager.session_anomalies_count,
        "score_threshold": stream_manager.session_detector.score_threshold,
        "sessions": stream_manager.sessions_history
    }

@app.get("/api/pcap-files")
def list_pcap_files():
    pcap_files = []
    if os.path.exists(PCAP_DIR):
        for f in os.listdir(PCAP_DIR):
            if f.endswith(".pcap") or f.endswith(".pcapng"):
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

    return {
        "status": "success",
        "message": f"10-Feature 모델 '{model_name}'이 /DATA.TRAIN 에 성공적으로 저장되었습니다.",
        "model_filename": model_name,
        "pcap_filename": pcap_filename,
        "train_packet_count": len(packets),
        "total_packets_in_file": total_in_file,
        "score_threshold": stream_manager.detector.score_threshold
    }

@app.post("/api/analyze-pcap")
def analyze_pcap_range(req: AnalyzePcapRequest):
    pcap_filename = req.pcap_filename.strip()
    filepath = os.path.join(PCAP_DIR, pcap_filename)
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail=f"/PCAP 디렉토리에 분석 PCAP 파일이 존재하지 않습니다: {pcap_filename}")

    if req.model_filename:
        model_name = req.model_filename.strip()
        loaded_ok = stream_manager.detector.load_trained_model(model_name)
        if loaded_ok:
            stream_manager.saved_model_filename = model_name

    from_pkt = req.from_pkt if (req.from_pkt and req.from_pkt > 0) else 1
    to_pkt = req.to_pkt if (req.to_pkt and req.to_pkt >= from_pkt) else 2500

    packets, total_in_file = parse_pcap_range(filepath, start_idx=from_pkt, end_idx=to_pkt)
    if not packets:
        raise HTTPException(status_code=400, detail=f"패킷 범위 [{from_pkt} ~ {to_pkt}] 추출에 실패했습니다.")

    stream_manager.load_pcap_range(packets, total_in_file, pcap_filename)

    return {
        "status": "ready_for_analysis",
        "message": f"모델 '{req.model_filename}'으로 파일 [{pcap_filename}] 범위 [{from_pkt} ~ {to_pkt}] 및 5-Tuple 세션 분석 준비 완료.",
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
    stream_manager.detector.add_approved_encrypted_ip(req.ip)
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

@app.websocket("/ws/packets")
async def websocket_packets(websocket: WebSocket):
    await stream_manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        stream_manager.disconnect(websocket)
