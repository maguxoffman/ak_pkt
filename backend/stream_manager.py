import asyncio
import json
import random
import time
import os
import numpy as np
from typing import List, Set
from fastapi import WebSocket
from ml_engine import PacketAnomalyDetector
from pcap_parser import generate_benign_packet, generate_anomaly_packet
from server_analyzer import generate_server_analysis_report

class StreamManager:
    """
    StreamManager initialized with clean idle state:
    - Starts with 0 packets and clean '분석 PCAP 업로드 대기 중' source indicator.
    - Resets source filename and model on reset_all_data().
    - Sets current_filename and saved_model_filename ONLY when analysis actually starts.
    """
    def __init__(self):
        self.active_websockets: Set[WebSocket] = set()
        self.is_playing: bool = False
        self.speed: float = 1.0
        self.detector = PacketAnomalyDetector(contamination=0.001)
        
        self.pcap_queue: List[dict] = []
        self.analyzed_history: List[dict] = []
        
        # Currently analyzed source/file indicator & packet count configs (Clean Initial State)
        self.current_filename: str = "분석 PCAP 업로드 대기 중"
        self.total_packets_in_file: int = 0
        self.max_packets_config: int = 0
        self.warmup_count: int = 0
        self.analysis_target_count: int = 0
        self.is_pcap_session: bool = False
        
        # Persistence memory for trained model and PCAP paths
        self.last_trained_pcap_path: str = ""
        self.last_trained_filename: str = ""
        self.saved_model_filename: str = "선택 안됨"
        self.saved_model_path: str = ""

        # Statistics for Inspection Phase only
        self.total_packets: int = 0
        self.anomalies_01_count: int = 0
        self.max_score: float = 0.0
        self.ip_anomalies = {}
        self.protocol_counts = {"TCP": 0, "UDP": 0, "HTTPS": 0, "DNS": 0, "OTHER": 0}

    def reset_all_data(self):
        """Clear all packet statistics, history, currently inspecting source filename, and model name."""
        self.total_packets = 0
        self.anomalies_01_count = 0
        self.max_score = 0.0
        self.ip_anomalies.clear()
        self.protocol_counts = {"TCP": 0, "UDP": 0, "HTTPS": 0, "DNS": 0, "OTHER": 0}
        self.detector.history_scores.clear()
        self.analyzed_history.clear()
        self.pcap_queue.clear()
        self.is_playing = False
        self.is_pcap_session = False
        
        # Reset inspecting source and model to clean idle state
        self.current_filename = "분석 PCAP 업로드 대기 중"
        self.saved_model_filename = "선택 안됨"
        self.analysis_target_count = 0
        self.total_packets_in_file = 0
        print("[StreamManager] All statistics, inspecting source filename, and model name cleanly reset.")

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_websockets.add(websocket)
        await websocket.send_text(json.dumps({
            "type": "INITIAL_STATE",
            "stats": self.get_stats(),
            "is_playing": self.is_playing,
            "speed": self.speed,
            "threshold": self.detector.score_threshold
        }))

    def disconnect(self, websocket: WebSocket):
        self.active_websockets.remove(websocket)

    def set_playing(self, playing: bool):
        if playing and self.is_pcap_session and self.total_packets >= self.analysis_target_count:
            if hasattr(self, 'saved_inspection_packets') and self.saved_inspection_packets:
                self.pcap_queue = list(self.saved_inspection_packets)
                self.total_packets = 0
                self.anomalies_01_count = 0
                self.analyzed_history.clear()

        self.is_playing = playing

    def set_speed(self, speed: float):
        self.speed = max(0.1, min(20.0, speed))

    def calibrate_session_threshold(self, packets: List[dict]):
        """Recalibrate 99.9th percentile threshold on active session packets to guarantee 0.1% cutoff."""
        if not packets or not self.detector.is_fitted:
            return
        
        try:
            X = np.array([self.detector.extract_features(p) for p in packets])
            X_scaled = self.detector.scaler.transform(X)
            raw_scores = -self.detector.model.score_samples(X_scaled)
            calibrated_threshold = float(np.percentile(raw_scores, 99.9))
            
            self.detector.score_threshold = max(self.detector.score_threshold, calibrated_threshold)
            print(f"[StreamManager] Calibrated 99.9% session threshold: {self.detector.score_threshold:.4f}")
        except Exception as e:
            print(f"[StreamManager Calibration Error] {e}")

    def learn_feedback_ip(self, ip: str):
        """Register IP as approved server & retrain ML model."""
        self.detector.add_approved_encrypted_ip(ip)
        if hasattr(self, 'saved_warmup_packets') and self.saved_warmup_packets:
            self.detector.fit(self.saved_warmup_packets)
            if self.saved_model_filename and self.saved_model_filename != "선택 안됨":
                self.detector.save_trained_model(self.saved_model_filename)

        new_anomalies = 0
        for pkt in self.analyzed_history:
            res = self.detector.predict_one(pkt)
            pkt.update(res)
            if pkt.get("is_anomaly_01"):
                new_anomalies += 1

        self.anomalies_01_count = new_anomalies
        print(f"[StreamManager] Active learning feedback applied for IP '{ip}'. Re-evaluated anomalies: {new_anomalies}")

    def inject_attack(self, attack_type: str = None) -> dict:
        """Forcefully inject an anomalous attack packet."""
        pkt = generate_anomaly_packet(attack_type)
        res = self.detector.predict_one(pkt)
        pkt.update(res)
        self._update_stats(pkt)
        return pkt

    def _update_stats(self, pkt: dict):
        self.total_packets += 1
        self.analyzed_history.append(pkt)

        proto = pkt.get("protocol", "OTHER")
        self.protocol_counts[proto] = self.protocol_counts.get(proto, 0) + 1

        if pkt.get("score", 0.0) > self.max_score:
            self.max_score = pkt.get("score", 0.0)

        if pkt.get("is_anomaly_01"):
            self.anomalies_01_count += 1
            src_ip = pkt.get("src_ip", "Unknown")
            self.ip_anomalies[src_ip] = self.ip_anomalies.get(src_ip, 0) + 1

    def get_stats(self) -> dict:
        return {
            "total_packets": self.total_packets,
            "anomalies_01_count": self.anomalies_01_count,
            "max_score": round(self.max_score, 4),
            "threshold": round(self.detector.score_threshold, 4),
            "current_filename": self.current_filename,
            "total_packets_in_file": self.total_packets_in_file,
            "max_packets_config": self.max_packets_config,
            "warmup_count": self.warmup_count,
            "analysis_target_count": self.analysis_target_count,
            "pcap_queue_left": len(self.pcap_queue),
            "is_pcap_session": self.is_pcap_session,
            "saved_model_filename": self.saved_model_filename,
            "last_trained_filename": self.last_trained_filename,
            "approved_encrypted_ips": list(self.detector.approved_encrypted_ips),
            "top_suspicious_ips": sorted(self.ip_anomalies.items(), key=lambda x: x[1], reverse=True)[:5],
            "protocol_counts": self.protocol_counts
        }

    def get_server_report(self) -> dict:
        """Generate server profile report from analyzed packet history."""
        return generate_server_analysis_report(self.analyzed_history, self.total_packets_in_file, self.analysis_target_count, self.warmup_count)

    async def broadcast_packet(self, pkt: dict):
        if not self.active_websockets:
            return
        payload = json.dumps({
            "type": "PACKET_EVENT",
            "packet": pkt,
            "stats": self.get_stats(),
            "is_playing": self.is_playing
        })
        disconnected = set()
        for ws in self.active_websockets:
            try:
                await ws.send_text(payload)
            except Exception:
                disconnected.add(ws)
        for ws in disconnected:
            self.active_websockets.remove(ws)

    async def stream_loop(self):
        """Background continuous stream producer loop."""
        while True:
            if self.is_playing and self.is_pcap_session:
                if self.total_packets >= self.analysis_target_count or not self.pcap_queue:
                    print(f"[StreamManager] Inspection Stream Completed ({self.total_packets}/{self.analysis_target_count}). Stopping stream.")
                    self.is_playing = False
                    await self.broadcast_packet({})
                    await asyncio.sleep(0.1)
                    continue

                pkt = self.pcap_queue.pop(0)
                result = self.detector.predict_one(pkt)
                pkt.update(result)
                self._update_stats(pkt)

                await self.broadcast_packet(pkt)

            sleep_time = max(0.01, 0.1 / self.speed)
            await asyncio.sleep(sleep_time)

stream_manager = StreamManager()
