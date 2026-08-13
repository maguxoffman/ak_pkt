import asyncio
import json
import random
import time
import os
import numpy as np
from typing import List, Set, Dict
from fastapi import WebSocket
from ml_engine import PacketAnomalyDetector, SessionAnomalyDetector
from pcap_parser import generate_benign_packet, generate_anomaly_packet, extract_sessions_from_packets, SessionFlow

class StreamManager:
    """
    StreamManager initialized with clean idle state:
    - Starts with 0 packets and clean '분석 PCAP 업로드 대기 중' source indicator.
    - Resets source filename, model, and session flow tracking on reset_all_data().
    - Real-time live session updates as packets stream in.
    """
    def __init__(self):
        self.active_websockets: Set[WebSocket] = set()
        self.is_playing: bool = False
        self.speed: float = 1.0
        self.detector = PacketAnomalyDetector(contamination=0.001)
        self.session_detector = SessionAnomalyDetector(contamination=0.001)
        
        self.pcap_queue: List[dict] = []
        self.analyzed_history: List[dict] = []
        self.live_sessions_map: Dict[tuple, SessionFlow] = {}
        self.sessions_history: List[dict] = []
        self.session_anomalies_count: int = 0
        
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
        """Clear all packet & session statistics, live session tracking maps, history, and model state."""
        self.total_packets = 0
        self.anomalies_01_count = 0
        self.max_score = 0.0
        self.ip_anomalies.clear()
        self.protocol_counts = {"TCP": 0, "UDP": 0, "HTTPS": 0, "DNS": 0, "OTHER": 0}
        self.detector.history_scores.clear()
        self.analyzed_history.clear()
        
        # Reset Session Flow tracking completely
        self.live_sessions_map.clear()
        self.sessions_history.clear()
        self.session_anomalies_count = 0
        
        self.pcap_queue.clear()
        self.is_playing = False
        self.is_pcap_session = False
        
        # Reset inspecting source and model to clean idle state
        self.current_filename = "분석 PCAP 업로드 대기 중"
        self.saved_model_filename = "선택 안됨"
        self.analysis_target_count = 0
        self.total_packets_in_file = 0
        print("[StreamManager] All packet & 5-Tuple session statistics cleanly reset.")

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_websockets.add(websocket)
        await websocket.send_text(json.dumps({
            "type": "INITIAL_STATE",
            "stats": self.get_stats(),
            "sessions": self.sessions_history,
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

        scores = []
        for p in packets:
            X = np.array([self.detector.extract_features(p)])
            X_scaled = self.detector.scaler.transform(X)
            score = float(-self.detector.model.score_samples(X_scaled)[0])
            scores.append(score)

        new_thresh = float(np.percentile(scores, 99.9))
        self.detector.score_threshold = round(new_thresh, 4)
        print(f"[StreamManager Calibrate] Dynamic 99.9% threshold set to: {self.detector.score_threshold:.4f} across {len(packets)} packets.")

    def update_live_session(self, packet: dict):
        """
        Dynamically update 5-Tuple Session Flow in real-time as each streaming packet arrives.
        """
        s_ip = packet.get("src_ip", "0.0.0.0")
        s_port = packet.get("src_port", 0)
        d_ip = packet.get("dst_ip", "0.0.0.0")
        d_port = packet.get("dst_port", 0)
        proto = packet.get("protocol", "OTHER")

        # Canonical key: normalize flow direction so A->B and B->A share the same Session
        if (s_ip, s_port) < (d_ip, d_port):
            canonical_key = (s_ip, s_port, d_ip, d_port, proto)
        else:
            canonical_key = (d_ip, d_port, s_ip, s_port, proto)

        if canonical_key not in self.live_sessions_map:
            session_id = len(self.live_sessions_map) + 1
            flow = SessionFlow(session_id, canonical_key, packet)
            self.live_sessions_map[canonical_key] = flow
        else:
            flow = self.live_sessions_map[canonical_key]
            pkt_t = packet.get("timestamp", time.time())
            if pkt_t - flow.last_time > 30.0:
                flow.state = "TIMED_OUT"
                session_id = len(self.live_sessions_map) + 1
                flow = SessionFlow(session_id, canonical_key, packet)
                self.live_sessions_map[canonical_key] = flow
            else:
                flow.update(packet)

        # Predict session score using Session ML Detector
        s_dict = flow.to_dict()
        res = self.session_detector.predict_one(s_dict)
        s_dict["score"] = res["score"]
        s_dict["is_anomaly_01"] = res["is_anomaly_01"]
        s_dict["threshold"] = res["threshold"]
        s_dict["explanation"] = res["explanation"]

        # Sync to sessions_history list
        existing_idx = next((i for i, s in enumerate(self.sessions_history) if s["session_id"] == flow.session_id), -1)
        if existing_idx >= 0:
            self.sessions_history[existing_idx] = s_dict
        else:
            self.sessions_history.append(s_dict)

        self.session_anomalies_count = len([s for s in self.sessions_history if s.get("is_anomaly_01")])

    def load_pcap_range(self, packets: List[dict], total_in_file: int, filename: str):
        """
        Load packets from PCAP file for inspection and reset/initialize 5-Tuple Network Sessions.
        """
        self.reset_all_data()

        self.saved_inspection_packets = list(packets)
        self.pcap_queue = list(packets)
        self.total_packets_in_file = total_in_file
        self.current_filename = filename
        self.analysis_target_count = len(packets)
        self.is_pcap_session = True

        if self.detector.is_fitted and packets:
            self.calibrate_session_threshold(packets)

        # Pre-fit Session Anomaly Detector using initial PCAP batch
        sessions = extract_sessions_from_packets(packets)
        if sessions:
            self.session_detector.fit(sessions)

        print(f"[StreamManager] Reset & Loaded {len(packets)} packets from '{filename}' for inspection & live session tracking.")

    async def broadcast_packet(self, packet: dict):
        self.total_packets += 1
        proto = packet.get("protocol", "OTHER")
        if proto in self.protocol_counts:
            self.protocol_counts[proto] += 1
        else:
            self.protocol_counts["OTHER"] += 1

        result = self.detector.predict_one(packet)
        score = result["score"]
        is_anomaly_01 = result["is_anomaly_01"]

        packet["score"] = score
        packet["is_anomaly_01"] = is_anomaly_01
        packet["threshold"] = result["threshold"]
        packet["explanation"] = result["explanation"]
        packet["metric_comparison"] = result.get("metric_comparison", [])

        if score > self.max_score:
            self.max_score = score

        if is_anomaly_01:
            self.anomalies_01_count += 1
            src_ip = packet.get("src_ip", "unknown")
            self.ip_anomalies[src_ip] = self.ip_anomalies.get(src_ip, 0) + 1

        self.analyzed_history.append(packet)

        # Real-Time Session Update
        self.update_live_session(packet)

        msg = json.dumps({
            "type": "PACKET_EVENT",
            "packet": packet,
            "stats": self.get_stats(),
            "sessions": self.sessions_history,
            "is_playing": self.is_playing
        })

        disconnected = set()
        for ws in self.active_websockets:
            try:
                await ws.send_text(msg)
            except Exception:
                disconnected.add(ws)

        for ws in disconnected:
            self.active_websockets.remove(ws)

    def get_stats(self) -> dict:
        top_ips = sorted(self.ip_anomalies.items(), key=lambda x: x[1], reverse=True)[:5]
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
            "saved_model_filename": self.saved_model_filename,
            "approved_encrypted_ips": list(self.detector.approved_encrypted_ips),
            "top_suspicious_ips": top_ips,
            "protocol_counts": self.protocol_counts,
            "session_stats": {
                "total_sessions": len(self.sessions_history),
                "session_anomalies_count": self.session_anomalies_count,
                "active_sessions_count": len([s for s in self.sessions_history if s.get("state") == "ACTIVE"]),
                "closed_sessions_count": len([s for s in self.sessions_history if s.get("state") in ("CLOSED_FIN", "CLOSED_RST", "TIMED_OUT")])
            }
        }

    async def start_streaming_loop(self):
        packet_counter = 0
        while True:
            try:
                if self.is_playing:
                    if self.is_pcap_session:
                        if self.pcap_queue:
                            pkt = self.pcap_queue.pop(0)
                            await self.broadcast_packet(pkt)
                            
                            if self.total_packets >= self.analysis_target_count:
                                self.is_playing = False
                                print(f"[StreamManager] Reached end of PCAP inspection range ({self.analysis_target_count} packets). Paused.")
                        else:
                            self.is_playing = False
                    else:
                        packet_counter += 1
                        if random.random() < 0.001:
                            pkt = generate_anomaly_packet(packet_counter)
                        else:
                            pkt = generate_benign_packet(packet_counter)
                        await self.broadcast_packet(pkt)

                sleep_time = max(0.01, 0.2 / self.speed)
                await asyncio.sleep(sleep_time)

            except Exception as e:
                print(f"[StreamManager Loop Exception] {e}")
                await asyncio.sleep(0.5)

stream_manager = StreamManager()
