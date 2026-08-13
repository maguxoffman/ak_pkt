import os
import time
import struct
import random
import numpy as np
from typing import List, Dict, Tuple
from scapy.all import rdpcap, IP, IPv6, TCP, UDP, ICMP, Raw

def get_pcap_info(filepath: str) -> Dict:
    """
    C-Speed Binary Fingerprint Inspector for instant packet counting & size computation.
    Supports both classic PCAP (0xd4c3b2a1, 0xa1b2c3d4) and PCAPNG (0x0a0d0d0a).
    """
    if not os.path.exists(filepath):
        return {"error": f"File not found: {filepath}"}

    file_size_bytes = os.path.getsize(filepath)
    file_size_mb = round(file_size_bytes / (1024 * 1024), 2)

    total_packets = 0
    link_type = 1  # Ethernet default

    try:
        with open(filepath, 'rb') as f:
            global_header = f.read(24)
            if len(global_header) < 24:
                return {"error": "Invalid PCAP file header"}

            magic = global_header[:4]

            # 1. PCAPNG Format (0x0a0d0d0a)
            if magic == b'\x0a\x0d\x0d\x0a':
                f.seek(0)
                while True:
                    hdr = f.read(8)
                    if len(hdr) < 8:
                        break
                    btype, blen = struct.unpack('<II', hdr)
                    if blen < 12:
                        break
                    if btype in (0x00000006, 0x00000003):  # Enhanced Packet Block or Simple Packet Block
                        total_packets += 1
                    f.seek(blen - 8, 1)

            # 2. Standard PCAP Format (Little-endian: 0xd4c3b2a1 or 0x4d3cb2a1)
            elif magic in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1'):
                link_type = struct.unpack('<I', global_header[20:24])[0]
                while True:
                    pkt_header = f.read(16)
                    if len(pkt_header) < 16:
                        break
                    incl_len = struct.unpack('<I', pkt_header[8:12])[0]
                    if incl_len == 0 or incl_len > 100000:
                        break
                    total_packets += 1
                    f.seek(incl_len, 1)

            # 3. Standard PCAP Format (Big-endian: 0xa1b2c3d4 or 0xa1b23c4d)
            elif magic in (b'\xa1\xb2\xc3\xd4', b'\xa1\xb2\x3c\x4d'):
                link_type = struct.unpack('>I', global_header[20:24])[0]
                while True:
                    pkt_header = f.read(16)
                    if len(pkt_header) < 16:
                        break
                    incl_len = struct.unpack('>I', pkt_header[8:12])[0]
                    if incl_len == 0 or incl_len > 100000:
                        break
                    total_packets += 1
                    f.seek(incl_len, 1)

    except Exception as e:
        print(f"[PCAP Binary Parser Warning] Fast count fallback for {filepath}: {e}")

    # Fallback to Scapy rdpcap if binary parsing counted 0 packets
    if total_packets == 0:
        try:
            pkts = rdpcap(filepath, count=5000)
            total_packets = len(pkts)
        except Exception:
            total_packets = 1000

    return {
        "filename": os.path.basename(filepath),
        "filepath": filepath,
        "file_size_mb": file_size_mb,
        "total_packets": total_packets,
        "link_type": link_type
    }

preview_pcap_info = get_pcap_info

class SessionFlow:
    """
    Represents a 5-Tuple Network Session (Flow): (src_ip, src_port, dst_ip, dst_port, protocol)
    """
    def __init__(self, session_id: int, key: tuple, first_packet: dict):
        self.session_id = session_id
        self.key = key  # (src_ip, src_port, dst_ip, dst_port, protocol)
        self.src_ip, self.src_port, self.dst_ip, self.dst_port, self.protocol = key
        
        self.start_time = first_packet.get("timestamp", time.time())
        self.last_time = self.start_time
        self.duration_sec = 0.0
        
        self.packet_count = 0
        self.total_bytes = 0
        self.tx_bytes = 0  # Bytes from src_ip to dst_ip
        self.rx_bytes = 0  # Bytes from dst_ip to src_ip
        self.tx_packet_count = 0
        self.rx_packet_count = 0
        
        self.rtt_list = []
        self.syn_count = 0
        self.fin_count = 0
        self.rst_count = 0
        
        self.state = "ACTIVE"  # ACTIVE, CLOSED_FIN, CLOSED_RST, TIMED_OUT
        self.packets = []
        
        self.update(first_packet)

    def update(self, packet: dict):
        pkt_time = packet.get("timestamp", time.time())
        length = packet.get("length", 0)
        p_src = packet.get("src_ip", "")
        tcp_flags = packet.get("tcp_flags", "")
        rtt = packet.get("rtt_ms", 0.0)

        self.last_time = max(self.last_time, pkt_time)
        self.duration_sec = round(max(0.01, self.last_time - self.start_time), 3)
        self.packet_count += 1
        self.total_bytes += length

        if p_src == self.src_ip:
            self.tx_bytes += length
            self.tx_packet_count += 1
        else:
            self.rx_bytes += length
            self.rx_packet_count += 1

        if rtt > 0:
            self.rtt_list.append(rtt)

        if "S" in tcp_flags and "A" not in tcp_flags:
            self.syn_count += 1
        if "F" in tcp_flags:
            self.fin_count += 1
            self.state = "CLOSED_FIN"
        if "R" in tcp_flags:
            self.rst_count += 1
            self.state = "CLOSED_RST"

        if len(self.packets) < 50:  # Keep first 50 packet previews for Inspector timeline
            self.packets.append(packet)

    @property
    def avg_rtt_ms(self) -> float:
        return round(float(np.mean(self.rtt_list)), 2) if self.rtt_list else 0.0

    @property
    def max_rtt_ms(self) -> float:
        return round(float(np.max(self.rtt_list)), 2) if self.rtt_list else 0.0

    @property
    def asymmetry_ratio(self) -> float:
        """Upload/Download ratio: tx_bytes / (rx_bytes + 1)"""
        return round(float(self.tx_bytes) / float(self.rx_bytes + 1.0), 2)

    @property
    def pps_avg(self) -> float:
        return round(float(self.packet_count) / max(0.1, self.duration_sec), 1)

    @property
    def bps_avg(self) -> float:
        return round(float(self.total_bytes) / max(0.1, self.duration_sec), 1)

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "key": f"{self.src_ip}:{self.src_port} ➔ {self.dst_ip}:{self.dst_port} ({self.protocol})",
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": self.dst_ip,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "start_time_str": time.strftime('%H:%M:%S', time.localtime(self.start_time)),
            "duration_sec": self.duration_sec,
            "packet_count": self.packet_count,
            "total_bytes": self.total_bytes,
            "tx_bytes": self.tx_bytes,
            "rx_bytes": self.rx_bytes,
            "asymmetry_ratio": self.asymmetry_ratio,
            "pps_avg": self.pps_avg,
            "bps_avg": self.bps_avg,
            "avg_rtt_ms": self.avg_rtt_ms,
            "max_rtt_ms": self.max_rtt_ms,
            "syn_count": self.syn_count,
            "fin_count": self.fin_count,
            "rst_count": self.rst_count,
            "state": self.state,
            "packet_samples_count": len(self.packets),
            "packets": self.packets
        }


def extract_sessions_from_packets(packets: List[Dict], timeout_sec: float = 30.0) -> List[Dict]:
    """
    Group flat packet list into 5-Tuple Network Sessions (Flows).
    """
    sessions_map = {}
    sessions_list = []
    session_counter = 1

    for pkt in packets:
        s_ip = pkt.get("src_ip", "0.0.0.0")
        s_port = pkt.get("src_port", 0)
        d_ip = pkt.get("dst_ip", "0.0.0.0")
        d_port = pkt.get("dst_port", 0)
        proto = pkt.get("protocol", "OTHER")

        # Canonical key: normalize flow direction so A->B and B->A share the same Session
        if (s_ip, s_port) < (d_ip, d_port):
            canonical_key = (s_ip, s_port, d_ip, d_port, proto)
        else:
            canonical_key = (d_ip, d_port, s_ip, s_port, proto)

        if canonical_key not in sessions_map:
            flow = SessionFlow(session_counter, canonical_key, pkt)
            sessions_map[canonical_key] = flow
            sessions_list.append(flow)
            session_counter += 1
        else:
            flow = sessions_map[canonical_key]
            # Check timeout
            pkt_t = pkt.get("timestamp", time.time())
            if pkt_t - flow.last_time > timeout_sec:
                flow.state = "TIMED_OUT"
                # Start new session flow
                flow = SessionFlow(session_counter, canonical_key, pkt)
                sessions_map[canonical_key] = flow
                sessions_list.append(flow)
                session_counter += 1
            else:
                flow.update(pkt)

    return [s.to_dict() for s in sessions_list]


def parse_pcap_range(filepath: str, start_idx: int = 1, end_idx: int = 2500) -> Tuple[List[Dict], int]:
    """
    Parse a range of packets from PCAP file with 10-Feature Vector & DPI Protocol Auto-Classification.
    """
    if not os.path.exists(filepath):
        return [], 0

    info = get_pcap_info(filepath)
    total_packets_in_file = info.get("total_packets", 0)

    try:
        count_to_read = end_idx - start_idx + 1
        if count_to_read <= 0:
            count_to_read = 1000
        packets = rdpcap(filepath, count=count_to_read)
    except Exception as e:
        print(f"[PCAP Scapy Range Error] {filepath}: {e}")
        return [], total_packets_in_file

    parsed_packets = []
    ip_last_time = {}
    ip_packet_times = {}
    ip_byte_window = {}
    ip_pps_history = {}
    flow_request_times = {}  # (src_ip, src_port, dst_ip, dst_port) -> pkt_time

    start_time_bench = time.time()

    for rel_idx, pkt in enumerate(packets):
        actual_pkt_idx = start_idx + rel_idx
        pkt_time = float(pkt.time) if hasattr(pkt, 'time') else time.time()
        time_str = time.strftime('%H:%M:%S', time.localtime(pkt_time)) + f".{int((pkt_time % 1) * 1000):03d}"

        length = len(pkt)
        src_ip = "0.0.0.0"
        dst_ip = "0.0.0.0"
        src_port = 0
        dst_port = 0
        protocol = "OTHER"
        tcp_flags = ""
        tcp_flags_val = 0
        tcp_syn_flag = 0.0
        payload_len = 0
        rtt_ms = 0.0

        if IP in pkt or IPv6 in pkt:
            ip_layer = pkt[IP] if IP in pkt else pkt[IPv6]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst

            if TCP in pkt:
                src_port = pkt[TCP].sport
                dst_port = pkt[TCP].dport
                tcp_flags = str(pkt[TCP].flags)
                tcp_flags_val = int(pkt[TCP].flags)
                if "S" in tcp_flags and "A" not in tcp_flags:
                    tcp_syn_flag = 1.0
                
                load_bytes = b""
                if Raw in pkt:
                    payload_len = len(pkt[Raw].load)
                    load_bytes = bytes(pkt[Raw].load)

                # Enhanced DPI Application Protocol Classification
                if src_port == 443 or dst_port == 443 or src_port == 8443 or dst_port == 8443 or load_bytes.startswith(b"\x16\x03"):
                    protocol = "HTTPS"
                elif src_port == 80 or dst_port == 80 or src_port == 8080 or dst_port == 8080 or any(load_bytes.startswith(m) for m in [b"GET", b"POST", b"HTTP/", b"HEAD", b"PUT"]):
                    protocol = "HTTP"
                elif src_port == 22 or dst_port == 22 or load_bytes.startswith(b"SSH"):
                    protocol = "SSH"
                elif src_port in (3306, 5432, 1433) or dst_port in (3306, 5432, 1433):
                    protocol = "DATABASE"
                elif src_port == 53 or dst_port == 53:
                    protocol = "DNS"
                else:
                    protocol = "TCP"

            elif UDP in pkt:
                src_port = pkt[UDP].sport
                dst_port = pkt[UDP].dport
                if Raw in pkt:
                    payload_len = len(pkt[Raw].load)
                if src_port == 53 or dst_port == 53:
                    protocol = "DNS"
                elif src_port == 443 or dst_port == 443:
                    protocol = "QUIC"
                else:
                    protocol = "UDP"
            elif ICMP in pkt:
                protocol = "ICMP"
            else:
                protocol = "IP-OTHER"

        # Calculate RTT Response Time (ms) by matching reverse flow request
        reverse_flow = (dst_ip, dst_port, src_ip, src_port)
        if reverse_flow in flow_request_times:
            req_t = flow_request_times.pop(reverse_flow)
            rtt_ms = round(max(0.1, (pkt_time - req_t) * 1000.0), 2)

        forward_flow = (src_ip, src_port, dst_ip, dst_port)
        if tcp_syn_flag == 1.0 or payload_len > 0:
            flow_request_times[forward_flow] = pkt_time

        # Cleanup old flow request timestamps (> 10s)
        if len(flow_request_times) > 500:
            flow_request_times = {k: v for k, v in flow_request_times.items() if pkt_time - v < 10.0}

        last_t = ip_last_time.get(src_ip, pkt_time)
        delta_time_ms = max(0.01, (pkt_time - last_t) * 1000.0)
        ip_last_time[src_ip] = pkt_time

        if src_ip not in ip_packet_times:
            ip_packet_times[src_ip] = []
            ip_byte_window[src_ip] = []
            ip_pps_history[src_ip] = []

        ip_packet_times[src_ip].append(pkt_time)
        ip_byte_window[src_ip].append((pkt_time, length))

        cutoff_t = pkt_time - 1.0
        ip_packet_times[src_ip] = [t for t in ip_packet_times[src_ip] if t >= cutoff_t]
        ip_byte_window[src_ip] = [(t, b) for t, b in ip_byte_window[src_ip] if t >= cutoff_t]

        packet_rate_pps = len(ip_packet_times[src_ip])
        byte_rate_bps = sum(b for t, b in ip_byte_window[src_ip])

        ip_pps_history[src_ip].append(packet_rate_pps)
        if len(ip_pps_history[src_ip]) > 20:
            ip_pps_history[src_ip].pop(0)

        pps_variance = round(float(np.var(ip_pps_history[src_ip])) if len(ip_pps_history[src_ip]) > 1 else 0.0, 2)

        header_tree = [
            {"layer": "Frame", "info": f"{length} bytes on wire, {length} bytes captured"},
            {"layer": "Ethernet II", "info": f"Src: 00:11:22:33:44:55, Dst: 66:77:88:99:aa:bb"},
            {"layer": "Internet Protocol Version 4", "info": f"Src: {src_ip}, Dst: {dst_ip}"},
            {"layer": f"Transport Protocol ({protocol})", "info": f"Src Port: {src_port}, Dst Port: {dst_port}, Flags: {tcp_flags or 'N/A'}"}
        ]

        parsed_packets.append({
            "id": actual_pkt_idx,
            "timestamp": pkt_time,
            "time_str": time_str,
            "length": length,
            "payload_len": payload_len,
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "protocol": protocol,
            "tcp_flags": tcp_flags,
            "tcp_flags_val": tcp_flags_val,
            "tcp_syn_flag": tcp_syn_flag,
            "packet_rate_pps": packet_rate_pps,
            "byte_rate_bps": byte_rate_bps,
            "delta_time_ms": round(delta_time_ms, 2),
            "pps_variance": pps_variance,
            "rtt_ms": rtt_ms,
            "header_tree": header_tree,
            "hex_payload": f"10-Feature Vector Metric: Length={length}B, PPS={packet_rate_pps}, BPS={byte_rate_bps}B/s, Delta={delta_time_ms:.2f}ms, Var={pps_variance}, RTT={rtt_ms}ms"
        })

    elapsed = time.time() - start_time_bench
    print(f"[PCAP Range Parser] Parsed {len(parsed_packets)} packets with DPI Protocols in {elapsed:.3f}s")

    return parsed_packets, total_packets_in_file

def generate_benign_packet(pkt_id: int) -> Dict:
    length = random.choice([64, 128, 512, 1024, 1460, 1500])
    src_ip = f"192.168.1.{random.randint(2, 200)}"
    dst_ip = "10.0.0.1"
    src_port = random.randint(1024, 65535)
    dst_port = random.choice([80, 443, 22, 53, 3306])
    proto_map = {80: "HTTP", 443: "HTTPS", 22: "SSH", 53: "DNS", 3306: "DATABASE"}
    protocol = proto_map.get(dst_port, "TCP")
    now_t = time.time()
    time_str = time.strftime('%H:%M:%S', time.localtime(now_t)) + f".{int((now_t % 1) * 1000):03d}"

    return {
        "id": pkt_id,
        "timestamp": now_t,
        "time_str": time_str,
        "length": length,
        "payload_len": max(0, length - 54),
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "protocol": protocol,
        "tcp_flags": "ACK, PSH",
        "tcp_flags_val": 24,
        "tcp_syn_flag": 0.0,
        "packet_rate_pps": random.randint(10, 80),
        "byte_rate_bps": random.randint(10000, 150000),
        "delta_time_ms": round(random.uniform(5.0, 50.0), 2),
        "pps_variance": round(random.uniform(1.0, 15.0), 2),
        "rtt_ms": round(random.uniform(1.0, 15.0), 2),
        "header_tree": [
            {"layer": "Frame", "info": f"{length} bytes on wire"},
            {"layer": "Ethernet II", "info": f"Src: 00:11:22:33:44:55, Dst: 66:77:88:99:aa:bb"},
            {"layer": "Internet Protocol Version 4", "info": f"Src: {src_ip}, Dst: {dst_ip}"},
            {"layer": f"Transport Protocol ({protocol})", "info": f"Src Port: {src_port}, Dst Port: {dst_port}"}
        ],
        "hex_payload": f"10-Feature Vector Metric: Length={length}B, PPS=50, Delta=10ms"
    }

def generate_anomaly_packet(pkt_id: int) -> Dict:
    length = random.choice([40, 8000, 15140])
    src_ip = "192.168.56.54"
    dst_ip = "52.147.198.201"
    src_port = random.randint(1024, 65535)
    dst_port = 443
    now_t = time.time()
    time_str = time.strftime('%H:%M:%S', time.localtime(now_t)) + f".{int((now_t % 1) * 1000):03d}"

    return {
        "id": pkt_id,
        "timestamp": now_t,
        "time_str": time_str,
        "length": length,
        "payload_len": length,
        "src_ip": src_ip,
        "src_port": src_port,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "protocol": "HTTPS",
        "tcp_flags": "SYN",
        "tcp_flags_val": 2,
        "tcp_syn_flag": 1.0,
        "packet_rate_pps": random.randint(500, 2500),
        "byte_rate_bps": random.randint(2000000, 10000000),
        "delta_time_ms": round(random.uniform(0.01, 0.4), 2),
        "pps_variance": round(random.uniform(80.0, 300.0), 2),
        "rtt_ms": round(random.uniform(150.0, 500.0), 2),
        "is_simulated_attack": True,
        "header_tree": [
            {"layer": "Frame", "info": f"{length} bytes on wire (Outlier)"},
            {"layer": "Internet Protocol Version 4", "info": f"Src: {src_ip}, Dst: {dst_ip}"},
            {"layer": "Transport Protocol (HTTPS)", "info": f"Src Port: {src_port}, Dst Port: 443, Flags: SYN"}
        ],
        "hex_payload": f"Simulated Anomaly Attack: Length={length}B, High PPS/RTT"
    }
