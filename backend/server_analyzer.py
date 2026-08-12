from typing import List, Dict

def generate_server_analysis_report(analyzed_history: List[Dict], total_file_packets: int, target_packets: int, warmup_count: int) -> Dict:
    """
    Generates Server Analysis Report focusing strictly on:
    - Packet Size metrics: average size, max size, total bytes
    - Speed/Rate metrics: max packets per second (PPS), bandwidth throughput (BPS), packet intervals
    (Encryption/Entropy is ignored)
    """
    if not analyzed_history:
        return {
            "summary": {
                "overall_risk": "SAFE",
                "total_servers": 0,
                "total_inspected_packets": 0,
                "anomalies_detected": 0,
                "analysis_focus": "Packet Size & Transmission Speed/Rate"
            },
            "servers": []
        }

    server_stats = {}

    for pkt in analyzed_history:
        src_ip = pkt.get("src_ip", "Unknown")
        if src_ip == "Unknown" or src_ip == "0.0.0.0":
            continue

        if src_ip not in server_stats:
            server_stats[src_ip] = {
                "ip": src_ip,
                "packet_count": 0,
                "total_bytes": 0,
                "max_size": 0,
                "min_size": 999999,
                "sizes": [],
                "protocols": set(),
                "ports": set(),
                "max_pps": 0,
                "max_bps": 0,
                "min_delta_ms": 999999.0,
                "anomaly_count": 0,
                "max_score": 0.0,
                "is_approved": False
            }

        st = server_stats[src_ip]
        st["packet_count"] += 1
        length = pkt.get("length", 0)
        st["total_bytes"] += length
        st["sizes"].append(length)
        
        if length > st["max_size"]:
            st["max_size"] = length
        if length < st["min_size"]:
            st["min_size"] = length

        st["protocols"].add(pkt.get("protocol", "OTHER"))
        if pkt.get("dst_port"):
            st["ports"].add(pkt.get("dst_port"))

        pps = pkt.get("packet_rate_pps", 0)
        bps = pkt.get("byte_rate_bps", 0)
        delta_t = pkt.get("delta_time_ms", 10.0)

        if pps > st["max_pps"]:
            st["max_pps"] = pps
        if bps > st["max_bps"]:
            st["max_bps"] = bps
        if delta_t < st["min_delta_ms"]:
            st["min_delta_ms"] = delta_t

        score = pkt.get("score", 0.0)
        if score > st["max_score"]:
            st["max_score"] = score

        if pkt.get("is_anomaly_01"):
            st["anomaly_count"] += 1

        if pkt.get("explanation", "").startswith("✅ Approved"):
            st["is_approved"] = True

    server_list = []
    total_anomalies = 0

    for ip, st in server_stats.items():
        total_anomalies += st["anomaly_count"]
        avg_size = round(sum(st["sizes"]) / len(st["sizes"]), 1) if st["sizes"] else 0

        # Formatted Bytes
        tot_b = st["total_bytes"]
        if tot_b > 1024 * 1024:
            bytes_fmt = f"{tot_b / 1024 / 1024:.2f} MB"
        else:
            bytes_fmt = f"{tot_b / 1024:.1f} KB"

        # Determine Role by Size & Speed
        if st["max_pps"] > 200 or st["max_bps"] > 1000000:
            role = "High-Speed Data Producer / Streamer"
        elif avg_size > 1000:
            role = "Bulk Bulk Data Transfer Server"
        else:
            role = "Standard Interactive Application Host"

        # Diagnostic Summary (Size & Speed Focus)
        diagnostics = []
        if st["anomaly_count"] > 0 and not st["is_approved"]:
            risk_level = "CRITICAL"
            risk_badge = "🔴 패킷 크기/속도 이상 탐지"
            diagnostics.append(f"⚠️ 최고 이상치 스코어: {st['max_score']:.4f} (상위 0.1% 도달)")
        elif st["is_approved"]:
            risk_level = "SAFE"
            risk_badge = "🟢 사용자 피드백 승인됨"
            diagnostics.append("✅ 사용자가 승인한 정상 특성 서버 (패킷 크기/속도 예외 적용)")
        else:
            risk_level = "SAFE"
            risk_badge = "🟢 정상 패킷 크기 및 속도"
            diagnostics.append("✅ 전송 패킷 크기 및 속도가 규정된 베이스라인 이내에 분포함")

        diagnostics.append(f"📦 패킷 크기 분포: 평균 {avg_size} Bytes (최대: {st['max_size']} Bytes, 최소: {st['min_size'] if st['min_size'] != 999999 else 0} Bytes)")
        diagnostics.append(f"⚡ 전송 속도 프로필: 최대 {st['max_pps']} pps ({st['max_bps'] / 1024:.1f} KB/s), 최소 간격 {st['min_delta_ms']:.2f} ms")

        server_list.append({
            "ip": ip,
            "packet_count": st["packet_count"],
            "total_bytes": st["total_bytes"],
            "bytes_formatted": bytes_fmt,
            "avg_size": avg_size,
            "max_size": st["max_size"],
            "max_pps": st["max_pps"],
            "max_bps": st["max_bps"],
            "min_delta_ms": round(st["min_delta_ms"], 2) if st["min_delta_ms"] != 999999.0 else 0.0,
            "primary_proto": ", ".join(list(st["protocols"])),
            "ports_list": sorted(list(st["ports"]))[:5],
            "role": role,
            "risk_level": risk_level,
            "risk_badge": risk_badge,
            "max_score": round(st["max_score"], 4),
            "anomaly_count": st["anomaly_count"],
            "diagnostic_summary": diagnostics
        })

    server_list.sort(key=lambda x: x["anomaly_count"], reverse=True)

    return {
        "summary": {
            "overall_risk": "CRITICAL" if total_anomalies > 0 else "SAFE",
            "total_servers": len(server_list),
            "total_inspected_packets": len(analyzed_history),
            "anomalies_detected": total_anomalies,
            "analysis_focus": "Packet Size & Transmission Speed/Rate (Encryption Ignored)"
        },
        "servers": server_list
    }
