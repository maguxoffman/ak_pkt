import unittest
from ml_engine import PacketAnomalyDetector, calculate_entropy
from pcap_parser import generate_benign_packet, generate_anomaly_packet

class TestMLEngine(unittest.TestCase):
    def test_calculate_entropy(self):
        # Zero entropy for repeated bytes
        self.assertEqual(calculate_entropy(b"AAAAAAA"), 0.0)
        # High entropy for uniform bytes
        self.assertGreater(calculate_entropy(bytes(range(256))), 7.9)

    def test_isolation_forest_detector(self):
        detector = PacketAnomalyDetector(contamination=0.001)
        
        # 1. Generate 500 benign packets
        benign_packets = [generate_benign_packet() for _ in range(500)]
        detector.fit(benign_packets)

        self.assertTrue(detector.is_fitted)
        self.assertGreater(detector.score_threshold, 0.4)

        # 2. Predict on normal packet
        normal_pkt = generate_benign_packet()
        res_normal = detector.predict_one(normal_pkt)
        self.assertIn("score", res_normal)
        self.assertIn("threshold", res_normal)

        # 3. Predict on 0.1% anomaly packet
        anomaly_pkt = generate_anomaly_packet("shellcode_high_entropy")
        res_anomaly = detector.predict_one(anomaly_pkt)
        print(f"Normal Score: {res_normal['score']} | Anomaly Score: {res_anomaly['score']} | Threshold: {res_normal['threshold']}")
        
        # Anomaly packet score should be significantly higher
        self.assertGreater(res_anomaly['score'], res_normal['score'])

if __name__ == '__main__':
    unittest.main()
