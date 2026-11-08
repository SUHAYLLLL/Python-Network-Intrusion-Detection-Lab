import sys
import unittest
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from port_scan_detector import detect_port_scan


class TestPortScanDetector(unittest.TestCase):

    def test_normal_traffic(self):
        now = datetime.now()

        normal_events = [
            {
                "timestamp": now + timedelta(seconds=i * 2),
                "source_ip": "192.168.1.50",
                "destination_ip": "192.168.1.20",
                "destination_port": port,
            }
            for i, port in enumerate([80, 443, 8080])
        ]

        alerts = detect_port_scan(normal_events)

        self.assertEqual(
            len(alerts),
            0,
            "Normal traffic should not trigger a port-scan alert"
        )

    def test_port_scan_detection(self):
        now = datetime.now()

        suspicious_events = [
            {
                "timestamp": now + timedelta(seconds=i * 2),
                "source_ip": "192.168.1.10",
                "destination_ip": "192.168.1.20",
                "destination_port": port,
            }
            for i, port in enumerate([21, 22, 23, 80, 443, 8080])
        ]

        alerts = detect_port_scan(suspicious_events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["source_ip"], "192.168.1.10")
        self.assertEqual(alerts[0]["ports_scanned"], 5)
        self.assertEqual(alerts[0]["severity"], "HIGH")

if __name__ == "__main__":
    unittest.main()