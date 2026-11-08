import csv
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import alert_generator


class TestAlertGenerator(unittest.TestCase):

    def test_csv_alert_creation(self):
        sample_alerts = [{
            "source_ip": "192.168.1.10",
            "destination_ip": "192.168.1.20",
            "attack_type": "Potential Port Scan",
            "ports_scanned": 5,
            "severity": "HIGH"
        }]

        with TemporaryDirectory() as temp_dir:
            output_file = Path(temp_dir) / "network_alerts.csv"

            with patch.object(alert_generator, "ALERT_FILE", output_file):
                alert_generator.save_alerts(sample_alerts)

            self.assertTrue(output_file.exists())

            with output_file.open(newline="") as file:
                rows = list(csv.DictReader(file))

            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["source_ip"], "192.168.1.10")
            self.assertEqual(rows[0]["ports_scanned"], "5")
            self.assertEqual(rows[0]["severity"], "HIGH")


if __name__ == "__main__":
    unittest.main()