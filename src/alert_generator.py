import csv
from datetime import datetime
from pathlib import Path

ALERT_FILE = Path(__file__).resolve().parent.parent / "alerts" / "network_alerts.csv"


def save_alerts(alerts):
    ALERT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with ALERT_FILE.open("w", newline="") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=[
                "timestamp",
                "source_ip",
                "destination_ip",
                "attack_type",
                "ports_scanned",
                "severity",
            ],
        )

        writer.writeheader()

        for alert in alerts:
            writer.writerow({
                "timestamp": datetime.now().isoformat(timespec="seconds"),
                "source_ip": alert["source_ip"],
                "destination_ip": alert["destination_ip"],
                "attack_type": alert["attack_type"],
                "ports_scanned": alert["ports_scanned"],
                "severity": alert["severity"],
            })

    print(f"Saved {len(alerts)} alert(s) to {ALERT_FILE}")