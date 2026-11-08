from datetime import datetime, timedelta

from port_scan_detector import detect_port_scan
from alert_generator import save_alerts
from incident_report import generate_report


def main():
    print("Starting Network Intrusion Detection Lab...")

    now = datetime.now()

    # Simulated network connection events
    sample_events = [
        {
            "timestamp": now + timedelta(seconds=i * 2),
            "source_ip": "192.168.1.10",
            "destination_ip": "192.168.1.20",
            "destination_port": port,
        }
        for i, port in enumerate([21, 22, 23, 80, 443, 8080])
    ]

    # Detect potential port scans
    alerts = detect_port_scan(sample_events)

    # Save alerts to CSV
    save_alerts(alerts)

    # Generate incident report
    generate_report()

    print(f"Detection complete. {len(alerts)} suspicious event(s) found.")


if __name__ == "__main__":
    main()