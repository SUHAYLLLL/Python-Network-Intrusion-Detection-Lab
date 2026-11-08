import csv
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
ALERT_FILE = BASE_DIR / "alerts" / "network_alerts.csv"
REPORT_FILE = BASE_DIR / "reports" / "network_incident_report.txt"


def generate_report():
    if not ALERT_FILE.exists():
        print("No security alerts found.")
        return

    with ALERT_FILE.open("r", newline="") as file:
        alerts = list(csv.DictReader(file))

    REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with REPORT_FILE.open("w") as report:
        report.write("NETWORK INTRUSION DETECTION REPORT\n")
        report.write("=" * 45 + "\n")
        report.write(f"Generated: {datetime.now()}\n")
        report.write(f"Total Security Alerts: {len(alerts)}\n\n")

        for index, alert in enumerate(alerts, start=1):
            report.write(f"INCIDENT {index}\n")
            report.write("-" * 30 + "\n")
            report.write(f"Timestamp: {alert['timestamp']}\n")
            report.write(f"Source IP: {alert['source_ip']}\n")
            report.write(f"Destination IP: {alert['destination_ip']}\n")
            report.write(f"Attack Type: {alert['attack_type']}\n")
            report.write(f"Ports Scanned: {alert['ports_scanned']}\n")
            report.write(f"Severity: {alert['severity']}\n\n")

            report.write("Recommended Response Actions:\n")
            report.write("1. Investigate the suspicious source IP.\n")
            report.write("2. Review firewall and network traffic logs.\n")
            report.write("3. Check for unauthorised connection attempts.\n")
            report.write("4. Consider blocking the source IP if malicious activity is confirmed.\n")
            report.write("5. Escalate the incident to the SOC team if necessary.\n\n")

    print(f"Incident report generated: {REPORT_FILE}")


if __name__ == "__main__":
    generate_report()