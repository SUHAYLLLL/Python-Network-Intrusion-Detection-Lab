from pathlib import Path
from datetime import datetime, timedelta
from scapy.all import PcapReader, IP, IPv6, TCP

from port_scan_detector import detect_port_scan
from alert_generator import save_alerts
from incident_report import generate_report

CAPTURE_FILE = (
    Path(__file__).resolve().parent.parent
    / "data"
    / "simulated_port_scan.pcap"
)


def analyze_pcap():
    events = []
    total_packets = 0

    with PcapReader(str(CAPTURE_FILE)) as packets:
        for packet in packets:
            total_packets += 1

            if TCP not in packet:
                continue

            # Only count TCP connection attempts (SYN without ACK).
            if not packet[TCP].flags & 0x02 or packet[TCP].flags & 0x10:
                continue

            if IP in packet:
                source_ip = packet[IP].src
                destination_ip = packet[IP].dst
            elif IPv6 in packet:
                source_ip = packet[IPv6].src
                destination_ip = packet[IPv6].dst
            else:
                continue

            events.append({
                "timestamp": datetime.fromtimestamp(float(packet.time)),
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "destination_port": int(packet[TCP].dport),
            })

    alerts = detect_port_scan(events)
    if alerts:
     save_alerts(alerts)
     generate_report()

    print("REAL NETWORK INTRUSION DETECTION")
    print("=" * 40)
    print(f"Packets analysed: {total_packets}")
    print(f"TCP connection attempts: {len(events)}")
    print(f"Potential port scans detected: {len(alerts)}")

    for alert in alerts:
        print("-" * 40)
        print(f"Source IP: {alert['source_ip']}")
        print(f"Destination IP: {alert['destination_ip']}")
        print(f"Ports scanned: {alert['ports_scanned']}")
        print(f"Severity: {alert['severity']}")


if __name__ == "__main__":
    analyze_pcap()