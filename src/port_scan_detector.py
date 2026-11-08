from collections import defaultdict, deque
from datetime import datetime, timedelta
from alert_generator import save_alerts


def detect_port_scan(events, threshold=5, window_seconds=60):
    alerts = []
    connections = defaultdict(list)

    for event in events:
        connections[(event["source_ip"], event["destination_ip"])].append(event)

    for (source_ip, destination_ip), ip_events in connections.items():
        window = deque()

        for event in sorted(ip_events, key=lambda e: e["timestamp"]):
            window.append(event)

            cutoff = event["timestamp"] - timedelta(seconds=window_seconds)

            while window and window[0]["timestamp"] < cutoff:
                window.popleft()

            unique_ports = {e["destination_port"] for e in window}

            if len(unique_ports) >= threshold:
                alerts.append({
                    "source_ip": source_ip,
                    "destination_ip": destination_ip,
                    "ports_scanned": len(unique_ports),
                    "severity": "HIGH",
                    "attack_type": "Potential Port Scan",
                })
                break

    return alerts


if __name__ == "__main__":
    now = datetime.now()

    sample_events = [
        {
            "timestamp": now + timedelta(seconds=i * 2),
            "source_ip": "192.168.1.10",
            "destination_ip": "192.168.1.20",
            "destination_port": port,
        }
        for i, port in enumerate([21, 22, 23, 80, 443, 8080])
    ]

    alerts = detect_port_scan(sample_events)
    
    save_alerts(alerts)

    print("Network Intrusion Detection Results")
    print("-----------------------------------")

    for alert in alerts:
        print(f"Suspicious IP: {alert['source_ip']}")
        print(f"Target IP: {alert['destination_ip']}")
        print(f"Ports Scanned: {alert['ports_scanned']}")
        print(f"Attack Type: {alert['attack_type']}")
        print(f"Severity: {alert['severity']}")

    if not alerts:
        print("No suspicious activity detected.")