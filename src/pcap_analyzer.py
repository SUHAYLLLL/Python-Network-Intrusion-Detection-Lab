from pathlib import Path
from scapy.all import rdpcap, IP, IPv6, TCP, UDP

CAPTURE_FILE = Path(__file__).resolve().parent.parent / "data" / "network_capture.pcapng"


def analyze_capture():
    print("NETWORK TRAFFIC ANALYSIS")
    print("=" * 40)

    packets = rdpcap(str(CAPTURE_FILE))

    print(f"Total packets captured: {len(packets)}")
    print("-" * 40)

    for packet in packets[:10]:
        if IP in packet:
            source_ip = packet[IP].src
            destination_ip = packet[IP].dst
        elif IPv6 in packet:
            source_ip = packet[IPv6].src
            destination_ip = packet[IPv6].dst
        else:
            continue

        if TCP in packet:
            protocol = "TCP"
        elif UDP in packet:
            protocol = "UDP"
        else:
            protocol = "Other"

        print(f"Source: {source_ip}")
        print(f"Destination: {destination_ip}")
        print(f"Protocol: {protocol}")
        print("-" * 40)


if __name__ == "__main__":
    analyze_capture()