from pathlib import Path
from scapy.all import IP, TCP, wrpcap

OUTPUT_FILE = (
    Path(__file__).resolve().parent.parent
    / "data"
    / "simulated_port_scan.pcap"
)

packets = []

for port in [21, 22, 23, 80, 443]:
    packet = (
        IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=12345, dport=port, flags="S")
    )
    packets.append(packet)

wrpcap(str(OUTPUT_FILE), packets)

print(f"Created {len(packets)} simulated TCP SYN packets")
print(f"Saved to: {OUTPUT_FILE}")