from scapy.all import IP, TCP


def analyze_packet(packet):
    if IP in packet:
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst

        print("Network Packet Detected")
        print("-----------------------")
        print(f"Source IP: {source_ip}")
        print(f"Destination IP: {destination_ip}")

        if TCP in packet:
            print("Protocol: TCP")
            print(f"Source Port: {packet[TCP].sport}")
            print(f"Destination Port: {packet[TCP].dport}")

        print("-----------------------")


if __name__ == "__main__":
    sample_packet = (
        IP(src="192.168.1.10", dst="192.168.1.20")
        / TCP(sport=12345, dport=80)
    )

    analyze_packet(sample_packet)