from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from datetime import datetime

# Analyze and display details of captured packet
def analyze_packet(packet):
    print("\n=== Packet Captured ===")
    print("Time:", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

    # Check if it's an IP packet
    if IP in packet:
        ip_layer = packet[IP]
        print("Source IP:", ip_layer.src)
        print("Destination IP:", ip_layer.dst)
        print("IP Protocol Number:", ip_layer.proto)

        # Check for transport protocols
        if TCP in packet:
            tcp_layer = packet[TCP]
            print("Protocol: TCP")
            print(f"Source Port: {tcp_layer.sport} → Destination Port: {tcp_layer.dport}")

        elif UDP in packet:
            udp_layer = packet[UDP]
            print("Protocol: UDP")
            print(f"Source Port: {udp_layer.sport} → Destination Port: {udp_layer.dport}")

        elif ICMP in packet:
            print("Protocol: ICMP")

        # Show raw payload if any
        if Raw in packet:
            payload = packet[Raw].load
            try:
                decoded = payload.decode('utf-8', errors='ignore')
                print("Payload:", decoded)
            except:
                print("Payload: (undecodable binary data)")
    else:
        print("Non-IP packet (likely ARP or other).")

# Entry point
def main():
    print("Starting network packet sniffer... Press Ctrl+C to stop.\n")
    sniff(prn=analyze_packet, store=False)

if __name__ == "__main__":
    main()
