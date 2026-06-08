from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from datetime import datetime


def process_packet(packet):

    print("\n" + "=" * 60)
    print("Packet Captured at:", datetime.now())

    # Check if packet has IP layer
    if packet.haslayer(IP):

        ip_layer = packet[IP]

        source_ip = ip_layer.src
        destination_ip = ip_layer.dst
        protocol = ip_layer.proto

        print(f"Source IP      : {source_ip}")
        print(f"Destination IP : {destination_ip}")

        # Detect protocol
        if packet.haslayer(TCP):
            print("Protocol       : TCP")

            tcp_layer = packet[TCP]
            print(f"Source Port    : {tcp_layer.sport}")
            print(f"Destination Port: {tcp_layer.dport}")

        elif packet.haslayer(UDP):
            print("Protocol       : UDP")

            udp_layer = packet[UDP]
            print(f"Source Port    : {udp_layer.sport}")
            print(f"Destination Port: {udp_layer.dport}")

        elif packet.haslayer(ICMP):
            print("Protocol       : ICMP")

        else:
            print(f"Protocol Number: {protocol}")

        # Display payload if available
        if packet.haslayer(Raw):

            try:
                payload = packet[Raw].load.decode(errors="ignore")

                print("\nPayload Data:")
                print(payload[:500])

            except:
                print("Could not decode payload")

    else:
        print("Non-IP Packet Detected")


print("=" * 60)
print(" BASIC NETWORK SNIFFER ")
print("=" * 60)
print("Starting packet capture...")
print("Press CTRL + C to stop.\n")

# Start sniffing
sniff(prn=process_packet, store=False)
