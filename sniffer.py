from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

packet_count = 0

def packet_callback(packet):
    global packet_count
    packet_count += 1

    print("\n" + "=" * 70)
    print(f"Packet #{packet_count}")

    if packet.haslayer(IP):
        print(f"Source IP      : {packet[IP].src}")
        print(f"Destination IP : {packet[IP].dst}")

        if packet.haslayer(TCP):
            print("Protocol       : TCP")
            print(f"Source Port    : {packet[TCP].sport}")
            print(f"Destination Port: {packet[TCP].dport}")

        elif packet.haslayer(UDP):
            print("Protocol       : UDP")
            print(f"Source Port    : {packet[UDP].sport}")
            print(f"Destination Port: {packet[UDP].dport}")

        elif packet.haslayer(ICMP):
            print("Protocol       : ICMP")

        else:
            print("Protocol       : Other")

        if packet.haslayer(Raw):
            try:
                payload = packet[Raw].load.decode(
                    "utf-8",
                    errors="ignore"
                )

                if payload.strip():
                    print("\nPayload:")
                    print(payload[:300])

            except:
                pass

print("Network Sniffer Started")
print("Capturing all network traffic...")
print("Press Ctrl + C to stop")

sniff(
    prn=packet_callback,
    store=False
)