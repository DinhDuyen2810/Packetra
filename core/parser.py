from scapy.all import IP, TCP, UDP, DNS

def parse_packet(packet, number):
    time = packet.time

    src = packet[IP].src if packet.haslayer(IP) else "N/A"
    dst = packet[IP].dst if packet.haslayer(IP) else "N/A"

    proto = "OTHER"
    if packet.haslayer(TCP):
        proto = "TCP"
    elif packet.haslayer(UDP):
        proto = "UDP"
    elif packet.haslayer(DNS):
        proto = "DNS"

    length = len(packet)

    info = packet.summary()

    return {
        "no": number,
        "time": f"{time:.6f}",
        "src": src,
        "dst": dst,
        "proto": proto,
        "length": length,
        "info": info,
        "raw": packet
    }