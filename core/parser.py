from scapy.all import IP, IPv6, TCP, UDP, DNS, ICMP, ARP


def parse_packet(packet, number):
    time = packet.time

    src = packet[IP].src if packet.haslayer(IP) else (
        str(packet[IPv6].src) if packet.haslayer(IPv6) else "N/A"
    )
    dst = packet[IP].dst if packet.haslayer(IP) else (
        str(packet[IPv6].dst) if packet.haslayer(IPv6) else "N/A"
    )

    # FIX #4: kiểm tra DNS & ICMP & ARP TRƯỚC UDP/TCP
    # Nếu kiểm tra UDP trước, packet DNS (chạy trên UDP) sẽ bị label "UDP"
    proto = "OTHER"
    if packet.haslayer(ARP):
        proto = "ARP"
        src = packet[ARP].psrc
        dst = packet[ARP].pdst
    elif packet.haslayer(ICMP):
        proto = "ICMP"
    elif packet.haslayer(DNS):
        proto = "DNS"
    elif packet.haslayer(TCP):
        proto = "TCP"
    elif packet.haslayer(UDP):
        proto = "UDP"

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
        "raw": packet,
    }