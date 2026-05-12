from scapy.all import rdpcap, wrpcap


def save_pcap(filename, packets):
    wrpcap(filename, packets)


def load_pcap(filename):
    return rdpcap(filename)
