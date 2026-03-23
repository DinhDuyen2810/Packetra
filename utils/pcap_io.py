from scapy.all import wrpcap, rdpcap

def save_pcap(filename, packets):
    wrpcap(filename, packets)

def load_pcap(filename):
    return rdpcap(filename)