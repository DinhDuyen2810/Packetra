import psutil
from scapy.all import get_if_list


def get_interfaces():
    return get_if_list()   # 🔥 dùng luôn scapy


def get_traffic():
    stats = psutil.net_io_counters(pernic=True)
    traffic = {}

    for iface, data in stats.items():
        traffic[iface] = data.bytes_sent + data.bytes_recv

    return traffic