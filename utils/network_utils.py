import psutil
import logging

log = logging.getLogger("network_utils")


def get_interfaces():
    """
    Trả về dict: {display_name: scapy_network_name}

    Strategy: dùng psutil để lấy danh sách adapter (tên hiển thị thân thiện),
    sau đó match sang scapy network_name qua conf.ifaces bằng cách so sánh
    .description (scapy) với psutil name — cả hai đều dùng Windows friendly name.
    """
    result = {}

    try:
        from scapy.all import conf

        # Build scapy lookup: description_lower → network_name
        scapy_map = {}
        for iface in conf.ifaces.values():
            desc = getattr(iface, "description", "") or ""
            net  = getattr(iface, "network_name", "") or getattr(iface, "name", "") or ""
            if desc and net:
                scapy_map[desc.lower()] = (desc, net)

        log.debug(f"scapy_map keys: {list(scapy_map.keys())}")

        # psutil friendly names
        psutil_names = list(psutil.net_io_counters(pernic=True).keys())
        log.debug(f"psutil names: {psutil_names}")

        for psutil_name in psutil_names:
            key = psutil_name.lower()
            if key in scapy_map:
                display, scapy_net = scapy_map[key]
                result[psutil_name] = scapy_net
                log.debug(f"  MATCH: psutil={psutil_name!r} → scapy={scapy_net!r}")
            else:
                # Không match được → dùng psutil name làm cả display lẫn scapy name
                # (fallback cho Linux / Mac)
                result[psutil_name] = psutil_name
                log.debug(f"  NO MATCH: psutil={psutil_name!r}, dùng trực tiếp")

    except Exception as e:
        log.error(f"get_interfaces() lỗi: {e}")
        # Fallback hoàn toàn
        for name in psutil.net_io_counters(pernic=True):
            result[name] = name

    return result  # {display_name: scapy_name}


def get_traffic():
    """Trả về {psutil_display_name: total_bytes}."""
    stats = psutil.net_io_counters(pernic=True)
    return {iface: data.bytes_sent + data.bytes_recv for iface, data in stats.items()}