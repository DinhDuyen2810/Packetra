from __future__ import annotations

from datetime import datetime, timezone
import ipaddress
from typing import Any, Dict, List


from scapy.all import ARP, DNS, Ether, ICMP, IP, IPv6, TCP, UDP
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.inet6 import ICMPv6EchoRequest, ICMPv6EchoReply, ICMPv6ND_NA, ICMPv6ND_NS, IPv6ExtHdrHopByHop, in6_chksum
from scapy.layers.l2 import Dot3, LLC, SNAP
from scapy.layers.tls.all import TLS, TLSClientHello  # type: ignore
from scapy.layers.quic import QUIC  # type: ignore
from scapy.layers.tls.record import TLSApplicationData

PRINTABLE = set(range(32, 127))
PACKET_BYTE_SOURCE = 'packet'
TCP_REASSEMBLED_BYTE_SOURCE = 'tcp_reassembled'

# MAC Vendor lookup (simplified, add more as needed)
MAC_VENDORS = {
    '00:00:0c': 'Cisco',
    '00:01:42': 'Parallels',
    '00:03:ff': 'Microsoft',
    '00:04:00': 'LexmarkInter',
    '00:05:69': 'VMware',
    '00:0c:29': 'VMware',
    '00:0f:4b': 'Virtual Iron Software',
    '00:13:07': 'Parallels',
    '00:15:5d': 'Microsoft',
    '00:16:3e': 'Xensource',
    '00:17:42': 'Parallels',
    '00:1c:14': 'VMware',
    '00:1c:42': 'Parallels',
    '00:21:6a': 'Intel',
    '00:21:f6': 'Virtual Iron Software',
    '00:24:0e': 'Apple',
    '00:50:56': 'VMware',
    'd4:21:22': 'Sercomm',
    '00:e0:4c': 'Realtek',
    '08:00:27': 'Oracle',
    '0a:00:27': 'Unknown',
    '52:54:00': 'QEMU',
    '98:40:bb': 'Dell',
    'e4:70:b8': 'Intel',
    '48:d6:82': 'zte',
}

def get_mac_vendor(mac: str) -> str:
    if not mac or len(mac) < 8:
        return ''
    prefix = mac.lower()[:8]
    return MAC_VENDORS.get(prefix, '')

def hex_dump(packet) -> str:
    raw = bytes(packet)
    lines = []

    for offset in range(0, len(raw), 16):
        chunk = raw[offset:offset + 16]

        left = ' '.join(f'{b:02x}' for b in chunk[:8])
        right = ' '.join(f'{b:02x}' for b in chunk[8:])

        hex_part = f'{left}  {right}'

        ascii_part = ''.join(
            chr(b) if b in PRINTABLE else '.'
            for b in chunk
        )

        lines.append(
            f'{offset:04x}  {hex_part:<48}  {ascii_part}'
        )

    return '\n'.join(lines)


def _byte_mapping(
    base_offset: int,
    relative_offset: int,
    length: int,
    byte_source: str = PACKET_BYTE_SOURCE,
) -> Dict[str, Any]:
    try:
        start = int(relative_offset)
        size = int(length)
    except Exception:
        return {}

    if start < 0 or size <= 0:
        return {}

    data: Dict[str, Any] = {
        'offset': int(base_offset + start) if byte_source == PACKET_BYTE_SOURCE else start,
        'length': size,
    }
    if byte_source != PACKET_BYTE_SOURCE:
        data['byte_source'] = byte_source
    return data


def _internet_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b'\x00'
    total = 0
    for index in range(0, len(data), 2):
        total += (data[index] << 8) | data[index + 1]
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _mac_display(mac: str) -> str:
    mac_text = str(mac or '')
    vendor = get_mac_vendor(mac_text)
    if vendor:
        suffix = ':'.join(mac_text.split(':')[-3:])
        return f'{vendor}_{suffix} ({mac_text})'
    return mac_text


def _mac_text_from_bytes(data: bytes) -> str:
    if len(data) < 6:
        return ''
    return ':'.join(f'{byte:02x}' for byte in data[:6])


def _ipv6_slaac_mac(address: str) -> str:
    try:
        packed = ipaddress.IPv6Address(str(address or '')).packed
    except Exception:
        return ''

    if packed[:8] != b'\xfe\x80\x00\x00\x00\x00\x00\x00':
        return ''

    interface_identifier = packed[8:]
    if interface_identifier[3:5] != b'\xff\xfe':
        return ''

    mac_bytes = bytes([
        interface_identifier[0] ^ 0x02,
        interface_identifier[1],
        interface_identifier[2],
        interface_identifier[5],
        interface_identifier[6],
        interface_identifier[7],
    ])
    return _mac_text_from_bytes(mac_bytes)


def _icmpv6_lifetime_text(seconds: int) -> str:
    value = int(seconds)
    if value > 0 and value % 86400 == 0:
        days = value // 86400
        return f'{days} day' if days == 1 else f'{days} days'
    return f'{value} second' if value == 1 else f'{value} seconds'


def _is_cdp_packet(packet) -> bool:
    try:
        if packet.haslayer(SNAP):
            oui = int(getattr(packet[SNAP], 'OUI', 0) or 0)
            code = int(getattr(packet[SNAP], 'code', 0) or 0)
            return oui == 0x00000C and code == 0x2000
    except Exception:
        pass
    return False


def _mpls_inner_ip(packet):
    try:
        if not packet.haslayer(Ether):
            return None
        eth_type = int(getattr(packet[Ether], 'type', 0) or 0)
        if eth_type != 0x8847:
            return None
        raw_bytes = bytes(packet)
        offset = 14
        while offset + 4 <= len(raw_bytes):
            label_word = int.from_bytes(raw_bytes[offset:offset + 4], 'big')
            offset += 4
            if label_word & 0x100:
                break
        if offset >= len(raw_bytes) or raw_bytes[offset] >> 4 != 4:
            return None
        return IP(raw_bytes[offset:])
    except Exception:
        return None


def _effective_ip_layer(packet):
    if packet.haslayer(IP):
        return packet[IP]
    return _mpls_inner_ip(packet)


def _effective_tcp_layer(packet, ip_layer=None):
    if packet.haslayer(TCP):
        return packet[TCP]
    effective_ip = ip_layer if ip_layer is not None else _effective_ip_layer(packet)
    if effective_ip is not None and effective_ip.haslayer(TCP):
        return effective_ip[TCP]
    return None


def _effective_udp_layer(packet, ip_layer=None):
    if packet.haslayer(UDP):
        return packet[UDP]
    effective_ip = ip_layer if ip_layer is not None else _effective_ip_layer(packet)
    if effective_ip is not None and effective_ip.haslayer(UDP):
        return effective_ip[UDP]
    return None


def _ipv4_payload_length(ip_layer):
    try:
        total_len = int(getattr(ip_layer, 'len', 0) or 0)
        header_len = int(getattr(ip_layer, 'ihl', 5) or 5) * 4
        if total_len >= header_len:
            return total_len - header_len
    except Exception:
        pass
    return None


def _tcp_payload_bytes(packet, tcp_layer):
    raw_payload = bytes(getattr(tcp_layer, 'payload', b''))
    effective_ip = _effective_ip_layer(packet) if packet is not None else None
    if effective_ip is not None:
        ip_payload_len = _ipv4_payload_length(effective_ip)
        if ip_payload_len is not None:
            tcp_header_len = int(getattr(tcp_layer, 'dataofs', 5) or 5) * 4
            payload_len = max(0, min(len(raw_payload), ip_payload_len - tcp_header_len))
            return raw_payload[:payload_len]
    if packet is not None and packet.haslayer(IPv6):
        try:
            ipv6_payload_len = int(getattr(packet[IPv6], 'plen', 0) or 0)
            tcp_header_len = int(getattr(tcp_layer, 'dataofs', 5) or 5) * 4
            payload_len = max(0, min(len(raw_payload), ipv6_payload_len - tcp_header_len))
            return raw_payload[:payload_len]
        except Exception:
            pass
    return raw_payload


def _frame_payload_length(packet):
    try:
        if packet.haslayer(ARP):
            return 14 + 28

        effective_ip = _effective_ip_layer(packet)
        if effective_ip is not None:
            total_len = int(getattr(effective_ip, 'len', 0) or 0)
            if total_len > 0:
                if packet.haslayer(IP):
                    return 14 + total_len
                if packet.haslayer(Ether):
                    eth_type = int(getattr(packet[Ether], 'type', 0) or 0)
                    if eth_type == 0x8847:
                        raw_bytes = bytes(packet)
                        offset = 14
                        while offset + 4 <= len(raw_bytes):
                            label_word = int.from_bytes(raw_bytes[offset:offset + 4], 'big')
                            offset += 4
                            if label_word & 0x100:
                                break
                        return offset + total_len

        if packet.haslayer(IPv6):
            payload_len = int(getattr(packet[IPv6], 'plen', 0) or 0)
            if payload_len > 0:
                return 14 + 40 + payload_len
    except Exception:
        pass
    return None


def _ip_payload_bytes(packet, ip_layer=None):
    effective_ip = ip_layer if ip_layer is not None else _effective_ip_layer(packet)
    if effective_ip is not None:
        raw_payload = bytes(getattr(effective_ip, 'payload', b''))
        ip_payload_len = _ipv4_payload_length(effective_ip)
        if ip_payload_len is not None:
            return raw_payload[:ip_payload_len]
        return raw_payload

    if packet is not None and packet.haslayer(IPv6):
        try:
            raw_payload = bytes(packet[IPv6].payload)
            payload_len = int(getattr(packet[IPv6], 'plen', 0) or 0)
            return raw_payload[:payload_len]
        except Exception:
            pass

    return b''


def _infer_padding(packet, record):
    frame_len = int(getattr(record, 'length', len(bytes(packet))) or len(bytes(packet)))

    if packet.haslayer('Padding'):
        try:
            padding_bytes = bytes(packet['Padding'])
            return padding_bytes.hex(), len(padding_bytes), max(0, frame_len - len(padding_bytes))
        except Exception:
            return '', 0, 0

    payload_length = _frame_payload_length(packet)
    if payload_length is None or payload_length >= frame_len:
        return '', 0, 0

    try:
        padding_bytes = bytes(packet)[payload_length:frame_len]
    except Exception:
        return '', 0, 0

    if not padding_bytes:
        return '', 0, 0

    return padding_bytes.hex(), len(padding_bytes), payload_length


def _is_l2tpv3_control_payload(payload: bytes) -> bool:
    if len(payload) < 16:
        return False
    flags = int.from_bytes(payload[4:6], 'big')
    return bool(flags & 0x8000) and (flags & 0x000F) == 3


def packet_summary_tree(packet, record) -> List[Dict[str, Any]]:

    sections: List[Dict[str, Any]] = []

    offset = 0
    payload_handled = False
    parsed_mpls_inner_ip = False
    raw_payload_consumed = False

    metadata = getattr(record, 'metadata', {}) or {}
    effective_ip_layer = _effective_ip_layer(packet)
    effective_tcp_layer = _effective_tcp_layer(packet, effective_ip_layer)
    effective_udp_layer = _effective_udp_layer(packet, effective_ip_layer)
    capwap_transport = str(metadata.get('capwap_transport', '') or '')
    is_capwap = capwap_transport in {'control', 'data'}

    def _idx(name: str) -> int:
        val = metadata.get(name, -1)
        if val is None:
            return -1
        try:
            return int(val)
        except Exception:
            return -1

    ether_stream_index = _idx('ether_stream_index')
    ip_stream_index = _idx('ip_stream_index')
    ipv6_stream_index = _idx('ipv6_stream_index')
    tcp_stream_index = _idx('tcp_stream_index')
    udp_stream_index = _idx('udp_stream_index')

    sections.append(
        _frame_section(record)
    )

    if packet.haslayer(Dot3):

        sections.append(
            _dot3_section(
                packet[Dot3],
                offset,
                ether_stream_index,
            )
        )

        offset += 14

        if packet.haslayer(LLC):
            snap_layer = packet[SNAP] if packet.haslayer(SNAP) else None
            sections.append(
                _llc_section(
                    packet[LLC],
                    snap_layer,
                    offset,
                )
            )
            offset += 3 + (5 if snap_layer is not None else 0)

            if _is_cdp_packet(packet):
                cdp_payload = bytes(getattr(snap_layer, 'payload', b'')) if snap_layer is not None else b''
                sections.append(_cdp_section(cdp_payload, offset))
                payload_handled = True

    elif packet.haslayer(Ether):

        padding_hex, padding_len, padding_offset = _infer_padding(packet, record)

        sections.append(
            _ether_section(
                packet[Ether],
                offset,
                ether_stream_index,
                padding_hex,
                padding_offset,
                padding_len,
            )
        )

        offset += 14

        try:
            eth_type = int(getattr(packet[Ether], 'type', 0) or 0)
        except Exception:
            eth_type = 0

        if eth_type == 0x8847:
            mpls_payload = bytes(packet)[offset:]
            if len(mpls_payload) >= 4:
                sections.append(_mpls_section(mpls_payload, offset))
                offset += 4
                try:
                    ip_pkt = IP(mpls_payload[4:])
                    effective_ip_layer = ip_pkt
                    effective_tcp_layer = _effective_tcp_layer(packet, ip_pkt)
                    effective_udp_layer = _effective_udp_layer(packet, ip_pkt)
                    ip_len = int(getattr(ip_pkt, 'ihl', 5) or 5) * 4
                    sections.append(_ip_section(ip_pkt, offset, ip_stream_index))
                    offset += ip_len
                    inner_payload = _ip_payload_bytes(packet, ip_pkt)
                    inner_proto = int(getattr(ip_pkt, 'proto', 0) or 0)
                    if inner_proto == 115 and len(inner_payload) >= 4:
                        l2tp_payload = inner_payload
                        sections.append(_l2tpv3_section(l2tp_payload, offset))
                        if len(l2tp_payload) > 4 and not _is_l2tpv3_control_payload(l2tp_payload):
                            sections.append(_bytes_data_section(l2tp_payload[4:], offset + 4))
                        payload_handled = True
                    parsed_mpls_inner_ip = True
                    raw_payload_consumed = True
                except Exception:
                    pass

        if eth_type == 0x9000:
            loop_payload = bytes(packet)[offset:]
            sections.append(_loop_section(loop_payload, offset))
            loop_header_len = min(len(loop_payload), 6)
            if len(loop_payload) > loop_header_len:
                sections.append(_bytes_data_section(loop_payload[loop_header_len:], offset + loop_header_len))
            payload_handled = True

    if packet.haslayer(ARP):

        sections.append(
            _arp_section(
                packet[ARP],
                offset
            )
        )

        offset += 28

    if effective_ip_layer is not None and not parsed_mpls_inner_ip:

        ip_layer = effective_ip_layer

        ip_len = (
            int(getattr(ip_layer, 'ihl', 5) or 5) * 4
        )

        sections.append(
            _ip_section(
                ip_layer,
                offset,
                ip_stream_index,
            )
        )

        offset += ip_len

    if packet.haslayer(IPv6):

        ipv6_section = _ipv6_section(
            packet[IPv6],
            offset,
            ipv6_stream_index,
        )
        sections.append(ipv6_section)

        offset += 40

        if packet.haslayer(IPv6ExtHdrHopByHop):
            hopopts_layer = packet[IPv6ExtHdrHopByHop]
            ipv6_section.setdefault('children', []).append(_ipv6_hopopts_section(hopopts_layer, offset))
            offset += max(8, (int(getattr(hopopts_layer, 'len', 0) or 0) + 1) * 8)

        if getattr(record, 'protocol', '') in {'ICMPV6', 'ICMPv6'}:
            if packet.haslayer(IPv6ExtHdrHopByHop):
                icmpv6_payload = bytes(getattr(packet[IPv6ExtHdrHopByHop], 'payload', b''))
            else:
                icmpv6_payload = bytes(getattr(packet[IPv6], 'payload', b''))
            if icmpv6_payload:
                sections.append(_icmpv6_section(icmpv6_payload, offset, record))
                payload_handled = True
                offset += len(icmpv6_payload)
        elif getattr(record, 'protocol', '') == 'OSPF':
            ospf_payload = bytes(getattr(packet[IPv6], 'payload', b''))
            if ospf_payload:
                sections.append(_ospf_section(ospf_payload, offset))
                payload_handled = True

    if effective_tcp_layer is not None:

        tcp_layer = effective_tcp_layer

        tcp_len = (
            int(getattr(tcp_layer, 'dataofs', 5) or 5) * 4
        )

        sections.append(
            _tcp_section(
                tcp_layer,
                offset,
                tcp_stream_index,
                record,
            )
        )

        offset += tcp_len

        tcp_reassembly_section = _tcp_reassembly_section(record)
        if tcp_reassembly_section is not None:
            sections.append(tcp_reassembly_section)

        tcp_payload = _tcp_payload_bytes(getattr(record, 'raw', None), tcp_layer)
        if getattr(record, 'protocol', '') == 'BGP' and tcp_payload:
            sections.append(_bgp_section(tcp_payload, offset))
            payload_handled = True
        elif getattr(record, 'protocol', '') == 'LDP' and tcp_payload:
            sections.append(_ldp_section(tcp_payload, offset))
            payload_handled = True
        elif getattr(record, 'protocol', '') == 'HTTP' and tcp_payload:
            sections.append(_http_section(tcp_payload, offset, record))
            if bool(metadata.get('http_has_line_based_text', False)):
                sections.append(_http_line_based_text_section(record, offset))
            payload_handled = True
        elif bool(metadata.get('tcp_is_retransmission', False)) and tcp_payload:
            payload_handled = True

    elif effective_udp_layer is not None:

        udp_layer = effective_udp_layer

        sections.append(
            _udp_section(
                udp_layer,
                offset,
                udp_stream_index,
                record,
            )
        )

        offset += 8

        try:
            sport = int(getattr(udp_layer, 'sport', 0) or 0)
            dport = int(getattr(udp_layer, 'dport', 0) or 0)
        except Exception:
            sport = dport = 0

        if getattr(record, 'protocol', '') in {'CAPWAP-Control', 'CAPWAP-Data', '802.11'} or is_capwap:
            capwap_payload = bytes(getattr(udp_layer, 'payload', b''))
            sections.append(_capwap_section(capwap_payload, offset, record))
            wlan = metadata.get('wlan', {}) if isinstance(metadata, dict) else {}
            if isinstance(wlan, dict) and wlan:
                sections.extend(_wlan_sections(wlan, offset))
            payload_handled = True
        elif getattr(record, 'protocol', '') == 'DHCPv6':
            dhcpv6_payload = bytes(getattr(udp_layer, 'payload', b''))
            sections.append(_dhcpv6_section(dhcpv6_payload, offset))
            payload_handled = True
        elif sport == 646 or dport == 646:
            ldp_payload = bytes(getattr(udp_layer, 'payload', b''))
            sections.append(_ldp_section(ldp_payload, offset))
            payload_handled = True

    if effective_ip_layer is not None and not parsed_mpls_inner_ip:
        try:
            ip_proto = int(getattr(effective_ip_layer, 'proto', 0) or 0)
        except Exception:
            ip_proto = 0
        if ip_proto == 2:
            igmp_payload = _ip_payload_bytes(packet, effective_ip_layer)
            sections.append(_igmp_section(igmp_payload, offset))
            payload_handled = True
        if ip_proto == 89:
            ospf_payload = bytes(getattr(effective_ip_layer, 'payload', b''))
            sections.append(_ospf_section(ospf_payload, offset))
            payload_handled = True
        if ip_proto == 115:
            l2tp_payload = _ip_payload_bytes(packet, effective_ip_layer)
            sections.append(_l2tpv3_section(l2tp_payload, offset))
            if len(l2tp_payload) > 4 and not _is_l2tpv3_control_payload(l2tp_payload):
                sections.append(_bytes_data_section(l2tp_payload[4:], offset + 4))
            payload_handled = True

    if packet.haslayer(ICMP):

        icmp_layer = packet[ICMP]

        sections.append(
            _icmp_section(
                icmp_layer,
                offset,
                record,
            )
        )

        payload_handled = True
        offset += len(icmp_layer)

    if packet.haslayer(DNS):

        dns_layer = packet[DNS]

        sections.append(
            _dns_section(
                dns_layer,
                offset,
                record,
            )
        )

        offset += len(dns_layer)

    if packet.haslayer(DHCP):

        dhcp_layer = packet[DHCP]
        bootp_layer = packet[BOOTP] if packet.haslayer(BOOTP) else None

        sections.append(
            _dhcp_section(
                bootp_layer,
                dhcp_layer,
                offset
            )
        )

        offset += len(bytes(bootp_layer)) if bootp_layer is not None else len(dhcp_layer)

    elif packet.haslayer(BOOTP):

        bootp_layer = packet[BOOTP]

        sections.append(
            _simple_layer_section(
                'BOOTP',
                bootp_layer,
                offset,
                len(bootp_layer)
            )
        )

        offset += len(bootp_layer)

    suppress_http_fallback = bool(metadata.get('http_incomplete', False)) or bool(
        metadata.get('tcp_reassembled_pdu_in_frame', False)
    )

    if (
        getattr(record, 'protocol', '') != 'HTTP'
        and not suppress_http_fallback
        and packet.haslayer(HTTPRequest)
    ):

        http_layer = packet[HTTPRequest]

        sections.append(
            _simple_layer_section(
                'Hypertext Transfer Protocol Request',
                http_layer,
                offset,
                len(http_layer)
            )
        )

        offset += len(http_layer)

    if (
        getattr(record, 'protocol', '') != 'HTTP'
        and not suppress_http_fallback
        and packet.haslayer(HTTPResponse)
    ):

        http_layer = packet[HTTPResponse]

        sections.append(
            _simple_layer_section(
                'Hypertext Transfer Protocol Response',
                http_layer,
                offset,
                len(http_layer)
            )
        )

        offset += len(http_layer)

    if packet.haslayer(TLS):

        tls_layer = packet[TLS]

        sections.append(
            _tls_section_precise(
                packet,
                offset,
                tcp_stream_index
            )
        )

        offset += len(tls_layer)

    if packet.haslayer(QUIC):

        quic_layer = packet[QUIC]

        sections.append(
            _simple_layer_section(
                'QUIC',
                quic_layer,
                offset,
                len(quic_layer)
            )
        )

        offset += len(quic_layer)

    if packet.haslayer('Raw') and not packet.haslayer(TLS) and not payload_handled and not raw_payload_consumed:

        raw_layer = packet['Raw']

        raw_len = len(raw_layer.load)

        sections.append(
            _data_section(
                raw_layer,
                offset,
                raw_len
            )
        )

    return sections

def _frame_section(record) -> Dict[str, Any]:

    ts_local = datetime.fromtimestamp(
        record.epoch_time
    ).astimezone()

    ts_utc = datetime.fromtimestamp(
        record.epoch_time,
        tz=timezone.utc
    )

    frame_len = int(getattr(record, 'length', 0) or 0)
    metadata = getattr(record, 'metadata', {}) or {}

    interface_id = int(
        getattr(record, 'interface_id', 0)
        or metadata.get('frame_interface_id', 0)
        or 0
    )

    iface = (
        str(metadata.get('frame_interface_name', '') or '').strip()
        or getattr(record, 'iface', None)
        or ''
    )
    if not iface:
        try:
            iface = getattr(record.raw, 'sniffed_on', None) or ''
        except Exception:
            pass
    if not iface:
        try:
            iface = getattr(record.raw, 'interface_name', None) or ''
        except Exception:
            pass
    if not iface:
        iface = 'Unknown'

    interface_description = str(metadata.get('frame_interface_description', '') or '').strip() or 'Ethernet'

    frame_number = getattr(record, 'number', 0)

    relative_time = float(
        getattr(record, 'relative_time', 0.0) or 0.0
    )

    delta_time = float(
        getattr(record, 'time_delta', None)
        or metadata.get('frame_time_delta', 0.0)
        or 0.0
    )

    delta_displayed = float(
        getattr(record, 'time_delta_displayed', None)
        or metadata.get('frame_time_delta_displayed', 0.0)
        or 0.0
    )

    protocol = getattr(record, 'protocol', 'UNKNOWN')
    if protocol not in {'CAPWAP-Control', 'CAPWAP-Data', '802.11'}:
        if str(metadata.get('capwap_transport', '') or '') == 'control':
            protocol = 'CAPWAP-Control'
        elif str(metadata.get('capwap_transport', '') or '') == 'data':
            protocol = 'CAPWAP-Data'

    layers = getattr(record, 'layers', [])

    # ---- PROTOCOL STACK ----

    protocol_stack = []

    for layer in layers:

        lname = str(layer).lower()

        if lname in ('ether', 'ethernet', 'dot3'):
            protocol_stack.append('eth')

        elif lname == 'llc':
            protocol_stack.append('llc')

        elif lname == 'ip':
            protocol_stack.append('ip')

        elif lname == 'ipv6':
            protocol_stack.append('ipv6')

        elif lname == 'tcp':
            protocol_stack.append('tcp')

        elif lname == 'udp':
            protocol_stack.append('udp')

        elif lname == 'arp':
            protocol_stack.append('arp')

        elif lname == 'dns':
            protocol_stack.append('dns')

        elif lname == 'tls':
            protocol_stack.append('tls')

        elif lname in ('httprequest', 'httpresponse'):
            protocol_stack.append('http')

        elif lname == 'raw':
            protocol_stack.append('data')

        else:
            protocol_stack.append(lname)

    if (
        'eth' in protocol_stack
        and ('ip' in protocol_stack or 'ipv6' in protocol_stack)
        and 'ethertype' not in protocol_stack
    ):
        protocol_stack.insert(1, 'ethertype')
    
    eth_type = metadata.get('eth_type')
    if protocol == 'RARP':
        protocol_string = 'eth:ethertype:arp'
    elif protocol == 'LDP':
        if metadata.get('tcp_stream_index', None) is not None and int(metadata.get('tcp_stream_index', -1)) >= 0:
            protocol_string = 'eth:ethertype:ip:tcp:ldp'
        else:
            protocol_string = 'eth:ethertype:ip:udp:ldp'
    elif protocol == 'BGP':
        protocol_string = 'eth:ethertype:mpls:tcp:bgp' if eth_type == 0x8847 else 'eth:ethertype:ip:tcp:bgp'
    elif protocol in {'L2TPv3', 'L2TPV3'}:
        if bool(metadata.get('l2tpv3_is_control', False)):
            protocol_string = 'eth:ethertype:mpls:l2tp'
        else:
            protocol_string = 'eth:ethertype:mpls:l2tp:data'
    elif protocol == 'LOOP':
        protocol_string = 'eth:ethertype:loop:data'
    elif protocol == 'OSPF':
        protocol_string = 'eth:ethertype:ipv6:ospf' if bool(metadata.get('is_ipv6', False)) else 'eth:ethertype:ip:ospf'
    elif protocol == 'CDP':
        protocol_string = 'eth:llc:cdp'
    elif protocol == 'CAPWAP-Control':
        protocol_string = 'eth:ethertype:ip:udp:capwap'
    elif protocol == 'CAPWAP-Data':
        protocol_string = 'eth:ethertype:ip:udp:capwap.data'
    elif protocol == '802.11' and str(metadata.get('capwap_transport', '') or '') == 'data':
        protocol_string = 'eth:ethertype:ip:udp:capwap.data:wlan'
    elif protocol == 'DHCP':
        protocol_string = 'eth:ethertype:ip:udp:dhcp'
    elif protocol == 'DHCPv6':
        protocol_string = 'eth:ethertype:ipv6:udp:dhcpv6'
    elif protocol in {'ICMPV6', 'ICMPv6'}:
        has_hopopts = any(str(layer).lower() == 'ipv6exthdrhopbyhop' for layer in layers)
        protocol_string = 'eth:ethertype:ipv6:ipv6.hopopts:icmpv6' if has_hopopts else 'eth:ethertype:ipv6:icmpv6'
    elif protocol == 'HTTP':
        protocol_string = 'eth:ethertype:ip:tcp:http:data-text-lines' if bool(metadata.get('http_has_line_based_text', False)) else 'eth:ethertype:ip:tcp:http'
    elif protocol == 'TCP':
        if eth_type == 0x8847:
            protocol_string = 'eth:ethertype:mpls:tcp'
        elif bool(metadata.get('is_ipv6', False)):
            protocol_string = 'eth:ethertype:ipv6:tcp'
        else:
            protocol_string = 'eth:ethertype:ip:tcp'
    else:
        protocol_string = ':'.join(protocol_stack)

    coloring_name = protocol
    coloring_string = protocol.lower()
    include_coloring = True
    if protocol == 'RARP':
        coloring_name = 'ARP'
        coloring_string = 'arp'
    elif protocol in {'HTTP', 'TCP'} and (
        int(getattr(record, 'sport', 0) or 0) in {80, 3128, 8080}
        or int(getattr(record, 'dport', 0) or 0) in {80, 3128, 8080}
    ):
        coloring_name = 'HTTP'
        coloring_string = 'http || tcp.port == 80 || http2'
    elif protocol == 'LDP':
        if metadata.get('tcp_stream_index', None) is not None and int(metadata.get('tcp_stream_index', -1)) >= 0:
            coloring_name = 'TCP'
            coloring_string = 'tcp'
        else:
            coloring_name = 'UDP'
            coloring_string = 'udp'
    elif protocol in {'CAPWAP-Control', 'CAPWAP-Data'} or (protocol == '802.11' and str(metadata.get('capwap_transport', '') or '') == 'data'):
        coloring_name = 'UDP'
        coloring_string = 'udp'
    elif protocol == 'DHCPv6':
        coloring_name = 'UDP'
        coloring_string = 'udp'
    elif protocol in {'OSPF', 'CDP', 'BGP'}:
        coloring_name = 'Routing'
        coloring_string = 'hsrp || eigrp || ospf || bgp || cdp || vrrp || carp || gvrp || igmp || ismp'
    elif protocol in {'ICMPV6', 'ICMPv6'}:
        coloring_name = 'ICMP'
        coloring_string = 'icmp || icmpv6'
    elif protocol == 'TCP' and (
        bool(metadata.get('tcp_is_retransmission', False))
        or bool(metadata.get('tcp_is_duplicate_ack', False))
        or bool(metadata.get('tcp_previous_segment_not_captured', False))
    ):
        coloring_name = 'Bad TCP'
        coloring_string = 'tcp.analysis.flags && !tcp.analysis.window_update && !tcp.analysis.keep_alive && !tcp.analysis.keep_alive_ack'
    elif protocol in {'LOOP', 'L2TPv3', 'L2TPV3'}:
        include_coloring = False

    children = [

        {
            'title': 'Section number: 1'
        },

        {
            'title': f'Interface id: {interface_id} ({iface})',

            'children': [

                {
                    'title':
                        f'Interface name: {iface}'
                },

                {
                    'title':
                        f'Interface description: {interface_description}'
                }
            ]
        },

        {
            'title':
                'Encapsulation type: Ethernet (1)'
        },

        {
            'title':
                'Arrival Time: '
                f'{ts_local.strftime("%b %d, %Y %H:%M:%S.%f %Z")}'
        },

        {
            'title':
                'UTC Arrival Time: '
                f'{ts_utc.strftime("%b %d, %Y %H:%M:%S.%f UTC")}'
        },

        {
            'title':
                f'Epoch Arrival Time: '
                f'{record.epoch_time:.9f}'
        },

        {
            'title':
                '[Time shift for this packet: '
                '0.000000000 seconds]'
        },

        {
            'title':
                '[Time delta from previous captured frame: '
                f'{delta_time:.9f} seconds]'
        },

        {
            'title':
                '[Time delta from previous displayed frame: '
                f'{delta_displayed:.9f} seconds]'
        },

        {
            'title':
                '[Time since reference or first frame: '
                f'{relative_time:.9f} seconds]'
        },

        {
            'title':
                f'Frame Number: {frame_number}'
        },

        {
            'title':
                f'Frame Length: '
                f'{frame_len} bytes '
                f'({frame_len * 8} bits)'
        },

        {
            'title':
                f'Capture Length: '
                f'{frame_len} bytes '
                f'({frame_len * 8} bits)'
        },

        {
            'title':
                '[Frame is marked: False]'
        },

        {
            'title':
                '[Frame is ignored: False]'
        },

        {
            'title':
                f'[Protocols in frame: '
                f'{protocol_string}]'
        },
        
        {
            'title':
                'Character encoding: ASCII (0)'
        },
        
    ]

    if include_coloring:
        children.extend([
            {
                'title':
                    f'[Coloring Rule Name: {coloring_name}]'
            },
            {
                'title':
                    f'[Coloring Rule String: '
                    f'{coloring_string}]'
            }
        ])

    return {

        'title':
            f'Frame {frame_number}: '
            f'{frame_len} bytes on wire '
            f'({frame_len * 8} bits), '
            f'{frame_len} bytes captured '
            f'({frame_len * 8} bits) '
            f'on interface {iface}, id {interface_id}',

        'offset': 0,
        'length': frame_len,

        'children': children,
    }

def _ether_section(
    layer,
    offset: int,
    stream_index: int,
    padding_hex: str = '',
    padding_offset: int = 0,
    padding_len: int = 0,
) -> Dict[str, Any]:

    src = getattr(layer, "src", "-")
    dst = getattr(layer, "dst", "-")

    eth_type = int(getattr(layer, "type", 0) or 0)

    # ---- MAC VENDOR ----

    src_vendor = get_mac_vendor(src)
    dst_vendor = get_mac_vendor(dst)

    def format_mac(mac: str, vendor: str):
        mac_text = str(mac or '')
        mac_lower = mac_text.lower()

        if mac_lower == 'ff:ff:ff:ff:ff:ff':
            return f'Broadcast ({mac_text})'

        if mac_lower.startswith('01:00:5e:'):
            suffix = mac_text.split(':')[-1]
            return f'IPv4mcast_{suffix} ({mac_text})'

        if mac_lower == '01:00:0c:cc:cc:cc':
            return f'CDP/VTP/DTP/PAgP/UDLD ({mac_text})'

        if not vendor:
            return mac_text

        suffix = ':'.join(mac_text.split(':')[-3:])

        return f'{vendor}_{suffix} ({mac_text})'

    src_display = format_mac(src, src_vendor)
    dst_display = format_mac(dst, dst_vendor)

    # ---- ADDRESS TYPE ----

    def is_group(mac: str):

        try:
            return bool(int(mac.split(':')[0], 16) & 1)
        except Exception:
            return False

    def is_local(mac: str):

        try:
            return bool(int(mac.split(':')[0], 16) & 2)
        except Exception:
            return False

    dst_group = is_group(dst)
    src_group = is_group(src)

    dst_local = is_local(dst)
    src_local = is_local(src)

    # ---- ETHERTYPE ----

    ether_types = {

        0x0800: 'IPv4',
        0x0806: 'ARP',
        0x8035: 'RARP',
        0x86DD: 'IPv6',
        0x8100: '802.1Q VLAN',
        0x88CC: 'LLDP',
        0x8847: 'MPLS label switched packet',
        0x9000: 'Loopback',
    }

    eth_name = ether_types.get(
        eth_type,
        f'0x{eth_type:04x}'
    )

    children = [
        {
            'title': f'Destination: {dst_display}',
            'offset': offset,
            'length': 6,
            'children': [
                {
                    'title': f'.... ..{"1" if dst_local else "0"}. .... .... .... .... = LG bit: {"Locally administered" if dst_local else "Globally unique"} address ({"this is NOT the factory default" if dst_local else "factory default"})',
                    'offset': offset,
                    'length': 3,
                },
                {
                    'title': f'.... ...{"1" if dst_group else "0"} .... .... .... .... = IG bit: {"Group" if dst_group else "Individual"} address ({"multicast/broadcast" if dst_group else "unicast"})',

                    'length': 3,
                }
            ]
        },
        {
            'title': f'Source: {src_display}',
            'offset': offset + 6,
            'length': 6,
            'children': [
                {
                    'title': f'.... ..{"1" if src_local else "0"}. .... .... .... .... = LG bit: {"Locally administered" if src_local else "Globally unique"} address ({"this is NOT the factory default" if src_local else "factory default"})',
                    'offset': offset + 6,
                    'length': 3,
                },
                {
                    'title': f'.... ...{"1" if src_group else "0"} .... .... .... .... = IG bit: {"Group" if src_group else "Individual"} address ({"multicast/broadcast" if src_group else "unicast"})',
                    'offset': offset + 6,
                    'length': 3,
                }
            ]
        },

        {
            'title':
                f'Type: {eth_name} '
                f'(0x{eth_type:04x})',

            'offset': offset + 12,
            'length': 2,
        },
    ]

    if stream_index >= 0:
        children.append({
            'title': f'[Stream index: {stream_index}]',
        })

    if padding_hex:
        children.append({
            'title': f'Padding: {padding_hex}',
            'offset': padding_offset,
            'length': padding_len,
        })

    return {

        'title':
            f'Ethernet II, '
            f'Src: {src_display}, '
            f'Dst: {dst_display}',

        'offset': offset,
        'length': 14,
        'children': children,
    }


def _arp_section(layer, offset: int) -> Dict[str, Any]:

    hwtype = int(getattr(layer, 'hwtype', 0) or 0)
    ptype = int(getattr(layer, 'ptype', 0) or 0)
    hwlen = int(getattr(layer, 'hwlen', 0) or 0)
    plen = int(getattr(layer, 'plen', 0) or 0)
    op = int(getattr(layer, 'op', 0) or 0)
    hwsrc = getattr(layer, 'hwsrc', '-')
    hwdst = getattr(layer, 'hwdst', '-')
    psrc = getattr(layer, 'psrc', '-')
    pdst = getattr(layer, 'pdst', '-')
    op_names = {
        1: 'request',
        2: 'reply',
        3: 'reverse request',
        4: 'reverse reply',
    }
    operation = op_names.get(op, str(op))
    hwtype_names = {1: 'Ethernet'}
    ptype_names = {0x0800: 'IPv4', 0x86DD: 'IPv6'}
    hwtype_name = hwtype_names.get(hwtype, str(hwtype))
    ptype_name = ptype_names.get(ptype, f'0x{ptype:04x}')
    is_gratuitous = str(psrc) == str(pdst) and str(psrc) not in {'', '-', '0.0.0.0'}
    # Format vendor for MAC
    def mac_vendor(mac):
        mac_text = str(mac or '')
        if mac_text.lower() == 'ff:ff:ff:ff:ff:ff':
            return f'Broadcast ({mac_text})'
        vendor = get_mac_vendor(mac)
        if vendor:
            suffix = ':'.join(mac_text.split(':')[-3:])
            return f'{vendor}_{suffix} ({mac_text})'
        return mac_text
    children = [
        {'title': f'Hardware type: {hwtype_name} ({hwtype})', 'offset': offset, 'length': 2},
        {'title': f'Protocol type: {ptype_name} (0x{ptype:04x})', 'offset': offset + 2, 'length': 2},
        {'title': f'Hardware size: {hwlen}', 'offset': offset + 4, 'length': 1},
        {'title': f'Protocol size: {plen}', 'offset': offset + 5, 'length': 1},
        {'title': f'Opcode: {operation} ({op})', 'offset': offset + 6, 'length': 2},
        {'title': f'Sender MAC address: {mac_vendor(hwsrc)}', 'offset': offset + 8, 'length': 6},
        {'title': f'Sender IP address: {psrc}', 'offset': offset + 14, 'length': 4},
        {'title': f'Target MAC address: {mac_vendor(hwdst)}', 'offset': offset + 18, 'length': 6},
        {'title': f'Target IP address: {pdst}', 'offset': offset + 24, 'length': 4},
    ]
    if is_gratuitous:
        children.insert(5, {'title': '[Is gratuitous: True]'})
    return {
        'title': f'Address Resolution Protocol ({operation}/gratuitous ARP)' if is_gratuitous else f'Address Resolution Protocol ({operation})',
        'offset': offset,
        'length': 28,
        'children': children,
    }


def _icmp_section(layer, offset: int, record=None) -> Dict[str, Any]:
    metadata = getattr(record, 'metadata', {}) if record else {}
    raw = bytes(layer)
    icmp_type = int(raw[0]) if len(raw) >= 1 else int(getattr(layer, 'type', 0) or 0)
    code = int(raw[1]) if len(raw) >= 2 else int(getattr(layer, 'code', 0) or 0)
    checksum = int.from_bytes(raw[2:4], 'big') if len(raw) >= 4 else 0
    identifier_be = int.from_bytes(raw[4:6], 'big') if len(raw) >= 6 else 0
    identifier_le = int.from_bytes(raw[4:6], 'little') if len(raw) >= 6 else 0
    sequence_be = int.from_bytes(raw[6:8], 'big') if len(raw) >= 8 else 0
    sequence_le = int.from_bytes(raw[6:8], 'little') if len(raw) >= 8 else 0
    payload = raw[8:] if len(raw) > 8 else b''

    checksum_status = 'Good'
    if len(raw) >= 4:
        checksum_bytes = bytearray(raw)
        checksum_bytes[2:4] = b'\x00\x00'
        if _internet_checksum(bytes(checksum_bytes)) != checksum:
            checksum_status = 'Bad'

    type_name = {
        0: 'Echo (ping) reply',
        8: 'Echo (ping) request',
    }.get(icmp_type, f'Type {icmp_type}')

    children = [
        {'title': f'Type: {type_name} ({icmp_type})', 'offset': offset, 'length': 1},
        {'title': f'Code: {code}', 'offset': offset + 1, 'length': 1},
        {'title': f'Checksum: 0x{checksum:04x} [{"correct" if checksum_status == "Good" else "incorrect"}]', 'offset': offset + 2, 'length': 2},
        {'title': f'[Checksum Status: {checksum_status}]'},
        {'title': f'Identifier (BE): {identifier_be} (0x{identifier_be:04x})', 'offset': offset + 4, 'length': 2},
        {'title': f'Identifier (LE): {identifier_le} (0x{identifier_le:04x})', 'offset': offset + 4, 'length': 2},
        {'title': f'Sequence Number (BE): {sequence_be} (0x{sequence_be:04x})', 'offset': offset + 6, 'length': 2},
        {'title': f'Sequence Number (LE): {sequence_le} (0x{sequence_le:04x})', 'offset': offset + 6, 'length': 2},
    ]

    response_frame = metadata.get('icmp_response_frame')
    if response_frame is not None:
        children.append({'title': f'[Response frame: {int(response_frame)}]'})

    if bool(metadata.get('icmp_no_response_seen', False)):
        children.append({
            'title': '[No response seen]',
            'children': [
                {
                    'title': '[Expert Info (Warning/Sequence): No response seen to ICMP request]',
                    'children': [
                        {'title': '[No response seen to ICMP request]'},
                        {'title': '[Severity level: Warning]'},
                        {'title': '[Group: Sequence]'},
                    ],
                },
            ],
        })

    request_frame = metadata.get('icmp_request_frame')
    if request_frame is not None:
        children.append({'title': f'[Request frame: {int(request_frame)}]'})

    response_time_ms = metadata.get('icmp_response_time_ms')
    if response_time_ms is not None:
        children.append({'title': f'[Response time: {float(response_time_ms):.3f} ms]'})

    if payload:
        children.append({
            'title': f'Data ({len(payload)} bytes)',
            'offset': offset + 8,
            'length': len(payload),
            'children': [
                {'title': f'Data: {payload.hex()}'},
                {'title': f'[Length: {len(payload)}]'},
            ],
        })

    return {
        'title': 'Internet Control Message Protocol',
        'offset': offset,
        'length': len(raw),
        'children': children,
    }


def _igmp_type_name(igmp_type: int) -> str:
    return {
        0x11: 'Membership Query',
        0x12: 'Version 1 Membership Report',
        0x16: 'Version 2 Membership Report',
        0x17: 'Leave Group',
        0x22: 'Version 3 Membership Report',
    }.get(int(igmp_type or 0), f'Type 0x{int(igmp_type or 0):02x}')


def _igmp_section(payload: bytes, offset: int) -> Dict[str, Any]:
    igmp_type = int(payload[0]) if len(payload) >= 1 else 0
    max_resp = int(payload[1]) if len(payload) >= 2 else 0
    checksum = int.from_bytes(payload[2:4], 'big') if len(payload) >= 4 else 0
    group_addr = str(ipaddress.IPv4Address(payload[4:8])) if len(payload) >= 8 else '0.0.0.0'

    checksum_status = 'Unverified'
    if len(payload) >= 4:
        checksum_bytes = bytearray(payload)
        checksum_bytes[2:4] = b'\x00\x00'
        checksum_status = 'Good' if _internet_checksum(bytes(checksum_bytes)) == checksum else 'Bad'

    children = [
        {'title': f'[IGMP Version: {3 if igmp_type == 0x11 and len(payload) >= 12 else 2}]'},
        {'title': f'Type: {_igmp_type_name(igmp_type)} (0x{igmp_type:02x})', 'offset': offset, 'length': 1},
        {'title': f'Max Resp Time: {max_resp / 10.0:.1f} sec (0x{max_resp:02x})', 'offset': offset + 1, 'length': 1},
        {'title': f'Checksum: 0x{checksum:04x} [{"correct" if checksum_status == "Good" else "incorrect"}]', 'offset': offset + 2, 'length': 2},
        {'title': f'[Checksum Status: {checksum_status}]'},
        {'title': f'Multicast Address: {group_addr}', 'offset': offset + 4, 'length': 4},
    ]

    if igmp_type == 0x11 and len(payload) >= 12:
        s_flag = (payload[8] >> 3) & 0x1
        qrv = payload[8] & 0x07
        qqic = int(payload[9])
        num_src = int.from_bytes(payload[10:12], 'big')
        children.extend([
            {'title': f'.... {s_flag}... = S: {"Suppress router side processing" if s_flag else "Do not suppress router side processing"}', 'offset': offset + 8, 'length': 1},
            {'title': f'.... .{qrv:03b} = QRV: {qrv}', 'offset': offset + 8, 'length': 1},
            {'title': f'QQIC: {qqic}', 'offset': offset + 9, 'length': 1},
            {'title': f'Num Src: {num_src}', 'offset': offset + 10, 'length': 2},
        ])
        if num_src > 0:
            source_children = []
            base = 12
            for index in range(num_src):
                entry_offset = base + (index * 4)
                if entry_offset + 4 > len(payload):
                    break
                source_children.append({
                    'title': f'Source Address [{index + 1}]: {ipaddress.IPv4Address(payload[entry_offset:entry_offset + 4])}',
                    'offset': offset + entry_offset,
                    'length': 4,
                })
            if source_children:
                children.append({'title': f'Source Addresses ({len(source_children)})', 'children': source_children})

    title = 'Internet Group Management Protocol'
    if igmp_type == 0x11 and len(payload) >= 12:
        title = 'Internet Group Management Protocol'
    return {
        'title': title,
        'offset': offset,
        'length': len(payload),
        'children': children,
    }


def _tls_clienthello_ja3(record_payload: bytes) -> Dict[str, str] | None:
    if len(record_payload) < 42 or int(record_payload[0]) != 1:
        return None

    grease_values = {
        0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
        0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
    }

    cursor = 4
    version = int.from_bytes(record_payload[cursor:cursor + 2], 'big')
    cursor += 2 + 32
    if cursor >= len(record_payload):
        return None
    session_id_len = int(record_payload[cursor])
    cursor += 1 + session_id_len
    if cursor + 2 > len(record_payload):
        return None
    cipher_len = int.from_bytes(record_payload[cursor:cursor + 2], 'big')
    cursor += 2
    ciphers = []
    cipher_end = min(len(record_payload), cursor + cipher_len)
    while cursor + 2 <= cipher_end:
        val = int.from_bytes(record_payload[cursor:cursor + 2], 'big')
        if val not in grease_values:
            ciphers.append(str(val))
        cursor += 2
    if cursor >= len(record_payload):
        return None
    comp_len = int(record_payload[cursor])
    cursor += 1 + comp_len
    if cursor + 2 > len(record_payload):
        exts = []
        groups = []
        point_formats = []
    else:
        ext_len = int.from_bytes(record_payload[cursor:cursor + 2], 'big')
        cursor += 2
        ext_end = min(len(record_payload), cursor + ext_len)
        exts = []
        groups = []
        point_formats = []
        while cursor + 4 <= ext_end:
            ext_type = int.from_bytes(record_payload[cursor:cursor + 2], 'big')
            ext_size = int.from_bytes(record_payload[cursor + 2:cursor + 4], 'big')
            data_start = cursor + 4
            data_end = min(ext_end, data_start + ext_size)
            if ext_type not in grease_values:
                exts.append(str(ext_type))
            ext_payload = record_payload[data_start:data_end]
            if ext_type == 10 and len(ext_payload) >= 2:
                list_len = int.from_bytes(ext_payload[:2], 'big')
                p = 2
                while p + 2 <= min(len(ext_payload), 2 + list_len):
                    group = int.from_bytes(ext_payload[p:p + 2], 'big')
                    if group not in grease_values:
                        groups.append(str(group))
                    p += 2
            elif ext_type == 11 and len(ext_payload) >= 1:
                list_len = int(ext_payload[0])
                for i in range(min(list_len, max(0, len(ext_payload) - 1))):
                    point_formats.append(str(int(ext_payload[1 + i])))
            cursor = data_end

    import hashlib
    full = f'{version},{ "-".join(ciphers)},{ "-".join(exts)},{ "-".join(groups)},{ "-".join(point_formats)}'
    return {'full': full, 'hash': hashlib.md5(full.encode('ascii')).hexdigest()}


def _tls_clienthello_ja4(record_payload: bytes) -> Dict[str, str] | None:
    if len(record_payload) < 42 or int(record_payload[0]) != 1:
        return None

    grease_values = {
        0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
        0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
    }

    cursor = 4
    version = int.from_bytes(record_payload[cursor:cursor + 2], 'big')
    version_token = {
        0x0301: '10',
        0x0302: '11',
        0x0303: '12',
        0x0304: '13',
    }.get(version, '00')
    cursor += 2 + 32
    if cursor >= len(record_payload):
        return None
    session_id_len = int(record_payload[cursor])
    cursor += 1 + session_id_len
    if cursor + 2 > len(record_payload):
        return None
    cipher_len = int.from_bytes(record_payload[cursor:cursor + 2], 'big')
    cursor += 2
    cipher_hex = []
    cipher_end = min(len(record_payload), cursor + cipher_len)
    while cursor + 2 <= cipher_end:
        val = int.from_bytes(record_payload[cursor:cursor + 2], 'big')
        if val not in grease_values:
            cipher_hex.append(f'{val:04x}')
        cursor += 2
    if cursor >= len(record_payload):
        return None
    comp_len = int(record_payload[cursor])
    cursor += 1 + comp_len
    ext_hex = []
    has_sni = False
    alpn_count = 0
    if cursor + 2 <= len(record_payload):
        ext_len = int.from_bytes(record_payload[cursor:cursor + 2], 'big')
        cursor += 2
        ext_end = min(len(record_payload), cursor + ext_len)
        while cursor + 4 <= ext_end:
            ext_type = int.from_bytes(record_payload[cursor:cursor + 2], 'big')
            ext_size = int.from_bytes(record_payload[cursor + 2:cursor + 4], 'big')
            data_start = cursor + 4
            data_end = min(ext_end, data_start + ext_size)
            if ext_type not in grease_values:
                ext_hex.append(f'{ext_type:04x}')
            if ext_type == 0:
                has_sni = True
            if ext_type == 16 and data_start + 2 <= data_end:
                try:
                    alpn_block_len = int.from_bytes(record_payload[data_start:data_start + 2], 'big')
                    p = data_start + 2
                    end = min(data_end, p + alpn_block_len)
                    while p < end:
                        ln = int(record_payload[p])
                        p += 1 + ln
                        alpn_count += 1
                except Exception:
                    alpn_count = 0
            cursor = data_end

    import hashlib
    prefix = f't{version_token}{"d" if has_sni else "i"}{len(cipher_hex):02d}{len(ext_hex):02d}{alpn_count:02d}'
    cipher_hash = hashlib.sha256(','.join(cipher_hex).encode('ascii')).hexdigest()[:12] if cipher_hex else '0' * 12
    ext_hash = hashlib.sha256(','.join(ext_hex).encode('ascii')).hexdigest()[:12] if ext_hex else '0' * 12
    raw = f'{prefix}_' + ','.join(cipher_hex)
    if ext_hex:
        raw += '_' + ','.join(ext_hex)
    return {'value': f'{prefix}_{cipher_hash}_{ext_hash}', 'raw': raw}


def _ipv6_next_header_name(next_header: int) -> str:
    return {
        0: 'IPv6 Hop-by-Hop Option',
        6: 'TCP',
        17: 'UDP',
        58: 'ICMPv6',
    }.get(int(next_header), f'Next Header {int(next_header)}')


def _ipv6_address_text(data: bytes) -> str:
    try:
        return str(ipaddress.IPv6Address(bytes(data[:16])))
    except Exception:
        return '::'


def _ipv6_hopopts_section(layer, offset: int) -> Dict[str, Any]:
    header_length = max(8, (int(getattr(layer, 'len', 0) or 0) + 1) * 8)
    raw = bytes(layer)[:header_length]
    next_header = int(raw[0]) if len(raw) >= 1 else int(getattr(layer, 'nh', 0) or 0)
    length_field = int(raw[1]) if len(raw) >= 2 else int(getattr(layer, 'len', 0) or 0)
    children: List[Dict[str, Any]] = [
        {'title': f'Next Header: {_ipv6_next_header_name(next_header)} ({next_header})', 'offset': offset, 'length': 1},
        {'title': f'Length: {length_field}', 'offset': offset + 1, 'length': 1},
        {'title': f'[Length: {header_length} bytes]'},
    ]

    cursor = 2
    while cursor < len(raw):
        option_type = int(raw[cursor])
        option_offset = offset + cursor
        if option_type == 0:
            children.append({'title': 'Pad1', 'offset': option_offset, 'length': 1})
            cursor += 1
            continue
        if cursor + 2 > len(raw):
            break
        option_length = int(raw[cursor + 1])
        available_length = max(0, len(raw) - (cursor + 2))
        actual_length = min(option_length, available_length)
        option_data = raw[cursor + 2:cursor + 2 + actual_length]

        if option_type == 5:
            router_alert = int.from_bytes(option_data[:2].ljust(2, b'\x00'), 'big') if option_data else 0
            router_alert_name = {
                0: 'MLD',
                1: 'RSVP',
                2: 'Active Networks',
            }.get(router_alert, f'Value {router_alert}')
            children.append(
                {
                    'title': 'Router Alert',
                    'offset': option_offset,
                    'length': 2 + actual_length,
                    'children': [
                        {
                            'title': 'Type: Router Alert (0x05)',
                            'offset': option_offset,
                            'length': 1,
                            'children': [
                                {'title': '00.. .... = Action: Skip and continue (0)', 'offset': option_offset, 'length': 1},
                                {'title': '..0. .... = May Change: No', 'offset': option_offset, 'length': 1},
                                {'title': '...0 0101 = Low-Order Bits: 0x05', 'offset': option_offset, 'length': 1},
                            ],
                        },
                        {'title': f'Length: {option_length}', 'offset': option_offset + 1, 'length': 1},
                        {'title': f'Router Alert: {router_alert_name} ({router_alert})', 'offset': option_offset + 2, 'length': min(2, actual_length)},
                    ],
                }
            )
        elif option_type == 1:
            children.append(
                {
                    'title': 'PadN',
                    'offset': option_offset,
                    'length': 2 + actual_length,
                    'children': [
                        {
                            'title': 'Type: PadN (0x01)',
                            'offset': option_offset,
                            'length': 1,
                            'children': [
                                {'title': '00.. .... = Action: Skip and continue (0)', 'offset': option_offset, 'length': 1},
                                {'title': '..0. .... = May Change: No', 'offset': option_offset, 'length': 1},
                                {'title': '...0 0001 = Low-Order Bits: 0x01', 'offset': option_offset, 'length': 1},
                            ],
                        },
                        {'title': f'Length: {option_length}', 'offset': option_offset + 1, 'length': 1},
                        {'title': 'PadN: <none>', 'offset': option_offset + 2, 'length': actual_length},
                    ],
                }
            )
        cursor += 2 + option_length

    return {
        'title': 'IPv6 Hop-by-Hop Option',
        'offset': offset,
        'length': header_length,
        'children': children,
    }


def _icmpv6_na_flag_children(flags: int, offset: int) -> List[Dict[str, Any]]:
    router = bool(int(flags) & 0x80000000)
    solicited = bool(int(flags) & 0x40000000)
    override = bool(int(flags) & 0x20000000)
    reserved = int(flags) & 0x1FFFFFFF
    reserved_bits = format(reserved, '029b')
    reserved_groups = ' '.join(reserved_bits[1 + (index * 4):1 + ((index + 1) * 4)] for index in range(7))
    return [
        {'title': f'{"1" if router else "0"}... .... .... .... .... .... .... .... = Router: {"Set" if router else "Not set"}', 'offset': offset, 'length': 4},
        {'title': f'.{"1" if solicited else "0"}.. .... .... .... .... .... .... .... = Solicited: {"Set" if solicited else "Not set"}', 'offset': offset, 'length': 4},
        {'title': f'..{"1" if override else "0"}. .... .... .... .... .... .... .... = Override: {"Set" if override else "Not set"}', 'offset': offset, 'length': 4},
        {'title': f'...{reserved_bits[0]} {reserved_groups} = Reserved: {reserved}', 'offset': offset, 'length': 4},
    ]


def _icmpv6_ra_flag_children(flags: int, offset: int) -> List[Dict[str, Any]]:
    managed = bool(int(flags) & 0x80)
    other = bool(int(flags) & 0x40)
    home_agent = bool(int(flags) & 0x20)
    prf = (int(flags) >> 3) & 0x03
    nd_proxy = bool(int(flags) & 0x04)
    snac_router = bool(int(flags) & 0x02)
    reserved = int(flags) & 0x01
    prf_name = {
        0: 'Medium',
        1: 'High',
        2: 'Reserved',
        3: 'Low',
    }.get(prf, f'Value {prf}')
    return [
        {'title': f'{"1" if managed else "0"}... .... = Managed address configuration: {"Set" if managed else "Not set"}', 'offset': offset, 'length': 1},
        {'title': f'.{"1" if other else "0"}.. .... = Other configuration: {"Set" if other else "Not set"}', 'offset': offset, 'length': 1},
        {'title': f'..{"1" if home_agent else "0"}. .... = Home Agent: {"Set" if home_agent else "Not set"}', 'offset': offset, 'length': 1},
        {'title': f'...{(prf >> 1) & 0x1} {prf & 0x1}... = Prf (Default Router Preference): {prf_name} ({prf})', 'offset': offset, 'length': 1},
        {'title': f'.... {"1" if nd_proxy else "0"}... = ND Proxy: {"Set" if nd_proxy else "Not set"}', 'offset': offset, 'length': 1},
        {'title': f'.... .{"1" if snac_router else "0"}.. = SNAC Router: {"Set" if snac_router else "Not set"}', 'offset': offset, 'length': 1},
        {'title': f'.... ...{reserved} = Reserved: {reserved}', 'offset': offset, 'length': 1},
    ]


def _icmpv6_nd_option_nodes(payload: bytes, offset: int) -> List[Dict[str, Any]]:
    children: List[Dict[str, Any]] = []
    cursor = 0

    while cursor + 2 <= len(payload):
        option_type = int(payload[cursor])
        option_units = int(payload[cursor + 1])
        if option_units <= 0:
            break

        option_length = option_units * 8
        actual_length = min(option_length, len(payload) - cursor)
        option_offset = offset + cursor
        body = payload[cursor + 2:cursor + actual_length]

        if option_type in {1, 2}:
            label = 'Source link-layer address' if option_type == 1 else 'Target link-layer address'
            mac = _mac_text_from_bytes(body)
            children.append(
                {
                    'title': f'ICMPv6 Option ({label} : {mac})' if mac else f'ICMPv6 Option ({label})',
                    'offset': option_offset,
                    'length': actual_length,
                    'children': [
                        {'title': f'Type: {label} ({option_type})', 'offset': option_offset, 'length': 1},
                        {'title': f'Length: {option_units} ({option_length} bytes)', 'offset': option_offset + 1, 'length': 1},
                        {'title': f'Link-layer address: {_mac_display(mac)}', 'offset': option_offset + 2, 'length': min(6, len(body))} if mac else {'title': 'Link-layer address', 'offset': option_offset + 2, 'length': len(body)},
                    ],
                }
            )
        elif option_type == 3 and actual_length >= 32:
            prefix_length = int(payload[cursor + 2])
            flags = int(payload[cursor + 3])
            valid_lifetime = int.from_bytes(payload[cursor + 4:cursor + 8], 'big')
            preferred_lifetime = int.from_bytes(payload[cursor + 8:cursor + 12], 'big')
            prefix = _ipv6_address_text(payload[cursor + 16:cursor + 32])
            flag_labels: List[str] = []
            if flags & 0x80:
                flag_labels.append('On-link Flag (L)')
            if flags & 0x40:
                flag_labels.append('Autonomous Address Configuration Flag (A)')
            if flags & 0x20:
                flag_labels.append('Router Address Flag (R)')
            if flags & 0x10:
                flag_labels.append('DHCPv6-PD Preferred Flag (P)')
            flag_title = f'Flag: 0x{flags:02x}'
            if flag_labels:
                flag_title += f', {", ".join(flag_labels)}'
            children.append(
                {
                    'title': f'ICMPv6 Option (Prefix information : {prefix}/{prefix_length})',
                    'offset': option_offset,
                    'length': actual_length,
                    'children': [
                        {'title': 'Type: Prefix information (3)', 'offset': option_offset, 'length': 1},
                        {'title': f'Length: {option_units} ({option_length} bytes)', 'offset': option_offset + 1, 'length': 1},
                        {'title': f'Prefix Length: {prefix_length}', 'offset': option_offset + 2, 'length': 1},
                        {
                            'title': flag_title,
                            'offset': option_offset + 3,
                            'length': 1,
                            'children': [
                                {'title': f'{"1" if flags & 0x80 else "0"}... .... = On-link Flag (L): {"Set" if flags & 0x80 else "Not set"}', 'offset': option_offset + 3, 'length': 1},
                                {'title': f'.{"1" if flags & 0x40 else "0"}.. .... = Autonomous Address Configuration Flag (A): {"Set" if flags & 0x40 else "Not set"}', 'offset': option_offset + 3, 'length': 1},
                                {'title': f'..{"1" if flags & 0x20 else "0"}. .... = Router Address Flag (R): {"Set" if flags & 0x20 else "Not set"}', 'offset': option_offset + 3, 'length': 1},
                                {'title': f'...{"1" if flags & 0x10 else "0"} .... = DHCPv6-PD Preferred Flag (P): {"Set" if flags & 0x10 else "Not set"}', 'offset': option_offset + 3, 'length': 1},
                                {'title': f'.... {flags & 0x0F:04b} = Reserved: {flags & 0x0F}', 'offset': option_offset + 3, 'length': 1},
                            ],
                        },
                        {'title': f'Valid Lifetime: {valid_lifetime} ({_icmpv6_lifetime_text(valid_lifetime)})', 'offset': option_offset + 4, 'length': 4},
                        {'title': f'Preferred Lifetime: {preferred_lifetime} ({_icmpv6_lifetime_text(preferred_lifetime)})', 'offset': option_offset + 8, 'length': 4},
                        {'title': 'Reserved', 'offset': option_offset + 12, 'length': 4},
                        {'title': f'Prefix: {prefix}', 'offset': option_offset + 16, 'length': 16},
                    ],
                }
            )
        elif option_type == 5 and actual_length >= 8:
            mtu = int.from_bytes(payload[cursor + 4:cursor + 8], 'big')
            children.append(
                {
                    'title': f'ICMPv6 Option (MTU : {mtu})',
                    'offset': option_offset,
                    'length': actual_length,
                    'children': [
                        {'title': 'Type: MTU (5)', 'offset': option_offset, 'length': 1},
                        {'title': f'Length: {option_units} ({option_length} bytes)', 'offset': option_offset + 1, 'length': 1},
                        {'title': 'Reserved', 'offset': option_offset + 2, 'length': 2},
                        {'title': f'MTU: {mtu}', 'offset': option_offset + 4, 'length': 4},
                    ],
                }
            )
        else:
            children.append(
                {
                    'title': f'ICMPv6 Option (Type {option_type})',
                    'offset': option_offset,
                    'length': actual_length,
                    'children': [
                        {'title': f'Type: {option_type}', 'offset': option_offset, 'length': 1},
                        {'title': f'Length: {option_units} ({option_length} bytes)', 'offset': option_offset + 1, 'length': 1},
                    ],
                }
            )

        cursor += option_length

    return children


def _icmpv6_section(payload: bytes, offset: int, record=None) -> Dict[str, Any]:
    icmpv6_type = int(payload[0]) if len(payload) >= 1 else 0
    code = int(payload[1]) if len(payload) >= 2 else 0
    checksum = int.from_bytes(payload[2:4], 'big') if len(payload) >= 4 else 0
    checksum_status = 'Good'

    try:
        raw_packet = getattr(record, 'raw', None)
        upper_layer = None
        if raw_packet is not None and raw_packet.haslayer(IPv6ExtHdrHopByHop):
            upper_layer = raw_packet[IPv6ExtHdrHopByHop].payload
        elif raw_packet is not None and raw_packet.haslayer(IPv6):
            upper_layer = raw_packet[IPv6].payload
        if upper_layer is not None and len(payload) >= 4:
            checksum_bytes = bytearray(payload)
            checksum_bytes[2:4] = b'\x00\x00'
            if in6_chksum(58, upper_layer, bytes(checksum_bytes)) != checksum:
                checksum_status = 'Bad'
    except Exception:
        checksum_status = 'Good'

    type_name = {
        128: 'Echo (ping) request',
        129: 'Echo (ping) reply',
        130: 'Multicast Listener Query',
        131: 'Multicast Listener Report',
        132: 'Multicast Listener Done',
        133: 'Router Solicitation',
        134: 'Router Advertisement',
        135: 'Neighbor Solicitation',
        136: 'Neighbor Advertisement',
        143: 'Multicast Listener Report Message v2',
    }.get(icmpv6_type, f'ICMPv6 Type {icmpv6_type}')

    children: List[Dict[str, Any]] = [
        {'title': f'Type: {type_name} ({icmpv6_type})', 'offset': offset, 'length': 1},
        {'title': f'Code: {code}', 'offset': offset + 1, 'length': 1},
        {'title': f'Checksum: 0x{checksum:04x} [{"correct" if checksum_status == "Good" else "incorrect"}]', 'offset': offset + 2, 'length': 2},
        {'title': f'[Checksum Status: {checksum_status}]'},
    ]

    if icmpv6_type == 143:
        reserved = int.from_bytes(payload[4:6], 'big') if len(payload) >= 6 else 0
        record_count = int.from_bytes(payload[6:8], 'big') if len(payload) >= 8 else 0
        children.extend([
            {'title': f'Reserved: {reserved:04x}', 'offset': offset + 4, 'length': 2 if len(payload) >= 6 else 0},
            {'title': f'Number of Multicast Address Records: {record_count}', 'offset': offset + 6, 'length': 2 if len(payload) >= 8 else 0},
        ])

        cursor = 8
        record_type_names = {
            1: 'Mode is include',
            2: 'Mode is exclude',
            3: 'Changed to include',
            4: 'Changed to exclude',
            5: 'Allow new sources',
            6: 'Block old sources',
        }
        for _ in range(record_count):
            if cursor + 20 > len(payload):
                break
            record_type = int(payload[cursor])
            aux_data_len = int(payload[cursor + 1])
            source_count = int.from_bytes(payload[cursor + 2:cursor + 4], 'big')
            multicast_address = _ipv6_address_text(payload[cursor + 4:cursor + 20])
            record_length = 20 + (source_count * 16) + (aux_data_len * 4)
            record_label = record_type_names.get(record_type, f'Record Type {record_type}')
            children.append(
                {
                    'title': f'Multicast Address Record {record_label}: {multicast_address}',
                    'offset': offset + cursor,
                    'length': min(record_length, max(0, len(payload) - cursor)),
                    'children': [
                        {'title': f'Record Type: {record_label} ({record_type})', 'offset': offset + cursor, 'length': 1},
                        {'title': f'Aux Data Len: {aux_data_len}', 'offset': offset + cursor + 1, 'length': 1},
                        {'title': f'Number of Sources: {source_count}', 'offset': offset + cursor + 2, 'length': 2},
                        {'title': f'Multicast Address: {multicast_address}', 'offset': offset + cursor + 4, 'length': 16},
                    ],
                }
            )
            cursor += record_length
    elif icmpv6_type == 133:
        reserved = int.from_bytes(payload[4:8], 'big') if len(payload) >= 8 else 0
        children.extend([
            {'title': f'Reserved: {reserved:08x}', 'offset': offset + 4, 'length': 4 if len(payload) >= 8 else 0},
        ])
        if len(payload) > 8:
            children.extend(_icmpv6_nd_option_nodes(payload[8:], offset + 8))
    elif icmpv6_type == 134:
        cur_hop_limit = int(payload[4]) if len(payload) >= 5 else 0
        flags = int(payload[5]) if len(payload) >= 6 else 0
        router_lifetime = int.from_bytes(payload[6:8], 'big') if len(payload) >= 8 else 0
        reachable_time = int.from_bytes(payload[8:12], 'big') if len(payload) >= 12 else 0
        retrans_timer = int.from_bytes(payload[12:16], 'big') if len(payload) >= 16 else 0
        prf = (flags >> 3) & 0x03
        prf_name = {
            0: 'Medium',
            1: 'High',
            2: 'Reserved',
            3: 'Low',
        }.get(prf, f'Value {prf}')
        flag_labels: List[str] = []
        if flags & 0x80:
            flag_labels.append('Managed address configuration')
        if flags & 0x40:
            flag_labels.append('Other configuration')
        if flags & 0x20:
            flag_labels.append('Home Agent')
        if prf != 0:
            flag_labels.append(f'Prf (Default Router Preference): {prf_name}')
        if flags & 0x04:
            flag_labels.append('ND Proxy')
        if flags & 0x02:
            flag_labels.append('SNAC Router')
        flags_title = f'Flags: 0x{flags:02x}'
        if flag_labels:
            flags_title += f', {", ".join(flag_labels)}'
        children.extend([
            {'title': f'Cur hop limit: {cur_hop_limit}', 'offset': offset + 4, 'length': 1 if len(payload) >= 5 else 0},
            {'title': flags_title, 'offset': offset + 5, 'length': 1 if len(payload) >= 6 else 0, 'children': _icmpv6_ra_flag_children(flags, offset + 5)},
            {'title': f'Router lifetime (s): {router_lifetime}', 'offset': offset + 6, 'length': 2 if len(payload) >= 8 else 0},
            {'title': f'Reachable time (ms): {reachable_time}', 'offset': offset + 8, 'length': 4 if len(payload) >= 12 else 0},
            {'title': f'Retrans timer (ms): {retrans_timer}', 'offset': offset + 12, 'length': 4 if len(payload) >= 16 else 0},
        ])
        if len(payload) > 16:
            children.extend(_icmpv6_nd_option_nodes(payload[16:], offset + 16))
    elif icmpv6_type == 135:
        reserved = int.from_bytes(payload[4:8], 'big') if len(payload) >= 8 else 0
        target = _ipv6_address_text(payload[8:24]) if len(payload) >= 24 else '::'
        children.extend([
            {'title': f'Reserved: {reserved:08x}', 'offset': offset + 4, 'length': 4 if len(payload) >= 8 else 0},
            {'title': f'Target Address: {target}', 'offset': offset + 8, 'length': 16 if len(payload) >= 24 else 0},
        ])
        if len(payload) > 24:
            children.extend(_icmpv6_nd_option_nodes(payload[24:], offset + 24))
    elif icmpv6_type == 136:
        flags = int.from_bytes(payload[4:8], 'big') if len(payload) >= 8 else 0
        target = _ipv6_address_text(payload[8:24]) if len(payload) >= 24 else '::'
        flag_labels: List[str] = []
        if flags & 0x80000000:
            flag_labels.append('Router')
        if flags & 0x40000000:
            flag_labels.append('Solicited')
        if flags & 0x20000000:
            flag_labels.append('Override')
        flags_title = f'Flags: 0x{flags:08x}'
        if flag_labels:
            flags_title += f', {", ".join(flag_labels)}'
        children.extend([
            {'title': flags_title, 'offset': offset + 4, 'length': 4 if len(payload) >= 8 else 0, 'children': _icmpv6_na_flag_children(flags, offset + 4)},
            {'title': f'Target Address: {target}', 'offset': offset + 8, 'length': 16 if len(payload) >= 24 else 0},
        ])
        if len(payload) > 24:
            children.extend(_icmpv6_nd_option_nodes(payload[24:], offset + 24))

    return {
        'title': 'Internet Control Message Protocol v6',
        'offset': offset,
        'length': len(payload),
        'children': children,
    }


def _bgp_section(payload: bytes, offset: int) -> Dict[str, Any]:
    marker = payload[:16]
    length = int.from_bytes(payload[16:18], 'big') if len(payload) >= 18 else 0
    msg_type = int(payload[18]) if len(payload) >= 19 else 0
    msg_name = {
        1: 'OPEN Message',
        2: 'UPDATE Message',
        3: 'NOTIFICATION Message',
        4: 'KEEPALIVE Message',
        5: 'ROUTE-REFRESH Message',
    }.get(msg_type, f'BGP Message ({msg_type})')

    children = [
        {'title': f'Marker: {marker.hex()}', 'offset': offset, 'length': min(16, len(payload))},
        {'title': f'Length: {length}', 'offset': offset + 16, 'length': 2 if len(payload) >= 18 else 0},
        {'title': f'Type: {msg_name} ({msg_type})', 'offset': offset + 18, 'length': 1 if len(payload) >= 19 else 0},
    ]

    section_length = len(payload)
    if length >= 19:
        section_length = min(len(payload), length)

    return {
        'title': f'Border Gateway Protocol - {msg_name}',
        'offset': offset,
        'length': section_length,
        'children': children,
    }


def _dot3_section(layer, offset: int, stream_index: int) -> Dict[str, Any]:
    src = getattr(layer, 'src', '-')
    dst = getattr(layer, 'dst', '-')
    length = int(getattr(layer, 'len', 0) or 0)

    src_vendor = get_mac_vendor(src)
    dst_vendor = get_mac_vendor(dst)

    def format_mac(mac: str, vendor: str):
        mac_text = str(mac or '')
        mac_lower = mac_text.lower()
        if mac_lower == '01:00:0c:cc:cc:cc':
            return f'CDP/VTP/DTP/PAgP/UDLD ({mac_text})'
        if not vendor:
            return mac_text
        suffix = ':'.join(mac_text.split(':')[-3:])
        return f'{vendor}_{suffix} ({mac_text})'

    def is_group(mac: str):
        try:
            return bool(int(mac.split(':')[0], 16) & 1)
        except Exception:
            return False

    def is_local(mac: str):
        try:
            return bool(int(mac.split(':')[0], 16) & 2)
        except Exception:
            return False

    src_display = format_mac(src, src_vendor)
    dst_display = format_mac(dst, dst_vendor)
    dst_group = is_group(dst)
    src_group = is_group(src)
    dst_local = is_local(dst)
    src_local = is_local(src)

    children = [
        {
            'title': f'Destination: {dst_display}',
            'offset': offset,
            'length': 6,
            'children': [
                {'title': f'.... ..{"1" if dst_local else "0"}. .... .... .... .... = LG bit: {"Locally administered" if dst_local else "Globally unique"} address ({"this is NOT the factory default" if dst_local else "factory default"})', 'offset': offset, 'length': 3},
                {'title': f'.... ...{"1" if dst_group else "0"} .... .... .... .... = IG bit: {"Group" if dst_group else "Individual"} address ({"multicast/broadcast" if dst_group else "unicast"})', 'offset': offset, 'length': 3},
            ],
        },
        {
            'title': f'Source: {src_display}',
            'offset': offset + 6,
            'length': 6,
            'children': [
                {'title': f'.... ..{"1" if src_local else "0"}. .... .... .... .... = LG bit: {"Locally administered" if src_local else "Globally unique"} address ({"this is NOT the factory default" if src_local else "factory default"})', 'offset': offset + 6, 'length': 3},
                {'title': f'.... ...{"1" if src_group else "0"} .... .... .... .... = IG bit: {"Group" if src_group else "Individual"} address ({"multicast/broadcast" if src_group else "unicast"})', 'offset': offset + 6, 'length': 3},
            ],
        },
        {'title': f'Length: {length}', 'offset': offset + 12, 'length': 2},
    ]

    if stream_index >= 0:
        children.append({'title': f'[Stream index: {stream_index}]'})

    return {
        'title': 'IEEE 802.3 Ethernet',
        'offset': offset,
        'length': 14,
        'children': children,
    }


def _llc_section(layer, snap_layer, offset: int) -> Dict[str, Any]:
    dsap = int(getattr(layer, 'dsap', 0) or 0)
    ssap = int(getattr(layer, 'ssap', 0) or 0)
    ctrl = int(getattr(layer, 'ctrl', 0) or 0)
    oui = int(getattr(snap_layer, 'OUI', 0) or 0) if snap_layer is not None else 0
    pid = int(getattr(snap_layer, 'code', 0) or 0) if snap_layer is not None else 0
    oui_text = f'{(oui >> 16) & 0xFF:02x}:{(oui >> 8) & 0xFF:02x}:{oui & 0xFF:02x}'
    pid_name = 'CDP' if pid == 0x2000 else f'0x{pid:04x}'

    children = [
        {
            'title': f'DSAP: SNAP (0x{dsap:02x})',
            'offset': offset,
            'length': 1,
            'children': [
                {'title': '1010 101. = SAP: SNAP', 'offset': offset, 'length': 1},
                {'title': '.... ...0 = IG Bit: Individual', 'offset': offset, 'length': 1},
            ],
        },
        {
            'title': f'SSAP: SNAP (0x{ssap:02x})',
            'offset': offset + 1,
            'length': 1,
            'children': [
                {'title': '1010 101. = SAP: SNAP', 'offset': offset + 1, 'length': 1},
                {'title': '.... ...0 = CR Bit: Command', 'offset': offset + 1, 'length': 1},
            ],
        },
        {
            'title': f'Control field: U, func=UI (0x{ctrl:02x})',
            'offset': offset + 2,
            'length': 1,
            'children': [
                {'title': '000. 00.. = Command: Unnumbered Information (0x00)', 'offset': offset + 2, 'length': 1},
                {'title': '.... ..11 = Frame type: Unnumbered frame (0x3)', 'offset': offset + 2, 'length': 1},
            ],
        },
    ]

    if snap_layer is not None:
        children.extend([
            {'title': f'Organization Code: {oui_text} (Cisco Systems, Inc)', 'offset': offset + 3, 'length': 3},
            {'title': f'PID: {pid_name} (0x{pid:04x})', 'offset': offset + 6, 'length': 2},
        ])

    return {
        'title': 'Logical-Link Control',
        'offset': offset,
        'length': 3 + (5 if snap_layer is not None else 0),
        'children': children,
    }

def _ip_section(layer, offset: int, stream_index: int) -> Dict[str, Any]:

    version = int(getattr(layer, 'version', 4) or 4)
    ihl = int(getattr(layer, 'ihl', 5) or 5)

    tos = int(getattr(layer, 'tos', 0) or 0)

    total_len = int(getattr(layer, 'len', 0) or 0)

    identification = int(getattr(layer, 'id', 0) or 0)

    frag = int(getattr(layer, 'frag', 0) or 0)

    ttl = int(getattr(layer, 'ttl', 0) or 0)

    proto_num = int(getattr(layer, 'proto', 0) or 0)

    checksum = int(getattr(layer, 'chksum', 0) or 0)

    src = getattr(layer, 'src', '-')
    dst = getattr(layer, 'dst', '-')

    ip_header_len = ihl * 4

    # ---- DSCP / ECN ----

    dscp = tos >> 2
    ecn = tos & 0x03

    dscp_names = {
        0: 'Default',
        8: 'CS1',
        16: 'CS2',
        24: 'CS3',
        32: 'CS4',
        40: 'CS5',
        48: 'CS6',
        56: 'CS7',
        46: 'EF',
    }

    dscp_name = dscp_names.get(dscp, str(dscp))

    ecn_names = {
        0: 'Not ECN-Capable Transport',
        1: 'ECT(1)',
        2: 'ECT(0)',
        3: 'Congestion Experienced',
    }

    ecn_name = ecn_names.get(ecn, str(ecn))

    # ---- FLAGS ----

    flags = int(getattr(layer, 'flags', 0) or 0)

    reserved = (flags & 0x4) >> 2
    df = (flags & 0x2) >> 1
    mf = flags & 0x1

    # ---- PROTOCOL ----

    proto_names = {
        1: 'ICMP',
        6: 'TCP',
        17: 'UDP',
        89: 'OSPF IGP',
        115: 'Layer 2 Tunneling',
        58: 'ICMPv6',
    }

    proto_name = proto_names.get(proto_num, str(proto_num))

    # ---- FRAGMENT FIELD ----

    frag_field = ((flags << 13) | frag) & 0xFFFF

    frag_bits = format(frag_field, '016b')

    frag_bits_pretty = (
        f'...{frag_bits[3]} '
        f'{frag_bits[4:8]} '
        f'{frag_bits[8:12]} '
        f'{frag_bits[12:16]}'
    )

    flags_bits = f'{reserved}{df}{mf}'

    children = [

        {
            'title':
                f'{version:04b} .... = Version: {version}',

            'offset': offset,
            'length': 1,
        },

        {
            'title':
                f'.... {ihl:04b} = Header Length: '
                f'{ip_header_len} bytes ({ihl})',

            'offset': offset,
            'length': 1,
        },

        {
            'title':
                f'Differentiated Services Field: '
                f'0x{tos:02x} '
                f'(DSCP: {dscp_name}, ECN: {ecn_name})',

            'offset': offset + 1,
            'length': 1,

            'children': [

                {
                    'title':
                        f'{format(dscp, "06b")} .. = '
                        f'Differentiated Services Codepoint: '
                        f'{dscp_name} ({dscp})',

                    'offset': offset + 1,
                    'length': 1,
                },

                {
                    'title':
                        f'.... ..{ecn:02b} = '
                        f'Explicit Congestion Notification: '
                        f'{ecn_name} ({ecn})',

                    'offset': offset + 1,
                    'length': 1,
                }
            ]
        },

        {
            'title':
                f'Total Length: {total_len}',

            'offset': offset + 2,
            'length': 2,
        },

        {
            'title':
                f'Identification: '
                f'0x{identification:04x} '
                f'({identification})',

            'offset': offset + 4,
            'length': 2,
        },

        {
            'title':
                    f'{flags_bits}. .... = Flags: 0x{flags:x}',
                'offset': offset + 6,
                'length': 1,
                'children': [
                    {
                        'title':
                            f'{reserved}... .... = '
                            f'Reserved bit: '
                            f'{"Set" if reserved else "Not set"}',
                        'offset': offset + 6,
                        'length': 1,
                    },
                    {
                        'title':
                            f'.{df}.. .... = '
                            f'Don\'t fragment: '
                            f'{"Set" if df else "Not set"}',
                        'offset': offset + 6,
                        'length': 1,
                    },
                    {
                        'title':
                            f'..{mf}. .... = '
                            f'More fragments: '
                            f'{"Set" if mf else "Not set"}',
                        'offset': offset + 6,
                        'length': 1,
                    }
                ]
        },

        {
            'title':
                f'{frag_bits_pretty} = '
                f'Fragment Offset: {frag}',

            'offset': offset + 6,
            'length': 2,
        },

        {
            'title':
                f'Time to Live: {ttl}',

            'offset': offset + 8,
            'length': 1,
        },

        {
            'title':
                f'Protocol: {proto_name} ({proto_num})',

            'offset': offset + 9,
            'length': 1,
        },

        {
            'title':
                f'Header Checksum: '
                f'0x{checksum:04x} '
                f'[validation disabled]',

            'offset': offset + 10,
            'length': 2,
        },

        {
            'title':
                '[Header checksum status: Unverified]',
        },

        {
            'title':
                f'Source Address: {src}',

            'offset': offset + 12,
            'length': 4,
        },

        {
            'title':
                f'Destination Address: {dst}',

            'offset': offset + 16,
            'length': 4,
        },
    ]

    if stream_index >= 0:
        children.append({
            'title': f'[Stream index: {stream_index}]',
        })

    return {
        'title':
            f'Internet Protocol Version 4, '
            f'Src: {src}, '
            f'Dst: {dst}',

        'offset': offset,
        'length': ip_header_len,
        'children': children,
    }

def _ipv6_multicast_scope_name(scope: int) -> str:
    return {
        0: 'Reserved scope',
        1: 'Interface-Local scope',
        2: 'Link-Local scope',
        3: 'Realm-Local scope',
        4: 'Admin-Local scope',
        5: 'Site-Local scope',
        8: 'Organization-Local scope',
        14: 'Global scope',
    }.get(int(scope), f'Scope {int(scope)}')


def _ipv6_address_children(address: str, offset: int, is_source: bool) -> List[Dict[str, Any]]:
    addr_text = str(address or '')
    lower = addr_text.lower()
    try:
        packed = ipaddress.IPv6Address(addr_text).packed
    except Exception:
        packed = b'\x00' * 16

    if addr_text == '::':
        return [
            {'title': '[Address Space: Reserved by IETF]', 'offset': offset, 'length': 16},
            {
                'title': '[Special-Purpose Allocation: Unspecified Address]',
                'offset': offset,
                'length': 16,
                'children': [
                    {'title': f'[Source: {"True" if is_source else "False"}]', 'offset': offset, 'length': 16},
                    {'title': f'[Destination: {"False" if is_source else "True"}]', 'offset': offset, 'length': 16},
                    {'title': '[Forwardable: False]', 'offset': offset, 'length': 16},
                    {'title': '[Globally Reachable: False]', 'offset': offset, 'length': 16},
                    {'title': '[Reserved-by-Protocol: True]', 'offset': offset, 'length': 16},
                ],
            },
        ]

    if lower.startswith('ff'):
        flags = (packed[1] >> 4) & 0x0F
        scope = packed[1] & 0x0F
        return [
            {'title': '[Address Space: Multicast]', 'offset': offset, 'length': 16},
            {
                'title': f'[.... .... {flags:04b} .... = Multicast Flags: 0x{flags:x}]',
                'offset': offset + 1,
                'length': 1,
                'children': [
                    {'title': f'.... .... {(flags >> 3) & 0x1}... .... = Reserved: {(flags >> 3) & 0x1}', 'offset': offset + 1, 'length': 1},
                    {'title': f'.... .... .{(flags >> 2) & 0x1}.. .... = Rendezvous Point (RP): {"True" if ((flags >> 2) & 0x1) else "False"}', 'offset': offset + 1, 'length': 1},
                    {'title': f'.... .... ..{(flags >> 1) & 0x1}. .... = Network Prefix: {"True" if ((flags >> 1) & 0x1) else "False"}', 'offset': offset + 1, 'length': 1},
                    {'title': f'.... .... ...{flags & 0x1} .... = Transient: {"True" if (flags & 0x1) else "False"}', 'offset': offset + 1, 'length': 1},
                ],
            },
            {
                'title': f'[.... .... .... {scope:04b} = Multicast Scope: {_ipv6_multicast_scope_name(scope)} (0x{scope:x})]',
                'offset': offset + 1,
                'length': 1,
            },
        ]

    if lower.startswith('fe80'):
        return [
            {'title': '[Address Space: Link-Local Unicast]', 'offset': offset, 'length': 16},
            {
                'title': '[Special-Purpose Allocation: Link-Local Unicast]',
                'offset': offset,
                'length': 16,
                'children': [
                    {'title': '[Source: True]', 'offset': offset, 'length': 16},
                    {'title': '[Destination: True]', 'offset': offset, 'length': 16},
                    {'title': '[Forwardable: False]', 'offset': offset, 'length': 16},
                    {'title': '[Globally Reachable: False]', 'offset': offset, 'length': 16},
                    {'title': '[Reserved-by-Protocol: True]', 'offset': offset, 'length': 16},
                ],
            },
        ]

    return [{'title': '[Address Space: Global Unicast]', 'offset': offset, 'length': 16}]


def _ipv6_section(layer, offset: int, stream_index: int) -> Dict[str, Any]:

    version = int(getattr(layer, 'version', 6) or 6)

    tc = int(getattr(layer, 'tc', 0) or 0)

    fl = int(getattr(layer, 'fl', 0) or 0)

    plen = int(getattr(layer, 'plen', 0) or 0)

    nh = int(getattr(layer, 'nh', 0) or 0)

    hlim = int(getattr(layer, 'hlim', 0) or 0)

    src = getattr(layer, 'src', '-')

    dst = getattr(layer, 'dst', '-')

    dscp = tc >> 2

    ecn = tc & 0x03

    dscp_names = {
        10: 'AF11',
        12: 'AF12',
        14: 'AF13',
        46: 'EF',
    }

    ecn_names = {
        0: 'Not-ECT',
        1: 'ECT(1)',
        2: 'ECT(0)',
        3: 'CE',
    }

    dscp_name = dscp_names.get(dscp, str(dscp))

    ecn_name = ecn_names.get(ecn, str(ecn))

    next_header_names = {
        0: 'IPv6 Hop-by-Hop Option',
        6: 'TCP',
        17: 'UDP',
        58: 'ICMPv6',
    }

    nh_name = next_header_names.get(nh, str(nh))

    children = [

        {
            'title':
                f'0110 .... = Version: {version}',
            'offset': offset,
            'length': 1,
        },

        {
            'title':
                f'.... {format(tc, "08b")} '
                f'.... .... .... .... .... = '
                f'Traffic Class: '
                f'0x{tc:02x} '
                f'(DSCP: {dscp_name}, ECN: {ecn_name})',
            'offset': offset,
            'length': 2,

            'children': [

                {
                    'title':
                        f'.... {format(dscp, "06b")}.. '
                        f'.... .... .... .... .... = '
                        f'Differentiated Services Codepoint: '
                        f'{dscp_name} ({dscp})',
                    'offset': offset,
                    'length': 2,
                },

                {
                    'title':
                        f'.... .... ..{ecn:02b} '
                        f'.... .... .... .... .... = '
                        f'Explicit Congestion Notification: '
                        f'{ecn_name} ({ecn})',
                    'offset': offset,
                    'length': 2,
                }
            ]
        },

        {
            'title':
                f'.... {format(fl, "020b")} = '
                f'Flow Label: 0x{fl:05x}',
            'offset': offset + 1,
            'length': 3,
        },

        {
            'title':
                f'Payload Length: {plen}',
            'offset': offset + 4,
            'length': 2,
        },

        {
            'title':
                f'Next Header: {nh_name} ({nh})',
            'offset': offset + 6,
            'length': 1,
        },

        {
            'title':
                f'Hop Limit: {hlim}',
            'offset': offset + 7,
            'length': 1,
        },

        {
            'title':
                f'Source Address: {src}',
            'offset': offset + 8,
            'length': 16,

            'children': _ipv6_address_children(src, offset + 8, True),
        },

        {
            'title':
                f'Destination Address: {dst}',
            'offset': offset + 24,
            'length': 16,

            'children': _ipv6_address_children(dst, offset + 24, False),
        },
    ]

    source_slaac_mac = _ipv6_slaac_mac(src)
    destination_slaac_mac = _ipv6_slaac_mac(dst)
    if source_slaac_mac:
        children.append({'title': f'[Source SLAAC MAC: {_mac_display(source_slaac_mac)}]', 'offset': offset + 8, 'length': 16})
    if destination_slaac_mac:
        children.append({'title': f'[Destination SLAAC MAC: {_mac_display(destination_slaac_mac)}]', 'offset': offset + 24, 'length': 16})

    if stream_index >= 0:
        children.append({
            'title': f'[Stream index: {stream_index}]'
        })

    return {

        'title':
            f'Internet Protocol Version 6, '
            f'Src: {src}, Dst: {dst}',

        'offset': offset,
        'length': 40,
        'children': children,
    }

def _tcp_option_length(option) -> int:
    try:
        name, value = option
    except Exception:
        return 1

    if name == 'MSS':
        return 4
    if name == 'NOP':
        return 1
    if name == 'WScale':
        return 3
    if name == 'SAckOK':
        return 2
    if name == 'EOL':
        return 1
    if isinstance(value, (bytes, bytearray)):
        return 2 + len(value)
    return 1


def _tcp_section(layer, offset: int, stream_index: int, record=None) -> Dict[str, Any]:

    sport = int(getattr(layer, 'sport', 0) or 0)
    dport = int(getattr(layer, 'dport', 0) or 0)

    seq = int(getattr(layer, 'seq', 0) or 0)
    ack = int(getattr(layer, 'ack', 0) or 0)

    metadata = getattr(record, 'metadata', {}) if record else {}
    stream_pkt_num = int(metadata.get('tcp_stream_packet_number', 1) or 1)
    relative_seq = int(metadata['tcp_relative_seq']) if 'tcp_relative_seq' in metadata else 1
    relative_ack = int(metadata.get('tcp_relative_ack', 0) or 0)
    options = getattr(layer, 'options', [])

    dataofs = int(getattr(layer, 'dataofs', 5) or 5)

    tcp_header_len = max(dataofs * 4, 20 + sum(_tcp_option_length(option) for option in options))

    window = int(getattr(layer, 'window', 0) or 0)

    checksum = int(getattr(layer, 'chksum', 0) or 0)

    urgptr = int(getattr(layer, 'urgptr', 0) or 0)

    payload = _tcp_payload_bytes(getattr(record, 'raw', None), layer)
    payload_len = len(payload)

    payload_hex = payload.hex()

    # ---- FLAGS ----

    flags = int(getattr(layer, 'flags', 0) or 0)

    flag_bits = {
        'FIN': flags & 0x01,
        'SYN': (flags >> 1) & 0x01,
        'RST': (flags >> 2) & 0x01,
        'PSH': (flags >> 3) & 0x01,
        'ACK': (flags >> 4) & 0x01,
        'URG': (flags >> 5) & 0x01,
        'ECE': (flags >> 6) & 0x01,
        'CWR': (flags >> 7) & 0x01,
    }

    set_flags = [
        name for name, value in flag_bits.items()
        if value
    ]

    flags_text = ', '.join(set_flags) if set_flags else 'None'

    next_seq_fallback = relative_seq + payload_len + (1 if flag_bits['SYN'] else 0) + (1 if flag_bits['FIN'] else 0)
    next_seq = int(metadata.get('tcp_next_seq', next_seq_fallback) or next_seq_fallback)

    stream_completeness = int(metadata.get('tcp_completeness_flags', 0) or 0)
    completeness_rst = 32 if (stream_completeness & 32) else 0
    completeness_fin = 16 if (stream_completeness & 16) else 0
    completeness_data = 8 if (stream_completeness & 8) else 0
    completeness_ack = 4 if (stream_completeness & 4) else 0
    completeness_synack = 2 if (stream_completeness & 2) else 0
    completeness_syn = 1 if (stream_completeness & 1) else 0
    completeness_flags = (
        completeness_rst
        + completeness_fin
        + completeness_data
        + completeness_ack
        + completeness_synack
        + completeness_syn
    )

    completeness_label = f'Incomplete ({completeness_flags})'
    if completeness_flags == 63:
        completeness_label = 'Complete (63)'
    elif completeness_flags == 31:
        completeness_label = 'Complete, WITH_DATA (31)'
    elif completeness_flags == 15:
        completeness_label = 'Incomplete, DATA (15)'

    completeness_marks = ''.join([
        'R' if completeness_rst else '·',
        'F' if completeness_fin else '·',
        'D' if completeness_data else '·',
        'A' if completeness_ack else '·',
        'S' if completeness_synack else '·',
        'S' if completeness_syn else '·',
    ])

    tcp_flag_marks = ''.join([
        '·',  # Reserved
        '·',  # Reserved
        '·',  # Reserved
        '·',  # Accurate ECN
        'C' if flag_bits['CWR'] else '·',
        'E' if flag_bits['ECE'] else '·',
        'U' if flag_bits['URG'] else '·',
        'A' if flag_bits['ACK'] else '·',
        'P' if flag_bits['PSH'] else '·',
        'R' if flag_bits['RST'] else '·',
        'S' if flag_bits['SYN'] else '·',
        'F' if flag_bits['FIN'] else '·',
    ])

    tcp_time_since_first = float(metadata.get('tcp_time_since_first', 0.0) or 0.0)
    tcp_time_since_prev = float(metadata.get('tcp_time_since_prev', 0.0) or 0.0)
    client_contiguous = int(metadata.get('tcp_client_contiguous_streams', 0) or 0)
    server_contiguous = int(metadata.get('tcp_server_contiguous_streams', 0) or 0)

    ack_frame_number = metadata.get('tcp_ack_frame_number', None)
    ack_rtt_ms = metadata.get('tcp_ack_rtt_ms', None)
    ack_ambiguous = bool(metadata.get('tcp_ack_ambiguous', False))
    duplicate_ack = bool(metadata.get('tcp_is_duplicate_ack', False))
    duplicate_ack_count = metadata.get('tcp_duplicate_ack_count', None)
    duplicate_ack_frame_number = metadata.get('tcp_duplicate_ack_frame_number', None)
    window_update = bool(metadata.get('tcp_is_window_update', False))
    previous_segment_not_captured = bool(metadata.get('tcp_previous_segment_not_captured', False))
    bytes_in_flight = metadata.get('tcp_bytes_in_flight', None)
    bytes_since_last_psh = metadata.get('tcp_bytes_since_last_psh', None)
    is_retransmission = bool(metadata.get('tcp_is_retransmission', False))
    protocol_name = str(getattr(record, 'protocol', '') or '').upper() if record else ''
    has_ack_flag = bool(flag_bits['ACK'])
    is_syn_packet = bool(flag_bits['SYN'])
    window_scale_shift = metadata.get('tcp_window_scale_shift', None)
    window_scaling_disabled = bool(metadata.get('tcp_window_scaling_disabled', False))
    calculated_window = int(window)
    window_scale_title = '[Window size scaling factor: -1 (unknown)]'
    if is_syn_packet:
        window_scale_title = ''
    elif window_scale_shift is not None:
        multiplier = 1 << int(window_scale_shift)
        calculated_window = int(window) * multiplier
        window_scale_title = f'[Window size scaling factor: {multiplier}]'
    elif window_scaling_disabled:
        window_scale_title = '[Window size scaling factor: -2 (no window scaling used)]'

    children = [

        {
            'title': f'Source Port: {sport}',
            'offset': offset,
            'length': 2,
        },

        {
            'title': f'Destination Port: {dport}',
            'offset': offset + 2,
            'length': 2,
        },

        {
            'title': f'Sequence Number: {relative_seq}    (relative sequence number)',
            'offset': offset + 4,
            'length': 4,
        },

        {
            'title': f'Sequence Number (raw): {seq}',
            'offset': offset + 4,
            'length': 4,
        },

        {
            'title': f'Acknowledgment Number: {relative_ack}    (relative ack number)' if has_ack_flag else f'Acknowledgment Number: {ack}',
            'offset': offset + 8,
            'length': 4,
        },

        {
            'title': f'Acknowledgment number (raw): {ack}',
            'offset': offset + 8,
            'length': 4,
        },

        {
            'title':
                f'{dataofs:04b} .... = '
                f'Header Length: {tcp_header_len} bytes ({dataofs})',

            'offset': offset + 12,
            'length': 1,
        },

        {
            'title':
                f'Flags: 0x{flags:03x} ({flags_text})',
            'offset': offset + 12,
            'length': 2,
            'children': [
                {
                    'title': '000. .... .... = Reserved: Not set',
                    'offset': offset + 12,
                    'length': 1,
                },
                {
                    'title': '...0 .... .... = Accurate ECN: Not set',
                    'offset': offset + 12,
                    'length': 1,
                },
                {
                    'title':
                        f'.... {"1" if flag_bits["CWR"] else "0"}... .... = '
                        f'Congestion Window Reduced: '
                        f'{"Set" if flag_bits["CWR"] else "Not set"}',
                    'offset': offset + 13,
                    'length': 1,
                },
                {
                    'title':
                        f'.... .{"1" if flag_bits["ECE"] else "0"}.. .... = '
                        f'ECN-Echo: '
                        f'{"Set" if flag_bits["ECE"] else "Not set"}',
                    'offset': offset + 13,
                    'length': 1,
                },
                {
                    'title':
                        f'.... ..{"1" if flag_bits["URG"] else "0"}. .... = '
                        f'Urgent: '
                        f'{"Set" if flag_bits["URG"] else "Not set"}',
                    'offset': offset + 13,
                    'length': 1,
                },
                {
                    'title':
                        f'.... ...{"1" if flag_bits["ACK"] else "0"} .... = '
                        f'Acknowledgment: '
                        f'{"Set" if flag_bits["ACK"] else "Not set"}',
                    'offset': offset + 13,
                    'length': 1,
                },
                {
                    'title':
                        f'.... .... {"1" if flag_bits["PSH"] else "0"}... = '
                        f'Push: '
                        f'{"Set" if flag_bits["PSH"] else "Not set"}',
                    'offset': offset + 13,
                    'length': 1,
                },
                {
                    'title':
                        f'.... .... .{"1" if flag_bits["RST"] else "0"}.. = '
                        f'Reset: '
                        f'{"Set" if flag_bits["RST"] else "Not set"}',
                    'offset': offset + 13,
                    'length': 1,
                },
                {
                    'title':
                        f'.... .... ..{"1" if flag_bits["SYN"] else "0"}. = '
                        f'Syn: '
                        f'{"Set" if flag_bits["SYN"] else "Not set"}',
                    'offset': offset + 13,
                    'length': 1,
                },
                {
                    'title':
                        f'.... .... ...{"1" if flag_bits["FIN"] else "0"} = '
                        f'Fin: '
                        f'{"Set" if flag_bits["FIN"] else "Not set"}',
                    'offset': offset + 13,
                    'length': 1,
                },
                {
                    'title': f'[TCP Flags: {tcp_flag_marks}]',
                },
            ]
        },

        {
            'title': f'Window: {window}',
            'offset': offset + 14,
            'length': 2,
        },

        {
            'title': f'[Calculated window size: {calculated_window}]',
        },

        {
            'title': window_scale_title,
        },

        {
            'title':
                f'Checksum: 0x{checksum:04x} [unverified]',

            'offset': offset + 16,
            'length': 2,
        },

        {
            'title':
                '[Checksum Status: Unverified]',
        },

        {
            'title':
                f'Urgent Pointer: {urgptr}',

            'offset': offset + 18,
            'length': 2,
        },
    ]

    stream_intro = []
    if stream_index >= 0:
        stream_intro.extend([
            {
                'title': f'[Stream index: {stream_index}]',
            },
            {
                'title': f'[Stream Packet Number: {stream_pkt_num}]',
            },
            {
                'title': f'[Conversation completeness: {completeness_label}]',
                'children': [
                    {
                        'title': f'..{"1" if completeness_rst else "0"}. .... = RST: {"Present" if completeness_rst else "Absent"}',
                    },
                    {
                        'title': f'...{"1" if completeness_fin else "0"} .... = FIN: {"Present" if completeness_fin else "Absent"}',
                    },
                    {
                        'title': f'.... {"1" if completeness_data else "0"}... = Data: {"Present" if completeness_data else "Absent"}',
                    },
                    {
                        'title': f'.... .{"1" if completeness_ack else "0"}.. = ACK: {"Present" if completeness_ack else "Absent"}',
                    },
                    {
                        'title': f'.... ..{"1" if completeness_synack else "0"}. = SYN-ACK: {"Present" if completeness_synack else "Absent"}',
                    },
                    {
                        'title': f'.... ...{"1" if completeness_syn else "0"} = SYN: {"Present" if completeness_syn else "Absent"}',
                    },
                    {
                        'title': f'[Completeness Flags: {completeness_marks}]',
                    },
                ],
            },
        ])

    ordered_children = []
    ordered_children.extend(children[:2])
    ordered_children.extend(stream_intro)
    ordered_children.append({
        'title': '[TCP Segment Len: ' f'{payload_len}]',
    })
    ordered_children.extend([
        children[2],
        children[3],
        {'title': f'[Next Sequence Number: {next_seq}    (relative sequence number)]'},
        children[4],
        children[5],
        children[6],
        children[7],
        children[8],
        children[9],
    ])
    if children[10].get('title'):
        ordered_children.append(children[10])
    ordered_children.extend([
        children[11],
        children[12],
        children[13],
    ])
    ordered_children.append({
        'title': '[Timestamps]',
        'children': [
            {
                'title': f'[Time since first frame in this TCP stream: {tcp_time_since_first:.9f} seconds]',
            },
            {
                'title': f'[Time since previous frame in this TCP stream: {tcp_time_since_prev:.9f} seconds]',
            },
        ],
    })
    seq_ack_children = []
    if is_retransmission:
        seq_ack_children.append({
            'title': '[TCP Analysis Flags]',
            'children': [
                {
                    'title': '[Expert Info (Note/Sequence): This frame is a (suspected) retransmission]',
                    'children': [
                        {'title': '[This frame is a (suspected) retransmission]'},
                        {'title': '[Severity level: Note]'},
                        {'title': '[Group: Sequence]'},
                    ],
                },
            ],
        })
    elif duplicate_ack:
        seq_ack_children.append({
            'title': '[TCP Analysis Flags]',
            'children': [
                {
                    'title': '[This is a TCP duplicate ack]',
                },
            ],
        })
        if duplicate_ack_count is not None:
            seq_ack_children.append({
                'title': f'[Duplicate ACK #: {int(duplicate_ack_count)}]',
            })
        if duplicate_ack_frame_number is not None:
            seq_ack_children.append({
                'title': f'[Duplicate to the ACK in frame: {int(duplicate_ack_frame_number)}]',
                'children': [
                    {
                        'title': f'[Expert Info (Note/Sequence): Duplicate ACK (#{int(duplicate_ack_count or 1)})]',
                        'children': [
                            {'title': f'[Duplicate ACK (#{int(duplicate_ack_count or 1)})]'},
                            {'title': '[Severity level: Note]'},
                            {'title': '[Group: Sequence]'},
                        ],
                    },
                ],
            })
    elif window_update:
        seq_ack_children.append({
            'title': '[TCP Analysis Flags]',
            'children': [
                {
                    'title': '[Expert Info (Chat/Sequence): TCP window update]',
                    'children': [
                        {'title': '[TCP window update]'},
                        {'title': '[Severity level: Chat]'},
                        {'title': '[Group: Sequence]'},
                    ],
                },
            ],
        })
    if ack_frame_number is not None:
        ack_child = {
            'title': f'[This is an ACK to the segment in frame: {int(ack_frame_number)}]',
        }
        if ack_ambiguous:
            ack_child['children'] = [
                {
                    'title': "[Expert Info (Note/Sequence): Ambiguous ACK following Karn's definition]",
                    'children': [
                        {"title": "[Ambiguous ACK following Karn's definition]"},
                        {'title': '[Severity level: Note]'},
                        {'title': '[Group: Sequence]'},
                    ],
                },
            ]
        seq_ack_children.append(ack_child)
    if ack_rtt_ms is not None:
        seq_ack_children.append({
            'title': f'[The RTT to ACK the segment was: {float(ack_rtt_ms):.6f} milliseconds]',
        })
    if previous_segment_not_captured:
        seq_ack_children.append({
            'title': '[TCP Analysis Flags]',
            'children': [
                {
                    'title': '[Expert Info (Warning/Sequence): Previous segment(s) not captured (common at capture start)]',
                    'children': [
                        {'title': '[Previous segment(s) not captured (common at capture start)]'},
                        {'title': '[Severity level: Warning]'},
                        {'title': '[Group: Sequence]'},
                    ],
                },
            ],
        })
    if bytes_in_flight is not None:
        seq_ack_children.append({
            'title': f'[Bytes in flight: {int(bytes_in_flight)}]',
        })
    if bytes_since_last_psh is not None:
        seq_ack_children.append({
            'title': f'[Bytes sent since last PSH flag: {int(bytes_since_last_psh)}]',
        })

    if seq_ack_children:
        ordered_children.append({
            'title': '[SEQ/ACK analysis]',
            'children': seq_ack_children,
        })
    ordered_children.append({
        'title': f'[Client Contiguous Streams: {client_contiguous}]',
    })
    ordered_children.append({
        'title': f'[Server Contiguous Streams: {server_contiguous}]',
    })

    children = ordered_children

    # ---- TCP OPTIONS ----

    if options:

        option_children = []
        option_titles = []
        option_offset = offset + 20

        for opt in options:

            try:

                name, value = opt
                if name == 'MSS':
                    option_titles.append('Maximum segment size')
                    option_children.append({
                        'title': f'TCP Option - Maximum segment size: {int(value)} bytes',
                        'offset': option_offset,
                        'length': 4,
                        'children': [
                            {'title': 'Kind: Maximum Segment Size (2)', 'offset': option_offset, 'length': 1},
                            {'title': 'Length: 4', 'offset': option_offset + 1, 'length': 1},
                            {'title': f'MSS Value: {int(value)}', 'offset': option_offset + 2, 'length': 2},
                        ],
                    })
                    option_offset += 4
                elif name == 'NOP':
                    option_titles.append('No-Operation (NOP)')
                    option_children.append({
                        'title': 'TCP Option - No-Operation (NOP)',
                        'offset': option_offset,
                        'length': 1,
                        'children': [
                            {'title': 'Kind: No-Operation (1)', 'offset': option_offset, 'length': 1},
                        ],
                    })
                    option_offset += 1
                elif name == 'WScale':
                    multiplier = 1 << int(value)
                    option_titles.append('Window scale')
                    option_children.append({
                        'title': f'TCP Option - Window scale: {int(value)} (multiply by {multiplier})',
                        'offset': option_offset,
                        'length': 3,
                        'children': [
                            {'title': 'Kind: Window Scale (3)', 'offset': option_offset, 'length': 1},
                            {'title': 'Length: 3', 'offset': option_offset + 1, 'length': 1},
                            {'title': f'Shift count: {int(value)}', 'offset': option_offset + 2, 'length': 1},
                            {'title': f'[Multiplier: {multiplier}]'},
                        ],
                    })
                    option_offset += 3
                elif name == 'SAckOK':
                    option_titles.append('SACK permitted')
                    option_children.append({
                        'title': 'TCP Option - SACK permitted',
                        'offset': option_offset,
                        'length': 2,
                        'children': [
                            {'title': 'Kind: SACK Permitted (4)', 'offset': option_offset, 'length': 1},
                            {'title': 'Length: 2', 'offset': option_offset + 1, 'length': 1},
                        ],
                    })
                    option_offset += 2
                else:
                    option_children.append({
                        'title': f'{name}: {value}'
                    })

            except Exception:

                option_children.append({
                    'title': str(opt)
                })

        children.append({

            'title': f'Options: ({max(0, tcp_header_len - 20)} bytes), ' + ', '.join(option_titles) if option_titles else 'Options',

            'offset': offset + 20,

            'length': max(0, tcp_header_len - 20),

            'children': option_children
        })

    # ---- PAYLOAD ----

    if payload_len > 0:
        children.append({
            'title': f'TCP payload ({payload_len} bytes)',
            'offset': offset + tcp_header_len,
            'length': payload_len,
        })
        if is_retransmission:
            children.append({
                'title': f'Retransmitted TCP segment data ({payload_len} bytes)',
                'offset': offset + tcp_header_len,
                'length': payload_len,
            })
        elif metadata.get('tcp_reassembled_pdu_in_frame', None) is not None:
            children.append({
                'title': f'[Reassembled PDU in frame: {int(metadata.get("tcp_reassembled_pdu_in_frame"))}]',
            })
            children.append({
                'title': f'TCP segment data ({payload_len} bytes)',
                'offset': offset + tcp_header_len,
                'length': payload_len,
            })
        elif metadata.get('tcp_reassembled_segments', None) or metadata.get('http_reassembled_segments', None):
            children.append({
                'title': f'TCP segment data ({payload_len} bytes)',
                'offset': offset + tcp_header_len,
                'length': payload_len,
            })
        elif protocol_name == 'BGP':
            children.append({
                'title': f'[PDU Size: {payload_len}]',
            })

    tcp_title = (
        f'Transmission Control Protocol, '
        f'Src Port: {sport}, '
        f'Dst Port: {dport}, '
        f'Seq: {relative_seq}, '
        + (f'Ack: {relative_ack}, ' if has_ack_flag else '')
        + f'Len: {payload_len}'
    )

    return {

        'title': tcp_title,

        'offset': offset,
        'length': tcp_header_len,
        'children': children,
    }


def _tcp_reassembly_section(record) -> Dict[str, Any] | None:
    metadata = getattr(record, 'metadata', {}) or {}
    segments = list(
        metadata.get('tcp_reassembled_segments', [])
        or metadata.get('http_reassembled_segments', [])
        or []
    )
    if not segments:
        return None

    reassembled_len = int(
        metadata.get('tcp_reassembled_length', 0)
        or metadata.get('http_reassembled_length', 0)
        or 0
    )
    if reassembled_len <= 0:
        reassembled_len = int(sum(int(segment.get('payload_length', 0) or 0) for segment in segments))

    segment_summary = ', '.join(
        f"#{int(segment.get('frame_number', 0) or 0)}({int(segment.get('payload_length', 0) or 0)})"
        for segment in segments
    )
    children = []
    for segment in segments:
        start_pos = int(segment.get('payload_start', 0) or 0)
        seg_len = int(segment.get('payload_length', 0) or 0)
        end_pos = max(start_pos, start_pos + seg_len - 1)
        children.append({
            'title': f"[Frame: {int(segment.get('frame_number', 0) or 0)}, payload: {start_pos}-{end_pos} ({seg_len} bytes)]",
            **_byte_mapping(0, start_pos, seg_len, TCP_REASSEMBLED_BYTE_SOURCE),
        })
    children.append({'title': f'[Segment count: {len(segments)}]'})
    children.append({
        'title': f'[Reassembled TCP length: {reassembled_len}]',
        **_byte_mapping(0, 0, reassembled_len, TCP_REASSEMBLED_BYTE_SOURCE),
    })

    reassembly_hex = str(metadata.get('tcp_reassembled_data_hex', '') or '')
    if not reassembly_hex:
        reassembly_payload = bytes(metadata.get('http_reassembled_payload', b'') or b'')
        reassembly_hex = reassembly_payload.hex() if reassembly_payload else ''
    if reassembly_hex:
        children.append({
            'title': f'[Reassembled TCP Data […]: {reassembly_hex[:160]}]',
            **_byte_mapping(0, 0, reassembled_len, TCP_REASSEMBLED_BYTE_SOURCE),
        })

    return {
        'title': f'[{len(segments)} Reassembled TCP Segments ({reassembled_len} bytes): {segment_summary}]',
        **_byte_mapping(0, 0, reassembled_len, TCP_REASSEMBLED_BYTE_SOURCE),
        'children': children,
    }


def _http_payload_lines(payload: bytes) -> List[tuple[str, int, int, bytes]]:
    lines = []
    pos = 0
    while pos < len(payload):
        end = payload.find(b'\r\n', pos)
        if end == -1:
            raw_line = payload[pos:]
            lines.append((raw_line.decode(errors='ignore'), pos, len(raw_line), raw_line))
            break
        raw_line = payload[pos:end]
        total_len = (end + 2) - pos
        lines.append((raw_line.decode(errors='ignore') + '\\r\\n', pos, total_len, raw_line))
        pos = end + 2
        if raw_line == b'':
            break
    return lines


def _http_body_lines(payload: bytes) -> List[str]:
    if not payload:
        return []
    body_lines = []
    for raw_line in payload.splitlines(keepends=True):
        text = raw_line.decode(errors='ignore')
        text = text.replace('\t', '\\t').replace('\r', '\\r').replace('\n', '\\n')
        body_lines.append(text)
    return body_lines


def _http_status_description(code: str) -> str:
    return {
        '200': 'OK',
        '301': 'Moved Permanently',
        '302': 'Found',
        '400': 'Bad Request',
        '404': 'Not Found',
        '500': 'Internal Server Error',
    }.get(str(code), '')


def _http_section(payload: bytes, offset: int, record=None) -> Dict[str, Any]:
    metadata = getattr(record, 'metadata', {}) if record else {}
    http_payload = metadata.get('http_reassembled_payload', payload)
    lines = _http_payload_lines(http_payload)
    children = []
    use_offsets = not bool(metadata.get('http_is_reassembled', False))
    byte_source = PACKET_BYTE_SOURCE if use_offsets else TCP_REASSEMBLED_BYTE_SOURCE
    header_length = int(metadata.get('http_header_len', 0) or 0)

    if lines:
        first_text, first_offset, first_length, first_raw = lines[0]
        first_line = first_raw.decode(errors='ignore')
        if first_line.startswith('HTTP/'):
            parts = first_line.split(' ', 2)
            response_children = []
            if len(parts) >= 2:
                version = parts[0]
                status_code = parts[1]
                reason = parts[2] if len(parts) > 2 else ''
                response_children = [
                    {
                        'title': f'Response Version: {version}',
                        **_byte_mapping(offset, first_offset, len(version), byte_source),
                    },
                    {
                        'title': f'Status Code: {status_code}',
                        **_byte_mapping(offset, first_offset + len(version) + 1, len(status_code), byte_source),
                    },
                ]
                description = _http_status_description(status_code)
                if description:
                    response_children.append({'title': f'[Status Code Description: {description}]'})
                if reason:
                    response_children.append({
                        'title': f'Response Phrase: {reason}',
                        **_byte_mapping(
                            offset,
                            first_offset + len(version) + 1 + len(status_code) + 1,
                            len(reason),
                            byte_source,
                        ),
                    })
            children.append({
                'title': first_text,
                **_byte_mapping(offset, first_offset, first_length, byte_source),
                'children': response_children,
            })
        else:
            parts = first_line.split(' ', 2)
            request_children = []
            if len(parts) == 3:
                method, uri, version = parts
                method_len = len(method)
                uri_len = len(uri)
                version_len = len(version)
                request_children = [
                    {
                        'title': f'Request Method: {method}',
                        **_byte_mapping(offset, first_offset, method_len, byte_source),
                    },
                    {
                        'title': f'Request URI: {uri}',
                        **_byte_mapping(offset, first_offset + method_len + 1, uri_len, byte_source),
                    },
                    {
                        'title': f'Request Version: {version}',
                        **_byte_mapping(
                            offset,
                            first_offset + method_len + 1 + uri_len + 1,
                            version_len,
                            byte_source,
                        ),
                    },
                ]
            children.append({
                'title': first_text,
                **_byte_mapping(offset, first_offset, first_length, byte_source),
                'children': request_children,
            })

        for line_text, line_offset, line_length, line_raw in lines[1:]:
            title = line_text if line_raw != b'' else '\\r\\n'
            item = {
                'title': title,
                **_byte_mapping(offset, line_offset, line_length, byte_source),
            }
            if line_raw.lower().startswith(b'content-length:'):
                try:
                    content_length = int(line_raw.split(b':', 1)[1].strip() or b'0')
                    value_offset = int(line_raw.find(b':')) + 1
                    while value_offset < len(line_raw) and line_raw[value_offset:value_offset + 1] == b' ':
                        value_offset += 1
                    item['children'] = [{
                        'title': f'[Content length: {content_length}]',
                        **_byte_mapping(offset, line_offset + value_offset, len(line_raw) - value_offset, byte_source),
                    }]
                except Exception:
                    pass
            children.append(item)

    response_frame = metadata.get('http_response_frame', None)
    if response_frame is not None:
        children.append({'title': f'[Response in frame: {int(response_frame)}]'})

    request_frame = metadata.get('http_request_frame', None)
    if request_frame is not None:
        children.append({'title': f'[Request in frame: {int(request_frame)}]'})

    time_since_request = metadata.get('http_time_since_request_ms', None)
    if time_since_request is not None:
        children.append({'title': f'[Time since request: {float(time_since_request):.6f} milliseconds]'})

    request_uri = str(metadata.get('http_request_uri', '') or '').strip()
    if request_uri:
        children.append({'title': f'[Request URI: {request_uri}]'})

    full_request_uri = metadata.get('http_full_request_uri', '')
    if full_request_uri:
        children.append({'title': f'[Full request URI: {full_request_uri}]'})

    content_length = metadata.get('http_content_length', None)
    if content_length is not None and int(content_length) > 0:
        body = bytes(metadata.get('http_body', b'') or b'')
        body_offset = int(metadata.get('http_header_len', 0) or 0)
        body_len = len(body) if body else int(content_length)
        children.append({
            'title': f'File Data: {int(content_length)} bytes',
            **_byte_mapping(offset, body_offset, body_len, byte_source),
        })

    return {
        'title': 'Hypertext Transfer Protocol',
        **_byte_mapping(offset, 0, header_length or len(http_payload), byte_source),
        'children': children,
    }


def _http_line_based_text_section(record, offset: int) -> Dict[str, Any]:
    metadata = getattr(record, 'metadata', {}) or {}
    content_type = str(metadata.get('http_content_type', '') or '').strip() or 'text/plain'
    body = bytes(metadata.get('http_body', b'') or b'')
    byte_source = PACKET_BYTE_SOURCE if not bool(metadata.get('http_is_reassembled', False)) else TCP_REASSEMBLED_BYTE_SOURCE
    body_offset = int(metadata.get('http_header_len', 0) or 0)
    lines = []
    cursor = 0
    for raw_line in body.splitlines(keepends=True):
        text = raw_line.decode(errors='ignore')
        text = text.replace('\t', '\\t').replace('\r', '\\r').replace('\n', '\\n')
        lines.append({
            'title': text,
            **_byte_mapping(offset, body_offset + cursor, len(raw_line), byte_source),
        })
        cursor += len(raw_line)
    return {
        'title': f'Line-based text data: {content_type} ({len(lines)} lines)',
        **_byte_mapping(offset, body_offset, len(body), byte_source),
        'children': lines,
    }


def _udp_section(layer, offset: int, stream_index: int, record=None) -> Dict[str, Any]:

    sport = getattr(layer, "sport", 0)

    dport = getattr(layer, "dport", 0)

    udp_len = int(
        getattr(layer, "len", 8) or 8
    )

    checksum = int(
        getattr(layer, "chksum", 0) or 0
    )

    metadata = getattr(record, 'metadata', {}) if record else {}
    stream_pkt_num = int(metadata.get('udp_stream_packet_number', 1) or 1)
    udp_time_since_first = float(metadata.get('udp_time_since_first', 0.0) or 0.0)
    udp_time_since_prev = float(metadata.get('udp_time_since_prev', 0.0) or 0.0)

    checksum_title = f'Checksum: 0x{checksum:04x} [unverified]'
    checksum_status = '[Checksum Status: Unverified]'
    if checksum == 0:
        checksum_title = f'Checksum: 0x{checksum:04x} [zero-value ignored]'
        checksum_status = '[Checksum Status: Not present]'

    children = [

        {
            'title': f'Source Port: {sport}',

            'offset': offset,
            'length': 2,
        },

        {
            'title': f'Destination Port: {dport}',

            'offset': offset + 2,
            'length': 2,
        },

        {
            'title': f'Length: {udp_len}',

            'offset': offset + 4,
            'length': 2,
        },

        {
            'title': checksum_title,

            'offset': offset + 6,
            'length': 2,
        },

        {
            'title': checksum_status,
        },
    ]

    if stream_index >= 0:
        children.append({
            'title': f'[Stream index: {stream_index}]',
        })

    children.extend([
        {
            'title':
                f'[Stream Packet Number: {stream_pkt_num}]',
        },

        {
            'title':
                '[Timestamps]',

            'children': [

                {
                    'title':
                        (
                            f'[Time since first frame: '
                            f'{udp_time_since_first:.9f} seconds]'
                        )
                },

                {
                    'title':
                        '[Time since previous frame: '
                        f'{udp_time_since_prev:.9f} seconds]'
                }
            ]
        }
    ])

    payload_len = max(0, udp_len - 8)

    if payload_len > 0:

        children.append({

            'title':
                f'UDP payload ({payload_len} bytes)',

            'offset': offset + 8,
            'length': payload_len,
        })

    return {

        'title':
            f'User Datagram Protocol, '
            f'Src Port: {sport}, '
            f'Dst Port: {dport}',

        'offset': offset,
        'length': 8,

        'children': children,
    }


def _capwap_vendor_display(vendor_name: str, vendor_id: int) -> str:
    name = str(vendor_name or '').strip()
    if name and name != 'Unknown':
        return f'{name} ({vendor_id})'
    return f'Unknown ({vendor_id})'


def _capwap_tree_node(
    title: str,
    offset: int | None = None,
    length: int | None = None,
    children: List[Dict[str, Any]] | None = None,
) -> Dict[str, Any]:
    node: Dict[str, Any] = {'title': title}
    if offset is not None and length is not None:
        node['offset'] = offset
        node['length'] = length
    if children is not None:
        node['children'] = children
    return node


def _wlan_bits_pattern(width: int, start_bit: int, bit_length: int, value: int) -> str:
    chars = ['.'] * max(0, int(width))
    width = len(chars)
    start_bit = int(start_bit)
    bit_length = int(bit_length)
    if bit_length <= 0 or start_bit < 0 or start_bit + bit_length > width:
        return ' '.join(''.join(chars[index:index + 4]) for index in range(0, width, 4))
    bits = format(int(value), f'0{bit_length}b')
    left_index = width - (start_bit + bit_length)
    chars[left_index:left_index + bit_length] = list(bits)
    return ' '.join(''.join(chars[index:index + 4]) for index in range(0, width, 4))


def _wlan_mac_display(mac: str) -> str:
    mac_text = str(mac or '')
    vendor = get_mac_vendor(mac_text)
    if vendor:
        suffix = ':'.join(mac_text.split(':')[-3:])
        return f'{vendor}_{suffix} ({mac_text})'
    return f'{mac_text} ({mac_text})'


def _wlan_mac_bit_children(mac: str, offset: int) -> List[Dict[str, Any]]:
    mac_text = str(mac or '')
    try:
        first_octet = int(mac_text.split(':', 1)[0], 16)
    except Exception:
        first_octet = 0
    local = bool(first_octet & 0x02)
    group = bool(first_octet & 0x01)
    return [
        {
            'title': f'.... ..{"1" if local else "0"}. .... .... .... .... = LG bit: {"Locally administered" if local else "Globally unique"} address ({"this is NOT the factory default" if local else "factory default"})',
            'offset': offset,
            'length': 3,
        },
        {
            'title': f'.... ...{"1" if group else "0"} .... .... .... .... = IG bit: {"Group" if group else "Individual"} address ({"multicast/broadcast" if group else "unicast"})',
            'offset': offset,
            'length': 3,
        },
    ]


def _wlan_address_node(title: str, mac: str, offset: int) -> Dict[str, Any]:
    return {
        'title': f'{title}: {_wlan_mac_display(mac)}',
        'offset': offset,
        'length': 6,
        'children': _wlan_mac_bit_children(mac, offset),
    }


def _wlan_flag_children(flags: int, offset: int) -> List[Dict[str, Any]]:
    ds_status = int(flags) & 0x03
    ds_status_label = {
        0: 'Not leaving DS or network is operating in AD-HOC mode (To DS: 0 From DS: 0)',
        1: 'Frame destined for distribution system (To DS: 1 From DS: 0)',
        2: 'Frame exiting distribution system (To DS: 0 From DS: 1)',
        3: 'WDS frame being distributed from one AP to another AP (To DS: 1 From DS: 1)',
    }.get(ds_status, 'Unknown DS status')
    return [
        {'title': f'{_wlan_bits_pattern(8, 0, 2, ds_status)} = DS status: {ds_status_label} (0x{ds_status:x})', 'offset': offset, 'length': 1},
        {'title': f'{_wlan_bits_pattern(8, 2, 1, 1 if int(flags) & 0x04 else 0)} = More Fragments: {"This is not the last fragment" if int(flags) & 0x04 else "This is the last fragment"}', 'offset': offset, 'length': 1},
        {'title': f'{_wlan_bits_pattern(8, 3, 1, 1 if int(flags) & 0x08 else 0)} = Retry: {"Frame is being retransmitted" if int(flags) & 0x08 else "Frame is not being retransmitted"}', 'offset': offset, 'length': 1},
        {'title': f'{_wlan_bits_pattern(8, 4, 1, 1 if int(flags) & 0x10 else 0)} = PWR MGT: {"STA will go to sleep" if int(flags) & 0x10 else "STA will stay up"}', 'offset': offset, 'length': 1},
        {'title': f'{_wlan_bits_pattern(8, 5, 1, 1 if int(flags) & 0x20 else 0)} = More Data: {"Data is buffered for STA at AP" if int(flags) & 0x20 else "No data buffered"}', 'offset': offset, 'length': 1},
        {'title': f'{_wlan_bits_pattern(8, 6, 1, 1 if int(flags) & 0x40 else 0)} = Protected flag: {"Data is protected" if int(flags) & 0x40 else "Data is not protected"}', 'offset': offset, 'length': 1},
        {'title': f'{_wlan_bits_pattern(8, 7, 1, 1 if int(flags) & 0x80 else 0)} = +HTC/Order flag: {"Strictly ordered" if int(flags) & 0x80 else "Not strictly ordered"}', 'offset': offset, 'length': 1},
    ]


def _wlan_capability_children(capabilities: int, offset: int) -> List[Dict[str, Any]]:
    value = int(capabilities)
    items = [
        (0, 'ESS capabilities', 'Transmitter is an AP' if value & 0x0001 else 'Transmitter is a STA'),
        (1, 'IBSS status', 'Transmitter belongs to an IBSS' if value & 0x0002 else 'Transmitter belongs to a BSS'),
        (2, 'Reserved', '0'),
        (3, 'Reserved', '0'),
        (4, 'Privacy', 'Data confidentiality required' if value & 0x0010 else 'Data confidentiality not required'),
        (5, 'Short Preamble', 'Allowed' if value & 0x0020 else 'Not Allowed'),
        (6, 'Critical Update Flag', 'True' if value & 0x0040 else 'False'),
        (7, 'Nontransmitted BSSIDs Critical Update Flag', 'True' if value & 0x0080 else 'False'),
        (8, 'Spectrum Management', 'Implemented' if value & 0x0100 else 'Not Implemented'),
        (9, 'QoS', 'Implemented' if value & 0x0200 else 'Not Implemented'),
        (10, 'Short Slot Time', 'In use' if value & 0x0400 else 'Not in use'),
        (11, 'Automatic Power Save Delivery', 'Implemented' if value & 0x0800 else 'Not Implemented'),
        (12, 'Radio Measurement', 'Implemented' if value & 0x1000 else 'Not Implemented'),
        (13, 'EPD', 'Implemented' if value & 0x2000 else 'Not Implemented'),
        (14, 'Reserved', '0'),
        (15, 'Reserved', '0'),
    ]
    return [
        {
            'title': f'{_wlan_bits_pattern(16, bit, 1, 1 if value & (1 << bit) else 0)} = {label}: {description}',
            'offset': offset,
            'length': 2,
        }
        for bit, label, description in items
    ]


def _wlan_ht_control_node(ht_control: Dict[str, Any], offset: int) -> Dict[str, Any]:
    value = int(ht_control.get('value', 0) or 0)
    lac = int(ht_control.get('link_adaptation_control', 0) or 0)
    calibration_position = int(ht_control.get('calibration_position', 0) or 0)
    calibration_position_label = {
        0: 'No calibration',
        1: 'Calibration Start',
        2: 'Calibration Response',
        3: 'Reserved',
    }.get(calibration_position, f'Calibration Position {calibration_position}')
    csi_steering = int(ht_control.get('csi_steering', 0) or 0)
    csi_label = {
        0: 'No feedback required',
        1: 'Reserved',
        2: 'Reserved',
        3: 'Reserved',
    }.get(csi_steering, f'Value {csi_steering}')
    return {
        'title': f'HT Control (+HTC): 0x{value:08x}',
        'offset': offset,
        'length': 4,
        'children': [
            {'title': f'{_wlan_bits_pattern(32, 0, 1, 1 if bool(ht_control.get("vht", False)) else 0)} = VHT: {bool(ht_control.get("vht", False))}', 'offset': offset, 'length': 4},
            {
                'title': f'{_wlan_bits_pattern(32, 1, 15, lac)} = Link Adaptation Control (LAC): 0x{lac:04x}',
                'offset': offset,
                'length': 4,
                'children': [
                    {'title': f'{_wlan_bits_pattern(16, 11, 1, int(ht_control.get("training_request", 0) or 0))} = Training Request (TRQ): {"Want sounding PPDU" if int(ht_control.get("training_request", 0) or 0) else "Do not want sounding PPDU"}'},
                    {'title': f'{_wlan_bits_pattern(16, 10, 1, int(ht_control.get("mcs_request", 0) or 0))} = MCS Request (MRQ): {"MCS feedback requested" if int(ht_control.get("mcs_request", 0) or 0) else "No MCS feedback requested"}'},
                    {'title': f'{_wlan_bits_pattern(16, 7, 3, int(ht_control.get("lac_reserved", 0) or 0))} = Reserved: 0x{int(ht_control.get("lac_reserved", 0) or 0):x}'},
                    {'title': f'{_wlan_bits_pattern(16, 4, 3, int(ht_control.get("mfsi", 0) or 0))} = MCS Feedback Sequence Identifier (MFSI): {int(ht_control.get("mfsi", 0) or 0)}'},
                    {'title': f'{_wlan_bits_pattern(16, 0, 4, int(ht_control.get("mfb", 0) or 0))} = MCS Feedback (MFB): 0x{int(ht_control.get("mfb", 0) or 0):02x}'},
                ],
            },
            {'title': f'{_wlan_bits_pattern(32, 16, 2, calibration_position)} = Calibration Position: {calibration_position_label} ({calibration_position})', 'offset': offset, 'length': 4},
            {'title': f'{_wlan_bits_pattern(32, 18, 2, int(ht_control.get("calibration_sequence", 0) or 0))} = Calibration Sequence Identifier: {int(ht_control.get("calibration_sequence", 0) or 0)}', 'offset': offset, 'length': 4},
            {'title': f'{_wlan_bits_pattern(32, 20, 2, int(ht_control.get("reserved_mid", 0) or 0))} = Reserved: 0x{int(ht_control.get("reserved_mid", 0) or 0):x}', 'offset': offset, 'length': 4},
            {'title': f'{_wlan_bits_pattern(32, 22, 2, csi_steering)} = CSI/Steering: {csi_label} ({csi_steering})', 'offset': offset, 'length': 4},
            {'title': f'{_wlan_bits_pattern(32, 24, 1, 1 if bool(ht_control.get("ndp_announcement", False)) else 0)} = NDP Announcement: {"NDP will follow" if bool(ht_control.get("ndp_announcement", False)) else "No NDP will follow"}', 'offset': offset, 'length': 4},
            {'title': f'{_wlan_bits_pattern(32, 25, 5, int(ht_control.get("reserved_upper", 0) or 0))} = Reserved: 0x{int(ht_control.get("reserved_upper", 0) or 0):02x}', 'offset': offset, 'length': 4},
            {'title': f'{_wlan_bits_pattern(32, 30, 1, 1 if bool(ht_control.get("ac_constraint", False)) else 0)} = AC Constraint: {bool(ht_control.get("ac_constraint", False))}', 'offset': offset, 'length': 4},
            {'title': f'{_wlan_bits_pattern(32, 31, 1, 1 if bool(ht_control.get("rdg_more_ppdu", False)) else 0)} = RDG/More PPDU: {bool(ht_control.get("rdg_more_ppdu", False))}', 'offset': offset, 'length': 4},
        ],
    }


def _wlan_tag_node(tag: Dict[str, Any], payload_offset: int) -> Dict[str, Any]:
    tag_number = int(tag.get('number', 0) or 0)
    tag_offset = payload_offset + int(tag.get('offset', 0) or 0)
    tag_length = int(tag.get('declared_length', 0) or 0)
    actual_length = int(tag.get('length', 0) or 0)
    value_offset = payload_offset + int(tag.get('value_offset', 0) or 0)
    name = str(tag.get('name', f'Tag {tag_number}') or f'Tag {tag_number}')

    tag_length_node: Dict[str, Any] = {
        'title': f'Tag length: {tag_length}',
        'offset': tag_offset + 1,
        'length': 1,
    }
    if bool(tag.get('malformed_length', False)):
        tag_length_node['children'] = [
            {
                'title': '[Expert Info (Error/Malformed): Tag Length is longer than remaining payload]',
                'children': [
                    {'title': '[Tag Length is longer than remaining payload]'},
                    {'title': '[Severity level: Error]'},
                    {'title': '[Group: Malformed]'},
                ],
            }
        ]

    children: List[Dict[str, Any]] = [
        {
            'title': f'Tag Number: {name} ({tag_number})',
            'offset': tag_offset,
            'length': 1,
        },
        tag_length_node,
    ]

    if tag_number == 0:
        children.append(
            {
                'title': f'SSID: "{str(tag.get("ssid", "") or "")}"',
                'offset': value_offset,
                'length': actual_length,
            }
        )
    elif tag_number in {1, 50}:
        rate_prefix = 'Extended Supported Rates' if tag_number == 50 else 'Supported Rates'
        for entry_index, entry in enumerate(tag.get('rates', [])):
            children.append(
                {
                    'title': f'{rate_prefix}: {str(entry.get("child_text", "") or "")} (0x{int(entry.get("value", 0) or 0):02x})',
                    'offset': value_offset + entry_index,
                    'length': 1,
                }
            )

    return {
        'title': str(tag.get('title', f'Tag: {name}') or f'Tag: {name}'),
        'offset': tag_offset,
        'length': 2 + actual_length,
        'children': children,
    }


def _wlan_malformed_node(summary: str) -> Dict[str, Any]:
    return {
        'title': summary,
        'children': [
            {
                'title': '[Expert Info (Error/Malformed): Malformed Packet (Exception occurred)]',
                'children': [
                    {'title': '[Malformed Packet (Exception occurred)]'},
                    {'title': '[Severity level: Error]'},
                    {'title': '[Group: Malformed]'},
                ],
            }
        ],
    }


def _wlan_sections(wlan: Dict[str, Any], payload_offset: int) -> List[Dict[str, Any]]:
    frame_offset = payload_offset + int(wlan.get('offset', 0) or 0)
    frame_control = int(wlan.get('frame_control', 0) or 0)
    flags = int(wlan.get('flags', 0) or 0)
    frame_control_low_offset = payload_offset + int(wlan.get('frame_control_low_offset', int(wlan.get('offset', 0) or 0)) or int(wlan.get('offset', 0) or 0))
    flags_offset = payload_offset + int(wlan.get('flags_offset', int(wlan.get('offset', 0) or 0) + 1) or (int(wlan.get('offset', 0) or 0) + 1))
    duration = int(wlan.get('duration', 0) or 0)
    fragment_number = int(wlan.get('fragment_number', 0) or 0)
    sequence_number = int(wlan.get('sequence_number', 0) or 0)
    flags_display = str(wlan.get('flags_display', '') or '')
    subtype_name = str(wlan.get('subtype_name', 'IEEE 802.11') or 'IEEE 802.11')
    management = wlan.get('management', {}) if isinstance(wlan.get('management', {}), dict) else {}
    flag_children = _wlan_flag_children(flags, flags_offset)
    fixed_offset = payload_offset + int(management.get('fixed_offset', 0) or 0)
    association_length = max(24, fixed_offset - frame_offset) if fixed_offset > frame_offset else (28 if wlan.get('ht_control', None) is not None else 24)

    frame_control_children: List[Dict[str, Any]] = [
        {'title': f'{_wlan_bits_pattern(8, 0, 2, 0)} = Version: 0', 'offset': frame_control_low_offset, 'length': 1},
        {'title': f'{_wlan_bits_pattern(8, 2, 2, int(wlan.get("type", 0) or 0))} = Type: {str(wlan.get("type_name", "Management frame") or "Management frame")} ({int(wlan.get("type", 0) or 0)})', 'offset': frame_control_low_offset, 'length': 1},
        {'title': f'{_wlan_bits_pattern(8, 4, 4, int(wlan.get("subtype", 0) or 0))} = Subtype: {int(wlan.get("subtype", 0) or 0)}', 'offset': frame_control_low_offset, 'length': 1},
        {
            'title': f'Flags: 0x{flags:02x}',
            'offset': flags_offset,
            'length': 1,
            'children': flag_children,
        },
    ]

    sections: List[Dict[str, Any]] = [
        {
            'title': f'IEEE 802.11 {subtype_name}, Flags: {flags_display}',
            'offset': frame_offset,
            'length': association_length,
            'children': [
                {
                    'title': f'Type/Subtype: {subtype_name} (0x{((int(wlan.get("subtype", 0) or 0) << 4) | (int(wlan.get("type", 0) or 0) << 2)):04x})',
                    'offset': frame_control_low_offset,
                    'length': 1,
                },
                {
                    'title': f'Frame Control Field: 0x{frame_control:04x}(Swapped)',
                    'offset': frame_offset,
                    'length': 2,
                    'selectable_bytes': True,
                    'children': frame_control_children,
                },
                {
                    'title': f'{_wlan_bits_pattern(16, 0, 16, duration)} = Duration: {duration} microseconds',
                    'offset': frame_offset + 2,
                    'length': 2,
                },
                _wlan_address_node('Receiver address', str(wlan.get('receiver', '') or ''), frame_offset + 4),
                _wlan_address_node('Destination address', str(wlan.get('destination', '') or ''), frame_offset + 4),
                _wlan_address_node('Transmitter address', str(wlan.get('transmitter', '') or ''), frame_offset + 10),
                _wlan_address_node('Source address', str(wlan.get('source', '') or ''), frame_offset + 10),
                _wlan_address_node('BSS Id', str(wlan.get('bssid', '') or ''), frame_offset + 16),
                {
                    'title': f'{_wlan_bits_pattern(16, 0, 4, fragment_number)} = Fragment number: {fragment_number}',
                    'offset': frame_offset + 22,
                    'length': 2,
                },
                {
                    'title': f'{_wlan_bits_pattern(16, 4, 12, sequence_number)} = Sequence number: {sequence_number}',
                    'offset': frame_offset + 22,
                    'length': 2,
                },
                {
                    'title': f'[WLAN Flags: {flags_display}]',
                },
            ] + ([_wlan_ht_control_node(wlan.get('ht_control', {}) or {}, frame_offset + 24)] if wlan.get('ht_control', None) is not None else []),
        }
    ]

    fixed_length = int(management.get('fixed_length', 0) or 0)
    tags = management.get('tags', []) if isinstance(management.get('tags', []), list) else []
    tags_length = int(management.get('tags_length', 0) or 0)
    management_children: List[Dict[str, Any]] = [
        {
            'title': 'Fixed parameters (4 bytes)',
            'offset': fixed_offset,
            'length': fixed_length,
            'children': [
                {
                    'title': f'Capabilities Information: 0x{int(management.get("capabilities", 0) or 0):04x}',
                    'offset': fixed_offset,
                    'length': min(2, fixed_length),
                    'children': _wlan_capability_children(int(management.get('capabilities', 0) or 0), fixed_offset),
                },
            ] + ([{
                'title': f'Listen Interval: 0x{int(management.get("listen_interval", 0) or 0):04x}',
                'offset': fixed_offset + 2,
                'length': 2,
            }] if management.get('listen_interval', None) is not None else []),
        }
    ]

    if tags:
        tags_offset = payload_offset + int(management.get('tags_offset', 0) or 0)
        management_children.append(
            {
                'title': f'Tagged parameters ({tags_length} bytes)',
                'offset': tags_offset,
                'length': tags_length,
                'children': [_wlan_tag_node(tag, payload_offset) for tag in tags],
            }
        )

    sections.append(
        {
            'title': 'IEEE 802.11 Wireless Management',
            'offset': fixed_offset,
            'length': fixed_length + tags_length,
            'children': management_children,
        }
    )

    malformed = wlan.get('malformed', {}) if isinstance(wlan.get('malformed', {}), dict) else {}
    summary = str(malformed.get('summary', '') or '')
    if summary:
        sections.append(_wlan_malformed_node(summary))

    return sections


def _capwap_element_base_children(element: Dict[str, Any], payload_offset: int) -> List[Dict[str, Any]]:
    element_offset = payload_offset + int(element.get('offset', 0) or 0)
    element_length = int(element.get('length', 0) or 0)
    value_offset = payload_offset + int(element.get('value_offset', 0) or 0)
    value_hex = str(element.get('value_hex', '') or '')
    element_name = str(element.get('name', f'Element {int(element.get("type", 0) or 0)}') or '')
    return [
        {
            'title': f'Type: {element_name} ({int(element.get("type", 0) or 0)})',
            'offset': element_offset,
            'length': 2,
        },
        {
            'title': f'Length: {element_length}',
            'offset': element_offset + 2,
            'length': 2,
        },
        {
            'title': f'Value: {value_hex}',
            'offset': value_offset,
            'length': element_length,
        },
    ]


def _capwap_location_data_node(element: Dict[str, Any], payload_offset: int) -> Dict[str, Any]:
    parsed = element.get('parsed', {}) or {}
    value_offset = payload_offset + int(element.get('value_offset', 0) or 0)
    value_length = int(element.get('length', 0) or 0)
    children = _capwap_element_base_children(element, payload_offset)
    children.append(_capwap_tree_node(f'Location Data: {str(parsed.get("text", "") or "")}', value_offset, value_length))
    return {
        'title': f'Type: (t={int(element.get("type", 0) or 0)},l={int(element.get("length", 0) or 0)}) {str(element.get("name", "") or "")}',
        'offset': payload_offset + int(element.get('offset', 0) or 0),
        'length': 4 + int(element.get('length', 0) or 0),
        'children': children,
    }


def _capwap_board_data_node(element: Dict[str, Any], payload_offset: int) -> Dict[str, Any]:
    parsed = element.get('parsed', {}) or {}
    element_value_offset = payload_offset + int(element.get('value_offset', 0) or 0)
    children = _capwap_element_base_children(element, payload_offset)
    children.append(
        _capwap_tree_node(
            f'WTP Board Data Vendor: {_capwap_vendor_display(str(parsed.get("vendor_name", "Unknown") or "Unknown"), int(parsed.get("vendor_id", 0) or 0))}',
            element_value_offset,
            4,
        )
    )

    for subelement in parsed.get('subelements', []) or []:
        sub_offset = payload_offset + int(subelement.get('offset', 0) or 0)
        sub_length = int(subelement.get('length', 0) or 0)
        sub_value_offset = payload_offset + int(subelement.get('value_offset', 0) or 0)
        sub_name = str(subelement.get('name', '') or '')
        sub_children = [
            {
                'title': f'Board Data Type: {sub_name} ({int(subelement.get("type", 0) or 0)})',
                'offset': sub_offset,
                'length': 2,
            },
            {
                'title': f'Board Data Length: {sub_length}',
                'offset': sub_offset + 2,
                'length': 2,
            },
            {
                'title': f'Board Data Value: {str(subelement.get("value_hex", "") or "")}',
                'offset': sub_value_offset,
                'length': sub_length,
            },
        ]
        display_value = str(subelement.get('display_value', '') or '')
        if display_value:
            sub_children.append(
                _capwap_tree_node(
                    f'{str(subelement.get("display_name", sub_name) or sub_name)}: {display_value}',
                    sub_value_offset,
                    sub_length,
                )
            )
        children.append({
            'title': f'WTP Board Data: (t={int(subelement.get("type", 0) or 0)},l={sub_length}) {sub_name}',
            'offset': sub_offset,
            'length': 4 + sub_length,
            'children': sub_children,
        })

    return {
        'title': f'Type: (t={int(element.get("type", 0) or 0)},l={int(element.get("length", 0) or 0)}) {str(element.get("name", "") or "")}',
        'offset': payload_offset + int(element.get('offset', 0) or 0),
        'length': 4 + int(element.get('length', 0) or 0),
        'children': children,
    }


def _capwap_descriptor_node(element: Dict[str, Any], payload_offset: int) -> Dict[str, Any]:
    parsed = element.get('parsed', {}) or {}
    value_offset = payload_offset + int(element.get('value_offset', 0) or 0)
    children = _capwap_element_base_children(element, payload_offset)
    children.extend([
        _capwap_tree_node(f'Max Radios: {int(parsed.get("max_radios", 0) or 0)}', value_offset, 1),
        _capwap_tree_node(f'Radio in use: {int(parsed.get("radios_in_use", 0) or 0)}', value_offset + 1, 1),
    ])

    encryption_children = []

    for encryption in parsed.get('encryptions', []) or []:
        encryption_offset = payload_offset + int(encryption.get('offset', 0) or 0)
        reserved = int(encryption.get('reserved', 0) or 0)
        wbid = int(encryption.get('wbid', 0) or 0)
        capabilities = int(encryption.get('capabilities', 0) or 0)
        wbid_bits = format(wbid, '05b')
        encryption_children.append({
            'title': f'Encryption Capabilities: (WBID {wbid}) {capabilities}',
            'offset': encryption_offset,
            'length': 3,
            'children': [
                {
                    'title': f'{reserved:03b}. .... = Reserved (Encrypt): {reserved}',
                    'offset': encryption_offset,
                    'length': 1,
                },
                {
                    'title': f'...{wbid_bits[0]} {wbid_bits[1:]} = Encrypt WBID: {str(encryption.get("wbid_name", "Unknown") or "Unknown")} ({wbid})',
                    'offset': encryption_offset,
                    'length': 1,
                },
                {
                    'title': f'Encryption Capabilities: {capabilities}',
                    'offset': encryption_offset + 1,
                    'length': 2,
                },
            ],
        })

    children.append(
        _capwap_tree_node(
            f'Encryption Capabilities (Number): {int(parsed.get("num_encrypt", 0) or 0)}',
            value_offset + 2,
            1,
            encryption_children,
        )
    )

    for descriptor in parsed.get('descriptors', []) or []:
        descriptor_offset = payload_offset + int(descriptor.get('offset', 0) or 0)
        descriptor_length = int(descriptor.get('length', 0) or 0)
        descriptor_value_offset = payload_offset + int(descriptor.get('value_offset', 0) or 0)
        descriptor_name = str(descriptor.get('name', '') or '')
        descriptor_children = [
            {
                'title': f'WTP Descriptor Vendor: {_capwap_vendor_display(str(descriptor.get("vendor_name", "Unknown") or "Unknown"), int(descriptor.get("vendor_id", 0) or 0))}',
                'offset': descriptor_offset,
                'length': 4,
            },
            {
                'title': f'Descriptor Type: {descriptor_name} ({int(descriptor.get("type", 0) or 0)})',
                'offset': descriptor_offset + 4,
                'length': 2,
            },
            {
                'title': f'Descriptor Length: {descriptor_length}',
                'offset': descriptor_offset + 6,
                'length': 2,
            },
            {
                'title': f'Descriptor Value: {str(descriptor.get("value_hex", "") or "")}',
                'offset': descriptor_value_offset,
                'length': descriptor_length,
            },
        ]
        text_value = str(descriptor.get('text', '') or '')
        if text_value:
            descriptor_children.append(
                _capwap_tree_node(
                    f'{descriptor_name}: {text_value}',
                    descriptor_value_offset,
                    descriptor_length,
                )
            )
        children.append({
            'title': f'WTP Descriptor: (t={int(descriptor.get("type", 0) or 0)},l={descriptor_length}) {descriptor_name}',
            'offset': descriptor_offset,
            'length': 8 + descriptor_length,
            'children': descriptor_children,
        })

    return {
        'title': f'Type: (t={int(element.get("type", 0) or 0)},l={int(element.get("length", 0) or 0)}) {str(element.get("name", "") or "")}',
        'offset': payload_offset + int(element.get('offset', 0) or 0),
        'length': 4 + int(element.get('length', 0) or 0),
        'children': children,
    }


def _capwap_simple_value_node(element: Dict[str, Any], payload_offset: int, label: str, value: str) -> Dict[str, Any]:
    value_offset = payload_offset + int(element.get('value_offset', 0) or 0)
    value_length = int(element.get('length', 0) or 0)
    children = _capwap_element_base_children(element, payload_offset)
    children.append(_capwap_tree_node(f'{label}: {value}', value_offset, value_length))
    return {
        'title': f'Type: (t={int(element.get("type", 0) or 0)},l={int(element.get("length", 0) or 0)}) {str(element.get("name", "") or "")}',
        'offset': payload_offset + int(element.get('offset', 0) or 0),
        'length': 4 + int(element.get('length', 0) or 0),
        'children': children,
    }


def _capwap_frame_tunnel_mode_node(element: Dict[str, Any], payload_offset: int) -> Dict[str, Any]:
    parsed = element.get('parsed', {}) or {}
    mode_value = int(parsed.get('value', 0) or 0)
    reserved_value = ((mode_value >> 4) << 1) | (mode_value & 0x01)
    value_offset = payload_offset + int(element.get('value_offset', 0) or 0)
    children = _capwap_element_base_children(element, payload_offset)
    children.append(
        _capwap_tree_node(
            f'WTP Frame Tunnel Mode: 0x{mode_value:02x}',
            value_offset,
            1,
            [
                _capwap_tree_node(
                    f'.... {1 if bool(parsed.get("native_frame_tunnel_mode", False)) else 0}... = Native Frame Tunnel Mode: {bool(parsed.get("native_frame_tunnel_mode", False))}',
                    value_offset,
                    1,
                ),
                _capwap_tree_node(
                    f'.... .{1 if bool(parsed.get("dot3_frame_tunnel_mode", False)) else 0}.. = 802.3 Frame Tunnel Mode: {bool(parsed.get("dot3_frame_tunnel_mode", False))}',
                    value_offset,
                    1,
                ),
                _capwap_tree_node(
                    f'.... ..{1 if bool(parsed.get("local_bridging", False)) else 0}. = Local Bridging: {bool(parsed.get("local_bridging", False))}',
                    value_offset,
                    1,
                ),
                _capwap_tree_node(
                    f'{mode_value >> 4:04b} ...{mode_value & 0x01} = Reserved: 0x{reserved_value:02x}',
                    value_offset,
                    1,
                ),
            ],
        )
    )
    return {
        'title': f'Type: (t={int(element.get("type", 0) or 0)},l={int(element.get("length", 0) or 0)}) {str(element.get("name", "") or "")}',
        'offset': payload_offset + int(element.get('offset', 0) or 0),
        'length': 4 + int(element.get('length', 0) or 0),
        'children': children,
    }


def _capwap_radio_information_node(element: Dict[str, Any], payload_offset: int) -> Dict[str, Any]:
    parsed = element.get('parsed', {}) or {}
    value_offset = payload_offset + int(element.get('value_offset', 0) or 0)
    children = _capwap_element_base_children(element, payload_offset)
    children.extend([
        _capwap_tree_node(f'Radio ID: {int(parsed.get("radio_id", 0) or 0)}', value_offset, 1),
        _capwap_tree_node(f'Radio Type Reserved: {str(parsed.get("reserved_bits", "000000") or "000000")}', value_offset + 1, 4),
        _capwap_tree_node(f'0... = Radio Type 802.11n: {bool(parsed.get("radio_type_80211n", False))}', value_offset + 1, 4),
        _capwap_tree_node(f'.{1 if bool(parsed.get("radio_type_80211g", False)) else 0}.. = Radio Type 802.11g: {bool(parsed.get("radio_type_80211g", False))}', value_offset + 1, 4),
        _capwap_tree_node(f'..{1 if bool(parsed.get("radio_type_80211a", False)) else 0}. = Radio Type 802.11a: {bool(parsed.get("radio_type_80211a", False))}', value_offset + 1, 4),
        _capwap_tree_node(f'...{1 if bool(parsed.get("radio_type_80211b", False)) else 0} = Radio Type 802.11b: {bool(parsed.get("radio_type_80211b", False))}', value_offset + 1, 4),
    ])
    return {
        'title': f'Type: (t={int(element.get("type", 0) or 0)},l={int(element.get("length", 0) or 0)}) {str(element.get("name", "") or "")}',
        'offset': payload_offset + int(element.get('offset', 0) or 0),
        'length': 4 + int(element.get('length', 0) or 0),
        'children': children,
    }


def _capwap_reboot_statistics_node(element: Dict[str, Any], payload_offset: int) -> Dict[str, Any]:
    parsed = element.get('parsed', {}) or {}
    value_offset = payload_offset + int(element.get('value_offset', 0) or 0)
    children = _capwap_element_base_children(element, payload_offset)
    children.extend([
        _capwap_tree_node(f'Reboot  Count: {int(parsed.get("reboot_count", 0) or 0)}', value_offset, 2),
        _capwap_tree_node(f'AC Initiated Count: {int(parsed.get("ac_initiated_count", 0) or 0)}', value_offset + 2, 2),
        _capwap_tree_node(f'Link Failure Count: {int(parsed.get("link_failure_count", 0) or 0)}', value_offset + 4, 2),
        _capwap_tree_node(f'SW Failure Count: {int(parsed.get("sw_failure_count", 0) or 0)}', value_offset + 6, 2),
        _capwap_tree_node(f'HW Failure Count: {int(parsed.get("hw_failure_count", 0) or 0)}', value_offset + 8, 2),
        _capwap_tree_node(f'Other Failure Count: {int(parsed.get("other_failure_count", 0) or 0)}', value_offset + 10, 2),
        _capwap_tree_node(f'Unknown Failure Count: {int(parsed.get("unknown_failure_count", 0) or 0)}', value_offset + 12, 2),
        _capwap_tree_node(f'Last Failure Type: {str(parsed.get("last_failure_name", "Not Supported") or "Not Supported")} ({int(parsed.get("last_failure_type", 0) or 0)})', value_offset + 14, 1),
    ])
    return {
        'title': f'Type: (t={int(element.get("type", 0) or 0)},l={int(element.get("length", 0) or 0)}) {str(element.get("name", "") or "")}',
        'offset': payload_offset + int(element.get('offset', 0) or 0),
        'length': 4 + int(element.get('length', 0) or 0),
        'children': children,
    }


def _capwap_element_node(element: Dict[str, Any], payload_offset: int, children: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        'title': f'Type: (t={int(element.get("type", 0) or 0)},l={int(element.get("length", 0) or 0)}) {str(element.get("name", "") or "")}',
        'offset': payload_offset + int(element.get('offset', 0) or 0),
        'length': 4 + int(element.get('length', 0) or 0),
        'children': children,
    }


def _capwap_extend_field_nodes(children: List[Dict[str, Any]], value_offset: int, field_specs: List[tuple[str, int, int]]) -> None:
    for title, relative_offset, length in field_specs:
        children.append(_capwap_tree_node(title, value_offset + relative_offset, length))


def _capwap_ac_descriptor_node(element: Dict[str, Any], payload_offset: int) -> Dict[str, Any]:
    parsed = element.get('parsed', {}) or {}
    value_offset = payload_offset + int(element.get('value_offset', 0) or 0)
    children = _capwap_element_base_children(element, payload_offset)

    _capwap_extend_field_nodes(children, value_offset, [
        (f'Stations: {int(parsed.get("stations", 0) or 0)}', 0, 2),
        (f'Limit Stations: {int(parsed.get("limit_stations", 0) or 0)}', 2, 2),
        (f'Active WTPs: {int(parsed.get("active_wtps", 0) or 0)}', 4, 2),
        (f'Max WTPs: {int(parsed.get("max_wtps", 0) or 0)}', 6, 2),
    ])

    security_flags = int(parsed.get('security_flags', 0) or 0)
    security_reserved = int(parsed.get('security_reserved', 0) or 0)
    children.append(
        _capwap_tree_node(
            f'Security Flags: 0x{security_flags:02x}',
            value_offset + 8,
            1,
            [
                _capwap_tree_node(f'{security_reserved:04b} 0..0 = Reserved: {"Set" if security_reserved else "Not set"}', value_offset + 8, 1),
                _capwap_tree_node(f'.... .{1 if bool(parsed.get("security_pre_shared", False)) else 0}.. = AC supports the pre-shared: {bool(parsed.get("security_pre_shared", False))}', value_offset + 8, 1),
                _capwap_tree_node(f'.... ..{1 if bool(parsed.get("security_x509", False)) else 0}. = AC supports X.509 Certificate: {bool(parsed.get("security_x509", False))}', value_offset + 8, 1),
            ],
        )
    )
    children.append(_capwap_tree_node(f'R-MAC Field: {str(parsed.get("r_mac_field_name", "Unknown") or "Unknown")} ({int(parsed.get("r_mac_field", 0) or 0)})', value_offset + 9, 1))
    children.append(_capwap_tree_node(f'Reserved: {int(parsed.get("reserved", 0) or 0)}', value_offset + 10, 1))

    dtls_policy_flags = int(parsed.get('dtls_policy_flags', 0) or 0)
    dtls_reserved = int(parsed.get('dtls_reserved', 0) or 0)
    children.append(
        _capwap_tree_node(
            f'DTLS Policy Flags: 0x{dtls_policy_flags:02x}',
            value_offset + 11,
            1,
            [
                _capwap_tree_node(f'{dtls_reserved:04b} 0..0 = Reserved: 0x{dtls_reserved:02x}', value_offset + 11, 1),
                _capwap_tree_node(f'.... .{1 if bool(parsed.get("dtls_data_channel_supported", False)) else 0}.. = DTLS-Enabled Data Channel Supported: {bool(parsed.get("dtls_data_channel_supported", False))}', value_offset + 11, 1),
                _capwap_tree_node(f'.... ..{1 if bool(parsed.get("dtls_clear_text_supported", False)) else 0}. = Clear Text Data Channel Supported: {bool(parsed.get("dtls_clear_text_supported", False))}', value_offset + 11, 1),
            ],
        )
    )

    for info in parsed.get('ac_information', []) or []:
        info_offset = payload_offset + int(info.get('offset', 0) or 0)
        info_length = int(info.get('length', 0) or 0)
        info_value_offset = payload_offset + int(info.get('value_offset', 0) or 0)
        info_name = str(info.get('name', '') or '')
        info_children = [
            _capwap_tree_node(f'AC Information Vendor: {_capwap_vendor_display(str(info.get("vendor_name", "Unknown") or "Unknown"), int(info.get("vendor_id", 0) or 0))}', info_offset, 4),
            _capwap_tree_node(f'AC Information Type: {info_name} ({int(info.get("type", 0) or 0)})', info_offset + 4, 2),
            _capwap_tree_node(f'AC Information Length: {info_length}', info_offset + 6, 2),
            _capwap_tree_node(f'AC Information Value: {str(info.get("value_hex", "") or "")}', info_value_offset, info_length),
        ]
        info_text = str(info.get('text', '') or '')
        if info_text:
            info_children.append(_capwap_tree_node(f'{info_name}: {info_text}', info_value_offset, info_length))
        children.append({
            'title': f'AC Information: (t={int(info.get("type", 0) or 0)},l={info_length}) {info_name}',
            'offset': info_offset,
            'length': 8 + info_length,
            'children': info_children,
        })

    return _capwap_element_node(element, payload_offset, children)


def _capwap_control_ipv4_node(element: Dict[str, Any], payload_offset: int) -> Dict[str, Any]:
    parsed = element.get('parsed', {}) or {}
    value_offset = payload_offset + int(element.get('value_offset', 0) or 0)
    children = _capwap_element_base_children(element, payload_offset)
    _capwap_extend_field_nodes(children, value_offset, [
        (f'CAPWAP Control IP Address: {str(parsed.get("address", "") or "")}', 0, 4),
        (f'CAPWAP Control WTP Count: {int(parsed.get("wtp_count", 0) or 0)}', 4, 2),
    ])
    return _capwap_element_node(element, payload_offset, children)


def _capwap_timers_node(element: Dict[str, Any], payload_offset: int) -> Dict[str, Any]:
    parsed = element.get('parsed', {}) or {}
    value_offset = payload_offset + int(element.get('value_offset', 0) or 0)
    children = _capwap_element_base_children(element, payload_offset)
    _capwap_extend_field_nodes(children, value_offset, [
        (f'CAPWAP Timers Discovery (Sec): {int(parsed.get("discovery_seconds", 0) or 0)}', 0, 1),
        (f'CAPWAP Timers Echo Request (Sec): {int(parsed.get("echo_request_seconds", 0) or 0)}', 1, 1),
    ])
    return _capwap_element_node(element, payload_offset, children)


def _capwap_decryption_error_node(element: Dict[str, Any], payload_offset: int) -> Dict[str, Any]:
    parsed = element.get('parsed', {}) or {}
    value_offset = payload_offset + int(element.get('value_offset', 0) or 0)
    children = _capwap_element_base_children(element, payload_offset)
    _capwap_extend_field_nodes(children, value_offset, [
        (f'Decryption Error Report Period Radio ID: {int(parsed.get("radio_id", 0) or 0)}', 0, 1),
        (f'Decryption Error Report Period Interval (Sec): {int(parsed.get("interval_seconds", 0) or 0)}', 1, 2),
    ])
    return _capwap_element_node(element, payload_offset, children)


def _capwap_radio_admin_state_node(element: Dict[str, Any], payload_offset: int) -> Dict[str, Any]:
    parsed = element.get('parsed', {}) or {}
    value_offset = payload_offset + int(element.get('value_offset', 0) or 0)
    children = _capwap_element_base_children(element, payload_offset)
    _capwap_extend_field_nodes(children, value_offset, [
        (f'Radio Administrative ID: {int(parsed.get("radio_id", 0) or 0)}', 0, 1),
        (f'Radio Administrative State: {str(parsed.get("state_name", "Unknown") or "Unknown")} ({int(parsed.get("state", 0) or 0)})', 1, 1),
    ])
    return _capwap_element_node(element, payload_offset, children)


def _capwap_radio_operational_state_node(element: Dict[str, Any], payload_offset: int) -> Dict[str, Any]:
    parsed = element.get('parsed', {}) or {}
    value_offset = payload_offset + int(element.get('value_offset', 0) or 0)
    children = _capwap_element_base_children(element, payload_offset)
    _capwap_extend_field_nodes(children, value_offset, [
        (f'Radio Operational ID: {int(parsed.get("radio_id", 0) or 0)}', 0, 1),
        (f'Radio Operational State: {str(parsed.get("state_name", "Unknown") or "Unknown")} ({int(parsed.get("state", 0) or 0)})', 1, 1),
        (f'Radio Operational Cause: {str(parsed.get("cause_name", "Unknown") or "Unknown")} ({int(parsed.get("cause", 0) or 0)})', 2, 1),
    ])
    return _capwap_element_node(element, payload_offset, children)


def _capwap_result_code_node(element: Dict[str, Any], payload_offset: int) -> Dict[str, Any]:
    parsed = element.get('parsed', {}) or {}
    value_offset = payload_offset + int(element.get('value_offset', 0) or 0)
    children = _capwap_element_base_children(element, payload_offset)
    children.append(_capwap_tree_node(f'Result Code: {str(parsed.get("name", "Unknown") or "Unknown")} ({int(parsed.get("value", 0) or 0)})', value_offset, 4))
    return _capwap_element_node(element, payload_offset, children)


def _capwap_statistics_timer_node(element: Dict[str, Any], payload_offset: int) -> Dict[str, Any]:
    parsed = element.get('parsed', {}) or {}
    value_offset = payload_offset + int(element.get('value_offset', 0) or 0)
    children = _capwap_element_base_children(element, payload_offset)
    children.append(_capwap_tree_node(f'Statistics Timer (Sec): {int(parsed.get("seconds", 0) or 0)}', value_offset, 2))
    return _capwap_element_node(element, payload_offset, children)


def _capwap_wtp_fallback_node(element: Dict[str, Any], payload_offset: int) -> Dict[str, Any]:
    parsed = element.get('parsed', {}) or {}
    value_offset = payload_offset + int(element.get('value_offset', 0) or 0)
    children = _capwap_element_base_children(element, payload_offset)
    children.append(_capwap_tree_node(f'WTP Fallback: {str(parsed.get("name", "Unknown") or "Unknown")} ({int(parsed.get("value", 0) or 0)})', value_offset, 1))
    return _capwap_element_node(element, payload_offset, children)


def _capwap_add_wlan_node(element: Dict[str, Any], payload_offset: int) -> Dict[str, Any]:
    parsed = element.get('parsed', {}) or {}
    value_offset = payload_offset + int(element.get('value_offset', 0) or 0)
    children = _capwap_element_base_children(element, payload_offset)

    capability = int(parsed.get('capability', 0) or 0)
    capability_bits = parsed.get('capability_bits', {}) or {}
    capability_children = [
        _capwap_tree_node(f'{1 if bool(capability_bits.get("ess", False)) else 0}... .... .... .... = ESS: {"Yes" if bool(capability_bits.get("ess", False)) else "No"}', value_offset + 2, 2),
        _capwap_tree_node(f'.{1 if bool(capability_bits.get("ibss", False)) else 0}.. .... .... .... = IBSS: {"Yes" if bool(capability_bits.get("ibss", False)) else "No"}', value_offset + 2, 2),
        _capwap_tree_node(f'..{1 if bool(capability_bits.get("cf_pollable", False)) else 0}. .... .... .... = CF-Pollable: {"Yes" if bool(capability_bits.get("cf_pollable", False)) else "No"}', value_offset + 2, 2),
        _capwap_tree_node(f'...{1 if bool(capability_bits.get("cf_poll_request", False)) else 0} .... .... .... = CF-Poll Request: {"Yes" if bool(capability_bits.get("cf_poll_request", False)) else "No"}', value_offset + 2, 2),
        _capwap_tree_node(f'.... {1 if bool(capability_bits.get("privacy", False)) else 0}... .... .... = Privacy: {"Yes" if bool(capability_bits.get("privacy", False)) else "No"}', value_offset + 2, 2),
        _capwap_tree_node(f'.... .{1 if bool(capability_bits.get("short_preamble", False)) else 0}.. .... .... = Short Preamble: {"Yes" if bool(capability_bits.get("short_preamble", False)) else "No"}', value_offset + 2, 2),
        _capwap_tree_node(f'.... ..{1 if bool(capability_bits.get("pbcc", False)) else 0}. .... .... = PBCC: {"Yes" if bool(capability_bits.get("pbcc", False)) else "No"}', value_offset + 2, 2),
        _capwap_tree_node(f'.... ...{1 if bool(capability_bits.get("channel_agility", False)) else 0} .... .... = Channel Agility: {"Yes" if bool(capability_bits.get("channel_agility", False)) else "No"}', value_offset + 2, 2),
        _capwap_tree_node(f'.... .... {1 if bool(capability_bits.get("spectrum_management", False)) else 0}... .... = Spectrum Management: {"Yes" if bool(capability_bits.get("spectrum_management", False)) else "No"}', value_offset + 2, 2),
        _capwap_tree_node(f'.... .... .{1 if bool(capability_bits.get("qos", False)) else 0}.. .... = QoS: {"Yes" if bool(capability_bits.get("qos", False)) else "No"}', value_offset + 2, 2),
        _capwap_tree_node(f'.... .... ..{1 if bool(capability_bits.get("short_slot_time", False)) else 0}. .... = Short Slot Time: {"Yes" if bool(capability_bits.get("short_slot_time", False)) else "No"}', value_offset + 2, 2),
        _capwap_tree_node(f'.... .... ...{1 if bool(capability_bits.get("apsd", False)) else 0} .... = APSD: {"Yes" if bool(capability_bits.get("apsd", False)) else "No"}', value_offset + 2, 2),
        _capwap_tree_node(f'.... .... .... {1 if bool(capability_bits.get("reserved", False)) else 0}... = Reserved: {"Yes" if bool(capability_bits.get("reserved", False)) else "No"}', value_offset + 2, 2),
        _capwap_tree_node(f'.... .... .... .{1 if bool(capability_bits.get("dsss_ofdm", False)) else 0}.. = DSSS-OFDM: {"Yes" if bool(capability_bits.get("dsss_ofdm", False)) else "No"}', value_offset + 2, 2),
        _capwap_tree_node(f'.... .... .... ..{1 if bool(capability_bits.get("delayed_block_ack", False)) else 0}. = Delayed Block ACK: {"Yes" if bool(capability_bits.get("delayed_block_ack", False)) else "No"}', value_offset + 2, 2),
        _capwap_tree_node(f'.... .... .... ...{1 if bool(capability_bits.get("immediate_block_ack", False)) else 0} = Immediate Block ACK: {"Yes" if bool(capability_bits.get("immediate_block_ack", False)) else "No"}', value_offset + 2, 2),
    ]

    children.extend([
        _capwap_tree_node(f'Radio ID: {int(parsed.get("radio_id", 0) or 0)}', value_offset, 1),
        _capwap_tree_node(f'WLAN ID: {int(parsed.get("wlan_id", 0) or 0)}', value_offset + 1, 1),
        _capwap_tree_node(f'Capability: 0x{capability:04x}', value_offset + 2, 2, capability_children),
        _capwap_tree_node(f'Key-Index: {int(parsed.get("key_index", 0) or 0)}', value_offset + 4, 1),
        _capwap_tree_node(f'Key Status: {str(parsed.get("key_status_name", "Unknown") or "Unknown")} ({int(parsed.get("key_status", 0) or 0)})', value_offset + 5, 1),
        _capwap_tree_node(f'Key Length: {int(parsed.get("key_length", 0) or 0)}', value_offset + 6, 2),
    ])

    key_length = int(parsed.get('key_length', 0) or 0)
    key_offset = int(parsed.get('key_offset', 8) or 8)
    if key_length > 0:
        children.append(_capwap_tree_node(f'Key: {str(parsed.get("key_value_hex", "") or "")}', value_offset + key_offset, key_length))
    else:
        children.append(_capwap_tree_node('Key: <MISSING>', value_offset + key_offset, 0))

    group_tsc_length = int(parsed.get('group_tsc_length', 0) or 0)
    if group_tsc_length > 0:
        children.append(_capwap_tree_node(f'Group TSC: 0x{int(parsed.get("group_tsc", 0) or 0):0{group_tsc_length * 2}x}', value_offset + int(parsed.get('group_tsc_offset', 0) or 0), group_tsc_length))

    children.extend([
        _capwap_tree_node(f'QoS: {str(parsed.get("qos_name", "Unknown") or "Unknown")} ({int(parsed.get("qos", 0) or 0)})', value_offset + int(parsed.get('qos_offset', 0) or 0), 1),
        _capwap_tree_node(f'Authentication Type: {str(parsed.get("auth_type_name", "Unknown") or "Unknown")} ({int(parsed.get("auth_type", 0) or 0)})', value_offset + int(parsed.get('auth_offset', 0) or 0), 1),
        _capwap_tree_node(f'MAC Mode: {str(parsed.get("mac_mode_name", "Unknown") or "Unknown")} ({int(parsed.get("mac_mode", 0) or 0)})', value_offset + int(parsed.get('mac_mode_offset', 0) or 0), 1),
        _capwap_tree_node(f'Tunnel Mode: {str(parsed.get("tunnel_mode_name", "Unknown") or "Unknown")} ({int(parsed.get("tunnel_mode", 0) or 0)})', value_offset + int(parsed.get('tunnel_mode_offset', 0) or 0), 1),
        _capwap_tree_node(f'.... ...{1 if bool(parsed.get("suppress_ssid", False)) else 0} = Suppress SSID: {"Yes" if bool(parsed.get("suppress_ssid", False)) else "No"}', value_offset + int(parsed.get('suppress_offset', 0) or 0), 1),
    ])

    ssid_offset = int(parsed.get('ssid_offset', 0) or 0)
    ssid_length = max(0, int(element.get('length', 0) or 0) - ssid_offset)
    if ssid_length > 0:
        children.append(_capwap_tree_node(f'SSID: {str(parsed.get("ssid", "") or "")}', value_offset + ssid_offset, ssid_length))

    return _capwap_element_node(element, payload_offset, children)


def _capwap_antenna_node(element: Dict[str, Any], payload_offset: int) -> Dict[str, Any]:
    parsed = element.get('parsed', {}) or {}
    value_offset = payload_offset + int(element.get('value_offset', 0) or 0)
    children = _capwap_element_base_children(element, payload_offset)
    _capwap_extend_field_nodes(children, value_offset, [
        (f'Radio ID: {int(parsed.get("radio_id", 0) or 0)}', 0, 1),
        (f'Diversity: {str(parsed.get("diversity_name", "Unknown") or "Unknown")} ({int(parsed.get("diversity", 0) or 0)})', 1, 1),
        (f'Combiner: {str(parsed.get("combiner_name", "Unknown") or "Unknown")} ({int(parsed.get("combiner", 0) or 0)})', 2, 1),
        (f'Antenna Count: {int(parsed.get("antenna_count", 0) or 0)}', 3, 1),
        (f'Selection: {str(parsed.get("selection_name", "Unknown") or "Unknown")} ({int(parsed.get("selection", 0) or 0)})', 4, 1),
    ])
    return _capwap_element_node(element, payload_offset, children)


def _capwap_assigned_bssid_node(element: Dict[str, Any], payload_offset: int) -> Dict[str, Any]:
    parsed = element.get('parsed', {}) or {}
    value_offset = payload_offset + int(element.get('value_offset', 0) or 0)
    children = _capwap_element_base_children(element, payload_offset)
    _capwap_extend_field_nodes(children, value_offset, [
        (f'Radio ID: {int(parsed.get("radio_id", 0) or 0)}', 0, 1),
        (f'WLAN ID: {int(parsed.get("wlan_id", 0) or 0)}', 1, 1),
        (f'BSSID: {str(parsed.get("bssid", "") or "")} ({str(parsed.get("bssid", "") or "")})', 2, 6),
    ])
    return _capwap_element_node(element, payload_offset, children)


def _capwap_direct_sequence_control_node(element: Dict[str, Any], payload_offset: int) -> Dict[str, Any]:
    parsed = element.get('parsed', {}) or {}
    value_offset = payload_offset + int(element.get('value_offset', 0) or 0)
    children = _capwap_element_base_children(element, payload_offset)
    _capwap_extend_field_nodes(children, value_offset, [
        (f'Radio ID: {int(parsed.get("radio_id", 0) or 0)}', 0, 1),
        (f'Reserved: {int(parsed.get("reserved", 0) or 0)}', 1, 1),
        (f'Current Channel: {int(parsed.get("current_channel", 0) or 0)}', 2, 1),
        (f'Current CCA: {int(parsed.get("current_cca", 0) or 0)}', 3, 1),
        (f'Energy Detect Threshold: {int(parsed.get("energy_detect_threshold", 0) or 0)}', 4, 4),
    ])
    return _capwap_element_node(element, payload_offset, children)


def _capwap_mac_operation_node(element: Dict[str, Any], payload_offset: int) -> Dict[str, Any]:
    parsed = element.get('parsed', {}) or {}
    value_offset = payload_offset + int(element.get('value_offset', 0) or 0)
    children = _capwap_element_base_children(element, payload_offset)
    _capwap_extend_field_nodes(children, value_offset, [
        (f'Radio ID: {int(parsed.get("radio_id", 0) or 0)}', 0, 1),
        (f'Reserved: 0x{int(parsed.get("reserved", 0) or 0):02x}', 1, 1),
        (f'RTS Threshold: {int(parsed.get("rts_threshold", 0) or 0)}', 2, 2),
        (f'Short Retry: {int(parsed.get("short_retry", 0) or 0)}', 4, 1),
        (f'Long Retry: {int(parsed.get("long_retry", 0) or 0)}', 5, 1),
        (f'Fragmentation Threshold: {int(parsed.get("fragmentation_threshold", 0) or 0)}', 6, 2),
        (f'Tx MDSU Lifetime: {int(parsed.get("tx_msdu_lifetime", 0) or 0)}', 8, 4),
        (f'Rx MDSU Lifetime: {int(parsed.get("rx_msdu_lifetime", 0) or 0)}', 12, 4),
    ])
    return _capwap_element_node(element, payload_offset, children)


def _capwap_multi_domain_node(element: Dict[str, Any], payload_offset: int) -> Dict[str, Any]:
    parsed = element.get('parsed', {}) or {}
    value_offset = payload_offset + int(element.get('value_offset', 0) or 0)
    children = _capwap_element_base_children(element, payload_offset)
    _capwap_extend_field_nodes(children, value_offset, [
        (f'Radio ID: {int(parsed.get("radio_id", 0) or 0)}', 0, 1),
        (f'Reserved: 0x{int(parsed.get("reserved", 0) or 0):02x}', 1, 1),
        (f'First Channel: {int(parsed.get("first_channel", 0) or 0)}', 2, 2),
        (f'Number of  Channels: {int(parsed.get("number_of_channels", 0) or 0)}', 4, 2),
        (f'Max TX Power Level: {int(parsed.get("max_tx_power_level", 0) or 0)}', 6, 2),
    ])
    return _capwap_element_node(element, payload_offset, children)


def _capwap_supported_rates_node(element: Dict[str, Any], payload_offset: int) -> Dict[str, Any]:
    parsed = element.get('parsed', {}) or {}
    value_offset = payload_offset + int(element.get('value_offset', 0) or 0)
    children = _capwap_element_base_children(element, payload_offset)
    children.append(_capwap_tree_node(f'Radio ID: {int(parsed.get("radio_id", 0) or 0)}', value_offset, 1))
    for index, rate in enumerate(parsed.get('rates', []) or []):
        raw_values = parsed.get('rate_values', []) or []
        raw_value = int(raw_values[index]) if index < len(raw_values) else int(rate * 2)
        children.append(_capwap_tree_node(f'Rates: {rate} (0x{raw_value:02x})', value_offset + 1 + index, 1))
    return _capwap_element_node(element, payload_offset, children)


def _capwap_tx_power_node(element: Dict[str, Any], payload_offset: int) -> Dict[str, Any]:
    parsed = element.get('parsed', {}) or {}
    value_offset = payload_offset + int(element.get('value_offset', 0) or 0)
    children = _capwap_element_base_children(element, payload_offset)
    _capwap_extend_field_nodes(children, value_offset, [
        (f'Radio ID: {int(parsed.get("radio_id", 0) or 0)}', 0, 1),
        (f'Reserved: 0x{int(parsed.get("reserved", 0) or 0):02x}', 1, 1),
        (f'Current TX Power: {int(parsed.get("current_tx_power", 0) or 0)}', 2, 2),
    ])
    return _capwap_element_node(element, payload_offset, children)


def _capwap_tx_power_level_node(element: Dict[str, Any], payload_offset: int) -> Dict[str, Any]:
    parsed = element.get('parsed', {}) or {}
    value_offset = payload_offset + int(element.get('value_offset', 0) or 0)
    children = _capwap_element_base_children(element, payload_offset)
    _capwap_extend_field_nodes(children, value_offset, [
        (f'Radio ID: {int(parsed.get("radio_id", 0) or 0)}', 0, 1),
        (f'Num Levels: {int(parsed.get("num_levels", 0) or 0)}', 1, 1),
        (f'Power Level: {int(parsed.get("power_level", 0) or 0)}', 2, 2),
    ])
    return _capwap_element_node(element, payload_offset, children)


def _capwap_wtp_radio_configuration_node(element: Dict[str, Any], payload_offset: int) -> Dict[str, Any]:
    parsed = element.get('parsed', {}) or {}
    value_offset = payload_offset + int(element.get('value_offset', 0) or 0)
    children = _capwap_element_base_children(element, payload_offset)
    _capwap_extend_field_nodes(children, value_offset, [
        (f'Radio ID: {int(parsed.get("radio_id", 0) or 0)}', 0, 1),
        (f'Short Preamble: {int(parsed.get("short_preamble", 0) or 0)}', 1, 1),
        (f'Num of BSSIDs: {int(parsed.get("num_bssids", 0) or 0)}', 2, 1),
        (f'DTIM Period: {int(parsed.get("dtim_period", 0) or 0)}', 3, 1),
        (f'BSSID: {str(parsed.get("bssid", "") or "")} ({str(parsed.get("bssid", "") or "")})', 4, 6),
        (f'Beacon Period: {int(parsed.get("beacon_period", 0) or 0)}', 10, 2),
        (f'Country String: {str(parsed.get("country_string", "") or "")}', 12, 4),
    ])
    return _capwap_element_node(element, payload_offset, children)


def _capwap_message_element_node(element: Dict[str, Any], payload_offset: int) -> Dict[str, Any]:
    element_type = int(element.get('type', 0) or 0)
    parsed = element.get('parsed', {}) or {}
    if element_type == 1:
        return _capwap_ac_descriptor_node(element, payload_offset)
    if element_type == 2:
        return _capwap_simple_value_node(element, payload_offset, 'AC IPv4 List', str(parsed.get('address', '') or ''))
    if element_type == 4:
        return _capwap_simple_value_node(element, payload_offset, 'AC Name', str(parsed.get('name', '') or ''))
    if element_type == 10:
        return _capwap_control_ipv4_node(element, payload_offset)
    if element_type == 12:
        return _capwap_timers_node(element, payload_offset)
    if element_type == 16:
        return _capwap_decryption_error_node(element, payload_offset)
    if element_type == 23:
        return _capwap_simple_value_node(element, payload_offset, 'Idle Timeout (Sec)', str(int(parsed.get('timeout_seconds', 0) or 0)))
    if element_type == 28:
        return _capwap_location_data_node(element, payload_offset)
    if element_type == 38:
        return _capwap_board_data_node(element, payload_offset)
    if element_type == 39:
        return _capwap_descriptor_node(element, payload_offset)
    if element_type == 31:
        return _capwap_radio_admin_state_node(element, payload_offset)
    if element_type == 32:
        return _capwap_radio_operational_state_node(element, payload_offset)
    if element_type == 33:
        return _capwap_result_code_node(element, payload_offset)
    if element_type == 45:
        return _capwap_simple_value_node(element, payload_offset, 'WTP Name', str(parsed.get('name', '') or ''))
    if element_type == 35:
        return _capwap_simple_value_node(element, payload_offset, 'Session ID', str(parsed.get('session_id', '') or ''))
    if element_type == 36:
        return _capwap_statistics_timer_node(element, payload_offset)
    if element_type == 40:
        return _capwap_wtp_fallback_node(element, payload_offset)
    if element_type == 41:
        return _capwap_frame_tunnel_mode_node(element, payload_offset)
    if element_type == 44:
        return _capwap_simple_value_node(element, payload_offset, 'WTP MAC Type', f'{str(parsed.get("name", "Unknown") or "Unknown")} ({int(parsed.get("value", 0) or 0)})')
    if element_type == 1048:
        return _capwap_radio_information_node(element, payload_offset)
    if element_type == 53:
        return _capwap_simple_value_node(element, payload_offset, 'ECN Support', f'{str(parsed.get("name", "Unknown") or "Unknown")} ({int(parsed.get("value", 0) or 0)})')
    if element_type == 30:
        return _capwap_simple_value_node(element, payload_offset, 'CAPWAP Local IPv4 Address', str(parsed.get('address', '') or ''))
    if element_type == 51:
        return _capwap_simple_value_node(element, payload_offset, 'CAPWAP Transport Protocol', f'{str(parsed.get("name", "Unknown") or "Unknown")} ({int(parsed.get("value", 0) or 0)})')
    if element_type == 48:
        return _capwap_reboot_statistics_node(element, payload_offset)
    if element_type == 1024:
        return _capwap_add_wlan_node(element, payload_offset)
    if element_type == 1025:
        return _capwap_antenna_node(element, payload_offset)
    if element_type == 1026:
        return _capwap_assigned_bssid_node(element, payload_offset)
    if element_type == 1028:
        return _capwap_direct_sequence_control_node(element, payload_offset)
    if element_type == 1030:
        return _capwap_mac_operation_node(element, payload_offset)
    if element_type == 1032:
        return _capwap_multi_domain_node(element, payload_offset)
    if element_type == 1040:
        return _capwap_supported_rates_node(element, payload_offset)
    if element_type == 1041:
        return _capwap_tx_power_node(element, payload_offset)
    if element_type == 1042:
        return _capwap_tx_power_level_node(element, payload_offset)
    if element_type == 1046:
        return _capwap_wtp_radio_configuration_node(element, payload_offset)
    return _capwap_element_node(element, payload_offset, _capwap_element_base_children(element, payload_offset))


def _capwap_section(payload: bytes, offset: int, record=None) -> Dict[str, Any]:
    metadata = getattr(record, 'metadata', {}) if record else {}
    capwap = metadata.get('capwap', {}) if isinstance(metadata, dict) else {}
    preamble = capwap.get('preamble', {}) if isinstance(capwap, dict) else {}
    header = capwap.get('header', {}) if isinstance(capwap, dict) else {}
    control_header = capwap.get('control_header', {}) if isinstance(capwap, dict) else {}
    data_header = capwap.get('data_header', {}) if isinstance(capwap, dict) else {}
    elements = capwap.get('message_elements', []) if isinstance(capwap, dict) else []
    transport = str(capwap.get('transport', 'control') or 'control')

    version = int(preamble.get('version', 0) or 0)
    preamble_type = int(preamble.get('type', 0) or 0)
    header_length = int(header.get('header_length', 0) or 0)
    header_length_bytes = int(header.get('header_length_bytes', 0) or 0)
    radio_id = int(header.get('radio_id', 0) or 0)
    wbid = int(header.get('wireless_binding_id', 0) or 0)
    wbid_name = str(header.get('wireless_binding_name', 'Reserved') or 'Reserved')
    header_flags_value = int(header.get('header_flags_value', 0) or 0)
    fragment_id = int(header.get('fragment_id', 0) or 0)
    fragment_offset = int(header.get('fragment_offset', 0) or 0)
    fragment_reserved = int(header.get('fragment_reserved', 0) or 0)
    message_type = int(control_header.get('message_type', 0) or 0)
    enterprise_number = int(control_header.get('message_type_enterprise', 0) or 0)
    enterprise_name = str(control_header.get('message_type_enterprise_name', 'Reserved') or 'Reserved')
    message_name = str(control_header.get('message_name', f'Control Message ({message_type})') or f'Control Message ({message_type})')
    sequence_number = int(control_header.get('sequence_number', 0) or 0)
    message_element_length_declared = int(control_header.get('message_element_length', 0) or 0)
    message_element_length = int(control_header.get('message_element_actual_length', message_element_length_declared) or 0)
    flags = int(control_header.get('flags', 0) or 0)
    control_header_offset = offset + int(control_header.get('offset', 0) or 0)
    control_header_length = int(control_header.get('length', 0) or 0)
    message_type_length = 4 if control_header_length >= 8 else 1
    enterprise_offset = control_header_offset
    enterprise_length = 3 if control_header_length >= 8 else 1
    enterprise_specific_offset = control_header_offset + (3 if control_header_length >= 8 else 0)
    sequence_offset = control_header_offset + (4 if control_header_length >= 8 else 1)
    message_element_length_offset = control_header_offset + (5 if control_header_length >= 8 else 2)
    flags_offset = control_header_offset + control_header_length - 1

    hlen_bits = format(header_length, '05b') if header_length >= 0 else '00000'
    radio_bits = format(radio_id, '05b')
    wbid_bits = format(wbid, '05b')
    fragment_offset_bits = format(fragment_offset, '013b')
    header_flags_bits = format(header_flags_value & 0x1FF, '09b')
    payload_type_label = 'Native frame format (see Wireless Binding ID field)' if bool(header.get('payload_type_native', False)) else 'IEEE 802.3 frame'
    fragment_label = 'Fragment' if bool(header.get('fragment', False)) else "Don't Fragment"
    last_fragment_label = 'This is the last fragment' if bool(header.get('last_fragment', False)) else 'More fragments follow'
    wireless_header_label = 'Wireless Specific Information Present' if bool(header.get('wireless_header', False)) else 'No Wireless Specific Information'
    radio_mac_header_label = 'Radio MAC Address Present' if bool(header.get('radio_mac_header', False)) else 'No Radio MAC Address'
    keep_alive_label = 'Keep-Alive' if bool(header.get('keep_alive', False)) else 'No Keep-Alive'

    message_element_children = [
        _capwap_message_element_node(element, offset)
        for element in elements
    ]

    children = [
        {
            'title': 'Preamble',
            'offset': offset,
            'length': 1,
            'children': [
                {
                    'title': f'{version:04b} .... = Version: {version}',
                    'offset': offset,
                    'length': 1,
                },
                {
                    'title': f'.... {preamble_type:04b} = Type: CAPWAP Header ({preamble_type})',
                    'offset': offset,
                    'length': 1,
                },
            ],
        },
        {
            'title': 'Header',
            'offset': offset + 1,
            'length': max(0, header_length_bytes - 1),
            'children': [
                {
                    'title': f'{hlen_bits[:4]} {hlen_bits[4]}... .... .... .... .... = Header Length: {header_length} ({header_length_bytes})',
                    'offset': offset + 1,
                    'length': 3,
                },
                {
                    'title': f'.... .{radio_bits[:3]} {radio_bits[3:]}.. .... .... .... = Radio ID: {radio_id}',
                    'offset': offset + 1,
                    'length': 3,
                },
                {
                    'title': f'.... .... ..{wbid_bits[:2]} {wbid_bits[2:]}. .... .... = Wireless Binding ID: {wbid_name} ({wbid})',
                    'offset': offset + 1,
                    'length': 3,
                },
                {
                    'title': (
                        f'.... .... .... ...{header_flags_bits[0]} {header_flags_bits[1:5]} {header_flags_bits[5:9]} '
                        f'= Header Flags: 0x{header_flags_value:03x}'
                        + (
                            ', ' + ', '.join(
                                flag_name
                                for flag_name, enabled in (
                                    ('Payload Type', bool(header.get('payload_type_native', False))),
                                    ('Keep-Alive', bool(header.get('keep_alive', False))),
                                )
                                if enabled
                            )
                            if any(
                                enabled
                                for _, enabled in (
                                    ('Payload Type', bool(header.get('payload_type_native', False))),
                                    ('Keep-Alive', bool(header.get('keep_alive', False))),
                                )
                            )
                            else ''
                        )
                    ),
                    'offset': offset + 2,
                    'length': 2,
                    'children': [
                        _capwap_tree_node(f'.... .... .... ...{1 if bool(header.get("payload_type_native", False)) else 0} .... .... = Payload Type: {payload_type_label}', offset + 2, 2),
                        _capwap_tree_node(f'.... .... .... .... {1 if bool(header.get("fragment", False)) else 0}... .... = Fragment: {fragment_label}', offset + 2, 2),
                        _capwap_tree_node(f'.... .... .... .... .{1 if bool(header.get("last_fragment", False)) else 0}.. .... = Last Fragment: {last_fragment_label}', offset + 2, 2),
                        _capwap_tree_node(f'.... .... .... .... ..{1 if bool(header.get("wireless_header", False)) else 0}. .... = Wireless header: {wireless_header_label}', offset + 2, 2),
                        _capwap_tree_node(f'.... .... .... .... ...{1 if bool(header.get("radio_mac_header", False)) else 0} .... = Radio MAC header: {radio_mac_header_label}', offset + 2, 2),
                        _capwap_tree_node(f'.... .... .... .... .... {1 if bool(header.get("keep_alive", False)) else 0}... = Keep-Alive: {keep_alive_label}', offset + 2, 2),
                        _capwap_tree_node(f'.... .... .... .... .... .{int(header.get("reserved_flags", 0) or 0):03b} = Reserved: 0x{int(header.get("reserved_flags", 0) or 0):x}', offset + 2, 2),
                    ],
                },
                {
                    'title': f'Fragment ID: {fragment_id}',
                    'offset': offset + 4,
                    'length': 2,
                },
                {
                    'title': f'{fragment_offset_bits[:4]} {fragment_offset_bits[4:8]} {fragment_offset_bits[8:12]} {fragment_offset_bits[12]}... = Fragment Offset: {fragment_offset}',
                    'offset': offset + 6,
                    'length': 2,
                },
                {
                    'title': f'.... .... .... .{fragment_reserved:03b} = Reserved: {fragment_reserved}',
                    'offset': offset + 7,
                    'length': 1,
                },
            ],
        },
    ]

    if transport == 'data':
        keepalive_offset = offset + int(data_header.get('offset', header_length_bytes) or header_length_bytes)
        keepalive_length = int(data_header.get('length', max(0, len(payload) - header_length_bytes)) or max(0, len(payload) - header_length_bytes))
        keepalive_declared_length = int(data_header.get('message_element_length', 0) or 0)
        keepalive_kind = str(data_header.get('kind', '') or '')
        if keepalive_kind == 'native_80211':
            return {
                'title': 'Control And Provisioning of Wireless Access Points - Data',
                'offset': offset,
                'length': len(payload),
                'children': children,
            }
        children.append(
            {
                'title': 'Keep-Alive' if keepalive_kind == 'keep_alive' else 'Data',
                'offset': keepalive_offset,
                'length': keepalive_length,
                'children': [
                    _capwap_tree_node(f'Message Element Length: {keepalive_declared_length}', keepalive_offset, 2),
                    *message_element_children,
                ],
            }
        )
        return {
            'title': 'Control And Provisioning of Wireless Access Points - Data',
            'offset': offset,
            'length': len(payload),
            'children': children,
        }

    children.extend([
        {
            'title': 'Control Header',
            'offset': control_header_offset,
            'length': control_header_length,
            'children': [
                _capwap_tree_node(
                    f'Message Type: {message_type}',
                    control_header_offset,
                    message_type_length,
                    [
                        _capwap_tree_node(
                            f'Message Type (Enterprise Number): {enterprise_name} ({enterprise_number})',
                            enterprise_offset,
                            enterprise_length,
                        ),
                        _capwap_tree_node(
                            f'Message Type (Enterprise Specific): {message_name} ({message_type})',
                            enterprise_specific_offset,
                            1,
                        ),
                    ],
                ),
                _capwap_tree_node(f'Sequence Number: {sequence_number}', sequence_offset, 1),
                _capwap_tree_node(f'Message Element Length: {message_element_length_declared}', message_element_length_offset, 2),
                _capwap_tree_node(f'Flags: {flags}', flags_offset, 1),
            ],
        },
        {
            'title': 'Message Element',
            'offset': offset + int(control_header.get('offset', 0) or 0) + int(control_header.get('length', 0) or 0),
            'length': message_element_length,
            'children': message_element_children,
        },
    ])

    return {
        'title': 'Control And Provisioning of Wireless Access Points - Control',
        'offset': offset,
        'length': len(payload),
        'children': children,
    }

def _dns_type_name(value: int) -> str:
    return {
        1: 'A',
        2: 'NS',
        5: 'CNAME',
        12: 'PTR',
        15: 'MX',
        16: 'TXT',
        28: 'AAAA',
    }.get(int(value or 0), str(int(value or 0)))


def _dns_class_name(value: int) -> str:
    return {1: 'IN'}.get(int(value or 0), f'0x{int(value or 0):04x}')


def _dns_read_name(data: bytes, start: int, _depth: int = 0) -> tuple[str, int]:
    if start >= len(data) or _depth > 10:
        return '', start

    labels = []
    pos = start
    consumed = start
    jumped = False

    while pos < len(data):
        length = data[pos]
        if length == 0:
            if not jumped:
                consumed = pos + 1
            break
        if (length & 0xC0) == 0xC0:
            if pos + 1 >= len(data):
                break
            pointer = ((length & 0x3F) << 8) | data[pos + 1]
            label, _ = _dns_read_name(data, pointer, _depth + 1)
            if label:
                labels.append(label)
            if not jumped:
                consumed = pos + 2
            jumped = True
            break
        pos += 1
        label_bytes = data[pos:pos + length]
        labels.append(label_bytes.decode(errors='ignore'))
        pos += length
        if not jumped:
            consumed = pos

    return '.'.join(part for part in labels if part), consumed


def _dns_rdata_text(data: bytes, rr_type: int) -> str:
    if rr_type == 1 and len(data) == 4:
        return str(ipaddress.IPv4Address(data))
    if rr_type == 28 and len(data) == 16:
        return str(ipaddress.IPv6Address(data))
    if rr_type in {2, 5, 12}:
        name, _ = _dns_read_name(data, 0)
        return name
    return data.hex()


def _dns_section(layer, offset: int, record=None) -> Dict[str, Any]:
    raw = bytes(layer)
    metadata = getattr(record, 'metadata', {}) if record else {}
    if len(raw) < 12:
        return {
            'title': 'Domain Name System',
            'offset': offset,
            'length': len(raw),
            'children': [],
        }

    transaction_id = int.from_bytes(raw[0:2], 'big')
    flags = int.from_bytes(raw[2:4], 'big')
    qdcount = int.from_bytes(raw[4:6], 'big')
    ancount = int.from_bytes(raw[6:8], 'big')
    nscount = int.from_bytes(raw[8:10], 'big')
    arcount = int.from_bytes(raw[10:12], 'big')

    qr = (flags >> 15) & 0x1
    opcode = (flags >> 11) & 0xF
    aa = (flags >> 10) & 0x1
    tc = (flags >> 9) & 0x1
    rd = (flags >> 8) & 0x1
    ra = (flags >> 7) & 0x1
    rcode = flags & 0xF

    opcode_name = {0: 'Standard query', 1: 'Inverse query', 2: 'Server status request'}.get(opcode, str(opcode))
    rcode_name = {0: 'No error', 1: 'Format error', 2: 'Server failure', 3: 'Name Error'}.get(rcode, str(rcode))
    z_bit = (flags >> 6) & 0x1
    ad_bit = (flags >> 5) & 0x1
    cd_bit = (flags >> 4) & 0x1

    flag_children = [
        {'title': f'{qr}... .... .... .... = Response: {"Message is a response" if qr else "Message is a query"}', 'offset': offset + 2, 'length': 2},
        {'title': f'.{opcode:04b} .... .... .... = Opcode: {opcode_name} ({opcode})', 'offset': offset + 2, 'length': 2},
    ]
    if qr:
        flag_children.append({'title': f'.... .{aa}.. .... .... = Authoritative: {"Server is an authority for domain" if aa else "Server is not an authority for domain"}', 'offset': offset + 2, 'length': 2})
    flag_children.extend([
        {'title': f'.... ..{tc}. .... .... = Truncated: {"Message is truncated" if tc else "Message is not truncated"}', 'offset': offset + 2, 'length': 2},
        {'title': f'.... ...{rd} .... .... = Recursion desired: {"Do query recursively" if rd else "Do not query recursively"}', 'offset': offset + 2, 'length': 2},
    ])
    if qr:
        flag_children.append({'title': f'.... .... {ra}... .... = Recursion available: {"Server can do recursive queries" if ra else "Server cannot do recursive queries"}', 'offset': offset + 2, 'length': 2})
    flag_children.append({'title': f'.... .... .{z_bit}.. .... = Z: reserved ({z_bit})', 'offset': offset + 2, 'length': 2})
    if qr:
        flag_children.append({'title': f'.... .... ..{ad_bit}. .... = Answer authenticated: {"Answer/authority portion was authenticated by the server" if ad_bit else "Answer/authority portion was not authenticated by the server"}', 'offset': offset + 2, 'length': 2})
    flag_children.append({'title': f'.... .... ...{cd_bit} .... = Non-authenticated data: {"Acceptable" if cd_bit else "Unacceptable"}', 'offset': offset + 2, 'length': 2})
    if qr:
        flag_children.append({'title': f'.... .... .... {rcode:04b} = Reply code: {rcode_name} ({rcode})', 'offset': offset + 2, 'length': 2})

    children = [
        {'title': f'Transaction ID: 0x{transaction_id:04x}', 'offset': offset, 'length': 2},
        {
            'title': f'Flags: 0x{flags:04x} {("Standard query response, " + rcode_name) if qr and opcode == 0 else (opcode_name if not qr else opcode_name + ", " + rcode_name)}',
            'offset': offset + 2,
            'length': 2,
            'children': flag_children,
        },
        {'title': f'Questions: {qdcount}', 'offset': offset + 4, 'length': 2},
        {'title': f'Answer RRs: {ancount}', 'offset': offset + 6, 'length': 2},
        {'title': f'Authority RRs: {nscount}', 'offset': offset + 8, 'length': 2},
        {'title': f'Additional RRs: {arcount}', 'offset': offset + 10, 'length': 2},
    ]

    pos = 12
    question_children = []
    for _ in range(qdcount):
        name, next_pos = _dns_read_name(raw, pos)
        if next_pos + 4 > len(raw):
            break
        qtype = int.from_bytes(raw[next_pos:next_pos + 2], 'big')
        qclass = int.from_bytes(raw[next_pos + 2:next_pos + 4], 'big')
        name_len = max(0, len(name.encode('utf-8')))
        label_count = len([part for part in name.split('.') if part])
        type_title = f'Type: {_dns_type_name(qtype)} ({qtype})'
        if qtype == 1:
            type_title += ' (Host Address)'
        question_children.append({
            'title': f'{name}: type {_dns_type_name(qtype)}, class {_dns_class_name(qclass)}',
            'offset': offset + pos,
            'length': next_pos + 4 - pos,
            'children': [
                {'title': f'Name: {name}', 'offset': offset + pos, 'length': max(0, next_pos - pos)},
                {'title': f'[Name Length: {name_len}]'},
                {'title': f'[Label Count: {label_count}]'},
                {'title': type_title, 'offset': offset + next_pos, 'length': 2},
                {'title': f'Class: {_dns_class_name(qclass)} (0x{qclass:04x})', 'offset': offset + next_pos + 2, 'length': 2},
            ],
        })
        pos = next_pos + 4

    if question_children:
        query_start = question_children[0].get('offset', offset)
        query_end = max(
            int(item.get('offset', query_start) or query_start) + int(item.get('length', 0) or 0)
            for item in question_children
        )
        children.append({
            'title': 'Queries',
            'offset': query_start,
            'length': max(0, query_end - query_start),
            'children': question_children,
        })

    def parse_rr_section(count: int, section_title: str) -> tuple[list[dict], int]:
        nonlocal pos
        items = []
        for _ in range(count):
            name, next_pos = _dns_read_name(raw, pos)
            if next_pos + 10 > len(raw):
                break
            rr_type = int.from_bytes(raw[next_pos:next_pos + 2], 'big')
            rr_class = int.from_bytes(raw[next_pos + 2:next_pos + 4], 'big')
            ttl = int.from_bytes(raw[next_pos + 4:next_pos + 8], 'big')
            rdlen = int.from_bytes(raw[next_pos + 8:next_pos + 10], 'big')
            rdata_start = next_pos + 10
            rdata_end = rdata_start + rdlen
            if rdata_end > len(raw):
                break
            rdata_bytes = raw[rdata_start:rdata_end]
            rdata_text = _dns_rdata_text(rdata_bytes, rr_type)
            type_title = f'Type: {_dns_type_name(rr_type)} ({rr_type})'
            if rr_type == 1:
                type_title += ' (Host Address)'
            items.append({
                'title': f'{name}: type {_dns_type_name(rr_type)}, class {_dns_class_name(rr_class)}, addr {rdata_text}',
                'offset': offset + pos,
                'length': rdata_end - pos,
                'children': [
                    {'title': f'Name: {name}', 'offset': offset + pos, 'length': max(0, next_pos - pos)},
                    {'title': type_title, 'offset': offset + next_pos, 'length': 2},
                    {'title': f'Class: {_dns_class_name(rr_class)} (0x{rr_class:04x})', 'offset': offset + next_pos + 2, 'length': 2},
                    {'title': f'Time to live: {ttl} ({ttl} seconds)', 'offset': offset + next_pos + 4, 'length': 4},
                    {'title': f'Data length: {rdlen}', 'offset': offset + next_pos + 8, 'length': 2},
                    {'title': f'Address: {rdata_text}', 'offset': offset + rdata_start, 'length': rdlen},
                ],
            })
            pos = rdata_end
        return items, pos

    answers, _ = parse_rr_section(ancount, 'Answers')
    if answers:
        answer_start = answers[0].get('offset', offset)
        answer_end = max(
            int(item.get('offset', answer_start) or answer_start) + int(item.get('length', 0) or 0)
            for item in answers
        )
        children.append({
            'title': 'Answers',
            'offset': answer_start,
            'length': max(0, answer_end - answer_start),
            'children': answers,
        })

    authorities, _ = parse_rr_section(nscount, 'Authorities')
    if authorities:
        children.append({'title': 'Authorities', 'children': authorities})

    additionals, _ = parse_rr_section(arcount, 'Additional records')
    if additionals:
        children.append({'title': 'Additional records', 'children': additionals})

    response_frame = metadata.get('dns_response_frame')
    if response_frame is not None:
        children.append({'title': f'[Response In: {int(response_frame)}]'})
    request_frame = metadata.get('dns_request_frame')
    if request_frame is not None:
        children.append({'title': f'[Request In: {int(request_frame)}]'})
    dns_time_ms = metadata.get('dns_time_ms')
    if dns_time_ms is not None:
        children.append({'title': f'[Time: {float(dns_time_ms):.6f} milliseconds]'})

    return {
        'title': f'Domain Name System ({"response" if qr else "query"})',
        'offset': offset,
        'length': len(raw),
        'children': children,
    }


def _dhcp_section(bootp_layer, layer, offset: int) -> Dict[str, Any]:

    raw = bytes(bootp_layer) if bootp_layer is not None else bytes(layer)
    raw_length = len(raw)

    def _ipv4_text(data: bytes) -> str:
        return '.'.join(str(int(byte)) for byte in data[:4]) if len(data) >= 4 else '0.0.0.0'

    def _text_or_not_given(data: bytes, title: str, field_offset: int, field_length: int) -> Dict[str, Any]:
        text = bytes(data[:field_length]).rstrip(b'\x00').decode('utf-8', errors='ignore')
        if text:
            return {'title': f'{title}: {text}', 'offset': field_offset, 'length': field_length}
        return {'title': f'{title} not given', 'offset': field_offset, 'length': field_length}

    def _duration_text(seconds: int) -> str:
        value = int(seconds)
        if value > 0 and value % 86400 == 0:
            days = value // 86400
            return f'{days} day ({value})' if days == 1 else f'{days} days ({value})'
        return str(value)

    def _padding_title(padding: bytes) -> str:
        padding_hex = padding.hex()
        if len(padding) > 16:
            return f'Padding […]: {padding_hex}'
        return f'Padding: {padding_hex}'

    def _param_request_name(code: int) -> str:
        return {
            1: 'Subnet Mask',
            2: 'Time Offset',
            3: 'Router',
            6: 'Domain Name Server',
            12: 'Host Name',
            15: 'Domain Name',
            26: 'Interface MTU',
            28: 'Broadcast Address',
            33: 'Static Route',
            42: 'Network Time Protocol Servers',
            44: 'NetBIOS over TCP/IP Name Server',
            47: 'NetBIOS over TCP/IP Scope',
            50: 'Requested IP Address',
            51: 'IP Address Lease Time',
            54: 'DHCP Server Identifier',
            55: 'Parameter Request List',
            119: 'Domain Search',
            121: 'Classless Static Route',
            249: 'Private/Classless Static Route (Microsoft)',
            252: 'Private/Proxy autodiscovery',
        }.get(int(code), f'Option {int(code)}')

    dhcp_type_names = {
        1: 'Discover',
        2: 'Offer',
        3: 'Request',
        4: 'Decline',
        5: 'ACK',
        6: 'NAK',
        7: 'Release',
        8: 'Inform',
    }

    op = int(getattr(bootp_layer, 'op', 0) or 0) if bootp_layer is not None else 0
    htype = int(getattr(bootp_layer, 'htype', 0) or 0) if bootp_layer is not None else 0
    hlen = int(getattr(bootp_layer, 'hlen', 0) or 0) if bootp_layer is not None else 0
    hops = int(getattr(bootp_layer, 'hops', 0) or 0) if bootp_layer is not None else 0
    xid = int(getattr(bootp_layer, 'xid', 0) or 0) if bootp_layer is not None else 0
    secs = int(getattr(bootp_layer, 'secs', 0) or 0) if bootp_layer is not None else 0
    flags = int(getattr(bootp_layer, 'flags', 0) or 0) if bootp_layer is not None else 0
    ciaddr = str(getattr(bootp_layer, 'ciaddr', '0.0.0.0') or '0.0.0.0') if bootp_layer is not None else '0.0.0.0'
    yiaddr = str(getattr(bootp_layer, 'yiaddr', '0.0.0.0') or '0.0.0.0') if bootp_layer is not None else '0.0.0.0'
    siaddr = str(getattr(bootp_layer, 'siaddr', '0.0.0.0') or '0.0.0.0') if bootp_layer is not None else '0.0.0.0'
    giaddr = str(getattr(bootp_layer, 'giaddr', '0.0.0.0') or '0.0.0.0') if bootp_layer is not None else '0.0.0.0'

    chaddr_field = raw[28:44] if len(raw) >= 44 else b''
    client_mac = _mac_text_from_bytes(chaddr_field[:hlen]) if hlen > 0 else ''
    client_padding = chaddr_field[hlen:16] if len(chaddr_field) >= 16 else b''
    hardware_name = {1: 'Ethernet'}.get(htype, f'Hardware type {htype}')
    op_name = {1: 'Boot Request', 2: 'Boot Reply'}.get(op, f'Operation {op}')
    flag_name = 'Broadcast' if flags & 0x8000 else 'Unicast'
    magic_cookie = raw[236:240] if len(raw) >= 240 else b''

    message_type = None
    children: List[Dict[str, Any]] = [
        {'title': f'Message type: {op_name} ({op})', 'offset': offset, 'length': 1 if raw_length >= 1 else 0},
        {'title': f'Hardware type: {hardware_name} (0x{htype:02x})', 'offset': offset + 1, 'length': 1 if raw_length >= 2 else 0},
        {'title': f'Hardware address length: {hlen}', 'offset': offset + 2, 'length': 1 if raw_length >= 3 else 0},
        {'title': f'Hops: {hops}', 'offset': offset + 3, 'length': 1 if raw_length >= 4 else 0},
        {'title': f'Transaction ID: 0x{xid:08x}', 'offset': offset + 4, 'length': 4 if raw_length >= 8 else 0},
        {'title': f'Seconds elapsed: {secs}', 'offset': offset + 8, 'length': 2 if raw_length >= 10 else 0},
        {
            'title': f'Bootp flags: 0x{flags:04x} ({flag_name})',
            'offset': offset + 10,
            'length': 2 if raw_length >= 12 else 0,
            'children': [
                {
                    'title': f'{"1" if (flags & 0x8000) else "0"}... .... .... .... = Broadcast flag: {"Broadcast" if (flags & 0x8000) else "Unicast"}',
                    'offset': offset + 10,
                    'length': 2 if raw_length >= 12 else 0,
                },
                {
                    'title': f'.{format(flags & 0x7FFF, "015b")[:3]} {format(flags & 0x7FFF, "015b")[3:7]} {format(flags & 0x7FFF, "015b")[7:11]} {format(flags & 0x7FFF, "015b")[11:15]} = Reserved flags: 0x{flags & 0x7FFF:04x}',
                    'offset': offset + 10,
                    'length': 2 if raw_length >= 12 else 0,
                },
            ],
        },
        {'title': f'Client IP address: {ciaddr}', 'offset': offset + 12, 'length': 4 if raw_length >= 16 else 0},
        {'title': f'Your (client) IP address: {yiaddr}', 'offset': offset + 16, 'length': 4 if raw_length >= 20 else 0},
        {'title': f'Next server IP address: {siaddr}', 'offset': offset + 20, 'length': 4 if raw_length >= 24 else 0},
        {'title': f'Relay agent IP address: {giaddr}', 'offset': offset + 24, 'length': 4 if raw_length >= 28 else 0},
        {'title': f'Client MAC address: {_mac_display(client_mac)}', 'offset': offset + 28, 'length': min(max(hlen, 0), 16) if raw_length >= 29 else 0},
    ]

    if client_padding:
        children.append({'title': f'Client hardware address padding: {client_padding.hex()}', 'offset': offset + 28 + hlen, 'length': len(client_padding)})

    if raw_length >= 44:
        children.append(_text_or_not_given(raw[44:108], 'Server host name', offset + 44, 64))
    if raw_length >= 108:
        children.append(_text_or_not_given(raw[108:236], 'Boot file name', offset + 108, 128))
    if magic_cookie:
        cookie_title = 'Magic cookie: DHCP' if magic_cookie == b'\x63\x82\x53\x63' else f'Magic cookie: {magic_cookie.hex()}'
        children.append({'title': cookie_title, 'offset': offset + 236, 'length': len(magic_cookie)})

    option_children: List[Dict[str, Any]] = []
    cursor = 240 if raw_length >= 240 else raw_length
    while cursor < raw_length:
        option_code = int(raw[cursor])
        option_offset = offset + cursor

        if option_code == 0:
            cursor += 1
            continue

        if option_code == 255:
            option_children.append(
                {
                    'title': 'Option: (255) End',
                    'offset': option_offset,
                    'length': 1,
                    'children': [
                        {'title': 'Option End: 255', 'offset': option_offset, 'length': 1},
                    ],
                }
            )
            cursor += 1
            if cursor < raw_length:
                padding = raw[cursor:]
                if padding:
                    option_children.append({'title': _padding_title(padding), 'offset': offset + cursor, 'length': len(padding)})
            break

        if cursor + 2 > raw_length:
            break

        option_length = int(raw[cursor + 1])
        actual_length = min(option_length, raw_length - (cursor + 2))
        value = raw[cursor + 2:cursor + 2 + actual_length]
        option_node: Dict[str, Any]

        if option_code == 53:
            message_type = int(value[0]) if value else 0
            message_name = dhcp_type_names.get(message_type, str(message_type))
            option_node = {
                'title': f'Option: (53) DHCP Message Type ({message_name})',
                'offset': option_offset,
                'length': 2 + actual_length,
                'children': [
                    {'title': f'Length: {option_length}', 'offset': option_offset + 1, 'length': 1},
                    {'title': f'DHCP: {message_name} ({message_type})', 'offset': option_offset + 2, 'length': 1 if actual_length >= 1 else 0},
                ],
            }
        elif option_code == 12:
            host_name = value.decode('utf-8', errors='ignore')
            option_node = {
                'title': 'Option: (12) Host Name',
                'offset': option_offset,
                'length': 2 + actual_length,
                'children': [
                    {'title': f'Length: {option_length}', 'offset': option_offset + 1, 'length': 1},
                    {'title': f'Host Name: {host_name}', 'offset': option_offset + 2, 'length': actual_length},
                ],
            }
        elif option_code == 50:
            requested_ip = _ipv4_text(value)
            option_node = {
                'title': f'Option: (50) Requested IP Address ({requested_ip})',
                'offset': option_offset,
                'length': 2 + actual_length,
                'children': [
                    {'title': f'Length: {option_length}', 'offset': option_offset + 1, 'length': 1},
                    {'title': f'Requested IP Address: {requested_ip}', 'offset': option_offset + 2, 'length': 4 if actual_length >= 4 else actual_length},
                ],
            }
        elif option_code == 51:
            lease_time = int.from_bytes(value[:4], 'big') if len(value) >= 4 else 0
            option_node = {
                'title': 'Option: (51) IP Address Lease Time',
                'offset': option_offset,
                'length': 2 + actual_length,
                'children': [
                    {'title': f'Length: {option_length}', 'offset': option_offset + 1, 'length': 1},
                    {'title': f'IP Address Lease Time: {_duration_text(lease_time)}', 'offset': option_offset + 2, 'length': 4 if actual_length >= 4 else actual_length},
                ],
            }
        elif option_code == 54:
            server_id = _ipv4_text(value)
            option_node = {
                'title': f'Option: (54) DHCP Server Identifier ({server_id})',
                'offset': option_offset,
                'length': 2 + actual_length,
                'children': [
                    {'title': f'Length: {option_length}', 'offset': option_offset + 1, 'length': 1},
                    {'title': f'DHCP Server Identifier: {server_id}', 'offset': option_offset + 2, 'length': 4 if actual_length >= 4 else actual_length},
                ],
            }
        elif option_code == 55:
            item_children = [
                {'title': f'Parameter Request List Item: ({int(code)}) {_param_request_name(int(code))}', 'offset': option_offset + 2 + index, 'length': 1}
                for index, code in enumerate(value)
            ]
            option_node = {
                'title': 'Option: (55) Parameter Request List',
                'offset': option_offset,
                'length': 2 + actual_length,
                'children': [
                    {'title': f'Length: {option_length}', 'offset': option_offset + 1, 'length': 1},
                ] + item_children,
            }
        elif option_code == 1:
            subnet_mask = _ipv4_text(value)
            option_node = {
                'title': f'Option: (1) Subnet Mask ({subnet_mask})',
                'offset': option_offset,
                'length': 2 + actual_length,
                'children': [
                    {'title': f'Length: {option_length}', 'offset': option_offset + 1, 'length': 1},
                    {'title': f'Subnet Mask: {subnet_mask}', 'offset': option_offset + 2, 'length': 4 if actual_length >= 4 else actual_length},
                ],
            }
        elif option_code == 3:
            routers = [_ipv4_text(value[index:index + 4]) for index in range(0, len(value), 4) if len(value[index:index + 4]) == 4]
            option_node = {
                'title': 'Option: (3) Router',
                'offset': option_offset,
                'length': 2 + actual_length,
                'children': [
                    {'title': f'Length: {option_length}', 'offset': option_offset + 1, 'length': 1},
                ] + [
                    {'title': f'Router: {router}', 'offset': option_offset + 2 + (index * 4), 'length': 4}
                    for index, router in enumerate(routers)
                ],
            }
        elif option_code == 6:
            name_servers = [_ipv4_text(value[index:index + 4]) for index in range(0, len(value), 4) if len(value[index:index + 4]) == 4]
            option_node = {
                'title': 'Option: (6) Domain Name Server',
                'offset': option_offset,
                'length': 2 + actual_length,
                'children': [
                    {'title': f'Length: {option_length}', 'offset': option_offset + 1, 'length': 1},
                ] + [
                    {'title': f'Domain Name Server: {server}', 'offset': option_offset + 2 + (index * 4), 'length': 4}
                    for index, server in enumerate(name_servers)
                ],
            }
        elif option_code == 15:
            domain_name = value.decode('utf-8', errors='ignore')
            option_node = {
                'title': 'Option: (15) Domain Name',
                'offset': option_offset,
                'length': 2 + actual_length,
                'children': [
                    {'title': f'Length: {option_length}', 'offset': option_offset + 1, 'length': 1},
                    {'title': f'Domain Name: {domain_name}', 'offset': option_offset + 2, 'length': actual_length},
                ],
            }
        else:
            option_node = {
                'title': f'Option: ({option_code}) {_param_request_name(option_code)}',
                'offset': option_offset,
                'length': 2 + actual_length,
                'children': [
                    {'title': f'Length: {option_length}', 'offset': option_offset + 1, 'length': 1},
                    {'title': f'Value: {value.hex()}', 'offset': option_offset + 2, 'length': actual_length},
                ],
            }

        option_children.append(option_node)
        cursor += 2 + option_length

    message_name = dhcp_type_names.get(int(message_type or 0), 'DHCP')

    return {
        'title': f'Dynamic Host Configuration Protocol ({message_name})',
        'offset': offset,
        'length': raw_length,
        'children': children + option_children,
    }


def _dhcpv6_message_name(msg_type: int) -> str:
    return {
        1: 'Solicit',
        2: 'Advertise',
        3: 'Request',
        4: 'Confirm',
        5: 'Renew',
        6: 'Rebind',
        7: 'Reply',
        8: 'Release',
        9: 'Decline',
        10: 'Reconfigure',
        11: 'Information-request',
        12: 'Relay-forward',
        13: 'Relay-reply',
    }.get(int(msg_type), f'DHCPv6 Type {int(msg_type)}')


def _dhcpv6_option_name(code: int) -> str:
    return {
        1: 'Client Identifier',
        2: 'Server Identifier',
        6: 'Option Request',
        8: 'Elapsed time',
        23: 'DNS recursive name server',
        39: 'Client Fully Qualified Domain Name',
    }.get(int(code), f'Option {int(code)}')


def _dhcpv6_duid_type_name(duid_type: int) -> str:
    return {
        1: 'link-layer address plus time',
        2: 'enterprise number',
        3: 'link-layer address',
        4: 'Universally Unique IDentifier (UUID)',
    }.get(int(duid_type), f'DUID Type {int(duid_type)}')


def _dhcpv6_hardware_type_name(hw_type: int) -> str:
    return {
        1: 'Ethernet',
    }.get(int(hw_type), f'Hardware type {int(hw_type)}')


def _dhcpv6_requested_option_name(code: int) -> str:
    return {
        1: 'Client Identifier',
        2: 'Server Identifier',
        23: 'DNS recursive name server',
        24: 'Domain Search List',
    }.get(int(code), _dhcpv6_option_name(code))


def _dhcpv6_duid_time_text(raw_time: int) -> str:
    signed_time = int(raw_time)
    if signed_time & 0x80000000:
        signed_time -= 0x100000000
    try:
        dt = datetime.fromtimestamp(946684800 + signed_time, tz=timezone.utc).astimezone()
        return f'{dt.strftime("%b")} {dt.day:2d}, {dt.year} {dt.strftime("%H:%M:%S")}.000000000 {dt.tzname() or "UTC"}'
    except Exception:
        return str(int(raw_time))


def _dhcpv6_section(payload: bytes, offset: int) -> Dict[str, Any]:
    msg_type = int(payload[0]) if len(payload) >= 1 else 0
    xid = int.from_bytes(payload[1:4], 'big') if len(payload) >= 4 else 0
    children: List[Dict[str, Any]] = [
        {'title': f'Message type: {_dhcpv6_message_name(msg_type)} ({msg_type})', 'offset': offset, 'length': 1 if len(payload) >= 1 else 0},
        {'title': f'Transaction ID: 0x{xid:06x}', 'offset': offset + 1, 'length': 3 if len(payload) >= 4 else 0},
    ]

    cursor = 4
    while cursor + 4 <= len(payload):
        option_code = int.from_bytes(payload[cursor:cursor + 2], 'big')
        option_length = int.from_bytes(payload[cursor + 2:cursor + 4], 'big')
        value_start = cursor + 4
        value_end = value_start + option_length
        if value_end > len(payload):
            break

        option_offset = offset + cursor
        option_value_offset = offset + value_start
        option_value = payload[value_start:value_end]
        option_name = _dhcpv6_option_name(option_code)
        option_children: List[Dict[str, Any]] = [
            {'title': f'Option: {option_name} ({option_code})', 'offset': option_offset, 'length': 2},
            {'title': f'Length: {option_length}', 'offset': option_offset + 2, 'length': 2},
        ]

        if option_code in {1, 2}:
            duid_type = int.from_bytes(option_value[0:2], 'big') if len(option_value) >= 2 else 0
            option_children.extend([
                {'title': f'DUID: {option_value.hex()}', 'offset': option_value_offset, 'length': len(option_value)},
                {'title': f'DUID Type: {_dhcpv6_duid_type_name(duid_type)} ({duid_type})', 'offset': option_value_offset, 'length': min(2, len(option_value))},
            ])
            if duid_type == 1 and len(option_value) >= 14:
                hardware_type = int.from_bytes(option_value[2:4], 'big')
                duid_time = int.from_bytes(option_value[4:8], 'big')
                link_layer = _mac_text_from_bytes(option_value[8:14])
                option_children.extend([
                    {'title': f'Hardware type: {_dhcpv6_hardware_type_name(hardware_type)} ({hardware_type})', 'offset': option_value_offset + 2, 'length': 2},
                    {'title': f'DUID Time: {_dhcpv6_duid_time_text(duid_time)}', 'offset': option_value_offset + 4, 'length': 4},
                    {'title': f'Link-layer address: {link_layer}', 'offset': option_value_offset + 8, 'length': 6},
                    {'title': f'Link-layer address (Ethernet): {_mac_display(link_layer)}', 'offset': option_value_offset + 8, 'length': 6},
                ])
            elif duid_type == 4 and len(option_value) >= 18:
                option_children.append({'title': f'UUID: {option_value[2:18].hex()}', 'offset': option_value_offset + 2, 'length': 16})
        elif option_code == 6:
            for index in range(0, len(option_value), 2):
                if index + 2 > len(option_value):
                    break
                requested_code = int.from_bytes(option_value[index:index + 2], 'big')
                option_children.append(
                    {
                        'title': f'Requested Option code: {_dhcpv6_requested_option_name(requested_code)} ({requested_code})',
                        'offset': option_value_offset + index,
                        'length': 2,
                    }
                )
        elif option_code == 8:
            elapsed = int.from_bytes(option_value[:2], 'big') if len(option_value) >= 2 else 0
            option_children.append({'title': f'Elapsed time: {elapsed * 10}ms', 'offset': option_value_offset, 'length': min(2, len(option_value))})
        elif option_code == 23:
            for index in range(0, len(option_value), 16):
                if index + 16 > len(option_value):
                    break
                option_children.append(
                    {
                        'title': f' {1 + (index // 16)} DNS server address: {_ipv6_address_text(option_value[index:index + 16])}',
                        'offset': option_value_offset + index,
                        'length': 16,
                    }
                )
        elif option_code == 39:
            option_children.append(
                {
                    'title': 'Only the following message types are permitted to use OPTION_CLIENT_FQDN:\nSOLICIT, REQUEST, RENEW, REBIND, ADVERTISE, and REPLY',
                    'children': [
                        {
                            'title': 'This message type is not permitted to use OPTION_CLIENT_FQDN',
                            'children': [
                                {
                                    'title': '[Expert Info (Error/Protocol): This message type is not permitted to use OPTION_CLIENT_FQDN]',
                                    'children': [
                                        {'title': '[This message type is not permitted to use OPTION_CLIENT_FQDN]'},
                                        {'title': '[Severity level: Error]'},
                                        {'title': '[Group: Protocol]'},
                                    ],
                                }
                            ],
                        }
                    ],
                }
            )
        else:
            option_children.append({'title': f'Value: {option_value.hex()}', 'offset': option_value_offset, 'length': len(option_value)})

        children.append(
            {
                'title': option_name,
                'offset': option_offset,
                'length': 4 + len(option_value),
                'children': option_children,
            }
        )
        cursor = value_end

    return {
        'title': 'DHCPv6',
        'offset': offset,
        'length': len(payload),
        'children': children,
    }


def _tls_section(packet, offset: int, stream_index: int) -> Dict[str, Any]:

    tls = packet[TLS]

    tls_len = len(tls)

    content_type_map = {
        20: 'Change Cipher Spec',
        21: 'Alert',
        22: 'Handshake',
        23: 'Application Data',
    }

    version_map = {
        0x0301: 'TLSv1.0',
        0x0302: 'TLSv1.1',
        0x0303: 'TLSv1.2',
        0x0304: 'TLSv1.3',
    }

    content_type = int(getattr(tls, 'type', 0) or 0)

    version = int(getattr(tls, 'version', 0) or 0)

    record_len = int(getattr(tls, 'len', 0) or 0)

    content_name = content_type_map.get(
        content_type,
        str(content_type)
    )

    version_name = version_map.get(
        version,
        f'0x{version:04x}'
    )

    payload = b''

    protocol_name = 'Hypertext Transfer Protocol'

    try:

        msg = getattr(tls, 'msg', None)

        if msg:

            # msg có thể là list hoặc object
            if isinstance(msg, list):

                for item in msg:
                    try:
                        payload += bytes(item)
                    except Exception:
                        pass

            else:

                try:
                    payload = bytes(msg)
                except Exception:
                    pass

        if not payload:

            try:
                payload = bytes(tls.payload)
            except Exception:
                payload = b''

    except Exception:

        payload = b''

    if not payload:
        payload = bytes(tls.payload)

    payload_hex = payload.hex()

    children = []

    if stream_index >= 0:
        children.append({
            'title': f'[Stream index: {stream_index}]'
        })

    children.append({
        'title':
                f'{version_name} Record Layer: '
                f'{content_name} Protocol: {protocol_name}',

            'offset': offset,
            'length': tls_len,

            'children': [

                {
                    'title':
                        f'Content Type: '
                        f'{content_name} ({content_type})',

                    'offset': offset,
                    'length': 1,
                },

                {
                    'title':
                        f'Version: '
                        f'{version_name} '
                        f'(0x{version:04x})',

                    'offset': offset + 1,
                    'length': 2,
                },

                {
                    'title':
                        f'Length: {record_len}',

                    'offset': offset + 3,
                    'length': 2,
                }
            ]
        })

    if payload_hex:

        children[1]['children'].append({

            'title':
                f'Encrypted Application Data: '
                f'{payload_hex}',

            'offset': offset + 5,
            'length': len(payload),
        })

        children[1]['children'].append({

            'title':
                '[Application Data Protocol]'
        })

    return {

        'title':
            'Transport Layer Security',

        'offset': offset,
        'length': tls_len,
        'children': children,
    }

def _tls_section_precise(packet, offset: int, stream_index: int) -> Dict[str, Any]:
    tcp_layer = _effective_tcp_layer(packet)
    tls_bytes = _tcp_payload_bytes(packet, tcp_layer) if tcp_layer is not None else bytes(packet[TLS])
    tls_len = len(tls_bytes)

    content_type_map = {
        20: 'Change Cipher Spec',
        21: 'Alert',
        22: 'Handshake',
        23: 'Application Data',
    }
    version_map = {
        0x0300: 'SSL 3.0',
        0x0301: 'TLS 1.0',
        0x0302: 'TLS 1.1',
        0x0303: 'TLS 1.2',
        0x0304: 'TLS 1.3',
    }
    handshake_type_map = {
        1: 'Client Hello',
        2: 'Server Hello',
        4: 'New Session Ticket',
        11: 'Certificate',
        12: 'Server Key Exchange',
        13: 'Certificate Request',
        14: 'Server Hello Done',
        15: 'Certificate Verify',
        16: 'Client Key Exchange',
        20: 'Finished',
    }
    cipher_suite_map = {
        0x002f: 'TLS_RSA_WITH_AES_128_CBC_SHA',
        0x0035: 'TLS_RSA_WITH_AES_256_CBC_SHA',
        0x0033: 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA',
        0x0032: 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA',
        0x0038: 'TLS_DHE_DSS_WITH_AES_256_CBC_SHA',
        0x0039: 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA',
        0x003c: 'TLS_RSA_WITH_AES_128_CBC_SHA256',
        0x003d: 'TLS_RSA_WITH_AES_256_CBC_SHA256',
        0x0040: 'TLS_DHE_DSS_WITH_AES_128_CBC_SHA256',
        0x0041: 'TLS_RSA_WITH_CAMELLIA_128_CBC_SHA',
        0x0044: 'TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA',
        0x0045: 'TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA',
        0x0067: 'TLS_DHE_RSA_WITH_AES_128_CBC_SHA256',
        0x006a: 'TLS_DHE_DSS_WITH_AES_256_CBC_SHA256',
        0x006b: 'TLS_DHE_RSA_WITH_AES_256_CBC_SHA256',
        0x0084: 'TLS_RSA_WITH_CAMELLIA_256_CBC_SHA',
        0x0087: 'TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA',
        0x0088: 'TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA',
        0x0096: 'TLS_RSA_WITH_SEED_CBC_SHA',
        0x0099: 'TLS_DHE_DSS_WITH_SEED_CBC_SHA',
        0x009a: 'TLS_DHE_RSA_WITH_SEED_CBC_SHA',
        0x000a: 'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
        0x0009: 'TLS_RSA_WITH_DES_CBC_SHA',
        0x0005: 'TLS_RSA_WITH_RC4_128_SHA',
        0x0004: 'TLS_RSA_WITH_RC4_128_MD5',
        0x0012: 'TLS_DHE_DSS_WITH_DES_CBC_SHA',
        0x0013: 'TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA',
        0x0015: 'TLS_DHE_RSA_WITH_DES_CBC_SHA',
        0x0016: 'TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA',
        0x009c: 'TLS_RSA_WITH_AES_128_GCM_SHA256',
        0x009d: 'TLS_RSA_WITH_AES_256_GCM_SHA384',
        0x009e: 'TLS_DHE_RSA_WITH_AES_128_GCM_SHA256',
        0x009f: 'TLS_DHE_RSA_WITH_AES_256_GCM_SHA384',
        0x00a2: 'TLS_DHE_DSS_WITH_AES_128_GCM_SHA256',
        0x00a3: 'TLS_DHE_DSS_WITH_AES_256_GCM_SHA384',
        0x00ff: 'TLS_EMPTY_RENEGOTIATION_INFO_SCSV',
        0xc002: 'TLS_ECDH_ECDSA_WITH_RC4_128_SHA',
        0xc003: 'TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA',
        0xc004: 'TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA',
        0xc005: 'TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA',
        0xc007: 'TLS_ECDHE_ECDSA_WITH_RC4_128_SHA',
        0xc008: 'TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA',
        0xc009: 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA',
        0xc00a: 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA',
        0xc00c: 'TLS_ECDH_RSA_WITH_RC4_128_SHA',
        0xc00d: 'TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA',
        0xc00e: 'TLS_ECDH_RSA_WITH_AES_128_CBC_SHA',
        0xc00f: 'TLS_ECDH_RSA_WITH_AES_256_CBC_SHA',
        0xc011: 'TLS_ECDHE_RSA_WITH_RC4_128_SHA',
        0xc012: 'TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA',
        0xc013: 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
        0xc014: 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
        0xc023: 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256',
        0xc024: 'TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384',
        0xc025: 'TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256',
        0xc026: 'TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384',
        0xc027: 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256',
        0xc028: 'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384',
        0xc029: 'TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256',
        0xc02a: 'TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384',
        0xc02b: 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
        0xc02c: 'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
        0xc02d: 'TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256',
        0xc02e: 'TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384',
        0xc02f: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
        0xc030: 'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
        0xc031: 'TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256',
        0xc032: 'TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384',
    }
    extension_name_map = {
        0: 'server_name',
        5: 'status_request',
        10: 'supported_groups',
        11: 'ec_point_formats',
        13: 'signature_algorithms',
        15: 'heartbeat',
        16: 'application_layer_protocol_negotiation',
        18: 'signed_certificate_timestamp',
        21: 'padding',
        23: 'extended_master_secret',
        35: 'session_ticket',
        43: 'supported_versions',
        45: 'psk_key_exchange_modes',
        51: 'key_share',
    }

    def record_version_name(value: int) -> str:
        mapping = {
            0x0301: 'TLSv1.0',
            0x0302: 'TLSv1.1',
            0x0303: 'TLSv1.2',
            0x0304: 'TLSv1.3',
        }
        return mapping.get(int(value or 0), f'0x{int(value or 0):04x}')

    def version_name(value: int) -> str:
        return version_map.get(int(value or 0), f'0x{int(value or 0):04x}')

    def tls_clienthello_version_name(value: int) -> str:
        return version_name(value)

    def _fmt_epoch_local(epoch_value: int) -> str:
        try:
            return datetime.fromtimestamp(int(epoch_value), tz=timezone.utc).astimezone().strftime('%b %d, %Y %H:%M:%S.000000000 %Z')
        except Exception:
            return f'{int(epoch_value)}'

    children = []
    if stream_index >= 0:
        children.append({'title': f'[Stream index: {stream_index}]'})

    pos = 0
    while pos + 5 <= len(tls_bytes):
        content_type = int(tls_bytes[pos])
        version = int.from_bytes(tls_bytes[pos + 1:pos + 3], 'big')
        record_len = int.from_bytes(tls_bytes[pos + 3:pos + 5], 'big')
        payload_start = pos + 5
        payload_end = min(len(tls_bytes), payload_start + record_len)
        record_payload = tls_bytes[payload_start:payload_end]
        content_name = content_type_map.get(content_type, str(content_type))

        record_children = [
            {'title': f'Content Type: {content_name} ({content_type})', 'offset': offset + pos, 'length': 1},
            {'title': f'Version: {version_name(version)} (0x{version:04x})', 'offset': offset + pos + 1, 'length': 2},
            {'title': f'Length: {record_len}', 'offset': offset + pos + 3, 'length': 2},
        ]
        record_title = f'{record_version_name(version)} Record Layer: {content_name} Protocol'

        if content_type == 22 and len(record_payload) >= 4:
            hs_type = int(record_payload[0])
            hs_len = int.from_bytes(record_payload[1:4], 'big')
            hs_name = handshake_type_map.get(hs_type, f'Handshake ({hs_type})')
            title_version_name = record_version_name(version)

            handshake_children = [
                {'title': f'Handshake Type: {hs_name} ({hs_type})', 'offset': offset + payload_start, 'length': 1},
                {'title': f'Length: {hs_len}', 'offset': offset + payload_start + 1, 'length': 3},
            ]

            if hs_type == 1 and len(record_payload) >= 42:
                cursor = 4
                hello_version = int.from_bytes(record_payload[cursor:cursor + 2], 'big')
                title_version_name = record_version_name(hello_version)
                record_title = f'{title_version_name} Record Layer: Handshake Protocol: {hs_name}'
                handshake_children.append({'title': f'Version: {tls_clienthello_version_name(hello_version)} (0x{hello_version:04x})', 'offset': offset + payload_start + cursor, 'length': 2})
                cursor += 2
                random_bytes = record_payload[cursor:cursor + 32]
                gmt_unix = int.from_bytes(random_bytes[:4], 'big') if len(random_bytes) >= 4 else 0
                handshake_children.append({
                    'title': f'Random: {random_bytes.hex()}',
                    'offset': offset + payload_start + cursor,
                    'length': 32,
                    'children': [
                        {'title': f'GMT Unix Time: {_fmt_epoch_local(gmt_unix)}', 'offset': offset + payload_start + cursor, 'length': 4},
                        {'title': f'Random Bytes: {random_bytes[4:].hex()}', 'offset': offset + payload_start + cursor + 4, 'length': max(0, len(random_bytes) - 4)},
                    ],
                })
                cursor += 32
            else:
                record_title = f'{title_version_name} Record Layer: Handshake Protocol: {hs_name}'

            if cursor < len(record_payload):
                session_id_len = int(record_payload[cursor])
                handshake_children.append({'title': f'Session ID Length: {session_id_len}', 'offset': offset + payload_start + cursor, 'length': 1})
                cursor += 1
                if session_id_len > 0:
                    handshake_children.append({'title': f'Session ID: {record_payload[cursor:cursor + session_id_len].hex()}', 'offset': offset + payload_start + cursor, 'length': session_id_len})
                cursor += session_id_len

            if cursor + 2 <= len(record_payload):
                cipher_len = int.from_bytes(record_payload[cursor:cursor + 2], 'big')
                handshake_children.append({'title': f'Cipher Suites Length: {cipher_len}', 'offset': offset + payload_start + cursor, 'length': 2})
                cursor += 2
                cipher_start = cursor
                cipher_children = []
                while cursor + 2 <= cipher_start + cipher_len and cursor + 2 <= len(record_payload):
                    suite = int.from_bytes(record_payload[cursor:cursor + 2], 'big')
                    cipher_children.append({
                        'title': f'Cipher Suite: {cipher_suite_map.get(suite, f"0x{suite:04x}")} (0x{suite:04x})',
                        'offset': offset + payload_start + cursor,
                        'length': 2,
                    })
                    cursor += 2
                handshake_children.append({'title': f'Cipher Suites ({len(cipher_children)} suites)', 'offset': offset + payload_start + cipher_start, 'length': cipher_len, 'children': cipher_children})

            if cursor < len(record_payload):
                compression_len = int(record_payload[cursor])
                handshake_children.append({'title': f'Compression Methods Length: {compression_len}', 'offset': offset + payload_start + cursor, 'length': 1})
                cursor += 1
                comp_start = cursor
                compression_children = []
                for _ in range(compression_len):
                    if cursor >= len(record_payload):
                        break
                    method = int(record_payload[cursor])
                    compression_children.append({
                        'title': f'Compression Method: {"null" if method == 0 else method} ({method})',
                        'offset': offset + payload_start + cursor,
                        'length': 1,
                    })
                    cursor += 1
                handshake_children.append({'title': f'Compression Methods ({len(compression_children)} methods)', 'offset': offset + payload_start + comp_start, 'length': compression_len, 'children': compression_children})

            if cursor + 2 <= len(record_payload):
                ext_len = int.from_bytes(record_payload[cursor:cursor + 2], 'big')
                handshake_children.append({'title': f'Extensions Length: {ext_len}', 'offset': offset + payload_start + cursor, 'length': 2})
                cursor += 2
                ext_start = cursor
                ext_children = []
                while cursor + 4 <= ext_start + ext_len and cursor + 4 <= len(record_payload):
                    ext_type = int.from_bytes(record_payload[cursor:cursor + 2], 'big')
                    ext_size = int.from_bytes(record_payload[cursor + 2:cursor + 4], 'big')
                    data_start = cursor + 4
                    data_end = min(len(record_payload), data_start + ext_size)
                    ext_name = extension_name_map.get(ext_type, ext_type)
                    ext_node = {
                        'title': f'Extension: {ext_name} (len={ext_size})',
                        'offset': offset + payload_start + cursor,
                        'length': min(len(record_payload) - cursor, 4 + ext_size),
                        'children': [
                            {'title': f'Type: {ext_name} ({ext_type})', 'offset': offset + payload_start + cursor, 'length': 2},
                            {'title': f'Length: {ext_size}', 'offset': offset + payload_start + cursor + 2, 'length': 2},
                        ],
                    }
                    ext_payload = record_payload[data_start:data_end]
                    if ext_type == 11 and len(ext_payload) >= 1:
                        list_len = int(ext_payload[0])
                        formats_map = {0: 'uncompressed', 1: 'ansiX962_compressed_prime', 2: 'ansiX962_compressed_char2'}
                        point_children = []
                        for i in range(min(list_len, max(0, len(ext_payload) - 1))):
                            fmt = int(ext_payload[1 + i])
                            point_children.append({'title': f'EC point format: {formats_map.get(fmt, fmt)} ({fmt})', 'offset': offset + payload_start + data_start + 1 + i, 'length': 1})
                        ext_node['children'].extend([
                            {'title': f'EC point formats Length: {list_len}', 'offset': offset + payload_start + data_start, 'length': 1},
                            {'title': f'Elliptic curves point formats ({len(point_children)})', 'offset': offset + payload_start + data_start + 1, 'length': max(0, len(ext_payload) - 1), 'children': point_children},
                        ])
                    elif ext_type == 10 and len(ext_payload) >= 2:
                        group_map = {
                            0x0001: 'sect163k1', 0x0002: 'sect163r1', 0x0003: 'sect163r2', 0x0004: 'sect193r1', 0x0005: 'sect193r2',
                            0x0006: 'sect233k1', 0x0007: 'sect233r1', 0x0008: 'sect239k1', 0x0009: 'sect283k1', 0x000a: 'sect283r1',
                            0x000b: 'sect409k1', 0x000c: 'sect409r1', 0x000d: 'sect571k1', 0x000e: 'sect571r1', 0x000f: 'secp160k1',
                            0x0010: 'secp160r1', 0x0011: 'secp160r2', 0x0012: 'secp192k1', 0x0013: 'secp192r1', 0x0014: 'secp224k1',
                            0x0015: 'secp224r1', 0x0016: 'secp256k1', 0x0017: 'secp256r1', 0x0018: 'secp384r1', 0x0019: 'secp521r1',
                        }
                        list_len = int.from_bytes(ext_payload[:2], 'big')
                        group_children = []
                        p = 2
                        while p + 2 <= min(len(ext_payload), 2 + list_len):
                            group = int.from_bytes(ext_payload[p:p + 2], 'big')
                            group_children.append({'title': f'Supported Group: {group_map.get(group, f"0x{group:04x}")} (0x{group:04x})', 'offset': offset + payload_start + data_start + p, 'length': 2})
                            p += 2
                        ext_node['children'].extend([
                            {'title': f'Supported Groups List Length: {list_len}', 'offset': offset + payload_start + data_start, 'length': 2},
                            {'title': f'Supported Groups ({len(group_children)} groups)', 'offset': offset + payload_start + data_start + 2, 'length': max(0, list_len), 'children': group_children},
                        ])
                    elif ext_type == 35:
                        ext_node['children'].append({'title': 'Session Ticket: <MISSING>'})
                    elif ext_type == 13 and len(ext_payload) >= 2:
                        sig_map = {
                            0x0601: 'rsa_pkcs1_sha512', 0x0602: 'SHA512 DSA', 0x0603: 'ecdsa_secp521r1_sha512',
                            0x0501: 'rsa_pkcs1_sha384', 0x0502: 'SHA384 DSA', 0x0503: 'ecdsa_secp384r1_sha384',
                            0x0401: 'rsa_pkcs1_sha256', 0x0402: 'SHA256 DSA', 0x0403: 'ecdsa_secp256r1_sha256',
                            0x0301: 'SHA224 RSA', 0x0302: 'SHA224 DSA', 0x0303: 'SHA224 ECDSA',
                            0x0201: 'rsa_pkcs1_sha1', 0x0202: 'SHA1 DSA', 0x0203: 'ecdsa_sha1',
                        }
                        hash_map = {2: 'SHA1', 3: 'SHA224', 4: 'SHA256', 5: 'SHA384', 6: 'SHA512'}
                        sign_map = {1: 'RSA', 2: 'DSA', 3: 'ECDSA'}
                        list_len = int.from_bytes(ext_payload[:2], 'big')
                        sig_children = []
                        p = 2
                        while p + 2 <= min(len(ext_payload), 2 + list_len):
                            sig = int.from_bytes(ext_payload[p:p + 2], 'big')
                            hash_id = ext_payload[p]
                            sign_id = ext_payload[p + 1]
                            sig_children.append({
                                'title': f'Signature Algorithm: {sig_map.get(sig, f"0x{sig:04x}")} (0x{sig:04x})',
                                'offset': offset + payload_start + data_start + p,
                                'length': 2,
                                'children': [
                                    {
                                        'title': f'Signature Hash Algorithm Hash: {hash_map.get(hash_id, hash_id)} ({hash_id})',
                                        'offset': offset + payload_start + data_start + p,
                                        'length': 1,
                                    },
                                    {
                                        'title': f'Signature Hash Algorithm Signature: {sign_map.get(sign_id, sign_id)} ({sign_id})',
                                        'offset': offset + payload_start + data_start + p + 1,
                                        'length': 1,
                                    },
                                ],
                            })
                            p += 2
                        ext_node['children'].extend([
                            {'title': f'Signature Hash Algorithms Length: {list_len}', 'offset': offset + payload_start + data_start, 'length': 2},
                            {'title': f'Signature Hash Algorithms ({len(sig_children)} algorithms)', 'offset': offset + payload_start + data_start + 2, 'length': max(0, list_len), 'children': sig_children},
                        ])
                    elif ext_type == 15 and len(ext_payload) >= 1:
                        mode = int(ext_payload[0])
                        ext_node['children'].append({'title': f'Mode: {"Peer allowed to send requests" if mode == 1 else mode} ({mode})', 'offset': offset + payload_start + data_start, 'length': 1})
                    else:
                        ext_node['children'].append({'title': f'Data: {ext_payload.hex()}', 'offset': offset + payload_start + data_start, 'length': max(0, len(ext_payload))})
                    ext_children.append(ext_node)
                    cursor = data_end
                handshake_children.append({'title': f'Extensions ({len(ext_children)})', 'offset': offset + payload_start + ext_start, 'length': ext_len, 'children': ext_children})

                try:
                    ja3 = _tls_clienthello_ja3(record_payload)
                    if ja3:
                        ja4 = _tls_clienthello_ja4(record_payload)
                        if ja4:
                            handshake_children.append({'title': f'[JA4: {ja4["value"]}]'})
                            handshake_children.append({'title': f'[JA4_r: {ja4["raw"]}]'})
                        handshake_children.append({'title': f'[JA3 Fullstring: {ja3["full"]}]'})
                        handshake_children.append({'title': f'[JA3: {ja3["hash"]}]'})
                except Exception:
                    pass

            record_children.append({
                'title': f'Handshake Protocol: {hs_name}',
                'offset': offset + payload_start,
                'length': min(len(record_payload), 4 + hs_len),
                'children': handshake_children,
            })
        elif record_payload:
            record_children.append({'title': f'Record Data: {record_payload.hex()}', 'offset': offset + payload_start, 'length': len(record_payload)})

        children.append({
            'title': record_title,
            'offset': offset + pos,
            'length': min(len(tls_bytes) - pos, 5 + record_len),
            'children': record_children,
        })

        if payload_end <= pos:
            break
        pos = payload_end

    return {
        'title': 'Transport Layer Security',
        'offset': offset,
        'length': tls_len,
        'children': children,
    }


def _mpls_section(payload: bytes, offset: int) -> Dict[str, Any]:
    if len(payload) < 4:
        return {'title': 'MPLS (incomplete)', 'offset': offset, 'length': len(payload), 'children': []}
    
    label_exp_s_ttl = int.from_bytes(payload[0:4], 'big')
    label = (label_exp_s_ttl >> 12) & 0xFFFFF
    exp = (label_exp_s_ttl >> 9) & 0x7
    s_bit = (label_exp_s_ttl >> 8) & 1
    ttl = label_exp_s_ttl & 0xFF
    
    label_bin = format((label_exp_s_ttl >> 12), '020b')
    exp_bin = format((label_exp_s_ttl >> 9) & 0x7, '03b')
    s_bin = format((label_exp_s_ttl >> 8) & 1, '01b')
    ttl_bin = format(ttl, '08b')
    
    children = [
        {'title': f'{label_bin} .... .... .... = MPLS Label: {label} (0x{label:05x})', 'offset': offset, 'length': 3},
        {'title': f'.... {exp_bin}. .... .... .... = MPLS Experimental Bits: {exp}', 'offset': offset + 2, 'length': 1},
        {'title': f'.... ...{s_bin} .... .... .... = MPLS Bottom Of Label Stack: {s_bit}', 'offset': offset + 2, 'length': 1},
        {'title': f'.... .... {ttl_bin} = MPLS TTL: {ttl}', 'offset': offset + 3, 'length': 1},
    ]
    
    return {
        'title': f'MultiProtocol Label Switching Header, Label: {label}, Exp: {exp}, S: {s_bit}, TTL: {ttl}',
        'offset': offset,
        'length': 4,
        'children': children,
    }


def _loop_section(payload: bytes, offset: int) -> Dict[str, Any]:
    skip_count = int.from_bytes(payload[0:2], 'big') if len(payload) >= 2 else 0
    fn = int.from_bytes(payload[2:4], 'little') if len(payload) >= 4 else 0
    receipt = int.from_bytes(payload[4:6], 'big') if len(payload) >= 6 else 0
    fn_name = {
        1: 'Reply',
        2: 'Forward Data',
    }.get(fn)
    function_title = f'Function: {fn_name} ({fn})' if fn_name is not None else f'Function: Unknown ({fn})'
    relevant_title = f'[Relevant function: {fn_name} ({fn})]' if fn_name is not None else f'[Relevant function: Unknown ({fn})]'

    children = [
        {'title': f'skipCount: {skip_count}', 'offset': offset, 'length': 2},
        {'title': relevant_title},
        {'title': function_title, 'offset': offset + 2, 'length': 2},
        {'title': f'Receipt number: {receipt}', 'offset': offset + 4, 'length': 2},
    ]

    return {
        'title': 'Configuration Test Protocol (loopback)',
        'offset': offset,
        'length': min(len(payload), 6),
        'children': children,
    }


def _ospf_ipv4(value: bytes) -> str:
    if len(value) != 4:
        return '-'
    return '.'.join(str(b) for b in value)


def _ospf_checksum_status(payload: bytes, packet_len: int) -> str:
    if packet_len < 24 or len(payload) < packet_len:
        return 'unverified'

    checksum = int.from_bytes(payload[12:14], 'big')
    checksum_bytes = bytearray(payload[:packet_len])
    checksum_bytes[12:14] = b'\x00\x00'
    checksum_data = bytes(checksum_bytes[:16] + checksum_bytes[24:])
    return 'correct' if _internet_checksum(checksum_data) == checksum else 'unverified'


def _ospf_option_descriptions(options: int) -> List[str]:
    labels = []
    if options & 0x40:
        labels.append('(O) Opaque')
    if options & 0x20:
        labels.append('(DC) Demand Circuits')
    if options & 0x10:
        labels.append('(L) LLS Data block')
    if options & 0x08:
        labels.append('(N) NSSA')
    if options & 0x04:
        labels.append('(MC) Multicast')
    if options & 0x02:
        labels.append('(E) External Routing')
    if options & 0x01:
        labels.append('(MT) Multi-Topology Routing')
    return labels


def _ospf_options_children(options: int, offset: int) -> List[Dict[str, Any]]:
    return [
        {'title': f'{1 if options & 0x80 else 0}... .... = DN: {"Set" if options & 0x80 else "Not set"}', 'offset': offset, 'length': 1},
        {'title': f'.{1 if options & 0x40 else 0}.. .... = (O) Opaque: {"Set" if options & 0x40 else "Not set"}', 'offset': offset, 'length': 1},
        {'title': f'..{1 if options & 0x20 else 0}. .... = (DC) Demand Circuits: {"Supported" if options & 0x20 else "Not supported"}', 'offset': offset, 'length': 1},
        {'title': f'...{1 if options & 0x10 else 0} .... = (L) LLS Data block: {"Present" if options & 0x10 else "Not Present"}', 'offset': offset, 'length': 1},
        {'title': f'.... {1 if options & 0x08 else 0}... = (N) NSSA: {"Supported" if options & 0x08 else "Not supported"}', 'offset': offset, 'length': 1},
        {'title': f'.... .{1 if options & 0x04 else 0}.. = (MC) Multicast: {"Capable" if options & 0x04 else "Not capable"}', 'offset': offset, 'length': 1},
        {'title': f'.... ..{1 if options & 0x02 else 0}. = (E) External Routing: {"Capable" if options & 0x02 else "Not capable"}', 'offset': offset, 'length': 1},
        {'title': f'.... ...{1 if options & 0x01 else 0} = (MT) Multi-Topology Routing: {"Yes" if options & 0x01 else "No"}', 'offset': offset, 'length': 1},
    ]


def _ospf_lls_section(payload: bytes, offset: int) -> Dict[str, Any]:
    lls_checksum = int.from_bytes(payload[0:2], 'big') if len(payload) >= 2 else 0
    lls_len_words = int.from_bytes(payload[2:4], 'big') if len(payload) >= 4 else 0
    lls_len_bytes = lls_len_words * 4

    children = [
        {'title': f'Checksum: 0x{lls_checksum:04x}', 'offset': offset, 'length': 2},
        {'title': f'LLS Data Length: {lls_len_bytes} bytes', 'offset': offset + 2, 'length': 2},
    ]

    tlv_offset = 4
    while tlv_offset + 4 <= len(payload):
        tlv_type = int.from_bytes(payload[tlv_offset:tlv_offset + 2], 'big')
        tlv_len = int.from_bytes(payload[tlv_offset + 2:tlv_offset + 4], 'big')
        tlv_value = payload[tlv_offset + 4:tlv_offset + 4 + tlv_len]
        if tlv_len < 0 or len(tlv_value) < tlv_len:
            break

        if tlv_type == 1 and tlv_len == 4:
            opts = int.from_bytes(tlv_value, 'big')
            children.append({
                'title': 'Extended options TLV',
                'offset': offset + tlv_offset,
                'length': tlv_len + 4,
                'children': [
                    {'title': f'TLV Type: {tlv_type}', 'offset': offset + tlv_offset, 'length': 2},
                    {'title': f'TLV Length: {tlv_len}', 'offset': offset + tlv_offset + 2, 'length': 2},
                    {'title': f'Options: 0x{opts:08x}, (LR) LSDB Resynchronization', 'offset': offset + tlv_offset + 4, 'length': 4, 'children': [
                        {'title': f'.... .... .... .... .... .... .... ..{1 if opts & 0x02 else 0}. = (RS) Restart Signal: {"Set" if opts & 0x02 else "Not set"}', 'offset': offset + tlv_offset + 4, 'length': 4},
                        {'title': f'.... .... .... .... .... .... .... ...{1 if opts & 0x01 else 0} = (LR) LSDB Resynchronization: {"Set" if opts & 0x01 else "Not set"}', 'offset': offset + tlv_offset + 4, 'length': 4},
                    ]},
                ],
            })

        tlv_offset += 4 + tlv_len

    return {
        'title': 'OSPF LLS Data Block',
        'offset': offset,
        'length': len(payload),
        'children': children,
    }


def _ospf_lsa_type_name(lsa_type: int) -> str:
    return {
        1: 'Router-LSA',
        2: 'Network-LSA',
        3: 'Summary-LSA',
        4: 'Summary-ASBR-LSA',
        5: 'AS-External-LSA',
    }.get(lsa_type, f'Unknown ({lsa_type})')


def _ospf_link_type_name(link_type: int) -> str:
    return {
        1: 'Point-to-point',
        2: 'Transit',
        3: 'Stub',
        4: 'Virtual',
    }.get(link_type, f'Unknown ({link_type})')


def _ospf_link_id_label(link_type: int) -> str:
    return {
        1: 'Neighboring router ID',
        2: 'IP address of Designated Router',
        3: 'IP network/subnet number',
        4: 'Neighboring router ID',
    }.get(link_type, 'Value')


def _ospf_lsa_age_bits(ls_age_raw: int) -> str:
    flag = '1' if ls_age_raw & 0x8000 else '.'
    bits = format(ls_age_raw & 0x7FFF, '015b')
    return f'{flag}{bits[:3]} {bits[3:7]} {bits[7:11]} {bits[11:]}'


def _ospf_section(payload: bytes, offset: int) -> Dict[str, Any]:
    version = int(payload[0]) if len(payload) >= 1 else 0
    msg_type = int(payload[1]) if len(payload) >= 2 else 0
    packet_len = int.from_bytes(payload[2:4], 'big') if len(payload) >= 4 else 0
    router_id = _ospf_ipv4(payload[4:8])
    area_id = _ospf_ipv4(payload[8:12])
    checksum = int.from_bytes(payload[12:14], 'big') if len(payload) >= 14 else 0
    instance_id = int(payload[14]) if len(payload) >= 15 else 0
    auth_type = int(payload[15]) if len(payload) >= 16 else 0
    auth_data = payload[16:24] if len(payload) >= 24 else b''
    msg_name = {
        1: 'Hello Packet',
        2: 'DB Description',
        3: 'LS Request',
        4: 'LS Update',
        5: 'LS Acknowledge',
    }.get(msg_type, f'OSPF Message ({msg_type})')
    area_name = ' (Backbone)' if area_id == '0.0.0.0' else ''
    checksum_status = _ospf_checksum_status(payload, packet_len)

    children = []
    header_children = [
        {'title': f'Version: {version}', 'offset': offset, 'length': 1},
        {'title': f'Message Type: {msg_name} ({msg_type})', 'offset': offset + 1, 'length': 1},
        {'title': f'Packet Length: {packet_len}', 'offset': offset + 2, 'length': 2},
        {'title': f'Source OSPF Router: {router_id}', 'offset': offset + 4, 'length': 4},
        {'title': f'Area ID: {area_id}{area_name}', 'offset': offset + 8, 'length': 4},
        {'title': f'Checksum: 0x{checksum:04x} [{checksum_status}]', 'offset': offset + 12, 'length': 2},
        {'title': f'Instance ID: Base IPv4 Unicast Instance ({instance_id})', 'offset': offset + 14, 'length': 1},
        {'title': f'Auth Type: Null ({auth_type})', 'offset': offset + 15, 'length': 1},
        {'title': f'Auth Data (none): {auth_data.hex()}', 'offset': offset + 16, 'length': 8},
    ]
    children.append({'title': 'OSPF Header', 'offset': offset, 'length': 24, 'children': header_children})

    packet_end = min(len(payload), packet_len) if packet_len > 0 else len(payload)
    body_offset = offset + 24
    body = payload[24:packet_end] if packet_end > 24 else b''

    if msg_type == 1 and body:
        mask = _ospf_ipv4(body[0:4])
        hello_interval = int.from_bytes(body[4:6], 'big') if len(body) >= 6 else 0
        options = int(body[6]) if len(body) >= 7 else 0
        prio = int(body[7]) if len(body) >= 8 else 0
        dead_interval = int.from_bytes(body[8:12], 'big') if len(body) >= 12 else 0
        designated = _ospf_ipv4(body[12:16])
        backup = _ospf_ipv4(body[16:20])
        neighbors = [
            _ospf_ipv4(body[index:index + 4])
            for index in range(20, len(body), 4)
            if len(body[index:index + 4]) == 4
        ]
        option_labels = _ospf_option_descriptions(options)
        option_suffix = f", {', '.join(option_labels)}" if option_labels else ''
        hello_children = [
            {'title': f'Network Mask: {mask}', 'offset': body_offset, 'length': 4},
            {'title': f'Hello Interval [sec]: {hello_interval}', 'offset': body_offset + 4, 'length': 2},
            {'title': f'Options: 0x{options:02x}{option_suffix}', 'offset': body_offset + 6, 'length': 1, 'children': _ospf_options_children(options, body_offset + 6)},
            {'title': f'Router Priority: {prio}', 'offset': body_offset + 7, 'length': 1},
            {'title': f'Router Dead Interval [sec]: {dead_interval}', 'offset': body_offset + 8, 'length': 4},
            {'title': f'Designated Router: {designated}', 'offset': body_offset + 12, 'length': 4},
            {'title': f'Backup Designated Router: {backup}', 'offset': body_offset + 16, 'length': 4},
        ]
        for neighbor in neighbors:
            hello_children.append({'title': f'Active Neighbor: {neighbor}'})
        children.append({'title': 'OSPF Hello Packet', 'offset': body_offset, 'length': len(body), 'children': hello_children})

    elif msg_type == 2 and len(body) >= 8:
        iface_mtu = int.from_bytes(body[0:2], 'big')
        options = int(body[2])
        dd_flags = int(body[3])
        dd_seq = int.from_bytes(body[4:8], 'big')
        option_labels = _ospf_option_descriptions(options)
        option_suffix = f", {', '.join(option_labels)}" if option_labels else ''
        dd_labels = []
        if dd_flags & 0x08:
            dd_labels.append('(R) OOBResync')
        if dd_flags & 0x04:
            dd_labels.append('(I) Init')
        if dd_flags & 0x02:
            dd_labels.append('(M) More')
        if dd_flags & 0x01:
            dd_labels.append('(MS) Master')
        dd_suffix = f", {', '.join(dd_labels)}" if dd_labels else ''
        db_desc_children = [
            {'title': f'Interface MTU: {iface_mtu}', 'offset': body_offset, 'length': 2},
            {'title': f'Options: 0x{options:02x}{option_suffix}', 'offset': body_offset + 2, 'length': 1, 'children': _ospf_options_children(options, body_offset + 2)},
            {'title': f'DB Description: 0x{dd_flags:02x}{dd_suffix}', 'offset': body_offset + 3, 'length': 1, 'children': [
                {'title': f'.... {1 if dd_flags & 0x08 else 0}... = (R) OOBResync: {"Set" if dd_flags & 0x08 else "Not set"}', 'offset': body_offset + 3, 'length': 1},
                {'title': f'.... .{1 if dd_flags & 0x04 else 0}.. = (I) Init: {"Set" if dd_flags & 0x04 else "Not set"}', 'offset': body_offset + 3, 'length': 1},
                {'title': f'.... ..{1 if dd_flags & 0x02 else 0}. = (M) More: {"Set" if dd_flags & 0x02 else "Not set"}', 'offset': body_offset + 3, 'length': 1},
                {'title': f'.... ...{1 if dd_flags & 0x01 else 0} = (MS) Master: {"Yes" if dd_flags & 0x01 else "No"}', 'offset': body_offset + 3, 'length': 1},
            ]},
            {'title': f'DD Sequence: {dd_seq}', 'offset': body_offset + 4, 'length': 4},
        ]
        children.append({'title': 'OSPF DB Description', 'offset': body_offset, 'length': 8, 'children': db_desc_children})

    elif msg_type == 3 and body:
        request_children = []
        pos = 0
        while pos + 12 <= len(body):
            ls_type = int.from_bytes(body[pos:pos + 4], 'big')
            link_state_id = _ospf_ipv4(body[pos + 4:pos + 8])
            adv_router = _ospf_ipv4(body[pos + 8:pos + 12])
            request_children.extend([
                {'title': f'LS Type: {_ospf_lsa_type_name(ls_type)} ({ls_type})', 'offset': body_offset + pos, 'length': 4},
                {'title': f'Link State ID: {link_state_id}', 'offset': body_offset + pos + 4, 'length': 4},
                {'title': f'Advertising Router: {adv_router}', 'offset': body_offset + pos + 8, 'length': 4},
            ])
            pos += 12
        children.append({'title': 'Link State Request', 'offset': body_offset, 'length': len(body), 'children': request_children})

    elif msg_type == 4 and len(body) >= 4:
        lsa_count = int.from_bytes(body[0:4], 'big')
        update_children = [
            {'title': f'Number of LSAs: {lsa_count}', 'offset': body_offset, 'length': 4},
        ]
        pos = 4
        parsed = 0
        while parsed < lsa_count and pos + 20 <= len(body):
            lsa_len = int.from_bytes(body[pos + 18:pos + 20], 'big')
            if lsa_len < 20 or pos + lsa_len > len(body):
                break

            lsa = body[pos:pos + lsa_len]
            lsa_offset = body_offset + pos
            ls_age_raw = int.from_bytes(lsa[0:2], 'big')
            options = int(lsa[2])
            lsa_type = int(lsa[3])
            link_state_id = _ospf_ipv4(lsa[4:8])
            adv_router = _ospf_ipv4(lsa[8:12])
            seq_num = int.from_bytes(lsa[12:16], 'big')
            lsa_checksum = int.from_bytes(lsa[16:18], 'big')
            option_labels = _ospf_option_descriptions(options)
            option_suffix = f", {', '.join(option_labels)}" if option_labels else ''

            lsa_children = [
                {'title': f'{_ospf_lsa_age_bits(ls_age_raw)} = LS Age (seconds): {ls_age_raw & 0x7FFF}', 'offset': lsa_offset, 'length': 2},
                {'title': f'{1 if ls_age_raw & 0x8000 else 0}... .... .... .... = Do Not Age Flag: {1 if ls_age_raw & 0x8000 else 0}', 'offset': lsa_offset, 'length': 2},
                {'title': f'Options: 0x{options:02x}{option_suffix}', 'offset': lsa_offset + 2, 'length': 1, 'children': _ospf_options_children(options, lsa_offset + 2)},
                {'title': f'LS Type: {_ospf_lsa_type_name(lsa_type)} ({lsa_type})', 'offset': lsa_offset + 3, 'length': 1},
                {'title': f'Link State ID: {link_state_id}', 'offset': lsa_offset + 4, 'length': 4},
                {'title': f'Advertising Router: {adv_router}', 'offset': lsa_offset + 8, 'length': 4},
                {'title': f'Sequence Number: 0x{seq_num:08x}', 'offset': lsa_offset + 12, 'length': 4},
                {'title': f'Checksum: 0x{lsa_checksum:04x}', 'offset': lsa_offset + 16, 'length': 2},
                {'title': f'Length: {lsa_len}', 'offset': lsa_offset + 18, 'length': 2},
            ]

            if lsa_type == 1 and len(lsa) >= 24:
                router_flags = int(lsa[20])
                num_links = int.from_bytes(lsa[22:24], 'big')
                lsa_children.append({
                    'title': f'Flags: 0x{router_flags:02x}',
                    'offset': lsa_offset + 20,
                    'length': 1,
                    'children': [
                        {'title': f'{1 if router_flags & 0x80 else 0}... .... = (H) Host: {"Yes" if router_flags & 0x80 else "No"}', 'offset': lsa_offset + 20, 'length': 1},
                        {'title': f'..{1 if router_flags & 0x20 else 0}. .... = (S) Shortcut-capable ABR: {"Yes" if router_flags & 0x20 else "No"}', 'offset': lsa_offset + 20, 'length': 1},
                        {'title': f'...{1 if router_flags & 0x10 else 0} .... = (N) NSSA translation: {"Yes" if router_flags & 0x10 else "No"}', 'offset': lsa_offset + 20, 'length': 1},
                        {'title': f'.... {1 if router_flags & 0x08 else 0}... = (W) Wild-card multicast receiver: {"Yes" if router_flags & 0x08 else "No"}', 'offset': lsa_offset + 20, 'length': 1},
                        {'title': f'.... .{1 if router_flags & 0x04 else 0}.. = (V) Virtual link endpoint: {"Yes" if router_flags & 0x04 else "No"}', 'offset': lsa_offset + 20, 'length': 1},
                        {'title': f'.... ..{1 if router_flags & 0x02 else 0}. = (E) AS boundary router: {"Yes" if router_flags & 0x02 else "No"}', 'offset': lsa_offset + 20, 'length': 1},
                        {'title': f'.... ...{1 if router_flags & 0x01 else 0} = (B) Area border router: {"Yes" if router_flags & 0x01 else "No"}', 'offset': lsa_offset + 20, 'length': 1},
                    ],
                })
                lsa_children.append({'title': f'Number of Links: {num_links}', 'offset': lsa_offset + 22, 'length': 2})

                link_pos = 24
                link_index = 0
                while link_index < num_links and link_pos + 12 <= len(lsa):
                    metric_count = int(lsa[link_pos + 9])
                    link_record_len = 12 + (metric_count * 4)
                    if link_pos + link_record_len > len(lsa):
                        break

                    link_id = _ospf_ipv4(lsa[link_pos:link_pos + 4])
                    link_data = _ospf_ipv4(lsa[link_pos + 4:link_pos + 8])
                    link_type = int(lsa[link_pos + 8])
                    metric = int.from_bytes(lsa[link_pos + 10:link_pos + 12], 'big')
                    link_name = _ospf_link_type_name(link_type)
                    link_label = _ospf_link_id_label(link_type)
                    link_offset = lsa_offset + link_pos
                    link_children = [
                        {'title': f'Link ID: {link_id} - {link_label}', 'offset': link_offset, 'length': 4},
                        {'title': f'Link Data: {link_data}', 'offset': link_offset + 4, 'length': 4},
                        {'title': f'Link Type: {link_type} - Connection to a {link_name.lower()} network' if link_type == 3 else (f'Link Type: {link_type} - Connection to a transit network' if link_type == 2 else f'Link Type: {link_type} - {link_name}'), 'offset': link_offset + 8, 'length': 1},
                        {'title': f'Number of Metrics: {metric_count} - TOS', 'offset': link_offset + 9, 'length': 1},
                        {'title': f'0 Metric: {metric}', 'offset': link_offset + 10, 'length': 2},
                    ]

                    update_children_title = f'Type: {link_name:<8} ID: {link_id:<15} Data: {link_data:<15} Metric: {metric}'
                    lsa_children.append({
                        'title': update_children_title,
                        'offset': link_offset,
                        'length': link_record_len,
                        'children': link_children,
                    })

                    link_pos += link_record_len
                    link_index += 1

            update_children.append({
                'title': f'LSA-type {lsa_type} ({_ospf_lsa_type_name(lsa_type)}), len {lsa_len}',
                'offset': lsa_offset,
                'length': lsa_len,
                'children': lsa_children,
            })

            pos += lsa_len
            parsed += 1

        children.append({'title': 'LS Update Packet', 'offset': body_offset, 'length': len(body), 'children': update_children})

    elif msg_type == 5 and body:
        pos = 0
        while pos + 20 <= len(body):
            lsa = body[pos:pos + 20]
            lsa_offset = body_offset + pos
            ls_age_raw = int.from_bytes(lsa[0:2], 'big')
            options = int(lsa[2])
            lsa_type = int(lsa[3])
            link_state_id = _ospf_ipv4(lsa[4:8])
            adv_router = _ospf_ipv4(lsa[8:12])
            seq_num = int.from_bytes(lsa[12:16], 'big')
            lsa_checksum = int.from_bytes(lsa[16:18], 'big')
            lsa_len = int.from_bytes(lsa[18:20], 'big')
            option_labels = _ospf_option_descriptions(options)
            option_suffix = f", {', '.join(option_labels)}" if option_labels else ''

            children.append({
                'title': f'LSA-type {lsa_type} ({_ospf_lsa_type_name(lsa_type)}), len {lsa_len}',
                'offset': lsa_offset,
                'length': len(lsa),
                'children': [
                    {'title': f'{_ospf_lsa_age_bits(ls_age_raw)} = LS Age (seconds): {ls_age_raw & 0x7FFF}', 'offset': lsa_offset, 'length': 2},
                    {'title': f'{1 if ls_age_raw & 0x8000 else 0}... .... .... .... = Do Not Age Flag: {1 if ls_age_raw & 0x8000 else 0}', 'offset': lsa_offset, 'length': 2},
                    {'title': f'Options: 0x{options:02x}{option_suffix}', 'offset': lsa_offset + 2, 'length': 1, 'children': _ospf_options_children(options, lsa_offset + 2)},
                    {'title': f'LS Type: {_ospf_lsa_type_name(lsa_type)} ({lsa_type})', 'offset': lsa_offset + 3, 'length': 1},
                    {'title': f'Link State ID: {link_state_id}', 'offset': lsa_offset + 4, 'length': 4},
                    {'title': f'Advertising Router: {adv_router}', 'offset': lsa_offset + 8, 'length': 4},
                    {'title': f'Sequence Number: 0x{seq_num:08x}', 'offset': lsa_offset + 12, 'length': 4},
                    {'title': f'Checksum: 0x{lsa_checksum:04x}', 'offset': lsa_offset + 16, 'length': 2},
                    {'title': f'Length: {lsa_len}', 'offset': lsa_offset + 18, 'length': 2},
                ],
            })
            pos += 20

    if msg_type in {1, 2} and len(payload) > packet_end and len(payload[packet_end:]) >= 4:
        children.append(_ospf_lls_section(payload[packet_end:], offset + packet_end))

    return {
        'title': 'Open Shortest Path First',
        'offset': offset,
        'length': len(payload),
        'children': children,
    }


def _cdp_section(payload: bytes, offset: int) -> Dict[str, Any]:
    version = int(payload[0]) if len(payload) >= 1 else 0
    ttl = int(payload[1]) if len(payload) >= 2 else 0
    checksum = int.from_bytes(payload[2:4], 'big') if len(payload) >= 4 else 0
    checksum_status = 'Good'
    if len(payload) >= 4:
        checksum_bytes = bytearray(payload)
        checksum_bytes[2:4] = b'\x00\x00'
        if _internet_checksum(bytes(checksum_bytes)) != checksum:
            checksum_status = 'Unverified'

    children = [
        {'title': f'Version: {version}', 'offset': offset, 'length': 1},
        {'title': f'TTL: {ttl} seconds', 'offset': offset + 1, 'length': 1},
        {'title': f'Checksum: 0x{checksum:04x} [{"correct" if checksum_status == "Good" else "unverified"}]', 'offset': offset + 2, 'length': 2},
        {'title': f'[Checksum Status: {checksum_status}]'},
    ]

    pos = 4
    capability_lines = [
        ('.... .... .... .... .... .... .... ...1', 'Router', 0x00000001),
        ('.... .... .... .... .... .... .... ..0.', 'Transparent Bridge', 0x00000002),
        ('.... .... .... .... .... .... .... .0..', 'Source Route Bridge', 0x00000004),
        ('.... .... .... .... .... .... .... 1...', 'Switch', 0x00000008),
        ('.... .... .... .... .... .... ...0 ....', 'Host', 0x00000010),
        ('.... .... .... .... .... .... ..1. ....', 'IGMP capable', 0x00000020),
        ('.... .... .... .... .... .... .0.. ....', 'Repeater', 0x00000040),
        ('.... .... .... .... .... .... 0... ....', 'VoIP Phone', 0x00000080),
        ('.... .... .... .... .... ...0 .... ....', 'Remotely Managed Device', 0x00000100),
        ('.... .... .... .... .... ..0. .... ....', 'CVTA/STP Dispute Resolution/Cisco VT Camera', 0x00000200),
        ('.... .... .... .... .... .0.. .... ....', 'Two Port Mac Relay', 0x00000400),
    ]

    while pos + 4 <= len(payload):
        tlv_type = int.from_bytes(payload[pos:pos + 2], 'big')
        tlv_len = int.from_bytes(payload[pos + 2:pos + 4], 'big')
        if tlv_len < 4 or pos + tlv_len > len(payload):
            break
        tlv_value = payload[pos + 4:pos + tlv_len]
        if tlv_type == 0x0001:
            value = tlv_value.decode(errors='ignore').rstrip('\x00')
            children.append({'title': f'Device ID: {value}', 'offset': offset + pos, 'length': tlv_len, 'children': [
                {'title': 'Type: Device ID (0x0001)', 'offset': offset + pos, 'length': 2},
                {'title': f'Length: {tlv_len}', 'offset': offset + pos + 2, 'length': 2},
                {'title': f'Device ID: {value}', 'offset': offset + pos + 4, 'length': len(tlv_value)},
            ]})
        elif tlv_type == 0x0005:
            sv_children = [
                {'title': 'Type: Software version (0x0005)', 'offset': offset + pos, 'length': 2},
                {'title': f'Length: {tlv_len}', 'offset': offset + pos + 2, 'length': 2},
            ]
            value_bytes = tlv_value.rstrip(b'\x00')
            line_start = 0
            while line_start < len(value_bytes):
                line_end = value_bytes.find(b'\n', line_start)
                has_newline = line_end != -1
                if line_end == -1:
                    line_end = len(value_bytes)
                line_bytes = value_bytes[line_start:line_end].rstrip(b'\r')
                line_length = (line_end - line_start) + (1 if has_newline else 0)
                if line_bytes:
                    sv_children.append({
                        'title': f'Software version: {line_bytes.decode(errors="ignore")}',
                        'offset': offset + pos + 4 + line_start,
                        'length': line_length,
                    })
                if not has_newline:
                    break
                line_start = line_end + 1
            children.append({'title': 'Software Version', 'offset': offset + pos, 'length': tlv_len, 'children': sv_children})
        elif tlv_type == 0x0006:
            value = tlv_value.decode(errors='ignore').rstrip('\x00')
            children.append({'title': f'Platform: {value}', 'offset': offset + pos, 'length': tlv_len, 'children': [
                {'title': 'Type: Platform (0x0006)', 'offset': offset + pos, 'length': 2},
                {'title': f'Length: {tlv_len}', 'offset': offset + pos + 2, 'length': 2},
                {'title': f'Platform: {value}', 'offset': offset + pos + 4, 'length': len(tlv_value)},
            ]})
        elif tlv_type == 0x0002:
            addr_children = [
                {'title': 'Type: Addresses (0x0002)', 'offset': offset + pos, 'length': 2},
                {'title': f'Length: {tlv_len}', 'offset': offset + pos + 2, 'length': 2},
            ]
            if len(tlv_value) >= 4:
                number = int.from_bytes(tlv_value[0:4], 'big')
                addr_children.append({'title': f'Number of addresses: {number}', 'offset': offset + pos + 4, 'length': 4})
                record_pos = 4
                for _ in range(number):
                    if record_pos + 4 > len(tlv_value):
                        break
                    proto_type = tlv_value[record_pos]
                    proto_len = tlv_value[record_pos + 1]
                    proto = tlv_value[record_pos + 2:record_pos + 2 + proto_len]
                    addr_len_offset = record_pos + 2 + proto_len
                    if addr_len_offset + 2 > len(tlv_value):
                        break
                    addr_len = int.from_bytes(tlv_value[addr_len_offset:addr_len_offset + 2], 'big')
                    addr_value = tlv_value[addr_len_offset + 2:addr_len_offset + 2 + addr_len]
                    ip_addr = '.'.join(str(b) for b in addr_value) if len(addr_value) == 4 else addr_value.hex()
                    record_offset = offset + pos + 4 + record_pos
                    addr_children.append({'title': f'IP address: {ip_addr}', 'offset': record_offset, 'length': 1 + 1 + proto_len + 2 + addr_len, 'children': [
                        {'title': f'Protocol type: NLPID (0x{proto_type:02x})', 'offset': record_offset, 'length': 1},
                        {'title': f'Protocol length: {proto_len}', 'offset': record_offset + 1, 'length': 1},
                        {'title': 'Protocol: IP' if proto == b'\xcc' else f'Protocol: {proto.hex()}', 'offset': record_offset + 2, 'length': proto_len},
                        {'title': f'Address length: {addr_len}', 'offset': record_offset + 2 + proto_len, 'length': 2},
                        {'title': f'IP Address: {ip_addr}', 'offset': record_offset + 4 + proto_len, 'length': addr_len},
                    ]})
                    record_pos = addr_len_offset + 2 + addr_len
            children.append({'title': 'Addresses', 'offset': offset + pos, 'length': tlv_len, 'children': addr_children})
        elif tlv_type == 0x0003:
            value = tlv_value.decode(errors='ignore').rstrip('\x00')
            children.append({'title': f'Port ID: {value}', 'offset': offset + pos, 'length': tlv_len, 'children': [
                {'title': 'Type: Port ID (0x0003)', 'offset': offset + pos, 'length': 2},
                {'title': f'Length: {tlv_len}', 'offset': offset + pos + 2, 'length': 2},
                {'title': f'Sent through Interface: {value}', 'offset': offset + pos + 4, 'length': len(tlv_value)},
            ]})
        elif tlv_type == 0x0004 and len(tlv_value) >= 4:
            capabilities = int.from_bytes(tlv_value[0:4], 'big')
            capabilities_offset = offset + pos + 4
            capabilities_children = []
            for pattern, label, mask in capability_lines:
                capabilities_children.append({
                    'title': f'{pattern} = {label}: {"Yes" if capabilities & mask else "No"}',
                    'offset': capabilities_offset,
                    'length': 4,
                })
            cap_children = [
                {'title': 'Type: Capabilities (0x0004)', 'offset': offset + pos, 'length': 2},
                {'title': f'Length: {tlv_len}', 'offset': offset + pos + 2, 'length': 2},
                {'title': f'Capabilities: 0x{capabilities:08x}', 'offset': capabilities_offset, 'length': 4, 'children': capabilities_children},
            ]
            children.append({'title': 'Capabilities', 'offset': offset + pos, 'length': tlv_len, 'children': cap_children})
        elif tlv_type == 0x0009:
            value = tlv_value.decode(errors='ignore').rstrip('\x00')
            children.append({'title': f'VTP Management Domain: {value}', 'offset': offset + pos, 'length': tlv_len, 'children': [
                {'title': 'Type: VTP Management Domain (0x0009)', 'offset': offset + pos, 'length': 2},
                {'title': f'Length: {tlv_len}', 'offset': offset + pos + 2, 'length': 2},
                {'title': f'VTP Management Domain: {value}', 'offset': offset + pos + 4, 'length': len(tlv_value)},
            ]})
        elif tlv_type == 0x000B and len(tlv_value) >= 1:
            duplex = 'Full' if tlv_value[0] else 'Half'
            children.append({'title': f'Duplex: {duplex}', 'offset': offset + pos, 'length': tlv_len, 'children': [
                {'title': 'Type: Duplex (0x000b)', 'offset': offset + pos, 'length': 2},
                {'title': f'Length: {tlv_len}', 'offset': offset + pos + 2, 'length': 2},
                {'title': f'Duplex: {duplex}', 'offset': offset + pos + 4, 'length': 1},
            ]})
        pos += tlv_len

    return {
        'title': 'Cisco Discovery Protocol',
        'offset': offset,
        'length': len(payload),
        'children': children,
    }


def _ldp_message_name(msg_type_val: int) -> str:
    return {
        0x0100: 'Hello Message',
        0x0200: 'Initialization Message',
        0x0201: 'Keep Alive Message',
        0x0300: 'Address Message',
        0x0301: 'Address Withdrawal Message',
        0x0400: 'Label Mapping Message',
        0x0401: 'Label Request Message',
        0x0402: 'Label Withdraw Message',
        0x0403: 'Label Release Message',
        0x0404: 'Label Abort Request Message',
        0x0001: 'Notification Message',
    }.get(msg_type_val, f'LDP Message (0x{msg_type_val:04x})')


def _ldp_tlv_unknown_bits_title(tlv_unknown_bits: int) -> str:
    return f'{tlv_unknown_bits:02b}.. .... = TLV Unknown bits: Known TLV, do not Forward (0x{tlv_unknown_bits:x})'


def _ldp_status_data_bits(status_data: int) -> str:
    bits = format(status_data & 0x3FFFFFFF, '030b')
    groups = [bits[:2], bits[2:6], bits[6:10], bits[10:14], bits[14:18], bits[18:22], bits[22:26], bits[26:30]]
    return f'..{groups[0]} {groups[1]} {groups[2]} {groups[3]} {groups[4]} {groups[5]} {groups[6]} {groups[7]}'


def _ldp_status_data_name(status_data: int) -> str:
    return {
        0x00000000: 'Success',
        0x0000000A: 'Shutdown',
    }.get(status_data, f'Unknown (0x{status_data:X})')


def _ldp_generic_label_bits(label_value: int) -> str:
    bits = format(label_value & 0xFFFFF, '020b')
    groups = [bits[0:4], bits[4:8], bits[8:12], bits[12:16], bits[16:20]]
    return f'.... .... .... {groups[0]} {groups[1]} {groups[2]} {groups[3]} {groups[4]}'


def _ldp_section(payload: bytes, offset: int) -> Dict[str, Any]:
    version = int.from_bytes(payload[0:2], 'big') if len(payload) >= 2 else 0
    pdu_len = int.from_bytes(payload[2:4], 'big') if len(payload) >= 4 else 0
    lsr_id = '.'.join(str(b) for b in payload[4:8]) if len(payload) >= 8 else '-'
    label_space = int.from_bytes(payload[8:10], 'big') if len(payload) >= 10 else 0
    pdu_end = min(len(payload), 4 + pdu_len) if pdu_len > 0 else len(payload)

    children = [
        {'title': f'Version: {version}', 'offset': offset, 'length': 2},
        {'title': f'PDU Length: {pdu_len}', 'offset': offset + 2, 'length': 2},
        {'title': f'LSR ID: {lsr_id}', 'offset': offset + 4, 'length': 4},
        {'title': f'Label Space ID: {label_space}', 'offset': offset + 8, 'length': 2},
    ]

    pos = 10
    while pos + 8 <= pdu_end:
        msg_header = int.from_bytes(payload[pos:pos + 2], 'big')
        u_bit = (msg_header >> 15) & 1
        msg_type_val = msg_header & 0x7FFF
        msg_len = int.from_bytes(payload[pos + 2:pos + 4], 'big')
        msg_id = int.from_bytes(payload[pos + 4:pos + 8], 'big') if pos + 8 <= len(payload) else 0
        total_len = 4 + msg_len
        msg_end = pos + total_len
        if msg_len < 4 or msg_end > pdu_end:
            break

        msg_name = _ldp_message_name(msg_type_val)
        msg_children = [
            {'title': f'{u_bit}... .... = U bit: Unknown bit {"set" if u_bit else "not set"}', 'offset': offset + pos, 'length': 1},
            {'title': f'Message Type: {msg_name} (0x{msg_type_val:x})', 'offset': offset + pos, 'length': 2},
            {'title': f'Message Length: {msg_len}', 'offset': offset + pos + 2, 'length': 2},
            {'title': f'Message ID: 0x{msg_id:08x}', 'offset': offset + pos + 4, 'length': 4},
        ]

        tlv_pos = pos + 8
        while tlv_pos + 4 <= msg_end:
            tlv_header = int.from_bytes(payload[tlv_pos:tlv_pos + 2], 'big')
            tlv_unknown_bits = (tlv_header >> 14) & 0x3
            tlv_type = tlv_header & 0x3FFF
            tlv_len = int.from_bytes(payload[tlv_pos + 2:tlv_pos + 4], 'big')
            tlv_end = tlv_pos + 4 + tlv_len
            if tlv_end > msg_end:
                break
            tlv_val = payload[tlv_pos + 4:tlv_end]

            if tlv_type == 0x0400 and tlv_len >= 4:
                hold_time = int.from_bytes(tlv_val[0:2], 'big')
                flags = int.from_bytes(tlv_val[2:4], 'big')
                targeted = (flags >> 15) & 1
                hello_req = (flags >> 14) & 1
                gtsm = (flags >> 13) & 1
                hello_reserved = flags & 0x1FFF
                reserved_bits = format(hello_reserved, '013b')
                pretty_reserved = f'...{reserved_bits[0]} {reserved_bits[1:5]} {reserved_bits[5:9]} {reserved_bits[9:13]}'
                gtsm_children = []
                if gtsm == 0:
                    gtsm_children.append({
                        'title': '[Expert Info (Chat/Protocol): GTSM is not supported by the source]',
                        'children': [
                            {'title': '[GTSM is not supported by the source]'},
                            {'title': '[Severity level: Chat]'},
                            {'title': '[Group: Protocol]'},
                        ],
                    })
                msg_children.append({
                    'title': 'Common Hello Parameters',
                    'offset': offset + tlv_pos,
                    'length': tlv_len + 4,
                    'children': [
                        {'title': _ldp_tlv_unknown_bits_title(tlv_unknown_bits), 'offset': offset + tlv_pos, 'length': 1},
                        {'title': f'TLV Type: Common Hello Parameters (0x{tlv_type:x})', 'offset': offset + tlv_pos, 'length': 2},
                        {'title': f'TLV Length: {tlv_len}', 'offset': offset + tlv_pos + 2, 'length': 2},
                        {'title': f'Hold Time: {hold_time}', 'offset': offset + tlv_pos + 4, 'length': 2},
                        {'title': f'{targeted}... .... .... .... = Targeted Hello: {"Targeted Hello" if targeted else "Link Hello"}', 'offset': offset + tlv_pos + 6, 'length': 2},
                        {'title': f'.{hello_req}.. .... .... .... = Hello Requested: Source {"requests" if hello_req else "does not request"} periodic hellos', 'offset': offset + tlv_pos + 6, 'length': 2},
                        {
                            'title': f'..{gtsm}. .... .... .... = GTSM Flag: {"Set" if gtsm else "Not set"}',
                            'offset': offset + tlv_pos + 6,
                            'length': 2,
                            'children': gtsm_children,
                        },
                        {'title': f'{pretty_reserved} = Reserved: 0x{hello_reserved:04x}', 'offset': offset + tlv_pos + 6, 'length': 2},
                    ],
                })
            elif tlv_type == 0x0401 and tlv_len == 4:
                ipv4_addr = '.'.join(str(b) for b in tlv_val)
                msg_children.append({
                    'title': 'IPv4 Transport Address',
                    'offset': offset + tlv_pos,
                    'length': tlv_len + 4,
                    'children': [
                        {'title': _ldp_tlv_unknown_bits_title(tlv_unknown_bits), 'offset': offset + tlv_pos, 'length': 1},
                        {'title': f'TLV Type: IPv4 Transport Address (0x{tlv_type:x})', 'offset': offset + tlv_pos, 'length': 2},
                        {'title': f'TLV Length: {tlv_len}', 'offset': offset + tlv_pos + 2, 'length': 2},
                        {'title': f'IPv4 Transport Address: {ipv4_addr}', 'offset': offset + tlv_pos + 4, 'length': 4},
                    ],
                })
            elif tlv_type == 0x0500 and tlv_len >= 14:
                session_protocol_version = int.from_bytes(tlv_val[0:2], 'big')
                keepalive_time = int.from_bytes(tlv_val[2:4], 'big')
                session_flags = int(tlv_val[4]) if len(tlv_val) >= 5 else 0
                label_advertisement = (session_flags >> 7) & 1
                loop_detection = (session_flags >> 6) & 1
                path_vector_limit = int(tlv_val[5]) if len(tlv_val) >= 6 else 0
                max_pdu_length = int.from_bytes(tlv_val[6:8], 'big') if len(tlv_val) >= 8 else 0
                receiver_lsr_id = '.'.join(str(b) for b in tlv_val[8:12]) if len(tlv_val) >= 12 else '-'
                receiver_label_space = int.from_bytes(tlv_val[12:14], 'big') if len(tlv_val) >= 14 else 0
                msg_children.append({
                    'title': 'Common Session Parameters',
                    'offset': offset + tlv_pos,
                    'length': tlv_len + 4,
                    'children': [
                        {'title': _ldp_tlv_unknown_bits_title(tlv_unknown_bits), 'offset': offset + tlv_pos, 'length': 1},
                        {'title': f'TLV Type: Common Session Parameters (0x{tlv_type:x})', 'offset': offset + tlv_pos, 'length': 2},
                        {'title': f'TLV Length: {tlv_len}', 'offset': offset + tlv_pos + 2, 'length': 2},
                        {
                            'title': 'Parameters',
                            'offset': offset + tlv_pos + 4,
                            'length': tlv_len,
                            'children': [
                                {'title': f'Session Protocol Version: {session_protocol_version}', 'offset': offset + tlv_pos + 4, 'length': 2},
                                {'title': f'Session KeepAlive Time: {keepalive_time}', 'offset': offset + tlv_pos + 6, 'length': 2},
                                {'title': f'{label_advertisement}... .... = Session Label Advertisement Discipline: {"Downstream on Demand proposed" if label_advertisement else "Downstream Unsolicited proposed"}', 'offset': offset + tlv_pos + 8, 'length': 1},
                                {'title': f'.{loop_detection}.. .... = Session Loop Detection: {"Loop Detection Enabled" if loop_detection else "Loop Detection Disabled"}', 'offset': offset + tlv_pos + 8, 'length': 1},
                                {'title': f'Session Path Vector Limit: {path_vector_limit}', 'offset': offset + tlv_pos + 9, 'length': 1},
                                {'title': f'Session Max PDU Length: {max_pdu_length}', 'offset': offset + tlv_pos + 10, 'length': 2},
                                {'title': f'Session Receiver LSR Identifier: {receiver_lsr_id}', 'offset': offset + tlv_pos + 12, 'length': 4},
                                {'title': f'Session Receiver Label Space Identifier: {receiver_label_space}', 'offset': offset + tlv_pos + 16, 'length': 2},
                            ],
                        },
                    ],
                })
            elif tlv_type == 0x0100 and tlv_len >= 1:
                fec_elements_children = []
                fec_pos = 0
                fec_index = 1
                while fec_pos < len(tlv_val):
                    fec_type = int(tlv_val[fec_pos])
                    if fec_type == 2 and fec_pos + 4 <= len(tlv_val):
                        fec_address_type = int.from_bytes(tlv_val[fec_pos + 1:fec_pos + 3], 'big')
                        fec_length = int(tlv_val[fec_pos + 3])
                        prefix_byte_len = (fec_length + 7) // 8
                        prefix_end = fec_pos + 4 + prefix_byte_len
                        if prefix_end > len(tlv_val):
                            break
                        prefix_raw = tlv_val[fec_pos + 4:prefix_end]
                        if fec_address_type == 1:
                            padded_prefix = prefix_raw + (b'\x00' * max(0, 4 - len(prefix_raw)))
                            prefix_text = '.'.join(str(b) for b in padded_prefix[:4])
                            fec_address_type_name = 'IPv4'
                        else:
                            prefix_text = prefix_raw.hex()
                            fec_address_type_name = f'Unknown ({fec_address_type})'
                        fec_elements_children.append({
                            'title': f'FEC Element {fec_index}',
                            'offset': offset + tlv_pos + 4 + fec_pos,
                            'length': prefix_end - fec_pos,
                            'children': [
                                {'title': f'FEC Element Type: Prefix FEC ({fec_type})', 'offset': offset + tlv_pos + 4 + fec_pos, 'length': 1},
                                {'title': f'FEC Element Address Type: {fec_address_type_name} ({fec_address_type})', 'offset': offset + tlv_pos + 4 + fec_pos + 1, 'length': 2},
                                {'title': f'FEC Element Length: {fec_length}', 'offset': offset + tlv_pos + 4 + fec_pos + 3, 'length': 1},
                                {'title': f'Prefix: {prefix_text}', 'offset': offset + tlv_pos + 4 + fec_pos + 4, 'length': prefix_byte_len},
                            ],
                        })
                        fec_pos = prefix_end
                        fec_index += 1
                    else:
                        break
                msg_children.append({
                    'title': 'FEC',
                    'offset': offset + tlv_pos,
                    'length': tlv_len + 4,
                    'children': [
                        {'title': _ldp_tlv_unknown_bits_title(tlv_unknown_bits), 'offset': offset + tlv_pos, 'length': 1},
                        {'title': f'TLV Type: FEC (0x{tlv_type:x})', 'offset': offset + tlv_pos, 'length': 2},
                        {'title': f'TLV Length: {tlv_len}', 'offset': offset + tlv_pos + 2, 'length': 2},
                        {'title': 'FEC Elements', 'offset': offset + tlv_pos + 4, 'length': tlv_len, 'children': fec_elements_children},
                    ],
                })
            elif tlv_type == 0x0200 and tlv_len == 4:
                generic_label = int.from_bytes(tlv_val[0:4], 'big') & 0xFFFFF
                msg_children.append({
                    'title': 'Generic Label',
                    'offset': offset + tlv_pos,
                    'length': tlv_len + 4,
                    'children': [
                        {'title': _ldp_tlv_unknown_bits_title(tlv_unknown_bits), 'offset': offset + tlv_pos, 'length': 1},
                        {'title': f'TLV Type: Generic Label (0x{tlv_type:x})', 'offset': offset + tlv_pos, 'length': 2},
                        {'title': f'TLV Length: {tlv_len}', 'offset': offset + tlv_pos + 2, 'length': 2},
                        {'title': f'{_ldp_generic_label_bits(generic_label)} = Generic Label: {generic_label} (0x{generic_label:05x})', 'offset': offset + tlv_pos + 4, 'length': 4},
                    ],
                })
            elif tlv_type == 0x0101 and tlv_len >= 2:
                address_family = int.from_bytes(tlv_val[0:2], 'big')
                address_family_name = 'IPv4' if address_family == 1 else f'Unknown ({address_family})'
                addresses_children = []
                address_bytes = tlv_val[2:]
                if address_family == 1:
                    for address_index, address_offset in enumerate(range(0, len(address_bytes), 4), start=1):
                        address_value = address_bytes[address_offset:address_offset + 4]
                        if len(address_value) != 4:
                            break
                        addresses_children.append({
                            'title': f'Address {address_index}: ' + '.'.join(str(b) for b in address_value),
                            'offset': offset + tlv_pos + 6 + address_offset,
                            'length': 4,
                        })
                msg_children.append({
                    'title': 'Address List',
                    'offset': offset + tlv_pos,
                    'length': tlv_len + 4,
                    'children': [
                        {'title': _ldp_tlv_unknown_bits_title(tlv_unknown_bits), 'offset': offset + tlv_pos, 'length': 1},
                        {'title': f'TLV Type: Address List (0x{tlv_type:x})', 'offset': offset + tlv_pos, 'length': 2},
                        {'title': f'TLV Length: {tlv_len}', 'offset': offset + tlv_pos + 2, 'length': 2},
                        {'title': f'Address Family: {address_family_name} ({address_family})', 'offset': offset + tlv_pos + 4, 'length': 2},
                        {'title': 'Addresses', 'offset': offset + tlv_pos + 6, 'length': max(0, tlv_len - 2), 'children': addresses_children},
                    ],
                })
            elif tlv_type == 0x0300 and tlv_len >= 10:
                status_code = int.from_bytes(tlv_val[0:4], 'big')
                status_message_id = int.from_bytes(tlv_val[4:8], 'big')
                status_message_type = int.from_bytes(tlv_val[8:10], 'big')
                e_bit = 1 if status_code & 0x80000000 else 0
                f_bit = 1 if status_code & 0x40000000 else 0
                status_data = status_code & 0x3FFFFFFF
                status_children = []
                if status_code != 0 or status_message_id != 0 or status_message_type != 0:
                    status_children = [
                        {'title': f'{e_bit}... .... = E Bit: {"Fatal Error Notification" if e_bit else "Advisory Notification"}', 'offset': offset + tlv_pos + 4, 'length': 1},
                        {'title': f'.{f_bit}.. .... = F Bit: Notification should {"be Forwarded" if f_bit else "NOT be Forwarded"}', 'offset': offset + tlv_pos + 4, 'length': 1},
                        {'title': f'{_ldp_status_data_bits(status_data)} = Status Data: {_ldp_status_data_name(status_data)} (0x{status_data:X})', 'offset': offset + tlv_pos + 4, 'length': 4},
                        {'title': f'Message ID: 0x{status_message_id:08x}', 'offset': offset + tlv_pos + 8, 'length': 4},
                        {'title': f'Message Type: {_ldp_message_name(status_message_type) if status_message_type else "Unknown"} (0x{status_message_type:04x})', 'offset': offset + tlv_pos + 12, 'length': 2},
                    ]
                msg_children.append({
                    'title': 'Status',
                    'offset': offset + tlv_pos,
                    'length': tlv_len + 4,
                    'children': [
                        {'title': _ldp_tlv_unknown_bits_title(tlv_unknown_bits), 'offset': offset + tlv_pos, 'length': 1},
                        {'title': f'TLV Type: Status (0x{tlv_type:x})', 'offset': offset + tlv_pos, 'length': 2},
                        {'title': f'TLV Length: {tlv_len}', 'offset': offset + tlv_pos + 2, 'length': 2},
                        {'title': 'Status', 'offset': offset + tlv_pos + 4, 'length': tlv_len, 'children': status_children},
                    ],
                })

            tlv_pos = tlv_end

        children.append({
            'title': msg_name,
            'offset': offset + pos,
            'length': total_len,
            'children': msg_children,
        })
        pos = msg_end

    return {
        'title': 'Label Distribution Protocol',
        'offset': offset,
        'length': len(payload),
        'children': children,
    }


def _l2tpv3_section(payload: bytes, offset: int) -> Dict[str, Any]:
    session_id = int.from_bytes(payload[:4], 'big') if len(payload) >= 4 else 0

    if _is_l2tpv3_control_payload(payload):
        flags = int.from_bytes(payload[4:6], 'big') if len(payload) >= 6 else 0
        length = int.from_bytes(payload[6:8], 'big') if len(payload) >= 8 else 0
        ccid = int.from_bytes(payload[8:12], 'big') if len(payload) >= 12 else 0
        ns = int.from_bytes(payload[12:14], 'big') if len(payload) >= 14 else 0
        nr = int.from_bytes(payload[14:16], 'big') if len(payload) >= 16 else 0
        version = flags & 0x000F
        avp_children = []
        children = [
            {'title': f'Session ID: 0x{session_id:08x}', 'offset': offset, 'length': 4},
            {
                'title': f'Flags: 0x{flags:04x}, Type: Control Message, Length Bit, Sequence Bit',
                'offset': offset + 4,
                'length': 2,
                'children': [
                    {'title': '1... .... .... .... = Type: Control Message (1)', 'offset': offset + 4, 'length': 2},
                    {'title': f'.{1 if flags & 0x4000 else 0}.. .... .... .... = Length Bit: Length field is {"present" if flags & 0x4000 else "not present"}', 'offset': offset + 4, 'length': 2},
                    {'title': f'.... {1 if flags & 0x0800 else 0}... .... .... = Sequence Bit: Ns and Nr fields are {"present" if flags & 0x0800 else "not present"}', 'offset': offset + 4, 'length': 2},
                    {'title': f'.... .... .... {version:04b} = Version: {version}', 'offset': offset + 4, 'length': 2},
                ],
            },
            {'title': f'Length: {length}', 'offset': offset + 6, 'length': 2},
            {'title': f'Control Connection ID: 0x{ccid:08x}', 'offset': offset + 8, 'length': 4},
            {'title': f'Ns: {ns}', 'offset': offset + 12, 'length': 2},
            {'title': f'Nr: {nr}', 'offset': offset + 14, 'length': 2},
        ]

        if len(payload) >= 24:
            avp_flags = int.from_bytes(payload[16:18], 'big')
            avp_len = avp_flags & 0x03FF
            vendor_id = int.from_bytes(payload[18:20], 'big') if len(payload) >= 20 else 0
            avp_type = int.from_bytes(payload[20:22], 'big') if len(payload) >= 22 else 0
            message_type = int.from_bytes(payload[22:24], 'big') if len(payload) >= 24 else 0
            message_name = {
                0: 'Reserved',
                1: 'SCCRQ',
                2: 'SCCRP',
                3: 'SCCCN',
                4: 'StopCCN',
                6: 'Hello',
            }.get(message_type, f'Control Message ({message_type})')
            avp_children = [
                {'title': f'1... .... .... .... = Mandatory: {"True" if avp_flags & 0x8000 else "False"}', 'offset': offset + 16, 'length': 2},
                {'title': f'.{1 if avp_flags & 0x4000 else 0}.. .... .... .... = Hidden: {"True" if avp_flags & 0x4000 else "False"}', 'offset': offset + 16, 'length': 2},
                {'title': f'.... ..{format(avp_len, "08b")[0:2]} {format(avp_len, "08b")[2:]} = Length: {avp_len}', 'offset': offset + 16, 'length': 2},
                {'title': f'Vendor ID: {"Reserved" if vendor_id == 0 else vendor_id} ({vendor_id})', 'offset': offset + 18, 'length': 2},
                {'title': f'AVP Type: {"Control Message" if avp_type == 0 else avp_type} ({avp_type})', 'offset': offset + 20, 'length': 2},
                {'title': f'Message Type: {message_name} ({message_type})', 'offset': offset + 22, 'length': 2},
            ]
            children.append({'title': 'Control Message AVP', 'offset': offset + 16, 'length': max(0, min(len(payload) - 16, avp_len)), 'children': avp_children})
        else:
            children.append({'title': 'Zero Length Body message'})

        return {
            'title': 'Layer 2 Tunneling Protocol version 3',
            'offset': offset,
            'length': len(payload),
            'children': children,
        }

    children = [
        {'title': f'Session ID: 0x{session_id:08x}', 'offset': offset, 'length': 4},
        {'title': '[Pseudowire Type: Unknown (0)]'},
    ]

    return {
        'title': 'Layer 2 Tunneling Protocol version 3',
        'offset': offset,
        'length': min(len(payload), 4),
        'children': children,
    }


def _bytes_data_section(raw_data: bytes, offset: int) -> Dict[str, Any]:
    return {
        'title': f'Data ({len(raw_data)} bytes)',
        'offset': offset,
        'length': len(raw_data),
        'children': [
            {'title': f'Data: {raw_data.hex()}'},
            {'title': f'[Length: {len(raw_data)}]'},
        ],
    }
    
    
def _simple_layer_section(
    title: str,
    layer,
    offset: int,
    length: int
) -> Dict[str, Any]:

    children = []

    # ---- FIELD WALK ----

    for field in getattr(layer, 'fields_desc', []):

        name = field.name

        try:
            value = layer.getfieldval(name)

        except Exception:
            continue

        # ---- RAW BYTES ----

        if isinstance(value, bytes):

            hex_str = value.hex()

            ascii_str = ''.join(

                chr(b)
                if b in PRINTABLE
                else '.'

                for b in value
            )

            preview = hex_str[:96]

            if len(hex_str) > 96:
                preview += '...'

            children.append({

                'title':
                    f'{name}: '
                    f'{preview}',

                'children': [

                    {
                        'title':
                            f'Length: {len(value)} bytes'
                    },

                    {
                        'title':
                            f'Hex: {hex_str}'
                    },

                    {
                        'title':
                            f'ASCII: {ascii_str}'
                    }
                ]
            })

        else:

            children.append({

                'title':
                    f'{name}: {value}'
            })

    # ---- FALLBACK ----

    if not children:

        try:

            raw_bytes = bytes(layer)

            hex_str = raw_bytes.hex()

            ascii_str = ''.join(

                chr(b)
                if b in PRINTABLE
                else '.'

                for b in raw_bytes
            )

            children.extend([

                {
                    'title':
                        f'Data ({len(raw_bytes)} bytes)'
                },

                {
                    'title':
                        f'Hex: {hex_str}'
                },

                {
                    'title':
                        f'ASCII: {ascii_str}'
                }
            ])

        except Exception:

            children.append({

                'title':
                    '(no decoded fields)'
            })

    return {

        'title': title,

        'offset': offset,
        'length': length,

        'children': children,
    }
    
def _data_section(layer, offset: int, length: int) -> Dict[str, Any]:

    raw_data = bytes(getattr(layer, 'load', b''))

    hex_data = raw_data.hex()

    preview_len = min(len(hex_data), 240)

    truncated_hex = hex_data[:preview_len]

    children = [

        {
            'title':
                f'Data […]: {truncated_hex}',

            'offset': offset,
            'length': length,
        },

        {
            'title':
                f'[Length: {length}]'
        }
    ]

    return {

        'title':
            f'Data ({length} bytes)',

        'offset': offset,
        'length': length,

        'children': children,
    }
