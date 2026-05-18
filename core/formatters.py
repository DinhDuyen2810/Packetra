from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List


from scapy.all import ARP, DNS, Ether, ICMP, IP, IPv6, TCP, UDP
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.inet6 import ICMPv6EchoRequest, ICMPv6EchoReply, ICMPv6ND_NA, ICMPv6ND_NS
from scapy.layers.l2 import Dot3, LLC, SNAP
from scapy.layers.tls.all import TLS, TLSClientHello  # type: ignore
from scapy.layers.quic import QUIC  # type: ignore
from scapy.layers.tls.record import TLSApplicationData

PRINTABLE = set(range(32, 127))

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
    '00:21:f6': 'Virtual Iron Software',
    '00:24:0e': 'Apple',
    '00:50:56': 'VMware',
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


def _internet_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b'\x00'
    total = 0
    for index in range(0, len(data), 2):
        total += (data[index] << 8) | data[index + 1]
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


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

        sections.append(
            _ipv6_section(
                packet[IPv6],
                offset,
                ipv6_stream_index,
            )
        )

        offset += 40

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

        tcp_payload = _tcp_payload_bytes(getattr(record, 'raw', None), tcp_layer)
        if getattr(record, 'protocol', '') == 'BGP' and tcp_payload:
            sections.append(_bgp_section(tcp_payload, offset))
            payload_handled = True
        elif getattr(record, 'protocol', '') == 'LDP' and tcp_payload:
            sections.append(_ldp_section(tcp_payload, offset))
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

        if sport == 646 or dport == 646:
            ldp_payload = bytes(getattr(udp_layer, 'payload', b''))
            sections.append(_ldp_section(ldp_payload, offset))
            payload_handled = True

    if effective_ip_layer is not None and not parsed_mpls_inner_ip:
        try:
            ip_proto = int(getattr(effective_ip_layer, 'proto', 0) or 0)
        except Exception:
            ip_proto = 0
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
                offset
            )
        )

        offset += len(dns_layer)

    if packet.haslayer(DHCP):

        dhcp_layer = packet[DHCP]

        sections.append(
            _dhcp_section(
                dhcp_layer,
                offset
            )
        )

        offset += len(dhcp_layer)

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

    if packet.haslayer(HTTPRequest):

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

    if packet.haslayer(HTTPResponse):

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
            _tls_section(
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

    iface = getattr(record, 'iface', None) or ''
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

    frame_number = getattr(record, 'number', 0)

    relative_time = float(
        getattr(record, 'relative_time', 0.0) or 0.0
    )

    metadata = getattr(record, 'metadata', {}) or {}

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
        protocol_string = 'eth:ethertype:ip:ospf'
    elif protocol == 'CDP':
        protocol_string = 'eth:llc:cdp'
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
    elif protocol == 'LDP':
        if metadata.get('tcp_stream_index', None) is not None and int(metadata.get('tcp_stream_index', -1)) >= 0:
            coloring_name = 'TCP'
            coloring_string = 'tcp'
        else:
            coloring_name = 'UDP'
            coloring_string = 'udp'
    elif protocol in {'OSPF', 'CDP', 'BGP'}:
        coloring_name = 'Routing'
        coloring_string = 'hsrp || eigrp || ospf || bgp || cdp || vrrp || carp || gvrp || igmp || ismp'
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
            'title': f'Interface id: 0 ({iface})',

            'children': [

                {
                    'title':
                        f'Interface name: {iface}'
                },

                {
                    'title':
                        'Interface description: Ethernet'
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
            f'on interface {iface}, id 0',

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
                    'offset': offset,
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
                    f'000. .... = Flags: 0x{flags:x}',
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
        6: 'TCP',
        17: 'UDP',
        58: 'ICMPv6',
    }

    nh_name = next_header_names.get(nh, str(nh))

    def ipv6_scope(addr: str):

        if addr.startswith('fe80'):
            return 'Link-local Unicast'

        if addr.startswith('ff'):
            return 'Multicast'

        return 'Global Unicast'

    children = [

        {
            'title':
                f'0110 .... = Version: {version}'
        },

        {
            'title':
                f'.... {format(tc, "08b")} '
                f'.... .... .... .... .... = '
                f'Traffic Class: '
                f'0x{tc:02x} '
                f'(DSCP: {dscp_name}, ECN: {ecn_name})',

            'children': [

                {
                    'title':
                        f'.... {format(dscp, "06b")}.. '
                        f'.... .... .... .... .... = '
                        f'Differentiated Services Codepoint: '
                        f'{dscp_name} ({dscp})'
                },

                {
                    'title':
                        f'.... .... ..{ecn:02b} '
                        f'.... .... .... .... .... = '
                        f'Explicit Congestion Notification: '
                        f'{ecn_name} ({ecn})'
                }
            ]
        },

        {
            'title':
                f'.... {format(fl, "020b")} = '
                f'Flow Label: 0x{fl:05x}'
        },

        {
            'title':
                f'Payload Length: {plen}'
        },

        {
            'title':
                f'Next Header: {nh_name} ({nh})'
        },

        {
            'title':
                f'Hop Limit: {hlim}'
        },

        {
            'title':
                f'Source Address: {src}',

            'children': [

                {
                    'title':
                        f'[Address Space: '
                        f'{ipv6_scope(src)}]'
                }
            ]
        },

        {
            'title':
                f'Destination Address: {dst}',

            'children': [

                {
                    'title':
                        f'[Address Space: '
                        f'{ipv6_scope(dst)}]'
                }
            ]
        },
    ]

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

def _tcp_section(layer, offset: int, stream_index: int, record=None) -> Dict[str, Any]:

    sport = int(getattr(layer, 'sport', 0) or 0)
    dport = int(getattr(layer, 'dport', 0) or 0)

    seq = int(getattr(layer, 'seq', 0) or 0)
    ack = int(getattr(layer, 'ack', 0) or 0)

    metadata = getattr(record, 'metadata', {}) if record else {}
    stream_pkt_num = int(metadata.get('tcp_stream_packet_number', 1) or 1)
    relative_seq = int(metadata.get('tcp_relative_seq', 1) or 1)
    relative_ack = int(metadata.get('tcp_relative_ack', 0) or 0)

    dataofs = int(getattr(layer, 'dataofs', 5) or 5)

    tcp_header_len = dataofs * 4

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

    next_seq = int(metadata.get('tcp_next_seq', relative_seq + payload_len) or (relative_seq + payload_len))

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

    completeness_marks = ''.join([
        'R' if completeness_rst else '·',
        'F' if completeness_fin else '·',
        'D' if completeness_data else '·',
        'A' if completeness_ack else '·',
        'K' if completeness_synack else '·',
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
            'title': f'Acknowledgment Number: {relative_ack}    (relative ack number)',
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
            'title': f'[Calculated window size: {window}]',
        },

        {
            'title': '[Window size scaling factor: -1 (unknown)]',
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
        children[10],
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

    options = getattr(layer, 'options', [])

    if options:

        option_children = []

        for opt in options:

            try:

                name, value = opt

                option_children.append({
                    'title': f'{name}: {value}'
                })

            except Exception:

                option_children.append({
                    'title': str(opt)
                })

        children.append({

            'title': 'Options',

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
        elif protocol_name == 'BGP':
            children.append({
                'title': f'[PDU Size: {payload_len}]',
            })

    return {

        'title':
            f'Transmission Control Protocol, '
            f'Src Port: {sport}, '
            f'Dst Port: {dport}, '
            f'Seq: {relative_seq}, '
            f'Ack: {relative_ack}, '
            f'Len: {payload_len}',

        'offset': offset,
        'length': tcp_header_len,
        'children': children,
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
            'title':
                f'Checksum: 0x{checksum:04x} '
                f'[unverified]',

            'offset': offset + 6,
            'length': 2,
        },

        {
            'title':
                '[Checksum Status: Unverified]',
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

def _dns_section(layer, offset: int) -> Dict[str, Any]:

    transaction_id = int(getattr(layer, 'id', 0) or 0)

    flags = int(getattr(layer, 'flags', 0) or 0)

    qdcount = int(getattr(layer, 'qdcount', 0) or 0)
    ancount = int(getattr(layer, 'ancount', 0) or 0)
    nscount = int(getattr(layer, 'nscount', 0) or 0)
    arcount = int(getattr(layer, 'arcount', 0) or 0)

    dns_len = len(layer)

    # ---- FLAGS ----

    qr = (flags >> 15) & 0x1
    opcode = (flags >> 11) & 0xF
    aa = (flags >> 10) & 0x1
    tc = (flags >> 9) & 0x1
    rd = (flags >> 8) & 0x1
    ra = (flags >> 7) & 0x1
    rcode = flags & 0xF

    opcode_names = {
        0: 'Standard query',
        1: 'Inverse query',
        2: 'Server status request',
    }

    rcode_names = {
        0: 'No error',
        1: 'Format error',
        2: 'Server failure',
        3: 'Name Error',
    }

    opcode_name = opcode_names.get(opcode, str(opcode))
    rcode_name = rcode_names.get(rcode, str(rcode))

    info = 'response' if qr else 'query'

    children = [

        {
            'title':
                f'Transaction ID: 0x{transaction_id:04x}',

            'offset': offset,
            'length': 2,
        },

        {
            'title':
                f'Flags: 0x{flags:04x} '
                f'({"Response" if qr else "Query"})',

            'offset': offset + 2,
            'length': 2,

            'children': [

                {
                    'title':
                        f'{qr}... .... .... .... = '
                        f'Response: '
                        f'{"Message is a response" if qr else "Message is a query"}',

                    'offset': offset + 2,
                    'length': 2,
                },

                {
                    'title':
                        f'.{opcode:04b} .... .... .... = '
                        f'Opcode: {opcode_name} ({opcode})',

                    'offset': offset + 2,
                    'length': 2,
                },

                {
                    'title':
                        f'..... {aa}... .... .... = '
                        f'Authoritative: '
                        f'{"Server is authoritative" if aa else "Server is not authoritative"}',

                    'offset': offset + 2,
                    'length': 2,
                },

                {
                    'title':
                        f'...... {tc}.. .... .... = '
                        f'Truncated: '
                        f'{"Message is truncated" if tc else "Message is not truncated"}',

                    'offset': offset + 2,
                    'length': 2,
                },

                {
                    'title':
                        f'....... {rd}. .... .... = '
                        f'Recursion desired: '
                        f'{"Do query recursively" if rd else "Do not query recursively"}',

                    'offset': offset + 2,
                    'length': 2,
                },

                {
                    'title':
                        f'........ {ra} .... .... = '
                        f'Recursion available: '
                        f'{"Server can do recursive queries" if ra else "Server cannot do recursive queries"}',

                    'offset': offset + 2,
                    'length': 2,
                },

                {
                    'title':
                        f'.... .... .... {rcode:04b} = '
                        f'Reply code: {rcode_name} ({rcode})',

                    'offset': offset + 2,
                    'length': 2,
                }
            ]
        },

        {
            'title':
                f'Questions: {qdcount}',

            'offset': offset + 4,
            'length': 2,
        },

        {
            'title':
                f'Answer RRs: {ancount}',

            'offset': offset + 6,
            'length': 2,
        },

        {
            'title':
                f'Authority RRs: {nscount}',

            'offset': offset + 8,
            'length': 2,
        },

        {
            'title':
                f'Additional RRs: {arcount}',

            'offset': offset + 10,
            'length': 2,
        },
    ]

    # ---- QUESTIONS ----

    questions = []

    try:

        qd = getattr(layer, 'qd', None)

        if qd:

            qname = getattr(qd, 'qname', b'')

            if isinstance(qname, bytes):
                qname = qname.decode(
                    errors='ignore'
                ).rstrip('.')

            qtype = getattr(qd, 'qtype', '-')
            qclass = getattr(qd, 'qclass', '-')

            questions.append({

                'title':
                    f'{qname}: type {qtype}, class {qclass}',

                'children': [

                    {
                        'title':
                            f'Name: {qname}'
                    },

                    {
                        'title':
                            f'Type: {qtype}'
                    },

                    {
                        'title':
                            f'Class: {qclass}'
                    }
                ]
            })

    except Exception:
        pass

    if questions:

        children.append({

            'title':
                f'Queries ({len(questions)})',

            'children': questions
        })

    # ---- ANSWERS ----

    answers = []

    try:

        an = getattr(layer, 'an', None)

        if an:

            current = an

            while current:

                rrname = getattr(current, 'rrname', b'')

                if isinstance(rrname, bytes):
                    rrname = rrname.decode(
                        errors='ignore'
                    ).rstrip('.')

                rrtype = getattr(current, 'type', '-')

                ttl = getattr(current, 'ttl', '-')

                rdata = getattr(current, 'rdata', '-')

                answers.append({

                    'title':
                        f'{rrname}: {rdata}',

                    'children': [

                        {
                            'title':
                                f'Name: {rrname}'
                        },

                        {
                            'title':
                                f'Type: {rrtype}'
                        },

                        {
                            'title':
                                f'TTL: {ttl}'
                        },

                        {
                            'title':
                                f'Address: {rdata}'
                        }
                    ]
                })

                current = getattr(
                    current,
                    'payload',
                    None
                )

                if not current or current.__class__.__name__ == 'NoPayload':
                    break

    except Exception:
        pass

    if answers:

        children.append({

            'title':
                f'Answers ({len(answers)})',

            'children': answers
        })

    return {

        'title':
            f'Domain Name System '
            f'({info})',

        'offset': offset,
        'length': dns_len,

        'children': children,
    }


def _dhcp_section(layer, offset: int) -> Dict[str, Any]:

    options = getattr(layer, 'options', [])

    option_children = []

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

    for item in options:

        if not isinstance(item, tuple):

            option_children.append({
                'title': str(item)
            })

            continue

        key = item[0]

        value = item[1] if len(item) > 1 else None

        # ---- MESSAGE TYPE ----

        if key == 'message-type':

            msg_name = dhcp_type_names.get(
                value,
                str(value)
            )

            option_children.append({

                'title':
                    f'Option: (53) DHCP Message Type '
                    f'({msg_name})'
            })

        # ---- HOSTNAME ----

        elif key == 'hostname':

            option_children.append({

                'title':
                    f'Option: (12) Host Name = {value}'
            })

        # ---- SERVER ID ----

        elif key == 'server_id':

            option_children.append({

                'title':
                    f'Option: (54) DHCP Server Identifier = {value}'
            })

        # ---- LEASE TIME ----

        elif key == 'lease_time':

            option_children.append({

                'title':
                    f'Option: (51) IP Address Lease Time = '
                    f'{value} seconds'
            })

        # ---- PARAM REQUEST LIST ----

        elif key == 'param_req_list':

            params = ', '.join(
                str(v)
                for v in value
            ) if isinstance(value, list) else str(value)

            option_children.append({

                'title':
                    f'Option: (55) Parameter Request List',

                'children': [

                    {
                        'title':
                            f'Parameter Request List Item: {params}'
                    }
                ]
            })

        # ---- VENDOR CLASS ----

        elif key == 'vendor_class_id':

            option_children.append({

                'title':
                    f'Option: (60) Vendor class identifier = {value}'
            })

        # ---- ROUTER ----

        elif key == 'router':

            option_children.append({

                'title':
                    f'Option: (3) Router = {value}'
            })

        # ---- DNS ----

        elif key == 'name_server':

            option_children.append({

                'title':
                    f'Option: (6) Domain Name Server = {value}'
            })

        else:

            option_children.append({

                'title':
                    f'{key}: {value}'
            })

    return {

        'title':
            'Dynamic Host Configuration Protocol',

        'offset': offset,
        'length': len(layer),

        'children':

            option_children

            if option_children else [

                {
                    'title': 'No DHCP options'
                }
            ]
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