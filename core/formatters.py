from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List

from scapy.all import ARP, DNS, Ether, ICMP, IP, IPv6, TCP, UDP
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.inet6 import ICMPv6EchoRequest, ICMPv6EchoReply, ICMPv6ND_NA, ICMPv6ND_NS
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


def packet_summary_tree(packet, record) -> List[Dict[str, Any]]:

    sections: List[Dict[str, Any]] = []

    offset = 0

    metadata = getattr(record, 'metadata', {}) or {}

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

    if packet.haslayer(Ether):

        padding_hex = ''
        padding_len = 0
        padding_offset = 0
        if packet.haslayer('Padding'):
            try:
                padding_bytes = bytes(packet['Padding'])
                padding_hex = padding_bytes.hex()
                padding_len = len(padding_bytes)
                frame_len = int(getattr(record, 'length', len(bytes(packet))) or len(bytes(packet)))
                padding_offset = max(0, frame_len - padding_len)
            except Exception:
                padding_hex = ''
                padding_len = 0
                padding_offset = 0

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

    if packet.haslayer(ARP):

        sections.append(
            _arp_section(
                packet[ARP],
                offset
            )
        )

        offset += 28

    if packet.haslayer(IP):

        ip_layer = packet[IP]

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

    if packet.haslayer(TCP):

        tcp_layer = packet[TCP]

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

    elif packet.haslayer(UDP):

        udp_layer = packet[UDP]

        sections.append(
            _udp_section(
                udp_layer,
                offset,
                udp_stream_index,
                record,
            )
        )

        offset += 8

    if packet.haslayer(ICMP):

        icmp_layer = packet[ICMP]

        sections.append(
            _simple_layer_section(
                'Internet Control Message Protocol',
                icmp_layer,
                offset,
                len(icmp_layer)
            )
        )

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

    if packet.haslayer('Raw') and not packet.haslayer(TLS):

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

        if lname in ('ether', 'ethernet'):
            protocol_stack.append('eth')

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
    
    protocol_string = ':'.join(protocol_stack)

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
        
        {
            'title':
                f'[Coloring Rule Name: {protocol}]'
        },

        {
            'title':
                f'[Coloring Rule String: '
                f'{protocol.lower()}]'
        }
    ]

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

        if not vendor:
            return mac

        suffix = ':'.join(mac.split(':')[-3:])

        return f'{vendor}_{suffix} ({mac})'

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
        0x86DD: 'IPv6',
        0x8100: '802.1Q VLAN',
        0x88CC: 'LLDP',
        0x8847: 'MPLS',
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
                    'title': f'.... ..{"1" if dst_local else "0"}. .... .... .... .... = LG bit: {"Locally administered" if dst_local else "Globally unique"} address ({"factory default" if not dst_local else "locally assigned"})',
                    'offset': offset,
                    'length': 3,
                },
                {
                    'title': f'.... ...{"1" if dst_group else "0"} .... .... .... .... = IG bit: {"Group" if dst_group else "Individual"} address ({"multicast" if dst_group else "unicast"})',
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
                    'title': f'.... ..{"1" if src_local else "0"}. .... .... .... .... = LG bit: {"Locally administered" if src_local else "Globally unique"} address ({"factory default" if not src_local else "locally assigned"})',
                    'offset': offset + 6,
                    'length': 3,
                },
                {
                    'title': f'.... ...{"1" if src_group else "0"} .... .... .... .... = IG bit: {"Group" if src_group else "Individual"} address ({"multicast" if src_group else "unicast"})',
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
    }

    operation = op_names.get(op, str(op))

    hwtype_names = {
        1: 'Ethernet',
    }

    ptype_names = {
        0x0800: 'IPv4',
        0x86DD: 'IPv6',
    }

    hwtype_name = hwtype_names.get(
        hwtype,
        str(hwtype)
    )

    ptype_name = ptype_names.get(
        ptype,
        f'0x{ptype:04x}'
    )

    children = [

        {
            'title':
                f'Hardware type: '
                f'{hwtype_name} ({hwtype})',

            'offset': offset,
            'length': 2,
        },

        {
            'title':
                f'Protocol type: '
                f'{ptype_name} '
                f'(0x{ptype:04x})',

            'offset': offset + 2,
            'length': 2,
        },

        {
            'title':
                f'Hardware size: {hwlen}',

            'offset': offset + 4,
            'length': 1,
        },

        {
            'title':
                f'Protocol size: {plen}',

            'offset': offset + 5,
            'length': 1,
        },

        {
            'title':
                f'Opcode: {operation} ({op})',

            'offset': offset + 6,
            'length': 2,
        },

        {
            'title':
                f'Sender MAC address: {hwsrc}',

            'offset': offset + 8,
            'length': 6,
        },

        {
            'title':
                f'Sender IP address: {psrc}',

            'offset': offset + 14,
            'length': 4,
        },

        {
            'title':
                f'Target MAC address: {hwdst}',

            'offset': offset + 18,
            'length': 6,
        },

        {
            'title':
                f'Target IP address: {pdst}',

            'offset': offset + 24,
            'length': 4,
        }
    ]

    return {

        'title':
            f'Address Resolution Protocol '
            f'({operation})',

        'offset': offset,
        'length': 28,

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

    payload = bytes(getattr(layer, 'payload', b""))
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
    bytes_in_flight = metadata.get('tcp_bytes_in_flight', None)
    bytes_since_last_psh = metadata.get('tcp_bytes_since_last_psh', None)

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
                        'title': f'..{"1" if flag_bits["RST"] else "0"}. .... = RST: {"Present" if flag_bits["RST"] else "Absent"}',
                    },
                    {
                        'title': f'...{"1" if flag_bits["FIN"] else "0"} .... = FIN: {"Present" if flag_bits["FIN"] else "Absent"}',
                    },
                    {
                        'title': f'.... {"1" if payload_len > 0 else "0"}... = Data: {"Present" if payload_len > 0 else "Absent"}',
                    },
                    {
                        'title': f'.... .{"1" if flag_bits["ACK"] else "0"}.. = ACK: {"Present" if flag_bits["ACK"] else "Absent"}',
                    },
                    {
                        'title': f'.... ..{"1" if (flag_bits["SYN"] and flag_bits["ACK"]) else "0"}. = SYN-ACK: {"Present" if (flag_bits["SYN"] and flag_bits["ACK"]) else "Absent"}',
                    },
                    {
                        'title': f'.... ...{"1" if (flag_bits["SYN"] and not flag_bits["ACK"]) else "0"} = SYN: {"Present" if (flag_bits["SYN"] and not flag_bits["ACK"]) else "Absent"}',
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
    if ack_frame_number is not None:
        seq_ack_children.append({
            'title': f'[This is an ACK to the segment in frame: {int(ack_frame_number)}]',
        })
    if ack_rtt_ms is not None:
        seq_ack_children.append({
            'title': f'[The RTT to ACK the segment was: {float(ack_rtt_ms):.6f} milliseconds]',
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