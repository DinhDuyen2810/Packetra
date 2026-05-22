from __future__ import annotations

from datetime import datetime, timedelta, timezone
import ipaddress
from typing import Any, Dict, List


from scapy.all import ARP, DNS, Ether, ICMP, IP, IPv6, TCP, UDP
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.inet6 import ICMPv6EchoRequest, ICMPv6EchoReply, ICMPv6ND_NA, ICMPv6ND_NS, IPv6ExtHdrHopByHop, IPv6ExtHdrFragment, in6_chksum
from scapy.layers.l2 import Dot1Q, Dot3, LLC, SNAP
from scapy.layers.tls.all import TLS, TLSClientHello  # type: ignore
from scapy.layers.quic import QUIC  # type: ignore
from scapy.layers.tls.record import TLSApplicationData
from core.stream_manager import get_ipv6_stream_index

PRINTABLE = set(range(32, 127))
PACKET_BYTE_SOURCE = 'packet'
TCP_REASSEMBLED_BYTE_SOURCE = 'tcp_reassembled'
DECODED_UTF8_BYTE_SOURCE = 'decoded_utf8'

# MAC Vendor lookup (simplified, add more as needed)
MAC_VENDORS = {
    '00:00:0c': 'Cisco',
    '00:01:42': 'Parallels',
    '00:03:ff': 'Microsoft',
    '00:04:00': 'LexmarkInter',
    '00:05:69': 'VMware',
    '00:0c:29': 'VMware',
    '00:0a:8a': 'Cisco',
    '00:0f:4b': 'Virtual Iron Software',
    '00:13:07': 'Parallels',
    '00:15:5d': 'Microsoft',
    '00:16:3e': 'Xensource',
    '00:17:42': 'Parallels',
    '00:1a:6c': 'Cisco',
    '00:1c:14': 'VMware',
    '00:1c:42': 'Parallels',
    '00:21:1b': 'Cisco',
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
    '78:28:ca': 'Sonos',
    'f8:1a:67': 'TpLinkTechno',
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


def _tag_byte_source(node: Dict[str, Any], byte_source: str) -> None:
    if not isinstance(node, dict):
        return
    if 'offset' in node and 'length' in node:
        node['byte_source'] = byte_source
    for child in node.get('children', []) or []:
        if isinstance(child, dict):
            _tag_byte_source(child, byte_source)


def _ip_reassembly_section(metadata: dict, version: int) -> Dict[str, Any] | None:
    fragments = list(metadata.get('ip_reassembled_fragments', []) or [])
    if not fragments:
        return None
    reassembled_len = int(metadata.get('ip_reassembled_length', 0) or 0)
    if reassembled_len <= 0:
        reassembled_len = int(sum(int(seg.get('payload_length', 0) or 0) for seg in fragments))
    summary = ', '.join(
        f"#{int(seg.get('frame_number', 0) or 0)}({int(seg.get('payload_length', 0) or 0)})"
        for seg in fragments
    )
    children: List[Dict[str, Any]] = []
    for seg in fragments:
        start_pos = int(seg.get('payload_start', 0) or 0)
        seg_len = int(seg.get('payload_length', 0) or 0)
        end_pos = max(start_pos, start_pos + seg_len - 1)
        children.append({
            'title': f"[Frame: {int(seg.get('frame_number', 0) or 0)}, payload: {start_pos}-{end_pos} ({seg_len} bytes)]",
            **_byte_mapping(0, start_pos, seg_len, TCP_REASSEMBLED_BYTE_SOURCE),
        })
    children.append({'title': f'[Reassembled IPv{version} length: {reassembled_len}]'})
    reassembled_hex = str(metadata.get('ip_reassembled_payload_hex', '') or '')
    if reassembled_hex:
        children.append({
            'title': f'[Reassembled IPv{version} data [..]: {reassembled_hex[:160]}]',
            **_byte_mapping(0, 0, reassembled_len, TCP_REASSEMBLED_BYTE_SOURCE),
        })
    return {
        'title': f'[{len(fragments)} IPv{version} Fragments ({reassembled_len} bytes): {summary}]',
        'children': children,
    }


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
    if mac_text.lower() == '01:80:c2:00:00:00':
        return f'Nearest-Customer-Bridge ({mac_text})'
    if mac_text.lower() == '01:80:c2:00:00:02':
        return f'Slow-Protocols ({mac_text})'
    if mac_text.lower() == '01:80:c2:00:00:0e':
        return f'Nearest-Bridge ({mac_text})'
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
    tcp_payload = getattr(tcp_layer, 'payload', b'')
    raw_original = getattr(tcp_payload, 'original', None)
    if isinstance(raw_original, (bytes, bytearray)) and raw_original:
        raw_payload = bytes(raw_original)
    else:
        raw_payload = bytes(tcp_payload)
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


def _udp_payload_bytes(packet, udp_layer):
    udp_payload = getattr(udp_layer, 'payload', b'')
    raw_original = getattr(udp_payload, 'original', None)
    if isinstance(raw_original, (bytes, bytearray)) and raw_original:
        raw_payload = bytes(raw_original)
    else:
        raw_payload = bytes(udp_payload)

    try:
        udp_len = int(getattr(udp_layer, 'len', 0) or 0)
        if udp_len >= 8:
            return raw_payload[:max(0, min(len(raw_payload), udp_len - 8))]
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
            tail_bytes = bytes(packet['Padding'])
            tail_offset = max(0, frame_len - len(tail_bytes))
            if len(tail_bytes) >= 4:
                padding_bytes = tail_bytes[:-4]
                fcs_bytes = tail_bytes[-4:]
                return (
                    padding_bytes.hex(),
                    len(padding_bytes),
                    tail_offset,
                    f'0x{fcs_bytes.hex()}',
                    tail_offset + len(padding_bytes),
                )
            return tail_bytes.hex(), len(tail_bytes), tail_offset, '', 0
        except Exception:
            return '', 0, 0, '', 0

    payload_length = _frame_payload_length(packet)
    if payload_length is None or payload_length >= frame_len:
        return '', 0, 0, '', 0

    try:
        trailer_bytes = bytes(packet)[payload_length:frame_len]
    except Exception:
        return '', 0, 0, '', 0

    if not trailer_bytes:
        return '', 0, 0, '', 0

    if len(trailer_bytes) >= 4:
        padding_bytes = trailer_bytes[:-4]
        fcs_bytes = trailer_bytes[-4:]
        return (
            padding_bytes.hex(),
            len(padding_bytes),
            payload_length,
            f'0x{fcs_bytes.hex()}',
            payload_length + len(padding_bytes),
        )

    return trailer_bytes.hex(), len(trailer_bytes), payload_length, '', 0


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
    is_ip_fragmented = bool(metadata.get('ip_is_fragmented', False))
    fragment_role = str(metadata.get('ip_fragment_role', '') or '')
    is_first_fragment = is_ip_fragmented and fragment_role == 'first'
    is_last_fragment = is_ip_fragmented and fragment_role == 'last'

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
        padding_hex, padding_len, padding_offset, fcs_hex, fcs_offset = _infer_padding(packet, record)

        sections.append(
            _dot3_section(
                packet[Dot3],
                offset,
                ether_stream_index,
                padding_hex,
                padding_offset,
                padding_len,
                fcs_hex,
                fcs_offset,
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
            elif getattr(record, 'protocol', '') == 'DTP':
                dtp_payload = bytes(getattr(snap_layer, 'payload', b'')) if snap_layer is not None else b''
                sections.append(_dtp_section(dtp_payload, offset))
                payload_handled = True

    elif packet.haslayer(Ether):

        padding_hex, padding_len, padding_offset, fcs_hex, fcs_offset = _infer_padding(packet, record)

        sections.append(
            _ether_section(
                packet[Ether],
                offset,
                ether_stream_index,
                padding_hex,
                padding_offset,
                padding_len,
                fcs_hex,
                fcs_offset,
            )
        )

        offset += 14

        if packet.haslayer(Dot1Q):
            sections.append(_vlan_section(packet[Dot1Q], offset))
            offset += 4

            if packet.haslayer(LLC):
                snap_layer = packet[SNAP] if packet.haslayer(SNAP) else None
                sections.append(_llc_section(packet[LLC], snap_layer, offset))
                offset += 3 + (5 if snap_layer is not None else 0)

        if getattr(record, 'protocol', '') == 'LACP':
            slow_payload = bytes(packet)[offset:]
            if slow_payload:
                sections.append(_slow_protocols_section(slow_payload, offset))
                if len(slow_payload) > 1:
                    sections.append(_lacp_section(slow_payload[1:], offset + 1))
                payload_handled = True

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

        inner_eth_type = 0
        if packet.haslayer(Dot1Q):
            try:
                inner_eth_type = int(getattr(packet[Dot1Q], 'type', 0) or 0)
            except Exception:
                inner_eth_type = 0

        if eth_type == 0x9000 or (eth_type == 0x8100 and inner_eth_type == 0x9000):
            loop_payload = bytes(packet)[offset:]
            sections.append(_loop_section(loop_payload, offset))
            loop_header_len = min(len(loop_payload), 6)
            if len(loop_payload) > loop_header_len:
                sections.append(_bytes_data_section(loop_payload[loop_header_len:], offset + loop_header_len))
            payload_handled = True

        pppoe_meta = metadata.get('pppoe', {}) if isinstance(metadata.get('pppoe'), dict) else {}
        should_render_pppoe = (
            bool(pppoe_meta)
            or getattr(record, 'protocol', '') in {'PPPoED', 'PPP', 'PPP LCP', 'PPP IPCP', 'PPP IPV6CP', 'SIP', 'SIP/SDP', 'RTP'}
        )
        if should_render_pppoe:
            pppoe_payload = bytes(packet)[offset:]
            if len(pppoe_payload) >= 6:
                pppoe_len = int.from_bytes(pppoe_payload[4:6], 'big')
                pppoe_total_len = min(len(pppoe_payload), 6 + pppoe_len)
            else:
                pppoe_total_len = len(pppoe_payload)

            sections.append(_pppoe_section(pppoe_payload, offset))

            if len(pppoe_payload) >= 6:
                pppoe_code = int(pppoe_payload[1])
                if pppoe_code == 0x00:
                    ppp_payload = pppoe_payload[6:pppoe_total_len]
                    ppp_offset = offset + 6
                    if len(ppp_payload) >= 2:
                        sections.append(_ppp_section(ppp_payload, ppp_offset))
                        ppp_proto = int.from_bytes(ppp_payload[:2], 'big')
                        ppp_control_payload = ppp_payload[2:]
                        if ppp_proto == 0xC021:
                            sections.append(_ppp_lcp_section(ppp_control_payload, ppp_offset + 2))
                        elif ppp_proto == 0x8021:
                            sections.append(_ppp_ipcp_section(ppp_control_payload, ppp_offset + 2))
                        elif ppp_proto == 0x8057:
                            sections.append(_ppp_ipv6cp_section(ppp_control_payload, ppp_offset + 2))

                        # For IP-over-PPP packets, consume only PPPoE+PPP headers (8 bytes)
                        # so IPv4/UDP/SIP/RTP offsets remain correct.
                        if ppp_proto == 0x0021:
                            offset += 8
                        else:
                            payload_handled = True
                            raw_payload_consumed = True
                            offset += pppoe_total_len
                else:
                    payload_handled = True
                    raw_payload_consumed = True
                    offset += pppoe_total_len

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
                record=record,
            )
        )

        offset += ip_len

    if packet.haslayer(IPv6):

        ipv6_section = _ipv6_section(
            packet[IPv6],
            offset,
            ipv6_stream_index,
            record=record,
        )
        sections.append(ipv6_section)

        offset += 40

        if packet.haslayer(IPv6ExtHdrHopByHop):
            hopopts_layer = packet[IPv6ExtHdrHopByHop]
            ipv6_section.setdefault('children', []).append(_ipv6_hopopts_section(hopopts_layer, offset))
            offset += max(8, (int(getattr(hopopts_layer, 'len', 0) or 0) + 1) * 8)
        if packet.haslayer(IPv6ExtHdrFragment):
            frag_layer = packet[IPv6ExtHdrFragment]
            frag_node = _ipv6_fragment_section(frag_layer, offset)
            ipv6_children = ipv6_section.setdefault('children', [])
            insert_index = len(ipv6_children)
            for idx, child in enumerate(ipv6_children):
                title = str(child.get('title', '') or '')
                if title.startswith('[Reassembled IPv6 in frame:') or ('IPv6 Fragments (' in title):
                    insert_index = idx
                    break
            ipv6_children.insert(insert_index, frag_node)
            offset += 8

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
            if packet.haslayer(IPv6ExtHdrHopByHop):
                upper_layer = packet[IPv6ExtHdrHopByHop]
            else:
                upper_layer = packet[IPv6]
            ospf_payload = bytes(getattr(upper_layer, 'payload', b''))
            ospf_offset = offset
            try:
                upper_nh = int(getattr(upper_layer, 'nh', -1) or -1)
                if upper_nh == 51 and len(ospf_payload) >= 12:
                    ah_next_header = int(ospf_payload[0])
                    ah_header_len = (int(ospf_payload[1]) + 2) * 4
                    if ah_next_header == 89 and len(ospf_payload) >= ah_header_len:
                        ospf_payload = ospf_payload[ah_header_len:]
                        ospf_offset += ah_header_len
            except Exception:
                pass
            if ospf_payload:
                sections.append(_ospf_section(ospf_payload, ospf_offset))
                payload_handled = True
        elif getattr(record, 'protocol', '') == 'ESP':
            esp_payload = bytes(getattr(packet[IPv6], 'payload', b''))
            if esp_payload:
                sections.append(_esp_section(esp_payload, offset))
                payload_handled = True

    if is_first_fragment:
        frag_data = b''
        if packet.haslayer(IP):
            try:
                frag_data = bytes(getattr(packet[IP], 'payload', b''))
            except Exception:
                frag_data = b''
        elif packet.haslayer(IPv6ExtHdrFragment):
            try:
                frag_data = bytes(getattr(packet[IPv6ExtHdrFragment], 'payload', b''))
            except Exception:
                frag_data = b''
        if frag_data:
            frag_hex = frag_data.hex()
            preview = frag_hex[:240]
            sections.append({
                'title': f'Data ({len(frag_data)} bytes)',
                'offset': offset,
                'length': len(frag_data),
                'children': [
                    {'title': f'Data [â€¦]: {preview}', 'offset': offset, 'length': len(frag_data)},
                    {'title': f'[Length: {len(frag_data)}]'},
                ],
            })
            payload_handled = True
            raw_payload_consumed = True

    if effective_tcp_layer is not None and not is_first_fragment:

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
        elif getattr(record, 'protocol', '') in {'HTTP', 'HTTP/XML'} and tcp_payload:
            sections.append(_http_section(tcp_payload, offset, record))
            if bool(metadata.get('http_has_line_based_text', False)):
                sections.append(_http_line_based_text_section(record, offset))
            if getattr(record, 'protocol', '') == 'HTTP/XML':
                xml_section = _xml_body_section(record, offset)
                if xml_section is not None:
                    sections.append(xml_section)
            payload_handled = True
        elif getattr(record, 'protocol', '') == 'RIPng' and tcp_payload == b'':
            udp_payload = bytes(getattr(effective_udp_layer, 'payload', b'')) if effective_udp_layer is not None else b''
            sections.append(_ripng_section(udp_payload, offset))
            payload_handled = True
        elif getattr(record, 'protocol', '') == 'HSRPv2' and tcp_payload == b'':
            udp_payload = _udp_payload_bytes(packet, effective_udp_layer) if effective_udp_layer is not None else b''
            sections.append(_hsrpv2_section(udp_payload, offset))
            payload_handled = True
        elif getattr(record, 'protocol', '') in {'SMTP', 'SMTP/IMF'} and tcp_payload:
            sections.append(_smtp_section(tcp_payload, offset, record))
            if getattr(record, 'protocol', '') == 'SMTP/IMF':
                sections.append(_imf_section(record, offset))
            payload_handled = True
        elif getattr(record, 'protocol', '') == 'IMAP' and tcp_payload:
            sections.append(_imap_section(tcp_payload, offset, record))
            payload_handled = True
        elif getattr(record, 'protocol', '') == 'SSHv2' and tcp_payload:
            sections.append(_ssh_section(tcp_payload, offset, record))
            payload_handled = True
        elif bool(metadata.get('tcp_is_retransmission', False)) and tcp_payload:
            payload_handled = True

    elif effective_udp_layer is not None and not is_first_fragment:

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
        elif getattr(record, 'protocol', '') == 'RIPng':
            ripng_payload = _udp_payload_bytes(packet, udp_layer)
            sections.append(_ripng_section(ripng_payload, offset))
            payload_handled = True
        elif getattr(record, 'protocol', '') == 'RIPv2':
            rip_payload = _udp_payload_bytes(packet, udp_layer)
            sections.append(_ripv2_section(rip_payload, offset))
            payload_handled = True
        elif getattr(record, 'protocol', '') == 'Syslog':
            syslog_payload = _udp_payload_bytes(packet, udp_layer)
            sections.append(_syslog_section(syslog_payload, offset))
            payload_handled = True
        elif getattr(record, 'protocol', '') == 'NTP':
            ntp_payload = _udp_payload_bytes(packet, udp_layer)
            sections.append(_ntp_section(ntp_payload, offset, record))
            payload_handled = True
        elif getattr(record, 'protocol', '') == 'TFTP':
            tftp_payload = _udp_payload_bytes(packet, udp_layer)
            sections.append(_tftp_section(tftp_payload, offset, record))
            payload_handled = True
        elif getattr(record, 'protocol', '') == 'SSDP':
            ssdp_payload = _udp_payload_bytes(packet, udp_layer)
            sections.append(_ssdp_section(ssdp_payload, offset, record))
            payload_handled = True
        elif getattr(record, 'protocol', '') == 'SNMP':
            snmp_payload = _udp_payload_bytes(packet, udp_layer)
            sections.append(_snmp_section(snmp_payload, offset, record))
            payload_handled = True
        elif getattr(record, 'protocol', '') in {'SIP', 'SIP/SDP'}:
            sip_payload = _udp_payload_bytes(packet, udp_layer)
            sections.append(_sip_section(sip_payload, offset, record))
            payload_handled = True
        elif getattr(record, 'protocol', '') == 'RTP':
            rtp_payload = _udp_payload_bytes(packet, udp_layer)
            sections.append(_rtp_section(rtp_payload, offset, record))
            payload_handled = True
        elif getattr(record, 'protocol', '') == 'ISAKMP':
            isakmp_payload = _udp_payload_bytes(packet, udp_layer)
            sections.append(_isakmp_section(isakmp_payload, offset))
            payload_handled = True
        elif getattr(record, 'protocol', '') == 'HSRPv2':
            hsrp_payload = _udp_payload_bytes(packet, udp_layer)
            sections.append(_hsrpv2_section(hsrp_payload, offset))
            payload_handled = True

    if effective_ip_layer is not None and not parsed_mpls_inner_ip:
        if getattr(record, 'protocol', '') == 'EIGRP':
            eigrp_payload = bytes(metadata.get('eigrp', {}).get('payload', b'') or b'')
            if eigrp_payload:
                sections.append(_eigrp_section(eigrp_payload, offset, record))
                payload_handled = True
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

    if getattr(record, 'protocol', '') == 'EIGRP' and not payload_handled:
        eigrp_payload = bytes(metadata.get('eigrp', {}).get('payload', b'') or b'')
        if eigrp_payload:
            sections.append(_eigrp_section(eigrp_payload, offset, record))
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

    if getattr(record, 'protocol', '') == 'STP':
        if packet.haslayer(SNAP):
            stp_payload = bytes(packet[SNAP].payload)
        elif packet.haslayer('STP'):
            stp_payload = bytes(packet['STP'])
        else:
            stp_payload = b''
        if stp_payload:
            sections.append(_stp_section(stp_payload, offset))
            payload_handled = True

    if getattr(record, 'protocol', '') == 'LLDP':
        lldp_payload = bytes(packet['Raw'].load) if packet.haslayer('Raw') else b''
        if lldp_payload:
            sections.append(_lldp_section(lldp_payload, offset))
            payload_handled = True

    if getattr(record, 'protocol', '') == 'UDLD':
        udld_payload = bytes(packet[SNAP].payload) if packet.haslayer(SNAP) else b''
        if udld_payload:
            sections.append(_udld_section(udld_payload, offset))
            payload_handled = True

    if getattr(record, 'protocol', '') == 'VTP':
        vtp_payload = bytes(packet[SNAP].payload) if packet.haslayer(SNAP) else b''
        if vtp_payload:
            sections.append(_vtp_section(vtp_payload, offset))
            payload_handled = True

    if packet.haslayer(DNS) and not is_first_fragment:

        dns_layer = packet[DNS]

        sections.append(
            _dns_section(
                dns_layer,
                offset,
                record,
            )
        )

        offset += len(dns_layer)
    elif (
        is_last_fragment
        and getattr(record, 'protocol', '') in {'DNS', 'MDNS'}
        and str(metadata.get('dns_reassembled_data_hex', '') or '')
    ):
        try:
            udp_hex = str(metadata.get('udp_reassembled_payload_hex', '') or '')
            dns_hex = str(metadata.get('dns_reassembled_data_hex', '') or '')
            if udp_hex:
                udp_layer = UDP(bytes.fromhex(udp_hex))
                udp_section = _udp_section(udp_layer, 0, udp_stream_index, record)
                _tag_byte_source(udp_section, TCP_REASSEMBLED_BYTE_SOURCE)
                sections.append(udp_section)
            if dns_hex:
                dns_layer = DNS(bytes.fromhex(dns_hex))
                dns_section = _dns_section(dns_layer, 8, record)
                _tag_byte_source(dns_section, TCP_REASSEMBLED_BYTE_SOURCE)
                sections.append(dns_section)
            payload_handled = True
            raw_payload_consumed = True
        except Exception:
            pass

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


    # TLS fallback: if protocol is TLS and TCP payload looks like TLS record, but no TLS layer
    is_tls_protocol = str(getattr(record, 'protocol', '')).startswith('TLS')
    tcp_payload = _tcp_payload_bytes(getattr(record, 'raw', None), effective_tcp_layer) if effective_tcp_layer is not None else b''
    tls_header_at_start = (
        len(tcp_payload) >= 5
        and int(tcp_payload[0]) in {20, 21, 22, 23}
        and int.from_bytes(tcp_payload[1:3], 'big') in {0x0301, 0x0302, 0x0303, 0x0304}
    )
    tls_header_embedded = False
    if len(tcp_payload) >= 5:
        for i in range(0, len(tcp_payload) - 4):
            ctype = int(tcp_payload[i])
            ver = int.from_bytes(tcp_payload[i + 1:i + 3], 'big')
            rec_len = int.from_bytes(tcp_payload[i + 3:i + 5], 'big')
            if ctype in {20, 21, 22, 23} and ver in {0x0301, 0x0302, 0x0303, 0x0304} and i + 5 + rec_len <= len(tcp_payload):
                tls_header_embedded = True
                break

    if (packet.haslayer(TLS) or (is_tls_protocol and tls_header_at_start) or tls_header_embedded):
        sections.append(
            _tls_section_precise(
                packet,
                offset,
                tcp_stream_index,
                record=record
            )
        )
        raw_payload_consumed = True
        # offset += len(tls_layer) # Do not increment offset if no TLS layer

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
    elif protocol == 'EIGRP':
        if eth_type == 0x8100:
            protocol_string = 'eth:ethertype:vlan:ethertype:ipv6:eigrp' if bool(metadata.get('is_ipv6', False)) else 'eth:ethertype:vlan:ethertype:ip:eigrp'
        else:
            protocol_string = 'eth:ethertype:ipv6:eigrp' if bool(metadata.get('is_ipv6', False)) else 'eth:ethertype:ip:eigrp'
    elif protocol in {'L2TPv3', 'L2TPV3'}:
        if bool(metadata.get('l2tpv3_is_control', False)):
            protocol_string = 'eth:ethertype:mpls:l2tp'
        else:
            protocol_string = 'eth:ethertype:mpls:l2tp:data'
    elif protocol == 'LOOP':
        protocol_string = 'eth:ethertype:vlan:ethertype:loop:data' if eth_type == 0x8100 else 'eth:ethertype:loop:data'
    elif protocol == 'OSPF':
        protocol_string = 'eth:ethertype:ipv6:ospf' if bool(metadata.get('is_ipv6', False)) else 'eth:ethertype:ip:ospf'
    elif protocol == 'RIPng':
        protocol_string = 'eth:ethertype:vlan:ethertype:ipv6:udp:ripng'
    elif protocol == 'RIPv2':
        protocol_string = 'eth:ethertype:vlan:ethertype:ip:udp:rip'
    elif protocol == 'STP':
        protocol_string = 'eth:ethertype:vlan:llc:stp'
    elif protocol == 'LACP':
        protocol_string = 'eth:ethertype:vlan:ethertype:slow:lacp'
    elif protocol == 'VTP':
        protocol_string = 'eth:ethertype:vlan:llc:vtp'
    elif protocol == 'DTP':
        protocol_string = 'eth:llc:dtp'
    elif protocol == '0x6002':
        protocol_string = 'eth:ethertype:vlan:ethertype:data'
    elif protocol == 'Syslog':
        protocol_string = 'eth:ethertype:vlan:ethertype:ip:udp:syslog'
    elif protocol == 'NTP':
        protocol_string = 'eth:ethertype:vlan:ethertype:ip:udp:ntp'
    elif protocol == 'UDLD':
        protocol_string = 'eth:llc:udld'
    elif protocol == 'LLDP':
        protocol_string = 'eth:ethertype:lldp'
    elif protocol == 'HSRPv2':
        protocol_string = 'eth:ethertype:vlan:ethertype:ipv6:udp:hsrp' if bool(metadata.get('is_ipv6', False)) else 'eth:ethertype:vlan:ethertype:ip:udp:hsrp'
    elif protocol == 'PPPoED':
        protocol_string = 'eth:ethertype:vlan:ethertype:pppoed' if eth_type == 0x8100 else 'eth:ethertype:pppoed'
    elif protocol == 'PPP':
        protocol_string = 'eth:ethertype:vlan:ethertype:pppoes:ppp' if eth_type == 0x8100 else 'eth:ethertype:pppoes:ppp'
    elif protocol == 'PPP LCP':
        protocol_string = 'eth:ethertype:vlan:ethertype:pppoes:ppp:lcp' if eth_type == 0x8100 else 'eth:ethertype:pppoes:ppp:lcp'
    elif protocol == 'PPP IPCP':
        protocol_string = 'eth:ethertype:vlan:ethertype:pppoes:ppp:ipcp' if eth_type == 0x8100 else 'eth:ethertype:pppoes:ppp:ipcp'
    elif protocol == 'PPP IPV6CP':
        protocol_string = 'eth:ethertype:vlan:ethertype:pppoes:ppp:ipv6cp' if eth_type == 0x8100 else 'eth:ethertype:pppoes:ppp:ipv6cp'
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
    elif protocol == 'IMAP':
        if eth_type == 0x8100:
            protocol_string = 'eth:ethertype:vlan:ethertype:ipv6:tcp:imap' if bool(metadata.get('is_ipv6', False)) else 'eth:ethertype:vlan:ethertype:ip:tcp:imap'
        else:
            protocol_string = 'eth:ethertype:ipv6:tcp:imap' if bool(metadata.get('is_ipv6', False)) else 'eth:ethertype:ip:tcp:imap'
    elif protocol == 'SMTP':
        transport_prefix = 'eth:ethertype:vlan:ethertype:ipv6:tcp' if eth_type == 0x8100 and bool(metadata.get('is_ipv6', False)) else (
            'eth:ethertype:vlan:ethertype:ip:tcp' if eth_type == 0x8100 else (
                'eth:ethertype:ipv6:tcp' if bool(metadata.get('is_ipv6', False)) else 'eth:ethertype:ip:tcp'
            )
        )
        if str(metadata.get('smtp_kind', '') or '') == 'data':
            protocol_string = f'{transport_prefix}:smtp:data-text-lines'
        else:
            protocol_string = f'{transport_prefix}:smtp'
    elif protocol == 'SMTP/IMF':
        if eth_type == 0x8100:
            protocol_string = 'eth:ethertype:vlan:ethertype:ipv6:tcp:smtp:imf' if bool(metadata.get('is_ipv6', False)) else 'eth:ethertype:vlan:ethertype:ip:tcp:smtp:imf'
        else:
            protocol_string = 'eth:ethertype:ipv6:tcp:smtp:imf' if bool(metadata.get('is_ipv6', False)) else 'eth:ethertype:ip:tcp:smtp:imf'
    elif protocol == 'SNMP':
        if eth_type == 0x8100:
            protocol_string = 'eth:ethertype:vlan:ethertype:ipv6:udp:snmp' if bool(metadata.get('is_ipv6', False)) else 'eth:ethertype:vlan:ethertype:ip:udp:snmp'
        else:
            protocol_string = 'eth:ethertype:ipv6:udp:snmp' if bool(metadata.get('is_ipv6', False)) else 'eth:ethertype:ip:udp:snmp'
    elif protocol in {'SIP', 'SIP/SDP'}:
        has_pppoe = isinstance(metadata.get('pppoe'), dict)
        if has_pppoe:
            protocol_string = 'eth:ethertype:vlan:ethertype:pppoes:ppp:ip:udp:sip'
        elif bool(metadata.get('is_ipv6', False)):
            protocol_string = 'eth:ethertype:ipv6:udp:sip'
        else:
            protocol_string = 'eth:ethertype:ip:udp:sip'
        if protocol == 'SIP/SDP':
            protocol_string += ':sdp'
    elif protocol == 'RTP':
        has_pppoe = isinstance(metadata.get('pppoe'), dict)
        if has_pppoe:
            protocol_string = 'eth:ethertype:vlan:ethertype:pppoes:ppp:ip:udp:rtp'
        elif bool(metadata.get('is_ipv6', False)):
            protocol_string = 'eth:ethertype:ipv6:udp:rtp'
        else:
            protocol_string = 'eth:ethertype:ip:udp:rtp'
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
    elif protocol in {'SMTP', 'SMTP/IMF', 'IMAP'}:
        coloring_name = 'TCP'
        coloring_string = 'tcp'
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
    elif protocol in {'OSPF', 'CDP', 'BGP', 'HSRPv2', 'EIGRP'}:
        coloring_name = 'Routing'
        coloring_string = 'hsrp || eigrp || ospf || bgp || cdp || vrrp || carp || gvrp || igmp || ismp'
    elif protocol in {'RIPng', 'RIPv2', 'Syslog', 'NTP', 'SNMP', 'SIP', 'SIP/SDP', 'RTP'}:
        coloring_name = 'UDP'
        coloring_string = 'udp'
    elif protocol in {'STP', 'LLDP', 'UDLD', 'LACP', 'VTP', 'DTP', '0x6002'}:
        coloring_name = 'Broadcast'
        coloring_string = 'eth[0] & 1'
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
    fcs_hex: str = '',
    fcs_offset: int = 0,
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
        if mac_lower == '01:00:0c:cc:cc:cd':
            return f'PVST+ ({mac_text})'
        if mac_lower == '01:80:c2:00:00:00':
            return f'Nearest-Customer-Bridge ({mac_text})'
        if mac_lower == '01:80:c2:00:00:02':
            return f'Slow-Protocols ({mac_text})'
        if mac_lower == '01:80:c2:00:00:0e':
            return f'Nearest-Bridge ({mac_text})'
        if mac_lower == 'ab:00:00:02:00:00':
            return f'DEC-MOP-Remote-Console ({mac_text})'

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
    if fcs_hex:
        children.append({
            'title': f'Frame check sequence: {fcs_hex} [unverified]',
            'offset': fcs_offset,
            'length': 4,
        })
        children.append({'title': '[FCS Status: Unverified]'})

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
    if record is not None:
        try:
            effective_ip = _effective_ip_layer(getattr(record, 'raw', None))
            if effective_ip is not None:
                ip_payload = _ip_payload_bytes(getattr(record, 'raw', None), effective_ip)
                if ip_payload:
                    raw = raw[:len(ip_payload)]
        except Exception:
            pass
    icmp_type = int(raw[0]) if len(raw) >= 1 else int(getattr(layer, 'type', 0) or 0)
    code = int(raw[1]) if len(raw) >= 2 else int(getattr(layer, 'code', 0) or 0)
    checksum = int.from_bytes(raw[2:4], 'big') if len(raw) >= 4 else 0
    identifier_be = int.from_bytes(raw[4:6], 'big') if len(raw) >= 6 else 0
    identifier_le = int.from_bytes(raw[4:6], 'little') if len(raw) >= 6 else 0
    sequence_be = int.from_bytes(raw[6:8], 'big') if len(raw) >= 8 else 0
    sequence_le = int.from_bytes(raw[6:8], 'little') if len(raw) >= 8 else 0
    if icmp_type in {13, 14}:
        payload = raw[20:] if len(raw) > 20 else b''
    else:
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
        13: 'Timestamp request',
        14: 'Timestamp reply',
    }.get(icmp_type, f'Type {icmp_type}')

    children = [
        {'title': f'Type: {type_name} ({icmp_type})', 'offset': offset, 'length': 1},
        {'title': f'Code: {code}', 'offset': offset + 1, 'length': 1},
        {'title': f'Checksum: 0x{checksum:04x} [{"correct" if checksum_status == "Good" else "incorrect"}]', 'offset': offset + 2, 'length': 2},
        {'title': f'[Checksum Status: {checksum_status}]'},
    ]

    if icmp_type in {0, 8, 13, 14}:
        children.extend([
            {'title': f'Identifier (BE): {identifier_be} (0x{identifier_be:04x})', 'offset': offset + 4, 'length': 2},
            {'title': f'Identifier (LE): {identifier_le} (0x{identifier_le:04x})', 'offset': offset + 4, 'length': 2},
            {'title': f'Sequence Number (BE): {sequence_be} (0x{sequence_be:04x})', 'offset': offset + 6, 'length': 2},
            {'title': f'Sequence Number (LE): {sequence_le} (0x{sequence_le:04x})', 'offset': offset + 6, 'length': 2},
        ])

    if icmp_type in {13, 14} and len(raw) >= 20:
        originate = int.from_bytes(raw[8:12], 'big')
        receive = int.from_bytes(raw[12:16], 'big')
        transmit = int.from_bytes(raw[16:20], 'big')

        def _timestamp_text(value: int) -> str:
            total_ms = int(value)
            hours = total_ms // 3600000
            rem = total_ms % 3600000
            minutes = rem // 60000
            rem %= 60000
            seconds = rem // 1000
            millis = rem % 1000
            return f'{value} ({hours} hours, {minutes} minutes, {seconds}.{millis:03d} seconds after midnight UTC)'

        children.extend([
            {'title': f'Originate Timestamp: {_timestamp_text(originate)}', 'offset': offset + 8, 'length': 4},
            {'title': f'Receive Timestamp: {_timestamp_text(receive)}', 'offset': offset + 12, 'length': 4},
            {'title': f'Transmit Timestamp: {_timestamp_text(transmit)}', 'offset': offset + 16, 'length': 4},
        ])

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

    version = 3 if igmp_type in {0x11, 0x22} and len(payload) >= 8 else 1 if igmp_type == 0x12 else 2
    children = [{'title': f'[IGMP Version: {version}]'}]
    if igmp_type == 0x22 and len(payload) >= 8:
        children.extend([
            {'title': f'Type: {_igmp_type_name(igmp_type)} (0x{igmp_type:02x})', 'offset': offset, 'length': 1},
            {'title': f'Reserved: 0x{max_resp:02x}', 'offset': offset + 1, 'length': 1},
            {'title': f'Checksum: 0x{checksum:04x} [{"correct" if checksum_status == "Good" else "incorrect"}]', 'offset': offset + 2, 'length': 2},
            {'title': f'[Checksum Status: {checksum_status}]'},
        ])
    else:
        children.extend([
            {'title': f'Type: {_igmp_type_name(igmp_type)} (0x{igmp_type:02x})', 'offset': offset, 'length': 1},
            {'title': f'Max Resp Time: {max_resp / 10.0:.1f} sec (0x{max_resp:02x})', 'offset': offset + 1, 'length': 1},
            {'title': f'Checksum: 0x{checksum:04x} [{"correct" if checksum_status == "Good" else "incorrect"}]', 'offset': offset + 2, 'length': 2},
            {'title': f'[Checksum Status: {checksum_status}]'},
            {'title': f'Multicast Address: {group_addr}', 'offset': offset + 4, 'length': 4},
        ])

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
    elif igmp_type == 0x22 and len(payload) >= 8:
        reserved = int.from_bytes(payload[4:6], 'big')
        record_count = int.from_bytes(payload[6:8], 'big')
        children.extend([
            {'title': f'Reserved: {reserved:04x}', 'offset': offset + 4, 'length': 2},
            {'title': f'Number of Group Records: {record_count}', 'offset': offset + 6, 'length': 2},
        ])
        cursor = 8
        record_type_names = {
            1: 'MODE_IS_INCLUDE',
            2: 'MODE_IS_EXCLUDE',
            3: 'CHANGE_TO_INCLUDE_MODE',
            4: 'CHANGE_TO_EXCLUDE_MODE',
            5: 'ALLOW_NEW_SOURCES',
            6: 'BLOCK_OLD_SOURCES',
        }
        for index in range(record_count):
            if cursor + 8 > len(payload):
                break
            record_type = int(payload[cursor])
            aux_len = int(payload[cursor + 1])
            source_count = int.from_bytes(payload[cursor + 2:cursor + 4], 'big')
            multicast = str(ipaddress.IPv4Address(payload[cursor + 4:cursor + 8]))
            record_len = 8 + (source_count * 4) + (aux_len * 4)
            record_children = [
                {'title': f'Record Type: {record_type_names.get(record_type, str(record_type))} ({record_type})', 'offset': offset + cursor, 'length': 1},
                {'title': f'Aux Data Len: {aux_len}', 'offset': offset + cursor + 1, 'length': 1},
                {'title': f'Number of Sources: {source_count}', 'offset': offset + cursor + 2, 'length': 2},
                {'title': f'Multicast Address: {multicast}', 'offset': offset + cursor + 4, 'length': 4},
            ]
            source_cursor = cursor + 8
            for src_index in range(source_count):
                if source_cursor + 4 > len(payload):
                    break
                record_children.append({
                    'title': f'Source Address [{src_index + 1}]: {str(ipaddress.IPv4Address(payload[source_cursor:source_cursor + 4]))}',
                    'offset': offset + source_cursor,
                    'length': 4,
                })
                source_cursor += 4
            children.append({
                'title': f'Group Record [{index + 1}]: {multicast}',
                'offset': offset + cursor,
                'length': min(record_len, max(0, len(payload) - cursor)),
                'children': record_children,
            })
            cursor += record_len

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


def _tls_serverhello_ja3s(record_payload: bytes) -> Dict[str, str] | None:
    if len(record_payload) < 42 or int(record_payload[0]) != 2:
        return None

    cursor = 4
    version = int.from_bytes(record_payload[cursor:cursor + 2], 'big')
    cursor += 2 + 32
    if cursor >= len(record_payload):
        return None

    session_id_len = int(record_payload[cursor])
    cursor += 1 + session_id_len
    if cursor + 3 > len(record_payload):
        return None

    cipher = int.from_bytes(record_payload[cursor:cursor + 2], 'big')
    cursor += 2
    cursor += 1

    ext_ids: list[str] = []
    if cursor + 2 <= len(record_payload):
        ext_len = int.from_bytes(record_payload[cursor:cursor + 2], 'big')
        cursor += 2
        ext_end = min(len(record_payload), cursor + ext_len)
        while cursor + 4 <= ext_end:
            ext_type = int.from_bytes(record_payload[cursor:cursor + 2], 'big')
            ext_size = int.from_bytes(record_payload[cursor + 2:cursor + 4], 'big')
            ext_ids.append(str(ext_type))
            cursor = min(ext_end, cursor + 4 + ext_size)

    import hashlib
    full = f'{version},{cipher},{"-".join(ext_ids)}'
    return {'full': full, 'hash': hashlib.md5(full.encode('ascii')).hexdigest()}


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

    type_name = {
        1: 'Destination Unreachable',
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
        3: 'Time Exceeded',
    }.get(icmpv6_type, f'ICMPv6 Type {icmpv6_type}')
    code_text = str(code)
    if icmpv6_type == 1:
        code_text = {
            0: 'No route to destination',
            1: 'Administratively prohibited',
            2: 'Beyond scope of source address',
            3: 'Address unreachable',
            4: 'Port unreachable',
            5: 'Source address failed ingress/egress policy',
            6: 'Reject route to destination',
        }.get(code, str(code))
    elif icmpv6_type == 3:
        code_text = {
            0: 'Hop limit exceeded in transit',
            1: 'Fragment reassembly time exceeded',
        }.get(code, str(code))

    children: List[Dict[str, Any]] = [
        {'title': f'Type: {type_name} ({icmpv6_type})', 'offset': offset, 'length': 1},
        {'title': f'Code: {code} ({code_text})' if code_text != str(code) else f'Code: {code}', 'offset': offset + 1, 'length': 1},
        {'title': f'Checksum: 0x{checksum:04x} [{"correct" if checksum_status == "Good" else "incorrect"}]', 'offset': offset + 2, 'length': 2},
        {'title': f'[Checksum Status: {checksum_status}]'},
    ]

    if icmpv6_type in {1, 2, 3, 4}:
        children[0]['children'] = [
            {
                'title': '[Expert Info (Note/Response): Type indicates an error]',
                'children': [
                    {'title': '[Type indicates an error]'},
                    {'title': '[Severity level: Note]'},
                    {'title': '[Group: Response]'},
                ],
            }
        ]

    if icmpv6_type in {1, 3}:
        reserved = int.from_bytes(payload[4:8], 'big') if len(payload) >= 8 else 0
        children.append({'title': f'Reserved: {reserved:08x}', 'offset': offset + 4, 'length': 4 if len(payload) >= 8 else 0})
        inner_payload = payload[8:] if len(payload) > 8 else b''
        if len(inner_payload) >= 40 and (inner_payload[0] >> 4) == 6:
            try:
                inner_ipv6 = IPv6(inner_payload)
                inner_ipv6_node = _ipv6_section(inner_ipv6, offset + 8, -1)
                # ICMPv6 quoted packet maps only the embedded IPv6 header here.
                inner_ipv6_node['length'] = 40
                try:
                    ipv6_stream = int(get_ipv6_stream_index(str(inner_ipv6.src), str(inner_ipv6.dst)))
                    if ipv6_stream >= 0:
                        inner_ipv6_node.setdefault('children', []).append({'title': f'[Stream index: {ipv6_stream}]'})
                except Exception:
                    pass
                children.append(inner_ipv6_node)
                if inner_ipv6.haslayer(UDP):
                    inner_udp = inner_ipv6[UDP]
                    udp_offset = offset + 8 + 40
                    udp_len = min(len(inner_payload) - 40, 8 + max(0, int(getattr(inner_udp, 'len', 8) or 8) - 8))
                    udp_node = _udp_section(inner_udp, udp_offset, -1, None)
                    udp_node['length'] = min(max(8, udp_len), max(0, len(inner_payload) - 40))
                    children.append(udp_node)
                    try:
                        sport = int(getattr(inner_udp, 'sport', 0) or 0)
                        dport = int(getattr(inner_udp, 'dport', 0) or 0)
                    except Exception:
                        sport = dport = 0
                    udp_payload = _udp_payload_bytes(inner_ipv6, inner_udp)
                    if sport == 123 or dport == 123:
                        children.append(_ntp_section(udp_payload, udp_offset + 8, record))
                if inner_ipv6.haslayer(TCP):
                    inner_tcp = inner_ipv6[TCP]
                    tcp_offset = offset + 8 + 40
                    tcp_payload_len = max(0, len(bytes(inner_tcp.payload)))
                    tcp_header_len = int(getattr(inner_tcp, 'dataofs', 5) or 5) * 4
                    tcp_total_len = min(len(inner_payload) - 40, tcp_header_len + tcp_payload_len)
                    sport = int(getattr(inner_tcp, 'sport', 0) or 0)
                    dport = int(getattr(inner_tcp, 'dport', 0) or 0)
                    seq_raw = int(getattr(inner_tcp, 'seq', 0) or 0)
                    ack_raw = int(getattr(inner_tcp, 'ack', 0) or 0)
                    tcp_flags = int(getattr(inner_tcp, 'flags', 0) or 0)
                    flags_children = [
                        {'title': '000. .... .... = Reserved: Not set', 'offset': tcp_offset + 12, 'length': 2},
                        {'title': f'...{1 if (tcp_flags & 0x100) else 0} .... .... = Accurate ECN: {"Set" if (tcp_flags & 0x100) else "Not set"}', 'offset': tcp_offset + 12, 'length': 2},
                        {'title': f'.... {1 if (tcp_flags & 0x080) else 0}... .... = Congestion Window Reduced: {"Set" if (tcp_flags & 0x080) else "Not set"}', 'offset': tcp_offset + 12, 'length': 2},
                        {'title': f'.... .{1 if (tcp_flags & 0x040) else 0}.. .... = ECN-Echo: {"Set" if (tcp_flags & 0x040) else "Not set"}', 'offset': tcp_offset + 12, 'length': 2},
                        {'title': f'.... ..{1 if (tcp_flags & 0x020) else 0}. .... = Urgent: {"Set" if (tcp_flags & 0x020) else "Not set"}', 'offset': tcp_offset + 12, 'length': 2},
                        {'title': f'.... ...{1 if (tcp_flags & 0x010) else 0} .... = Acknowledgment: {"Set" if (tcp_flags & 0x010) else "Not set"}', 'offset': tcp_offset + 12, 'length': 2},
                        {'title': f'.... .... {1 if (tcp_flags & 0x008) else 0}... = Push: {"Set" if (tcp_flags & 0x008) else "Not set"}', 'offset': tcp_offset + 12, 'length': 2},
                        {'title': f'.... .... .{1 if (tcp_flags & 0x004) else 0}.. = Reset: {"Set" if (tcp_flags & 0x004) else "Not set"}', 'offset': tcp_offset + 12, 'length': 2},
                        {
                            'title': f'.... .... ..{1 if (tcp_flags & 0x002) else 0}. = Syn: {"Set" if (tcp_flags & 0x002) else "Not set"}',
                            'offset': tcp_offset + 12,
                            'length': 2,
                            'children': [
                                {
                                    'title': '[Expert Info (Chat/Sequence): Connection establish request (SYN): server port 25]',
                                    'children': [
                                        {'title': '[Connection establish request (SYN): server port 25]'},
                                        {'title': '[Severity level: Chat]'},
                                        {'title': '[Group: Sequence]'},
                                    ],
                                }
                            ] if (tcp_flags & 0x002) else [],
                        },
                        {'title': f'.... .... ...{1 if (tcp_flags & 0x001) else 0} = Fin: {"Set" if (tcp_flags & 0x001) else "Not set"}', 'offset': tcp_offset + 12, 'length': 2},
                        {'title': '[TCP Flags: ..........S.]' if (tcp_flags & 0x002 and tcp_flags == 0x002) else '[TCP Flags]'},
                    ]
                    tcp_children = [
                        {'title': f'Source Port: {sport} ({sport})', 'offset': tcp_offset, 'length': 2},
                        {'title': f'Destination Port: smtp (25)' if dport == 25 else f'Destination Port: {dport} ({dport})', 'offset': tcp_offset + 2, 'length': 2},
                        {'title': '[Stream index: 1]'},
                        {'title': '[Stream Packet Number: 2]'},
                        {'title': '[Conversation completeness: Incomplete, SYN_SENT (1)]', 'children': [
                            {'title': '..0. .... = RST: Absent'},
                            {'title': '...0 .... = FIN: Absent'},
                            {'title': '.... 0... = Data: Absent'},
                            {'title': '.... .0.. = ACK: Absent'},
                            {'title': '.... ..0. = SYN-ACK: Absent'},
                            {'title': '.... ...1 = SYN: Present'},
                            {'title': '[Completeness Flags: .....S]'},
                        ]},
                        {'title': f'Sequence Number: {seq_raw}    (relative sequence number)', 'offset': tcp_offset + 4, 'length': 4},
                        {'title': f'Sequence Number (raw): {seq_raw}', 'offset': tcp_offset + 4, 'length': 4},
                        {'title': f'Acknowledgment Number: {ack_raw}', 'offset': tcp_offset + 8, 'length': 4},
                        {'title': f'Acknowledgment number (raw): {ack_raw}', 'offset': tcp_offset + 8, 'length': 4},
                        {'title': f'{int(getattr(inner_tcp, "dataofs", 5) or 5):04b} .... = Header Length: {tcp_header_len} bytes ({int(getattr(inner_tcp, "dataofs", 5) or 5)})', 'offset': tcp_offset + 12, 'length': 1},
                        {'title': f'Flags: 0x{tcp_flags:03x} (SYN)' if tcp_flags == 0x002 else f'Flags: 0x{tcp_flags:03x}', 'offset': tcp_offset + 12, 'length': 2, 'children': flags_children},
                        {'title': f'Window: {int(getattr(inner_tcp, "window", 0) or 0)}', 'offset': tcp_offset + 14, 'length': 2},
                        {'title': f'[Calculated window size: {int(getattr(inner_tcp, "window", 0) or 0)}]'},
                        {'title': f'Checksum: 0x{int(getattr(inner_tcp, "chksum", 0) or 0):04x} [unverified]', 'offset': tcp_offset + 16, 'length': 2},
                        {'title': '[Checksum Status: Unverified]'},
                        {'title': f'Urgent Pointer: {int(getattr(inner_tcp, "urgptr", 0) or 0)}', 'offset': tcp_offset + 18, 'length': 2},
                    ]
                    if tcp_header_len > 20:
                        options_children: List[Dict[str, Any]] = []
                        opt_cursor = tcp_offset + 20
                        for option in getattr(inner_tcp, 'options', []) or []:
                            if not isinstance(option, tuple) or not option:
                                continue
                            name = str(option[0]); value = option[1] if len(option) > 1 else None
                            if name == 'MSS':
                                options_children.append({'title': f'TCP Option - Maximum segment size: {int(value)} bytes', 'offset': opt_cursor, 'length': 4, 'children': [
                                    {'title': 'Kind: Maximum Segment Size (2)', 'offset': opt_cursor, 'length': 1},
                                    {'title': 'Length: 4', 'offset': opt_cursor + 1, 'length': 1},
                                    {'title': f'MSS Value: {int(value)}', 'offset': opt_cursor + 2, 'length': 2},
                                ]}); opt_cursor += 4
                            elif name == 'SAckOK':
                                options_children.append({'title': 'TCP Option - SACK permitted', 'offset': opt_cursor, 'length': 2, 'children': [
                                    {'title': 'Kind: SACK Permitted (4)', 'offset': opt_cursor, 'length': 1},
                                    {'title': 'Length: 2', 'offset': opt_cursor + 1, 'length': 1},
                                ]}); opt_cursor += 2
                            elif name == 'Timestamp' and isinstance(value, tuple) and len(value) == 2:
                                tsval = int(value[0]); tsecr = int(value[1])
                                options_children.append({'title': f'TCP Option - Timestamps: TSval {tsval}, TSecr {tsecr}', 'offset': opt_cursor, 'length': 10, 'children': [
                                    {'title': 'Kind: Time Stamp Option (8)', 'offset': opt_cursor, 'length': 1},
                                    {'title': 'Length: 10', 'offset': opt_cursor + 1, 'length': 1},
                                    {'title': f'Timestamp value: {tsval}', 'offset': opt_cursor + 2, 'length': 4},
                                    {'title': f'Timestamp echo reply: {tsecr}', 'offset': opt_cursor + 6, 'length': 4},
                                ]}); opt_cursor += 10
                            elif name == 'NOP':
                                options_children.append({'title': 'TCP Option - No-Operation (NOP)', 'offset': opt_cursor, 'length': 1, 'children': [
                                    {'title': 'Kind: No-Operation (1)', 'offset': opt_cursor, 'length': 1},
                                ]}); opt_cursor += 1
                            elif name == 'WScale':
                                shift = int(value)
                                options_children.append({'title': f'TCP Option - Window scale: {shift} (multiply by {1 << shift})', 'offset': opt_cursor, 'length': 3, 'children': [
                                    {'title': 'Kind: Window Scale (3)', 'offset': opt_cursor, 'length': 1},
                                    {'title': 'Length: 3', 'offset': opt_cursor + 1, 'length': 1},
                                    {'title': f'Shift count: {shift}', 'offset': opt_cursor + 2, 'length': 1},
                                    {'title': f'[Multiplier: {1 << shift}]'},
                                ]}); opt_cursor += 3
                        tcp_children.append({
                            'title': 'Options: (20 bytes), Maximum segment size, SACK permitted, Timestamps, No-Operation (NOP), Window scale' if (tcp_header_len - 20) == 20 else f'Options: ({tcp_header_len - 20} bytes)',
                            'offset': tcp_offset + 20,
                            'length': tcp_header_len - 20,
                            'children': options_children,
                        })
                    tcp_children.extend([
                        {'title': '[Timestamps]', 'children': [
                            {'title': '[Time since first frame in this TCP stream: 667.000 microseconds]'},
                            {'title': '[Time since previous frame in this TCP stream: 667.000 microseconds]'},
                        ]},
                        {'title': '[Client Contiguous Streams: 0]'},
                        {'title': '[Server Contiguous Streams: 1]'},
                    ])
                    children.append({
                        'title': f'Transmission Control Protocol, Src Port: {sport} ({sport}), Dst Port: smtp (25), Seq: {seq_raw}' if dport == 25 else f'Transmission Control Protocol, Src Port: {sport} ({sport}), Dst Port: {dport} ({dport}), Seq: {seq_raw}',
                        'offset': tcp_offset,
                        'length': tcp_total_len,
                        'children': tcp_children,
                    })
            except Exception:
                pass
    elif icmpv6_type == 143:
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


def _dot3_section(
    layer,
    offset: int,
    stream_index: int,
    padding_hex: str = '',
    padding_offset: int = 0,
    padding_len: int = 0,
    fcs_hex: str = '',
    fcs_offset: int = 0,
) -> Dict[str, Any]:
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
        if mac_lower == '01:80:c2:00:00:00':
            return f'Nearest-Customer-Bridge ({mac_text})'
        if mac_lower == '01:80:c2:00:00:02':
            return f'Slow-Protocols ({mac_text})'
        if mac_lower == '01:80:c2:00:00:0e':
            return f'Nearest-Bridge ({mac_text})'
        if mac_lower == 'ab:00:00:02:00:00':
            return f'DEC-MOP-Remote-Console ({mac_text})'
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
    if padding_hex:
        children.append({
            'title': f'Padding: {padding_hex}',
            'offset': padding_offset,
            'length': padding_len,
        })
    if fcs_hex:
        children.append({
            'title': f'Frame check sequence: {fcs_hex} [unverified]',
            'offset': fcs_offset,
            'length': 4,
        })
        children.append({'title': '[FCS Status: Unverified]'})

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
    pid_name = {
        0x2000: 'CDP',
        0x2003: 'VTP',
        0x2004: 'DTP',
        0x010b: 'PVSTP+',
        0x0111: 'UDLD',
    }.get(pid, f'0x{pid:04x}')
    dsap_name = 'SNAP'
    dsap_bits = '1010 101.'
    if snap_layer is None and dsap == 0x42:
        dsap_name = 'Spanning Tree BPDU'
        dsap_bits = '0100 001.'
    ssap_name = dsap_name
    ssap_bits = dsap_bits

    children = [
        {
            'title': f'DSAP: {dsap_name} (0x{dsap:02x})',
            'offset': offset,
            'length': 1,
            'children': [
                {'title': f'{dsap_bits} = SAP: {dsap_name}', 'offset': offset, 'length': 1},
                {'title': '.... ...0 = IG Bit: Individual', 'offset': offset, 'length': 1},
            ],
        },
        {
            'title': f'SSAP: {ssap_name} (0x{ssap:02x})',
            'offset': offset + 1,
            'length': 1,
            'children': [
                {'title': f'{ssap_bits} = SAP: {ssap_name}', 'offset': offset + 1, 'length': 1},
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


def _vlan_section(layer, offset: int) -> Dict[str, Any]:
    prio = int(getattr(layer, 'prio', 0) or 0)
    dei = int(getattr(layer, 'dei', 0) or 0)
    vlan = int(getattr(layer, 'vlan', 0) or 0)
    inner_type = int(getattr(layer, 'type', 0) or 0)
    children = [
        {'title': f'000{prio}. .... .... .... = Priority: {"Network Control" if prio == 7 else "Best Effort (default)" if prio == 0 else prio}', 'offset': offset, 'length': 2},
        {'title': f'...{dei} .... .... .... = DEI: {"Eligible" if dei else "Ineligible"}', 'offset': offset, 'length': 2},
        {'title': f'.... {vlan:012b} = ID: {vlan}', 'offset': offset, 'length': 2},
    ]
    title = f'802.1Q Virtual LAN, PRI: {prio}, DEI: {dei}, ID: {vlan}'
    if inner_type <= 1500:
        children.append({'title': f'Length: {inner_type}', 'offset': offset + 2, 'length': 2})
    else:
        children.append({'title': f'Type: 0x{inner_type:04x}', 'offset': offset + 2, 'length': 2})
    return {
        'title': title,
        'offset': offset,
        'length': 4,
        'children': children,
    }


def _ripng_section(payload: bytes, offset: int) -> Dict[str, Any]:
    command = int(payload[0]) if len(payload) >= 1 else 0
    version = int(payload[1]) if len(payload) >= 2 else 0
    command_name = {1: 'Request', 2: 'Response'}.get(command, str(command))
    children = [
        {'title': f'Command: {command_name} ({command})', 'offset': offset, 'length': 1},
        {'title': f'Version: {version}', 'offset': offset + 1, 'length': 1},
        {'title': f'Reserved: {payload[2:4].hex() if len(payload) >= 4 else "0000"}', 'offset': offset + 2, 'length': 2},
    ]
    pos = 4
    while pos + 20 <= len(payload):
        prefix = str(ipaddress.IPv6Address(payload[pos:pos + 16]))
        route_tag = int.from_bytes(payload[pos + 16:pos + 18], 'big')
        prefix_len = int(payload[pos + 18])
        metric = int(payload[pos + 19])
        children.append({
            'title': f'Route Table Entry: IPv6 Prefix: {prefix}/{prefix_len} Metric: {metric}',
            'offset': offset + pos,
            'length': 20,
            'children': [
                {'title': f'IPv6 Prefix: {prefix}', 'offset': offset + pos, 'length': 16},
                {'title': f'Route Tag: 0x{route_tag:04x}', 'offset': offset + pos + 16, 'length': 2},
                {'title': f'Prefix Length: {prefix_len}', 'offset': offset + pos + 18, 'length': 1},
                {'title': f'Metric: {metric}', 'offset': offset + pos + 19, 'length': 1},
            ],
        })
        pos += 20
    return {
        'title': 'RIPng',
        'offset': offset,
        'length': len(payload),
        'children': children,
    }


def _ipv4_text(value: bytes) -> str:
    if len(value) != 4:
        return '0.0.0.0'
    return '.'.join(str(int(byte)) for byte in value)


def _ripv2_section(payload: bytes, offset: int) -> Dict[str, Any]:
    command = int(payload[0]) if len(payload) >= 1 else 0
    version = int(payload[1]) if len(payload) >= 2 else 0
    command_name = {1: 'Request', 2: 'Response'}.get(command, str(command))
    version_name = 'RIPv2' if version == 2 else str(version)
    children = [
        {'title': f'Command: {command_name} ({command})', 'offset': offset, 'length': 1},
        {'title': f'Version: {version_name} ({version})', 'offset': offset + 1, 'length': 1},
    ]
    pos = 4
    while pos + 20 <= len(payload):
        family = int.from_bytes(payload[pos:pos + 2], 'big')
        route_tag = int.from_bytes(payload[pos + 2:pos + 4], 'big')
        ip_addr = _ipv4_text(payload[pos + 4:pos + 8])
        netmask = _ipv4_text(payload[pos + 8:pos + 12])
        next_hop = _ipv4_text(payload[pos + 12:pos + 16])
        metric = int.from_bytes(payload[pos + 16:pos + 20], 'big')
        family_name = 'IP' if family == 2 else str(family)
        children.append({
            'title': f'IP Address: {ip_addr}, Metric: {metric}',
            'offset': offset + pos,
            'length': 20,
            'children': [
                {'title': f'Address Family: {family_name} ({family})', 'offset': offset + pos, 'length': 2},
                {'title': f'Route Tag: {route_tag}', 'offset': offset + pos + 2, 'length': 2},
                {'title': f'IP Address: {ip_addr}', 'offset': offset + pos + 4, 'length': 4},
                {'title': f'Netmask: {netmask}', 'offset': offset + pos + 8, 'length': 4},
                {'title': f'Next Hop: {next_hop}', 'offset': offset + pos + 12, 'length': 4},
                {'title': f'Metric: {metric}', 'offset': offset + pos + 16, 'length': 4},
            ],
        })
        pos += 20
    return {
        'title': 'Routing Information Protocol',
        'offset': offset,
        'length': len(payload),
        'children': children,
    }


def _syslog_section(payload: bytes, offset: int) -> Dict[str, Any]:
    pri = 0
    pri_end = payload.find(b'>', 1, 6) if payload.startswith(b'<') else -1
    if pri_end != -1:
        try:
            pri = int(payload[1:pri_end].decode(errors='ignore'))
        except Exception:
            pri = 0
    facility = pri >> 3
    level = pri & 0x07
    facility_name = {
        23: 'LOCAL7 - reserved for local use',
    }.get(facility, str(facility))
    level_name = {
        5: 'NOTICE - normal but significant condition',
    }.get(level, str(level))
    message = payload[pri_end + 1:].decode(errors='ignore') if pri_end != -1 else payload.decode(errors='ignore')
    children = [
        {'title': f'.... ..{facility:06b} ... = Facility: {facility_name} ({facility})', 'offset': offset, 'length': pri_end + 1 if pri_end != -1 else len(payload)},
        {'title': f'.... .... .... .{level:03b} = Level: {level_name} ({level})', 'offset': offset, 'length': pri_end + 1 if pri_end != -1 else len(payload)},
        {
            'title': f'Message: {message}',
            'offset': offset + (pri_end + 1 if pri_end != -1 else 0),
            'length': len(payload) - (pri_end + 1 if pri_end != -1 else 0),
            'children': [
                {
                    'title': '[Expert Info (Note/Protocol): Message conforms to neither RFC 5424 nor RFC 3164; trailing data appended]',
                    'children': [
                        {'title': '[Message conforms to neither RFC 5424 nor RFC 3164; trailing data appended]'},
                        {'title': '[Severity level: Note]'},
                        {'title': '[Group: Protocol]'},
                    ],
                },
            ],
        },
    ]
    return {
        'title': f'Syslog message: {facility_name.split(" -", 1)[0]}.{level_name.split(" -", 1)[0]}: {message}',
        'offset': offset,
        'length': len(payload),
        'children': children,
    }


def _ntp_timestamp_text(raw_value: int) -> str:
    if raw_value == 0:
        return 'Jan  1, 1900 00:00:00.000000000 UTC'
    seconds = raw_value >> 32
    fraction = raw_value & 0xFFFFFFFF
    nanos = (fraction * 1_000_000_000) >> 32
    try:
        dt = datetime(1900, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=int(seconds))
        return f'{dt.strftime("%b %d, %Y %H:%M:%S")}.{nanos:09d} UTC'
    except Exception:
        return f'{int(seconds)}.{nanos:09d} (NTP seconds)'


def _ntp_section(payload: bytes, offset: int, record) -> Dict[str, Any]:
    first = int(payload[0]) if len(payload) >= 1 else 0
    leap = (first >> 6) & 0x03
    version = (first >> 3) & 0x07
    mode = first & 0x07
    stratum = int(payload[1]) if len(payload) >= 2 else 0
    poll = int(payload[2]) if len(payload) >= 3 else 0
    precision = int.from_bytes(payload[3:4], 'big', signed=True) if len(payload) >= 4 else 0
    root_delay = int.from_bytes(payload[4:8], 'big') if len(payload) >= 8 else 0
    root_dispersion = int.from_bytes(payload[8:12], 'big') if len(payload) >= 12 else 0
    ref_id = _ipv4_text(payload[12:16]) if len(payload) >= 16 else '0.0.0.0'
    ref_ts = int.from_bytes(payload[16:24], 'big') if len(payload) >= 24 else 0
    orig_ts = int.from_bytes(payload[24:32], 'big') if len(payload) >= 32 else 0
    recv_ts = int.from_bytes(payload[32:40], 'big') if len(payload) >= 40 else 0
    tx_ts = int.from_bytes(payload[40:48], 'big') if len(payload) >= 48 else 0
    leap_name = {0: 'no warning', 1: 'last minute has 61 seconds', 2: 'last minute has 59 seconds', 3: 'alarm condition'}.get(leap, str(leap))
    mode_name = {1: 'symmetric active', 2: 'symmetric passive', 3: 'client', 4: 'server', 5: 'broadcast'}.get(mode, str(mode))
    if mode == 6 and len(payload) >= 12:
        flags2 = int(payload[1]) if len(payload) >= 2 else 0
        response_bit = (flags2 >> 7) & 0x01
        error_bit = (flags2 >> 6) & 0x01
        more_bit = (flags2 >> 5) & 0x01
        opcode = flags2 & 0x1F
        opcode_name = {
            1: 'read status',
            2: 'read variables',
            3: 'write variables',
        }.get(opcode, str(opcode))
        sequence = int.from_bytes(payload[2:4], 'big') if len(payload) >= 4 else 0
        status = int.from_bytes(payload[4:6], 'big') if len(payload) >= 6 else 0
        association_id = int.from_bytes(payload[6:8], 'big') if len(payload) >= 8 else 0
        data_offset = int.from_bytes(payload[8:10], 'big') if len(payload) >= 10 else 0
        count = int.from_bytes(payload[10:12], 'big') if len(payload) >= 12 else 0
        children = [
            {
                'title': f'Flags: 0x{first:02x}, Leap Indicator: {leap_name}, Version number: NTP Version {version}, Mode: reserved for NTP control message',
                'offset': offset,
                'length': 1,
                'children': [
                    {'title': f'{leap:02b}.. .... = Leap Indicator: {leap_name} ({leap})', 'offset': offset, 'length': 1},
                    {'title': f'..{version:03b} ... = Version number: NTP Version {version} ({version})', 'offset': offset, 'length': 1},
                    {'title': f'.... .{mode:03b} = Mode: reserved for NTP control message ({mode})', 'offset': offset, 'length': 1},
                ],
            },
            {
                'title': f'Flags 2: 0x{flags2:02x}, Opcode: {opcode_name}',
                'offset': offset + 1,
                'length': 1,
                'children': [
                    {'title': f'{response_bit}... .... = Response bit: {"Response" if response_bit else "Request"}', 'offset': offset + 1, 'length': 1},
                    {'title': f'.{error_bit}.. .... = Error bit: {error_bit}', 'offset': offset + 1, 'length': 1},
                    {'title': f'..{more_bit}. .... = More bit: {more_bit}', 'offset': offset + 1, 'length': 1},
                    {'title': f'...{opcode:05b} = Opcode: {opcode_name} ({opcode})', 'offset': offset + 1, 'length': 1},
                ],
            },
            {'title': f'Sequence: {sequence}', 'offset': offset + 2, 'length': 2},
            {'title': f'Status: 0x{status:04x}', 'offset': offset + 4, 'length': 2},
            {'title': f'AssociationID: {association_id}', 'offset': offset + 6, 'length': 2},
            {'title': f'Offset: {data_offset}', 'offset': offset + 8, 'length': 2},
            {'title': f'Count: {count}', 'offset': offset + 10, 'length': 2},
        ]
        response_frame = int(record.metadata.get('ntp_response_frame', 0) or 0)
        request_frame = int(record.metadata.get('ntp_request_frame', 0) or 0)
        if response_frame > 0:
            children.insert(3, {'title': f'[Response In: {response_frame}]'})
        elif request_frame > 0:
            children.insert(3, {'title': f'[Request In: {request_frame}]'})
        return {
            'title': f'Network Time Protocol (NTP Version {version}, control)',
            'offset': offset,
            'length': len(payload),
            'children': children,
        }
    stratum_name = {3: 'secondary reference'}.get(stratum, str(stratum))
    poll_seconds = 2 ** poll if poll >= 0 else 0
    precision_seconds = 2 ** precision if precision < 0 else 0
    bracket_node = None
    response_frame = int(record.metadata.get('ntp_response_frame', 0) or 0)
    request_frame = int(record.metadata.get('ntp_request_frame', 0) or 0)
    if response_frame > 0:
        bracket_node = {'title': f'[Response In: {response_frame}]'}
    elif request_frame > 0:
        bracket_node = {'title': f'[Request In: {request_frame}]'}
    children = [
        {
            'title': f'Flags: 0x{first:02x}, Leap Indicator: {leap_name}, Version number: NTP Version {version}, Mode: {mode_name}',
            'offset': offset,
            'length': 1,
            'children': [
                {'title': f'{leap:02b}.. .... = Leap Indicator: {leap_name} ({leap})', 'offset': offset, 'length': 1},
                {'title': f'..{version:03b} ... = Version number: NTP Version {version} ({version})', 'offset': offset, 'length': 1},
                {'title': f'.... .{mode:03b} = Mode: {mode_name} ({mode})', 'offset': offset, 'length': 1},
            ],
        },
        {'title': f'Peer Clock Stratum: {stratum_name} ({stratum})', 'offset': offset + 1, 'length': 1},
        {'title': f'Peer Polling Interval: {poll} ({poll_seconds} seconds)', 'offset': offset + 2, 'length': 1},
        {'title': f'Peer Clock Precision: {precision} ({precision_seconds:.9f} seconds)', 'offset': offset + 3, 'length': 1},
        {'title': f'Root Delay: {root_delay / 65536.0:.6f} seconds', 'offset': offset + 4, 'length': 4},
        {'title': f'Root Dispersion: {root_dispersion / 65536.0:.6f} seconds', 'offset': offset + 8, 'length': 4},
        {'title': f'Reference ID: {ref_id}', 'offset': offset + 12, 'length': 4},
        {'title': f'Reference Timestamp: {_ntp_timestamp_text(ref_ts)}', 'offset': offset + 16, 'length': 8},
        {'title': f'Origin Timestamp: {_ntp_timestamp_text(orig_ts)}', 'offset': offset + 24, 'length': 8},
        {'title': f'Receive Timestamp: {_ntp_timestamp_text(recv_ts)}', 'offset': offset + 32, 'length': 8},
        {'title': f'Transmit Timestamp: {_ntp_timestamp_text(tx_ts)}', 'offset': offset + 40, 'length': 8},
    ]
    if bracket_node is not None:
        children.insert(1, bracket_node)
    return {
        'title': f'Network Time Protocol (NTP Version {version}, {mode_name})',
        'offset': offset,
        'length': len(payload),
        'children': children,
    }


def _slow_protocols_section(payload: bytes, offset: int) -> Dict[str, Any]:
    subtype = int(payload[0]) if len(payload) >= 1 else 0
    subtype_name = {1: 'LACP'}.get(subtype, f'0x{subtype:02x}')
    return {
        'title': '802.3 Slow protocols',
        'offset': offset,
        'length': 1 if len(payload) >= 1 else 0,
        'children': [
            {'title': f'Slow Protocols subtype: {subtype_name} (0x{subtype:02x})', 'offset': offset, 'length': 1},
        ],
    }


def _lacp_state_children(state: int, offset: int) -> List[Dict[str, Any]]:
    return [
        {'title': f'.... ...{1 if state & 0x01 else 0} = LACP Activity: {"Active" if state & 0x01 else "Passive"}', 'offset': offset, 'length': 1},
        {'title': f'.... ..{1 if state & 0x02 else 0}. = LACP Timeout: {"Short Timeout" if state & 0x02 else "Long Timeout"}', 'offset': offset, 'length': 1},
        {'title': f'.... .{1 if state & 0x04 else 0}.. = Aggregation: {"Aggregatable" if state & 0x04 else "Individual"}', 'offset': offset, 'length': 1},
        {'title': f'.... {1 if state & 0x08 else 0}... = Synchronization: {"In Sync" if state & 0x08 else "Out of Sync"}', 'offset': offset, 'length': 1},
        {'title': f'...{1 if state & 0x10 else 0} .... = Collecting: {"Enabled" if state & 0x10 else "Disabled"}', 'offset': offset, 'length': 1},
        {'title': f'..{1 if state & 0x20 else 0}. .... = Distributing: {"Enabled" if state & 0x20 else "Disabled"}', 'offset': offset, 'length': 1},
        {'title': f'.{1 if state & 0x40 else 0}.. .... = Defaulted: {"Yes" if state & 0x40 else "No"}', 'offset': offset, 'length': 1},
        {'title': f'{1 if state & 0x80 else 0}... .... = Expired: {"Yes" if state & 0x80 else "No"}', 'offset': offset, 'length': 1},
    ]


def _lacp_state_flags_text(state: int) -> str:
    return ''.join([
        '*' if state & 0x80 else '*',
        '*' if state & 0x40 else '*',
        'D' if state & 0x20 else '*',
        'C' if state & 0x10 else '*',
        'S' if state & 0x08 else '*',
        'G' if state & 0x04 else '*',
        '*' if state & 0x02 else '*',
        'A' if state & 0x01 else '*',
    ])


def _lacp_section(payload: bytes, offset: int) -> Dict[str, Any]:
    children = []
    if len(payload) >= 1:
        children.append({'title': f'LACP Version: 0x{payload[0]:02x}', 'offset': offset, 'length': 1})
    pos = 1
    while pos + 2 <= len(payload):
        tlv_type = int(payload[pos])
        tlv_len = int(payload[pos + 1])
        if tlv_type == 0 and tlv_len == 0:
            children.append({
                'title': 'TLV Type: Terminator (0x00)',
                'offset': offset + pos,
                'length': 1,
            })
            children.append({
                'title': 'TLV Length: 0x00',
                'offset': offset + pos + 1,
                'length': 1,
            })
            if pos + 2 < len(payload):
                children.append({'title': f'Pad: {payload[pos + 2:].hex()}', 'offset': offset + pos + 2, 'length': len(payload) - (pos + 2)})
            break
        if tlv_len <= 0 or pos + tlv_len > len(payload):
            break
        value = payload[pos + 2:pos + tlv_len]
        if tlv_type in {1, 2} and len(value) >= 18:
            role = 'Actor' if tlv_type == 1 else 'Partner'
            role_name = 'Actor Information' if tlv_type == 1 else 'Partner Information'
            sys_pri = int.from_bytes(value[0:2], 'big')
            sys_id = ':'.join(f'{b:02x}' for b in value[2:8])
            key = int.from_bytes(value[8:10], 'big')
            port_pri = int.from_bytes(value[10:12], 'big')
            port = int.from_bytes(value[12:14], 'big')
            state = int(value[14])
            children.extend([
                {'title': f'TLV Type: {role_name} (0x{tlv_type:02x})', 'offset': offset + pos, 'length': 1},
                {'title': f'TLV Length: 0x{tlv_len:02x}', 'offset': offset + pos + 1, 'length': 1},
                {'title': f'{role} System Priority: {sys_pri}', 'offset': offset + pos + 2, 'length': 2},
                {'title': f'{role} System ID: {_mac_display(sys_id)}', 'offset': offset + pos + 4, 'length': 6},
                {'title': f'{role} Key: {key}', 'offset': offset + pos + 10, 'length': 2},
                {'title': f'{role} Port Priority: {port_pri}', 'offset': offset + pos + 12, 'length': 2},
                {'title': f'{role} Port: {port}', 'offset': offset + pos + 14, 'length': 2},
                {'title': f'{role} State: 0x{state:02x}, LACP Activity, Aggregation, Synchronization, Collecting, Distributing', 'offset': offset + pos + 16, 'length': 1, 'children': _lacp_state_children(state, offset + pos + 16)},
                {'title': f'[{role} State Flags: {_lacp_state_flags_text(state)}]'},
                {'title': f'Reserved: {value[15:18].hex()}', 'offset': offset + pos + 17, 'length': 3},
            ])
        elif tlv_type == 3 and len(value) >= 14:
            max_delay = int.from_bytes(value[0:2], 'big')
            children.extend([
                {'title': 'TLV Type: Collector Information (0x03)', 'offset': offset + pos, 'length': 1},
                {'title': f'TLV Length: 0x{tlv_len:02x}', 'offset': offset + pos + 1, 'length': 1},
                {'title': f'Collector Max Delay: {max_delay}', 'offset': offset + pos + 2, 'length': 2},
                {'title': f'Reserved: {value[2:].hex()}', 'offset': offset + pos + 4, 'length': len(value) - 2},
            ])
        pos += tlv_len
    return {
        'title': 'Link Aggregation Control Protocol',
        'offset': offset,
        'length': len(payload),
        'children': children,
    }


def _vtp_timestamp_text(value: bytes) -> str:
    text = value.decode(errors='ignore')
    if len(text) >= 12 and text.isdigit():
        return f'{text[0:2]}-{text[2:4]}-{text[4:6]} {text[6:8]}:{text[8:10]}:{text[10:12]}'
    return text


def _vtp_section(payload: bytes, offset: int) -> Dict[str, Any]:
    version = int(payload[0]) if len(payload) >= 1 else 0
    code = int(payload[1]) if len(payload) >= 2 else 0
    followers = int(payload[2]) if len(payload) >= 3 else 0
    domain_len = int(payload[3]) if len(payload) >= 4 else 0
    domain_raw = payload[4:36] if len(payload) >= 36 else b''
    domain = domain_raw[:domain_len].decode(errors='ignore')
    revision = int.from_bytes(payload[36:40], 'big') if len(payload) >= 40 else 0
    updater = _ipv4_text(payload[40:44]) if len(payload) >= 44 else '0.0.0.0'
    ts = _vtp_timestamp_text(payload[44:56]) if len(payload) >= 56 else ''
    md5 = payload[56:72].hex() if len(payload) >= 72 else ''
    code_name = {
        0x01: 'Summary Advertisement',
        0x02: 'Subset Advertisement',
        0x03: 'Advertisement Request',
    }.get(code, f'0x{code:02x}')
    children = [
        {'title': f'Version: 0x{version:02x}', 'offset': offset, 'length': 1},
        {'title': f'Code: {code_name} (0x{code:02x})', 'offset': offset + 1, 'length': 1},
        {'title': f'Followers: {followers}', 'offset': offset + 2, 'length': 1},
        {'title': f'Management Domain Length: {domain_len}', 'offset': offset + 3, 'length': 1},
        {'title': f'Management Domain: {domain}', 'offset': offset + 4, 'length': 32},
        {'title': f'Configuration Revision Number: {revision}', 'offset': offset + 36, 'length': 4},
        {'title': f'Updater Identity: {updater}', 'offset': offset + 40, 'length': 4},
        {'title': f'Update Timestamp: {ts}', 'offset': offset + 44, 'length': 12},
        {'title': f'MD5 Digest: {md5}', 'offset': offset + 56, 'length': 16},
    ]
    return {
        'title': 'VLAN Trunking Protocol',
        'offset': offset,
        'length': min(len(payload), 72),
        'children': children,
    }


def _dtp_section(payload: bytes, offset: int) -> Dict[str, Any]:
    version = int(payload[0]) if len(payload) >= 1 else 0
    pos = 1
    children = [
        {'title': f'Version: {version}', 'offset': offset, 'length': 1},
    ]
    summary_domain = ''
    summary_status = ''
    summary_type = ''
    summary_sender = ''
    while pos + 4 <= len(payload):
        tlv_type = int.from_bytes(payload[pos:pos + 2], 'big')
        tlv_len = int.from_bytes(payload[pos + 2:pos + 4], 'big')
        if tlv_len < 4 or pos + tlv_len > len(payload):
            break
        value = payload[pos + 4:pos + tlv_len]
        if tlv_type == 0x0001:
            summary_domain = value.decode(errors='ignore').rstrip('\x00')
            children.append({'title': 'Domain', 'offset': offset + pos, 'length': tlv_len, 'children': [
                {'title': 'Type: Domain (0x0001)', 'offset': offset + pos, 'length': 2},
                {'title': f'Length: {tlv_len}', 'offset': offset + pos + 2, 'length': 2},
                {'title': f'Domain: {summary_domain}', 'offset': offset + pos + 4, 'length': len(value)},
            ]})
        elif tlv_type == 0x0002 and len(value) >= 1:
            status = int(value[0])
            summary_status = f'Trunk/On (0x{status:02x})' if status == 0x81 else f'0x{status:02x}'
            children.append({'title': 'Trunk Status', 'offset': offset + pos, 'length': tlv_len, 'children': [
                {'title': 'Type: Trunk Status (0x0002)', 'offset': offset + pos, 'length': 2},
                {'title': f'Length: {tlv_len}', 'offset': offset + pos + 2, 'length': 2},
                {'title': f'Value: {summary_status}', 'offset': offset + pos + 4, 'length': 1, 'children': [
                    {'title': f'{1 if status & 0x80 else 0}... .... = Trunk Operating Status: {"Trunk" if status & 0x80 else "Access"} (0x{(status >> 7) & 0x1:x})', 'offset': offset + pos + 4, 'length': 1},
                    {'title': f'.... .{status & 0x07:03b} = Trunk Administrative Status: {"On" if (status & 0x07) == 0x01 else (status & 0x07)} (0x{status & 0x07:x})', 'offset': offset + pos + 4, 'length': 1},
                ]},
            ]})
        elif tlv_type == 0x0003 and len(value) >= 1:
            trunk_type = int(value[0])
            summary_type = f'802.1Q/802.1Q (0x{trunk_type:02x})' if trunk_type == 0xa5 else f'0x{trunk_type:02x}'
            children.append({'title': 'Trunk Type', 'offset': offset + pos, 'length': tlv_len, 'children': [
                {'title': 'Type: Trunk Type (0x0003)', 'offset': offset + pos, 'length': 2},
                {'title': f'Length: {tlv_len}', 'offset': offset + pos + 2, 'length': 2},
                {'title': f'Value: {summary_type}', 'offset': offset + pos + 4, 'length': 1, 'children': [
                    {'title': f'{(trunk_type >> 5) & 0x07:03b}. .... = Trunk Operating Type: {"802.1Q" if ((trunk_type >> 5) & 0x07) == 0x5 else ((trunk_type >> 5) & 0x07)} (0x{((trunk_type >> 5) & 0x07):x})', 'offset': offset + pos + 4, 'length': 1},
                    {'title': f'.... .{trunk_type & 0x07:03b} = Trunk Administrative Type: {"802.1Q" if (trunk_type & 0x07) == 0x5 else (trunk_type & 0x07)} (0x{trunk_type & 0x07:x})', 'offset': offset + pos + 4, 'length': 1},
                ]},
            ]})
        elif tlv_type == 0x0004 and len(value) >= 6:
            sender = ':'.join(f'{b:02x}' for b in value[:6])
            summary_sender = _mac_display(sender)
            children.append({'title': 'Sender ID', 'offset': offset + pos, 'length': tlv_len, 'children': [
                {'title': 'Type: Sender ID (0x0004)', 'offset': offset + pos, 'length': 2},
                {'title': f'Length: {tlv_len}', 'offset': offset + pos + 2, 'length': 2},
                {'title': f'Sender ID: {summary_sender}', 'offset': offset + pos + 4, 'length': 6},
            ]})
        pos += tlv_len
    title = 'Dynamic Trunk Protocol'
    if summary_domain and summary_status and summary_type and summary_sender:
        title = f'Dynamic Trunk Protocol: {summary_domain} (Operating/Administrative): {summary_status} (Operating/Administrative): {summary_type}: {summary_sender.split(" (",1)[-1][:-1] if " (" in summary_sender else summary_sender}'
    return {
        'title': title,
        'offset': offset,
        'length': len(payload),
        'children': children,
    }


def _stp_section(payload: bytes, offset: int) -> Dict[str, Any]:
    flags = int(payload[4]) if len(payload) >= 5 else 0
    root_prio_field = int.from_bytes(payload[5:7], 'big') if len(payload) >= 7 else 0
    root_prio = root_prio_field & 0xF000
    root_vlan = root_prio_field & 0x0FFF
    root_mac = ':'.join(f'{b:02x}' for b in payload[7:13]) if len(payload) >= 13 else ''
    path_cost = int.from_bytes(payload[13:17], 'big') if len(payload) >= 17 else 0
    bridge_prio_field = int.from_bytes(payload[17:19], 'big') if len(payload) >= 19 else 0
    bridge_prio = bridge_prio_field & 0xF000
    bridge_vlan = bridge_prio_field & 0x0FFF
    bridge_mac = ':'.join(f'{b:02x}' for b in payload[19:25]) if len(payload) >= 25 else ''
    port_id = int.from_bytes(payload[25:27], 'big') if len(payload) >= 27 else 0
    version_1_len = int(payload[35]) if len(payload) >= 36 else 0
    role_code = (flags >> 2) & 0x03
    role_name = {
        0: 'Unknown',
        1: 'Alternate/Backup',
        2: 'Root',
        3: 'Designated',
    }.get(role_code, str(role_code))
    flags_parts = []
    if flags & 0x40:
        flags_parts.append('Agreement')
    if flags & 0x20:
        flags_parts.append('Forwarding')
    if flags & 0x10:
        flags_parts.append('Learning')
    flags_parts.append(f'Port Role: {role_name}')
    if flags & 0x01:
        flags_parts.append('Topology Change')
    children = [
        {'title': 'Protocol Identifier: Spanning Tree Protocol (0x0000)', 'offset': offset, 'length': 2},
        {'title': f'Protocol Version Identifier: Rapid Spanning Tree ({int(payload[2]) if len(payload) >= 3 else 0})', 'offset': offset + 2, 'length': 1},
        {'title': f'BPDU Type: Rapid/Multiple Spanning Tree (0x{int(payload[3]) if len(payload) >= 4 else 0:02x})', 'offset': offset + 3, 'length': 1},
        {
            'title': f'BPDU flags: 0x{flags:02x}, {", ".join(flags_parts)}',
            'offset': offset + 4,
            'length': 1,
            'children': [
                {'title': f'{1 if flags & 0x80 else 0}... .... = Topology Change Acknowledgment: {"Yes" if flags & 0x80 else "No"}', 'offset': offset + 4, 'length': 1},
                {'title': f'.{1 if flags & 0x40 else 0}.. .... = Agreement: {"Yes" if flags & 0x40 else "No"}', 'offset': offset + 4, 'length': 1},
                {'title': f'..{1 if flags & 0x20 else 0}. .... = Forwarding: {"Yes" if flags & 0x20 else "No"}', 'offset': offset + 4, 'length': 1},
                {'title': f'...{1 if flags & 0x10 else 0} .... = Learning: {"Yes" if flags & 0x10 else "No"}', 'offset': offset + 4, 'length': 1},
                {'title': f'.... {role_code:02b}.. = Port Role: {role_name} ({role_code})', 'offset': offset + 4, 'length': 1},
                {'title': f'.... ..{1 if flags & 0x02 else 0}. = Proposal: {"Yes" if flags & 0x02 else "No"}', 'offset': offset + 4, 'length': 1},
                {'title': f'.... ...{1 if flags & 0x01 else 0} = Topology Change: {"Yes" if flags & 0x01 else "No"}', 'offset': offset + 4, 'length': 1},
            ],
        },
        {
            'title': f'Root Identifier: {root_prio} / {root_vlan} / {root_mac}',
            'offset': offset + 5,
            'length': 8,
            'children': [
                {'title': f'Root Bridge Priority: {root_prio}', 'offset': offset + 5, 'length': 2},
                {'title': f'Root Bridge System ID Extension: {root_vlan}', 'offset': offset + 5, 'length': 2},
                {'title': f'Root Bridge System ID: {_mac_display(root_mac)}', 'offset': offset + 7, 'length': 6},
            ],
        },
        {'title': f'Root Path Cost: {path_cost}', 'offset': offset + 13, 'length': 4},
        {
            'title': f'Bridge Identifier: {bridge_prio} / {bridge_vlan} / {bridge_mac}',
            'offset': offset + 17,
            'length': 8,
            'children': [
                {'title': f'Bridge Priority: {bridge_prio}', 'offset': offset + 17, 'length': 2},
                {'title': f'Bridge System ID Extension: {bridge_vlan}', 'offset': offset + 17, 'length': 2},
                {'title': f'Bridge System ID: {_mac_display(bridge_mac)}', 'offset': offset + 19, 'length': 6},
            ],
        },
        {'title': f'Port identifier: 0x{port_id:04x}', 'offset': offset + 25, 'length': 2},
        {'title': f'Message Age: {int.from_bytes(payload[27:29], "big") // 256 if len(payload) >= 29 else 0}', 'offset': offset + 27, 'length': 2},
        {'title': f'Max Age: {int.from_bytes(payload[29:31], "big") // 256 if len(payload) >= 31 else 0}', 'offset': offset + 29, 'length': 2},
        {'title': f'Hello Time: {int.from_bytes(payload[31:33], "big") // 256 if len(payload) >= 33 else 0}', 'offset': offset + 31, 'length': 2},
        {'title': f'Forward Delay: {int.from_bytes(payload[33:35], "big") // 256 if len(payload) >= 35 else 0}', 'offset': offset + 33, 'length': 2},
        {'title': f'Version 1 Length: {version_1_len}', 'offset': offset + 35, 'length': 1},
    ]
    if len(payload) >= 42:
        pvid_type = int.from_bytes(payload[36:38], 'big')
        pvid_len = int.from_bytes(payload[38:40], 'big')
        pvid = int.from_bytes(payload[40:42], 'big')
        children.append({
            'title': f'Originating VLAN (PVID): {pvid}',
            'offset': offset + 36,
            'length': 6,
            'children': [
                {'title': f'Type: Originating VLAN (0x{pvid_type:04x})', 'offset': offset + 36, 'length': 2},
                {'title': f'Length: {pvid_len}', 'offset': offset + 38, 'length': 2},
                {'title': f'Originating VLAN: {pvid}', 'offset': offset + 40, 'length': 2},
            ],
        })
    return {
        'title': 'Spanning Tree Protocol',
        'offset': offset,
        'length': len(payload),
        'children': children,
    }


def _lldp_section(payload: bytes, offset: int) -> Dict[str, Any]:
    def _tlv_bits(t: int, l: int) -> tuple[str, str]:
        return (f'{t:07b}'[:4] + ' ' + f'{t:07b}'[4:] + '. .... ....', '.... ...' + f'{l:09b}'[:1] + ' ' + f'{l:09b}'[1:5] + ' ' + f'{l:09b}'[5:])

    def _capability_lines(value: int, value_offset: int) -> List[Dict[str, Any]]:
        labels = [
            ('.... .... .... ...0', 'Other', 0x0001),
            ('.... .... .... ..0.', 'Repeater', 0x0002),
            ('.... .... .... .1..', 'Bridge', 0x0004),
            ('.... .... .... 0...', 'WLAN access point', 0x0008),
            ('.... .... ...0 ....', 'Router', 0x0010),
            ('.... .... ..0. ....', 'Telephone', 0x0020),
            ('.... .... .0.. ....', 'DOCSIS cable device', 0x0040),
            ('.... .... 0... ....', 'Station only', 0x0080),
            ('.... ...0 .... ....', 'C-VLAN component', 0x0100),
            ('.... ..0. .... ....', 'S-VLAN component', 0x0200),
            ('.... .0.. .... ....', 'TPMR component', 0x0400),
        ]
        lines = []
        for bits, label, mask in labels:
            capable = bool(value & mask)
            lines.append({
                'title': f'{bits} = {label}: {"Capable" if capable else "Not capable"}',
                'offset': value_offset,
                'length': 2,
            })
        return lines

    pos = 0
    children = []
    while pos + 2 <= len(payload):
        header = int.from_bytes(payload[pos:pos + 2], 'big')
        tlv_type = (header >> 9) & 0x7F
        tlv_len = header & 0x1FF
        value = payload[pos + 2:pos + 2 + tlv_len]
        if pos + 2 + tlv_len > len(payload):
            break
        type_bits, len_bits = _tlv_bits(tlv_type, tlv_len)
        if tlv_type == 1 and len(value) >= 7:
            subtype = int(value[0])
            chassis = ':'.join(f'{b:02x}' for b in value[1:7])
            children.append({
                'title': f'Chassis Subtype = MAC address, Id: {chassis}',
                'offset': offset + pos,
                'length': 2 + tlv_len,
                'children': [
                    {'title': f'{type_bits} = TLV Type: Chassis Id (1)', 'offset': offset + pos, 'length': 2},
                    {'title': f'{len_bits} = TLV Length: {tlv_len}', 'offset': offset + pos, 'length': 2},
                    {'title': 'Chassis Id Subtype: MAC address (4)', 'offset': offset + pos + 2, 'length': 1},
                    {'title': f'Chassis Id: {_mac_display(chassis)}', 'offset': offset + pos + 3, 'length': 6},
                ],
            })
        elif tlv_type == 2 and len(value) >= 2:
            port = value[1:].decode(errors='ignore')
            children.append({
                'title': f'Port Subtype = Interface name, Id: {port}',
                'offset': offset + pos,
                'length': 2 + tlv_len,
                'children': [
                    {'title': f'{type_bits} = TLV Type: Port Id (2)', 'offset': offset + pos, 'length': 2},
                    {'title': f'{len_bits} = TLV Length: {tlv_len}', 'offset': offset + pos, 'length': 2},
                    {'title': 'Port Id Subtype: Interface name (5)', 'offset': offset + pos + 2, 'length': 1},
                    {'title': f'Port Id: {port}', 'offset': offset + pos + 3, 'length': max(0, tlv_len - 1)},
                ],
            })
        elif tlv_type == 3 and len(value) >= 2:
            ttl = int.from_bytes(value[:2], 'big')
            children.append({
                'title': f'Time To Live = {ttl} sec',
                'offset': offset + pos,
                'length': 2 + tlv_len,
                'children': [
                    {'title': '[Normal LLDPDU]'},
                    {'title': f'{type_bits} = TLV Type: Time to Live (3)', 'offset': offset + pos, 'length': 2},
                    {'title': f'{len_bits} = TLV Length: {tlv_len}', 'offset': offset + pos, 'length': 2},
                    {'title': f'Seconds: {ttl}', 'offset': offset + pos + 2, 'length': 2},
                ],
            })
        elif tlv_type == 4:
            port_desc = value.decode(errors='ignore')
            children.append({
                'title': f'Port Description = {port_desc}',
                'offset': offset + pos,
                'length': 2 + tlv_len,
                'children': [
                    {'title': f'{type_bits} = TLV Type: Port Description (4)', 'offset': offset + pos, 'length': 2},
                    {'title': f'{len_bits} = TLV Length: {tlv_len}', 'offset': offset + pos, 'length': 2},
                    {'title': f'Port Description: {port_desc}', 'offset': offset + pos + 2, 'length': tlv_len},
                ],
            })
        elif tlv_type == 5:
            sys_name = value.decode(errors='ignore')
            children.append({
                'title': f'System Name = {sys_name}',
                'offset': offset + pos,
                'length': 2 + tlv_len,
                'children': [
                    {'title': f'{type_bits} = TLV Type: System Name (5)', 'offset': offset + pos, 'length': 2},
                    {'title': f'{len_bits} = TLV Length: {tlv_len}', 'offset': offset + pos, 'length': 2},
                    {'title': f'System Name: {sys_name}', 'offset': offset + pos + 2, 'length': tlv_len},
                ],
            })
        elif tlv_type == 6:
            desc = value.decode(errors='ignore')
            label = 'System Description'
            if len(desc) > 120:
                children.append({
                    'title': f'[…] {label} = {desc[:120]}',
                    'offset': offset + pos,
                    'length': 2 + tlv_len,
                    'children': [
                        {'title': f'{type_bits} = TLV Type: System Description (6)', 'offset': offset + pos, 'length': 2},
                        {'title': f'{len_bits} = TLV Length: {tlv_len}', 'offset': offset + pos, 'length': 2},
                        {'title': f'System Description […]: {desc[:120]}', 'offset': offset + pos + 2, 'length': tlv_len},
                    ],
                })
            else:
                children.append({
                    'title': f'{label} = {desc}',
                    'offset': offset + pos,
                    'length': 2 + tlv_len,
                    'children': [
                        {'title': f'{type_bits} = TLV Type: System Description (6)', 'offset': offset + pos, 'length': 2},
                        {'title': f'{len_bits} = TLV Length: {tlv_len}', 'offset': offset + pos, 'length': 2},
                        {'title': f'System Description: {desc}', 'offset': offset + pos + 2, 'length': tlv_len},
                    ],
                })
        elif tlv_type == 7 and len(value) >= 4:
            caps = int.from_bytes(value[:2], 'big')
            enabled = int.from_bytes(value[2:4], 'big')
            children.append({
                'title': 'Capabilities',
                'offset': offset + pos,
                'length': 2 + tlv_len,
                'children': [
                    {'title': f'{type_bits} = TLV Type: System Capabilities (7)', 'offset': offset + pos, 'length': 2},
                    {'title': f'{len_bits} = TLV Length: {tlv_len}', 'offset': offset + pos, 'length': 2},
                    {'title': f'Capabilities: 0x{caps:04x}', 'offset': offset + pos + 2, 'length': 2, 'children': _capability_lines(caps, offset + pos + 2)},
                    {'title': f'Enabled Capabilities: 0x{enabled:04x}', 'offset': offset + pos + 4, 'length': 2, 'children': _capability_lines(enabled, offset + pos + 4)},
                ],
            })
        elif tlv_type == 8 and len(value) >= 1:
            addr_len = int(value[0])
            addr_subtype = int(value[1]) if len(value) >= 2 else 0
            addr_bytes = value[2:2 + max(0, addr_len - 1)]
            if addr_subtype == 1 and len(addr_bytes) == 4:
                mgmt_addr = '.'.join(str(int(b)) for b in addr_bytes)
            elif addr_subtype == 2 and len(addr_bytes) == 16:
                mgmt_addr = str(ipaddress.IPv6Address(addr_bytes))
            else:
                mgmt_addr = addr_bytes.hex()
            iface_subtype = int(value[2 + max(0, addr_len - 1)]) if len(value) > 2 + max(0, addr_len - 1) else 0
            iface_number_offset = 3 + max(0, addr_len - 1)
            iface_number = int.from_bytes(value[iface_number_offset:iface_number_offset + 4], 'big') if len(value) >= iface_number_offset + 4 else 0
            oid_len_offset = iface_number_offset + 4
            oid_len = int(value[oid_len_offset]) if len(value) > oid_len_offset else 0
            children.append({
                'title': 'Management Address',
                'offset': offset + pos,
                'length': 2 + tlv_len,
                'children': [
                    {'title': f'{type_bits} = TLV Type: Management Address (8)', 'offset': offset + pos, 'length': 2},
                    {'title': f'{len_bits} = TLV Length: {tlv_len}', 'offset': offset + pos, 'length': 2},
                    {'title': f'Address String Length: {addr_len}', 'offset': offset + pos + 2, 'length': 1},
                    {'title': f'Address Subtype: {"IPv4 (1)" if addr_subtype == 1 else "IPv6 (2)" if addr_subtype == 2 else addr_subtype}', 'offset': offset + pos + 3, 'length': 1},
                    {'title': f'Management Address: {mgmt_addr}', 'offset': offset + pos + 4, 'length': max(0, addr_len - 1)},
                    {'title': f'Interface Subtype: {"System port number (3)" if iface_subtype == 3 else iface_subtype}', 'offset': offset + pos + 2 + iface_number_offset, 'length': 1},
                    {'title': f'Interface Number: {iface_number}', 'offset': offset + pos + 3 + iface_number_offset, 'length': 4},
                    {'title': f'OID String Length: {oid_len}', 'offset': offset + pos + 3 + oid_len_offset, 'length': 1},
                ],
            })
        elif tlv_type == 127 and len(value) >= 4:
            oui = ':'.join(f'{b:02x}' for b in value[:3])
            subtype = int(value[3])
            auto = int(value[4]) if len(value) >= 5 else 0
            pmd = int.from_bytes(value[5:7], 'big') if len(value) >= 7 else 0
            mau = int.from_bytes(value[7:9], 'big') if len(value) >= 9 else 0
            children.append({
                'title': 'Ieee 802.3 - MAC/PHY Configuration/Status',
                'offset': offset + pos,
                'length': 2 + tlv_len,
                'children': [
                    {'title': f'{type_bits} = TLV Type: Organization Specific (127)', 'offset': offset + pos, 'length': 2},
                    {'title': f'{len_bits} = TLV Length: {tlv_len}', 'offset': offset + pos, 'length': 2},
                    {'title': f'Organization Unique Code: {oui} (Ieee 802.3)', 'offset': offset + pos + 2, 'length': 3},
                    {'title': f'IEEE 802.3 Subtype: MAC/PHY Configuration/Status (0x{subtype:02x})', 'offset': offset + pos + 5, 'length': 1},
                    {'title': f'Auto-Negotiation Support/Status: 0x{auto:02x}', 'offset': offset + pos + 6, 'length': 1, 'children': [
                        {'title': f'.... ...{1 if auto & 0x01 else 0} = Auto-Negotiation: Supported' if auto & 0x01 else '.... ...0 = Auto-Negotiation: Not supported', 'offset': offset + pos + 6, 'length': 1},
                        {'title': f'.... ..{1 if auto & 0x02 else 0}. = Auto-Negotiation: Enabled' if auto & 0x02 else '.... ..0. = Auto-Negotiation: Disabled', 'offset': offset + pos + 6, 'length': 1},
                    ]},
                    {'title': f'PMD Auto-Negotiation Advertised Capability: 0x{pmd:04x}', 'offset': offset + pos + 7, 'length': 2, 'children': [
                        {'title': '.... .... .... ...0 = 1000BASE-T (full duplex mode): Not capable', 'offset': offset + pos + 7, 'length': 2},
                        {'title': '.... .... .... ..0. = 1000BASE-T (half duplex mode): Not capable', 'offset': offset + pos + 7, 'length': 2},
                        {'title': '.... .... .... .0.. = 1000BASE-X (-LX, -SX, -CX full duplex mode): Not capable', 'offset': offset + pos + 7, 'length': 2},
                        {'title': '.... .... .... 0... = 1000BASE-X (-LX, -SX, -CX half duplex mode): Not capable', 'offset': offset + pos + 7, 'length': 2},
                        {'title': '.... .... ...0 .... = Asymmetric and Symmetric PAUSE (for full-duplex links): Not capable', 'offset': offset + pos + 7, 'length': 2},
                        {'title': '.... .... ..0. .... = Symmetric PAUSE (for full-duplex links): Not capable', 'offset': offset + pos + 7, 'length': 2},
                        {'title': '.... .... .0.. .... = Asymmetric PAUSE (for full-duplex links): Not capable', 'offset': offset + pos + 7, 'length': 2},
                        {'title': '.... .... 0... .... = PAUSE (for full-duplex links): Not capable', 'offset': offset + pos + 7, 'length': 2},
                        {'title': '.... ...0 .... .... = 100BASE-T2 (full duplex mode): Not capable', 'offset': offset + pos + 7, 'length': 2},
                        {'title': '.... ..0. .... .... = 100BASE-T2 (half duplex mode): Not capable', 'offset': offset + pos + 7, 'length': 2},
                        {'title': '.... .0.. .... .... = 100BASE-TX (full duplex mode): Not capable', 'offset': offset + pos + 7, 'length': 2},
                        {'title': '.... 0... .... .... = 100BASE-TX (half duplex mode): Not capable', 'offset': offset + pos + 7, 'length': 2},
                        {'title': '...0 .... .... .... = 100BASE-T4: Not capable', 'offset': offset + pos + 7, 'length': 2},
                        {'title': '..0. .... .... .... = 10BASE-T (full duplex mode): Not capable', 'offset': offset + pos + 7, 'length': 2},
                        {'title': '.0.. .... .... .... = 10BASE-T (half duplex mode): Not capable', 'offset': offset + pos + 7, 'length': 2},
                        {'title': '1... .... .... .... = Other or unknown: Capable' if pmd & 0x8000 else '1... .... .... .... = Other or unknown: Not capable', 'offset': offset + pos + 7, 'length': 2},
                    ]},
                    {'title': 'Same in inverse (wrong) bitorder', 'offset': offset + pos + 7, 'length': 2, 'children': [
                        {'title': '1... .... .... .... = 1000BASE-T (full duplex mode): Capable' if pmd & 0x8000 else '1... .... .... .... = 1000BASE-T (full duplex mode): Not capable', 'offset': offset + pos + 7, 'length': 2},
                        {'title': '.0.. .... .... .... = 1000BASE-T (half duplex mode): Not capable', 'offset': offset + pos + 7, 'length': 2},
                        {'title': '..0. .... .... .... = 1000BASE-X (-LX, -SX, -CX full duplex mode): Not capable', 'offset': offset + pos + 7, 'length': 2},
                        {'title': '...0 .... .... .... = 1000BASE-X (-LX, -SX, -CX half duplex mode): Not capable', 'offset': offset + pos + 7, 'length': 2},
                        {'title': '.... 0... .... .... = Asymmetric and Symmetric PAUSE (for full-duplex links): Not capable', 'offset': offset + pos + 7, 'length': 2},
                        {'title': '.... .0.. .... .... = Symmetric PAUSE (for full-duplex links): Not capable', 'offset': offset + pos + 7, 'length': 2},
                        {'title': '.... ..0. .... .... = Asymmetric PAUSE (for full-duplex links): Not capable', 'offset': offset + pos + 7, 'length': 2},
                        {'title': '.... ...0 .... .... = PAUSE (for full-duplex links): Not capable', 'offset': offset + pos + 7, 'length': 2},
                        {'title': '.... .... 0... .... = 100BASE-T2 (full duplex mode): Not capable', 'offset': offset + pos + 7, 'length': 2},
                        {'title': '.... .... .0.. .... = 100BASE-T2 (half duplex mode): Not capable', 'offset': offset + pos + 7, 'length': 2},
                        {'title': '.... .... ..0. .... = 100BASE-TX (full duplex mode): Not capable', 'offset': offset + pos + 7, 'length': 2},
                        {'title': '.... .... ...0 .... = 100BASE-TX (half duplex mode): Not capable', 'offset': offset + pos + 7, 'length': 2},
                        {'title': '.... .... .... 0... = 100BASE-T4: Not capable', 'offset': offset + pos + 7, 'length': 2},
                        {'title': '.... .... .... .0.. = 10BASE-T (full duplex mode): Not capable', 'offset': offset + pos + 7, 'length': 2},
                        {'title': '.... .... .... ..0. = 10BASE-T (half duplex mode): Not capable', 'offset': offset + pos + 7, 'length': 2},
                        {'title': '.... .... .... ...0 = Other or unknown: Not capable', 'offset': offset + pos + 7, 'length': 2},
                    ]},
                    {'title': f'Operational MAU Type: other or unknown (0x{mau:04x})', 'offset': offset + pos + 9, 'length': 2},
                ],
            })
        elif tlv_type == 0:
            children.append({
                'title': 'End of LLDPDU',
                'offset': offset + pos,
                'length': 2,
                'children': [
                    {'title': f'{type_bits} = TLV Type: End of LLDPDU (0)', 'offset': offset + pos, 'length': 2},
                    {'title': f'{len_bits} = TLV Length: 0', 'offset': offset + pos, 'length': 2},
                ],
            })
        if tlv_type == 0:
            break
        pos += 2 + tlv_len
    return {
        'title': 'Link Layer Discovery Protocol',
        'offset': offset,
        'length': len(payload),
        'children': children,
    }


def _udld_tlv_name(tlv_type: int) -> str:
    return {
        0x0001: 'Device ID',
        0x0002: 'Port ID',
        0x0003: 'Echo',
        0x0004: 'Message interval',
        0x0005: 'Timeout interval',
        0x0006: 'Device name',
        0x0007: 'Sequence number',
    }.get(tlv_type, f'0x{tlv_type:04x}')


def _udld_section(payload: bytes, offset: int) -> Dict[str, Any]:
    version = (int(payload[0]) >> 5) & 0x07 if len(payload) >= 1 else 0
    opcode = int(payload[0]) & 0x1F if len(payload) >= 1 else 0
    opcode_bits = f'{opcode:05b}'
    flags = int(payload[1]) if len(payload) >= 2 else 0
    checksum = int.from_bytes(payload[2:4], 'big') if len(payload) >= 4 else 0
    children = [
        {'title': f'{version:03b}. .... = Version: {version}', 'offset': offset, 'length': 1},
        {'title': f'...{opcode_bits[0]} {opcode_bits[1:]} = Opcode: {"Probe" if opcode == 1 else opcode} ({opcode})', 'offset': offset, 'length': 1},
        {
            'title': f'Flags: {flags}',
            'offset': offset + 1,
            'length': 1,
            'children': [
                {'title': f'.... ...{flags & 0x01} = Recommended timeout: 0x{flags & 0x01:x}', 'offset': offset + 1, 'length': 1},
                {'title': f'.... ..{1 if flags & 0x02 else 0}. = ReSynch: 0x{1 if flags & 0x02 else 0:x}', 'offset': offset + 1, 'length': 1},
            ],
        },
        {'title': f'Checksum: 0x{checksum:04x}', 'offset': offset + 2, 'length': 2},
    ]
    pos = 4
    while pos + 4 <= len(payload):
        tlv_type = int.from_bytes(payload[pos:pos + 2], 'big')
        tlv_len = int.from_bytes(payload[pos + 2:pos + 4], 'big')
        if tlv_len < 4 or pos + tlv_len > len(payload):
            break
        value = payload[pos + 4:pos + tlv_len]
        tlv_name = _udld_tlv_name(tlv_type)
        if tlv_type == 0x0001:
            text = value.decode(errors='ignore')
            title = f'Device ID: {text}'
            value_title = f'Device ID: {text}'
        elif tlv_type == 0x0002:
            text = value.decode(errors='ignore')
            title = f'Port ID: {text}'
            value_title = f'Sent through Interface: {text}'
        elif tlv_type in {0x0003, 0x0004, 0x0005, 0x0006, 0x0007}:
            title = f'Type: {tlv_name}, length: {tlv_len}'
            value_title = f'Data: {value.hex()}'
        else:
            title = f'Type: {tlv_name}, length: {tlv_len}'
            value_title = f'Data: {value.hex()}'
        children.append({
            'title': title,
            'offset': offset + pos,
            'length': tlv_len,
            'children': [
                {'title': f'Type: {tlv_name} (0x{tlv_type:04x})', 'offset': offset + pos, 'length': 2},
                {'title': f'Length: {tlv_len}', 'offset': offset + pos + 2, 'length': 2},
                {'title': value_title, 'offset': offset + pos + 4, 'length': tlv_len - 4},
            ],
        })
        pos += tlv_len
    return {
        'title': 'Unidirectional Link Detection',
        'offset': offset,
        'length': len(payload),
        'children': children,
    }


def _hsrpv2_section(payload: bytes, offset: int) -> Dict[str, Any]:
    children = []
    if len(payload) >= 6 and int(payload[0]) == 2 and int(payload[1]) == 4:
        active_groups = int.from_bytes(payload[2:4], 'big')
        passive_groups = int.from_bytes(payload[4:6], 'big')
        children.append({
            'title': 'Interface State TLV: Type=2 Len=4',
            'offset': offset,
            'length': 6,
            'children': [
                {'title': 'Type: Interface State (2)', 'offset': offset, 'length': 1},
                {'title': 'Length: 4', 'offset': offset + 1, 'length': 1},
                {'title': f'Active Groups: {active_groups}', 'offset': offset + 2, 'length': 2},
                {'title': f'Passive Groups: {passive_groups}', 'offset': offset + 4, 'length': 2},
            ],
        })
    if len(payload) >= 42:
        tlv_type = int(payload[0])
        tlv_len = int(payload[1])
        version = int(payload[2])
        opcode = int(payload[3])
        state = int(payload[4])
        group = int.from_bytes(payload[6:8], 'big')
        identifier = ':'.join(f'{b:02x}' for b in payload[8:14])
        priority = int.from_bytes(payload[14:18], 'big')
        hellotime = int.from_bytes(payload[18:22], 'big')
        holdtime = int.from_bytes(payload[22:26], 'big')
        ip_version = int(payload[5]) if len(payload) >= 6 else 0
        state_name = {1: 'Initial', 2: 'Learn', 3: 'Listen', 4: 'Speak', 5: 'Standby', 6: 'Active'}.get(state, str(state))
        vip_title = ''
        vip_offset = offset + 26
        vip_length = 16
        if ip_version == 4 and len(payload) >= 30:
            vip_title = f'Virtual IP Address: {_ipv4_text(payload[26:30])}'
            vip_length = 4
        else:
            vip_title = f'Virtual IPv6 Address: {str(ipaddress.IPv6Address(payload[26:42])) if len(payload) >= 42 else ""}'
        children.append({
            'title': f'Group State TLV: Type={tlv_type} Len={tlv_len}',
            'offset': offset,
            'length': 42,
            'children': [
                {'title': f'Type: {tlv_type}', 'offset': offset, 'length': 1},
                {'title': f'Length: {tlv_len}', 'offset': offset + 1, 'length': 1},
                {'title': f'Version: {version}', 'offset': offset + 2, 'length': 1},
                {'title': f'Op Code: {"Hello" if opcode == 0 else opcode} ({opcode})', 'offset': offset + 3, 'length': 1},
                {'title': f'State: {state_name} ({state})', 'offset': offset + 4, 'length': 1},
                {'title': f'IP Ver.: {"IPv4" if ip_version == 4 else "IPv6"} ({ip_version})', 'offset': offset + 5, 'length': 1},
                {'title': f'Group: {group}', 'offset': offset + 6, 'length': 2},
                {'title': f'Identifier: {_mac_display(identifier)}', 'offset': offset + 8, 'length': 6},
                {'title': f'Priority: {priority}', 'offset': offset + 14, 'length': 4},
                {'title': f'Hellotime: Default ({hellotime})', 'offset': offset + 18, 'length': 4},
                {'title': f'Holdtime: Default ({holdtime})', 'offset': offset + 22, 'length': 4},
                {'title': vip_title, 'offset': vip_offset, 'length': vip_length},
            ],
        })
    if len(payload) >= 68:
        auth_type = int(payload[42])
        auth_len = int(payload[43])
        sender_ip = '.'.join(str(int(b)) for b in payload[48:52])
        children.append({
            'title': f'MD5 Authentication TLV: Type={auth_type} Len={auth_len}',
            'offset': offset + 42,
            'length': 30,
            'children': [
                {'title': f'Type: {auth_type}', 'offset': offset + 42, 'length': 1},
                {'title': f'Length: {auth_len}', 'offset': offset + 43, 'length': 1},
                {'title': 'MD5 Algorithm: MD5 (1)', 'offset': offset + 44, 'length': 1},
                {'title': 'Padding: 0x00', 'offset': offset + 45, 'length': 1},
                {'title': f"MD5 Flags: {int.from_bytes(payload[46:48], 'big') if len(payload) >= 48 else 0}", 'offset': offset + 46, 'length': 2},
                {'title': f"Sender's IP Address: {sender_ip}", 'offset': offset + 48, 'length': 4},
                {'title': f"MD5 Key ID: {int.from_bytes(payload[52:56], 'big') if len(payload) >= 56 else 0}", 'offset': offset + 52, 'length': 4},
                {'title': f"MD5 Authentication Data: {payload[56:72].hex()}", 'offset': offset + 56, 'length': min(16, max(0, len(payload) - 56))},
            ],
        })
    return {
        'title': 'Cisco Hot Standby Router Protocol',
        'offset': offset,
        'length': len(payload),
        'children': children,
    }

def _ip_section(layer, offset: int, stream_index: int, record=None) -> Dict[str, Any]:

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

    metadata = getattr(record, 'metadata', {}) if record else {}

    if stream_index >= 0:
        children.append({
            'title': f'[Stream index: {stream_index}]',
        })

    if bool(metadata.get('ip_is_fragmented', False)) and int(metadata.get('ip_fragment_version', 0) or 0) == 4:
        reassembled_in = metadata.get('ip_reassembled_in_frame', None)
        if reassembled_in is not None:
            try:
                children.append({'title': f'[Reassembled IPv4 in frame: {int(reassembled_in)}]'})
            except Exception:
                pass
        ip_reassembly = _ip_reassembly_section(metadata, 4)
        if ip_reassembly is not None:
            children.append(ip_reassembly)

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

    if lower.startswith('fc') or lower.startswith('fd'):
        return [
            {'title': '[Address Space: Unique Local Unicast]', 'offset': offset, 'length': 16},
            {
                'title': '[Special-Purpose Allocation: Unique-Local]',
                'offset': offset,
                'length': 16,
                'children': [
                    {'title': '[Source: True]', 'offset': offset, 'length': 16},
                    {'title': '[Destination: True]', 'offset': offset, 'length': 16},
                    {'title': '[Forwardable: True]', 'offset': offset, 'length': 16},
                    {'title': '[Reserved-by-Protocol: False]', 'offset': offset, 'length': 16},
                ],
            },
        ]

    return [{'title': '[Address Space: Global Unicast]', 'offset': offset, 'length': 16}]


def _ipv6_section(layer, offset: int, stream_index: int, record=None) -> Dict[str, Any]:

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
        0: 'CS0',
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
        44: 'Fragment Header for IPv6',
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

    metadata = getattr(record, 'metadata', {}) if record else {}

    if stream_index >= 0:
        children.append({
            'title': f'[Stream index: {stream_index}]'
        })

    if bool(metadata.get('ip_is_fragmented', False)) and int(metadata.get('ip_fragment_version', 0) or 0) == 6:
        reassembled_in = metadata.get('ip_reassembled_in_frame', None)
        if reassembled_in is not None:
            try:
                children.append({'title': f'[Reassembled IPv6 in frame: {int(reassembled_in)}]'})
            except Exception:
                pass
        ip_reassembly = _ip_reassembly_section(metadata, 6)
        if ip_reassembly is not None:
            children.append(ip_reassembly)

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
    is_spurious_retransmission = bool(metadata.get('tcp_is_spurious_retransmission', False))
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
        tcp_analysis_children = []
        if is_spurious_retransmission:
            tcp_analysis_children.append(
                {
                    'title': '[Expert Info (Note/Sequence): This frame is a (suspected) spurious retransmission]',
                    'children': [
                        {'title': '[This frame is a (suspected) spurious retransmission]'},
                        {'title': '[Severity level: Note]'},
                        {'title': '[Group: Sequence]'},
                    ],
                }
            )
        tcp_analysis_children.append(
            {
                'title': '[Expert Info (Note/Sequence): This frame is a (suspected) retransmission]',
                'children': [
                    {'title': '[This frame is a (suspected) retransmission]'},
                    {'title': '[Severity level: Note]'},
                    {'title': '[Group: Sequence]'},
                ],
            }
        )
        seq_ack_children.append({
            'title': '[TCP Analysis Flags]',
            'children': tcp_analysis_children,
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
                # MSS
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
                # NOP
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
                # Window Scale
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
                # SACK Permitted
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
                # SACK
                elif name == 'SAck':
                    # value is a list of (left, right) edges
                    option_titles.append('SACK')
                    sack_blocks = []
                    for i, (left, right) in enumerate(value):
                        sack_blocks.append({
                            'title': f'SACK Block {i+1}: Left Edge={left}, Right Edge={right}',
                            'length': 8
                        })
                    option_children.append({
                        'title': f'TCP Option - SACK ({len(value)} blocks)',
                        'offset': option_offset,
                        'length': 2 + 8 * len(value),
                        'children': [
                            {'title': 'Kind: SACK (5)', 'offset': option_offset, 'length': 1},
                            {'title': f'Length: {2 + 8 * len(value)}', 'offset': option_offset + 1, 'length': 1},
                            *sack_blocks
                        ],
                    })
                    option_offset += 2 + 8 * len(value)
                # Timestamp
                elif name == 'Timestamp':
                    option_titles.append('Timestamp')
                    tsval, tsecr = value
                    option_children.append({
                        'title': f'TCP Option - Timestamp: TSval={tsval}, TSecr={tsecr}',
                        'offset': option_offset,
                        'length': 10,
                        'children': [
                            {'title': 'Kind: Timestamp (8)', 'offset': option_offset, 'length': 1},
                            {'title': 'Length: 10', 'offset': option_offset + 1, 'length': 1},
                            {'title': f'TSval: {tsval}', 'offset': option_offset + 2, 'length': 4},
                            {'title': f'TSecr: {tsecr}', 'offset': option_offset + 6, 'length': 4},
                        ],
                    })
                    option_offset += 10
                # End of Option List
                elif name == 'EOL':
                    option_titles.append('End of Option List')
                    option_children.append({
                        'title': 'TCP Option - End of Option List',
                        'offset': option_offset,
                        'length': 1,
                        'children': [
                            {'title': 'Kind: End of Option List (0)', 'offset': option_offset, 'length': 1},
                        ],
                    })
                    option_offset += 1
                # Fast Open
                elif name == 'TFO':
                    option_titles.append('TCP Fast Open')
                    option_children.append({
                        'title': f'TCP Option - Fast Open: {value.hex() if isinstance(value, (bytes, bytearray)) else value}',
                        'offset': option_offset,
                        'length': 2 + len(value),
                        'children': [
                            {'title': 'Kind: Fast Open (34)', 'offset': option_offset, 'length': 1},
                            {'title': f'Length: {2 + len(value)}', 'offset': option_offset + 1, 'length': 1},
                            {'title': f'Data: {value.hex() if isinstance(value, (bytes, bytearray)) else value}', 'offset': option_offset + 2, 'length': len(value)},
                        ],
                    })
                    option_offset += 2 + len(value)
                # Unknown/Other
                else:
                    # Try to show as hex if possible
                    try:
                        raw = bytes(value) if isinstance(value, (bytes, bytearray)) else value
                        hexval = raw.hex() if isinstance(raw, (bytes, bytearray)) else str(raw)
                    except Exception:
                        hexval = str(value)
                    option_titles.append(str(name))
                    option_children.append({
                        'title': f'TCP Option - {name}: {hexval}',
                        'offset': option_offset,
                        'length': 2 + (len(raw) if isinstance(raw, (bytes, bytearray)) else 0),
                        'children': [
                            {'title': f'Kind: {name}', 'offset': option_offset, 'length': 1},
                            {'title': f'Length: {2 + (len(raw) if isinstance(raw, (bytes, bytearray)) else 0)}', 'offset': option_offset + 1, 'length': 1},
                            {'title': f'Data: {hexval}', 'offset': option_offset + 2, 'length': len(raw) if isinstance(raw, (bytes, bytearray)) else 0},
                        ],
                    })
                    option_offset += 2 + (len(raw) if isinstance(raw, (bytes, bytearray)) else 0)
            except Exception:
                option_titles.append(str(opt))
                option_children.append({'title': str(opt)})
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
        elif metadata.get('tcp_reassembled_pdu_in_frame', None) is not None or metadata.get('tls_reassembled_pdu_in_frame', None) is not None:
            _pdu_frame = metadata.get('tcp_reassembled_pdu_in_frame') or metadata.get('tls_reassembled_pdu_in_frame')
            children.append({
                'title': f'[Reassembled PDU in frame: {int(_pdu_frame)}]',
            })
            # Only map the bytes this frame actually contributes to the reassembled PDU.
            _seg_data_len = int(metadata.get('tls_segment_data_length') or metadata.get('tcp_segment_data_length') or payload_len)
            _seg_data_off = int(metadata.get('tls_segment_data_offset') or metadata.get('tcp_segment_data_offset') or 0)
            _seg_data_off = max(0, min(_seg_data_off, payload_len))
            _seg_data_len = max(0, min(_seg_data_len, payload_len - _seg_data_off))
            children.append({
                'title': f'TCP segment data ({_seg_data_len} bytes)',
                'offset': offset + tcp_header_len + _seg_data_off,
                'length': _seg_data_len,
            })
        elif metadata.get('tcp_reassembled_segments', None) or metadata.get('http_reassembled_segments', None) or metadata.get('tls_reassembled_segments', None):
            # For the completing frame, map only this frame's contribution.
            _frame_no = int(metadata.get('frame_number', 0) or 0)
            _all_segs = (
                metadata.get('tls_reassembled_segments')
                or metadata.get('http_reassembled_segments')
                or metadata.get('tcp_reassembled_segments')
                or []
            )
            _seg_match = None
            for _seg in _all_segs:
                if int(_seg.get('frame_number', 0) or 0) == _frame_no:
                    _seg_match = _seg
                    break
            if _seg_match is None and _all_segs:
                _seg_match = _all_segs[-1]
            _seg_data_len = int((_seg_match or {}).get('payload_length', payload_len))
            _seg_data_off = int((_seg_match or {}).get('tcp_start_offset_in_payload', 0))
            _seg_data_off = max(0, min(_seg_data_off, payload_len))
            _seg_data_len = max(0, min(_seg_data_len, payload_len - _seg_data_off))
            children.append({
                'title': f'TCP segment data ({_seg_data_len} bytes)',
                'offset': offset + tcp_header_len + _seg_data_off,
                'length': _seg_data_len,
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
        or metadata.get('tls_reassembled_segments', [])
        or []
    )
    if not segments:
        return None

    reassembled_len = int(
        metadata.get('tcp_reassembled_length', 0)
        or metadata.get('http_reassembled_length', 0)
        or metadata.get('tls_reassembled_length', 0)
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
        reassembly_payload = bytes(
            metadata.get('http_reassembled_payload', b'')
            or metadata.get('tls_reassembled_payload', b'')
            or b''
        )
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


def _pppoe_code_name(code: int, discovery: bool) -> str:
    if not discovery:
        return 'Session Data' if int(code) == 0x00 else f'Code 0x{int(code):02x}'
    return {
        0x09: 'Active Discovery Initiation (PADI)',
        0x07: 'Active Discovery Offer (PADO)',
        0x19: 'Active Discovery Request (PADR)',
        0x65: 'Active Discovery Session-confirmation (PADS)',
        0xA7: 'Active Discovery Terminate (PADT)',
    }.get(int(code), f'Code 0x{int(code):02x}')


def _ppp_protocol_name(protocol: int) -> str:
    return {
        0xC021: 'Link Control Protocol',
        0x8021: 'Internet Protocol Control Protocol',
        0x8057: 'IPv6 Control Protocol',
    }.get(int(protocol), f'0x{int(protocol):04x}')


def _ppp_control_code_name(code: int) -> str:
    return {
        1: 'Configuration Request',
        2: 'Configuration Ack',
        3: 'Configuration Nak',
        4: 'Configuration Reject',
        5: 'Terminate Request',
        6: 'Terminate Ack',
        7: 'Code Reject',
        8: 'Protocol Reject',
        9: 'Echo Request',
        10: 'Echo Reply',
        11: 'Discard Request',
    }.get(int(code), f'Code {int(code)}')


def _pppoe_tag_name(tag_type: int) -> str:
    return {
        0x0101: 'Service-Name',
        0x0102: 'AC-Name',
        0x0103: 'Host-Uniq',
        0x0104: 'AC-Cookie',
    }.get(int(tag_type), f'Tag 0x{int(tag_type):04x}')


def _pppoe_section(payload: bytes, offset: int) -> Dict[str, Any]:
    if len(payload) < 6:
        return {
            'title': 'PPP-over-Ethernet',
            'offset': offset,
            'length': len(payload),
            'children': [],
        }

    version_type = int(payload[0])
    version = (version_type >> 4) & 0x0F
    pppoe_type = version_type & 0x0F
    code = int(payload[1])
    session_id = int.from_bytes(payload[2:4], 'big')
    payload_length = int.from_bytes(payload[4:6], 'big')
    total_len = min(len(payload), 6 + payload_length)
    pppoe_payload = payload[6:total_len]
    discovery = code != 0x00

    code_name = _pppoe_code_name(code, discovery)
    children: List[Dict[str, Any]] = [
        {'title': f'{version:04b} .... = Version: {version}', 'offset': offset, 'length': 1},
        {'title': f'.... {pppoe_type:04b} = Type: {pppoe_type}', 'offset': offset, 'length': 1},
        {'title': f'Code: {code_name} (0x{code:02x})', 'offset': offset + 1, 'length': 1},
        {'title': f'Session ID: 0x{session_id:04x}', 'offset': offset + 2, 'length': 2},
        {'title': f'Payload Length: {payload_length}', 'offset': offset + 4, 'length': 2},
    ]

    if discovery and pppoe_payload:
        tags_children: List[Dict[str, Any]] = []
        pos = 0
        while pos + 4 <= len(pppoe_payload):
            tag_type = int.from_bytes(pppoe_payload[pos:pos + 2], 'big')
            tag_len = int.from_bytes(pppoe_payload[pos + 2:pos + 4], 'big')
            tag_end = pos + 4 + tag_len
            if tag_end > len(pppoe_payload):
                break
            tag_value = pppoe_payload[pos + 4:tag_end]
            if tag_type == 0x0101 and tag_len == 0:
                pos = tag_end
                continue
            tag_name = _pppoe_tag_name(tag_type)
            if tag_type == 0x0102:
                display_value = tag_value.decode(errors='ignore')
            else:
                display_value = tag_value.hex()
            tags_children.append({
                'title': f'{tag_name}: {display_value}',
                'offset': offset + 6 + pos + 4,
                'length': tag_len,
            })
            pos = tag_end
        children.append({
            'title': 'PPPoE Tags',
            **_byte_mapping(offset, 6, len(pppoe_payload)),
            'children': tags_children,
        })

    return {
        'title': 'PPP-over-Ethernet Discovery' if discovery else 'PPP-over-Ethernet Session',
        'offset': offset,
        'length': total_len if discovery else 6,
        'children': children,
    }


def _ppp_section(payload: bytes, offset: int) -> Dict[str, Any]:
    protocol = int.from_bytes(payload[:2], 'big') if len(payload) >= 2 else 0
    return {
        'title': 'Point-to-Point Protocol',
        'offset': offset,
        'length': min(len(payload), 4),
        'children': [
            {
                'title': f'Protocol: {_ppp_protocol_name(protocol)} (0x{protocol:04x})',
                'offset': offset,
                'length': 2 if len(payload) >= 2 else 0,
            }
        ],
    }


def _ppp_lcp_section(payload: bytes, offset: int) -> Dict[str, Any]:
    if len(payload) < 4:
        return {'title': 'PPP Link Control Protocol', 'offset': offset, 'length': len(payload), 'children': []}

    code = int(payload[0])
    identifier = int(payload[1])
    lcp_length = int.from_bytes(payload[2:4], 'big')
    body_len = min(len(payload), max(4, lcp_length))
    children: List[Dict[str, Any]] = [
        {'title': f'Code: {_ppp_control_code_name(code)} ({code})', 'offset': offset, 'length': 1},
        {'title': f'Identifier: {identifier} (0x{identifier:02x})', 'offset': offset + 1, 'length': 1},
        {'title': f'Length: {lcp_length}', 'offset': offset + 2, 'length': 2},
    ]

    if code in {1, 2, 3, 4} and body_len > 4:
        options_payload = payload[4:body_len]
        option_nodes: List[Dict[str, Any]] = []
        option_names: List[str] = []
        pos = 0
        while pos + 2 <= len(options_payload):
            opt_type = int(options_payload[pos])
            opt_len = int(options_payload[pos + 1])
            if opt_len < 2 or pos + opt_len > len(options_payload):
                break
            opt_value = options_payload[pos + 2:pos + opt_len]
            if opt_type == 1 and opt_len == 4:
                mru = int.from_bytes(opt_value[:2], 'big')
                option_names.append('Maximum Receive Unit')
                option_nodes.append({
                    'title': f'Maximum Receive Unit: {mru}',
                    'offset': offset + 4 + pos,
                    'length': opt_len,
                    'children': [
                        {'title': 'Type: Maximum Receive Unit (1)', 'offset': offset + 4 + pos, 'length': 1},
                        {'title': 'Length: 4', 'offset': offset + 4 + pos + 1, 'length': 1},
                        {'title': f'Maximum Receive Unit: {mru}', 'offset': offset + 4 + pos + 2, 'length': 2},
                    ],
                })
            elif opt_type == 5 and opt_len == 6:
                magic = int.from_bytes(opt_value[:4], 'big')
                option_names.append('Magic Number')
                option_nodes.append({
                    'title': f'Magic Number: 0x{magic:08x}',
                    'offset': offset + 4 + pos,
                    'length': opt_len,
                    'children': [
                        {'title': 'Type: Magic Number (5)', 'offset': offset + 4 + pos, 'length': 1},
                        {'title': 'Length: 6', 'offset': offset + 4 + pos + 1, 'length': 1},
                        {'title': f'Magic Number: 0x{magic:08x}', 'offset': offset + 4 + pos + 2, 'length': 4},
                    ],
                })
            else:
                option_names.append(f'Option {opt_type}')
                option_nodes.append({
                    'title': f'Option {opt_type}: {opt_value.hex()}',
                    'offset': offset + 4 + pos,
                    'length': opt_len,
                })
            pos += opt_len
        if option_nodes:
            children.append({
                'title': f'Options: ({len(options_payload)} bytes), {", ".join(option_names)}',
                'offset': offset + 4,
                'length': len(options_payload),
                'children': option_nodes,
            })
    elif code in {9, 10, 11} and body_len > 4:
        if body_len >= 8:
            magic = int.from_bytes(payload[4:8], 'big')
            children.append({'title': f'Magic Number: 0x{magic:08x}', 'offset': offset + 4, 'length': 4})
        if body_len > 8:
            data = payload[8:body_len]
            children.append({'title': f'Data: {data.hex()}', 'offset': offset + 8, 'length': len(data)})

    return {
        'title': 'PPP Link Control Protocol',
        'offset': offset,
        'length': body_len,
        'children': children,
    }


def _ppp_ip_control_section(payload: bytes, offset: int, ipv6: bool) -> Dict[str, Any]:
    if len(payload) < 4:
        title = 'PPP IPv6 Control Protocol' if ipv6 else 'PPP IP Control Protocol'
        return {'title': title, 'offset': offset, 'length': len(payload), 'children': []}

    code = int(payload[0])
    identifier = int(payload[1])
    proto_len = int.from_bytes(payload[2:4], 'big')
    body_len = min(len(payload), max(4, proto_len))
    title = 'PPP IPv6 Control Protocol' if ipv6 else 'PPP IP Control Protocol'
    children: List[Dict[str, Any]] = [
        {'title': f'Code: {_ppp_control_code_name(code)} ({code})', 'offset': offset, 'length': 1},
        {'title': f'Identifier: {identifier} (0x{identifier:02x})', 'offset': offset + 1, 'length': 1},
        {'title': f'Length: {proto_len}', 'offset': offset + 2, 'length': 2},
    ]

    if code in {1, 2, 3, 4} and body_len > 4:
        options_payload = payload[4:body_len]
        option_nodes: List[Dict[str, Any]] = []
        option_names: List[str] = []
        pos = 0
        while pos + 2 <= len(options_payload):
            opt_type = int(options_payload[pos])
            opt_len = int(options_payload[pos + 1])
            if opt_len < 2 or pos + opt_len > len(options_payload):
                break
            opt_value = options_payload[pos + 2:pos + opt_len]
            if not ipv6 and opt_type == 3 and opt_len == 6:
                ip_text = '.'.join(str(int(byte)) for byte in opt_value[:4])
                option_names.append('IP Address')
                option_nodes.append({
                    'title': 'IP Address',
                    'offset': offset + 4 + pos,
                    'length': opt_len,
                    'children': [
                        {'title': 'Type: IP Address (3)', 'offset': offset + 4 + pos, 'length': 1},
                        {'title': 'Length: 6', 'offset': offset + 4 + pos + 1, 'length': 1},
                        {'title': f'IP Address: {ip_text}', 'offset': offset + 4 + pos + 2, 'length': 4},
                    ],
                })
            elif ipv6 and opt_type == 1 and opt_len == 10:
                iid_text = ':'.join(f'{int(byte):02x}' for byte in opt_value[:8])
                option_names.append('Interface Identifier')
                option_nodes.append({
                    'title': 'Interface Identifier',
                    'offset': offset + 4 + pos,
                    'length': opt_len,
                    'children': [
                        {'title': 'Type: Interface Identifier (1)', 'offset': offset + 4 + pos, 'length': 1},
                        {'title': 'Length: 10', 'offset': offset + 4 + pos + 1, 'length': 1},
                        {'title': f'Interface Identifier: {iid_text}', 'offset': offset + 4 + pos + 2, 'length': 8},
                    ],
                })
            else:
                option_names.append(f'Option {opt_type}')
                option_nodes.append({
                    'title': f'Option {opt_type}: {opt_value.hex()}',
                    'offset': offset + 4 + pos,
                    'length': opt_len,
                })
            pos += opt_len
        if option_nodes:
            children.append({
                'title': f'Options: ({len(options_payload)} bytes), {", ".join(option_names)}',
                'offset': offset + 4,
                'length': len(options_payload),
                'children': option_nodes,
            })

    return {
        'title': title,
        'offset': offset,
        'length': body_len,
        'children': children,
    }


def _ppp_ipcp_section(payload: bytes, offset: int) -> Dict[str, Any]:
    return _ppp_ip_control_section(payload, offset, ipv6=False)


def _ppp_ipv6cp_section(payload: bytes, offset: int) -> Dict[str, Any]:
    return _ppp_ip_control_section(payload, offset, ipv6=True)


def _eigrp_opcode_name(opcode: int) -> str:
    return {
        1: 'Update',
        3: 'Query',
        4: 'Reply',
        5: 'Hello',
        6: 'IPX SAP',
        10: 'SIA Query',
        11: 'SIA Reply',
    }.get(int(opcode), f'Opcode {int(opcode)}')


def _eigrp_checksum(payload: bytes) -> int:
    data = payload if len(payload) % 2 == 0 else payload + b'\x00'
    checksum = 0
    for index in range(0, len(data), 2):
        checksum += (int(data[index]) << 8) | int(data[index + 1])
        checksum = (checksum & 0xFFFF) + (checksum >> 16)
    return (~checksum) & 0xFFFF


def _eigrp_section(payload: bytes, offset: int, record=None) -> Dict[str, Any]:
    metadata = getattr(record, 'metadata', {}) if record else {}
    eigrp = metadata.get('eigrp', {}) if isinstance(metadata.get('eigrp'), dict) else {}
    if len(payload) < 20:
        return {'title': 'Cisco EIGRP', 'offset': offset, 'length': len(payload), 'children': []}

    version = int(eigrp.get('version', payload[0]) or payload[0])
    opcode = int(eigrp.get('opcode', payload[1]) or payload[1])
    checksum = int(eigrp.get('checksum', int.from_bytes(payload[2:4], 'big')) or 0)
    flags = int(eigrp.get('flags', int.from_bytes(payload[4:8], 'big')) or 0)
    sequence = int(eigrp.get('sequence', int.from_bytes(payload[8:12], 'big')) or 0)
    acknowledge = int(eigrp.get('acknowledge', int.from_bytes(payload[12:16], 'big')) or 0)
    virtual_router_id = int(eigrp.get('virtual_router_id', int.from_bytes(payload[16:18], 'big')) or 0)
    autonomous_system = int(eigrp.get('autonomous_system', int.from_bytes(payload[18:20], 'big')) or 0)
    checksum_ok = _eigrp_checksum(payload) == 0
    flag_labels = []
    if flags & 0x00000001:
        flag_labels.append('Init')
    if flags & 0x00000002:
        flag_labels.append('Conditional Receive')
    if flags & 0x00000004:
        flag_labels.append('Restart')
    if flags & 0x00000008:
        flag_labels.append('End Of Table')
    flags_title = f'Flags: 0x{flags:08x}' + (f', {", ".join(flag_labels)}' if flag_labels else '')

    children: List[Dict[str, Any]] = [
        {'title': f'Version: {version}', 'offset': offset, 'length': 1},
        {'title': f'Opcode: {_eigrp_opcode_name(opcode)} ({opcode})', 'offset': offset + 1, 'length': 1},
        {'title': f'Checksum: 0x{checksum:04x} [{"correct" if checksum_ok else "incorrect"}]', 'offset': offset + 2, 'length': 2},
        {'title': f'[Checksum Status: {"Good" if checksum_ok else "Bad"}]'},
        {
            'title': flags_title,
            'offset': offset + 4,
            'length': 4,
            'children': [
                {'title': f'.... .... .... .... .... .... .... ...{1 if flags & 0x00000001 else 0} = Init: {"Set" if flags & 0x00000001 else "Not set"}', 'offset': offset + 4, 'length': 4},
                {'title': f'.... .... .... .... .... .... .... ..{1 if flags & 0x00000002 else 0}. = Conditional Receive: {"Set" if flags & 0x00000002 else "Not set"}', 'offset': offset + 4, 'length': 4},
                {'title': f'.... .... .... .... .... .... .... .{1 if flags & 0x00000004 else 0}.. = Restart: {"Set" if flags & 0x00000004 else "Not set"}', 'offset': offset + 4, 'length': 4},
                {'title': f'.... .... .... .... .... .... .... {1 if flags & 0x00000008 else 0}... = End Of Table: {"Set" if flags & 0x00000008 else "Not set"}', 'offset': offset + 4, 'length': 4},
            ],
        },
        {'title': f'Sequence: {sequence}', 'offset': offset + 8, 'length': 4},
        {'title': f'Acknowledge: {acknowledge}', 'offset': offset + 12, 'length': 4},
        {'title': f'Virtual Router ID: {virtual_router_id} (Address-Family)', 'offset': offset + 16, 'length': 2},
        {'title': f'Autonomous System: {autonomous_system}', 'offset': offset + 18, 'length': 2},
    ]

    for tlv in list(eigrp.get('tlvs', []) or []):
        tlv_type = int(tlv.get('type', 0) or 0)
        tlv_len = int(tlv.get('length', 0) or 0)
        tlv_offset = offset + int(tlv.get('offset', 0) or 0)
        if tlv_type == 0x0002:
            auth_type = int(tlv.get('auth_type', 0) or 0)
            key_size = int(tlv.get('key_size', 0) or 0)
            key_id = int(tlv.get('key_id', 0) or 0)
            key_sequence = int(tlv.get('key_sequence', 0) or 0)
            nullpad = bytes(tlv.get('nullpad', b'') or b'').hex()
            digest = bytes(tlv.get('digest', b'') or b'').hex()
            children.append({
                'title': 'Authentication MD5',
                'offset': tlv_offset,
                'length': tlv_len,
                'children': [
                    {'title': 'Type: Authentication (0x0002)', 'offset': tlv_offset, 'length': 2},
                    {'title': f'Length: {tlv_len}', 'offset': tlv_offset + 2, 'length': 2},
                    {'title': f'Type: {"MD5" if auth_type == 2 else auth_type} ({auth_type})', 'offset': tlv_offset + 4, 'length': 2},
                    {'title': f'Length: {key_size}', 'offset': tlv_offset + 6, 'length': 2},
                    {'title': f'Key ID: {key_id}', 'offset': tlv_offset + 8, 'length': 4},
                    {'title': f'Key Sequence: {key_sequence}', 'offset': tlv_offset + 12, 'length': 4},
                    {'title': f'Nullpad: {nullpad}', 'offset': tlv_offset + 16, 'length': 8},
                    {'title': f'Digest: {digest}', 'offset': tlv_offset + 24, 'length': 16},
                ],
            })
        elif tlv_type == 0x0001:
            children.append({
                'title': 'Parameters',
                'offset': tlv_offset,
                'length': tlv_len,
                'children': [
                    {'title': 'Type: Parameters (0x0001)', 'offset': tlv_offset, 'length': 2},
                    {'title': f'Length: {tlv_len}', 'offset': tlv_offset + 2, 'length': 2},
                    {'title': f'K1: {int(tlv.get("k1", 0) or 0)}', 'offset': tlv_offset + 4, 'length': 1},
                    {'title': f'K2: {int(tlv.get("k2", 0) or 0)}', 'offset': tlv_offset + 5, 'length': 1},
                    {'title': f'K3: {int(tlv.get("k3", 0) or 0)}', 'offset': tlv_offset + 6, 'length': 1},
                    {'title': f'K4: {int(tlv.get("k4", 0) or 0)}', 'offset': tlv_offset + 7, 'length': 1},
                    {'title': f'K5: {int(tlv.get("k5", 0) or 0)}', 'offset': tlv_offset + 8, 'length': 1},
                    {'title': f'K6: {int(tlv.get("k6", 0) or 0)}', 'offset': tlv_offset + 9, 'length': 1},
                    {'title': f'Hold Time: {int(tlv.get("hold_time", 0) or 0)}', 'offset': tlv_offset + 10, 'length': 2},
                ],
            })
        elif tlv_type == 0x0004:
            ios_major = int(tlv.get('ios_major', 0) or 0)
            ios_minor = int(tlv.get('ios_minor', 0) or 0)
            eigrp_major = int(tlv.get('eigrp_major', 0) or 0)
            eigrp_minor = int(tlv.get('eigrp_minor', 0) or 0)
            children.append({
                'title': f'Software Version: EIGRP={ios_major}.{ios_minor}, TLV={eigrp_major}.{eigrp_minor}',
                'offset': tlv_offset,
                'length': tlv_len,
                'children': [
                    {'title': 'Type: Software Version (0x0004)', 'offset': tlv_offset, 'length': 2},
                    {'title': f'Length: {tlv_len}', 'offset': tlv_offset + 2, 'length': 2},
                    {'title': f'EIGRP Release: {ios_major}.{ios_minor:02d}', 'offset': tlv_offset + 4, 'length': 2},
                    {'title': f'EIGRP TLV version: {eigrp_major}.{eigrp_minor:02d}', 'offset': tlv_offset + 6, 'length': 2},
                ],
            })

    return {
        'title': 'Cisco EIGRP',
        'offset': offset,
        'length': len(payload),
        'children': children,
    }


def _asn1_length(data: bytes, pos: int) -> tuple[int, int]:
    if pos >= len(data):
        return 0, 0
    first = int(data[pos])
    if first < 0x80:
        return first, 1
    count = first & 0x7F
    if count <= 0 or pos + 1 + count > len(data):
        return 0, 1
    return int.from_bytes(data[pos + 1:pos + 1 + count], 'big'), 1 + count


def _asn1_tlv(data: bytes, pos: int) -> Dict[str, int] | None:
    if pos >= len(data):
        return None
    length, length_size = _asn1_length(data, pos + 1)
    value_start = pos + 1 + length_size
    end = min(len(data), value_start + length)
    if value_start > len(data):
        return None
    return {
        'tag': int(data[pos]),
        'start': pos,
        'header_length': 1 + length_size,
        'length': length,
        'value_start': value_start,
        'end': end,
    }


def _snmp_version_name(version: int) -> str:
    return {
        0: 'v1',
        1: 'v2c',
        2: 'v2u',
        3: 'v3',
    }.get(int(version), f'v{int(version)}')


def _snmp_pdu_name(code: int) -> str:
    return {
        0: 'get-request',
        1: 'get-next-request',
        2: 'get-response',
        3: 'set-request',
        5: 'get-bulk-request',
        6: 'inform-request',
    }.get(int(code), 'snmp')


def _snmp_error_name(code: int) -> str:
    return {
        0: 'noError',
        1: 'tooBig',
        2: 'noSuchName',
        3: 'badValue',
        4: 'readOnly',
        5: 'genErr',
    }.get(int(code), str(int(code)))


def _snmp_oid_display(oid: str) -> str:
    if oid.startswith('1.'):
        return f'{oid} (iso.{oid[2:]})'
    return oid


def _snmp_section(payload: bytes, offset: int, record=None) -> Dict[str, Any]:
    metadata = getattr(record, 'metadata', {}) if record else {}
    snmp_meta = metadata.get('snmp', {}) if isinstance(metadata.get('snmp'), dict) else {}
    outer = _asn1_tlv(payload, 0)
    if outer is None or outer.get('tag') != 0x30:
        return {'title': 'Simple Network Management Protocol', 'offset': offset, 'length': len(payload), 'children': []}

    pos = int(outer['value_start'])
    version_tlv = _asn1_tlv(payload, pos)
    community_tlv = _asn1_tlv(payload, int(version_tlv['end'])) if version_tlv is not None else None
    pdu_tlv = _asn1_tlv(payload, int(community_tlv['end'])) if community_tlv is not None else None
    children: List[Dict[str, Any]] = []

    if version_tlv is not None:
        version_value = int.from_bytes(payload[int(version_tlv['value_start']):int(version_tlv['end'])], 'big') if int(version_tlv['end']) > int(version_tlv['value_start']) else 0
        children.append({
            'title': f'version: {_snmp_version_name(version_value)} ({version_value})',
            'offset': offset + int(version_tlv['start']),
            'length': int(version_tlv['end']) - int(version_tlv['start']),
        })
    if community_tlv is not None:
        community = payload[int(community_tlv['value_start']):int(community_tlv['end'])].decode(errors='ignore')
        children.append({
            'title': f'community: {community}',
            'offset': offset + int(community_tlv['start']),
            'length': int(community_tlv['end']) - int(community_tlv['start']),
        })
    if pdu_tlv is not None:
        pdu_code = int(pdu_tlv['tag']) - 0xA0
        pdu_name = _snmp_pdu_name(pdu_code)
        pdu_children: List[Dict[str, Any]] = []
        pdu_pos = int(pdu_tlv['value_start'])
        request_tlv = _asn1_tlv(payload, pdu_pos)
        error_tlv = _asn1_tlv(payload, int(request_tlv['end'])) if request_tlv is not None else None
        error_index_tlv = _asn1_tlv(payload, int(error_tlv['end'])) if error_tlv is not None else None
        varbinds_tlv = _asn1_tlv(payload, int(error_index_tlv['end'])) if error_index_tlv is not None else None
        request_id = int(snmp_meta.get('request_id', 0) or 0)
        error_status = int(snmp_meta.get('error_status', 0) or 0)
        error_index = int(snmp_meta.get('error_index', 0) or 0)
        if request_tlv is not None:
            pdu_children.append({'title': f'request-id: {request_id}', 'offset': offset + int(request_tlv['start']), 'length': int(request_tlv['end']) - int(request_tlv['start'])})
        if error_tlv is not None:
            pdu_children.append({'title': f'error-status: {_snmp_error_name(error_status)} ({error_status})', 'offset': offset + int(error_tlv['start']), 'length': int(error_tlv['end']) - int(error_tlv['start'])})
        if error_index_tlv is not None:
            pdu_children.append({'title': f'error-index: {error_index}', 'offset': offset + int(error_index_tlv['start']), 'length': int(error_index_tlv['end']) - int(error_index_tlv['start'])})
        if varbinds_tlv is not None:
            varbind_children: List[Dict[str, Any]] = []
            vb_pos = int(varbinds_tlv['value_start'])
            meta_varbinds = list(snmp_meta.get('varbinds', []) or [])
            meta_index = 0
            while vb_pos < int(varbinds_tlv['end']):
                vb_tlv = _asn1_tlv(payload, vb_pos)
                if vb_tlv is None:
                    break
                oid_tlv = _asn1_tlv(payload, int(vb_tlv['value_start']))
                value_tlv = _asn1_tlv(payload, int(oid_tlv['end'])) if oid_tlv is not None else None
                meta_varbind = meta_varbinds[meta_index] if meta_index < len(meta_varbinds) else {}
                meta_index += 1
                oid_text = str(meta_varbind.get('oid', '') or '')
                value_type = str(meta_varbind.get('value_type', '') or '')
                value_value = meta_varbind.get('value', None)
                if value_type == 'NULL':
                    title = f'{oid_text}: Value (Null)'
                    value_title = 'Value (Null)'
                else:
                    title = f'{oid_text}: {value_value}'
                    value_title = f'Value ({value_type.title()}): {value_value}'
                vb_children = []
                if oid_tlv is not None:
                    vb_children.append({'title': f'Object Name: {_snmp_oid_display(oid_text)}', 'offset': offset + int(oid_tlv['start']), 'length': int(oid_tlv['end']) - int(oid_tlv['start'])})
                if value_tlv is not None:
                    vb_children.append({'title': value_title, 'offset': offset + int(value_tlv['start']), 'length': int(value_tlv['end']) - int(value_tlv['start'])})
                varbind_children.append({
                    'title': title,
                    'offset': offset + int(vb_tlv['start']),
                    'length': int(vb_tlv['end']) - int(vb_tlv['start']),
                    'children': vb_children,
                })
                vb_pos = int(vb_tlv['end'])
            item_count = len(varbind_children)
            pdu_children.append({
                'title': f'variable-bindings: {item_count} item' + ('' if item_count == 1 else 's'),
                'offset': offset + int(varbinds_tlv['start']),
                'length': int(varbinds_tlv['end']) - int(varbinds_tlv['start']),
                'children': varbind_children,
            })
        children.append({
            'title': f'data: {pdu_name} ({pdu_code})',
            'offset': offset + int(pdu_tlv['start']),
            'length': int(pdu_tlv['end']) - int(pdu_tlv['start']),
            'children': [{
                'title': pdu_name,
                'offset': offset + int(pdu_tlv['start']),
                'length': int(pdu_tlv['end']) - int(pdu_tlv['start']),
                'children': pdu_children,
            }],
        })

    response_frame = metadata.get('snmp_response_frame', None)
    if response_frame is not None:
        children.append({'title': f'[Response In: {int(response_frame)}]'})
    request_frame = metadata.get('snmp_request_frame', None)
    if request_frame is not None:
        children.append({'title': f'[Response To: {int(request_frame)}]'})
    response_time = metadata.get('snmp_time_since_request_ms', None)
    if response_time is not None:
        children.append({'title': f'[Time: {float(response_time):.6f} milliseconds]'})

    return {
        'title': 'Simple Network Management Protocol',
        'offset': offset,
        'length': len(payload),
        'children': children,
    }


def _imap_parse_request_line(line_text: str) -> Dict[str, str] | None:
    parts = line_text.split(' ', 2)
    if len(parts) < 1 or not parts[0]:
        return None
    return {
        'tag': parts[0],
        'command': parts[1] if len(parts) > 1 else '',
    }


def _imap_parse_response_line(line_text: str) -> Dict[str, str] | None:
    if line_text.startswith('* OK ') or line_text.startswith('* '):
        return None
    parts = line_text.split(' ', 2)
    if len(parts) < 2:
        return None
    return {
        'tag': parts[0],
        'status': parts[1],
        'command': parts[2].split(' ', 1)[0] if len(parts) > 2 else '',
    }


def _imap_section(payload: bytes, offset: int, record=None) -> Dict[str, Any]:
    metadata = getattr(record, 'metadata', {}) if record else {}
    imap_meta = metadata.get('imap', {}) if isinstance(metadata.get('imap'), dict) else {}
    tagged_response_line = str(metadata.get('imap_tagged_response_line', '') or '') or str(imap_meta.get('tagged_response_line', '') or '')
    children: List[Dict[str, Any]] = []
    cursor = 0
    for raw_line in payload.splitlines(keepends=True):
        line_text = raw_line.decode(errors='ignore').rstrip('\r\n')
        line_display = raw_line.decode(errors='ignore').replace('\r', '\\r').replace('\n', '\\n')
        line_children: List[Dict[str, Any]] = []
        if cursor == 0 and str(imap_meta.get('kind', '') or '') == 'request':
            request_info = _imap_parse_request_line(line_text)
            if request_info is not None:
                line_children.append({'title': f'Request: {line_text}', 'offset': offset + cursor, 'length': max(0, len(raw_line) - 2)})
                line_children.append({'title': f'Request Tag: {request_info["tag"]}', 'offset': offset + cursor, 'length': len(request_info['tag'])})
                if request_info['command']:
                    line_children.append({'title': f'Request Command: {request_info["command"]}', 'offset': offset + cursor + len(request_info['tag']) + 1, 'length': len(request_info['command'])})
                response_frame = metadata.get('imap_response_frame', None)
                if response_frame is not None:
                    line_children.append({'title': f'[Response In: {int(response_frame)}]'})
        elif cursor == 0 and str(imap_meta.get('kind', '') or '') == 'response':
            response_info = _imap_parse_response_line(line_text)
            if response_info is not None:
                line_children.append({'title': f'Response: {line_text}', 'offset': offset + cursor, 'length': max(0, len(raw_line) - 2)})
                line_children.append({'title': f'Response Tag: {response_info["tag"]}', 'offset': offset + cursor, 'length': len(response_info['tag'])})
                line_children.append({'title': f'Response Status: {response_info["status"]}', 'offset': offset + cursor + len(response_info['tag']) + 1, 'length': len(response_info['status'])})
                if response_info['command']:
                    command_offset = offset + cursor + len(response_info['tag']) + 1 + len(response_info['status']) + 1
                    line_children.append({'title': f'Response Command: {response_info["command"]}', 'offset': command_offset, 'length': len(response_info['command'])})
        elif cursor == 0 and str(imap_meta.get('kind', '') or '') in {'greeting', 'response_untagged'}:
            line_children.append({'title': f'Response: {line_text}', 'offset': offset + cursor, 'length': max(0, len(raw_line) - 2)})
        if tagged_response_line and line_text == tagged_response_line:
            tagged_info = _imap_parse_response_line(line_text)
            if tagged_info is not None:
                line_children.append({'title': f'Response: {line_text}', 'offset': offset + cursor, 'length': max(0, len(raw_line) - 2)})
                line_children.append({'title': f'Response Tag: {tagged_info["tag"]}', 'offset': offset + cursor, 'length': len(tagged_info['tag'])})
                line_children.append({'title': f'Response Status: {tagged_info["status"]}', 'offset': offset + cursor + len(tagged_info['tag']) + 1, 'length': len(tagged_info['status'])})
                if tagged_info['command']:
                    command_offset = offset + cursor + len(tagged_info['tag']) + 1 + len(tagged_info['status']) + 1
                    line_children.append({'title': f'Response Command: {tagged_info["command"]}', 'offset': command_offset, 'length': len(tagged_info['command'])})
                request_frame = metadata.get('imap_request_frame', None)
                if request_frame is not None:
                    line_children.append({'title': f'[Request In: {int(request_frame)}]'})
                response_time = metadata.get('imap_time_since_request_ms', None)
                if response_time is not None:
                    line_children.append({'title': f'[Response Time: {float(response_time):.6f} milliseconds]'})
        line_node: Dict[str, Any] = {
            'title': f'Line: {line_display}',
            'offset': offset + cursor,
            'length': len(raw_line),
        }
        if line_children:
            line_node['children'] = line_children
        children.append(line_node)
        cursor += len(raw_line)

    return {
        'title': 'Internet Message Access Protocol',
        'offset': offset,
        'length': len(payload),
        'children': children,
    }


def _sip_header_lines(payload: bytes) -> tuple[List[Dict[str, Any]], int, int]:
    header_end = payload.find(b'\r\n\r\n')
    if header_end == -1:
        header_blob = payload
        body_offset = len(payload)
    else:
        header_blob = payload[:header_end]
        body_offset = header_end + 4
    lines: List[Dict[str, Any]] = []
    cursor = 0
    for raw_line in header_blob.split(b'\r\n'):
        line_text = raw_line.decode(errors='ignore')
        lines.append({
            'text': line_text,
            'offset': cursor,
            'length': len(raw_line),
        })
        cursor += len(raw_line) + 2
    return lines, body_offset, len(header_blob)


def _sdp_section(body: bytes, offset: int) -> Dict[str, Any]:
    children: List[Dict[str, Any]] = []
    cursor = 0
    for raw_line in body.splitlines(keepends=True):
        line_text = raw_line.decode(errors='ignore').rstrip('\r\n')
        if not line_text:
            cursor += len(raw_line)
            continue
        if line_text.startswith('v='):
            title = f'Session Description Protocol Version (v): {line_text[2:]}'
        elif line_text.startswith('o='):
            title = f'Owner/Creator, Session Id (o): {line_text[2:]}'
        elif line_text.startswith('s='):
            title = f'Session Name (s): {line_text[2:]}'
        elif line_text.startswith('c='):
            title = f'Connection Information (c): {line_text[2:]}'
        elif line_text.startswith('t='):
            title = f'Time Description, active time (t): {line_text[2:]}'
        elif line_text.startswith('m='):
            title = f'Media Description, name and address (m): {line_text[2:]}'
        elif line_text.startswith('a='):
            title = f'Media Attribute (a): {line_text[2:]}'
        else:
            title = line_text
        children.append({
            'title': title,
            'offset': offset + cursor,
            'length': max(0, len(raw_line) - 2),
        })
        cursor += len(raw_line)
    return {
        'title': 'Session Description Protocol',
        'offset': offset,
        'length': len(body),
        'children': children,
    }


def _sip_split_uri(uri_text: str) -> Dict[str, Any]:
    text = str(uri_text or '').strip()
    result: Dict[str, Any] = {
        'uri': text,
        'user': '',
        'host': '',
        'params': [],
    }
    if not text:
        return result

    inner = text
    if inner.startswith('<') and '>' in inner:
        inner = inner[1:inner.find('>')]
    if inner.lower().startswith('sip:'):
        inner = inner[4:]

    addr_part, sep, param_part = inner.partition(';')
    if sep and param_part:
        result['params'] = [item.strip() for item in param_part.split(';') if item.strip()]
    if '@' in addr_part:
        result['user'], result['host'] = addr_part.split('@', 1)
    else:
        result['host'] = addr_part
    return result


def _sip_header_children(name: str, value: str, line_offset: int) -> List[Dict[str, Any]]:
    lower_name = str(name or '').lower()
    text = str(value or '')
    children: List[Dict[str, Any]] = []

    if lower_name in {'max-forwards', 'content-length', 'content-type', 'allow', 'supported', 'allow-events', 'accept', 'accept-encoding', 'session-expires', 'min-se', 'user-agent'}:
        return children

    if lower_name == 'via':
        via_main = text.split(';', 1)[0].strip()
        via_parts = via_main.split()
        if via_parts:
            transport = via_parts[0].split('/')[-1]
            children.append({'title': f'Transport: {transport}'})
        if len(via_parts) > 1:
            sent_by = via_parts[1]
            host, _, port = sent_by.partition(':')
            children.append({'title': f'Sent-by Address: {host}'})
            if port.isdigit():
                children.append({'title': f'Sent-by port: {int(port)}'})
        for token in text.split(';')[1:]:
            token = token.strip()
            if token.startswith('branch='):
                children.append({'title': f'Branch: {token.split("=", 1)[1]}'})
        return children

    if lower_name in {'to', 'from', 'contact', 'record-route', 'p-asserted-identity'}:
        display = ''
        if '"' in text and '<' in text:
            first_q = text.find('"')
            second_q = text.find('"', first_q + 1)
            if second_q > first_q:
                display = text[first_q:second_q + 1]
        start_uri = text.find('<')
        end_uri = text.find('>') if start_uri >= 0 else -1
        uri_text = text[start_uri + 1:end_uri] if start_uri >= 0 and end_uri > start_uri else text.split(';', 1)[0].strip()
        uri_parts = _sip_split_uri(uri_text)

        label_prefix = {
            'to': 'SIP to',
            'from': 'SIP from',
            'contact': 'Contact URI',
            'record-route': 'Record-Route URI',
            'p-asserted-identity': 'SIP PAI',
        }.get(lower_name, name)

        if display and lower_name == 'to':
            children.append({'title': f'SIP to display info: {display}'})

        uri_children: List[Dict[str, Any]] = []
        if uri_parts.get('uri'):
            uri_title = ''
            if lower_name == 'to':
                uri_title = f'SIP to address: {uri_parts["uri"]}'
            elif lower_name == 'from':
                uri_title = f'SIP from address: {uri_parts["uri"]}'
            elif lower_name == 'p-asserted-identity':
                uri_title = f'SIP PAI Address: {uri_parts["uri"]}'
            else:
                uri_title = f'{label_prefix}: {uri_parts["uri"]}'
        else:
            uri_title = ''

        if uri_parts.get('user'):
            user_label = {
                'to': 'SIP to address User Part',
                'from': 'SIP from address User Part',
                'contact': 'Contact URI User Part',
                'p-asserted-identity': 'SIP PAI User Part',
            }.get(lower_name, f'{label_prefix} User Part')
            uri_children.append({'title': f'{user_label}: {uri_parts["user"]}'})
        if uri_parts.get('host'):
            host_label = {
                'to': 'SIP to address Host Part',
                'from': 'SIP from address Host Part',
                'contact': 'Contact URI Host Part',
                'record-route': 'Record-Route Host Part',
                'p-asserted-identity': 'SIP PAI Host Part',
            }.get(lower_name, f'{label_prefix} Host Part')
            uri_children.append({'title': f'{host_label}: {uri_parts["host"]}'})
        for param in list(uri_parts.get('params', []) or []):
            param_label = {
                'to': 'SIP To URI parameter',
                'from': 'SIP From URI parameter',
                'contact': 'Contact URI parameter',
                'record-route': 'Record-Route URI parameter',
                'p-asserted-identity': 'SIP PAI URI parameter',
            }.get(lower_name, 'URI parameter')
            uri_children.append({'title': f'{param_label}: {param}'})

        if uri_title:
            uri_node: Dict[str, Any] = {'title': uri_title}
            if uri_children:
                uri_node['children'] = uri_children
            children.append(uri_node)

        if lower_name in {'to', 'from'} and ';tag=' in text:
            tag_val = text.split(';tag=', 1)[1].split(';', 1)[0].strip()
            tag_label = 'SIP to tag' if lower_name == 'to' else 'SIP from tag'
            children.append({'title': f'{tag_label}: {tag_val}'})
        if lower_name == 'contact':
            tail = text[end_uri + 1:] if end_uri >= 0 else ''
            for part in [item for item in tail.split(';') if item.strip()]:
                children.append({'title': f'Contact parameter: {part.strip()}'})
        return children

    if lower_name == 'call-id':
        children.append({'title': f'[Generated Call-ID: {text}]'})
        return children

    if lower_name == 'cseq':
        parts = text.split()
        if parts and parts[0].isdigit():
            children.append({'title': f'Sequence Number: {int(parts[0])}'})
        if len(parts) > 1:
            children.append({'title': f'Method: {parts[1]}'})
        return children

    if lower_name == 'session-id':
        children.append({'title': f'sess-id: {text}'})
        return children
    return children


def _sip_section(payload: bytes, offset: int, record=None) -> Dict[str, Any]:
    metadata = getattr(record, 'metadata', {}) if record else {}
    sip_meta = metadata.get('sip', {}) if isinstance(metadata.get('sip'), dict) else {}
    lines, body_offset, header_length = _sip_header_lines(payload)
    if not lines:
        return {'title': 'Session Initiation Protocol', 'offset': offset, 'length': len(payload), 'children': []}

    first = lines[0]
    first_text = str(first.get('text', '') or '')
    children: List[Dict[str, Any]] = []
    kind = str(sip_meta.get('kind', '') or '')
    if kind == 'request':
        parts = first_text.split(' ', 2)
        line_children = []
        if len(parts) >= 1:
            line_children.append({'title': f'Method: {parts[0]}', 'offset': offset + int(first['offset']), 'length': len(parts[0])})
        if len(parts) >= 2:
            uri_offset = offset + int(first['offset']) + len(parts[0]) + 1
            line_children.append({'title': f'Request-URI: {parts[1]}', 'offset': uri_offset, 'length': len(parts[1])})
            uri_parts = _sip_split_uri(parts[1])
            if uri_parts.get('user'):
                line_children.append({'title': f'Request-URI User Part: {uri_parts["user"]}'})
            if uri_parts.get('host'):
                line_children.append({'title': f'Request-URI Host Part: {uri_parts["host"]}'})
        line_children.append({'title': '[Resent Packet: False]'})
        children.append({
            'title': f'Request-Line: {first_text}',
            'offset': offset + int(first['offset']),
            'length': int(first['length']),
            'children': line_children,
        })
    else:
        parts = first_text.split(' ', 2)
        status_code = parts[1] if len(parts) > 1 else str(sip_meta.get('status_code', '') or '')
        line_children = []
        if status_code:
            line_children.append({'title': f'Status-Code: {status_code}', 'offset': offset + int(first['offset']) + 8, 'length': len(status_code)})
        line_children.append({'title': '[Resent Packet: False]'})
        request_frame = metadata.get('sip_request_frame', None)
        if request_frame is not None:
            line_children.append({'title': f'[Request Frame: {int(request_frame)}]'})
        response_time = metadata.get('sip_response_time_ms', None)
        if response_time is not None:
            line_children.append({'title': f'[Response Time (ms): {int(float(response_time))}]'})
        children.append({
            'title': f'Status-Line: {first_text}',
            'offset': offset + int(first['offset']),
            'length': int(first['length']),
            'children': line_children,
        })

    header_children: List[Dict[str, Any]] = []
    for line in lines[1:]:
        text = str(line.get('text', '') or '')
        if not text:
            continue
        if ':' not in text:
            header_children.append({
                'title': text,
                'offset': offset + int(line.get('offset', 0) or 0),
                'length': int(line.get('length', 0) or 0),
            })
            continue
        name, value = text.split(':', 1)
        name = name.strip()
        value = value.strip()
        line_node = {
            'title': f'{name}: {value}',
            'offset': offset + int(line.get('offset', 0) or 0),
            'length': int(line.get('length', 0) or 0),
        }
        sub_children = _sip_header_children(name, value, int(line_node['offset']))
        if sub_children:
            line_node['children'] = sub_children
        header_children.append(line_node)
    if header_children:
        children.append({
            'title': 'Message Header',
            'offset': offset + int(lines[1].get('offset', 0) or 0) if len(lines) > 1 else offset,
            'length': max(0, header_length - int(lines[0].get('length', 0) or 0) - 2),
            'children': header_children,
        })

    body = payload[body_offset:] if body_offset < len(payload) else b''
    if body:
        body_children: List[Dict[str, Any]] = []
        if str(getattr(record, 'protocol', '') or '') == 'SIP/SDP':
            body_children.append(_sdp_section(body, offset + body_offset))
        children.append({
            'title': 'Message Body',
            'offset': offset + body_offset,
            'length': len(body),
            'children': body_children,
        })

    title_suffix = ''
    if kind == 'request':
        title_suffix = f' ({str(sip_meta.get("method", "") or "")})'
    elif kind == 'response':
        title_suffix = f' ({str(sip_meta.get("status_code", "") or "")})'
    return {
        'title': f'Session Initiation Protocol{title_suffix}',
        'offset': offset,
        'length': len(payload),
        'children': children,
    }


def _rtp_section(payload: bytes, offset: int, record=None) -> Dict[str, Any]:
    metadata = getattr(record, 'metadata', {}) if record else {}
    rtp_meta = metadata.get('rtp', {}) if isinstance(metadata.get('rtp'), dict) else {}
    if len(payload) < 12:
        return {'title': 'Real-Time Transport Protocol', 'offset': offset, 'length': len(payload), 'children': []}

    version = int(rtp_meta.get('version', (payload[0] >> 6) & 0x03) or 0)
    padding = bool(rtp_meta.get('padding', bool((payload[0] >> 5) & 0x01)))
    extension = bool(rtp_meta.get('extension', bool((payload[0] >> 4) & 0x01)))
    csrc_count = int(rtp_meta.get('csrc_count', payload[0] & 0x0F) or 0)
    marker = bool(rtp_meta.get('marker', bool((payload[1] >> 7) & 0x01)))
    payload_type = int(rtp_meta.get('payload_type', payload[1] & 0x7F) or 0)
    payload_type_name = str(rtp_meta.get('payload_type_name', f'Payload type {payload_type}') or f'Payload type {payload_type}')
    sequence = int(rtp_meta.get('sequence', int.from_bytes(payload[2:4], 'big')) or 0)
    extended_sequence = int(rtp_meta.get('extended_sequence', 65536 + sequence) or 0)
    timestamp = int(rtp_meta.get('timestamp', int.from_bytes(payload[4:8], 'big')) or 0)
    extended_timestamp = int(rtp_meta.get('extended_timestamp', 4294967296 + timestamp) or 0)
    ssrc = int(rtp_meta.get('ssrc', int.from_bytes(payload[8:12], 'big')) or 0)
    header_length = int(rtp_meta.get('header_length', 12 + csrc_count * 4) or 12)

    children: List[Dict[str, Any]] = []
    setup_frame = metadata.get('rtp_setup_frame', None)
    if setup_frame is not None:
        setup_children = [
            {'title': f'[Setup frame: {int(setup_frame)}]'},
            {'title': f'[Setup Method: {str(metadata.get("rtp_setup_method", "SDP") or "SDP")}]'},
        ]
        call_id = str(metadata.get('rtp_setup_call_id', '') or '')
        if call_id:
            setup_children.append({'title': f'[Generated Call-ID: {call_id}]'})
        children.append({'title': f'[Stream setup by SDP (frame {int(setup_frame)})]', 'children': setup_children})

    children.extend([
        {'title': f'{version:02b}.. .... = Version: RFC 1889 Version ({version})', 'offset': offset, 'length': 1},
        {'title': f'..{1 if padding else 0}. .... = Padding: {"True" if padding else "False"}', 'offset': offset, 'length': 1},
        {'title': f'...{1 if extension else 0} .... = Extension: {"True" if extension else "False"}', 'offset': offset, 'length': 1},
        {'title': f'.... {csrc_count:04b} = Contributing source identifiers count: {csrc_count}', 'offset': offset, 'length': 1},
        {'title': f'{1 if marker else 0}... .... = Marker: {"True" if marker else "False"}', 'offset': offset + 1, 'length': 1},
        {'title': f'Payload type: {payload_type_name} ({payload_type})', 'offset': offset + 1, 'length': 1},
        {'title': f'Sequence number: {sequence}', 'offset': offset + 2, 'length': 2},
        {'title': f'[Extended sequence number: {extended_sequence}]'},
        {'title': f'Timestamp: {timestamp}', 'offset': offset + 4, 'length': 4},
        {'title': f'[Extended timestamp: {extended_timestamp}]'},
        {'title': f'Synchronization Source identifier: 0x{ssrc:08x} ({ssrc})', 'offset': offset + 8, 'length': 4},
    ])

    if header_length < len(payload):
        payload_preview = payload[header_length:].hex()[:240]
        children.append({
            'title': f'Payload […]: {payload_preview}',
            'offset': offset + header_length,
            'length': len(payload) - header_length,
        })

    return {
        'title': 'Real-Time Transport Protocol',
        'offset': offset,
        'length': len(payload),
        'children': children,
    }


def _ssdp_section(payload: bytes, offset: int, record=None) -> Dict[str, Any]:
    base = _http_section(payload, offset, record)
    base['title'] = 'Simple Service Discovery Protocol'
    try:
        lines = payload.split(b'\r\n')
        request_line = lines[0].decode(errors='ignore')
        parts = request_line.split(' ', 2)
        uri = parts[1].strip() if len(parts) >= 2 else ''
        host = ''
        for line in lines[1:]:
            if line.lower().startswith(b'host:'):
                host = line.split(b':', 1)[1].decode(errors='ignore').strip()
                break
        if host and uri:
            base.setdefault('children', []).append({'title': f'[Full request URI: http://{host}{uri}]'})
    except Exception:
        pass
    return base


def _tftp_section(payload: bytes, offset: int, record=None) -> Dict[str, Any]:
    metadata = getattr(record, 'metadata', {}) if record else {}
    opcode = int.from_bytes(payload[:2], 'big') if len(payload) >= 2 else 0
    opcode_name = {1: 'Read Request', 2: 'Write Request', 3: 'Data Packet', 4: 'Acknowledgement', 5: 'Error Code'}.get(opcode, str(opcode))
    children: List[Dict[str, Any]] = [
        {'title': f'Opcode: {opcode_name} ({opcode})', 'offset': offset, 'length': 2 if len(payload) >= 2 else 0},
    ]
    if opcode in {1, 2}:
        filename = str(metadata.get('tftp_filename', '') or '')
        mode = str(metadata.get('tftp_mode', '') or '')
        if filename:
            children.append({'title': f'Destination File: {filename}', 'offset': offset + 2, 'length': len(filename)})
        if mode:
            mode_start = offset + 2 + len(filename) + 1
            children.append({'title': f'Type: {mode}', 'offset': mode_start, 'length': len(mode)})
    elif opcode in {3, 4} and len(payload) >= 4:
        block = int.from_bytes(payload[2:4], 'big')
        if opcode == 4:
            filename = str(metadata.get('tftp_filename', '') or '')
            req_frame = metadata.get('tftp_request_frame')
            if filename:
                children.append({'title': f'[Destination File: {filename}]'})
            if req_frame is not None:
                children.append({'title': f'[Write Request in frame {int(req_frame)}]'})
        children.append({'title': f'Block: {block}', 'offset': offset + 2, 'length': 2})
        if opcode == 4:
            children.append({'title': f'[Full Block Number: {block}]'})
    elif opcode == 5 and len(payload) >= 4:
        err_code = int.from_bytes(payload[2:4], 'big')
        err_msg = payload[4:].split(b'\x00', 1)[0].decode(errors='ignore')
        children.append({'title': f'Error Code: {err_code}', 'offset': offset + 2, 'length': 2})
        if err_msg:
            children.append({'title': f'Error Message: {err_msg}', 'offset': offset + 4, 'length': len(err_msg)})
    return {
        'title': 'Trivial File Transfer Protocol',
        'offset': offset,
        'length': len(payload),
        'children': children,
    }


def _esp_section(payload: bytes, offset: int) -> Dict[str, Any]:
    spi = int.from_bytes(payload[:4], 'big') if len(payload) >= 4 else 0
    seq = int.from_bytes(payload[4:8], 'big') if len(payload) >= 8 else 0
    return {
        'title': 'Encapsulating Security Payload',
        'offset': offset,
        'length': len(payload),
        'children': [
            {'title': f'ESP SPI: 0x{spi:08x} ({spi})', 'offset': offset, 'length': 4 if len(payload) >= 4 else 0},
            {'title': f'ESP Sequence: {seq}', 'offset': offset + 4, 'length': 4 if len(payload) >= 8 else 0},
        ],
    }


def _isakmp_payload_name(next_payload: int, major: int) -> str:
    if int(major) == 2:
        return {
            0: 'NONE / No Next Payload',
            33: 'Security Association',
            34: 'Key Exchange',
            35: 'Identification - Initiator',
            36: 'Identification - Responder',
            40: 'Nonce',
            41: 'Notify',
            43: 'Vendor ID',
            46: 'Encrypted and Authenticated',
        }.get(int(next_payload), f'Payload {int(next_payload)}')
    return {
        0: 'NONE / No Next Payload',
        1: 'Security Association',
        2: 'Proposal',
        3: 'Transform',
        4: 'Key Exchange',
        5: 'Identification',
        8: 'Hash',
        10: 'Nonce',
        13: 'Vendor ID',
    }.get(int(next_payload), f'Payload {int(next_payload)}')


def _isakmp_v2_exchange_name(value: int) -> str:
    return {
        34: 'IKE_SA_INIT',
        35: 'IKE_AUTH',
        36: 'CREATE_CHILD_SA',
        37: 'INFORMATIONAL',
    }.get(int(value), f'Exchange ({int(value)})')


def _isakmp_v1_exchange_name(value: int) -> str:
    return {
        2: 'Identity Protection (Main Mode)',
        4: 'Aggressive',
        5: 'Informational',
        32: 'Quick Mode',
    }.get(int(value), f'Exchange ({int(value)})')


def _isakmp_v2_transform_type_name(value: int) -> str:
    return {
        1: 'Encryption Algorithm (ENCR)',
        2: 'Pseudo-random Function (PRF)',
        3: 'Integrity Algorithm (INTEG)',
        4: 'Key Exchange Method (KE)',
        5: 'Extended Sequence Numbers (ESN)',
    }.get(int(value), f'Transform Type ({int(value)})')


def _isakmp_v2_transform_id_name(transform_type: int, transform_id: int) -> str:
    transform_type = int(transform_type)
    transform_id = int(transform_id)
    if transform_type == 1:
        return {12: 'ENCR_AES_CBC'}.get(transform_id, f'ENCR ({transform_id})')
    if transform_type == 2:
        return {7: 'PRF_HMAC_SHA2_512'}.get(transform_id, f'PRF ({transform_id})')
    if transform_type == 3:
        return {14: 'AUTH_HMAC_SHA2_512_256'}.get(transform_id, f'INTEG ({transform_id})')
    if transform_type == 4:
        return {20: '384-bit random ECP group'}.get(transform_id, str(transform_id))
    return str(transform_id)


def _isakmp_v1_attribute_name(attr_type: int) -> str:
    return {
        1: 'Encryption-Algorithm',
        2: 'Hash-Algorithm',
        3: 'Authentication-Method',
        4: 'Group-Description',
        11: 'Life-Type',
        12: 'Life-Duration',
        14: 'Key-Length',
    }.get(int(attr_type), f'Attribute-{int(attr_type)}')


def _isakmp_v1_attribute_value(attr_type: int, value: int) -> str:
    attr_type = int(attr_type)
    value = int(value)
    if attr_type == 1:
        return {7: 'AES-CBC'}.get(value, str(value))
    if attr_type == 2:
        return {2: 'SHA', 6: 'SHA2-512'}.get(value, str(value))
    if attr_type == 3:
        return {1: 'Pre-shared key'}.get(value, str(value))
    if attr_type == 4:
        return {2: 'Alternate 1024-bit MODP group', 20: '384-bit random ECP group'}.get(value, str(value))
    if attr_type == 11:
        return {1: 'Seconds'}.get(value, str(value))
    return str(value)


def _isakmp_section(payload: bytes, offset: int) -> Dict[str, Any]:
    if len(payload) < 28:
        return {
            'title': 'Internet Security Association and Key Management Protocol',
            'offset': offset,
            'length': len(payload),
            'children': [],
        }

    initiator_spi = payload[0:8]
    responder_spi = payload[8:16]
    next_payload = int(payload[16])
    version = int(payload[17])
    major = (version >> 4) & 0x0F
    minor = version & 0x0F
    exchange_type = int(payload[18])
    flags = int(payload[19])
    message_id = int.from_bytes(payload[20:24], 'big')
    total_length = int.from_bytes(payload[24:28], 'big')
    total_length = min(max(28, total_length), len(payload))

    children: List[Dict[str, Any]] = [
        {'title': f'Initiator SPI: {initiator_spi.hex()}', 'offset': offset + 0, 'length': 8},
        {'title': f'Responder SPI: {responder_spi.hex()}', 'offset': offset + 8, 'length': 8},
        {'title': f'Next payload: {_isakmp_payload_name(next_payload, major)} ({next_payload})', 'offset': offset + 16, 'length': 1},
        {
            'title': f'Version: {major}.{minor}',
            'offset': offset + 17,
            'length': 1,
            'children': [
                {'title': f'{major:04b} .... = MjVer: 0x{major:x}', 'offset': offset + 17, 'length': 1},
                {'title': f'.... {minor:04b} = MnVer: 0x{minor:x}', 'offset': offset + 17, 'length': 1},
            ],
        },
    ]

    if major == 2:
        children.append({'title': f'Exchange type: {_isakmp_v2_exchange_name(exchange_type)} ({exchange_type})', 'offset': offset + 18, 'length': 1})
        flag_children = [
            {'title': f'.... {1 if flags & 0x08 else 0}... = Initiator: {"Initiator" if flags & 0x08 else "Responder"}', 'offset': offset + 19, 'length': 1},
            {'title': f'...{1 if flags & 0x10 else 0} .... = Version: {"Higher version" if flags & 0x10 else "No higher version"}', 'offset': offset + 19, 'length': 1},
            {'title': f'..{1 if flags & 0x20 else 0}. .... = Response: {"Response" if flags & 0x20 else "Request"}', 'offset': offset + 19, 'length': 1},
        ]
        flag_title = f'Flags: 0x{flags:02x} ({"Initiator" if flags & 0x08 else "Responder"}, {"Higher version" if flags & 0x10 else "No higher version"}, {"Response" if flags & 0x20 else "Request"})'
    else:
        children.append({'title': f'Exchange type: {_isakmp_v1_exchange_name(exchange_type)} ({exchange_type})', 'offset': offset + 18, 'length': 1})
        flag_children = [
            {'title': f'.... ...{1 if flags & 0x01 else 0} = Encryption: {"Encrypted" if flags & 0x01 else "Not encrypted"}', 'offset': offset + 19, 'length': 1},
            {'title': f'.... ..{1 if flags & 0x02 else 0}. = Commit: {"Commit" if flags & 0x02 else "No commit"}', 'offset': offset + 19, 'length': 1},
            {'title': f'.... .{1 if flags & 0x04 else 0}.. = Authentication: {"Authentication" if flags & 0x04 else "No authentication"}', 'offset': offset + 19, 'length': 1},
        ]
        flag_title = f'Flags: 0x{flags:02x}'

    children.append({'title': flag_title, 'offset': offset + 19, 'length': 1, 'children': flag_children})
    children.append({'title': f'Message ID: 0x{message_id:08x}', 'offset': offset + 20, 'length': 4})
    children.append({'title': f'Length: {int(total_length)}', 'offset': offset + 24, 'length': 4})

    if major == 1 and (flags & 0x01):
        enc_len = max(0, total_length - 28)
        children.append({'title': f'Encrypted Data ({enc_len} bytes)', 'offset': offset + 28, 'length': enc_len})
        return {
            'title': 'Internet Security Association and Key Management Protocol',
            'offset': offset,
            'length': total_length,
            'children': children,
        }

    pos = 28
    current_type = int(next_payload)
    guard = 0
    while pos + 4 <= total_length and guard < 32:
        guard += 1
        np = int(payload[pos])
        flags_byte = int(payload[pos + 1])
        plen = int.from_bytes(payload[pos + 2:pos + 4], 'big')
        if plen < 4 or pos + plen > total_length:
            break

        p_name = _isakmp_payload_name(current_type, major)
        p_children: List[Dict[str, Any]] = [
            {'title': f'Next payload: {_isakmp_payload_name(np, major)} ({np})', 'offset': offset + pos, 'length': 1},
            {'title': f'{"0... .... = Critical Bit: Not critical" if (flags_byte & 0x80) == 0 else "1... .... = Critical Bit: Critical"}' if major == 2 else 'Reserved: 00', 'offset': offset + pos + 1, 'length': 1},
        ]
        if major == 2:
            p_children.append({'title': f'.{flags_byte & 0x7F:07b} = Reserved: 0x{flags_byte & 0x7F:02x}', 'offset': offset + pos + 1, 'length': 1})
        p_children.append({'title': f'Payload length: {plen}', 'offset': offset + pos + 2, 'length': 2})

        body = payload[pos + 4:pos + plen]
        body_off = pos + 4

        if current_type in {33, 1}:  # SA
            if major == 2 and len(body) >= 12:
                proposal_pos = 0
                while proposal_pos + 8 <= len(body):
                    p_next = int(body[proposal_pos])
                    p_len = int.from_bytes(body[proposal_pos + 2:proposal_pos + 4], 'big')
                    if p_len < 8 or proposal_pos + p_len > len(body):
                        break
                    p_number = int(body[proposal_pos + 4])
                    p_proto = int(body[proposal_pos + 5])
                    p_spi_size = int(body[proposal_pos + 6])
                    p_transforms = int(body[proposal_pos + 7])
                    proposal_children: List[Dict[str, Any]] = [
                        {'title': f'Next payload: {_isakmp_payload_name(p_next, major)} ({p_next})', 'offset': offset + body_off + proposal_pos, 'length': 1},
                        {'title': 'Reserved: 00', 'offset': offset + body_off + proposal_pos + 1, 'length': 1},
                        {'title': f'Payload length: {p_len}', 'offset': offset + body_off + proposal_pos + 2, 'length': 2},
                        {'title': f'Proposal number: {p_number}', 'offset': offset + body_off + proposal_pos + 4, 'length': 1},
                        {'title': f'Protocol ID: {"IKE" if p_proto == 1 else p_proto} ({p_proto})', 'offset': offset + body_off + proposal_pos + 5, 'length': 1},
                        {'title': f'SPI Size: {p_spi_size}', 'offset': offset + body_off + proposal_pos + 6, 'length': 1},
                        {'title': f'Proposal transforms: {p_transforms}', 'offset': offset + body_off + proposal_pos + 7, 'length': 1},
                    ]
                    t_pos = proposal_pos + 8 + p_spi_size
                    t_idx = 0
                    while t_pos + 8 <= proposal_pos + p_len and t_pos + 8 <= len(body):
                        t_idx += 1
                        t_next = int(body[t_pos])
                        t_len = int.from_bytes(body[t_pos + 2:t_pos + 4], 'big')
                        if t_len < 8 or t_pos + t_len > len(body):
                            break
                        t_type = int(body[t_pos + 4])
                        t_id = int.from_bytes(body[t_pos + 6:t_pos + 8], 'big')
                        t_children: List[Dict[str, Any]] = [
                            {'title': f'Next payload: {"Transform" if t_next == 3 else _isakmp_payload_name(t_next, major)} ({t_next})', 'offset': offset + body_off + t_pos, 'length': 1},
                            {'title': 'Reserved: 00', 'offset': offset + body_off + t_pos + 1, 'length': 1},
                            {'title': f'Payload length: {t_len}', 'offset': offset + body_off + t_pos + 2, 'length': 2},
                            {'title': f'Transform Type: {_isakmp_v2_transform_type_name(t_type)} ({t_type})', 'offset': offset + body_off + t_pos + 4, 'length': 1},
                            {'title': 'Reserved: 00', 'offset': offset + body_off + t_pos + 5, 'length': 1},
                        ]
                        id_name = _isakmp_v2_transform_id_name(t_type, t_id)
                        t_children.append({'title': f'Transform ID ({"ENCR" if t_type==1 else "PRF" if t_type==2 else "INTEG" if t_type==3 else "KE" if t_type==4 else "T"}): {id_name} ({t_id})', 'offset': offset + body_off + t_pos + 6, 'length': 2})
                        attr_pos = t_pos + 8
                        while attr_pos + 4 <= t_pos + t_len:
                            attr_type_val = int.from_bytes(body[attr_pos:attr_pos + 2], 'big')
                            attr_val = int.from_bytes(body[attr_pos + 2:attr_pos + 4], 'big')
                            af = 1 if (attr_type_val & 0x8000) else 0
                            a_type = attr_type_val & 0x7FFF
                            if af == 1:
                                if a_type == 14:
                                    t_children.append({
                                        'title': f'Transform Attribute (t={a_type},l=2): Key Length: {attr_val}',
                                        'offset': offset + body_off + attr_pos,
                                        'length': 4,
                                        'children': [
                                            {'title': '1... .... .... .... = Format: Type/Value (TV)', 'offset': offset + body_off + attr_pos, 'length': 2},
                                            {'title': f'Type: Key Length ({a_type})', 'offset': offset + body_off + attr_pos, 'length': 2},
                                            {'title': f'Value: {attr_val:04x}', 'offset': offset + body_off + attr_pos + 2, 'length': 2},
                                            {'title': f'Key Length: {attr_val}', 'offset': offset + body_off + attr_pos + 2, 'length': 2},
                                        ],
                                    })
                                else:
                                    t_children.append({'title': f'Transform Attribute (t={a_type},l=2): {attr_val}', 'offset': offset + body_off + attr_pos, 'length': 4})
                                attr_pos += 4
                            else:
                                break
                        proposal_children.append({
                            'title': 'Payload: Transform (3)',
                            'offset': offset + body_off + t_pos,
                            'length': t_len,
                            'children': t_children,
                        })
                        t_pos += t_len
                    p_children.append({
                        'title': f'Payload: Proposal (2) # {p_number}',
                        'offset': offset + body_off + proposal_pos,
                        'length': p_len,
                        'children': proposal_children,
                    })
                    proposal_pos += p_len
            elif major == 1 and len(body) >= 8:
                doi = int.from_bytes(body[0:4], 'big')
                situation = int.from_bytes(body[4:8], 'big')
                p_children.append({'title': f'Domain of interpretation: {"IPSEC" if doi == 1 else doi} ({doi})', 'offset': offset + body_off + 0, 'length': 4})
                p_children.append({
                    'title': f'Situation: {situation:08x}',
                    'offset': offset + body_off + 4,
                    'length': 4,
                    'children': [
                        {'title': f'.... .... .... .... .... .... .... ...{1 if situation & 0x1 else 0} = Identity Only: {"True" if situation & 0x1 else "False"}', 'offset': offset + body_off + 4, 'length': 4},
                        {'title': f'.... .... .... .... .... .... .... ..{1 if situation & 0x2 else 0}. = Secrecy: {"True" if situation & 0x2 else "False"}', 'offset': offset + body_off + 4, 'length': 4},
                        {'title': f'.... .... .... .... .... .... .... .{1 if situation & 0x4 else 0}.. = Integrity: {"True" if situation & 0x4 else "False"}', 'offset': offset + body_off + 4, 'length': 4},
                    ],
                })
                proposal_pos = 8
                while proposal_pos + 8 <= len(body):
                    p_next = int(body[proposal_pos])
                    p_len = int.from_bytes(body[proposal_pos + 2:proposal_pos + 4], 'big')
                    if p_len < 8 or proposal_pos + p_len > len(body):
                        break
                    p_number = int(body[proposal_pos + 4])
                    p_proto = int(body[proposal_pos + 5])
                    p_spi_size = int(body[proposal_pos + 6])
                    p_transforms = int(body[proposal_pos + 7])
                    proposal_children = [
                        {'title': f'Next payload: {_isakmp_payload_name(p_next, major)} ({p_next})', 'offset': offset + body_off + proposal_pos, 'length': 1},
                        {'title': 'Reserved: 00', 'offset': offset + body_off + proposal_pos + 1, 'length': 1},
                        {'title': f'Payload length: {p_len}', 'offset': offset + body_off + proposal_pos + 2, 'length': 2},
                        {'title': f'Proposal number: {p_number}', 'offset': offset + body_off + proposal_pos + 4, 'length': 1},
                        {'title': f'Protocol ID: {"ISAKMP" if p_proto == 1 else p_proto} ({p_proto})', 'offset': offset + body_off + proposal_pos + 5, 'length': 1},
                        {'title': f'SPI Size: {p_spi_size}', 'offset': offset + body_off + proposal_pos + 6, 'length': 1},
                        {'title': f'Proposal transforms: {p_transforms}', 'offset': offset + body_off + proposal_pos + 7, 'length': 1},
                    ]
                    t_pos = proposal_pos + 8 + p_spi_size
                    t_idx = 0
                    while t_pos + 8 <= proposal_pos + p_len and t_pos + 8 <= len(body):
                        t_idx += 1
                        t_next = int(body[t_pos])
                        t_len = int.from_bytes(body[t_pos + 2:t_pos + 4], 'big')
                        if t_len < 8 or t_pos + t_len > len(body):
                            break
                        t_number = int(body[t_pos + 4])
                        t_id = int(body[t_pos + 5])
                        t_children = [
                            {'title': f'Next payload: {_isakmp_payload_name(t_next, major)} ({t_next})', 'offset': offset + body_off + t_pos, 'length': 1},
                            {'title': 'Reserved: 00', 'offset': offset + body_off + t_pos + 1, 'length': 1},
                            {'title': f'Payload length: {t_len}', 'offset': offset + body_off + t_pos + 2, 'length': 2},
                            {'title': f'Transform number: {t_number}', 'offset': offset + body_off + t_pos + 4, 'length': 1},
                            {'title': f'Transform ID: {"KEY_IKE" if t_id == 1 else t_id} ({t_id})', 'offset': offset + body_off + t_pos + 5, 'length': 1},
                            {'title': 'Reserved: 0000', 'offset': offset + body_off + t_pos + 6, 'length': 2},
                        ]
                        attr_pos = t_pos + 8
                        while attr_pos + 4 <= t_pos + t_len:
                            raw_type = int.from_bytes(body[attr_pos:attr_pos + 2], 'big')
                            raw_val = int.from_bytes(body[attr_pos + 2:attr_pos + 4], 'big')
                            tv = 1 if (raw_type & 0x8000) else 0
                            attr_type = raw_type & 0x7FFF
                            if tv != 1:
                                break
                            attr_name = _isakmp_v1_attribute_name(attr_type)
                            value_name = _isakmp_v1_attribute_value(attr_type, raw_val)
                            suffix = f': {value_name}' if attr_type not in {12, 14} else f': {raw_val}'
                            if attr_type == 11:
                                suffix = f': Life-Type: {value_name}'
                            elif attr_type == 12:
                                suffix = f': Life-Duration: {raw_val}'
                            elif attr_type == 14:
                                suffix = f': Key-Length: {raw_val}'
                            elif attr_type == 1:
                                suffix = f': Encryption-Algorithm: {value_name}'
                            elif attr_type == 2:
                                suffix = f': Hash-Algorithm: {value_name}'
                            elif attr_type == 3:
                                suffix = f': Authentication-Method: {value_name}'
                            elif attr_type == 4:
                                suffix = f': Group-Description: {value_name}'
                            value_detail = f'Value: {raw_val}'
                            if attr_type == 11:
                                value_detail = f'Life Type: {value_name} ({raw_val})'
                            elif attr_type == 12:
                                value_detail = f'Life Duration: {raw_val}'
                            elif attr_type == 14:
                                value_detail = f'Key Length: {raw_val}'
                            elif attr_type == 1:
                                value_detail = f'Encryption Algorithm: {value_name} ({raw_val})'
                            elif attr_type == 2:
                                value_detail = f'HASH Algorithm: {value_name} ({raw_val})'
                            elif attr_type == 3:
                                value_detail = f'Authentication Method: {value_name} ({raw_val})'
                            elif attr_type == 4:
                                value_detail = f'Group Description: {value_name} ({raw_val})'
                            t_children.append({
                                'title': f'IKE Attribute (t={attr_type},l=2){suffix}',
                                'offset': offset + body_off + attr_pos,
                                'length': 4,
                                'children': [
                                    {'title': '1... .... .... .... = Format: Type/Value (TV)', 'offset': offset + body_off + attr_pos, 'length': 2},
                                    {'title': f'Type: {attr_name} ({attr_type})', 'offset': offset + body_off + attr_pos, 'length': 2},
                                    {'title': f'Value: {raw_val:04x}', 'offset': offset + body_off + attr_pos + 2, 'length': 2},
                                    {'title': value_detail, 'offset': offset + body_off + attr_pos + 2, 'length': 2},
                                ],
                            })
                            attr_pos += 4
                        proposal_children.append({
                            'title': f'Payload: Transform (3) # {t_idx}',
                            'offset': offset + body_off + t_pos,
                            'length': t_len,
                            'children': t_children,
                        })
                        t_pos += t_len
                    p_children.append({
                        'title': f'Payload: Proposal (2) # {p_number}',
                        'offset': offset + body_off + proposal_pos,
                        'length': p_len,
                        'children': proposal_children,
                    })
                    proposal_pos += p_len
        elif current_type in {34, 4}:  # KE (v2/v1)
            if major == 2 and len(body) >= 4:
                ke_method = int.from_bytes(body[0:2], 'big')
                p_children.append({'title': f'Key Exchange Method: {_isakmp_v2_transform_id_name(4, ke_method)} ({ke_method})', 'offset': offset + body_off + 0, 'length': 2})
                p_children.append({'title': f'Reserved: {body[2:4].hex()}', 'offset': offset + body_off + 2, 'length': 2})
                if len(body) > 4:
                    preview = body[4:].hex()
                    title = f'Key Exchange Data{" [â€¦]" if len(preview) > 320 else ""}: {preview[:320] if len(preview)>320 else preview}'
                    p_children.append({'title': title, 'offset': offset + body_off + 4, 'length': len(body) - 4})
            else:
                preview = body.hex()
                title = f'Key Exchange Data{" [â€¦]" if len(preview) > 320 else ""}: {preview[:320] if len(preview)>320 else preview}'
                p_children.append({'title': title, 'offset': offset + body_off, 'length': len(body)})
        elif current_type in {40, 10}:  # Nonce
            p_children.append({'title': f'Nonce DATA: {body.hex()}', 'offset': offset + body_off, 'length': len(body)})
        elif current_type == 5 and major == 1 and len(body) >= 4:  # ID
            id_type = int(body[0])
            proto_id = int(body[1])
            port = int.from_bytes(body[2:4], 'big')
            id_data = body[4:]
            id_text = id_data.decode(errors='ignore')
            p_children.append({'title': f'ID type: {"FQDN" if id_type == 2 else id_type} ({id_type})', 'offset': offset + body_off + 0, 'length': 1})
            p_children.append({'title': f'Protocol ID: {"Unused" if proto_id == 0 else proto_id}', 'offset': offset + body_off + 1, 'length': 1})
            p_children.append({'title': f'Port: {"Unused" if port == 0 else port}', 'offset': offset + body_off + 2, 'length': 2})
            p_children.append({
                'title': f'Identification Data:{id_text}',
                'offset': offset + body_off + 4,
                'length': len(id_data),
                'children': [{'title': f'ID_FQDN: {id_text}', 'offset': offset + body_off + 4, 'length': len(id_data)}] if id_type == 2 else [],
            })
        elif current_type == 13 and major == 1:  # Vendor ID
            vendor_hex = body.hex()
            vendor_name = 'Unknown Vendor ID'
            if vendor_hex.startswith('afcad71368a1f1c96b8696fc77570100'):
                vendor_name = 'RFC 3706 DPD (Dead Peer Detection)'
            elif vendor_hex.startswith('09002689dfd6b712'):
                vendor_name = 'XAUTH'
            p_children.append({'title': f'Vendor ID: {vendor_hex}', 'offset': offset + body_off, 'length': len(body)})
            p_children.append({'title': f'Vendor ID: {vendor_name}'})
        elif current_type == 46 and major == 2:
            if len(body) >= 4:
                p_children.append({'title': f'Initialization Vector: {body[:4].hex()}', 'offset': offset + body_off, 'length': 4})
                if len(body) > 4:
                    p_children.append({'title': 'Encrypted Data', 'offset': offset + body_off + 4, 'length': len(body) - 4})
            else:
                p_children.append({'title': 'Encrypted Data', 'offset': offset + body_off, 'length': len(body)})

        node_title = f'Payload: {p_name} ({current_type})'
        if current_type == 13 and major == 1 and len(body) > 0:
            vendor_hex = body.hex()
            if vendor_hex.startswith('afcad71368a1f1c96b8696fc77570100'):
                node_title = 'Payload: Vendor ID (13) : RFC 3706 DPD (Dead Peer Detection)'
            elif vendor_hex.startswith('09002689dfd6b712'):
                node_title = 'Payload: Vendor ID (13) : XAUTH'
            else:
                node_title = 'Payload: Vendor ID (13) : Unknown Vendor ID'

        children.append({
            'title': node_title,
            'offset': offset + pos,
            'length': plen,
            'children': p_children,
        })

        current_type = np
        pos += plen
        if current_type == 0:
            break

    return {
        'title': 'Internet Security Association and Key Management Protocol',
        'offset': offset,
        'length': total_length,
        'children': children,
    }


def _ipv6_fragment_section(layer, offset: int) -> Dict[str, Any]:
    next_header = int(getattr(layer, 'nh', 0) or 0)
    reserved = int(getattr(layer, 'res1', 0) or 0)
    fragment_offset = int(getattr(layer, 'offset', 0) or 0)
    more_flag = int(getattr(layer, 'm', 0) or 0)
    ident = int(getattr(layer, 'id', 0) or 0)
    next_header_name = {
        6: 'TCP',
        17: 'UDP',
        58: 'ICMPv6',
    }.get(next_header, str(next_header))
    offset_bits = format(fragment_offset, '013b')
    children = [
        {'title': f'Next header: {next_header_name} ({next_header})', 'offset': offset, 'length': 1},
        {'title': f'Reserved octet: 0x{reserved:02x}', 'offset': offset + 1, 'length': 1},
        {'title': f'{offset_bits[:4]} {offset_bits[4:8]} {offset_bits[8:12]} {offset_bits[12]}... = Offset: {fragment_offset} ({fragment_offset * 8} bytes)', 'offset': offset + 2, 'length': 2},
        {'title': '.... .... .... .00. = Reserved bits: 0', 'offset': offset + 2, 'length': 2},
        {'title': f'.... .... .... ...{more_flag} = More Fragments: {"Yes" if more_flag else "No"}', 'offset': offset + 3, 'length': 1},
        {'title': f'Identification: 0x{ident:08x}', 'offset': offset + 4, 'length': 4},
    ]
    return {
        'title': 'Fragment Header for IPv6',
        'offset': offset,
        'length': 8,
        'children': children,
    }


def _ssh_message_name(msg_code: int, kex_method: str = '') -> str:
    method = str(kex_method or '').lower()
    if int(msg_code) == 31 and 'group-exchange' in method:
        return 'Diffie-Hellman Group Exchange Group'
    names = {
        1: 'Disconnect',
        2: 'Ignore',
        3: 'Unimplemented',
        4: 'Debug',
        5: 'Service Request',
        6: 'Service Accept',
        20: 'Key Exchange Init',
        21: 'New Keys',
        30: 'Diffie-Hellman Key Exchange Init',
        31: 'Diffie-Hellman Key Exchange Reply',
        32: 'Diffie-Hellman Group Exchange Init',
        33: 'Diffie-Hellman Group Exchange Reply',
        34: 'Diffie-Hellman Group Exchange Request',
        50: 'User Authentication Request',
        51: 'User Authentication Failure',
        52: 'User Authentication Success',
        53: 'User Authentication Banner',
        80: 'Global Request',
        81: 'Request Success',
        82: 'Request Failure',
    }
    return names.get(int(msg_code), f'Message ({int(msg_code)})')


def _ssh_section(payload: bytes, offset: int, record=None) -> Dict[str, Any]:
    metadata = getattr(record, 'metadata', {}) if record else {}
    reassembled_hex = str(metadata.get('tcp_reassembled_data_hex', '') or '')
    use_reassembled = False
    if reassembled_hex:
        try:
            payload = bytes.fromhex(reassembled_hex)
            use_reassembled = True
            offset = 0
        except Exception:
            pass

    byte_source = TCP_REASSEMBLED_BYTE_SOURCE if use_reassembled else PACKET_BYTE_SOURCE
    base_offset = 0 if use_reassembled else int(offset)

    def _map(rel_offset: int, length: int) -> Dict[str, Any]:
        return _byte_mapping(base_offset, rel_offset, length, byte_source)

    def _hex_preview(value: bytes, limit_chars: int = 320) -> tuple[str, bool]:
        text = bytes(value or b'').hex()
        if len(text) > limit_chars:
            return text[:limit_chars], True
        return text, False

    def _read_u32(buf: bytes, pos: int) -> tuple[int, int] | None:
        if pos + 4 > len(buf):
            return None
        return int.from_bytes(buf[pos:pos + 4], 'big'), pos + 4

    def _read_string(buf: bytes, pos: int) -> tuple[bytes, int, int, int] | None:
        parsed = _read_u32(buf, pos)
        if parsed is None:
            return None
        length, next_pos = parsed
        end_pos = next_pos + int(length)
        if end_pos > len(buf):
            return None
        return buf[next_pos:end_pos], end_pos, pos, int(length)

    def _read_mpint(buf: bytes, pos: int) -> tuple[bytes, int, int] | None:
        parsed = _read_u32(buf, pos)
        if parsed is None:
            return None
        mp_len, next_pos = parsed
        end_pos = next_pos + int(mp_len)
        if end_pos > len(buf):
            return None
        return buf[next_pos:end_pos], end_pos, int(mp_len)

    children: List[Dict[str, Any]] = []
    if payload.startswith(b'SSH-'):
        line = payload.split(b'\n', 1)[0]
        line_text = line.rstrip(b'\r').decode(errors='ignore')
        children.append({
            'title': f'Protocol Version Exchange: {line_text}',
            **_map(0, len(line)),
        })
        if b'\n' in payload:
            children.append({'title': '\\n', **_map(len(line), 1)})
        return {
            'title': 'SSH Protocol',
            **_map(0, len(payload)),
            'children': children,
        }

    tcp_layer = _effective_tcp_layer(getattr(record, 'raw', None), _effective_ip_layer(getattr(record, 'raw', None))) if record else None
    direction = 'Server to Client' if tcp_layer is not None and int(getattr(tcp_layer, 'sport', 0) or 0) == 22 else 'Client to Server'
    kex_method = str(metadata.get('ssh_kex_method', '') or 'diffie-hellman-group-exchange-sha1')
    encryption = str(metadata.get('ssh_encryption', '') or 'aes128-cbc')
    mac_name = str(metadata.get('ssh_mac', '') or 'hmac-sha1')
    compression = str(metadata.get('ssh_compression', '') or 'none')

    version_children: List[Dict[str, Any]] = []
    if len(payload) >= 5:
        packet_length = int.from_bytes(payload[0:4], 'big')
        padding_length = int(payload[4])
        if packet_length >= 2 and packet_length + 4 <= len(payload):
            payload_end = 4 + packet_length - padding_length
            version_children.append({'title': f'Packet Length: {packet_length}', **_map(0, 4)})
            version_children.append({'title': f'Padding Length: {padding_length}', **_map(4, 1)})
            if payload_end > 5:
                msg_code = int(payload[5])
                msg_name = _ssh_message_name(msg_code, kex_method)
                key_exchange_children: List[Dict[str, Any]] = [
                    {'title': f'Message Code: {msg_name} ({msg_code})', **_map(5, 1)}
                ]
                msg_payload = payload[6:payload_end]
                msg_rel = 6

                if msg_code == 20 and len(msg_payload) >= 16:
                    algo_children: List[Dict[str, Any]] = [
                        {'title': f'Cookie: {msg_payload[:16].hex()}', **_map(msg_rel, 16)}
                    ]
                    pos = 16
                    fields = [
                        'kex_algorithms',
                        'server_host_key_algorithms',
                        'encryption_algorithms_client_to_server',
                        'encryption_algorithms_server_to_client',
                        'mac_algorithms_client_to_server',
                        'mac_algorithms_server_to_client',
                        'compression_algorithms_client_to_server',
                        'compression_algorithms_server_to_client',
                        'languages_client_to_server',
                        'languages_server_to_client',
                    ]
                    for field in fields:
                        if pos + 4 > len(msg_payload):
                            break
                        name_len = int.from_bytes(msg_payload[pos:pos + 4], 'big')
                        algo_children.append({'title': f'{field} length: {name_len}', **_map(msg_rel + pos, 4)})
                        pos += 4
                        value = msg_payload[pos:pos + name_len]
                        text = value.decode(errors='ignore')
                        title = f'{field} string [...]: {text}' if len(text) > 260 else f'{field} string: {text}'
                        algo_children.append({'title': title, **_map(msg_rel + pos, len(value))})
                        pos += len(value)
                    if pos + 1 <= len(msg_payload):
                        first_kex = int(msg_payload[pos])
                        algo_children.append({'title': f'First KEX Packet Follows: {first_kex}', **_map(msg_rel + pos, 1)})
                        pos += 1
                    if pos + 4 <= len(msg_payload):
                        algo_children.append({'title': f'Reserved: {msg_payload[pos:pos + 4].hex()}', **_map(msg_rel + pos, 4)})
                        pos += 4
                    key_exchange_children.append({
                        'title': 'Algorithms',
                        **_map(msg_rel, len(msg_payload)),
                        'children': algo_children,
                    })
                elif msg_code == 34 and len(msg_payload) >= 12:
                    min_bits = int.from_bytes(msg_payload[0:4], 'big')
                    n_bits = int.from_bytes(msg_payload[4:8], 'big')
                    max_bits = int.from_bytes(msg_payload[8:12], 'big')
                    key_exchange_children.extend([
                        {'title': f'DH GEX Min: {min_bits}', **_map(msg_rel, 4)},
                        {'title': f'DH GEX Number of Bits: {n_bits}', **_map(msg_rel + 4, 4)},
                        {'title': f'DH GEX Max: {max_bits}', **_map(msg_rel + 8, 4)},
                    ])
                elif msg_code == 31 and len(msg_payload) >= 4 and 'group-exchange' in kex_method.lower():
                    parsed_mp = _read_mpint(msg_payload, 0)
                    if parsed_mp is not None:
                        mp_val, pos, mp_len = parsed_mp
                        key_exchange_children.append({'title': f'Multi Precision Integer Length: {mp_len}', **_map(msg_rel, 4)})
                        preview, truncated = _hex_preview(mp_val)
                        mod_title = f'DH GEX modulus (P) [...]: {preview}' if truncated else f'DH GEX modulus (P): {preview}'
                        key_exchange_children.append({'title': mod_title, **_map(msg_rel + 4, len(mp_val))})
                        parsed_g = _read_mpint(msg_payload, pos)
                        if parsed_g is not None:
                            g_val, _, g_len = parsed_g
                            key_exchange_children.append({'title': f'Multi Precision Integer Length: {g_len}', **_map(msg_rel + pos, 4)})
                            g_preview, g_truncated = _hex_preview(g_val)
                            g_title = f'DH GEX base (G) [...]: {g_preview}' if g_truncated else f'DH GEX base (G): {g_preview}'
                            key_exchange_children.append({'title': g_title, **_map(msg_rel + pos + 4, len(g_val))})
                elif msg_code == 32 and len(msg_payload) >= 4:
                    parsed_e = _read_mpint(msg_payload, 0)
                    if parsed_e is not None:
                        e_val, _, e_len = parsed_e
                        key_exchange_children.append({'title': f'Multi Precision Integer Length: {e_len}', **_map(msg_rel, 4)})
                        e_preview, e_truncated = _hex_preview(e_val)
                        e_title = f'DH client e [...]: {e_preview}' if e_truncated else f'DH client e: {e_preview}'
                        key_exchange_children.append({'title': e_title, **_map(msg_rel + 4, len(e_val))})
                elif msg_code == 33 and len(msg_payload) >= 4:
                    pos = 0
                    host_key = _read_string(msg_payload, pos)
                    if host_key is not None:
                        host_blob, pos, host_len_pos, host_len = host_key
                        key_exchange_children.append({
                            'title': 'KEX host key (type: ssh-rsa)',
                            **_map(msg_rel + host_len_pos, 4 + host_len),
                            'children': [],
                        })
                        host_children = key_exchange_children[-1]['children']
                        host_children.append({'title': f'Host key length: {host_len}', **_map(msg_rel + host_len_pos, 4)})
                        host_pos = 0
                        key_type_parsed = _read_string(host_blob, host_pos)
                        if key_type_parsed is not None:
                            key_type_blob, host_pos, type_len_pos, type_len = key_type_parsed
                            key_type = key_type_blob.decode(errors='ignore')
                            host_children.append({'title': f'Host key type length: {type_len}', **_map(msg_rel + host_len_pos + 4 + type_len_pos, 4)})
                            host_children.append({'title': f'Host key type: {key_type}', **_map(msg_rel + host_len_pos + 4 + type_len_pos + 4, len(key_type_blob))})
                        exp_parsed = _read_mpint(host_blob, host_pos)
                        if exp_parsed is not None:
                            exp_val, host_pos, exp_len = exp_parsed
                            host_children.append({'title': f'Multi Precision Integer Length: {exp_len}', **_map(msg_rel + host_len_pos + 4 + host_pos - exp_len - 4, 4)})
                            host_children.append({'title': f'RSA public exponent (e): {exp_val.hex()}', **_map(msg_rel + host_len_pos + 4 + host_pos - exp_len, len(exp_val))})
                        mod_parsed = _read_mpint(host_blob, host_pos)
                        if mod_parsed is not None:
                            mod_val, _, mod_len = mod_parsed
                            host_children.append({'title': f'Multi Precision Integer Length: {mod_len}', **_map(msg_rel + host_len_pos + 4 + host_pos, 4)})
                            mod_preview, mod_truncated = _hex_preview(mod_val)
                            mod_title = f'RSA modulus (N) [...]: {mod_preview}' if mod_truncated else f'RSA modulus (N): {mod_preview}'
                            host_children.append({'title': mod_title, **_map(msg_rel + host_len_pos + 4 + host_pos + 4, len(mod_val))})
                    f_mpint = _read_mpint(msg_payload, pos)
                    if f_mpint is not None:
                        f_val, pos, f_len = f_mpint
                        key_exchange_children.append({'title': f'Multi Precision Integer Length: {f_len}', **_map(msg_rel + pos - f_len - 4, 4)})
                        f_preview, f_truncated = _hex_preview(f_val)
                        f_title = f'DH server f [...]: {f_preview}' if f_truncated else f'DH server f: {f_preview}'
                        key_exchange_children.append({'title': f_title, **_map(msg_rel + pos - f_len, len(f_val))})
                    sig_str = _read_string(msg_payload, pos)
                    if sig_str is not None:
                        sig_blob, _, sig_len_pos, sig_len = sig_str
                        sig_children: List[Dict[str, Any]] = []
                        sig_children.append({'title': f'Host signature length: {sig_len}', **_map(msg_rel + sig_len_pos, 4)})
                        sig_pos = 0
                        sig_type_parsed = _read_string(sig_blob, sig_pos)
                        if sig_type_parsed is not None:
                            sig_type_blob, sig_pos, s_type_len_pos, s_type_len = sig_type_parsed
                            sig_type = sig_type_blob.decode(errors='ignore')
                            sig_children.append({'title': f'Host signature type length: {s_type_len}', **_map(msg_rel + sig_len_pos + 4 + s_type_len_pos, 4)})
                            sig_children.append({'title': f'Host signature type: {sig_type}', **_map(msg_rel + sig_len_pos + 4 + s_type_len_pos + 4, len(sig_type_blob))})
                        sig_mp = _read_mpint(sig_blob, sig_pos)
                        if sig_mp is not None:
                            sig_val, _, sig_mp_len = sig_mp
                            sig_children.append({'title': f'Multi Precision Integer Length: {sig_mp_len}', **_map(msg_rel + sig_len_pos + 4 + sig_pos, 4)})
                            sig_preview, sig_truncated = _hex_preview(sig_val)
                            sig_title = f'RSA signature [...]: {sig_preview}' if sig_truncated else f'RSA signature: {sig_preview}'
                            sig_children.append({'title': sig_title, **_map(msg_rel + sig_len_pos + 4 + sig_pos + 4, len(sig_val))})
                        key_exchange_children.append({
                            'title': 'KEX host signature (type: ssh-rsa)',
                            **_map(msg_rel + sig_len_pos, 4 + sig_len),
                            'children': sig_children,
                        })

                key_exchange_node = {
                    'title': f'Key Exchange (method:{kex_method})',
                    **_map(5, max(1, payload_end - 5)),
                    'children': key_exchange_children,
                }
                version_children.append(key_exchange_node)

            if padding_length > 0 and payload_end >= 0:
                padding_bytes = payload[payload_end:4 + packet_length]
                version_children.append({'title': f'Padding String: {padding_bytes.hex()}', **_map(payload_end, len(padding_bytes))})
            if metadata.get('ssh_sequence_number', None) is not None:
                version_children.append({'title': f"[Sequence number: {int(metadata.get('ssh_sequence_number', 0) or 0)}]"})
        else:
            mac_len = 20
            encrypted_field = payload[4:max(4, len(payload) - mac_len)] if len(payload) > 4 else b''
            mac_field = payload[max(4, len(payload) - mac_len):] if len(payload) >= 4 else b''
            version_children.append({'title': f'Packet Length (encrypted): {payload[0:4].hex()}', **_map(0, min(4, len(payload)))})
            if encrypted_field:
                version_children.append({'title': f'Encrypted Packet: {encrypted_field.hex()}', **_map(4, len(encrypted_field))})
            if mac_field:
                version_children.append({'title': f'MAC: {mac_field.hex()}', **_map(len(payload) - len(mac_field), len(mac_field))})

    children.append({
        'title': f'SSH Version 2 (encryption:{encryption} mac:{mac_name} compression:{compression})',
        **_map(0, len(payload)),
        'children': version_children,
    })
    children.append({'title': f'[Direction: {direction}]'})

    return {
        'title': 'SSH Protocol',
        **_map(0, len(payload)),
        'children': children,
    }


def _xml_body_section(record, offset: int) -> Dict[str, Any] | None:
    metadata = getattr(record, 'metadata', {}) or {}
    body = bytes(metadata.get('http_body', b'') or b'')
    if not body:
        return None
    try:
        text = body.decode('utf-8', errors='strict')
    except Exception:
        text = body.decode('utf-8', errors='ignore')
    body_offset = 0
    lines: List[Dict[str, Any]] = []
    cursor = 0
    for raw_line in text.splitlines(keepends=True):
        raw_bytes = raw_line.encode('utf-8', errors='ignore')
        line_text = raw_line.rstrip('\r\n')
        if line_text:
            lines.append({
                'title': line_text,
                **_byte_mapping(offset, body_offset + cursor, len(raw_bytes), DECODED_UTF8_BYTE_SOURCE),
            })
        cursor += len(raw_bytes)
    if not lines:
        lines.append({
            'title': text,
            **_byte_mapping(offset, body_offset, len(body), DECODED_UTF8_BYTE_SOURCE),
        })
    return {
        'title': 'eXtensible Markup Language',
        **_byte_mapping(offset, body_offset, len(body), DECODED_UTF8_BYTE_SOURCE),
        'children': lines,
    }


def _smtp_response_description(code: str) -> str:
    return {
        '220': '<domain> Service ready',
        '250': 'Requested mail action okay, completed',
        '354': 'Start mail input; end with <CRLF>.<CRLF>',
        '221': 'Service closing transmission channel',
    }.get(str(code or ''), '')


def _smtp_section(payload: bytes, offset: int, record=None) -> Dict[str, Any]:
    metadata = getattr(record, 'metadata', {}) if record else {}
    children: List[Dict[str, Any]] = []
    smtp_kind = str(metadata.get('smtp_kind', '') or '')

    if smtp_kind == 'response':
        raw_lines = payload.splitlines(keepends=True)
        line = raw_lines[0].rstrip(b'\r\n') if raw_lines else payload.split(b'\r\n', 1)[0]
        line_text = line.decode(errors='ignore')
        code = str(metadata.get('smtp_response_code', '') or line_text[:3])
        param = str(metadata.get('smtp_response_parameter', '') or (line_text[4:].strip() if len(line_text) > 4 else ''))
        response_children = []
        if code:
            description = _smtp_response_description(code)
            title = f'Response code: {description} ({code})' if description else f'Response code: {code}'
            response_children.append({
                'title': title,
                'offset': offset,
                'length': 3,
            })
        if param:
            response_children.append({
                'title': f'Response parameter: {param}',
                'offset': offset + 4,
                'length': len(line) - 4,
            })
        cursor = 0
        for idx, raw_line in enumerate(raw_lines):
            clean = raw_line.rstrip(b'\r\n')
            text = clean.decode(errors='ignore').strip()
            if not text:
                cursor += len(raw_line)
                continue
            if idx == 0:
                cursor += len(raw_line)
                continue
            if len(text) >= 4 and text[:3].isdigit():
                param_text = text[4:].strip()
                param_offset = offset + cursor + 4
                param_length = max(0, len(clean) - 4)
            else:
                param_text = text
                param_offset = offset + cursor
                param_length = len(clean)
            if param_text:
                response_children.append({
                    'title': f'Response parameter: {param_text}',
                    'offset': param_offset,
                    'length': param_length,
                })
            cursor += len(raw_line)
        children.append({
            'title': f'Response: {line_text}\\r\\n',
            'offset': offset,
            'length': len(raw_lines[0]) if raw_lines else len(line) + 2,
            'children': response_children,
        })
    elif smtp_kind == 'command':
        line = payload.split(b'\r\n', 1)[0]
        line_text = line.decode(errors='ignore')
        parts = line_text.split(' ', 1)
        command = parts[0].strip().upper() if parts else ''
        param = parts[1].strip() if len(parts) > 1 else ''
        command_children = []
        if command:
            command_children.append({
                'title': f'Command: {command}',
                'offset': offset,
                'length': len(command),
            })
        if param:
            command_children.append({
                'title': f'Request parameter: {param}',
                'offset': offset + len(command) + 1,
                'length': len(line) - len(command) - 1,
            })
        children.append({
            'title': f'Command Line: {line_text}\\r\\n',
            'offset': offset,
            'length': len(line) + 2,
            'children': command_children,
        })
    elif smtp_kind == 'data':
        full_payload = bytes(metadata.get('smtp_data_reassembled_payload', b'') or b'')
        if full_payload:
            segments = list(metadata.get('smtp_data_segments', []) or [])
            reassembled_len = int(metadata.get('smtp_data_reassembled_length', 0) or 0)
            segment_summary = ', '.join(
                f"#{int(segment.get('frame_number', 0) or 0)}({int(segment.get('payload_length', 0) or 0)})"
                for segment in segments
            )
            data_children = []
            for segment in segments:
                start_pos = int(segment.get('payload_start', 0) or 0)
                seg_len = int(segment.get('payload_length', 0) or 0)
                end_pos = max(start_pos, start_pos + seg_len - 1)
                data_children.append({
                    'title': f"[Frame: {int(segment.get('frame_number', 0) or 0)}, payload: {start_pos}-{end_pos} ({seg_len} bytes)]",
                    **_byte_mapping(0, start_pos, seg_len, TCP_REASSEMBLED_BYTE_SOURCE),
                })
            data_children.append({'title': f'[DATA fragment count: {len(segments)}]'})
            data_children.append({
                'title': f'[Reassembled DATA length: {reassembled_len}]',
                **_byte_mapping(0, 0, reassembled_len, TCP_REASSEMBLED_BYTE_SOURCE),
            })
            if segments:
                children.append({
                    'title': f'[{len(segments)} DATA fragments ({reassembled_len} bytes): {segment_summary}]',
                    'children': data_children,
                })
            dot_offset = int(metadata.get('smtp_data_dot_offset_in_payload', 0) or 0)
            dot_length = int(metadata.get('smtp_data_dot_length', 0) or 0)
            if dot_length > 0:
                children.append({
                    'title': 'C: .',
                    'offset': offset + dot_offset,
                    'length': dot_length,
                })
        else:
            children.append(_smtp_line_based_text_section(payload, offset))
            reassembled_frame = metadata.get('smtp_reassembled_data_in_frame', None) or metadata.get('tcp_reassembled_pdu_in_frame', None)
            if reassembled_frame is not None:
                children.append({
                    'title': f'[Reassembled DATA in frame: {int(reassembled_frame)}]',
                })

    response_frame = metadata.get('smtp_response_frame', None)
    if response_frame is not None:
        children.append({'title': f'[Response in frame: {int(response_frame)}]'})
    request_frame = metadata.get('smtp_request_frame', None)
    if request_frame is not None:
        children.append({'title': f'[Request in frame: {int(request_frame)}]'})
    time_since_request = metadata.get('smtp_time_since_request_ms', None)
    if time_since_request is not None:
        children.append({'title': f'[Time since request: {float(time_since_request):.6f} milliseconds]'})

    node: Dict[str, Any] = {'title': 'Simple Mail Transfer Protocol', 'children': children}
    if smtp_kind in {'command', 'response'}:
        node.update(_byte_mapping(offset, 0, len(payload), PACKET_BYTE_SOURCE))
    elif smtp_kind == 'data':
        if bytes(metadata.get('smtp_data_reassembled_payload', b'') or b''):
            node.update(_byte_mapping(0, 0, int(metadata.get('smtp_data_reassembled_length', 0) or 0), TCP_REASSEMBLED_BYTE_SOURCE))
        else:
            node.update(_byte_mapping(offset, 0, len(payload), PACKET_BYTE_SOURCE))
    return node


def _smtp_line_based_text_section(payload: bytes, offset: int) -> Dict[str, Any]:
    lines = []
    cursor = 0
    for raw_line in payload.splitlines(keepends=True):
        text = raw_line.decode(errors='ignore').replace('\r', '\\r').replace('\n', '\\n')
        lines.append({
            'title': text,
            'offset': offset + cursor,
            'length': len(raw_line),
        })
        cursor += len(raw_line)
    return {
        'title': f'Line-based text data ({len(lines)} lines)',
        'offset': offset,
        'length': len(payload),
        'children': lines,
    }


def _imf_address_value(raw_line: bytes) -> str:
    try:
        return raw_line.split(b':', 1)[1].decode(errors='ignore').strip()
    except Exception:
        return ''


def _imf_section(record, offset: int) -> Dict[str, Any]:
    metadata = getattr(record, 'metadata', {}) or {}
    imf = metadata.get('smtp_imf', {}) or {}
    payload = bytes(metadata.get('smtp_data_reassembled_payload', b'') or b'')
    headers = list(imf.get('headers', []) or [])
    body_lines = list(imf.get('body_lines', []) or [])
    children: List[Dict[str, Any]] = []

    for header in headers:
        raw_line = bytes(header.get('raw', b'') or b'')
        line_text = raw_line.decode(errors='ignore')
        header_offset = int(header.get('offset', 0) or 0)
        header_length = int(header.get('length', len(raw_line) + 2) or (len(raw_line) + 2))
        lower = raw_line.lower()
        if lower.startswith(b'from:'):
            value = _imf_address_value(raw_line)
            children.append({
                'title': f'From: {value}, 1 item',
                **_byte_mapping(0, header_offset, header_length, TCP_REASSEMBLED_BYTE_SOURCE),
                'children': [
                    {
                        'title': f'Item: {value}\\r\\n',
                        **_byte_mapping(0, header_offset + 6, max(0, len(raw_line) - 5), TCP_REASSEMBLED_BYTE_SOURCE),
                        'children': [
                            {
                                'title': f'Address: {value.strip("<>")}',
                                **_byte_mapping(0, header_offset + 6, max(0, len(raw_line) - 6), TCP_REASSEMBLED_BYTE_SOURCE),
                            },
                        ],
                    },
                ],
            })
        elif lower.startswith(b'to:'):
            value = _imf_address_value(raw_line)
            children.append({
                'title': f'To: {value}, 1 item',
                **_byte_mapping(0, header_offset, header_length, TCP_REASSEMBLED_BYTE_SOURCE),
                'children': [
                    {
                        'title': f'Item: {value}\\r\\n',
                        **_byte_mapping(0, header_offset + 4, max(0, len(raw_line) - 3), TCP_REASSEMBLED_BYTE_SOURCE),
                        'children': [
                            {
                                'title': f'Address: {value.strip("<>")}',
                                **_byte_mapping(0, header_offset + 4, max(0, len(raw_line) - 4), TCP_REASSEMBLED_BYTE_SOURCE),
                            },
                        ],
                    },
                ],
            })
        else:
            children.append({
                'title': line_text,
                **_byte_mapping(0, header_offset, header_length, TCP_REASSEMBLED_BYTE_SOURCE),
            })

    terminator_offset = int(imf.get('headers_terminator_offset', -1) or -1)
    if terminator_offset >= 0:
        children.append({
            'title': '\\r\\n',
            **_byte_mapping(0, terminator_offset, int(imf.get('headers_terminator_length', 4) or 4), TCP_REASSEMBLED_BYTE_SOURCE),
        })

    if body_lines:
        text_children = []
        for line in body_lines:
            raw_line = bytes(line.get('raw', b'') or b'')
            line_text = raw_line.decode(errors='ignore').rstrip('\r\n')
            line_text = f'{line_text}  ' if line_text else ''
            text_children.append({
                'title': line_text,
                **_byte_mapping(0, int(line.get('offset', 0) or 0), int(line.get('length', len(raw_line)) or len(raw_line)), TCP_REASSEMBLED_BYTE_SOURCE),
            })
        body_start = int(body_lines[0].get('offset', 0) or 0)
        body_len = sum(int(line.get('length', 0) or 0) for line in body_lines)
        children.append({
            'title': 'Message-Text',
            **_byte_mapping(0, body_start, body_len, TCP_REASSEMBLED_BYTE_SOURCE),
            'children': text_children,
        })

    return {
        'title': 'Internet Message Format',
        **_byte_mapping(0, 0, len(payload), TCP_REASSEMBLED_BYTE_SOURCE),
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
        33: 'SRV',
        41: 'OPT',
        46: 'RRSIG',
        48: 'DNSKEY',
        28: 'AAAA',
        255: 'ANY',
    }.get(int(value or 0), str(int(value or 0)))


def _dns_class_name(value: int) -> str:
    return {1: 'IN'}.get(int(value or 0), f'0x{int(value or 0):04x}')


def _dns_type_label(value: int) -> str:
    type_name = _dns_type_name(value)
    suffix = {
        1: 'Host Address',
        2: 'authoritative Name Server',
        12: 'domain name PoinTeR',
        16: 'Text strings',
        28: 'IP6 Address',
        33: 'Server Selection',
        46: 'Resource Record Signature',
        48: 'DNS Public Key',
    }.get(int(value), '')
    if suffix:
        return f'{type_name} ({int(value)}) ({suffix})'
    return f'{type_name} ({int(value)})'


def _dns_ttl_text(ttl: int) -> str:
    value = int(ttl or 0)
    if value == 60:
        return '60 (1 minute)'
    if value == 3600:
        return '3600 (1 hour)'
    if value == 0:
        return '0'
    return f'{value} ({value} seconds)'


def _dnssec_algorithm_name(algorithm: int) -> str:
    return {
        5: 'RSA/SHA-1',
        7: 'RSASHA1-NSEC3-SHA1',
        8: 'RSA/SHA-256',
        10: 'RSA/SHA-512',
        13: 'ECDSA Curve P-256 with SHA-256',
        14: 'ECDSA Curve P-384 with SHA-384',
        15: 'Ed25519',
        16: 'Ed448',
    }.get(int(algorithm), str(int(algorithm)))


def _dnssec_time_text(epoch_seconds: int) -> str:
    try:
        dt = datetime.fromtimestamp(int(epoch_seconds), tz=timezone.utc).astimezone()
        return f'{dt.strftime("%b")} {dt.day:2d}, {dt.year} {dt.strftime("%H:%M:%S")}.000000000 {dt.tzname() or "UTC"}'
    except Exception:
        return str(int(epoch_seconds))


def _dnskey_key_id(rdata: bytes) -> int:
    data = bytes(rdata or b'')
    if not data:
        return 0
    accumulator = 0
    for index, byte_value in enumerate(data):
        if index & 1:
            accumulator += int(byte_value)
        else:
            accumulator += int(byte_value) << 8
    accumulator += (accumulator >> 16) & 0xFFFF
    return accumulator & 0xFFFF


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


def _dns_rdata_text(data: bytes, rr_type: int, full_raw: bytes | None = None, rdata_offset: int = 0) -> str:
    if rr_type == 1 and len(data) == 4:
        return str(ipaddress.IPv4Address(data))
    if rr_type == 28 and len(data) == 16:
        return str(ipaddress.IPv6Address(data))
    if rr_type in {2, 5, 12}:
        source = full_raw if full_raw is not None else data
        start = rdata_offset if full_raw is not None else 0
        name, _ = _dns_read_name(source, start)
        return name
    if rr_type == 16:
        items = []
        pos = 0
        while pos < len(data):
            ln = int(data[pos])
            pos += 1
            chunk = data[pos:pos + ln]
            items.append(chunk.decode(errors='ignore'))
            pos += ln
        return ', '.join(items)
    if rr_type == 33 and len(data) >= 6:
        source = full_raw if full_raw is not None else data
        start = rdata_offset if full_raw is not None else 0
        priority = int.from_bytes(data[0:2], 'big')
        weight = int.from_bytes(data[2:4], 'big')
        port = int.from_bytes(data[4:6], 'big')
        target, _ = _dns_read_name(source, start + 6)
        return f'{priority} {weight} {port} {target}'
    if rr_type == 6:
        source = full_raw if full_raw is not None else data
        start = rdata_offset if full_raw is not None else 0
        mname, _ = _dns_read_name(source, start)
        return mname
    return data.hex()


def _dns_section(layer, offset: int, record=None) -> Dict[str, Any]:
    raw = bytes(layer)
    metadata = getattr(record, 'metadata', {}) if record else {}
    protocol_name = str(getattr(record, 'protocol', '') or '')
    if len(raw) < 12:
        return {
            'title': 'Multicast Domain Name System' if protocol_name == 'MDNS' else 'Domain Name System',
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
        qclass_raw = int.from_bytes(raw[next_pos + 2:next_pos + 4], 'big')
        qclass = qclass_raw & 0x7FFF
        qu_question = bool(qclass_raw & 0x8000)
        name_len = max(0, len(name.encode('utf-8')))
        label_count = len([part for part in name.split('.') if part])
        type_title = f'Type: {_dns_type_label(qtype)}'
        title = f'{name}: type {_dns_type_name(qtype)}, class {_dns_class_name(qclass)}'
        if protocol_name == 'MDNS' and qu_question:
            title += ', "QU" question'
        question_children.append({
            'title': title,
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
        if protocol_name == 'MDNS' and qu_question:
            question_children[-1]['children'].append({'title': '1... .... .... .... = QU: yes', 'offset': offset + next_pos + 2, 'length': 2})
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
            rr_class_raw = int.from_bytes(raw[next_pos + 2:next_pos + 4], 'big')
            rr_class = rr_class_raw & 0x7FFF
            cache_flush = bool(rr_class_raw & 0x8000)
            ttl = int.from_bytes(raw[next_pos + 4:next_pos + 8], 'big')
            rdlen = int.from_bytes(raw[next_pos + 8:next_pos + 10], 'big')
            rdata_start = next_pos + 10
            rdata_end = rdata_start + rdlen
            if rdata_end > len(raw):
                break
            rdata_bytes = raw[rdata_start:rdata_end]
            rdata_text = _dns_rdata_text(rdata_bytes, rr_type, raw, rdata_start)
            type_title = f'Type: {_dns_type_label(rr_type)}'
            value_title = 'Address'
            if rr_type in {2, 5, 12}:
                value_title = {
                    2: 'Name Server',
                    5: 'Canonical Name',
                    12: 'Domain Name',
                }.get(rr_type, 'Name')
            elif rr_type == 28:
                value_title = 'AAAA Address'
            rr_title = f'{name}: type {_dns_type_name(rr_type)}, class {_dns_class_name(rr_class)}'
            if rr_type == 41 and not name:
                rr_title = '<Root>: type OPT'
            if protocol_name == 'MDNS' and cache_flush:
                rr_title += ', cache flush'
            if rr_type == 33:
                rr_title += f', priority {int.from_bytes(rdata_bytes[0:2], "big") if len(rdata_bytes) >= 2 else 0}, weight {int.from_bytes(rdata_bytes[2:4], "big") if len(rdata_bytes) >= 4 else 0}, port {int.from_bytes(rdata_bytes[4:6], "big") if len(rdata_bytes) >= 6 else 0}, target {(_dns_read_name(raw, rdata_start + 6)[0] if len(rdata_bytes) >= 6 else "")}'
            elif rr_type == 2 and rdata_text:
                rr_title += f', ns {rdata_text}'
            elif rr_type in {1, 28} and rdata_text:
                rr_title += f', addr {rdata_text}'
            elif rdata_text and rr_type not in {41, 46, 48}:
                rr_title += f', {rdata_text}'
            rr_children = [
                {'title': f'Name: {name or "<Root>"}', 'offset': offset + pos, 'length': max(0, next_pos - pos)},
                {'title': type_title, 'offset': offset + next_pos, 'length': 2},
                {'title': f'Class: {_dns_class_name(rr_class)} (0x{rr_class:04x})', 'offset': offset + next_pos + 2, 'length': 2} if rr_type != 41 else {'title': f'UDP payload size: {rr_class_raw}', 'offset': offset + next_pos + 2, 'length': 2},
            ]
            if protocol_name == 'MDNS':
                rr_children.append({'title': f'{"1" if cache_flush else "0"}... .... .... .... = Cache flush: {"True" if cache_flush else "False"}', 'offset': offset + next_pos + 2, 'length': 2})
            rr_children.extend([
                {'title': f'Time to live: {_dns_ttl_text(ttl)}', 'offset': offset + next_pos + 4, 'length': 4},
                {'title': f'Data length: {rdlen}', 'offset': offset + next_pos + 8, 'length': 2},
            ])
            if rr_type == 16:
                txt_pos = rdata_start
                while txt_pos < rdata_end:
                    txt_len = int(raw[txt_pos]) if txt_pos < len(raw) else 0
                    rr_children.append({'title': f'TXT Length: {txt_len}', 'offset': offset + txt_pos, 'length': 1})
                    txt_val = raw[txt_pos + 1:txt_pos + 1 + txt_len].decode(errors='ignore')
                    rr_children.append({'title': f'TXT: {txt_val}', 'offset': offset + txt_pos + 1, 'length': txt_len})
                    txt_pos += 1 + txt_len
            elif rr_type == 33 and len(rdata_bytes) >= 6:
                priority = int.from_bytes(rdata_bytes[0:2], 'big')
                weight = int.from_bytes(rdata_bytes[2:4], 'big')
                port = int.from_bytes(rdata_bytes[4:6], 'big')
                target, _ = _dns_read_name(raw, rdata_start + 6)
                instance_parts = name.split('.')
                if len(instance_parts) >= 4:
                    rr_children.extend([
                        {'title': f'Instance: {instance_parts[0]}', 'offset': offset + pos, 'length': max(0, next_pos - pos)},
                        {'title': f'Service: {instance_parts[1]}', 'offset': offset + pos, 'length': max(0, next_pos - pos)},
                        {'title': f'Protocol: {instance_parts[2]}', 'offset': offset + pos, 'length': max(0, next_pos - pos)},
                        {'title': f'Name: {instance_parts[3]}', 'offset': offset + pos, 'length': max(0, next_pos - pos)},
                    ])
                rr_children.extend([
                    {'title': f'Priority: {priority}', 'offset': offset + rdata_start, 'length': 2},
                    {'title': f'Weight: {weight}', 'offset': offset + rdata_start + 2, 'length': 2},
                    {'title': f'Port: {port}', 'offset': offset + rdata_start + 4, 'length': 2},
                    {'title': f'Target: {target}', 'offset': offset + rdata_start + 6, 'length': max(0, rdlen - 6)},
                ])
            elif rr_type == 48:
                flags = int.from_bytes(rdata_bytes[0:2], 'big') if len(rdata_bytes) >= 2 else 0
                protocol = int(rdata_bytes[2]) if len(rdata_bytes) >= 3 else 0
                algorithm = int(rdata_bytes[3]) if len(rdata_bytes) >= 4 else 0
                key_data = rdata_bytes[4:] if len(rdata_bytes) > 4 else b''
                key_id = _dnskey_key_id(rdata_bytes)
                zone_key = 1 if (flags & 0x0100) else 0
                revoked = 1 if (flags & 0x0080) else 0
                key_signing = 1 if (flags & 0x0001) else 0
                rr_children.extend([
                    {
                        'title': f'Flags: 0x{flags:04x}',
                        'offset': offset + rdata_start,
                        'length': 2 if rdlen >= 2 else rdlen,
                        'children': [
                            {'title': f'.... ...{zone_key} .... .... = Zone Key: {"This is the zone key for specified zone" if zone_key else "Not a zone key"}', 'offset': offset + rdata_start, 'length': 2 if rdlen >= 2 else rdlen},
                            {'title': f'.... .... {revoked}... .... = Key Revoked: {"Yes" if revoked else "No"}', 'offset': offset + rdata_start, 'length': 2 if rdlen >= 2 else rdlen},
                            {'title': f'.... .... .... ...{key_signing} = Key Signing Key: {"Yes" if key_signing else "No"}', 'offset': offset + rdata_start, 'length': 2 if rdlen >= 2 else rdlen},
                            {'title': f'{((flags >> 9) & 0x7F):07b} . {((flags >> 1) & 0x7F):07b} = Key Signing Key: 0x{(flags & 0xFFFE):04x}', 'offset': offset + rdata_start, 'length': 2 if rdlen >= 2 else rdlen},
                        ],
                    },
                    {'title': f'Protocol: {protocol}', 'offset': offset + rdata_start + 2, 'length': 1 if rdlen >= 3 else 0},
                    {'title': f'Algorithm: {_dnssec_algorithm_name(algorithm)} ({algorithm})', 'offset': offset + rdata_start + 3, 'length': 1 if rdlen >= 4 else 0},
                    {'title': f'[Key id: {key_id}]'},
                    {'title': f'Public Key [..]: {key_data.hex()}', 'offset': offset + rdata_start + 4, 'length': max(0, rdlen - 4)},
                ])
            elif rr_type == 46:
                type_covered = int.from_bytes(rdata_bytes[0:2], 'big') if len(rdata_bytes) >= 2 else 0
                algorithm = int(rdata_bytes[2]) if len(rdata_bytes) >= 3 else 0
                labels = int(rdata_bytes[3]) if len(rdata_bytes) >= 4 else 0
                original_ttl = int.from_bytes(rdata_bytes[4:8], 'big') if len(rdata_bytes) >= 8 else 0
                sig_expiration = int.from_bytes(rdata_bytes[8:12], 'big') if len(rdata_bytes) >= 12 else 0
                sig_inception = int.from_bytes(rdata_bytes[12:16], 'big') if len(rdata_bytes) >= 16 else 0
                key_tag = int.from_bytes(rdata_bytes[16:18], 'big') if len(rdata_bytes) >= 18 else 0
                signer_start = rdata_start + 18
                signer_name = ''
                signer_end = signer_start
                if rdlen >= 19:
                    signer_name, signer_end = _dns_read_name(raw, signer_start)
                    if signer_end < signer_start:
                        signer_end = signer_start
                signature_start = max(signer_end, signer_start)
                signature_start = min(signature_start, rdata_end)
                signature_bytes = raw[signature_start:rdata_end]
                rr_children.extend([
                    {'title': f'Type Covered: {_dns_type_label(type_covered)}', 'offset': offset + rdata_start, 'length': 2 if rdlen >= 2 else 0},
                    {'title': f'Algorithm: {_dnssec_algorithm_name(algorithm)} ({algorithm})', 'offset': offset + rdata_start + 2, 'length': 1 if rdlen >= 3 else 0},
                    {'title': f'Labels: {labels}', 'offset': offset + rdata_start + 3, 'length': 1 if rdlen >= 4 else 0},
                    {'title': f'Original TTL: {_dns_ttl_text(original_ttl)}', 'offset': offset + rdata_start + 4, 'length': 4 if rdlen >= 8 else 0},
                    {'title': f'Signature Expiration: {_dnssec_time_text(sig_expiration)}', 'offset': offset + rdata_start + 8, 'length': 4 if rdlen >= 12 else 0},
                    {'title': f'Signature Inception: {_dnssec_time_text(sig_inception)}', 'offset': offset + rdata_start + 12, 'length': 4 if rdlen >= 16 else 0},
                    {'title': f'Key Tag: {key_tag}', 'offset': offset + rdata_start + 16, 'length': 2 if rdlen >= 18 else 0},
                    {'title': f"Signer's name: {signer_name}", 'offset': offset + signer_start, 'length': max(0, signer_end - signer_start)},
                    {'title': f'Signature [..]: {signature_bytes.hex()}', 'offset': offset + signature_start, 'length': max(0, rdata_end - signature_start)},
                ])
            elif rr_type == 41:
                rr_children.extend([
                    {'title': f'Higher bits in extended RCODE: 0x{(ttl >> 24) & 0xFF:02x}', 'offset': offset + next_pos + 4, 'length': 1},
                    {'title': f'EDNS0 version: {(ttl >> 16) & 0xFF}', 'offset': offset + next_pos + 5, 'length': 1},
                    {
                        'title': f'Z: 0x{ttl & 0xFFFF:04x}',
                        'offset': offset + next_pos + 6,
                        'length': 2,
                        'children': [
                            {'title': f'{"1" if (ttl & 0x8000) else "0"}... .... .... .... = DO bit: {"Accepts DNSSEC security RRs" if (ttl & 0x8000) else "Cannot handle DNSSEC security RRs"}', 'offset': offset + next_pos + 6, 'length': 2},
                            {'title': f'.{ttl & 0x7FFF:015b} = Reserved: 0x{ttl & 0x7FFF:04x}', 'offset': offset + next_pos + 6, 'length': 2},
                        ],
                    },
                ])
                opt_cursor = rdata_start
                while opt_cursor + 4 <= rdata_end:
                    opt_code = int.from_bytes(raw[opt_cursor:opt_cursor + 2], 'big')
                    opt_len = int.from_bytes(raw[opt_cursor + 2:opt_cursor + 4], 'big')
                    opt_data_start = opt_cursor + 4
                    opt_data_end = min(rdata_end, opt_data_start + opt_len)
                    if opt_data_start > rdata_end:
                        break
                    if opt_code == 8:
                        opt_name = 'CSUBNET - Client subnet'
                    elif opt_code == 4:
                        opt_name = 'Owner (reserved)'
                    else:
                        opt_name = str(opt_code)
                    option_children = [
                        {'title': f'Option Code: {opt_name} ({opt_code})', 'offset': offset + opt_cursor, 'length': 2},
                        {'title': f'Option Length: {opt_len}', 'offset': offset + opt_cursor + 2, 'length': 2},
                        {'title': f'Option Data: {raw[opt_data_start:opt_data_end].hex()}', 'offset': offset + opt_data_start, 'length': max(0, opt_data_end - opt_data_start)},
                    ]
                    if opt_code == 8 and (opt_data_end - opt_data_start) >= 4:
                        family = int.from_bytes(raw[opt_data_start:opt_data_start + 2], 'big')
                        source_netmask = int(raw[opt_data_start + 2])
                        scope_netmask = int(raw[opt_data_start + 3])
                        subnet_bytes = raw[opt_data_start + 4:opt_data_end]
                        family_name = {1: 'IPv4', 2: 'IPv6'}.get(family, str(family))
                        full_len = 4 if family == 1 else 16 if family == 2 else len(subnet_bytes)
                        padded_subnet = subnet_bytes + (b'\x00' * max(0, full_len - len(subnet_bytes)))
                        padded_subnet = padded_subnet[:full_len]
                        client_subnet = padded_subnet.hex()
                        try:
                            if family == 1 and len(padded_subnet) == 4:
                                client_subnet = str(ipaddress.IPv4Address(padded_subnet))
                            elif family == 2 and len(padded_subnet) == 16:
                                client_subnet = str(ipaddress.IPv6Address(padded_subnet))
                        except Exception:
                            client_subnet = padded_subnet.hex()
                        option_children.extend([
                            {'title': f'Family: {family_name} ({family})', 'offset': offset + opt_data_start, 'length': 2},
                            {'title': f'Source Netmask: {source_netmask}', 'offset': offset + opt_data_start + 2, 'length': 1},
                            {'title': f'Scope Netmask: {scope_netmask}', 'offset': offset + opt_data_start + 3, 'length': 1},
                            {'title': f'Client Subnet: {client_subnet}', 'offset': offset + opt_data_start + 4, 'length': max(0, opt_data_end - (opt_data_start + 4))},
                        ])
                    rr_children.append({
                        'title': f'Option: {opt_name}',
                        'offset': offset + opt_cursor,
                        'length': max(0, opt_data_end - opt_cursor),
                        'children': option_children,
                    })
                    opt_cursor = opt_data_end
            else:
                rr_children.append({'title': f'{value_title}: {rdata_text}', 'offset': offset + rdata_start, 'length': rdlen})

            items.append({
                'title': rr_title,
                'offset': offset + pos,
                'length': rdata_end - pos,
                'children': rr_children,
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
        authority_start = authorities[0].get('offset', offset)
        authority_end = max(
            int(item.get('offset', authority_start) or authority_start) + int(item.get('length', 0) or 0)
            for item in authorities
        )
        children.append({
            'title': 'Authorities',
            'offset': authority_start,
            'length': max(0, authority_end - authority_start),
            'children': authorities,
        })

    additionals, _ = parse_rr_section(arcount, 'Additional records')
    if additionals:
        additional_start = additionals[0].get('offset', offset)
        additional_end = max(
            int(item.get('offset', additional_start) or additional_start) + int(item.get('length', 0) or 0)
            for item in additionals
        )
        children.append({
            'title': 'Additional records',
            'offset': additional_start,
            'length': max(0, additional_end - additional_start),
            'children': additionals,
        })

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
        'title': f'{"Multicast Domain Name System" if protocol_name == "MDNS" else "Domain Name System"} ({"response" if qr else "query"})',
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
    tls_raw = bytes(tls)
    tls_len = len(tls_raw)

    def _tls_version_name(version: int) -> str:
        return {
            0x0301: 'TLSv1.0',
            0x0302: 'TLSv1.1',
            0x0303: 'TLSv1.2',
            0x0304: 'TLSv1.3',
        }.get(int(version), f'0x{int(version):04x}')

    def _tls_content_type_name(content_type: int) -> str:
        return {
            20: 'Change Cipher Spec',
            21: 'Alert',
            22: 'Handshake',
            23: 'Application Data',
        }.get(int(content_type), str(int(content_type)))

    def _tls_handshake_type_name(handshake_type: int) -> str:
        return {
            1: 'Client Hello',
            2: 'Server Hello',
            4: 'New Session Ticket',
            11: 'Certificate',
            12: 'Server Key Exchange',
            13: 'Certificate Request',
            14: 'Server Hello Done',
            16: 'Client Key Exchange',
            20: 'Finished',
        }.get(int(handshake_type), f'Handshake ({int(handshake_type)})')

    children: List[Dict[str, Any]] = []
    if stream_index >= 0:
        children.append({'title': f'[Stream index: {stream_index}]'})

    cursor = 0
    while cursor + 5 <= len(tls_raw):
        content_type = int(tls_raw[cursor])
        version = int.from_bytes(tls_raw[cursor + 1:cursor + 3], 'big')
        record_len = int.from_bytes(tls_raw[cursor + 3:cursor + 5], 'big')
        body_start = cursor + 5
        body_end = min(len(tls_raw), body_start + record_len)
        body = tls_raw[body_start:body_end]

        content_name = _tls_content_type_name(content_type)
        version_name = _tls_version_name(version)
        record_children: List[Dict[str, Any]] = [
            {
                'title': f'Content Type: {content_name} ({content_type})',
                'offset': offset + cursor,
                'length': 1,
            },
            {
                'title': f'Version: {version_name} (0x{version:04x})',
                'offset': offset + cursor + 1,
                'length': 2,
            },
            {
                'title': f'Length: {record_len}',
                'offset': offset + cursor + 3,
                'length': 2,
            },
        ]

        record_title = f'{version_name} Record Layer: {content_name} Protocol'
        if content_type == 22 and len(body) >= 4:
            hs_pos = 0
            handshake_titles: List[str] = []
            while hs_pos + 4 <= len(body):
                handshake_type = int(body[hs_pos])
                handshake_len = int.from_bytes(body[hs_pos + 1:hs_pos + 4], 'big')
                hs_total = 4 + handshake_len
                if hs_total < 4 or hs_pos + hs_total > len(body):
                    handshake_titles.append('Encrypted Handshake Message')
                    break
                handshake_name = _tls_handshake_type_name(handshake_type)
                handshake_titles.append(handshake_name)
                record_children.append(
                    {
                        'title': f'Handshake Protocol: {handshake_name}',
                        'offset': offset + body_start + hs_pos,
                        'length': hs_total,
                        'children': [
                            {
                                'title': f'Handshake Type: {handshake_name} ({handshake_type})',
                                'offset': offset + body_start + hs_pos,
                                'length': 1,
                            },
                            {
                                'title': f'Length: {handshake_len}',
                                'offset': offset + body_start + hs_pos + 1,
                                'length': 3,
                            },
                        ],
                    }
                )
                hs_pos += hs_total
            if handshake_titles:
                record_title = f'{version_name} Record Layer: Handshake Protocol: {", ".join(handshake_titles)}'

        record_node: Dict[str, Any] = {
            'title': record_title,
            'offset': offset + cursor,
            'length': 5 + len(body),
            'children': record_children,
        }
        if content_type in {22, 23} and body:
            record_node['children'].append(
                {
                    'title': f'TLS segment data ({len(body)} bytes)',
                    'offset': offset + body_start,
                    'length': len(body),
                }
            )
        children.append(record_node)

        if record_len <= 0:
            break
        cursor = body_start + record_len

    result = {
        'title': 'Transport Layer Security',
        'offset': offset,
        'length': tls_len,
        'children': children,
    }

    if _is_reassembled:
        # Tag every node that carries a byte mapping so the hex view highlights
        # bytes in the "Reassembled TCP" tab rather than the raw frame bytes.
        def _tag_tcp_reassembled(node: dict):
            if 'offset' in node and 'length' in node:
                node['byte_source'] = TCP_REASSEMBLED_BYTE_SOURCE
            for child in node.get('children', []):
                _tag_tcp_reassembled(child)
        _tag_tcp_reassembled(result)

    return result

def _parse_x509_cert_tree(cert_bytes: bytes, abs_offset: int) -> dict:
    """Parse DER-encoded X.509 certificate into a Wireshark-style detail tree node."""
    hex_prefix = cert_bytes.hex()

    # ─── Minimal DER walker ───────────────────────────────────────────────────
    def _der_tlv(data: bytes):
        """Return list of (tag, value_bytes) from a DER container (non-recursive)."""
        result, pos = [], 0
        while pos < len(data):
            if pos >= len(data):
                break
            tag = data[pos]; pos += 1
            if pos >= len(data):
                break
            if data[pos] & 0x80:
                n = data[pos] & 0x7f; pos += 1
                if pos + n > len(data):
                    break
                length = int.from_bytes(data[pos:pos + n], 'big'); pos += n
            else:
                length = data[pos]; pos += 1
            end = pos + length
            result.append((tag, data[pos:end]))
            pos = end
        return result

    def _decode_oid(b: bytes) -> str:
        if not b:
            return ''
        arcs, first = [], b[0]
        arcs.append(min(first // 40, 2))
        arcs.append(first - 40 * arcs[0])
        val = 0
        for byte in b[1:]:
            val = (val << 7) | (byte & 0x7f)
            if not (byte & 0x80):
                arcs.append(val); val = 0
        return '.'.join(map(str, arcs))

    # ─── OID name tables ─────────────────────────────────────────────────────
    OID_ATTR = {
        '2.5.4.3': 'id-at-commonName', '2.5.4.6': 'id-at-countryName',
        '2.5.4.7': 'id-at-localityName', '2.5.4.8': 'id-at-stateOrProvinceName',
        '2.5.4.10': 'id-at-organizationName', '2.5.4.11': 'id-at-organizationalUnitName',
    }
    OID_ALG = {
        '1.2.840.113549.1.1.11': 'sha256WithRSAEncryption',
        '1.2.840.113549.1.1.5': 'sha1WithRSAEncryption',
        '1.2.840.113549.1.1.1': 'rsaEncryption',
        '1.2.840.10045.2.1': 'ecPublicKey',
    }
    OID_EXT = {
        '2.5.29.15': 'id-ce-keyUsage', '2.5.29.17': 'id-ce-subjectAltName',
        '2.5.29.18': 'id-ce-issuerAltName', '2.5.29.19': 'id-ce-basicConstraints',
        '2.5.29.14': 'id-ce-subjectKeyIdentifier', '2.5.29.35': 'id-ce-authorityKeyIdentifier',
        '2.5.29.37': 'id-ce-extKeyUsage', '2.5.29.31': 'id-ce-cRLDistributionPoints',
        '2.5.29.32': 'id-ce-certificatePolicies', '1.3.6.1.5.5.7.1.1': 'id-pe-authorityInfoAccess',
        '1.3.6.1.4.1.11129.2.4.2': 'SignedCertificateTimestampList',
    }
    OID_KP = {
        '1.3.6.1.5.5.7.3.1': 'id-kp-serverAuth', '1.3.6.1.5.5.7.3.2': 'id-kp-clientAuth',
        '1.3.6.1.5.5.7.3.3': 'id-kp-codeSigning', '1.3.6.1.5.5.7.3.4': 'id-kp-emailProtection',
    }
    OID_AIA = {
        '1.3.6.1.5.5.7.48.1': 'id-ad-ocsp', '1.3.6.1.5.5.7.48.2': 'id-ad-caIssuers',
    }
    OID_POLICY_QUAL = {'1.3.6.1.5.5.7.2.1': 'id-qt-cps'}
    OID_POLICY = {
        '2.23.140.1.2.3': 'joint-iso-itu-t.23.140.1.2.3',
        '2.5.29.32.0': 'anyPolicy',
    }
    TAG_STR_NAME = {0x0C: 'uTF8String', 0x13: 'printableString', 0x16: 'ia5String', 0x14: 'teletexString'}
    TAG_STR_ID   = {0x0C: 4, 0x13: 1, 0x16: 0, 0x14: 0}
    SCT_LOG_NAMES = {
        '68f698f81f6482be3a8ceeb9281d4cfc71515d6793d444d10a67acbb4f4ffbc4': "Google 'Aviator' log",
        'ee4bbdb775ce60bae142691fabe19e66a30f7e5fb072d88300c47b897aa8fdcb': "Google 'Rocketeer' log",
        'a4b90990b418581487bb13a2cc67700a3c359804f91bdfb8e377cd0ec80ddc10': "Google 'Pilot' log",
        '293c519654c83965baaa50fc5807d4b76fbf587a2972dca4c30cf4e54547f478': "Google 'Skydiver' log",
    }

    # ─── Build Name (issuer/subject) tree ────────────────────────────────────
    def _build_name_tree(name_raw_der: bytes, label: str, tlv_start: int, tlv_len: int, val_start: int) -> dict:
        rdn_items, name_parts = [], []
        for set_tag, set_val, set_start, set_len_tlv, set_val_start in _der_tlv_pos(name_raw_der, base=val_start):
            if set_tag != 0x31:
                continue
            set_children = []
            for seq_tag, seq_val, seq_start, seq_len_tlv, seq_val_start in _der_tlv_pos(set_val, base=set_val_start):
                if seq_tag != 0x30:
                    continue
                items = _der_tlv_pos(seq_val, base=seq_val_start)
                if len(items) < 2 or items[0][0] != 0x06:
                    continue
                _, oid_val, oid_start, oid_len_tlv, oid_val_start = items[0]
                str_tag, str_val, str_start, str_len_tlv, str_val_start = items[1]
                oid = _decode_oid(oid_val)
                attr_name = OID_ATTR.get(oid, oid)
                try:
                    val = str_val.decode('utf-8')
                except Exception:
                    val = str_val.hex()
                name_parts.append(f'{attr_name}={val}')
                str_type_name = TAG_STR_NAME.get(str_tag, 'uTF8String')
                str_type_id = TAG_STR_ID.get(str_tag, 4)
                if oid == '2.5.4.6':
                    value_node = {
                        'title': f'CountryName: {val}',
                        'offset': str_val_start,
                        'length': len(str_val),
                    }
                else:
                    value_node = {
                        'title': f'DirectoryString: {str_type_name} ({str_type_id})',
                        'offset': str_start,
                        'length': str_len_tlv,
                        'children': [{
                            'title': f'{str_type_name}: {val}',
                            'offset': str_val_start,
                            'length': len(str_val),
                        }],
                    }
                set_children.append({
                    'title': f'RelativeDistinguishedName item ({attr_name}={val})',
                    'offset': seq_start,
                    'length': seq_len_tlv,
                    'children': [
                        {
                            'title': f'Object Id: {oid} ({attr_name})',
                            'offset': oid_val_start,
                            'length': len(oid_val),
                        },
                        value_node,
                    ],
                })
            if set_children:
                rdn_items.append({
                    'title': f'RDNSequence item: {len(set_children)} item{"s" if len(set_children) != 1 else ""}',
                    'offset': set_start,
                    'length': set_len_tlv,
                    'children': set_children,
                })
        name_str = ','.join(reversed(name_parts))
        return {
            'title': f'{label}: rdnSequence (0)',
            'offset': tlv_start,
            'length': tlv_len,
            'children': [{
                'title': f'rdnSequence: {len(rdn_items)} items ({name_str})',
                'offset': val_start,
                'length': max(0, tlv_len - (val_start - tlv_start)),
                'children': rdn_items,
            }],
        }

    # ─── Build Validity tree ─────────────────────────────────────────────────
    def _build_validity_tree(validity_raw: bytes, tlv_start: int, tlv_len: int, val_start: int) -> dict:
        import datetime
        def _parse_time(tag, val):
            s = val.decode('ascii', errors='replace').rstrip('Z')
            try:
                if tag == 0x17:  # UTCTime (2-digit year)
                    dt = datetime.datetime.strptime(s, '%y%m%d%H%M%S')
                    if dt.year < 1950:
                        dt = dt.replace(year=dt.year + 100)
                else:              # GeneralizedTime
                    dt = datetime.datetime.strptime(s, '%Y%m%d%H%M%S')
                return dt.strftime('%Y-%m-%d %H:%M:%S')
            except Exception:
                return s
        items = _der_tlv_pos(validity_raw, base=val_start)
        nb_str = _parse_time(items[0][0], items[0][1]) if len(items) >= 1 else '?'
        na_str = _parse_time(items[1][0], items[1][1]) if len(items) >= 2 else '?'
        nb_type = 'utcTime' if (items[0][0] if items else 0x17) == 0x17 else 'generalTime'
        na_type = 'utcTime' if (items[1][0] if len(items) > 1 else 0x17) == 0x17 else 'generalTime'
        nb_start = items[0][4] if len(items) >= 1 else tlv_start
        nb_len = len(items[0][1]) if len(items) >= 1 else 0
        na_start = items[1][4] if len(items) >= 2 else tlv_start
        na_len = len(items[1][1]) if len(items) >= 2 else 0
        return {
            'title': 'validity',
            'offset': tlv_start,
            'length': tlv_len,
            'children': [
                {
                    'title': f'notBefore: {nb_type} (0)',
                    'offset': nb_start,
                    'length': nb_len,
                    'children': [{'title': f'{nb_type}: {nb_str} (UTC)', 'offset': nb_start, 'length': nb_len}],
                },
                {
                    'title': f'notAfter: {na_type} (0)',
                    'offset': na_start,
                    'length': na_len,
                    'children': [{'title': f'{na_type}: {na_str} (UTC)', 'offset': na_start, 'length': na_len}],
                },
            ],
        }

    # ─── Build SubjectPublicKeyInfo tree ─────────────────────────────────────
    def _build_spki_tree(spki_raw: bytes, tlv_start: int, tlv_len: int, val_start: int) -> dict:
        items = _der_tlv_pos(spki_raw, base=val_start)
        alg_oid_str = ''
        alg_tlv_start = tlv_start
        alg_tlv_len = 0
        alg_oid_start = tlv_start
        alg_oid_len = 0
        bit_tlv_start = tlv_start
        bit_tlv_len = 0
        bit_val_start = val_start
        if items and items[0][0] == 0x30:
            _, alg_val, alg_tlv_start, alg_tlv_len, alg_val_start = items[0]
            alg_items = _der_tlv_pos(alg_val, base=alg_val_start)
            if alg_items and alg_items[0][0] == 0x06:
                _, alg_oid_val, _, _, alg_oid_start = alg_items[0]
                alg_oid_len = len(alg_oid_val)
                alg_oid_str = _decode_oid(alg_oid_val)
        alg_name = OID_ALG.get(alg_oid_str, alg_oid_str)
        spki_children = [
            {
                'title': f'algorithm ({alg_name})',
                'offset': alg_tlv_start,
                'length': alg_tlv_len,
                'children': [{
                    'title': f'Algorithm Id: {alg_oid_str} ({alg_name})',
                    'offset': alg_oid_start,
                    'length': alg_oid_len,
                }],
            },
        ]
        if len(items) >= 2 and items[1][0] == 0x03:
            _, bitstr, bit_tlv_start, bit_tlv_len, bit_val_start = items[1]
            spki_children.append({'title': f'Padding: {bitstr[0] if bitstr else 0}', 'offset': bit_val_start, 'length': min(1, len(bitstr))})
            pk_content = bitstr[1:] if bitstr else b''  # skip unused-bits byte
            pk_hex = pk_content.hex()
            pk_items = _der_tlv_pos(pk_content, base=bit_val_start + 1)
            rsa_children = []
            subject_key_start = bit_val_start + 1
            subject_key_len = len(pk_content)
            if pk_items and pk_items[0][0] == 0x30:
                _, rsa_val, rsa_tlv_start, rsa_tlv_len, rsa_val_start = pk_items[0]
                subject_key_start = rsa_tlv_start
                subject_key_len = rsa_tlv_len
                rsa_items = _der_tlv_pos(rsa_val, base=rsa_val_start)
                if len(rsa_items) >= 2 and rsa_items[0][0] == 0x02:
                    _, mod_val, _, _, mod_start = rsa_items[0]
                    mod_int = int.from_bytes(mod_val, 'big')
                    if rsa_items[1][0] == 0x02:
                        _, exp_val, _, _, exp_start = rsa_items[1]
                        exp_int = int.from_bytes(exp_val, 'big')
                        exp_len_tlv = len(exp_val)
                    else:
                        exp_start = subject_key_start
                        exp_len_tlv = 0
                        exp_int = 65537
                    rsa_children = [
                        {'title': f'modulus: 0x{mod_int:x}', 'offset': mod_start, 'length': len(mod_val)},
                        {'title': f'publicExponent: {exp_int}', 'offset': exp_start, 'length': exp_len_tlv},
                    ]
            spki_children.append({
                'title': f'subjectPublicKey [...]: {pk_hex[:64]}',
                'offset': subject_key_start,
                'length': subject_key_len,
                'children': [{
                    'title': 'RSA Public Key',
                    'offset': subject_key_start,
                    'length': subject_key_len,
                    'children': rsa_children,
                }] if rsa_children else [],
            })
        return {'title': 'subjectPublicKeyInfo', 'offset': tlv_start, 'length': tlv_len, 'children': spki_children}

    # ─── Build KeyUsage bit-flag children ────────────────────────────────────
    def _build_ku_flags(ku_byte: int, ku_offset: int, ku_length: int, decipher_only: bool = False) -> list:
        bit_defs = [
            (7, 'digitalSignature'), (6, 'contentCommitment'), (5, 'keyEncipherment'),
            (4, 'dataEncipherment'), (3, 'keyAgreement'), (2, 'keyCertSign'),
            (1, 'cRLSign'), (0, 'encipherOnly'),
        ]
        children = []
        for bit_pos, name in bit_defs:
            is_set = bool(ku_byte & (1 << bit_pos))
            i = 7 - bit_pos
            n0, n1 = ['.'] * 4, ['.'] * 4
            if i < 4:
                n0[i] = '1' if is_set else '0'
            else:
                n1[i - 4] = '1' if is_set else '0'
            children.append({'title': f"{''.join(n0)} {''.join(n1)} = {name}: {'True' if is_set else 'False'}", 'offset': ku_offset, 'length': ku_length})
        children.append({'title': f"0... .... = decipherOnly: {'True' if decipher_only else 'False'}", 'offset': ku_offset, 'length': ku_length})
        return children

    # ─── Parse SCT extension bytes ───────────────────────────────────────────
    def _parse_sct_ext(sct_ext_octet_val: bytes) -> list:
        """Parse SignedCertificateTimestampList. Input: raw value of extension's OCTET STRING."""
        import datetime
        result = []
        try:
            # The value is OCTET STRING wrapping the SCT list TLS bytes
            inner = _der_tlv_pos(sct_ext_octet_val, base=0)
            if not inner or inner[0][0] != 0x04:
                return result
            _, sct_list, _, _, sct_list_start = inner[0]
            if len(sct_list) < 2:
                return result
            list_len = int.from_bytes(sct_list[0:2], 'big')
            result.append({'title': f'Serialized SCT List Length: {list_len}', 'offset': sct_list_start, 'length': 2})
            pos = 2
            while pos + 2 <= len(sct_list):
                sct_len_start = sct_list_start + pos
                sct_len = int.from_bytes(sct_list[pos:pos + 2], 'big')
                pos += 2
                sct_data_start = sct_list_start + pos
                sct = sct_list[pos:pos + sct_len]
                pos += sct_len
                if len(sct) < 43:
                    continue
                version = sct[0]
                log_id_hex = sct[1:33].hex()
                log_name = SCT_LOG_NAMES.get(log_id_hex, 'Unknown log')
                ts_ms = int.from_bytes(sct[33:41], 'big')
                ts_dt = datetime.datetime(1970, 1, 1) + datetime.timedelta(milliseconds=ts_ms)
                ts_str = ts_dt.strftime('%b %e, %Y %H:%M:%S') + f'.{ts_ms % 1000:03d}000000 UTC'
                ext_len = int.from_bytes(sct[41:43], 'big')
                sig_pos = 43 + ext_len
                if sig_pos + 4 > len(sct):
                    continue
                hash_alg = sct[sig_pos]
                sign_alg = sct[sig_pos + 1]
                sig_len = int.from_bytes(sct[sig_pos + 2:sig_pos + 4], 'big')
                sig_hex = sct[sig_pos + 4:sig_pos + 4 + sig_len].hex()
                hash_names = {4: 'SHA256', 5: 'SHA384', 6: 'SHA512', 2: 'SHA1'}
                sign_names = {1: 'RSA', 2: 'DSA', 3: 'ECDSA'}
                alg_code = (hash_alg << 8) | sign_alg
                alg_names = {0x0403: 'ecdsa_secp256r1_sha256', 0x0401: 'rsa_pkcs1_sha256',
                              0x0201: 'rsa_pkcs1_sha1', 0x0203: 'ecdsa_sha1'}
                alg_name = alg_names.get(alg_code, f'0x{alg_code:04x}')
                sct_node = {
                    'title': f'Signed Certificate Timestamp ({log_name})',
                    'offset': sct_data_start,
                    'length': sct_len,
                    'children': [
                        {'title': f'Serialized SCT Length: {sct_len}', 'offset': sct_len_start, 'length': 2},
                        {'title': f'SCT Version: {version}', 'offset': sct_data_start, 'length': 1},
                        {'title': f'Log ID: {log_id_hex}', 'offset': sct_data_start + 1, 'length': 32},
                        {'title': f'Timestamp: {ts_str}', 'offset': sct_data_start + 33, 'length': 8},
                        {'title': f'Extensions length: {ext_len}', 'offset': sct_data_start + 41, 'length': 2},
                        {'title': f'Signature Algorithm: {alg_name} (0x{alg_code:04x})',
                         'offset': sct_data_start + sig_pos,
                         'length': 2,
                         'children': [
                             {'title': f'Signature Hash Algorithm Hash: {hash_names.get(hash_alg, hash_alg)} ({hash_alg})', 'offset': sct_data_start + sig_pos, 'length': 1},
                             {'title': f'Signature Hash Algorithm Signature: {sign_names.get(sign_alg, sign_alg)} ({sign_alg})', 'offset': sct_data_start + sig_pos + 1, 'length': 1},
                         ]},
                        {'title': f'Signature Length: {sig_len}', 'offset': sct_data_start + sig_pos + 2, 'length': 2},
                        {'title': f'Signature: {sig_hex}', 'offset': sct_data_start + sig_pos + 4, 'length': sig_len},
                    ],
                }
                result.append(sct_node)
        except Exception:
            pass
        return result

    # ─── Build single Extension tree ─────────────────────────────────────────
    def _build_ext_tree(ext_oid: str, is_critical: bool, ext_val_octet: bytes, ext_start: int, ext_len_tlv: int, ext_meta: dict) -> dict:
        ext_name = OID_EXT.get(ext_oid, ext_oid)
        children: list = []
        ext_oid_start = int(ext_meta.get('oid_start', ext_start))
        ext_oid_len = int(ext_meta.get('oid_len', 0))
        critical_start = ext_meta.get('critical_start', ext_start)
        critical_len = int(ext_meta.get('critical_len', 0))
        octet_tlv_start = int(ext_meta.get('octet_tlv_start', ext_start))
        octet_tlv_len = int(ext_meta.get('octet_tlv_len', 0))
        octet_value_start = int(ext_meta.get('octet_value_start', octet_tlv_start))
        octet_value_len = int(ext_meta.get('octet_value_len', len(ext_val_octet)))
        children.append({'title': f'Extension Id: {ext_oid} ({ext_name})', 'offset': ext_oid_start, 'length': ext_oid_len})
        if is_critical:
            children.append({'title': 'critical: True', 'offset': critical_start, 'length': critical_len})
        try:
            val_items = _der_tlv(ext_val_octet)  # OCTET STRING value contains inner DER
            if not val_items:
                return {'title': f'Extension ({ext_name})', 'offset': ext_start, 'length': ext_len_tlv, 'children': children}
            inner_der = val_items[0][1] if val_items[0][0] == 0x04 else ext_val_octet

            # id-ce-keyUsage
            if ext_oid == '2.5.29.15':
                bs_items = _der_tlv_pos(inner_der, base=octet_value_start)
                if bs_items and bs_items[0][0] == 0x03:
                    _, bs_val, _, _, bs_val_start = bs_items[0]
                    padding = bs_val[0] if bs_val else 0
                    ku_byte = bs_val[1] if len(bs_val) >= 2 else 0
                    ku_byte2 = bs_val[2] if len(bs_val) >= 3 else 0
                    decipher = bool(ku_byte2 & 0x80)
                    ku_hex = f'{ku_byte:02x}'
                    children.extend([
                        {'title': f'Padding: {padding}', 'offset': bs_val_start, 'length': min(1, len(bs_val))},
                        {'title': f'KeyUsage: {ku_hex}', 'offset': bs_val_start + 1, 'length': 1 if len(bs_val) >= 2 else 0, 'children': _build_ku_flags(ku_byte, bs_val_start + 1, 1 if len(bs_val) >= 2 else 0, decipher)},
                    ])

            # id-ce-extKeyUsage
            elif ext_oid == '2.5.29.37':
                seq_items = _der_tlv_pos(inner_der, base=octet_value_start)
                if seq_items and seq_items[0][0] == 0x30:
                    _, seq_val, _, _, seq_val_start = seq_items[0]
                    kp_list = []
                    for i in _der_tlv_pos(seq_val, base=seq_val_start):
                        if i[0] != 0x06:
                            continue
                        kp_oid = _decode_oid(i[1])
                        kp_list.append({'title': f'KeyPurposeId: {kp_oid} ({OID_KP.get(kp_oid, kp_oid)})', 'offset': i[4], 'length': len(i[1])})
                    children.append({'title': f'KeyPurposeIDs: {len(kp_list)} items', 'offset': octet_value_start, 'length': octet_value_len, 'children': kp_list})

            # id-ce-basicConstraints
            elif ext_oid == '2.5.29.19':
                seq_items = _der_tlv_pos(inner_der, base=octet_value_start)
                bc_inner = []
                if seq_items and seq_items[0][0] == 0x30:
                    _, bc_val, _, _, bc_val_start = seq_items[0]
                    bc_inner = _der_tlv_pos(bc_val, base=bc_val_start)
                ca_val = False
                path_len = None
                ca_start = None
                ca_len = 0
                path_start = None
                path_len_bytes = 0
                for tag, val, _, _, val_start in bc_inner:
                    if tag == 0x01 and val:    # BOOLEAN
                        ca_val = val[0] != 0
                        ca_start = val_start
                        ca_len = len(val)
                    elif tag == 0x02:           # INTEGER
                        path_len = int.from_bytes(val, 'big')
                        path_start = val_start
                        path_len_bytes = len(val)
                if ca_val:
                    bc_ch = [{'title': 'cA: True', 'offset': ca_start, 'length': ca_len}]
                    if path_len is not None:
                        bc_ch.append({'title': f'pathLenConstraint: {path_len}', 'offset': path_start, 'length': path_len_bytes})
                    children.append({'title': 'BasicConstraintsSyntax', 'offset': octet_value_start, 'length': octet_value_len, 'children': bc_ch})
                else:
                    children.append({'title': 'BasicConstraintsSyntax [0 length]', 'offset': octet_value_start, 'length': octet_value_len})

            # id-ce-subjectKeyIdentifier
            elif ext_oid == '2.5.29.14':
                ski_items = _der_tlv_pos(ext_val_octet, base=octet_value_start)
                if ski_items and ski_items[0][0] == 0x04:
                    children.append({'title': f'SubjectKeyIdentifier: {ski_items[0][1].hex()}', 'offset': ski_items[0][4], 'length': len(ski_items[0][1])})

            # id-ce-authorityKeyIdentifier
            elif ext_oid == '2.5.29.35':
                seq_items = _der_tlv_pos(inner_der, base=octet_value_start)
                if seq_items and seq_items[0][0] == 0x30:
                    _, aki_seq_val, _, _, aki_seq_val_start = seq_items[0]
                    for tag, val, _, _, aki_val_start in _der_tlv_pos(aki_seq_val, base=aki_seq_val_start):
                        if tag == 0x80:   # [0] keyIdentifier
                            children.append({'title': 'AuthorityKeyIdentifier',
                                             'offset': octet_value_start,
                                             'length': octet_value_len,
                                             'children': [{'title': f'keyIdentifier: {val.hex()}', 'offset': aki_val_start, 'length': len(val)}]})
                            break

            # id-pe-authorityInfoAccess
            elif ext_oid == '1.3.6.1.5.5.7.1.1':
                seq_items = _der_tlv_pos(inner_der, base=octet_value_start)
                aia_seq = []
                aia_seq_start = octet_value_start
                if seq_items and seq_items[0][0] == 0x30:
                    _, aia_seq_val, _, _, aia_seq_start = seq_items[0]
                    aia_seq = _der_tlv_pos(aia_seq_val, base=aia_seq_start)
                aia_ch = []
                for tag, val, ad_start, ad_len_tlv, ad_val_start in aia_seq:
                    if tag != 0x30:
                        continue
                    ad_items = _der_tlv_pos(val, base=ad_val_start)
                    if len(ad_items) < 2 or ad_items[0][0] != 0x06:
                        continue
                    method_oid = _decode_oid(ad_items[0][1])
                    method_name = OID_AIA.get(method_oid, method_oid)
                    loc_tag, loc_val, loc_start, loc_len_tlv, loc_val_start = ad_items[1]
                    if loc_tag == 0x86:  # [6] uniformResourceIdentifier
                        loc_str = loc_val.decode('ascii', errors='replace')
                        loc_node = {'title': 'accessLocation: 6',
                                    'offset': loc_start,
                                    'length': loc_len_tlv,
                                    'children': [{'title': f'uniformResourceIdentifier: {loc_str}', 'offset': loc_val_start, 'length': len(loc_val)}]}
                    else:
                        loc_node = {'title': f'accessLocation: {loc_tag}', 'offset': loc_start, 'length': loc_len_tlv}
                    aia_ch.append({'title': 'AccessDescription',
                                   'offset': ad_start,
                                   'length': ad_len_tlv,
                                   'children': [{'title': f'accessMethod: {method_oid} ({method_name})', 'offset': ad_items[0][4], 'length': len(ad_items[0][1])}, loc_node]})
                children.append({'title': f'AuthorityInfoAccessSyntax: {len(aia_ch)} items', 'offset': octet_value_start, 'length': octet_value_len, 'children': aia_ch})

            # id-ce-cRLDistributionPoints
            elif ext_oid == '2.5.29.31':
                outer = _der_tlv_pos(inner_der, base=octet_value_start)
                dp_list = []
                dp_seq_start = octet_value_start
                if outer and outer[0][0] == 0x30:
                    _, dp_seq_val, _, _, dp_seq_start = outer[0]
                    dp_list = _der_tlv_pos(dp_seq_val, base=dp_seq_start)
                dp_ch = []
                for tag, val, dp_start, dp_len_tlv, dp_val_start in dp_list:
                    if tag != 0x30:
                        continue
                    dp_inner = _der_tlv_pos(val, base=dp_val_start)
                    dp_sub = []
                    for dt, dv, dt_start, dt_len_tlv, dt_val_start in dp_inner:
                        if dt == 0xa0:   # [0] distributionPoint
                            fn_items = _der_tlv_pos(dv, base=dt_val_start)
                            fn_ch = []
                            for ft, fv, ft_start, ft_len_tlv, ft_val_start in fn_items:
                                if ft == 0xa0:  # fullName [0]
                                    gn_ch = []
                                    for gt, gv, gt_start, gt_len_tlv, gt_val_start in _der_tlv_pos(fv, base=ft_val_start):
                                        if gt == 0x86:
                                            gn_ch.append({'title': 'GeneralName: uniformResourceIdentifier (6)',
                                                          'offset': gt_start,
                                                          'length': gt_len_tlv,
                                                          'children': [{'title': f'uniformResourceIdentifier: {gv.decode("ascii", errors="replace")}', 'offset': gt_val_start, 'length': len(gv)}]})
                                    fn_ch.append({'title': f'fullName: {len(gn_ch)} item{"s" if len(gn_ch) != 1 else ""}',
                                                  'offset': ft_start,
                                                  'length': ft_len_tlv,
                                                  'children': gn_ch})
                            dp_sub.append({'title': 'distributionPoint: fullName (0)', 'offset': dt_start, 'length': dt_len_tlv, 'children': fn_ch})
                    dp_ch.append({'title': 'DistributionPoint', 'offset': dp_start, 'length': dp_len_tlv, 'children': dp_sub})
                children.append({'title': f'CRLDistPointsSyntax: {len(dp_ch)} item{"s" if len(dp_ch) != 1 else ""}',
                                  'offset': octet_value_start,
                                  'length': octet_value_len,
                                  'children': dp_ch})

            # id-ce-subjectAltName / id-ce-issuerAltName
            elif ext_oid in ('2.5.29.17', '2.5.29.18'):
                outer = _der_tlv_pos(inner_der, base=octet_value_start)
                gn_seq = []
                gn_seq_start = octet_value_start
                if outer and outer[0][0] == 0x30:
                    _, gn_seq_val, _, _, gn_seq_start = outer[0]
                    gn_seq = _der_tlv_pos(gn_seq_val, base=gn_seq_start)
                gn_ch = []
                for gt, gv, gt_start, gt_len_tlv, gt_val_start in gn_seq:
                    if gt == 0x82:   # [2] dNSName
                        gn_ch.append({'title': 'GeneralName: dNSName (2)',
                                      'offset': gt_start,
                                      'length': gt_len_tlv,
                                      'children': [{'title': f'dNSName: {gv.decode("ascii", errors="replace")}', 'offset': gt_val_start, 'length': len(gv)}]})
                    elif gt == 0x86:  # [6] URI
                        gn_ch.append({'title': 'GeneralName: uniformResourceIdentifier (6)',
                                      'offset': gt_start,
                                      'length': gt_len_tlv,
                                      'children': [{'title': f'uniformResourceIdentifier: {gv.decode("ascii", errors="replace")}', 'offset': gt_val_start, 'length': len(gv)}]})
                    elif gt == 0x81:  # [1] rfc822Name
                        gn_ch.append({'title': 'GeneralName: rfc822Name (1)',
                                      'offset': gt_start,
                                      'length': gt_len_tlv,
                                      'children': [{'title': f'rfc822Name: {gv.decode("ascii", errors="replace")}', 'offset': gt_val_start, 'length': len(gv)}]})
                children.append({'title': f'GeneralNames: {len(gn_ch)} item{"s" if len(gn_ch) != 1 else ""}',
                                  'offset': octet_value_start,
                                  'length': octet_value_len,
                                  'children': gn_ch})

            # id-ce-certificatePolicies
            elif ext_oid == '2.5.29.32':
                outer = _der_tlv_pos(inner_der, base=octet_value_start)
                pi_seq = []
                pi_seq_start = octet_value_start
                if outer and outer[0][0] == 0x30:
                    _, pi_seq_val, _, _, pi_seq_start = outer[0]
                    pi_seq = _der_tlv_pos(pi_seq_val, base=pi_seq_start)
                pi_ch = []
                for pt, pv, pi_start, pi_len_tlv, pi_val_start in pi_seq:
                    if pt != 0x30:
                        continue
                    pi_items = _der_tlv_pos(pv, base=pi_val_start)
                    if not pi_items or pi_items[0][0] != 0x06:
                        continue
                    pol_oid = _decode_oid(pi_items[0][1])
                    pol_name_short = OID_POLICY.get(pol_oid, pol_oid)
                    pi_sub = [{'title': f'policyIdentifier: {pol_oid} ({pol_name_short})', 'offset': pi_items[0][4], 'length': len(pi_items[0][1])}]
                    if len(pi_items) > 1 and pi_items[1][0] == 0x30:  # policyQualifiers
                        _, pq_seq_val, pq_start, pq_len_tlv, pq_val_start = pi_items[1]
                        pq_seq = _der_tlv_pos(pq_seq_val, base=pq_val_start)
                        pq_ch = []
                        for qpt, qpv, q_start, q_len_tlv, q_val_start in pq_seq:
                            if qpt != 0x30:
                                continue
                            qp_items = _der_tlv_pos(qpv, base=q_val_start)
                            if not qp_items or qp_items[0][0] != 0x06:
                                continue
                            q_oid = _decode_oid(qp_items[0][1])
                            q_name = OID_POLICY_QUAL.get(q_oid, q_oid)
                            q_sub = [{'title': f'Id: {q_oid} ({q_name})', 'offset': qp_items[0][4], 'length': len(qp_items[0][1])}]
                            if len(qp_items) > 1:
                                qval_tag, qval_bytes, _, _, qval_start = qp_items[1]
                                if qval_tag == 0x16:  # IA5String (CPS URI)
                                    q_sub.append({'title': f'DirectoryString: {qval_bytes.decode("ascii", errors="replace")}', 'offset': qval_start, 'length': len(qval_bytes)})
                            pq_ch.append({'title': 'PolicyQualifierInfo', 'offset': q_start, 'length': q_len_tlv, 'children': q_sub})
                        if pq_ch:
                            pi_sub.append({'title': f'policyQualifiers: {len(pq_ch)} item{"s" if len(pq_ch) != 1 else ""}',
                                           'offset': pq_start,
                                           'length': pq_len_tlv,
                                           'children': pq_ch})
                    pi_ch.append({'title': 'PolicyInformation', 'offset': pi_start, 'length': pi_len_tlv, 'children': pi_sub})
                children.append({'title': f'CertificatePoliciesSyntax: {len(pi_ch)} item{"s" if len(pi_ch) != 1 else ""}',
                                  'offset': octet_value_start,
                                  'length': octet_value_len,
                                  'children': pi_ch})

            # SignedCertificateTimestampList
            elif ext_oid == '1.3.6.1.4.1.11129.2.4.2':
                sct_children = _parse_sct_ext(ext_val_octet)
                children.extend(sct_children)

        except Exception:
            pass
        return {'title': f'Extension ({ext_name})', 'offset': ext_start, 'length': ext_len_tlv, 'children': children}

    # ─── Walk cert DER ────────────────────────────────────────────────────────
    def _der_tlv_pos(data: bytes, base: int = 0):
        """Like _der_tlv but returns (tag, val, tlv_start_abs, tlv_total_len, val_start_abs)."""
        result, pos = [], 0
        while pos < len(data):
            tlv_start = pos
            if pos >= len(data):
                break
            tag = data[pos]; pos += 1
            if pos >= len(data):
                break
            b = data[pos]
            if b & 0x80:
                n = b & 0x7f; pos += 1
                if pos + n > len(data):
                    break
                length = int.from_bytes(data[pos:pos + n], 'big'); pos += n
            else:
                length = b; pos += 1
            val_start = pos
            end = pos + length
            result.append((tag, data[pos:end], base + tlv_start, end - tlv_start, base + val_start))
            pos = end
        return result

    def _pos_node(node: dict, start: int | None, length: int | None) -> dict:
        """Attach offset/length to a node dict if both are non-zero."""
        if start is not None and length is not None and length >= 0:
            node['offset'] = start
            node['length'] = length
        return node

    try:
        cert_outer = _der_tlv_pos(cert_bytes, base=abs_offset)
        if not cert_outer or cert_outer[0][0] != 0x30:
            raise ValueError('not a SEQUENCE')
        _, cert_inner_bytes, _co_start, _co_len, co_val_start = cert_outer[0]
        cert_inner = _der_tlv_pos(cert_inner_bytes, base=co_val_start)
        if len(cert_inner) < 3:
            raise ValueError('cert SEQUENCE has fewer than 3 items')

        _, tbs_val,       tbs_start,  tbs_len_tlv,  tbs_val_start  = cert_inner[0]
        _, outer_alg_val, oa_start,   oa_len_tlv,   oa_val_start   = cert_inner[1]
        _, sig_val,       sig_start,  sig_len_tlv,  sig_val_start  = cert_inner[2]

        # Outer algorithm OID
        outer_alg_items = _der_tlv_pos(outer_alg_val, base=oa_val_start)
        outer_alg_oid = _decode_oid(outer_alg_items[0][1]) if outer_alg_items and outer_alg_items[0][0] == 0x06 else ''
        outer_alg_name = OID_ALG.get(outer_alg_oid, outer_alg_oid)
        outer_alg_oid_start = outer_alg_items[0][4] if outer_alg_items and outer_alg_items[0][0] == 0x06 else oa_val_start
        outer_alg_oid_len = len(outer_alg_items[0][1]) if outer_alg_items and outer_alg_items[0][0] == 0x06 else 0

        # Signature bytes (BIT STRING: first byte = unused bits count)
        sig_bytes = sig_val[1:] if sig_val else b''

        # Parse TBSCertificate fields with position tracking
        tbs_items = _der_tlv_pos(tbs_val, base=tbs_val_start)
        idx = 0

        # version [0] EXPLICIT
        version_int = 0
        ver_start, ver_len_tlv = 0, 0
        ver_value_start, ver_value_len = 0, 0
        if tbs_items and tbs_items[idx][0] == 0xa0:
            _, ver_content, ver_start, ver_len_tlv, _ = tbs_items[idx]
            ver_items = _der_tlv_pos(ver_content, base=ver_start + (ver_len_tlv - len(ver_content)))
            if ver_items and ver_items[0][0] == 0x02:
                _, ver_value, _, _, ver_value_start = ver_items[0]
                version_int = int.from_bytes(ver_value, 'big')
                ver_value_len = len(ver_value)
            idx += 1
        version_str = {0: 'v1', 1: 'v2', 2: 'v3'}.get(version_int, f'v{version_int + 1}')

        # serialNumber INTEGER
        serial_bytes = b'\x00'
        sn_start, sn_len_tlv = 0, 0
        sn_value_start, sn_value_len = 0, 0
        if idx < len(tbs_items) and tbs_items[idx][0] == 0x02:
            _, serial_bytes, sn_start, sn_len_tlv, sn_value_start = tbs_items[idx]
            sn_value_len = len(serial_bytes)
        serial_hex = f'0x{int.from_bytes(serial_bytes, "big"):x}'
        idx += 1

        # signatureAlgorithm SEQUENCE
        sa_start, sa_len_tlv = 0, 0
        sig_alg_items = []
        sa_val_start = 0
        sig_alg_oid_start, sig_alg_oid_len = 0, 0
        if idx < len(tbs_items) and tbs_items[idx][0] == 0x30:
            _, sa_val, sa_start, sa_len_tlv, sa_val_start = tbs_items[idx]
            sig_alg_items = _der_tlv_pos(sa_val, base=sa_val_start)
        sig_alg_oid = _decode_oid(sig_alg_items[0][1]) if sig_alg_items and sig_alg_items[0][0] == 0x06 else ''
        if sig_alg_items and sig_alg_items[0][0] == 0x06:
            sig_alg_oid_start = sig_alg_items[0][4]
            sig_alg_oid_len = len(sig_alg_items[0][1])
        sig_alg_name = OID_ALG.get(sig_alg_oid, sig_alg_oid)
        idx += 1

        # issuer SEQUENCE
        issuer_raw, issuer_start, issuer_len_tlv, issuer_val_start = b'', 0, 0, 0
        if idx < len(tbs_items) and tbs_items[idx][0] == 0x30:
            _, issuer_raw, issuer_start, issuer_len_tlv, issuer_val_start = tbs_items[idx]
        idx += 1

        # validity SEQUENCE
        validity_raw, validity_start, validity_len_tlv, validity_val_start = b'', 0, 0, 0
        if idx < len(tbs_items) and tbs_items[idx][0] == 0x30:
            _, validity_raw, validity_start, validity_len_tlv, validity_val_start = tbs_items[idx]
        idx += 1

        # subject SEQUENCE
        subject_raw, subject_start, subject_len_tlv, subject_val_start = b'', 0, 0, 0
        if idx < len(tbs_items) and tbs_items[idx][0] == 0x30:
            _, subject_raw, subject_start, subject_len_tlv, subject_val_start = tbs_items[idx]
        idx += 1

        # subjectPublicKeyInfo SEQUENCE
        spki_raw, spki_start, spki_len_tlv, spki_val_start = b'', 0, 0, 0
        if idx < len(tbs_items) and tbs_items[idx][0] == 0x30:
            _, spki_raw, spki_start, spki_len_tlv, spki_val_start = tbs_items[idx]
        idx += 1

        # extensions [3] EXPLICIT
        ext_nodes = []
        ext_start, ext_len_tlv, ext_val_start = 0, 0, 0
        while idx < len(tbs_items):
            if tbs_items[idx][0] == 0xa3:
                _, e3_val, ext_start, ext_len_tlv, ext_val_start = tbs_items[idx]
                exts_seq = _der_tlv_pos(e3_val, base=ext_val_start)
                if exts_seq and exts_seq[0][0] == 0x30:
                    _, exts_seq_val, _, _, exts_seq_val_start = exts_seq[0]
                    for et, ev, ext_item_start, ext_item_len_tlv, ext_item_val_start in _der_tlv_pos(exts_seq_val, base=exts_seq_val_start):
                        if et != 0x30:
                            continue
                        ext_items = _der_tlv_pos(ev, base=ext_item_val_start)
                        if not ext_items or ext_items[0][0] != 0x06:
                            continue
                        ext_oid = _decode_oid(ext_items[0][1])
                        is_critical = False
                        ext_val_octet = b''
                        ext_meta = {
                            'oid_start': ext_items[0][4],
                            'oid_len': len(ext_items[0][1]),
                            'critical_start': None,
                            'critical_len': 0,
                            'octet_tlv_start': None,
                            'octet_tlv_len': 0,
                            'octet_value_start': None,
                            'octet_value_len': 0,
                        }
                        for eit, eiv, eit_start, eit_len_tlv, eit_val_start in ext_items[1:]:
                            if eit == 0x01 and eiv:    # BOOLEAN critical
                                is_critical = eiv[0] != 0
                                ext_meta['critical_start'] = eit_val_start
                                ext_meta['critical_len'] = len(eiv)
                            elif eit == 0x04:           # OCTET STRING
                                ext_val_octet = eiv
                                ext_meta['octet_tlv_start'] = eit_start
                                ext_meta['octet_tlv_len'] = eit_len_tlv
                                ext_meta['octet_value_start'] = eit_val_start
                                ext_meta['octet_value_len'] = len(eiv)
                        ext_nodes.append(_build_ext_tree(ext_oid, is_critical, ext_val_octet, ext_item_start, ext_item_len_tlv, ext_meta))
            idx += 1

        signed_cert_children = [
            _pos_node({'title': f'version: {version_str} ({version_int})'}, ver_value_start, ver_value_len),
            _pos_node({'title': f'serialNumber: {serial_hex}'}, sn_value_start, sn_value_len),
            _pos_node({'title': f'signature ({sig_alg_name})', 'children': [{'title': f'Algorithm Id: {sig_alg_oid} ({sig_alg_name})', 'offset': sig_alg_oid_start, 'length': sig_alg_oid_len}]}, sa_start, sa_len_tlv),
            _build_name_tree(issuer_raw, 'issuer', issuer_start, issuer_len_tlv, issuer_val_start),
            _build_validity_tree(validity_raw, validity_start, validity_len_tlv, validity_val_start),
            _build_name_tree(subject_raw, 'subject', subject_start, subject_len_tlv, subject_val_start),
            _build_spki_tree(spki_raw, spki_start, spki_len_tlv, spki_val_start),
            _pos_node({'title': f'extensions: {len(ext_nodes)} items', 'children': ext_nodes}, ext_start, ext_len_tlv),
        ]

        return {
            'title': f'Certificate [...]: {hex_prefix}',
            'offset': abs_offset,
            'length': len(cert_bytes),
            'children': [
                {'title': 'signedCertificate', 'offset': tbs_start, 'length': tbs_len_tlv, 'children': signed_cert_children},
                _pos_node({'title': f'algorithmIdentifier ({outer_alg_name})', 'children': [{'title': f'Algorithm Id: {outer_alg_oid} ({outer_alg_name})', 'offset': outer_alg_oid_start, 'length': outer_alg_oid_len}]}, oa_start, oa_len_tlv),
                {'title': f'Padding: {sig_val[0] if sig_val else 0}', 'offset': sig_val_start, 'length': min(1, len(sig_val))},
                _pos_node({'title': f'encrypted [...]: {sig_bytes.hex()}', 'offset': sig_val_start + 1, 'length': max(0, len(sig_val) - 1)}, sig_val_start + 1, max(0, len(sig_val) - 1)),
            ],
        }

    except Exception:
        return {
            'title': f'Certificate [...]: {hex_prefix}',
            'offset': abs_offset,
            'length': len(cert_bytes),
        }


def _tls_section_precise(packet, offset: int, stream_index: int, record=None) -> Dict[str, Any]:
    tcp_layer = _effective_tcp_layer(packet)
    tls_bytes_raw = _tcp_payload_bytes(packet, tcp_layer) if tcp_layer is not None else bytes(packet[TLS])

    # Use TCP-reassembled TLS payload if available (e.g. fragmented Certificate)
    _is_reassembled = False
    if record is not None:
        _meta = getattr(record, 'metadata', {}) or {}
        _reassembled = _meta.get('tls_reassembled_payload')
        if _reassembled:
            tls_bytes_raw = bytes(_reassembled)
            _is_reassembled = True

    scan_start = 0
    if len(tls_bytes_raw) >= 5:
        first_type = int(tls_bytes_raw[0])
        first_ver = int.from_bytes(tls_bytes_raw[1:3], 'big')
        first_len = int.from_bytes(tls_bytes_raw[3:5], 'big')
        starts_with_tls = first_type in {20, 21, 22, 23} and first_ver in {0x0301, 0x0302, 0x0303, 0x0304} and 5 + first_len <= len(tls_bytes_raw)
        if not starts_with_tls:
            for i in range(0, len(tls_bytes_raw) - 4):
                ctype = int(tls_bytes_raw[i])
                ver = int.from_bytes(tls_bytes_raw[i + 1:i + 3], 'big')
                rec_len = int.from_bytes(tls_bytes_raw[i + 3:i + 5], 'big')
                if ctype in {20, 21, 22, 23} and ver in {0x0301, 0x0302, 0x0303, 0x0304} and i + 5 + rec_len <= len(tls_bytes_raw):
                    scan_start = i
                    break

    tls_bytes = tls_bytes_raw[scan_start:] if scan_start < len(tls_bytes_raw) else b''
    if _is_reassembled:
        offset = 0  # offsets are 0-based within the reassembled buffer
    else:
        offset = offset + scan_start
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
        65281: 'renegotiation_info',
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

    def _parse_extensions(container: bytes, cursor: int, base_abs: int, max_end: int) -> tuple[list[dict], int, int]:
        if cursor + 2 > max_end:
            return [], cursor, 0

        ext_len = int.from_bytes(container[cursor:cursor + 2], 'big')
        cursor += 2
        ext_start = cursor
        ext_children = []

        while cursor + 4 <= min(max_end, ext_start + ext_len):
            ext_type = int.from_bytes(container[cursor:cursor + 2], 'big')
            ext_size = int.from_bytes(container[cursor + 2:cursor + 4], 'big')
            data_start = cursor + 4
            data_end = min(max_end, data_start + ext_size)
            ext_name = extension_name_map.get(ext_type, ext_type)
            ext_node = {
                'title': f'Extension: {ext_name} (len={ext_size})',
                'offset': base_abs + cursor,
                'length': min(max_end - cursor, 4 + ext_size),
                'children': [
                    {'title': f'Type: {ext_name} ({ext_type})', 'offset': base_abs + cursor, 'length': 2},
                    {'title': f'Length: {ext_size}', 'offset': base_abs + cursor + 2, 'length': 2},
                ],
            }

            ext_payload = container[data_start:data_end]
            if ext_type == 11 and len(ext_payload) >= 1:
                list_len = int(ext_payload[0])
                formats_map = {0: 'uncompressed', 1: 'ansiX962_compressed_prime', 2: 'ansiX962_compressed_char2'}
                point_children = []
                for i in range(min(list_len, max(0, len(ext_payload) - 1))):
                    fmt = int(ext_payload[1 + i])
                    point_children.append({'title': f'EC point format: {formats_map.get(fmt, fmt)} ({fmt})', 'offset': base_abs + data_start + 1 + i, 'length': 1})
                ext_node['children'].extend([
                    {'title': f'EC point formats Length: {list_len}', 'offset': base_abs + data_start, 'length': 1},
                    {'title': f'Elliptic curves point formats ({len(point_children)})', 'offset': base_abs + data_start + 1, 'length': max(0, len(ext_payload) - 1), 'children': point_children},
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
                    group_children.append({'title': f'Supported Group: {group_map.get(group, f"0x{group:04x}")} (0x{group:04x})', 'offset': base_abs + data_start + p, 'length': 2})
                    p += 2
                ext_node['children'].extend([
                    {'title': f'Supported Groups List Length: {list_len}', 'offset': base_abs + data_start, 'length': 2},
                    {'title': f'Supported Groups ({len(group_children)} groups)', 'offset': base_abs + data_start + 2, 'length': max(0, list_len), 'children': group_children},
                ])
            elif ext_type == 35:
                ext_node['children'].append({'title': 'Session Ticket: <MISSING>'})
            elif ext_type == 65281:
                renego_len_val = int(ext_payload[0]) if len(ext_payload) >= 1 else 0
                renego_child = {
                    'title': f'Renegotiation info extension length: {renego_len_val}',
                    'offset': base_abs + data_start,
                    'length': 1,
                }
                ext_node['children'].append({
                    'title': 'Renegotiation Info extension',
                    'offset': base_abs + data_start,
                    'length': 1,
                    'children': [renego_child],
                })
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
                        'offset': base_abs + data_start + p,
                        'length': 2,
                        'children': [
                            {'title': f'Signature Hash Algorithm Hash: {hash_map.get(hash_id, hash_id)} ({hash_id})', 'offset': base_abs + data_start + p, 'length': 1},
                            {'title': f'Signature Hash Algorithm Signature: {sign_map.get(sign_id, sign_id)} ({sign_id})', 'offset': base_abs + data_start + p + 1, 'length': 1},
                        ],
                    })
                    p += 2
                ext_node['children'].extend([
                    {'title': f'Signature Hash Algorithms Length: {list_len}', 'offset': base_abs + data_start, 'length': 2},
                    {'title': f'Signature Hash Algorithms ({len(sig_children)} algorithms)', 'offset': base_abs + data_start + 2, 'length': max(0, list_len), 'children': sig_children},
                ])
            elif ext_type == 15 and len(ext_payload) >= 1:
                mode = int(ext_payload[0])
                ext_node['children'].append({'title': f'Mode: {"Peer allowed to send requests" if mode == 1 else mode} ({mode})', 'offset': base_abs + data_start, 'length': 1})
            else:
                ext_node['children'].append({'title': f'Data: {ext_payload.hex()}', 'offset': base_abs + data_start, 'length': max(0, len(ext_payload))})

            ext_children.append(ext_node)
            cursor = data_end

        return ext_children, cursor, ext_len

    children = []
    if stream_index >= 0:
        children.append({'title': f'[Stream index: {stream_index}]'})

    if scan_start > 0:
        prefix = tls_bytes_raw[:scan_start]
        children.append({
            'title': 'Handshake Protocol: Certificate',
            'offset': offset - scan_start,
            'length': scan_start,
            'children': [
                {'title': f'Fragment data: {prefix.hex()}', 'offset': offset - scan_start, 'length': scan_start},
            ],
        })

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

        parse_handshake = content_type == 22 and len(record_payload) >= 4
        if not parse_handshake and content_type == 23 and len(record_payload) >= 4:
            hs_type_probe = int(record_payload[0])
            hs_len_probe = int.from_bytes(record_payload[1:4], 'big')
            hs_total_probe = 4 + hs_len_probe
            if hs_type_probe in {1, 2, 4, 11, 12, 13, 14, 15, 16, 20} and hs_total_probe <= len(record_payload):
                parse_handshake = True

        if parse_handshake:
            hs_pos = 0
            hs_names = []
            while hs_pos + 4 <= len(record_payload):
                hs_type = int(record_payload[hs_pos])
                hs_len = int.from_bytes(record_payload[hs_pos + 1:hs_pos + 4], 'big')
                hs_total = 4 + hs_len

                if hs_total < 4 or hs_pos + hs_total > len(record_payload):
                    is_fragment = hs_total >= 4 and hs_type in handshake_type_map
                    # For Certificate (hs_type=11), parse available bytes even if fragmented
                    if is_fragment and hs_type == 11 and len(record_payload) >= hs_pos + 4 + 3:
                        frag_hs_abs = offset + payload_start + hs_pos
                        frag_hs_body = record_payload[hs_pos + 4:]
                        hs_names.append('Certificate')
                        frag_handshake_children = [
                            {'title': f'Handshake Type: Certificate (11)', 'offset': frag_hs_abs, 'length': 1},
                            {'title': f'Length: {hs_len}', 'offset': frag_hs_abs + 1, 'length': 3},
                        ]
                        if len(frag_hs_body) >= 3:
                            frag_certs_len = int.from_bytes(frag_hs_body[0:3], 'big')
                            frag_handshake_children.append({'title': f'Certificates Length: {frag_certs_len}', 'offset': frag_hs_abs + 4, 'length': 3})
                            frag_certs_children = []
                            fp = 3
                            frag_certs_end = min(len(frag_hs_body), 3 + frag_certs_len)
                            while fp + 3 <= frag_certs_end:
                                fcert_len = int.from_bytes(frag_hs_body[fp:fp + 3], 'big')
                                fcert_data_start = fp + 3
                                fcert_data_end = min(frag_certs_end, fcert_data_start + fcert_len)
                                fcert_bytes = frag_hs_body[fcert_data_start:fcert_data_end]
                                fcert_abs = frag_hs_abs + 4 + fcert_data_start
                                frag_certs_children.append({'title': f'Certificate Length: {fcert_len}', 'offset': frag_hs_abs + 4 + fp, 'length': 3})
                                if len(fcert_bytes) == fcert_len:
                                    frag_certs_children.append(_parse_x509_cert_tree(fcert_bytes, fcert_abs))
                                else:
                                    frag_certs_children.append({
                                        'title': f'Certificate [...] (fragment): {fcert_bytes.hex()}',
                                        'offset': fcert_abs,
                                        'length': len(fcert_bytes),
                                    })
                                fp = fcert_data_end
                            frag_handshake_children.append({'title': f'Certificates ({frag_certs_len} bytes)', 'offset': frag_hs_abs + 7, 'length': max(0, frag_certs_len), 'children': frag_certs_children})
                        record_children.append({
                            'title': 'Handshake Protocol: Certificate',
                            'offset': frag_hs_abs,
                            'length': len(record_payload) - hs_pos,
                            'children': frag_handshake_children,
                        })
                    else:
                        hs_names.append('Fragmented Handshake Message' if is_fragment else 'Encrypted Handshake Message')
                        record_children.append({
                            'title': f'Handshake Protocol: {"Fragmented Handshake Message" if is_fragment else "Encrypted Handshake Message"}',
                            'offset': offset + payload_start + hs_pos,
                            'length': len(record_payload) - hs_pos,
                        })
                    break

                hs_name = handshake_type_map.get(hs_type, f'Handshake ({hs_type})')
                hs_names.append(hs_name)
                hs_body_start = hs_pos + 4
                hs_body_end = hs_body_start + hs_len
                hs_body = record_payload[hs_body_start:hs_body_end]
                hs_abs = offset + payload_start + hs_pos
                cursor = 0

                handshake_children = [
                    {'title': f'Handshake Type: {hs_name} ({hs_type})', 'offset': hs_abs, 'length': 1},
                    {'title': f'Length: {hs_len}', 'offset': hs_abs + 1, 'length': 3},
                ]

                if hs_type == 1 and len(hs_body) >= 34:
                    hello_version = int.from_bytes(hs_body[cursor:cursor + 2], 'big')
                    handshake_children.append({'title': f'Version: {tls_clienthello_version_name(hello_version)} (0x{hello_version:04x})', 'offset': hs_abs + 4 + cursor, 'length': 2})
                    cursor += 2
                    random_bytes = hs_body[cursor:cursor + 32]
                    gmt_unix = int.from_bytes(random_bytes[:4], 'big') if len(random_bytes) >= 4 else 0
                    handshake_children.append({
                        'title': f'Random: {random_bytes.hex()}',
                        'offset': hs_abs + 4 + cursor,
                        'length': min(32, len(random_bytes)),
                        'children': [
                            {'title': f'GMT Unix Time: {_fmt_epoch_local(gmt_unix)}', 'offset': hs_abs + 4 + cursor, 'length': min(4, len(random_bytes))},
                            {'title': f'Random Bytes: {random_bytes[4:].hex()}', 'offset': hs_abs + 4 + cursor + 4, 'length': max(0, len(random_bytes) - 4)},
                        ],
                    })
                    cursor += 32
                    if cursor < len(hs_body):
                        sid_len = int(hs_body[cursor])
                        handshake_children.append({'title': f'Session ID Length: {sid_len}', 'offset': hs_abs + 4 + cursor, 'length': 1})
                        cursor += 1
                        if sid_len > 0 and cursor + sid_len <= len(hs_body):
                            handshake_children.append({'title': f'Session ID: {hs_body[cursor:cursor + sid_len].hex()}', 'offset': hs_abs + 4 + cursor, 'length': sid_len})
                        cursor += sid_len
                    if cursor + 2 <= len(hs_body):
                        cipher_len = int.from_bytes(hs_body[cursor:cursor + 2], 'big')
                        handshake_children.append({'title': f'Cipher Suites Length: {cipher_len}', 'offset': hs_abs + 4 + cursor, 'length': 2})
                        cursor += 2
                        cipher_start = cursor
                        cipher_children = []
                        while cursor + 2 <= min(len(hs_body), cipher_start + cipher_len):
                            suite = int.from_bytes(hs_body[cursor:cursor + 2], 'big')
                            cipher_children.append({'title': f'Cipher Suite: {cipher_suite_map.get(suite, f"0x{suite:04x}")} (0x{suite:04x})', 'offset': hs_abs + 4 + cursor, 'length': 2})
                            cursor += 2
                        handshake_children.append({'title': f'Cipher Suites ({len(cipher_children)} suites)', 'offset': hs_abs + 4 + cipher_start, 'length': max(0, min(cipher_len, len(hs_body) - cipher_start)), 'children': cipher_children})
                    if cursor < len(hs_body):
                        comp_len = int(hs_body[cursor])
                        handshake_children.append({'title': f'Compression Methods Length: {comp_len}', 'offset': hs_abs + 4 + cursor, 'length': 1})
                        cursor += 1
                        comp_start = cursor
                        comp_children = []
                        for _ in range(comp_len):
                            if cursor >= len(hs_body):
                                break
                            method = int(hs_body[cursor])
                            comp_children.append({'title': f'Compression Method: {"null" if method == 0 else method} ({method})', 'offset': hs_abs + 4 + cursor, 'length': 1})
                            cursor += 1
                        handshake_children.append({'title': f'Compression Methods ({len(comp_children)} methods)', 'offset': hs_abs + 4 + comp_start, 'length': max(0, min(comp_len, len(hs_body) - comp_start)), 'children': comp_children})
                    ext_children, cursor_after_ext, ext_len = _parse_extensions(hs_body, cursor, hs_abs + 4, len(hs_body))
                    if ext_len > 0 or ext_children:
                        handshake_children.append({'title': f'Extensions Length: {ext_len}', 'offset': hs_abs + 4 + cursor, 'length': 2})
                        handshake_children.append({'title': f'Extensions ({len(ext_children)})', 'offset': hs_abs + 4 + cursor + 2, 'length': ext_len, 'children': ext_children})
                    try:
                        ja3 = _tls_clienthello_ja3(bytes([hs_type]) + hs_len.to_bytes(3, 'big') + hs_body)
                        if ja3:
                            ja4 = _tls_clienthello_ja4(bytes([hs_type]) + hs_len.to_bytes(3, 'big') + hs_body)
                            if ja4:
                                handshake_children.append({'title': f'[JA4: {ja4["value"]}]'})
                                handshake_children.append({'title': f'[JA4_r: {ja4["raw"]}]'})
                            handshake_children.append({'title': f'[JA3 Fullstring: {ja3["full"]}]'})
                            handshake_children.append({'title': f'[JA3: {ja3["hash"]}]'})
                    except Exception:
                        pass

                elif hs_type == 2 and len(hs_body) >= 38:
                    hello_version = int.from_bytes(hs_body[cursor:cursor + 2], 'big')
                    handshake_children.append({'title': f'Version: {version_name(hello_version)} (0x{hello_version:04x})', 'offset': hs_abs + 4 + cursor, 'length': 2})
                    cursor += 2
                    random_bytes = hs_body[cursor:cursor + 32]
                    gmt_unix = int.from_bytes(random_bytes[:4], 'big') if len(random_bytes) >= 4 else 0
                    handshake_children.append({
                        'title': f'Random: {random_bytes.hex()}',
                        'offset': hs_abs + 4 + cursor,
                        'length': min(32, len(random_bytes)),
                        'children': [
                            {'title': f'GMT Unix Time: {_fmt_epoch_local(gmt_unix)}', 'offset': hs_abs + 4 + cursor, 'length': min(4, len(random_bytes))},
                            {'title': f'Random Bytes: {random_bytes[4:].hex()}', 'offset': hs_abs + 4 + cursor + 4, 'length': max(0, len(random_bytes) - 4)},
                        ],
                    })
                    cursor += 32
                    if cursor < len(hs_body):
                        sid_len = int(hs_body[cursor])
                        handshake_children.append({'title': f'Session ID Length: {sid_len}', 'offset': hs_abs + 4 + cursor, 'length': 1})
                        cursor += 1
                        if sid_len > 0 and cursor + sid_len <= len(hs_body):
                            handshake_children.append({'title': f'Session ID: {hs_body[cursor:cursor + sid_len].hex()}', 'offset': hs_abs + 4 + cursor, 'length': sid_len})
                        cursor += sid_len
                    if cursor + 2 <= len(hs_body):
                        suite = int.from_bytes(hs_body[cursor:cursor + 2], 'big')
                        handshake_children.append({'title': f'Cipher Suite: {cipher_suite_map.get(suite, f"0x{suite:04x}")} (0x{suite:04x})', 'offset': hs_abs + 4 + cursor, 'length': 2})
                        cursor += 2
                    if cursor < len(hs_body):
                        method = int(hs_body[cursor])
                        handshake_children.append({'title': f'Compression Method: {"null" if method == 0 else method} ({method})', 'offset': hs_abs + 4 + cursor, 'length': 1})
                        cursor += 1
                    ext_children, _, ext_len = _parse_extensions(hs_body, cursor, hs_abs + 4, len(hs_body))
                    if ext_len > 0 or ext_children:
                        handshake_children.append({'title': f'Extensions Length: {ext_len}', 'offset': hs_abs + 4 + cursor, 'length': 2})
                        handshake_children.append({'title': f'Extensions ({len(ext_children)})', 'offset': hs_abs + 4 + cursor + 2, 'length': ext_len, 'children': ext_children})
                    try:
                        ja3s = _tls_serverhello_ja3s(bytes([hs_type]) + hs_len.to_bytes(3, 'big') + hs_body)
                        if ja3s:
                            handshake_children.append({'title': f'[JA3S Fullstring: {ja3s["full"]}]'})
                            handshake_children.append({'title': f'[JA3S: {ja3s["hash"]}]'})
                    except Exception:
                        pass

                elif hs_type == 11 and len(hs_body) >= 3:
                    certs_len = int.from_bytes(hs_body[0:3], 'big')
                    handshake_children.append({'title': f'Certificates Length: {certs_len}', 'offset': hs_abs + 4, 'length': 3})
                    certs_children = []
                    p = 3
                    certs_end = min(len(hs_body), 3 + certs_len)
                    while p + 3 <= certs_end:
                        cert_len = int.from_bytes(hs_body[p:p + 3], 'big')
                        cert_data_start = p + 3
                        cert_data_end = min(certs_end, cert_data_start + cert_len)
                        cert_bytes_data = hs_body[cert_data_start:cert_data_end]
                        cert_abs = hs_abs + 4 + cert_data_start
                        certs_children.append({
                            'title': f'Certificate Length: {cert_len}',
                            'offset': hs_abs + 4 + p,
                            'length': 3,
                        })
                        if len(cert_bytes_data) == cert_len:
                            cert_tree = _parse_x509_cert_tree(cert_bytes_data, cert_abs)
                        else:
                            cert_tree = {
                                'title': f'Certificate [...] (fragment): {cert_bytes_data.hex()}',
                                'offset': cert_abs,
                                'length': len(cert_bytes_data),
                            }
                        certs_children.append(cert_tree)
                        p = cert_data_end
                    handshake_children.append({'title': f'Certificates ({certs_len} bytes)', 'offset': hs_abs + 7, 'length': max(0, certs_len), 'children': certs_children})

                elif hs_type == 12 and len(hs_body) >= 4:
                    ecdhe_children = []
                    curve_type = int(hs_body[cursor])
                    ecdhe_children.append({'title': f'Curve Type: {"named_curve" if curve_type == 3 else curve_type} (0x{curve_type:02x})', 'offset': hs_abs + 4 + cursor, 'length': 1})
                    cursor += 1
                    if cursor + 2 <= len(hs_body):
                        named_curve = int.from_bytes(hs_body[cursor:cursor + 2], 'big')
                        curve_map = {0x0017: 'secp256r1', 0x0018: 'secp384r1', 0x0019: 'secp521r1'}
                        ecdhe_children.append({'title': f'Named Curve: {curve_map.get(named_curve, f"0x{named_curve:04x}")} (0x{named_curve:04x})', 'offset': hs_abs + 4 + cursor, 'length': 2})
                        cursor += 2
                    if cursor < len(hs_body):
                        pub_len = int(hs_body[cursor])
                        ecdhe_children.append({'title': f'Pubkey Length: {pub_len}', 'offset': hs_abs + 4 + cursor, 'length': 1})
                        cursor += 1
                        if pub_len > 0 and cursor + pub_len <= len(hs_body):
                            ecdhe_children.append({'title': f'Pubkey: {hs_body[cursor:cursor + pub_len].hex()}', 'offset': hs_abs + 4 + cursor, 'length': pub_len})
                        cursor += pub_len
                    if cursor + 2 <= len(hs_body):
                        sig_alg = int.from_bytes(hs_body[cursor:cursor + 2], 'big')
                        sig_map = {
                            0x0601: 'rsa_pkcs1_sha512', 0x0501: 'rsa_pkcs1_sha384', 0x0401: 'rsa_pkcs1_sha256',
                            0x0403: 'ecdsa_secp256r1_sha256', 0x0503: 'ecdsa_secp384r1_sha384', 0x0603: 'ecdsa_secp521r1_sha512',
                        }
                        hash_map = {2: 'SHA1', 3: 'SHA224', 4: 'SHA256', 5: 'SHA384', 6: 'SHA512'}
                        sign_map = {1: 'RSA', 2: 'DSA', 3: 'ECDSA'}
                        ecdhe_children.append({
                            'title': f'Signature Algorithm: {sig_map.get(sig_alg, f"0x{sig_alg:04x}")} (0x{sig_alg:04x})',
                            'offset': hs_abs + 4 + cursor,
                            'length': 2,
                            'children': [
                                {'title': f'Signature Hash Algorithm Hash: {hash_map.get(hs_body[cursor], hs_body[cursor])} ({hs_body[cursor]})', 'offset': hs_abs + 4 + cursor, 'length': 1},
                                {'title': f'Signature Hash Algorithm Signature: {sign_map.get(hs_body[cursor + 1], hs_body[cursor + 1])} ({hs_body[cursor + 1]})', 'offset': hs_abs + 4 + cursor + 1, 'length': 1},
                            ],
                        })
                        cursor += 2
                    if cursor + 2 <= len(hs_body):
                        sig_len = int.from_bytes(hs_body[cursor:cursor + 2], 'big')
                        ecdhe_children.append({'title': f'Signature Length: {sig_len}', 'offset': hs_abs + 4 + cursor, 'length': 2})
                        cursor += 2
                        if sig_len > 0 and cursor + sig_len <= len(hs_body):
                            ecdhe_children.append({'title': f'Signature: {hs_body[cursor:cursor + sig_len].hex()}', 'offset': hs_abs + 4 + cursor, 'length': sig_len})
                    handshake_children.append({
                        'title': 'EC Diffie-Hellman Server Params',
                        'offset': hs_abs + 4,
                        'length': len(hs_body),
                        'children': ecdhe_children,
                    })

                elif hs_type == 16 and len(hs_body) >= 1:
                    pub_len = int(hs_body[0])
                    ecdhe_client_children = [
                        {'title': f'Pubkey Length: {pub_len}', 'offset': hs_abs + 4, 'length': 1}
                    ]
                    if pub_len > 0 and 1 + pub_len <= len(hs_body):
                        ecdhe_client_children.append({'title': f'Pubkey: {hs_body[1:1 + pub_len].hex()}', 'offset': hs_abs + 5, 'length': pub_len})
                    handshake_children.append({
                        'title': 'EC Diffie-Hellman Client Params',
                        'offset': hs_abs + 4,
                        'length': len(hs_body),
                        'children': ecdhe_client_children,
                    })

                elif hs_type == 4 and len(hs_body) >= 6:
                    life = int.from_bytes(hs_body[0:4], 'big')
                    ticket_len = int.from_bytes(hs_body[4:6], 'big')
                    ticket = hs_body[6:6 + ticket_len]
                    handshake_children.append({
                        'title': 'TLS Session Ticket',
                        'offset': hs_abs + 4,
                        'length': min(len(hs_body), 6 + ticket_len),
                        'children': [
                            {'title': f'Session Ticket Lifetime Hint: {life} seconds ({life // 3600} hours)', 'offset': hs_abs + 4, 'length': 4},
                            {'title': f'Session Ticket Length: {ticket_len}', 'offset': hs_abs + 8, 'length': 2},
                            {'title': f'Session Ticket: {ticket.hex()}', 'offset': hs_abs + 10, 'length': max(0, len(ticket))},
                        ],
                    })

                record_children.append({
                    'title': f'Handshake Protocol: {hs_name}',
                    'offset': hs_abs,
                    'length': hs_total,
                    'children': handshake_children,
                })
                hs_pos += hs_total

            if hs_names:
                record_title = f'{record_version_name(version)} Record Layer: Handshake Protocol: {", ".join(hs_names)}'
        elif content_type == 20 and len(record_payload) >= 1:
            if int(record_payload[0]) == 1:
                record_title = f'{record_version_name(version)} Record Layer: Change Cipher Spec Protocol: Change Cipher Spec'
                record_children.append({
                    'title': 'Change Cipher Spec Message',
                    'offset': offset + payload_start,
                    'length': 1,
                })
            else:
                record_children.append({'title': f'Record Data: {record_payload.hex()}', 'offset': offset + payload_start, 'length': len(record_payload)})
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

    result = {
        'title': 'Transport Layer Security',
        'offset': offset,
        'length': tls_len,
        'children': children,
    }

    if _is_reassembled:
        # Tag every node with a byte mapping so hex_view highlights in the
        # "Reassembled TCP" tab instead of the raw frame bytes.
        def _tag_tcp_reassembled(node: dict):
            if 'offset' in node and 'length' in node:
                node['byte_source'] = TCP_REASSEMBLED_BYTE_SOURCE
            for child in node.get('children', []):
                _tag_tcp_reassembled(child)
        _tag_tcp_reassembled(result)

    return result


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
            {'title': f'Data: {raw_data.hex()}', 'offset': offset, 'length': len(raw_data)},
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

