from __future__ import annotations

from typing import Dict, Optional, Tuple


_eth_streams: Dict[Tuple, int] = {}
_ip_streams: Dict[Tuple, int] = {}
_ipv6_streams: Dict[Tuple, int] = {}
_tcp_streams: Dict[Tuple, int] = {}
_udp_streams: Dict[Tuple, int] = {}

_eth_next = 0
_ip_next = 0
_ipv6_next = 0
_tcp_next = 0
_udp_next = 0

_stream_packet_counts: Dict[Tuple[str, int], int] = {}
_stream_seq_ack: Dict[Tuple[str, int], Tuple[Optional[int], Optional[int]]] = {}


def reset_streams():
    global _eth_streams, _ip_streams, _ipv6_streams, _tcp_streams, _udp_streams
    global _eth_next, _ip_next, _ipv6_next, _tcp_next, _udp_next
    global _stream_packet_counts, _stream_seq_ack

    _eth_streams.clear()
    _ip_streams.clear()
    _ipv6_streams.clear()
    _tcp_streams.clear()
    _udp_streams.clear()
    _stream_packet_counts.clear()
    _stream_seq_ack.clear()

    _eth_next = 0
    _ip_next = 0
    _ipv6_next = 0
    _tcp_next = 0
    _udp_next = 0


def _normalize_mac(mac: str) -> str:
    return mac.lower() if mac else mac


def _get_stream_key_ether(src_mac: str, dst_mac: str):
    src = _normalize_mac(src_mac)
    dst = _normalize_mac(dst_mac)
    fwd = (src, dst)
    rev = (dst, src)
    return fwd, rev


def _get_stream_key_ip(src_ip: str, dst_ip: str):
    fwd = (src_ip, dst_ip)
    rev = (dst_ip, src_ip)
    return fwd, rev


def _get_stream_key_transport(src_ip: str, sport: int, dst_ip: str, dport: int):
    fwd = (src_ip, int(sport), dst_ip, int(dport))
    rev = (dst_ip, int(dport), src_ip, int(sport))
    return fwd, rev


def get_ether_stream_index(src_mac: str, dst_mac: str):
    global _eth_next
    fwd, rev = _get_stream_key_ether(src_mac, dst_mac)

    if fwd in _eth_streams:
        return _eth_streams[fwd]
    if rev in _eth_streams:
        return _eth_streams[rev]

    idx = _eth_next
    _eth_streams[fwd] = idx
    _eth_next += 1
    return idx


def get_ip_stream_index(src_ip: str, dst_ip: str):
    global _ip_next
    fwd, rev = _get_stream_key_ip(src_ip, dst_ip)

    if fwd in _ip_streams:
        return _ip_streams[fwd]
    if rev in _ip_streams:
        return _ip_streams[rev]

    idx = _ip_next
    _ip_streams[fwd] = idx
    _ip_next += 1
    return idx


def get_ipv6_stream_index(src_ip: str, dst_ip: str):
    global _ipv6_next
    fwd, rev = _get_stream_key_ip(src_ip, dst_ip)

    if fwd in _ipv6_streams:
        return _ipv6_streams[fwd]
    if rev in _ipv6_streams:
        return _ipv6_streams[rev]

    idx = _ipv6_next
    _ipv6_streams[fwd] = idx
    _ipv6_next += 1
    return idx


def get_tcp_stream_index(src_ip: str, sport: int, dst_ip: str, dport: int):
    global _tcp_next
    fwd, rev = _get_stream_key_transport(src_ip, sport, dst_ip, dport)

    if fwd in _tcp_streams:
        return _tcp_streams[fwd]
    if rev in _tcp_streams:
        return _tcp_streams[rev]

    idx = _tcp_next
    _tcp_streams[fwd] = idx
    _tcp_next += 1
    return idx


def get_udp_stream_index(src_ip: str, sport: int, dst_ip: str, dport: int):
    global _udp_next
    fwd, rev = _get_stream_key_transport(src_ip, sport, dst_ip, dport)

    if fwd in _udp_streams:
        return _udp_streams[fwd]
    if rev in _udp_streams:
        return _udp_streams[rev]

    idx = _udp_next
    _udp_streams[fwd] = idx
    _udp_next += 1
    return idx


def get_and_count_stream_packet(stream_type: str, stream_index: int) -> int:
    key = (stream_type, stream_index)
    current = _stream_packet_counts.get(key, 0)
    _stream_packet_counts[key] = current + 1
    return current + 1


def track_stream_seq_ack(stream_type: str, stream_index: int, seq: int, ack: int) -> Tuple[int, int]:
    key = (stream_type, stream_index)
    if key not in _stream_seq_ack:
        _stream_seq_ack[key] = (seq, ack)
        return (0, 0)
    
    first_seq, first_ack = _stream_seq_ack[key]
    relative_seq = (seq - first_seq) & 0xFFFFFFFF
    relative_ack = (ack - first_ack) & 0xFFFFFFFF
    return (relative_seq, relative_ack)