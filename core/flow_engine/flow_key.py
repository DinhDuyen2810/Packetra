from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from scapy.all import IP, IPv6, TCP, UDP, ICMP  # type: ignore


@dataclass(frozen=True)
class FlowEndpoint:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str


@dataclass(frozen=True)
class FlowKey:
    """Canonical bidirectional key so A->B and B->A map to the same flow."""

    a_ip: str
    a_port: int
    b_ip: str
    b_port: int
    protocol: str

    @classmethod
    def from_endpoint(cls, endpoint: FlowEndpoint) -> tuple["FlowKey", bool]:
        fwd_tuple = (
            endpoint.src_ip,
            int(endpoint.src_port),
            endpoint.dst_ip,
            int(endpoint.dst_port),
        )
        rev_tuple = (
            endpoint.dst_ip,
            int(endpoint.dst_port),
            endpoint.src_ip,
            int(endpoint.src_port),
        )
        is_forward = fwd_tuple <= rev_tuple
        selected = fwd_tuple if is_forward else rev_tuple
        return (
            cls(
                a_ip=str(selected[0]),
                a_port=int(selected[1]),
                b_ip=str(selected[2]),
                b_port=int(selected[3]),
                protocol=str(endpoint.protocol).upper(),
            ),
            is_forward,
        )

    def flow_id(self) -> str:
        return f"{self.a_ip}-{self.b_ip}-{self.a_port}-{self.b_port}-{self.protocol}"


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return int(default)


def packet_to_endpoint(packet: Any) -> FlowEndpoint | None:
    if packet is None:
        return None

    if packet.haslayer(IP):
        ip_layer = packet[IP]
        src_ip = str(getattr(ip_layer, "src", "") or "")
        dst_ip = str(getattr(ip_layer, "dst", "") or "")
    elif packet.haslayer(IPv6):
        ip_layer = packet[IPv6]
        src_ip = str(getattr(ip_layer, "src", "") or "")
        dst_ip = str(getattr(ip_layer, "dst", "") or "")
    else:
        return None

    protocol = ""
    src_port = 0
    dst_port = 0

    if packet.haslayer(TCP):
        protocol = "TCP"
        src_port = _safe_int(getattr(packet[TCP], "sport", 0), 0)
        dst_port = _safe_int(getattr(packet[TCP], "dport", 0), 0)
    elif packet.haslayer(UDP):
        protocol = "UDP"
        src_port = _safe_int(getattr(packet[UDP], "sport", 0), 0)
        dst_port = _safe_int(getattr(packet[UDP], "dport", 0), 0)
    elif packet.haslayer(ICMP):
        protocol = "ICMP"
        icmp = packet[ICMP]
        src_port = _safe_int(getattr(icmp, "type", 0), 0)
        dst_port = _safe_int(getattr(icmp, "code", 0), 0)
    elif packet.haslayer("ICMPv6Unknown") or packet.haslayer("ICMPv6EchoRequest") or packet.haslayer("ICMPv6EchoReply"):
        protocol = "ICMPV6"
        icmp6 = packet.getlayer("ICMPv6Unknown") or packet.getlayer("ICMPv6EchoRequest") or packet.getlayer("ICMPv6EchoReply")
        src_port = _safe_int(getattr(icmp6, "type", 0), 0)
        dst_port = _safe_int(getattr(icmp6, "code", 0), 0)
    else:
        return None

    if not src_ip or not dst_ip:
        return None
    return FlowEndpoint(src_ip=src_ip, dst_ip=dst_ip, src_port=src_port, dst_port=dst_port, protocol=protocol)

