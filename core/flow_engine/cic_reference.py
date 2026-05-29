from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from scapy.all import IP, TCP, UDP  # type: ignore


def _load_cic_modules() -> tuple[Any, Any, Any]:
    root = Path(__file__).resolve().parents[2]
    cic_src = root / "docs" / "CICFlowMeter" / "cicflowmeter-master" / "src"
    if str(cic_src) not in sys.path:
        sys.path.insert(0, str(cic_src))
    from cicflowmeter.flow import Flow  # type: ignore
    from cicflowmeter.features.context import PacketDirection, get_packet_flow_key  # type: ignore
    from cicflowmeter.constants import EXPIRED_UPDATE, PACKETS_PER_GC  # type: ignore
    return Flow, PacketDirection, (EXPIRED_UPDATE, PACKETS_PER_GC, get_packet_flow_key)


def extract_cic_rows_from_packets(packets: list[Any]) -> list[dict[str, Any]]:
    Flow, PacketDirection, deps = _load_cic_modules()
    EXPIRED_UPDATE, PACKETS_PER_GC, get_packet_flow_key = deps

    flows: dict[tuple, Any] = {}
    packets_count = 0
    out_rows: list[dict[str, Any]] = []

    def garbage_collect(latest_time: float | None) -> None:
        keys = list(flows.keys())
        for k in keys:
            flow = flows.get(k)
            if not flow:
                continue
            if (
                latest_time is not None
                and (latest_time - flow.latest_timestamp) < EXPIRED_UPDATE
                and flow.duration < 90
            ):
                continue
            out_rows.append(flow.get_data(None))
            del flows[k]

    for pkt in packets:
        if (not pkt.haslayer(IP)) or (not (pkt.haslayer(TCP) or pkt.haslayer(UDP))):
            continue
        count = 0
        direction = PacketDirection.FORWARD
        try:
            packet_flow_key = get_packet_flow_key(pkt, direction)
            flow = flows.get((packet_flow_key, count))
        except Exception:
            continue

        packets_count += 1

        if flow is None:
            direction = PacketDirection.REVERSE
            packet_flow_key = get_packet_flow_key(pkt, direction)
            flow = flows.get((packet_flow_key, count))

        if flow is None:
            direction = PacketDirection.FORWARD
            flow = Flow(pkt, direction)
            packet_flow_key = get_packet_flow_key(pkt, direction)
            flows[(packet_flow_key, count)] = flow
        elif (pkt.time - flow.latest_timestamp) > EXPIRED_UPDATE:
            expired = EXPIRED_UPDATE
            while (pkt.time - flow.latest_timestamp) > expired:
                count += 1
                expired += EXPIRED_UPDATE
                flow2 = flows.get((packet_flow_key, count))
                if flow2 is None:
                    flow = Flow(pkt, direction)
                    flows[(packet_flow_key, count)] = flow
                    break
                flow = flow2
        elif "F" in pkt.flags:
            flow.add_packet(pkt, direction)
            garbage_collect(float(pkt.time))
            continue

        flow.add_packet(pkt, direction)
        if packets_count % PACKETS_PER_GC == 0 or flow.duration > 120:
            garbage_collect(float(pkt.time))

    garbage_collect(None)
    return out_rows
