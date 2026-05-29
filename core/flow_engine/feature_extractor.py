from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from scapy.all import PcapReader, IP, TCP, UDP  # type: ignore

from .flow import PacketraFlow
from .flow_key import FlowKey, packet_to_endpoint

log = logging.getLogger("flow_engine")


class FlowFeatureExtractor:
    def __init__(self, flow_timeout_seconds: float = 120.0, cic_compat_mode: bool = False) -> None:
        self.flow_timeout_seconds = float(flow_timeout_seconds)
        self.cic_compat_mode = bool(cic_compat_mode)

    def extract_from_pcap(self, pcap_path: str) -> list[PacketraFlow]:
        path = Path(pcap_path)
        if not path.exists():
            raise FileNotFoundError(f"Pcap not found: {pcap_path}")
        packets = []
        reader = PcapReader(str(path))
        try:
            for pkt in reader:
                packets.append(pkt)
        finally:
            try:
                reader.close()
            except Exception:
                pass
        return self.extract_from_packets(packets)

    def extract_from_packets(self, packets: list[Any]) -> list[PacketraFlow]:
        if self.cic_compat_mode:
            return self._extract_from_packets_cic_compat(packets)

        active: dict[FlowKey, PacketraFlow] = {}
        completed: list[PacketraFlow] = []
        skipped = 0
        for packet in packets:
            raw = getattr(packet, "raw", None)
            pkt_obj = raw if raw is not None else packet
            if (not pkt_obj.haslayer(IP)) or (not (pkt_obj.haslayer(TCP) or pkt_obj.haslayer(UDP))):
                skipped += 1
                continue
            endpoint = packet_to_endpoint(pkt_obj)
            if endpoint is None:
                skipped += 1
                continue

            key, is_forward = FlowKey.from_endpoint(endpoint)
            ts = float(getattr(pkt_obj, "time", 0.0) or 0.0)

            flow = active.get(key)
            existing_flow = flow is not None
            if flow is None:
                # Keep the canonical key for bidirectional grouping, but use the
                # first observed packet as the forward direction baseline.
                flow = PacketraFlow(
                    key=key,
                    start_time=ts,
                    first_direction_forward=True,
                    initiator_src_ip=endpoint.src_ip,
                    initiator_src_port=endpoint.src_port,
                    initiator_dst_ip=endpoint.dst_ip,
                    initiator_dst_port=endpoint.dst_port,
                )
                active[key] = flow
                is_forward = True
                if self.cic_compat_mode:
                    # CICFlowMeter-compatible behavior:
                    # first packet can be processed once in constructor path and once in update path.
                    flow.add_packet(pkt_obj, ts, is_forward=is_forward)
            else:
                is_forward = (
                    endpoint.src_ip == flow.initiator_src_ip
                    and int(endpoint.src_port) == int(flow.initiator_src_port)
                    and endpoint.dst_ip == flow.initiator_dst_ip
                    and int(endpoint.dst_port) == int(flow.initiator_dst_port)
                )
                if ts - flow.end_time > self.flow_timeout_seconds:
                    completed.append(flow)
                    flow = PacketraFlow(
                        key=key,
                        start_time=ts,
                        first_direction_forward=True,
                        initiator_src_ip=endpoint.src_ip,
                        initiator_src_port=endpoint.src_port,
                        initiator_dst_ip=endpoint.dst_ip,
                        initiator_dst_port=endpoint.dst_port,
                    )
                    active[key] = flow
                    is_forward = True
                    if self.cic_compat_mode:
                        flow.add_packet(pkt_obj, ts, is_forward=is_forward)

            try:
                flow.add_packet(pkt_obj, ts, is_forward=is_forward)
            except Exception as exc:
                skipped += 1
                log.debug("Skip packet during flow add: %s", exc)
                continue

            # NOTE:
            # In CICFlowMeter session, FIN branch triggers garbage_collect(latest_time)
            # but does not forcibly remove the current flow if GC keep-condition still passes.
            # Therefore, we do not close flow immediately on FIN here.

        if skipped:
            # Skipped packets are expected for non-IP/non-TCP-UDP frames or malformed frames.
            # Keep this at debug level to avoid noisy false-error impression in normal runs.
            log.debug("Flow extractor skipped %d unsupported/invalid packets", skipped)
        completed.extend(active.values())
        return completed

    def _extract_from_packets_cic_compat(self, packets: list[Any]) -> list[PacketraFlow]:
        EXPIRED_UPDATE = 240.0
        PACKETS_PER_GC = 1000
        active: dict[tuple[tuple[str, str, int, int, str], int], PacketraFlow] = {}
        completed: list[PacketraFlow] = []
        packets_count = 0
        skipped = 0

        def flow_key_tuple(src_ip: str, dst_ip: str, src_port: int, dst_port: int, proto: str) -> tuple[str, str, int, int, str]:
            return (str(src_ip), str(dst_ip), int(src_port), int(dst_port), str(proto))

        def garbage_collect(latest_time: float | None) -> None:
            to_remove: list[tuple[tuple[str, str, int, int, str], int]] = []
            for k, flow in active.items():
                if latest_time is not None and (latest_time - flow.latest_timestamp) < EXPIRED_UPDATE and flow.duration < 90.0:
                    continue
                completed.append(flow)
                to_remove.append(k)
            for k in to_remove:
                active.pop(k, None)

        for packet in packets:
            raw = getattr(packet, "raw", None)
            pkt_obj = raw if raw is not None else packet
            endpoint = packet_to_endpoint(pkt_obj)
            if endpoint is None:
                skipped += 1
                continue

            ts = float(getattr(pkt_obj, "time", 0.0) or 0.0)
            proto = str(endpoint.protocol or "")
            fwd_key = flow_key_tuple(endpoint.src_ip, endpoint.dst_ip, endpoint.src_port, endpoint.dst_port, proto)
            rev_key = flow_key_tuple(endpoint.dst_ip, endpoint.src_ip, endpoint.dst_port, endpoint.src_port, proto)
            count = 0
            direction_forward = True

            flow = active.get((fwd_key, count))
            if flow is None:
                direction_forward = False
                flow = active.get((rev_key, count))

            packets_count += 1

            created_new = False
            current_key = fwd_key if direction_forward else rev_key
            if flow is None:
                direction_forward = True
                current_key = fwd_key
                key_obj, _ = FlowKey.from_endpoint(endpoint)
                flow = PacketraFlow(
                    key=key_obj,
                    start_time=ts,
                    first_direction_forward=True,
                    initiator_src_ip=endpoint.src_ip,
                    initiator_src_port=endpoint.src_port,
                    initiator_dst_ip=endpoint.dst_ip,
                    initiator_dst_port=endpoint.dst_port,
                )
                active[(current_key, count)] = flow
                created_new = True
            elif (ts - flow.latest_timestamp) > EXPIRED_UPDATE:
                expired = EXPIRED_UPDATE
                while (ts - flow.latest_timestamp) > expired:
                    count += 1
                    expired += EXPIRED_UPDATE
                    flow2 = active.get((current_key, count))
                    if flow2 is None:
                        key_obj, _ = FlowKey.from_endpoint(endpoint)
                        flow = PacketraFlow(
                            key=key_obj,
                            start_time=ts,
                            first_direction_forward=direction_forward,
                            initiator_src_ip=endpoint.src_ip if direction_forward else endpoint.dst_ip,
                            initiator_src_port=endpoint.src_port if direction_forward else endpoint.dst_port,
                            initiator_dst_ip=endpoint.dst_ip if direction_forward else endpoint.src_ip,
                            initiator_dst_port=endpoint.dst_port if direction_forward else endpoint.src_port,
                        )
                        active[(current_key, count)] = flow
                        created_new = True
                        break
                    flow = flow2

            if created_new:
                # CICFlowMeter-compatible behavior:
                # first packet can be processed once in constructor path and once in update path.
                try:
                    flow.add_packet(pkt_obj, ts, is_forward=direction_forward)
                except Exception as exc:
                    skipped += 1
                    log.debug("Skip packet during flow add(created_new): %s", exc)
                    continue

            # FIN branch in CIC triggers GC and returns after a single add.
            if flow is not None and not created_new and pkt_obj.haslayer(TCP):
                try:
                    flags = int(getattr(pkt_obj[TCP], "flags", 0) or 0)
                except Exception:
                    flags = 0
                if flags & 0x01:
                    try:
                        flow.add_packet(pkt_obj, ts, is_forward=direction_forward)
                    except Exception as exc:
                        skipped += 1
                        log.debug("Skip packet during flow add(fin): %s", exc)
                        continue
                    garbage_collect(ts)
                    continue

            try:
                flow.add_packet(pkt_obj, ts, is_forward=direction_forward)
            except Exception as exc:
                skipped += 1
                log.debug("Skip packet during flow add: %s", exc)
                continue

            if packets_count % PACKETS_PER_GC == 0 or flow.duration > 120.0:
                garbage_collect(ts)

        garbage_collect(None)
        if skipped:
            log.debug("Flow extractor skipped %d unsupported/invalid packets", skipped)
        return completed

    def extract_features(self, packets: list[Any]) -> list[dict[str, Any]]:
        return [flow.to_features() for flow in self.extract_from_packets(packets)]
