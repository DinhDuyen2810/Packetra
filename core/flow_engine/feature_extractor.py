from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from scapy.all import PcapReader, IP, TCP, UDP  # type: ignore

from .flow import PacketraFlow
from .flow_key import FlowKey, packet_to_endpoint
from .cic_reference import extract_cic_rows_from_packets


def _protocol_name(proto: Any) -> str:
    value = str(proto).strip()
    return {"6": "TCP", "17": "UDP", "1": "ICMP"}.get(value, value.upper())


def _reference_row_to_features(row: dict[str, Any]) -> dict[str, Any]:
    proto_name = _protocol_name(row.get("protocol", ""))
    src_ip = str(row.get("src_ip", "") or "")
    dst_ip = str(row.get("dst_ip", "") or "")
    src_port = row.get("src_port", 0)
    dst_port = row.get("dst_port", 0)
    flow_duration_us = int(round(float(row.get("flow_duration", 0) or 0.0) * 1_000_000.0))
    timestamp = str(row.get("timestamp", "") or "")

    return {
        "Flow ID": f"{src_ip}-{dst_ip}-{src_port}-{dst_port}-{proto_name}",
        "Src IP": src_ip,
        "Src Port": src_port,
        "Dst IP": dst_ip,
        "Dst Port": dst_port,
        "Protocol": proto_name,
        "Timestamp": timestamp,
        "Flow Duration": flow_duration_us,
        "Total Fwd Packets": row.get("tot_fwd_pkts", 0),
        "Total Backward Packets": row.get("tot_bwd_pkts", 0),
        "Total Length of Fwd Packets": row.get("totlen_fwd_pkts", 0),
        "Total Length of Bwd Packets": row.get("totlen_bwd_pkts", 0),
        "Fwd Packet Length Max": row.get("fwd_pkt_len_max", 0),
        "Fwd Packet Length Min": row.get("fwd_pkt_len_min", 0),
        "Fwd Packet Length Mean": row.get("fwd_pkt_len_mean", 0),
        "Fwd Packet Length Std": row.get("fwd_pkt_len_std", 0),
        "Bwd Packet Length Max": row.get("bwd_pkt_len_max", 0),
        "Bwd Packet Length Min": row.get("bwd_pkt_len_min", 0),
        "Bwd Packet Length Mean": row.get("bwd_pkt_len_mean", 0),
        "Bwd Packet Length Std": row.get("bwd_pkt_len_std", 0),
        "Flow Bytes/s": row.get("flow_byts_s", 0),
        "Flow Packets/s": row.get("flow_pkts_s", 0),
        "Flow IAT Mean": row.get("flow_iat_mean", 0),
        "Flow IAT Std": row.get("flow_iat_std", 0),
        "Flow IAT Max": row.get("flow_iat_max", 0),
        "Flow IAT Min": row.get("flow_iat_min", 0),
        "Fwd IAT Total": row.get("fwd_iat_tot", 0),
        "Fwd IAT Mean": row.get("fwd_iat_mean", 0),
        "Fwd IAT Std": row.get("fwd_iat_std", 0),
        "Fwd IAT Max": row.get("fwd_iat_max", 0),
        "Fwd IAT Min": row.get("fwd_iat_min", 0),
        "Bwd IAT Total": row.get("bwd_iat_tot", 0),
        "Bwd IAT Mean": row.get("bwd_iat_mean", 0),
        "Bwd IAT Std": row.get("bwd_iat_std", 0),
        "Bwd IAT Max": row.get("bwd_iat_max", 0),
        "Bwd IAT Min": row.get("bwd_iat_min", 0),
        "Fwd PSH Flags": row.get("fwd_psh_flags", 0),
        "Bwd PSH Flags": row.get("bwd_psh_flags", 0),
        "Fwd URG Flags": row.get("fwd_urg_flags", 0),
        "Bwd URG Flags": row.get("bwd_urg_flags", 0),
        "Fwd Header Length": row.get("fwd_header_len", 0),
        "Bwd Header Length": row.get("bwd_header_len", 0),
        "Fwd Packets/s": row.get("fwd_pkts_s", 0),
        "Bwd Packets/s": row.get("bwd_pkts_s", 0),
        "Min Packet Length": row.get("pkt_len_min", 0),
        "Max Packet Length": row.get("pkt_len_max", 0),
        "Packet Length Mean": row.get("pkt_len_mean", 0),
        "Packet Length Std": row.get("pkt_len_std", 0),
        "Packet Length Variance": row.get("pkt_len_var", 0),
        "FIN Flag Count": row.get("fin_flag_cnt", 0),
        "SYN Flag Count": row.get("syn_flag_cnt", 0),
        "RST Flag Count": row.get("rst_flag_cnt", 0),
        "PSH Flag Count": row.get("psh_flag_cnt", 0),
        "ACK Flag Count": row.get("ack_flag_cnt", 0),
        "URG Flag Count": row.get("urg_flag_cnt", 0),
        "CWE Flag Count": row.get("cwr_flag_count", 0),
        "ECE Flag Count": row.get("ece_flag_cnt", 0),
        "Down/Up Ratio": row.get("down_up_ratio", 0),
        "Average Packet Size": row.get("pkt_size_avg", 0),
        "Avg Fwd Segment Size": row.get("fwd_seg_size_avg", 0),
        "Avg Bwd Segment Size": row.get("bwd_seg_size_avg", 0),
        "Fwd Avg Bytes/Bulk": row.get("fwd_byts_b_avg", 0),
        "Fwd Avg Packets/Bulk": row.get("fwd_pkts_b_avg", 0),
        "Fwd Avg Bulk Rate": row.get("fwd_blk_rate_avg", 0),
        "Bwd Avg Bytes/Bulk": row.get("bwd_byts_b_avg", 0),
        "Bwd Avg Packets/Bulk": row.get("bwd_pkts_b_avg", 0),
        "Bwd Avg Bulk Rate": row.get("bwd_blk_rate_avg", 0),
        "Subflow Fwd Packets": row.get("subflow_fwd_pkts", 0),
        "Subflow Fwd Bytes": row.get("subflow_fwd_byts", 0),
        "Subflow Bwd Packets": row.get("subflow_bwd_pkts", 0),
        "Subflow Bwd Bytes": row.get("subflow_bwd_byts", 0),
        "Init_Win_bytes_forward": row.get("init_fwd_win_byts", 0),
        "Init_Win_bytes_backward": row.get("init_bwd_win_byts", 0),
        "act_data_pkt_fwd": row.get("fwd_act_data_pkts", 0),
        "min_seg_size_forward": row.get("fwd_seg_size_min", 0),
        "Active Mean": row.get("active_mean", 0),
        "Active Std": row.get("active_std", 0),
        "Active Max": row.get("active_max", 0),
        "Active Min": row.get("active_min", 0),
        "Idle Mean": row.get("idle_mean", 0),
        "Idle Std": row.get("idle_std", 0),
        "Idle Max": row.get("idle_max", 0),
        "Idle Min": row.get("idle_min", 0),
    }


class CICCompatFlowView:
    def __init__(self, reference_row: dict[str, Any]) -> None:
        self.reference_row = reference_row

    def to_features(self) -> dict[str, Any]:
        return _reference_row_to_features(self.reference_row)

    @property
    def flow_id(self) -> str:
        return str(self.to_features().get("Flow ID", ""))

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
            rows = extract_cic_rows_from_packets(packets)
            return [CICCompatFlowView(row) for row in rows]  # type: ignore[return-value]

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
            if (not pkt_obj.haslayer(IP)) or (not (pkt_obj.haslayer(TCP) or pkt_obj.haslayer(UDP))):
                skipped += 1
                continue
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
