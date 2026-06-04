from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from math import isfinite
from typing import Any

import numpy
from scapy.all import IP, IPv6, TCP, UDP  # type: ignore

from .flow_key import FlowKey


def _to_float(value: Any, default: float = 0.0) -> float:
    try:
        out = float(value)
        return out if isfinite(out) else default
    except Exception:
        return default


def _to_int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _stats(values: list[float]) -> tuple[float, float, float, float]:
    if not values:
        return 0, 0, 0, 0
    if len(values) == 1:
        v = float(values[0])
        return v, 0.0, v, v
    arr = [float(v) for v in values]
    return float(numpy.mean(arr)), float(numpy.sqrt(numpy.var(arr))), float(max(arr)), float(min(arr))


def _iat_stats(values: list[float]) -> tuple[float, float, float, float]:
    if len(values) <= 1:
        return 0, 0, 0, 0
    arr = [float(v) for v in values]
    return float(numpy.mean(arr)), float(numpy.sqrt(numpy.var(arr))), float(max(arr)), float(min(arr))


CLUMP_TIMEOUT = 1.0
ACTIVE_TIMEOUT = 5.0


@dataclass
class PacketMeta:
    timestamp: float
    length: int
    payload_len: int
    header_len: int
    flags: int
    window: int
    direction: str  # fwd/bwd


class PacketraFlow:
    def __init__(
        self,
        key: FlowKey,
        start_time: float,
        first_direction_forward: bool,
        initiator_src_ip: str,
        initiator_src_port: int,
        initiator_dst_ip: str,
        initiator_dst_port: int,
    ) -> None:
        self.key = key
        self.start_time = _to_float(start_time)
        self.end_time = self.start_time
        self.first_direction_forward = bool(first_direction_forward)
        self.initiator_src_ip = str(initiator_src_ip or "")
        self.initiator_src_port = int(initiator_src_port or 0)
        self.initiator_dst_ip = str(initiator_dst_ip or "")
        self.initiator_dst_port = int(initiator_dst_port or 0)
        self.packets: list[PacketMeta] = []
        self._fwd_times: list[float] = []
        self._bwd_times: list[float] = []
        self._all_times: list[float] = []
        self._active_periods: list[float] = []
        self._idle_periods: list[float] = []
        self._last_ts: float | None = None
        self._active_start_ts: float = self.start_time
        self._last_active: float = 0.0
        self._init_win_fwd = 0
        self._init_win_bwd = 0
        self._subflow_fwd = 0
        self._subflow_bwd = 0
        self._subflow_fwd_bytes = 0
        self._subflow_bwd_bytes = 0
        # CIC-like bulk state
        self._forward_bulk_last_timestamp = 0.0
        self._forward_bulk_start_tmp = 0.0
        self._forward_bulk_count = 0
        self._forward_bulk_count_tmp = 0
        self._forward_bulk_duration = 0.0
        self._forward_bulk_packet_count = 0
        self._forward_bulk_size = 0
        self._forward_bulk_size_tmp = 0
        self._backward_bulk_last_timestamp = 0.0
        self._backward_bulk_start_tmp = 0.0
        self._backward_bulk_count = 0
        self._backward_bulk_count_tmp = 0
        self._backward_bulk_duration = 0.0
        self._backward_bulk_packet_count = 0
        self._backward_bulk_size = 0
        self._backward_bulk_size_tmp = 0
        self._fin_seen_fwd = False
        self._fin_seen_bwd = False
        self._rst_seen = False

    @property
    def flow_id(self) -> str:
        # Preserve the first-observed packet orientation so Flow ID stays aligned
        # with Src/Dst fields and CICFlowMeter-style output.
        if self.initiator_src_ip and self.initiator_dst_ip:
            return f"{self.initiator_src_ip}-{self.initiator_dst_ip}-{self.initiator_src_port}-{self.initiator_dst_port}-{self.key.protocol}"
        return self.key.flow_id()

    @property
    def latest_timestamp(self) -> float:
        return self.end_time

    @property
    def duration(self) -> float:
        if not self._all_times:
            return 0.0
        return max(0.0, max(float(ts) - self.start_time for ts in self._all_times))

    @property
    def tcp_terminated(self) -> bool:
        return bool(self._rst_seen or (self._fin_seen_fwd and self._fin_seen_bwd))

    def add_packet(self, packet: Any, timestamp: float, is_forward: bool) -> None:
        ts = _to_float(timestamp)
        self.end_time = max(self.end_time, ts)
        direction = "fwd" if is_forward else "bwd"

        length = _to_int(len(packet), 0)
        header_len = 0
        if packet.haslayer(IP):
            header_len = _to_int(getattr(packet[IP], "ihl", 0), 0) * 4
        elif packet.haslayer(IPv6):
            header_len = 40

        payload_len = 0
        flags = 0
        win = 0
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            flags = _to_int(getattr(tcp, "flags", 0), 0)
            win = _to_int(getattr(tcp, "window", 0), 0)
            try:
                payload_len = len(bytes(getattr(tcp, "payload", b"") or b""))
            except Exception:
                payload_len = 0
            if is_forward and self._init_win_fwd == 0:
                self._init_win_fwd = win
            if (not is_forward) and self._init_win_bwd == 0:
                self._init_win_bwd = win
        elif packet.haslayer(UDP):
            udp = packet[UDP]
            try:
                payload_len = len(bytes(getattr(udp, "payload", b"") or b""))
            except Exception:
                payload_len = 0

        self.packets.append(
            PacketMeta(
                timestamp=ts,
                length=length,
                payload_len=payload_len,
                header_len=header_len,
                flags=flags,
                window=win,
                direction=direction,
            )
        )

        self._update_flow_bulk(ts, payload_len, direction)
        if flags & 0x01:
            if direction == "fwd":
                self._fin_seen_fwd = True
            else:
                self._fin_seen_bwd = True
        if flags & 0x04:
            self._rst_seen = True

        # CICFlowMeter updates latest_timestamp before the active/idle check,
        # which makes the effective delta zero for the current packet.
        # Keep that behavior so our exported values stay aligned with the reference.
        last_timestamp = self.end_time
        if (ts - last_timestamp) > CLUMP_TIMEOUT:
            self._update_active_idle(ts - last_timestamp)
        self._last_ts = ts
        self._all_times.append(ts)
        if is_forward:
            self._fwd_times.append(ts)
            self._subflow_fwd += 1
            self._subflow_fwd_bytes += length
        else:
            self._bwd_times.append(ts)
            self._subflow_bwd += 1
            self._subflow_bwd_bytes += length

    def _iat(self, times: list[float]) -> list[float]:
        if len(times) <= 1:
            return []
        return [float(times[i]) - float(times[i - 1]) for i in range(1, len(times))]

    def _update_active_idle(self, current_time: float) -> None:
        if (current_time - self._last_active) > ACTIVE_TIMEOUT:
            duration = abs(self._last_active - self._active_start_ts)
            if duration > 0:
                self._active_periods.append(duration)
            self._idle_periods.append(current_time - self._last_active)
            self._active_start_ts = current_time
            self._last_active = current_time
        else:
            self._last_active = current_time

    def _flag_count(self, bit: int) -> int:
        return sum(1 for p in self.packets if (p.flags & bit) != 0)

    def _update_flow_bulk(self, ts: float, payload_size: int, direction: str) -> None:
        if payload_size <= 0:
            return
        CLUMP_TIMEOUT = 1.0
        BULK_BOUND = 4
        if direction == "fwd":
            if self._backward_bulk_last_timestamp > self._forward_bulk_start_tmp:
                self._forward_bulk_start_tmp = 0.0
            if self._forward_bulk_start_tmp == 0.0:
                self._forward_bulk_start_tmp = ts
                self._forward_bulk_last_timestamp = ts
                self._forward_bulk_count_tmp = 1
                self._forward_bulk_size_tmp = payload_size
            else:
                if (ts - self._forward_bulk_last_timestamp) > CLUMP_TIMEOUT:
                    self._forward_bulk_start_tmp = ts
                    self._forward_bulk_last_timestamp = ts
                    self._forward_bulk_count_tmp = 1
                    self._forward_bulk_size_tmp = payload_size
                else:
                    self._forward_bulk_count_tmp += 1
                    self._forward_bulk_size_tmp += payload_size
                    if self._forward_bulk_count_tmp == BULK_BOUND:
                        self._forward_bulk_count += 1
                        self._forward_bulk_packet_count += self._forward_bulk_count_tmp
                        self._forward_bulk_size += self._forward_bulk_size_tmp
                        self._forward_bulk_duration += (ts - self._forward_bulk_start_tmp)
                    elif self._forward_bulk_count_tmp > BULK_BOUND:
                        self._forward_bulk_packet_count += 1
                        self._forward_bulk_size += payload_size
                        self._forward_bulk_duration += (ts - self._forward_bulk_last_timestamp)
                    self._forward_bulk_last_timestamp = ts
        else:
            if self._forward_bulk_last_timestamp > self._backward_bulk_start_tmp:
                self._backward_bulk_start_tmp = 0.0
            if self._backward_bulk_start_tmp == 0.0:
                self._backward_bulk_start_tmp = ts
                self._backward_bulk_last_timestamp = ts
                self._backward_bulk_count_tmp = 1
                self._backward_bulk_size_tmp = payload_size
            else:
                if (ts - self._backward_bulk_last_timestamp) > CLUMP_TIMEOUT:
                    self._backward_bulk_start_tmp = ts
                    self._backward_bulk_last_timestamp = ts
                    self._backward_bulk_count_tmp = 1
                    self._backward_bulk_size_tmp = payload_size
                else:
                    self._backward_bulk_count_tmp += 1
                    self._backward_bulk_size_tmp += payload_size
                    if self._backward_bulk_count_tmp == BULK_BOUND:
                        self._backward_bulk_count += 1
                        self._backward_bulk_packet_count += self._backward_bulk_count_tmp
                        self._backward_bulk_size += self._backward_bulk_size_tmp
                        self._backward_bulk_duration += (ts - self._backward_bulk_start_tmp)
                    elif self._backward_bulk_count_tmp > BULK_BOUND:
                        self._backward_bulk_packet_count += 1
                        self._backward_bulk_size += payload_size
                        self._backward_bulk_duration += (ts - self._backward_bulk_last_timestamp)
                    self._backward_bulk_last_timestamp = ts

    def to_features(self) -> dict[str, Any]:
        duration_s = self.duration
        duration_us = int(round(duration_s * 1_000_000.0))
        total_pkts = len(self.packets)
        fwd_pkts = [p for p in self.packets if p.direction == "fwd"]
        bwd_pkts = [p for p in self.packets if p.direction == "bwd"]
        fwd_lengths = [float(p.length) for p in fwd_pkts]
        bwd_lengths = [float(p.length) for p in bwd_pkts]
        all_lengths = [float(p.length) for p in self.packets]

        fwd_mean, fwd_std, fwd_max, fwd_min = _stats(fwd_lengths)
        bwd_mean, bwd_std, bwd_max, bwd_min = _stats(bwd_lengths)
        pkt_mean, pkt_std, pkt_max, pkt_min = _stats(all_lengths)
        pkt_var = float(numpy.var(all_lengths)) if len(all_lengths) > 0 else 0.0

        flow_iat = self._iat(self._all_times)
        fwd_iat = self._iat(self._fwd_times)
        bwd_iat = self._iat(self._bwd_times)
        flow_iat_mean, flow_iat_std, flow_iat_max, flow_iat_min = _iat_stats(flow_iat)
        fwd_iat_mean, fwd_iat_std, fwd_iat_max, fwd_iat_min = _iat_stats(fwd_iat)
        bwd_iat_mean, bwd_iat_std, bwd_iat_max, bwd_iat_min = _iat_stats(bwd_iat)

        total_fwd_len = int(sum(fwd_lengths))
        total_bwd_len = int(sum(bwd_lengths))
        flow_bytes = total_fwd_len + total_bwd_len
        flow_bytes_s = (flow_bytes / duration_s) if duration_s > 0 else 0.0
        flow_pkts_s = (total_pkts / duration_s) if duration_s > 0 else 0.0
        fwd_pkts_s = (len(fwd_pkts) / duration_s) if duration_s > 0 else 0.0
        bwd_pkts_s = (len(bwd_pkts) / duration_s) if duration_s > 0 else 0.0

        fwd_header_len = int(sum(p.header_len for p in fwd_pkts))
        bwd_header_len = int(sum(p.header_len for p in bwd_pkts))
        min_seg_size_forward = int(min((p.header_len for p in fwd_pkts), default=0))
        act_data_pkt_fwd = int(sum(1 for p in fwd_pkts if p.payload_len > 0))

        active_mean, active_std, active_max, active_min = _stats(self._active_periods)
        idle_mean, idle_std, idle_max, idle_min = _stats(self._idle_periods)
        fwd_bytes_bulk = float(self._forward_bulk_size / self._forward_bulk_count) if self._forward_bulk_count > 0 else 0.0
        fwd_pkts_bulk = float(self._forward_bulk_packet_count / self._forward_bulk_count) if self._forward_bulk_count > 0 else 0.0
        fwd_bulk_rate = float(self._forward_bulk_size / self._forward_bulk_duration) if self._forward_bulk_duration > 0 else 0.0
        bwd_bytes_bulk = float(self._backward_bulk_size / self._backward_bulk_count) if self._backward_bulk_count > 0 else 0.0
        bwd_pkts_bulk = float(self._backward_bulk_packet_count / self._backward_bulk_count) if self._backward_bulk_count > 0 else 0.0
        bwd_bulk_rate = float(self._backward_bulk_size / self._backward_bulk_duration) if self._backward_bulk_duration > 0 else 0.0

        timestamp = datetime.fromtimestamp(self.start_time).strftime("%d/%m/%Y %H:%M:%S")
        src_ip = self.initiator_src_ip
        dst_ip = self.initiator_dst_ip
        src_port = self.initiator_src_port
        dst_port = self.initiator_dst_port

        avg_packet_size = float((flow_bytes / total_pkts) if total_pkts else 0.0)
        down_up_ratio = float((len(bwd_pkts) / len(fwd_pkts)) if fwd_pkts else 0.0)

        return {
            "Flow ID": self.flow_id,
            "Src IP": src_ip,
            "Src Port": src_port,
            "Dst IP": dst_ip,
            "Dst Port": dst_port,
            "Protocol": self.key.protocol,
            "Timestamp": timestamp,
            "Flow Duration": duration_us,
            "Total Fwd Packets": len(fwd_pkts),
            "Total Backward Packets": len(bwd_pkts),
            "Total Length of Fwd Packets": total_fwd_len,
            "Total Length of Bwd Packets": total_bwd_len,
            "Fwd Packet Length Max": fwd_max,
            "Fwd Packet Length Min": fwd_min,
            "Fwd Packet Length Mean": fwd_mean,
            "Fwd Packet Length Std": fwd_std,
            "Bwd Packet Length Max": bwd_max,
            "Bwd Packet Length Min": bwd_min,
            "Bwd Packet Length Mean": bwd_mean,
            "Bwd Packet Length Std": bwd_std,
            "Flow Bytes/s": flow_bytes_s,
            "Flow Packets/s": flow_pkts_s,
            "Flow IAT Mean": flow_iat_mean,
            "Flow IAT Std": flow_iat_std,
            "Flow IAT Max": flow_iat_max,
            "Flow IAT Min": flow_iat_min,
            "Fwd IAT Total": float(sum(fwd_iat)),
            "Fwd IAT Mean": fwd_iat_mean,
            "Fwd IAT Std": fwd_iat_std,
            "Fwd IAT Max": fwd_iat_max,
            "Fwd IAT Min": fwd_iat_min,
            "Bwd IAT Total": float(sum(bwd_iat)),
            "Bwd IAT Mean": bwd_iat_mean,
            "Bwd IAT Std": bwd_iat_std,
            "Bwd IAT Max": bwd_iat_max,
            "Bwd IAT Min": bwd_iat_min,
            "Fwd PSH Flags": int(sum(1 for p in fwd_pkts if p.flags & 0x08)),
            "Bwd PSH Flags": int(sum(1 for p in bwd_pkts if p.flags & 0x08)),
            "Fwd URG Flags": int(sum(1 for p in fwd_pkts if p.flags & 0x20)),
            "Bwd URG Flags": int(sum(1 for p in bwd_pkts if p.flags & 0x20)),
            "Fwd Header Length": fwd_header_len,
            "Bwd Header Length": bwd_header_len,
            "Fwd Packets/s": fwd_pkts_s,
            "Bwd Packets/s": bwd_pkts_s,
            "Min Packet Length": pkt_min,
            "Max Packet Length": pkt_max,
            "Packet Length Mean": pkt_mean,
            "Packet Length Std": pkt_std,
            "Packet Length Variance": pkt_var,
            "FIN Flag Count": self._flag_count(0x01),
            "SYN Flag Count": self._flag_count(0x02),
            "RST Flag Count": self._flag_count(0x04),
            "PSH Flag Count": self._flag_count(0x08),
            "ACK Flag Count": self._flag_count(0x10),
            "URG Flag Count": self._flag_count(0x20),
            "CWE Flag Count": int(sum(1 for p in fwd_pkts if p.flags & 0x20)),
            "ECE Flag Count": self._flag_count(0x40),
            "Down/Up Ratio": down_up_ratio,
            "Average Packet Size": avg_packet_size,
            "Avg Fwd Segment Size": fwd_mean,
            "Avg Bwd Segment Size": bwd_mean,
            "Fwd Avg Bytes/Bulk": fwd_bytes_bulk,
            "Fwd Avg Packets/Bulk": fwd_pkts_bulk,
            "Fwd Avg Bulk Rate": fwd_bulk_rate,
            "Bwd Avg Bytes/Bulk": bwd_bytes_bulk,
            "Bwd Avg Packets/Bulk": bwd_pkts_bulk,
            "Bwd Avg Bulk Rate": bwd_bulk_rate,
            "Subflow Fwd Packets": self._subflow_fwd,
            "Subflow Fwd Bytes": self._subflow_fwd_bytes,
            "Subflow Bwd Packets": self._subflow_bwd,
            "Subflow Bwd Bytes": self._subflow_bwd_bytes,
            "Init_Win_bytes_forward": self._init_win_fwd,
            "Init_Win_bytes_backward": self._init_win_bwd,
            "act_data_pkt_fwd": act_data_pkt_fwd,
            "min_seg_size_forward": min_seg_size_forward,
            "Active Mean": active_mean,
            "Active Std": active_std,
            "Active Max": active_max,
            "Active Min": active_min,
            "Idle Mean": idle_mean,
            "Idle Std": idle_std,
            "Idle Max": idle_max,
            "Idle Min": idle_min,
        }
