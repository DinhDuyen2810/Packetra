from __future__ import annotations

import csv
from datetime import datetime
from pathlib import Path
from typing import Any

from .feature_extractor import FlowFeatureExtractor
from .flow import PacketraFlow
from .cic_reference import extract_cic_rows_from_packets
from scapy.all import PcapReader  # type: ignore


CSV_HEADER = [
    "Flow ID",
    "Src IP",
    "Src Port",
    "Dst IP",
    "Dst Port",
    "Protocol",
    "Timestamp",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Total",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd PSH Flags",
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",
    "Fwd Header Length",
    "Bwd Header Length",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "CWE Flag Count",
    "ECE Flag Count",
    "Down/Up Ratio",
    "Average Packet Size",
    "Avg Fwd Segment Size",
    "Avg Bwd Segment Size",
    "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets",
    "Subflow Fwd Bytes",
    "Subflow Bwd Packets",
    "Subflow Bwd Bytes",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "act_data_pkt_fwd",
    "min_seg_size_forward",
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min",
]

CIC_COMPAT_HEADER = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Total",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd PSH Flags",
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",
    "Fwd Header Length",
    "Bwd Header Length",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "CWE Flag Count",
    "ECE Flag Count",
    "Down/Up Ratio",
    "Average Packet Size",
    "Avg Fwd Segment Size",
    "Avg Bwd Segment Size",
    "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets",
    "Subflow Fwd Bytes",
    "Subflow Bwd Packets",
    "Subflow Bwd Bytes",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "act_data_pkt_fwd",
    "min_seg_size_forward",
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min",
]

CIC_LEGACY_HEADER = [
    "dst_port", "flow_duration", "tot_fwd_pkts", "tot_bwd_pkts", "totlen_fwd_pkts", "totlen_bwd_pkts",
    "fwd_pkt_len_max", "fwd_pkt_len_min", "fwd_pkt_len_mean", "fwd_pkt_len_std", "bwd_pkt_len_max",
    "bwd_pkt_len_min", "bwd_pkt_len_mean", "bwd_pkt_len_std", "flow_byts_s", "flow_pkts_s",
    "flow_iat_mean", "flow_iat_std", "flow_iat_max", "flow_iat_min", "fwd_iat_tot", "fwd_iat_mean",
    "fwd_iat_std", "fwd_iat_max", "fwd_iat_min", "bwd_iat_tot", "bwd_iat_mean", "bwd_iat_std",
    "bwd_iat_max", "bwd_iat_min", "fwd_psh_flags", "bwd_psh_flags", "fwd_urg_flags", "bwd_urg_flags",
    "fwd_header_len", "bwd_header_len", "fwd_pkts_s", "bwd_pkts_s", "pkt_len_min", "pkt_len_max",
    "pkt_len_mean", "pkt_len_std", "pkt_len_var", "fin_flag_cnt", "syn_flag_cnt", "rst_flag_cnt",
    "psh_flag_cnt", "ack_flag_cnt", "urg_flag_cnt", "cwr_flag_count", "ece_flag_cnt", "down_up_ratio",
    "pkt_size_avg", "fwd_seg_size_avg", "bwd_seg_size_avg", "fwd_byts_b_avg", "fwd_pkts_b_avg",
    "fwd_blk_rate_avg", "bwd_byts_b_avg", "bwd_pkts_b_avg", "bwd_blk_rate_avg", "subflow_fwd_pkts",
    "subflow_fwd_byts", "subflow_bwd_pkts", "subflow_bwd_byts", "init_fwd_win_byts", "init_bwd_win_byts",
    "act_data_pkt_fwd", "min_seg_size_forward", "active_mean", "active_std", "active_max", "active_min",
    "idle_mean", "idle_std", "idle_max", "idle_min",
]

CIC_SOURCE_HEADER = [
    "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "timestamp",
    "flow_duration", "flow_byts_s", "flow_pkts_s", "fwd_pkts_s", "bwd_pkts_s",
    "tot_fwd_pkts", "tot_bwd_pkts", "totlen_fwd_pkts", "totlen_bwd_pkts",
    "fwd_pkt_len_max", "fwd_pkt_len_min", "fwd_pkt_len_mean", "fwd_pkt_len_std",
    "bwd_pkt_len_max", "bwd_pkt_len_min", "bwd_pkt_len_mean", "bwd_pkt_len_std",
    "pkt_len_max", "pkt_len_min", "pkt_len_mean", "pkt_len_std", "pkt_len_var",
    "fwd_header_len", "bwd_header_len", "fwd_seg_size_min", "fwd_act_data_pkts",
    "flow_iat_mean", "flow_iat_max", "flow_iat_min", "flow_iat_std",
    "fwd_iat_tot", "fwd_iat_max", "fwd_iat_min", "fwd_iat_mean", "fwd_iat_std",
    "bwd_iat_tot", "bwd_iat_max", "bwd_iat_min", "bwd_iat_mean", "bwd_iat_std",
    "fwd_psh_flags", "bwd_psh_flags", "fwd_urg_flags", "bwd_urg_flags",
    "fin_flag_cnt", "syn_flag_cnt", "rst_flag_cnt", "psh_flag_cnt", "ack_flag_cnt", "urg_flag_cnt", "ece_flag_cnt",
    "down_up_ratio", "pkt_size_avg", "init_fwd_win_byts", "init_bwd_win_byts",
    "active_max", "active_min", "active_mean", "active_std",
    "idle_max", "idle_min", "idle_mean", "idle_std",
    "fwd_byts_b_avg", "fwd_pkts_b_avg", "bwd_byts_b_avg", "bwd_pkts_b_avg",
    "fwd_blk_rate_avg", "bwd_blk_rate_avg", "fwd_seg_size_avg", "bwd_seg_size_avg", "cwr_flag_count",
    "subflow_fwd_pkts", "subflow_bwd_pkts", "subflow_fwd_byts", "subflow_bwd_byts",
]


def _write_feature_rows(rows: list[dict[str, Any]], output_path: str) -> str:
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(CSV_HEADER)
        for row in rows:
            writer.writerow([row.get(col, 0) for col in CSV_HEADER])
    return str(out)


def export_flows_to_csv(flows: list[PacketraFlow], output_path: str) -> str:
    rows = [flow.to_features() for flow in flows]
    return _write_feature_rows(rows, output_path)


def export_flows_to_cic_csv(flows: list[PacketraFlow], output_path: str) -> str:
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(CIC_COMPAT_HEADER)
        for flow in flows:
            ref_row = getattr(flow, "reference_row", None)
            feat = flow.to_features()
            row = []
            for col in CIC_COMPAT_HEADER:
                if col == "Destination Port":
                    row.append(feat.get("Dst Port", 0))
                elif ref_row is not None and col == "Flow Duration":
                    row.append(float(ref_row.get("flow_duration", feat.get("Flow Duration", 0)) or 0))
                elif ref_row is not None and col in {
                    "Flow Bytes/s",
                    "Flow Packets/s",
                    "Fwd Packets/s",
                    "Bwd Packets/s",
                }:
                    ref_key = {
                        "Flow Bytes/s": "flow_byts_s",
                        "Flow Packets/s": "flow_pkts_s",
                        "Fwd Packets/s": "fwd_pkts_s",
                        "Bwd Packets/s": "bwd_pkts_s",
                    }[col]
                    row.append(ref_row.get(ref_key, feat.get(col, 0)))
                else:
                    row.append(feat.get(col, 0))
            writer.writerow(row)
    return str(out)


def export_flows_to_cic_legacy_csv(flows: list[PacketraFlow], output_path: str) -> str:
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(CIC_LEGACY_HEADER)
        for flow in flows:
            ref_row = getattr(flow, "reference_row", None)
            feat = flow.to_features()
            # Legacy CIC block (snake_case header) stores duration/IAT-like fields in seconds.
            sec_fields: set[str] = set()
            key_map = {
                "dst_port": "Dst Port",
                "flow_duration": "Flow Duration",
                "tot_fwd_pkts": "Total Fwd Packets",
                "tot_bwd_pkts": "Total Backward Packets",
                "totlen_fwd_pkts": "Total Length of Fwd Packets",
                "totlen_bwd_pkts": "Total Length of Bwd Packets",
                "fwd_pkt_len_max": "Fwd Packet Length Max",
                "fwd_pkt_len_min": "Fwd Packet Length Min",
                "fwd_pkt_len_mean": "Fwd Packet Length Mean",
                "fwd_pkt_len_std": "Fwd Packet Length Std",
                "bwd_pkt_len_max": "Bwd Packet Length Max",
                "bwd_pkt_len_min": "Bwd Packet Length Min",
                "bwd_pkt_len_mean": "Bwd Packet Length Mean",
                "bwd_pkt_len_std": "Bwd Packet Length Std",
                "flow_byts_s": "Flow Bytes/s",
                "flow_pkts_s": "Flow Packets/s",
                "flow_iat_mean": "Flow IAT Mean",
                "flow_iat_std": "Flow IAT Std",
                "flow_iat_max": "Flow IAT Max",
                "flow_iat_min": "Flow IAT Min",
                "fwd_iat_tot": "Fwd IAT Total",
                "fwd_iat_mean": "Fwd IAT Mean",
                "fwd_iat_std": "Fwd IAT Std",
                "fwd_iat_max": "Fwd IAT Max",
                "fwd_iat_min": "Fwd IAT Min",
                "bwd_iat_tot": "Bwd IAT Total",
                "bwd_iat_mean": "Bwd IAT Mean",
                "bwd_iat_std": "Bwd IAT Std",
                "bwd_iat_max": "Bwd IAT Max",
                "bwd_iat_min": "Bwd IAT Min",
                "fwd_psh_flags": "Fwd PSH Flags",
                "bwd_psh_flags": "Bwd PSH Flags",
                "fwd_urg_flags": "Fwd URG Flags",
                "bwd_urg_flags": "Bwd URG Flags",
                "fwd_header_len": "Fwd Header Length",
                "bwd_header_len": "Bwd Header Length",
                "fwd_pkts_s": "Fwd Packets/s",
                "bwd_pkts_s": "Bwd Packets/s",
                "pkt_len_min": "Min Packet Length",
                "pkt_len_max": "Max Packet Length",
                "pkt_len_mean": "Packet Length Mean",
                "pkt_len_std": "Packet Length Std",
                "pkt_len_var": "Packet Length Variance",
                "fin_flag_cnt": "FIN Flag Count",
                "syn_flag_cnt": "SYN Flag Count",
                "rst_flag_cnt": "RST Flag Count",
                "psh_flag_cnt": "PSH Flag Count",
                "ack_flag_cnt": "ACK Flag Count",
                "urg_flag_cnt": "URG Flag Count",
                "cwr_flag_count": "CWE Flag Count",
                "ece_flag_cnt": "ECE Flag Count",
                "down_up_ratio": "Down/Up Ratio",
                "pkt_size_avg": "Average Packet Size",
                "fwd_seg_size_avg": "Avg Fwd Segment Size",
                "bwd_seg_size_avg": "Avg Bwd Segment Size",
                "fwd_byts_b_avg": "Fwd Avg Bytes/Bulk",
                "fwd_pkts_b_avg": "Fwd Avg Packets/Bulk",
                "fwd_blk_rate_avg": "Fwd Avg Bulk Rate",
                "bwd_byts_b_avg": "Bwd Avg Bytes/Bulk",
                "bwd_pkts_b_avg": "Bwd Avg Packets/Bulk",
                "bwd_blk_rate_avg": "Bwd Avg Bulk Rate",
                "subflow_fwd_pkts": "Subflow Fwd Packets",
                "subflow_fwd_byts": "Subflow Fwd Bytes",
                "subflow_bwd_pkts": "Subflow Bwd Packets",
                "subflow_bwd_byts": "Subflow Bwd Bytes",
                "init_fwd_win_byts": "Init_Win_bytes_forward",
                "init_bwd_win_byts": "Init_Win_bytes_backward",
                "act_data_pkt_fwd": "act_data_pkt_fwd",
                "min_seg_size_forward": "min_seg_size_forward",
                "active_mean": "Active Mean",
                "active_std": "Active Std",
                "active_max": "Active Max",
                "active_min": "Active Min",
                "idle_mean": "Idle Mean",
                "idle_std": "Idle Std",
                "idle_max": "Idle Max",
                "idle_min": "Idle Min",
            }
            row = []
            for col in CIC_LEGACY_HEADER:
                src_key = key_map[col]
                if ref_row is not None:
                    ref_key = {
                        "dst_port": "dst_port",
                        "flow_duration": "flow_duration",
                        "tot_fwd_pkts": "tot_fwd_pkts",
                        "tot_bwd_pkts": "tot_bwd_pkts",
                        "totlen_fwd_pkts": "totlen_fwd_pkts",
                        "totlen_bwd_pkts": "totlen_bwd_pkts",
                        "fwd_pkt_len_max": "fwd_pkt_len_max",
                        "fwd_pkt_len_min": "fwd_pkt_len_min",
                        "fwd_pkt_len_mean": "fwd_pkt_len_mean",
                        "fwd_pkt_len_std": "fwd_pkt_len_std",
                        "bwd_pkt_len_max": "bwd_pkt_len_max",
                        "bwd_pkt_len_min": "bwd_pkt_len_min",
                        "bwd_pkt_len_mean": "bwd_pkt_len_mean",
                        "bwd_pkt_len_std": "bwd_pkt_len_std",
                        "flow_byts_s": "flow_byts_s",
                        "flow_pkts_s": "flow_pkts_s",
                        "flow_iat_mean": "flow_iat_mean",
                        "flow_iat_std": "flow_iat_std",
                        "flow_iat_max": "flow_iat_max",
                        "flow_iat_min": "flow_iat_min",
                        "fwd_iat_tot": "fwd_iat_tot",
                        "fwd_iat_mean": "fwd_iat_mean",
                        "fwd_iat_std": "fwd_iat_std",
                        "fwd_iat_max": "fwd_iat_max",
                        "fwd_iat_min": "fwd_iat_min",
                        "bwd_iat_tot": "bwd_iat_tot",
                        "bwd_iat_mean": "bwd_iat_mean",
                        "bwd_iat_std": "bwd_iat_std",
                        "bwd_iat_max": "bwd_iat_max",
                        "bwd_iat_min": "bwd_iat_min",
                        "fwd_psh_flags": "fwd_psh_flags",
                        "bwd_psh_flags": "bwd_psh_flags",
                        "fwd_urg_flags": "fwd_urg_flags",
                        "bwd_urg_flags": "bwd_urg_flags",
                        "fwd_header_len": "fwd_header_len",
                        "bwd_header_len": "bwd_header_len",
                        "fwd_pkts_s": "fwd_pkts_s",
                        "bwd_pkts_s": "bwd_pkts_s",
                        "pkt_len_min": "pkt_len_min",
                        "pkt_len_max": "pkt_len_max",
                        "pkt_len_mean": "pkt_len_mean",
                        "pkt_len_std": "pkt_len_std",
                        "pkt_len_var": "pkt_len_var",
                        "fin_flag_cnt": "fin_flag_cnt",
                        "syn_flag_cnt": "syn_flag_cnt",
                        "rst_flag_cnt": "rst_flag_cnt",
                        "psh_flag_cnt": "psh_flag_cnt",
                        "ack_flag_cnt": "ack_flag_cnt",
                        "urg_flag_cnt": "urg_flag_cnt",
                        "cwr_flag_count": "cwr_flag_count",
                        "ece_flag_cnt": "ece_flag_cnt",
                        "down_up_ratio": "down_up_ratio",
                        "pkt_size_avg": "pkt_size_avg",
                        "fwd_seg_size_avg": "fwd_seg_size_avg",
                        "bwd_seg_size_avg": "bwd_seg_size_avg",
                        "fwd_byts_b_avg": "fwd_byts_b_avg",
                        "fwd_pkts_b_avg": "fwd_pkts_b_avg",
                        "fwd_blk_rate_avg": "fwd_blk_rate_avg",
                        "bwd_byts_b_avg": "bwd_byts_b_avg",
                        "bwd_pkts_b_avg": "bwd_pkts_b_avg",
                        "bwd_blk_rate_avg": "bwd_blk_rate_avg",
                        "subflow_fwd_pkts": "subflow_fwd_pkts",
                        "subflow_fwd_byts": "subflow_fwd_byts",
                        "subflow_bwd_pkts": "subflow_bwd_pkts",
                        "subflow_bwd_byts": "subflow_bwd_byts",
                        "init_fwd_win_byts": "init_fwd_win_byts",
                        "init_bwd_win_byts": "init_bwd_win_byts",
                        "act_data_pkt_fwd": "fwd_act_data_pkts",
                        "min_seg_size_forward": "fwd_seg_size_min",
                        "active_mean": "active_mean",
                        "active_std": "active_std",
                        "active_max": "active_max",
                        "active_min": "active_min",
                        "idle_mean": "idle_mean",
                        "idle_std": "idle_std",
                        "idle_max": "idle_max",
                        "idle_min": "idle_min",
                    }[col]
                    value = ref_row.get(ref_key, 0)
                else:
                    value = feat.get(src_key, 0)
                    if col == "flow_duration":
                        value = round(float(value or 0) / 1_000_000.0, 6)
                    elif col == "flow_byts_s":
                        dur_s = round(float(feat.get("Flow Duration", 0) or 0) / 1_000_000.0, 6)
                        tot_fwd = float(feat.get("Total Fwd Packets", 0) or 0)
                        tot_bwd = float(feat.get("Total Backward Packets", 0) or 0)
                        tot_fwd_len = float(feat.get("Total Length of Fwd Packets", 0) or 0)
                        tot_bwd_len = float(feat.get("Total Length of Bwd Packets", 0) or 0)
                        value = ((tot_fwd_len + tot_bwd_len) / dur_s) if dur_s > 0 else 0.0
                    elif col == "flow_pkts_s":
                        dur_s = round(float(feat.get("Flow Duration", 0) or 0) / 1_000_000.0, 6)
                        tot_fwd = float(feat.get("Total Fwd Packets", 0) or 0)
                        tot_bwd = float(feat.get("Total Backward Packets", 0) or 0)
                        value = ((tot_fwd + tot_bwd) / dur_s) if dur_s > 0 else 0.0
                    elif col == "fwd_pkts_s":
                        dur_s = round(float(feat.get("Flow Duration", 0) or 0) / 1_000_000.0, 6)
                        tot_fwd = float(feat.get("Total Fwd Packets", 0) or 0)
                        value = (tot_fwd / dur_s) if dur_s > 0 else 0.0
                    elif col == "bwd_pkts_s":
                        dur_s = round(float(feat.get("Flow Duration", 0) or 0) / 1_000_000.0, 6)
                        tot_bwd = float(feat.get("Total Backward Packets", 0) or 0)
                        value = (tot_bwd / dur_s) if dur_s > 0 else 0.0
                if src_key in sec_fields:
                    try:
                        value = float(value) / 1_000_000.0
                    except Exception:
                        pass
                row.append(value)
            writer.writerow(row)
    return str(out)

def export_flows_to_cic_source_csv(flows: list[PacketraFlow], output_path: str) -> str:
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(CIC_SOURCE_HEADER)
        for flow in flows:
            feat = flow.to_features()
            dur_s = round(float(feat.get("Flow Duration", 0) or 0) / 1_000_000.0, 6)
            tf = float(feat.get("Total Fwd Packets", 0) or 0)
            tb = float(feat.get("Total Backward Packets", 0) or 0)
            tlf = float(feat.get("Total Length of Fwd Packets", 0) or 0)
            tlb = float(feat.get("Total Length of Bwd Packets", 0) or 0)
            flow_byts_s = ((tlf + tlb) / dur_s) if dur_s > 0 else 0.0
            flow_pkts_s = ((tf + tb) / dur_s) if dur_s > 0 else 0.0
            fwd_pkts_s = (tf / dur_s) if dur_s > 0 else 0.0
            bwd_pkts_s = (tb / dur_s) if dur_s > 0 else 0.0
            ts = datetime.fromtimestamp(flow.start_time).strftime("%Y-%m-%d %H:%M:%S")
            row = {
                "src_ip": feat.get("Src IP", ""),
                "dst_ip": feat.get("Dst IP", ""),
                "src_port": feat.get("Src Port", 0),
                "dst_port": feat.get("Dst Port", 0),
                "protocol": 6 if str(feat.get("Protocol", "")).upper() == "TCP" else 17 if str(feat.get("Protocol", "")).upper() == "UDP" else 1,
                "timestamp": ts,
                "flow_duration": dur_s,
                "flow_byts_s": flow_byts_s,
                "flow_pkts_s": flow_pkts_s,
                "fwd_pkts_s": fwd_pkts_s,
                "bwd_pkts_s": bwd_pkts_s,
                "tot_fwd_pkts": feat.get("Total Fwd Packets", 0),
                "tot_bwd_pkts": feat.get("Total Backward Packets", 0),
                "totlen_fwd_pkts": feat.get("Total Length of Fwd Packets", 0),
                "totlen_bwd_pkts": feat.get("Total Length of Bwd Packets", 0),
                "fwd_pkt_len_max": feat.get("Fwd Packet Length Max", 0),
                "fwd_pkt_len_min": feat.get("Fwd Packet Length Min", 0),
                "fwd_pkt_len_mean": feat.get("Fwd Packet Length Mean", 0),
                "fwd_pkt_len_std": feat.get("Fwd Packet Length Std", 0),
                "bwd_pkt_len_max": feat.get("Bwd Packet Length Max", 0),
                "bwd_pkt_len_min": feat.get("Bwd Packet Length Min", 0),
                "bwd_pkt_len_mean": feat.get("Bwd Packet Length Mean", 0),
                "bwd_pkt_len_std": feat.get("Bwd Packet Length Std", 0),
                "pkt_len_max": feat.get("Max Packet Length", 0),
                "pkt_len_min": feat.get("Min Packet Length", 0),
                "pkt_len_mean": feat.get("Packet Length Mean", 0),
                "pkt_len_std": feat.get("Packet Length Std", 0),
                "pkt_len_var": feat.get("Packet Length Variance", 0),
                "fwd_header_len": feat.get("Fwd Header Length", 0),
                "bwd_header_len": feat.get("Bwd Header Length", 0),
                "fwd_seg_size_min": feat.get("min_seg_size_forward", 0),
                "fwd_act_data_pkts": feat.get("act_data_pkt_fwd", 0),
                "flow_iat_mean": feat.get("Flow IAT Mean", 0),
                "flow_iat_max": feat.get("Flow IAT Max", 0),
                "flow_iat_min": feat.get("Flow IAT Min", 0),
                "flow_iat_std": feat.get("Flow IAT Std", 0),
                "fwd_iat_tot": feat.get("Fwd IAT Total", 0),
                "fwd_iat_max": feat.get("Fwd IAT Max", 0),
                "fwd_iat_min": feat.get("Fwd IAT Min", 0),
                "fwd_iat_mean": feat.get("Fwd IAT Mean", 0),
                "fwd_iat_std": feat.get("Fwd IAT Std", 0),
                "bwd_iat_tot": feat.get("Bwd IAT Total", 0),
                "bwd_iat_max": feat.get("Bwd IAT Max", 0),
                "bwd_iat_min": feat.get("Bwd IAT Min", 0),
                "bwd_iat_mean": feat.get("Bwd IAT Mean", 0),
                "bwd_iat_std": feat.get("Bwd IAT Std", 0),
                "fwd_psh_flags": feat.get("Fwd PSH Flags", 0),
                "bwd_psh_flags": feat.get("Bwd PSH Flags", 0),
                "fwd_urg_flags": feat.get("Fwd URG Flags", 0),
                "bwd_urg_flags": feat.get("Bwd URG Flags", 0),
                "fin_flag_cnt": feat.get("FIN Flag Count", 0),
                "syn_flag_cnt": feat.get("SYN Flag Count", 0),
                "rst_flag_cnt": feat.get("RST Flag Count", 0),
                "psh_flag_cnt": feat.get("PSH Flag Count", 0),
                "ack_flag_cnt": feat.get("ACK Flag Count", 0),
                "urg_flag_cnt": feat.get("URG Flag Count", 0),
                "ece_flag_cnt": feat.get("ECE Flag Count", 0),
                "down_up_ratio": feat.get("Down/Up Ratio", 0),
                "pkt_size_avg": feat.get("Average Packet Size", 0),
                "init_fwd_win_byts": feat.get("Init_Win_bytes_forward", 0),
                "init_bwd_win_byts": feat.get("Init_Win_bytes_backward", 0),
                "active_max": feat.get("Active Max", 0),
                "active_min": feat.get("Active Min", 0),
                "active_mean": feat.get("Active Mean", 0),
                "active_std": feat.get("Active Std", 0),
                "idle_max": feat.get("Idle Max", 0),
                "idle_min": feat.get("Idle Min", 0),
                "idle_mean": feat.get("Idle Mean", 0),
                "idle_std": feat.get("Idle Std", 0),
                "fwd_byts_b_avg": feat.get("Fwd Avg Bytes/Bulk", 0),
                "fwd_pkts_b_avg": feat.get("Fwd Avg Packets/Bulk", 0),
                "bwd_byts_b_avg": feat.get("Bwd Avg Bytes/Bulk", 0),
                "bwd_pkts_b_avg": feat.get("Bwd Avg Packets/Bulk", 0),
                "fwd_blk_rate_avg": feat.get("Fwd Avg Bulk Rate", 0),
                "bwd_blk_rate_avg": feat.get("Bwd Avg Bulk Rate", 0),
                "fwd_seg_size_avg": feat.get("Avg Fwd Segment Size", 0),
                "bwd_seg_size_avg": feat.get("Avg Bwd Segment Size", 0),
                "cwr_flag_count": feat.get("CWE Flag Count", 0),
                "subflow_fwd_pkts": feat.get("Subflow Fwd Packets", 0),
                "subflow_bwd_pkts": feat.get("Subflow Bwd Packets", 0),
                "subflow_fwd_byts": feat.get("Subflow Fwd Bytes", 0),
                "subflow_bwd_byts": feat.get("Subflow Bwd Bytes", 0),
            }
            writer.writerow([row.get(col, 0) for col in CIC_SOURCE_HEADER])
    return str(out)

def export_packets_to_csv(packets: list[Any], output_path: str, flow_timeout_seconds: float = 120.0) -> tuple[str, list[PacketraFlow]]:
    extractor = FlowFeatureExtractor(flow_timeout_seconds=flow_timeout_seconds)
    flows = extractor.extract_from_packets(packets)
    csv_path = export_flows_to_csv(flows, output_path)
    return csv_path, flows


def export_pcap_to_csv(pcap_path: str, output_path: str, flow_timeout_seconds: float = 120.0) -> tuple[str, list[PacketraFlow]]:
    extractor = FlowFeatureExtractor(flow_timeout_seconds=flow_timeout_seconds)
    flows = extractor.extract_from_pcap(pcap_path)
    csv_path = export_flows_to_csv(flows, output_path)
    return csv_path, flows


def export_pcap_to_cic_csv(pcap_path: str, output_path: str, flow_timeout_seconds: float = 240.0) -> tuple[str, list[PacketraFlow]]:
    extractor = FlowFeatureExtractor(flow_timeout_seconds=flow_timeout_seconds, cic_compat_mode=True)
    flows = extractor.extract_from_pcap(pcap_path)
    csv_path = export_flows_to_cic_csv(flows, output_path)
    return csv_path, flows


def export_pcap_to_cic_legacy_csv(pcap_path: str, output_path: str, flow_timeout_seconds: float = 240.0) -> tuple[str, list[PacketraFlow]]:
    extractor = FlowFeatureExtractor(flow_timeout_seconds=flow_timeout_seconds, cic_compat_mode=True)
    flows = extractor.extract_from_pcap(pcap_path)
    csv_path = export_flows_to_cic_legacy_csv(flows, output_path)
    return csv_path, flows

def export_pcap_to_cic_source_csv(
    pcap_path: str,
    output_path: str,
    flow_timeout_seconds: float = 240.0,
) -> tuple[str, list[PacketraFlow]]:
    packets = []
    reader = PcapReader(str(pcap_path))
    try:
        for pkt in reader:
            packets.append(pkt)
    finally:
        try:
            reader.close()
        except Exception:
            pass

    rows = extract_cic_rows_from_packets(packets)
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(CIC_SOURCE_HEADER)
        for row in rows:
            writer.writerow([row.get(col, 0) for col in CIC_SOURCE_HEADER])

    # Keep return type compatibility for callers that expect flow list.
    extractor = FlowFeatureExtractor(flow_timeout_seconds=flow_timeout_seconds, cic_compat_mode=True)
    flows = extractor.extract_from_packets(packets)
    return str(out), flows
