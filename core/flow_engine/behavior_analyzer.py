from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

from .flow import PacketraFlow


class BehaviorAnalyzer:
    def analyze(self, flows: list[PacketraFlow], model_result: list[dict[str, Any]] | str | None = None) -> list[dict[str, Any]]:
        if not flows:
            return []

        summaries: list[dict[str, Any]] = []
        dst_ports_by_src_dst: dict[tuple[str, str], set[int]] = defaultdict(set)
        syn_ratio_map: dict[str, tuple[int, int]] = {}
        dns_counter: Counter[str] = Counter()
        icmp_counter: Counter[str] = Counter()
        syn_only_flows_by_dst: Counter[str] = Counter()
        syn_only_unique_src_by_dst: dict[str, set[str]] = defaultdict(set)

        feature_rows = [f.to_features() for f in flows]
        for row in feature_rows:
            src = str(row.get("Src IP", ""))
            dst = str(row.get("Dst IP", ""))
            dst_port = int(row.get("Dst Port", 0) or 0)
            dst_ports_by_src_dst[(src, dst)].add(dst_port)
            syn = int(row.get("SYN Flag Count", 0) or 0)
            ack = int(row.get("ACK Flag Count", 0) or 0)
            syn_ratio_map[row.get("Flow ID", "")] = (syn, ack)
            protocol = str(row.get("Protocol", "")).upper()
            bwd_pkts = int(row.get("Total Backward Packets", 0) or 0)
            if protocol == "TCP" and syn >= 1 and ack == 0 and bwd_pkts == 0:
                syn_only_flows_by_dst[dst] += 1
                syn_only_unique_src_by_dst[dst].add(src)
            if protocol == "UDP" and dst_port == 53:
                dns_counter[src] += 1
            if protocol.startswith("ICMP"):
                icmp_counter[(src, dst)] += 1

        for idx, row in enumerate(feature_rows):
            src = str(row.get("Src IP", ""))
            dst = str(row.get("Dst IP", ""))
            src_port = int(row.get("Src Port", 0) or 0)
            dst_port = int(row.get("Dst Port", 0) or 0)
            protocol = str(row.get("Protocol", "")).upper()
            flow_id = str(row.get("Flow ID", ""))
            duration_us = float(row.get("Flow Duration", 0) or 0)
            syn, ack = syn_ratio_map.get(flow_id, (0, 0))
            dst_port_count = len(dst_ports_by_src_dst.get((src, dst), set()))
            syn_only_to_dst = int(syn_only_flows_by_dst.get(dst, 0))
            syn_only_src_count = len(syn_only_unique_src_by_dst.get(dst, set()))
            bwd_pkts = int(row.get("Total Backward Packets", 0) or 0)

            summary = "Khong phat hien bat thuong ro rang trong flow nay."
            behavior = "normal"
            severity = "normal"
            evidence = [
                f"protocol={protocol}",
                f"duration_us={int(duration_us)}",
                f"fwd_packets={int(row.get('Total Fwd Packets', 0) or 0)}",
                f"bwd_packets={int(row.get('Total Backward Packets', 0) or 0)}",
            ]

            if (
                protocol == "TCP"
                and syn >= 1
                and ack == 0
                and bwd_pkts == 0
                and (syn_only_to_dst >= 30 or syn_only_src_count >= 10)
            ):
                summary = (
                    f"{dst} dang nhan luong SYN bat thuong lon"
                    f" ({syn_only_to_dst} flow SYN-only), nghi ngo SYN flood."
                )
                behavior = "syn_flood_distributed"
                severity = "high"
                evidence.extend(
                    [
                        f"syn_only_flows_to_dst={syn_only_to_dst}",
                        f"syn_only_unique_src_to_dst={syn_only_src_count}",
                    ]
                )
            elif protocol == "TCP" and dst_port_count >= 10:
                summary = f"{src} dang quet nhieu cong tren {dst}, nghi ngo port scan."
                behavior = "port_scan"
                severity = "high"
                evidence.append(f"unique_dst_ports_to_same_dst={dst_port_count}")
            elif protocol == "TCP" and syn >= 20 and ack <= max(1, syn // 5):
                summary = f"{src} gui nhieu goi SYN toi {dst}, nghi ngo SYN scan hoac SYN flood."
                behavior = "syn_scan_or_flood"
                severity = "high"
                evidence.extend([f"syn_count={syn}", f"ack_count={ack}"])
            elif protocol == "UDP" and dst_port_count >= 10:
                summary = f"{src} gui nhieu UDP packet toi {dst}, co the la UDP scan hoac UDP flood."
                behavior = "udp_scan_or_flood"
                severity = "medium"
                evidence.append(f"unique_udp_dst_ports={dst_port_count}")
            elif protocol == "UDP" and dst_port == 53 and dns_counter.get(src, 0) >= 20:
                summary = f"{src} gui nhieu truy van DNS bat thuong, co the la DNS tunneling hoac DNS flood."
                behavior = "dns_anomaly"
                severity = "medium"
                evidence.append(f"dns_flow_count_from_src={dns_counter.get(src, 0)}")
            elif protocol == "TCP" and dst_port in {80, 8080, 443}:
                summary = f"{src} dang truy cap dich vu web tren {dst}."
                behavior = "web_access"
                severity = "normal"
                evidence.append(f"dst_port={dst_port}")
            elif protocol == "TCP" and dst_port == 22 and int(row.get("Total Fwd Packets", 0) or 0) >= 10:
                summary = f"{src} co nhieu ket noi toi SSH cua {dst}, can kiem tra brute force."
                behavior = "ssh_suspicious"
                severity = "medium"
                evidence.append("dst_port=22")
            elif protocol.startswith("ICMP") and icmp_counter.get((src, dst), 0) >= 20:
                summary = f"{src} gui nhieu ICMP toi {dst}, co the la ping scan hoac ICMP flood."
                behavior = "icmp_anomaly"
                severity = "medium"
                evidence.append(f"icmp_flow_count_src_dst={icmp_counter.get((src, dst), 0)}")

            model_pred = None
            model_score = None
            if isinstance(model_result, list) and idx < len(model_result):
                model_pred = model_result[idx].get("prediction")
                model_score = model_result[idx].get("anomaly_score")
                evidence.append(f"model_prediction={model_pred}")
                evidence.append(f"model_score={model_score}")

            summaries.append(
                {
                    "flow_id": flow_id,
                    "src_ip": src,
                    "dst_ip": dst,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "protocol": protocol,
                    "summary": summary,
                    "possible_behavior": behavior,
                    "severity": severity,
                    "evidence": evidence,
                    "model_prediction": model_pred,
                    "anomaly_score": model_score,
                }
            )
        return summaries


def analyze_flows(flows: list[PacketraFlow], use_model: bool = False, model_adapter: Any = None) -> dict[str, Any]:
    feature_rows = [flow.to_features() for flow in flows]
    model_result = None
    if use_model and model_adapter is not None:
        model_result = model_adapter.predict(feature_rows)

    analyzer = BehaviorAnalyzer()
    summaries = analyzer.analyze(flows, model_result if isinstance(model_result, list) else None)
    return {
        "csv_path": "",
        "flow_count": len(flows),
        "summaries": summaries,
        "model_status": model_result if isinstance(model_result, str) else "ok",
    }
