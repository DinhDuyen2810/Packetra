from __future__ import annotations

import argparse
import csv
import hashlib
import os
import re
import shutil
import subprocess
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(CURRENT_DIR)
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from core.formatters import packet_summary_tree
from core.parser import PacketParser
from utils.pcap_io import iter_pcap_packets


@dataclass
class WsListRow:
    number: int
    time_epoch: str
    src: str
    dst: str
    protocol: str
    length: str
    info: str


@dataclass
class AppPacket:
    number: int
    protocol: str
    info: str
    tabs: List[str]
    detail_text: str
    detail_sig: str
    mapping_summary: List[str]


@dataclass
class MismatchCase:
    ws_protocol: str
    ws_detail_sig: str
    representative: int
    packets: List[int] = field(default_factory=list)
    list_mismatch_packets: List[int] = field(default_factory=list)
    detail_mismatch_packets: List[int] = field(default_factory=list)


def _default_tshark_path() -> str:
    found = shutil.which("tshark")
    if found:
        return found
    win_default = r"C:\Program Files\Wireshark\tshark.exe"
    if os.path.exists(win_default):
        return win_default
    return "tshark"


def _normalize_text(text: str) -> str:
    return " ".join(str(text or "").strip().split())


def _normalize_protocol(text: str) -> str:
    return _normalize_text(text).upper()


def _node_title_signature(title: str) -> str:
    text = str(title or "").strip()
    if ":" in text:
        text = text.split(":", 1)[0].strip() + ":"
    text = re.sub(r"\[.*?\]", "[]", text)
    text = re.sub(r"\s+", " ", text)
    return text


def _text_shape_signature(text: str) -> str:
    lines = str(text or "").splitlines()
    norm: List[str] = []
    frame_re = re.compile(r"^Frame\s+\d+:")
    for raw in lines:
        if not raw.strip():
            continue
        if frame_re.match(raw.strip()):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        level = indent // 4
        item = raw.strip()
        item = _node_title_signature(item)
        norm.append(f"{level}:{item}")
    payload = "\n".join(norm)
    return hashlib.sha1(payload.encode("utf-8", errors="ignore")).hexdigest()


def _render_tree_text(tree: List[dict]) -> str:
    lines: List[str] = []

    def walk(node: dict, depth: int) -> None:
        title = str(node.get("title", "") or "")
        if title:
            lines.append(("    " * depth) + title)
        for child in node.get("children", []) or []:
            if isinstance(child, dict):
                walk(child, depth + 1)

    for root in tree:
        if isinstance(root, dict):
            walk(root, 0)
    return "\n".join(lines).rstrip()


def _tabs_from_record(record) -> List[str]:
    metadata = getattr(record, "metadata", {}) or {}
    protocol_name = str(getattr(record, "protocol", "") or "")
    tabs = ["packet"]

    reassembled_hex = str(metadata.get("tcp_reassembled_data_hex", "") or "")
    if reassembled_hex:
        tabs.append("reassembled")

    http_body = bytes(metadata.get("http_body", b"") or b"")
    if http_body and protocol_name != "IPP":
        try:
            http_body.decode("utf-8", errors="strict")
            tabs.append("decoded_utf8")
        except Exception:
            pass

    dechunked_body = bytes(metadata.get("http_dechunked_body", b"") or b"")
    if dechunked_body:
        tabs.append("dechunked_entity_body")

    zabbix_uncompressed = bytes(metadata.get("zabbix_uncompressed_body", b"") or b"")
    zabbix_body = bytes(metadata.get("zabbix_body", b"") or b"")
    if protocol_name == "Zabbix" and zabbix_uncompressed and zabbix_uncompressed != zabbix_body:
        tabs.append("uncompressed_entity_body")
    return tabs


def _mapping_summary(tree: List[dict]) -> List[str]:
    summary: List[str] = []
    for node in tree:
        if not isinstance(node, dict):
            continue
        title = str(node.get("title", "") or "")
        if not title or title.startswith("Frame "):
            continue
        if "offset" in node and "length" in node:
            try:
                offset = int(node.get("offset", 0) or 0)
                length = int(node.get("length", 0) or 0)
            except Exception:
                continue
            if length <= 0:
                continue
            source = str(node.get("byte_source", "packet") or "packet")
            end = offset + length - 1
            summary.append(f"- `{title}` => `{source}[{offset}..{end}]` ({length} bytes)")
    return summary


def load_ws_packet_list(pcap: str, tshark_path: str) -> Dict[int, WsListRow]:
    cmd = [
        tshark_path,
        "-r",
        pcap,
        "-n",
        "-T",
        "fields",
        "-E",
        "separator=\t",
        "-E",
        "quote=d",
        "-E",
        "header=n",
        "-e",
        "frame.number",
        "-e",
        "frame.time_epoch",
        "-e",
        "_ws.col.Source",
        "-e",
        "_ws.col.Destination",
        "-e",
        "_ws.col.Protocol",
        "-e",
        "_ws.col.Length",
        "-e",
        "_ws.col.Info",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", check=False)
    if proc.returncode != 0:
        raise RuntimeError(f"tshark packet list failed: {proc.stderr.strip()}")
    reader = csv.reader(proc.stdout.splitlines(), delimiter="\t", quotechar='"')
    rows: Dict[int, WsListRow] = {}
    for row in reader:
        if not row:
            continue
        while len(row) < 7:
            row.append("")
        try:
            number = int(str(row[0] or "").strip())
        except Exception:
            continue
        rows[number] = WsListRow(
            number=number,
            time_epoch=str(row[1] or "").strip(),
            src=str(row[2] or "").strip(),
            dst=str(row[3] or "").strip(),
            protocol=str(row[4] or "").strip(),
            length=str(row[5] or "").strip(),
            info=str(row[6] or "").strip(),
        )
    return rows


def load_ws_detail_text(pcap: str, tshark_path: str) -> Dict[int, str]:
    cmd = [tshark_path, "-r", pcap, "-n", "-V"]
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", check=False)
    if proc.returncode != 0:
        raise RuntimeError(f"tshark detail failed: {proc.stderr.strip()}")
    frame_re = re.compile(r"^Frame\s+(\d+):")
    blocks: Dict[int, List[str]] = {}
    current_no = 0
    current_lines: List[str] = []
    for line in proc.stdout.splitlines():
        m = frame_re.match(line)
        if m:
            if current_no > 0:
                blocks[current_no] = list(current_lines)
            current_no = int(m.group(1))
            current_lines = [line]
        elif current_no > 0:
            current_lines.append(line)
    if current_no > 0:
        blocks[current_no] = list(current_lines)
    return {k: "\n".join(v).rstrip() for k, v in blocks.items()}


def load_app_packets(pcap: str, max_packet: int) -> Dict[int, AppPacket]:
    parser = PacketParser()
    parser.set_capture_file_path(pcap, use_wireshark_baseline=True)
    out: Dict[int, AppPacket] = {}
    for number, packet in enumerate(iter_pcap_packets(pcap), start=1):
        record = parser.parse_fast(packet, number)
        tree = packet_summary_tree(record.raw, record)
        detail_text = _render_tree_text(tree)
        out[number] = AppPacket(
            number=number,
            protocol=str(record.protocol or "").strip(),
            info=str(record.info or "").strip(),
            tabs=_tabs_from_record(record),
            detail_text=detail_text,
            detail_sig=_text_shape_signature(detail_text),
            mapping_summary=_mapping_summary(tree),
        )
        if number >= max_packet:
            break
    return out


def build_mismatch_cases(
    ws_list: Dict[int, WsListRow],
    ws_detail: Dict[int, str],
    app_packets: Dict[int, AppPacket],
    batch_size: int,
) -> Tuple[Dict[str, List[MismatchCase]], List[str], int]:
    max_packet = min(max(ws_list.keys(), default=0), max(ws_detail.keys(), default=0), max(app_packets.keys(), default=0))
    progress: List[str] = []

    by_protocol: Dict[str, Dict[str, MismatchCase]] = defaultdict(dict)
    for start in range(1, max_packet + 1, batch_size):
        end = min(start + batch_size - 1, max_packet)
        batch_new = 0
        for number in range(start, end + 1):
            ws_row = ws_list.get(number)
            ws_detail_text = ws_detail.get(number, "")
            app = app_packets.get(number)
            if ws_row is None or app is None or not ws_detail_text:
                continue

            list_mismatch = (
                _normalize_protocol(ws_row.protocol) != _normalize_protocol(app.protocol)
                or _normalize_text(ws_row.info) != _normalize_text(app.info)
            )
            ws_sig = _text_shape_signature(ws_detail_text)
            detail_mismatch = ws_sig != app.detail_sig

            if not list_mismatch and not detail_mismatch:
                continue

            proto_key = _normalize_protocol(ws_row.protocol)
            case_lookup = by_protocol[proto_key]
            case = case_lookup.get(ws_sig)
            if case is None:
                case = MismatchCase(
                    ws_protocol=ws_row.protocol,
                    ws_detail_sig=ws_sig,
                    representative=number,
                    packets=[number],
                    list_mismatch_packets=[number] if list_mismatch else [],
                    detail_mismatch_packets=[number] if detail_mismatch else [],
                )
                case_lookup[ws_sig] = case
                batch_new += 1
            else:
                case.packets.append(number)
                if list_mismatch:
                    case.list_mismatch_packets.append(number)
                if detail_mismatch:
                    case.detail_mismatch_packets.append(number)
        progress.append(f"- Packets `{start}-{end}`: new mismatch detail-cases `{batch_new}`")

    protocol_cases: Dict[str, List[MismatchCase]] = {}
    for proto_key, mapping in by_protocol.items():
        protocol_cases[proto_key] = sorted(mapping.values(), key=lambda c: c.representative)
    return protocol_cases, progress, max_packet


def _packet_list_line_ws(row: WsListRow) -> str:
    return (
        f"{row.number}\t{row.time_epoch}\t{row.src}\t{row.dst}\t"
        f"{row.protocol}\t{row.length}\t{row.info}"
    )


def _packet_list_line_app(app: AppPacket, ws: WsListRow) -> str:
    return (
        f"{app.number}\t{ws.time_epoch}\t{ws.src}\t{ws.dst}\t"
        f"{app.protocol}\t{ws.length}\t{app.info}"
    )


def write_markdown(
    output_path: str,
    pcap: str,
    protocol_cases: Dict[str, List[MismatchCase]],
    progress: List[str],
    ws_list: Dict[int, WsListRow],
    ws_detail: Dict[int, str],
    app_packets: Dict[int, AppPacket],
    max_packet: int,
) -> None:
    lines: List[str] = []
    total_case = sum(len(items) for items in protocol_cases.values())
    pcap_label = os.path.splitext(os.path.basename(pcap))[0]
    lines.append(f"# {pcap_label} — Mismatch Catalog")
    lines.append("")
    lines.append(f"- PCAP: `{pcap}`")
    lines.append(f"- Scanned packets: `{max_packet}`")
    lines.append(f"- Protocols có mismatch: `{len(protocol_cases)}`")
    lines.append(f"- Tổng case mismatch (detail-format): `{total_case}`")
    lines.append("")
    lines.append("## Quét Theo Batch 100")
    lines.append("")
    lines.extend(progress if progress else ["- No data"])
    lines.append("")

    lines.append("## I. Bảng Protocol Và Danh Sách Gói Định Dạng Khác Nhau (List/Detail Không Khớp Wireshark)")
    lines.append("")
    lines.append("| Protocol | Số case mismatch | Packet đại diện mỗi case | Toàn bộ packet trong các case |")
    lines.append("|---|---:|---|---|")
    for proto_key in sorted(protocol_cases.keys()):
        cases = protocol_cases[proto_key]
        protocol_name = cases[0].ws_protocol if cases else proto_key
        reps = ", ".join(str(c.representative) for c in cases)
        all_packets = ", ".join(str(n) for c in cases for n in c.packets)
        lines.append(f"| `{protocol_name}` | {len(cases)} | {reps} | {all_packets} |")
    lines.append("")

    lines.append("## II. Mô Tả Từng Gói Sẽ Làm Như Nào")
    lines.append("")
    for proto_key in sorted(protocol_cases.keys()):
        cases = protocol_cases[proto_key]
        protocol_name = cases[0].ws_protocol if cases else proto_key
        lines.append(f"### Protocol `{protocol_name}`")
        lines.append("")
        for idx, case in enumerate(cases, start=1):
            rep = case.representative
            ws = ws_list[rep]
            app = app_packets[rep]
            list_mis = len(case.list_mismatch_packets)
            detail_mis = len(case.detail_mismatch_packets)
            lines.append(f"#### Case {idx} — Packet đại diện `{rep}`")
            lines.append("")
            lines.append(f"- Packets cùng định dạng Wireshark: `{', '.join(str(x) for x in case.packets)}`")
            lines.append(f"- Mismatch loại list: `{list_mis}/{len(case.packets)}` packet")
            lines.append(f"- Mismatch loại detail: `{detail_mis}/{len(case.packets)}` packet")
            lines.append(f"- Packet bytes tabs (app): `{len(app.tabs)}` => `{', '.join(app.tabs)}`")
            if _normalize_protocol(ws.protocol) != _normalize_protocol(app.protocol):
                lines.append(
                    f"- Hành động dispatch: sửa rule detect để packet `{rep}` parse ra `{ws.protocol}` thay vì `{app.protocol}`."
                )
            else:
                lines.append("- Hành động dispatch: protocol đã đúng, không sửa dispatch.")
            if _normalize_text(ws.info) != _normalize_text(app.info):
                lines.append("- Hành động packet list: sửa logic build `Info` theo message type/opcode/command bytes thực tế.")
            else:
                lines.append("- Hành động packet list: Info đã khớp, không cần sửa.")
            lines.append("- Hành động detail tree: so khớp 1-1 với Wireshark, giữ đúng parent/child và thứ tự field.")
            lines.append("- Hành động mapping: map đúng tab + offset + length, không overlap protocol khác, không map giả.")
            lines.append("")

    lines.append("## III. Chi Tiết Packetlist + Packet Detail Đầy Đủ Từng Gói Đại Diện")
    lines.append("")
    for proto_key in sorted(protocol_cases.keys()):
        cases = protocol_cases[proto_key]
        protocol_name = cases[0].ws_protocol if cases else proto_key
        lines.append(f"### Protocol `{protocol_name}`")
        lines.append("")
        for idx, case in enumerate(cases, start=1):
            rep = case.representative
            ws = ws_list[rep]
            app = app_packets[rep]
            lines.append(f"#### Case {idx} — Packet `{rep}`")
            lines.append("")
            lines.append("- Packet list (Wireshark expected):")
            lines.append(f"  `{_packet_list_line_ws(ws)}`")
            lines.append("- Packet list (App actual):")
            lines.append(f"  `{_packet_list_line_app(app, ws)}`")
            lines.append(f"- Tabs packet bytes (App): `{len(app.tabs)}` => `{', '.join(app.tabs)}`")
            lines.append("- Mapping summary (App):")
            if app.mapping_summary:
                lines.extend(app.mapping_summary)
            else:
                lines.append("- `No mapped node captured`")
            lines.append("")
            lines.append("- Packet detail đầy đủ (Wireshark expected):")
            lines.append("")
            lines.append("```text")
            lines.append(ws_detail.get(rep, "").rstrip())
            lines.append("```")
            lines.append("")

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(lines) + "\n")


def main() -> int:
    argp = argparse.ArgumentParser(description="Build mismatch markdown for split_00008.")
    argp.add_argument("--pcap", required=True)
    argp.add_argument("--output", default="docs/split_00008_mismatch_cases.md")
    argp.add_argument("--batch-size", type=int, default=100)
    argp.add_argument("--tshark", default=_default_tshark_path())
    args = argp.parse_args()

    ws_list = load_ws_packet_list(args.pcap, args.tshark)
    ws_detail = load_ws_detail_text(args.pcap, args.tshark)
    max_packet = min(max(ws_list.keys(), default=0), max(ws_detail.keys(), default=0))
    app_packets = load_app_packets(args.pcap, max_packet=max_packet)

    protocol_cases, progress, scanned = build_mismatch_cases(
        ws_list=ws_list,
        ws_detail=ws_detail,
        app_packets=app_packets,
        batch_size=int(args.batch_size),
    )
    write_markdown(
        output_path=args.output,
        pcap=args.pcap,
        protocol_cases=protocol_cases,
        progress=progress,
        ws_list=ws_list,
        ws_detail=ws_detail,
        app_packets=app_packets,
        max_packet=scanned,
    )
    total_case = sum(len(v) for v in protocol_cases.values())
    print(f"Done. packets={scanned} protocols={len(protocol_cases)} mismatch_cases={total_case} output={args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
