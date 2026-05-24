from __future__ import annotations

import argparse
import csv
import hashlib
import os
import re
import shutil
import subprocess
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Dict, List

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(CURRENT_DIR)
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from core.parser import PacketParser
from core.formatters import packet_summary_tree
from utils.pcap_io import iter_pcap_packets


@dataclass
class ListRow:
    number: int
    time: str
    src: str
    dst: str
    protocol: str
    length: str
    info: str
    stack: str


@dataclass
class AppRow:
    number: int
    protocol: str
    info: str
    tabs: List[str]
    detail_shape: str


@dataclass
class CaseItem:
    protocol: str
    signature: str
    shape_digest: str
    first_packet: int
    packet_numbers: List[int] = field(default_factory=list)
    protocol_match_count: int = 0
    info_match_count: int = 0


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


def _safe_slug(text: str) -> str:
    out = re.sub(r"[^a-zA-Z0-9]+", "_", str(text or "").strip()).strip("_")
    return out.lower() or "unknown"


def _build_tabs(record) -> List[str]:
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


def _app_detail_shape(record) -> str:
    try:
        tree = packet_summary_tree(record.raw, record)
    except Exception:
        return ""
    lines: List[str] = []

    def walk(node: dict, depth: int) -> None:
        title = str(node.get("title", "") or "")
        if title:
            normalized = title
            if ":" in normalized:
                normalized = normalized.split(":", 1)[0].strip() + ":"
            normalized = re.sub(r"\s+", " ", normalized).strip()
            lines.append(f"{depth}:{normalized}")
        for child in node.get("children", []) or []:
            if isinstance(child, dict):
                walk(child, depth + 1)

    for root in tree:
        if isinstance(root, dict):
            walk(root, 0)
    return "\n".join(lines)


def load_ws_list_rows(pcap: str, tshark: str) -> Dict[int, ListRow]:
    cmd = [
        tshark,
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
        "-e",
        "frame.protocols",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", check=False)
    if proc.returncode != 0:
        raise RuntimeError(f"tshark list failed ({proc.returncode}): {proc.stderr.strip()}")
    result: Dict[int, ListRow] = {}
    reader = csv.reader(proc.stdout.splitlines(), delimiter="\t", quotechar='"')
    for row in reader:
        if not row:
            continue
        while len(row) < 8:
            row.append("")
        try:
            number = int(str(row[0] or "").strip())
        except Exception:
            continue
        result[number] = ListRow(
            number=number,
            time=str(row[1] or "").strip(),
            src=str(row[2] or "").strip(),
            dst=str(row[3] or "").strip(),
            protocol=str(row[4] or "").strip(),
            length=str(row[5] or "").strip(),
            info=str(row[6] or "").strip(),
            stack=str(row[7] or "").strip(),
        )
    return result


def load_ws_detail_blocks(pcap: str, tshark: str) -> Dict[int, str]:
    cmd = [tshark, "-r", pcap, "-n", "-V"]
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", check=False)
    if proc.returncode != 0:
        raise RuntimeError(f"tshark detail failed ({proc.returncode}): {proc.stderr.strip()}")
    lines = proc.stdout.splitlines()
    frame_re = re.compile(r"^Frame\s+(\d+):")
    blocks: Dict[int, List[str]] = {}
    current_no = 0
    current_lines: List[str] = []
    for line in lines:
        match = frame_re.match(line)
        if match:
            if current_no > 0:
                blocks[current_no] = list(current_lines)
            current_no = int(match.group(1))
            current_lines = [line]
        else:
            if current_no > 0:
                current_lines.append(line)
    if current_no > 0:
        blocks[current_no] = list(current_lines)
    return {num: "\n".join(chunk).rstrip() for num, chunk in blocks.items()}


def _detail_shape_signature(detail_text: str) -> str:
    lines = str(detail_text or "").splitlines()
    shape_lines: List[str] = []
    frame_re = re.compile(r"^Frame\s+\d+:")
    for raw in lines:
        if not raw.strip():
            continue
        if frame_re.match(raw):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        level = indent // 4
        text = raw.strip()
        text = re.sub(r"\[.*?\]", "[]", text)
        if ":" in text:
            key = text.split(":", 1)[0].strip()
            text = key + ":"
        else:
            text = re.sub(r"\b0x[0-9a-fA-F]+\b", "0x#", text)
            text = re.sub(r"\b\d+\b", "#", text)
        text = re.sub(r"\s+", " ", text).strip()
        if not text:
            continue
        shape_lines.append(f"{level}:{text}")
    joined = "\n".join(shape_lines)
    return hashlib.sha1(joined.encode("utf-8", errors="ignore")).hexdigest()


def load_app_rows(pcap: str, max_packet: int) -> Dict[int, AppRow]:
    parser = PacketParser()
    result: Dict[int, AppRow] = {}
    for number, packet in enumerate(iter_pcap_packets(pcap), start=1):
        record = parser.parse_fast(packet, number)
        result[number] = AppRow(
            number=number,
            protocol=str(record.protocol or "").strip(),
            info=str(record.info or "").strip(),
            tabs=_build_tabs(record),
            detail_shape=_app_detail_shape(record),
        )
        if number >= max_packet:
            break
    return result


def _suggest_fix(ws_row: ListRow, app_row: AppRow, packet_no: int) -> List[str]:
    hints: List[str] = []
    ws_proto = _normalize_protocol(ws_row.protocol)
    app_proto = _normalize_protocol(app_row.protocol)
    if ws_proto != app_proto:
        hints.append(
            f"Dispatch mismatch: packet `{packet_no}` Wireshark=`{ws_row.protocol}` but app=`{app_row.protocol}`. "
            f"Cần siết điều kiện detect/dispatch cho protocol `{ws_row.protocol}`."
        )
    else:
        hints.append(
            f"Protocol matched (`{ws_row.protocol}`), tập trung sửa formatter/detail tree và mapping offsets."
        )
    if _normalize_text(ws_row.info) != _normalize_text(app_row.info):
        hints.append(
            "Packet list Info khác Wireshark. Cần cập nhật logic build info (ưu tiên message type/command thực tế từ bytes)."
        )
    tab_count = len(app_row.tabs)
    hints.append(
        f"Packet bytes tabs (app): `{tab_count}` tab(s) => {', '.join(app_row.tabs)}. "
        "Kiểm tra mapping node vào đúng tab (packet/reassembled/decoded...) theo payload source."
    )
    hints.append(
        "Mapping rule: parent/child đúng cây detail; field nào có byte range thật thì map offset/length chính xác; "
        "field generated/summary thì không map giả."
    )
    return hints


def build_catalog(
    pcap: str,
    ws_list: Dict[int, ListRow],
    ws_detail: Dict[int, str],
    app_rows: Dict[int, AppRow],
    batch_size: int,
) -> tuple[Dict[str, List[CaseItem]], List[str], int]:
    max_packet = min(max(ws_list.keys(), default=0), max(app_rows.keys(), default=0), max(ws_detail.keys(), default=0))
    protocol_cases: Dict[str, List[CaseItem]] = defaultdict(list)
    seen_by_protocol: Dict[str, Dict[str, CaseItem]] = defaultdict(dict)
    progress_lines: List[str] = []

    new_case_counter = 0
    for start in range(1, max_packet + 1, batch_size):
        end = min(start + batch_size - 1, max_packet)
        batch_new_cases = 0
        batch_new_protocols: set[str] = set()
        for packet_no in range(start, end + 1):
            ws_row = ws_list.get(packet_no)
            detail = ws_detail.get(packet_no, "")
            app = app_rows.get(packet_no)
            if ws_row is None or app is None or not detail:
                continue
            proto_key = _normalize_protocol(ws_row.protocol)
            signature = _detail_shape_signature(detail)
            case_lookup = seen_by_protocol[proto_key]
            if signature not in case_lookup:
                digest = hashlib.sha1(f"{proto_key}:{signature}".encode("utf-8")).hexdigest()[:12]
                item = CaseItem(
                    protocol=ws_row.protocol,
                    signature=signature,
                    shape_digest=digest,
                    first_packet=packet_no,
                    packet_numbers=[packet_no],
                    protocol_match_count=1 if _normalize_protocol(ws_row.protocol) == _normalize_protocol(app.protocol) else 0,
                    info_match_count=1 if _normalize_text(ws_row.info) == _normalize_text(app.info) else 0,
                )
                case_lookup[signature] = item
                protocol_cases[proto_key].append(item)
                batch_new_cases += 1
                new_case_counter += 1
                batch_new_protocols.add(proto_key)
            else:
                item = case_lookup[signature]
                item.packet_numbers.append(packet_no)
                if _normalize_protocol(ws_row.protocol) == _normalize_protocol(app.protocol):
                    item.protocol_match_count += 1
                if _normalize_text(ws_row.info) == _normalize_text(app.info):
                    item.info_match_count += 1

        progress_lines.append(
            f"- Packets `{start}-{end}`: new detail cases `{batch_new_cases}`, "
            f"new protocols in batch `{len(batch_new_protocols)}`"
        )
    return protocol_cases, progress_lines, max_packet


def write_md(
    output_md: str,
    pcap: str,
    protocol_cases: Dict[str, List[CaseItem]],
    progress_lines: List[str],
    ws_list: Dict[int, ListRow],
    ws_detail: Dict[int, str],
    app_rows: Dict[int, AppRow],
    max_packet: int,
) -> None:
    total_cases = sum(len(items) for items in protocol_cases.values())
    total_protocols = len(protocol_cases)
    lines: List[str] = []
    lines.append("# Packet Detail Catalog By Protocol/Format")
    lines.append("")
    lines.append(f"- PCAP: `{pcap}`")
    lines.append(f"- Total packets scanned: `{max_packet}`")
    lines.append(f"- Total protocols found: `{total_protocols}`")
    lines.append(f"- Total unique detail formats: `{total_cases}`")
    lines.append("")

    lines.append("## Cách Sửa Theo Loại")
    lines.append("")
    lines.append("1. Nếu protocol mismatch (`Wireshark protocol` != `App protocol`): sửa dispatch/match rule trước.")
    lines.append("2. Nếu protocol match nhưng info mismatch: sửa logic `packet list info` từ bytes thật (message type/opcode/command).")
    lines.append("3. Detail tree: field phải đúng parent/child và thứ tự như Wireshark detail.")
    lines.append("4. Mapping: chỉ map field có byte range thật, đúng tab + offset + length, không overlap protocol khác.")
    lines.append("5. Packet bytes tabs: kiểm tra từng case có bao nhiêu tab (`packet`, `reassembled`, `decoded...`) trước khi map.")
    lines.append("")

    lines.append("## Progress Theo Batch 100")
    lines.append("")
    lines.extend(progress_lines if progress_lines else ["- No data"])
    lines.append("")

    lines.append("## Protocol Catalog")
    lines.append("")
    for proto_key, case_items in sorted(protocol_cases.items(), key=lambda kv: kv[0]):
        display_name = case_items[0].protocol if case_items else proto_key
        packet_count = sum(len(c.packet_numbers) for c in case_items)
        lines.append(f"### Protocol `{display_name}`")
        lines.append("")
        lines.append(f"- Total packets: `{packet_count}`")
        lines.append(f"- Unique detail formats: `{len(case_items)}`")
        lines.append("")

        for idx, case in enumerate(sorted(case_items, key=lambda c: c.first_packet), start=1):
            rep_no = case.first_packet
            ws_row = ws_list.get(rep_no)
            app_row = app_rows.get(rep_no)
            if ws_row is None or app_row is None:
                continue
            lines.append(f"#### Case {idx} — Signature `{case.shape_digest}`")
            lines.append("")
            numbers_text = ", ".join(str(n) for n in case.packet_numbers)
            lines.append(f"- Packets cùng định dạng: `{numbers_text}`")
            lines.append(
                f"- Match stats trong case: protocol `{case.protocol_match_count}/{len(case.packet_numbers)}`, "
                f"info `{case.info_match_count}/{len(case.packet_numbers)}`"
            )
            lines.append("- Packet list (Wireshark representative):")
            lines.append(
                f"  `{ws_row.number}\\t{ws_row.time}\\t{ws_row.src}\\t{ws_row.dst}\\t{ws_row.protocol}\\t{ws_row.length}\\t{ws_row.info}`"
            )
            lines.append("- Packet list (App representative):")
            lines.append(
                f"  `{app_row.number}\\t{app_row.protocol}\\t{app_row.info}`"
            )
            lines.append(f"- Packet bytes tabs (app): `{len(app_row.tabs)}` => `{', '.join(app_row.tabs)}`")
            lines.append("- Hướng sửa/mapping:")
            for hint in _suggest_fix(ws_row, app_row, rep_no):
                lines.append(f"  - {hint}")
            lines.append("- Detail chính xác (Wireshark, representative):")
            lines.append("")
            lines.append("```text")
            lines.append(ws_detail.get(rep_no, "").rstrip())
            lines.append("```")
            lines.append("")
        lines.append("")

    os.makedirs(os.path.dirname(output_md) or ".", exist_ok=True)
    with open(output_md, "w", encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(lines) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Catalog unique packet detail formats by protocol.")
    parser.add_argument("--pcap", required=True, help="Path to pcap/pcapng")
    parser.add_argument("--output", default="docs/split_00008_detail_catalog.md", help="Output markdown path")
    parser.add_argument("--batch-size", type=int, default=100, help="Batch size")
    parser.add_argument("--tshark", default=_default_tshark_path(), help="Path to tshark")
    args = parser.parse_args()

    ws_list = load_ws_list_rows(args.pcap, args.tshark)
    ws_detail = load_ws_detail_blocks(args.pcap, args.tshark)
    max_packet = min(max(ws_list.keys(), default=0), max(ws_detail.keys(), default=0))
    app_rows = load_app_rows(args.pcap, max_packet=max_packet)

    protocol_cases, progress_lines, scanned_max = build_catalog(
        pcap=args.pcap,
        ws_list=ws_list,
        ws_detail=ws_detail,
        app_rows=app_rows,
        batch_size=int(args.batch_size),
    )

    write_md(
        output_md=args.output,
        pcap=args.pcap,
        protocol_cases=protocol_cases,
        progress_lines=progress_lines,
        ws_list=ws_list,
        ws_detail=ws_detail,
        app_rows=app_rows,
        max_packet=scanned_max,
    )

    proto_count = len(protocol_cases)
    case_count = sum(len(v) for v in protocol_cases.values())
    print(f"Done. packets={scanned_max} protocols={proto_count} unique_cases={case_count} output={args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
