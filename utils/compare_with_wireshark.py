from __future__ import annotations

import argparse
import csv
import os
import sys
import shutil
import subprocess
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Dict, List

CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT_DIR = os.path.dirname(CURRENT_DIR)
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from core.parser import PacketParser
from utils.pcap_io import iter_pcap_packets


@dataclass
class TsharkRow:
    number: int
    protocol: str
    info: str
    frame_protocols: str


@dataclass
class CompareRow:
    number: int
    ws_protocol: str
    app_protocol: str
    ws_info: str
    app_info: str
    ws_stack: str
    app_stack: str
    protocol_match: bool
    info_match: bool
    stack_match: bool


def _normalize_text(text: str) -> str:
    return " ".join(str(text or "").strip().split())


def _normalize_protocol(text: str) -> str:
    return _normalize_text(text).upper()


def _stack_last_protocol(stack_text: str) -> str:
    tokens = [token.strip() for token in str(stack_text or "").split(":") if token.strip()]
    if not tokens:
        return ""
    return tokens[-1].upper()


def _default_tshark_path() -> str:
    found = shutil.which("tshark")
    if found:
        return found
    win_default = r"C:\Program Files\Wireshark\tshark.exe"
    if os.path.exists(win_default):
        return win_default
    return "tshark"


def load_tshark_rows(pcap_path: str, tshark_path: str) -> Dict[int, TsharkRow]:
    cmd = [
        tshark_path,
        "-r",
        pcap_path,
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
        "_ws.col.Protocol",
        "-e",
        "_ws.col.Info",
        "-e",
        "frame.protocols",
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", check=False)
    if proc.returncode != 0:
        raise RuntimeError(f"tshark failed ({proc.returncode}): {proc.stderr.strip()}")

    result: Dict[int, TsharkRow] = {}
    reader = csv.reader(proc.stdout.splitlines(), delimiter="\t", quotechar='"')
    for row in reader:
        if not row:
            continue
        while len(row) < 4:
            row.append("")
        number_text, proto, info, frame_protocols = row[:4]
        try:
            number = int(number_text.strip())
        except Exception:
            continue
        result[number] = TsharkRow(
            number=number,
            protocol=str(proto or "").strip(),
            info=str(info or "").strip(),
            frame_protocols=str(frame_protocols or "").strip(),
        )
    return result


def load_app_rows(pcap_path: str, limit: int | None = None) -> Dict[int, CompareRow]:
    parser = PacketParser()
    parser.set_capture_file_path(pcap_path, use_wireshark_baseline=True)
    result: Dict[int, CompareRow] = {}
    for number, packet in enumerate(iter_pcap_packets(pcap_path), start=1):
        record = parser.parse_fast(packet, number)
        app_stack = ":".join(str(layer or "").lower() for layer in (record.layers or []))
        result[number] = CompareRow(
            number=number,
            ws_protocol="",
            app_protocol=str(record.protocol or "").strip(),
            ws_info="",
            app_info=str(record.info or "").strip(),
            ws_stack="",
            app_stack=app_stack,
            protocol_match=False,
            info_match=False,
            stack_match=False,
        )
        if limit is not None and number >= limit:
            break
    return result


def compare_rows(ws_rows: Dict[int, TsharkRow], app_rows: Dict[int, CompareRow], limit: int | None = None) -> List[CompareRow]:
    numbers = sorted(set(ws_rows.keys()) & set(app_rows.keys()))
    if limit is not None:
        numbers = [n for n in numbers if n <= limit]

    rows: List[CompareRow] = []
    for number in numbers:
        ws = ws_rows[number]
        app = app_rows[number]
        app.ws_protocol = ws.protocol
        app.ws_info = ws.info
        app.ws_stack = ws.frame_protocols
        app.protocol_match = _normalize_protocol(ws.protocol) == _normalize_protocol(app.app_protocol)
        app.info_match = _normalize_text(ws.info) == _normalize_text(app.app_info)
        ws_last = _stack_last_protocol(ws.frame_protocols)
        app_last = _normalize_protocol(app.app_protocol)
        app_stack_last = _stack_last_protocol(app.app_stack)
        app.stack_match = ws_last == app_last or ws_last == app_stack_last
        rows.append(app)
    return rows


def write_report(
    report_path: str,
    pcap_path: str,
    rows: List[CompareRow],
    batch_size: int,
) -> None:
    total = len(rows)
    protocol_ok = sum(1 for r in rows if r.protocol_match)
    info_ok = sum(1 for r in rows if r.info_match)
    stack_ok = sum(1 for r in rows if r.stack_match)

    protocol_mismatches = [r for r in rows if not r.protocol_match]
    info_mismatches = [r for r in rows if not r.info_match]
    stack_mismatches = [r for r in rows if not r.stack_match]

    mismatch_groups: Dict[tuple[str, str], List[CompareRow]] = defaultdict(list)
    for row in protocol_mismatches:
        key = (_normalize_protocol(row.ws_protocol), _normalize_protocol(row.app_protocol))
        mismatch_groups[key].append(row)

    ws_protocol_counter = Counter(_normalize_protocol(r.ws_protocol) for r in rows)
    app_protocol_counter = Counter(_normalize_protocol(r.app_protocol) for r in rows)

    lines: List[str] = []
    lines.append("# Wireshark vs Project Parser Compare")
    lines.append("")
    lines.append(f"- PCAP: `{pcap_path}`")
    lines.append(f"- Compared packets: `{total}`")
    lines.append(f"- Batch size: `{batch_size}`")
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- Protocol match: `{protocol_ok}/{total}`")
    lines.append(f"- Info match: `{info_ok}/{total}`")
    lines.append(f"- Stack match: `{stack_ok}/{total}`")
    lines.append("")
    lines.append(f"- Protocol mismatches: `{len(protocol_mismatches)}`")
    lines.append(f"- Info mismatches: `{len(info_mismatches)}`")
    lines.append(f"- Stack mismatches: `{len(stack_mismatches)}`")
    lines.append("")
    lines.append("## Protocol Frequency (Top)")
    lines.append("")
    lines.append("### Wireshark")
    for proto, count in ws_protocol_counter.most_common(20):
        lines.append(f"- `{proto}`: `{count}`")
    lines.append("")
    lines.append("### Project")
    for proto, count in app_protocol_counter.most_common(20):
        lines.append(f"- `{proto}`: `{count}`")
    lines.append("")

    lines.append("## Protocol Mismatch Groups")
    lines.append("")
    if not mismatch_groups:
        lines.append("- None")
    else:
        ordered = sorted(mismatch_groups.items(), key=lambda item: len(item[1]), reverse=True)
        for (ws_proto, app_proto), items in ordered:
            first = min(items, key=lambda x: x.number)
            lines.append(
                f"- WS `{ws_proto}` vs App `{app_proto}`: `{len(items)}` packets "
                f"(first: `{first.number}`, ws_info=`{first.ws_info}`, app_info=`{first.app_info}`)"
            )
    lines.append("")

    lines.append("## Batch (100) Progress")
    lines.append("")
    seen_mismatch_signatures: set[tuple[str, str]] = set()
    max_number = max((r.number for r in rows), default=0)
    for start in range(1, max_number + 1, batch_size):
        end = min(start + batch_size - 1, max_number)
        batch_rows = [r for r in rows if start <= r.number <= end]
        if not batch_rows:
            continue
        b_total = len(batch_rows)
        b_proto_bad = [r for r in batch_rows if not r.protocol_match]
        b_info_bad = sum(1 for r in batch_rows if not r.info_match)
        b_stack_bad = sum(1 for r in batch_rows if not r.stack_match)

        new_signatures = []
        for row in b_proto_bad:
            sign = (_normalize_protocol(row.ws_protocol), _normalize_protocol(row.app_protocol))
            if sign not in seen_mismatch_signatures:
                seen_mismatch_signatures.add(sign)
                new_signatures.append(sign)

        lines.append(
            f"- Packets `{start}-{end}`: total `{b_total}`, "
            f"protocol mismatch `{len(b_proto_bad)}`, info mismatch `{b_info_bad}`, stack mismatch `{b_stack_bad}`, "
            f"new protocol-mismatch signatures `{len(new_signatures)}`"
        )

    lines.append("")
    lines.append("## First 50 Protocol Mismatch Packets")
    lines.append("")
    if not protocol_mismatches:
        lines.append("- None")
    else:
        for row in sorted(protocol_mismatches, key=lambda x: x.number)[:50]:
            lines.append(
                f"- `{row.number}`: WS `{row.ws_protocol}` | App `{row.app_protocol}` | "
                f"WS Info `{row.ws_info}` | App Info `{row.app_info}`"
            )
    lines.append("")
    lines.append("## Next Fix Targets")
    lines.append("")
    if mismatch_groups:
        for (ws_proto, app_proto), items in sorted(mismatch_groups.items(), key=lambda item: len(item[1]), reverse=True)[:10]:
            lines.append(f"- `{ws_proto}` -> `{app_proto}`: fix one representative packet first, then re-check whole signature.")
    else:
        lines.append("- No protocol mismatch signature.")

    os.makedirs(os.path.dirname(report_path) or ".", exist_ok=True)
    with open(report_path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(lines) + "\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Compare Wireshark (tshark) packet list vs project parser.")
    parser.add_argument("--pcap", required=True, help="Path to pcap/pcapng file")
    parser.add_argument("--report", default="docs/wireshark_compare_report.md", help="Output markdown report path")
    parser.add_argument("--batch-size", type=int, default=100, help="Batch size for progress summary")
    parser.add_argument("--limit", type=int, default=0, help="Limit packet count (0 = all)")
    parser.add_argument("--tshark", default=_default_tshark_path(), help="Path to tshark executable")
    args = parser.parse_args()

    limit = int(args.limit) if int(args.limit) > 0 else None
    ws_rows = load_tshark_rows(args.pcap, args.tshark)
    app_rows = load_app_rows(args.pcap, limit=limit)
    rows = compare_rows(ws_rows, app_rows, limit=limit)
    write_report(args.report, args.pcap, rows, int(args.batch_size))
    print(f"Done. compared={len(rows)} report={args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
