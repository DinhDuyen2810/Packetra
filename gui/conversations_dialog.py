from dataclasses import dataclass

from scapy.all import Ether, IP, IPv6, TCP, UDP

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
    QHeaderView,
    QAbstractItemView,
    QFrame,
)


@dataclass
class ConversationStats:
    packets: int = 0
    bytes: int = 0
    packets_ab: int = 0
    bytes_ab: int = 0
    packets_ba: int = 0
    bytes_ba: int = 0
    first_time: float = None
    last_time: float = None


@dataclass
class ConversationEntry:
    key: tuple
    stream_id: int
    addr_a: str
    addr_b: str
    port_a: int | None = None
    port_b: int | None = None
    src_origin: tuple | None = None
    stats: ConversationStats = None

    def __post_init__(self):
        if self.stats is None:
            self.stats = ConversationStats()


class ConversationsDialog(QDialog):
    def __init__(self, packets, parent=None):
        super().__init__(parent)
        self.packets = packets
        self.tables = {}
        self._table_models = {}

        self.setWindowTitle("Conversations")
        self.resize(1400, 800)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        self.title = QLabel("Analyzing conversations...")
        self.title.setStyleSheet("font-weight: bold; font-size: 12px;")
        layout.addWidget(self.title)

        self.tabs = QTabWidget()
        layout.addWidget(self.tabs, 1)

        button_row = QHBoxLayout()
        button_row.addStretch(1)
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.close)
        button_row.addWidget(close_btn)
        layout.addLayout(button_row)

        self._analyze_packets()

    def _style_table(self, table: QTableWidget):
        table.setAlternatingRowColors(True)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setShowGrid(False)
        table.setFrameShape(QFrame.Shape.NoFrame)
        table.setStyleSheet('QTableWidget { border: none; gridline-color: transparent; }')
        return table

    def _analyze_packets(self):
        tabs_order = ["Ethernet", "IPv4", "IPv6", "TCP", "UDP"]
        stream_maps = {name: {} for name in tabs_order}
        next_stream = {name: 0 for name in tabs_order}
        grouped = {name: {} for name in tabs_order}

        for record in self.packets:
            try:
                packet = getattr(record, "raw", None)
                pkt_len = int(getattr(record, "length", 0) or 0)
                pkt_time = float(getattr(record, "epoch_time", 0.0) or 0.0)
                if packet is None:
                    continue

                ip_src = ""
                ip_dst = ""
                if packet.haslayer(IP):
                    ip_src = str(packet[IP].src)
                    ip_dst = str(packet[IP].dst)
                elif packet.haslayer(IPv6):
                    ip_src = str(packet[IPv6].src)
                    ip_dst = str(packet[IPv6].dst)

                if packet.haslayer(Ether):
                    eth_src = str(packet[Ether].src).lower()
                    eth_dst = str(packet[Ether].dst).lower()
                    self._accumulate_entry(
                        grouped["Ethernet"],
                        stream_maps,
                        next_stream,
                        tab_name="Ethernet",
                        forward=(eth_src, eth_dst),
                        reverse=(eth_dst, eth_src),
                        addr_src=eth_src,
                        addr_dst=eth_dst,
                        port_src=None,
                        port_dst=None,
                        pkt_len=pkt_len,
                        pkt_time=pkt_time,
                        src_origin=(eth_src, None),
                    )

                if packet.haslayer(IP):
                    src = str(packet[IP].src)
                    dst = str(packet[IP].dst)
                    self._accumulate_entry(
                        grouped["IPv4"],
                        stream_maps,
                        next_stream,
                        tab_name="IPv4",
                        forward=(src, dst),
                        reverse=(dst, src),
                        addr_src=src,
                        addr_dst=dst,
                        port_src=None,
                        port_dst=None,
                        pkt_len=pkt_len,
                        pkt_time=pkt_time,
                        src_origin=(src, None),
                    )

                if packet.haslayer(IPv6):
                    src = str(packet[IPv6].src)
                    dst = str(packet[IPv6].dst)
                    self._accumulate_entry(
                        grouped["IPv6"],
                        stream_maps,
                        next_stream,
                        tab_name="IPv6",
                        forward=(src, dst),
                        reverse=(dst, src),
                        addr_src=src,
                        addr_dst=dst,
                        port_src=None,
                        port_dst=None,
                        pkt_len=pkt_len,
                        pkt_time=pkt_time,
                        src_origin=(src, None),
                    )

                if packet.haslayer(TCP):
                    src = ip_src or str(getattr(record, "src", "") or "")
                    dst = ip_dst or str(getattr(record, "dst", "") or "")
                    sport = int(packet[TCP].sport)
                    dport = int(packet[TCP].dport)
                    self._accumulate_entry(
                        grouped["TCP"],
                        stream_maps,
                        next_stream,
                        tab_name="TCP",
                        forward=(src, sport, dst, dport),
                        reverse=(dst, dport, src, sport),
                        addr_src=src,
                        addr_dst=dst,
                        port_src=sport,
                        port_dst=dport,
                        pkt_len=pkt_len,
                        pkt_time=pkt_time,
                        src_origin=(src, sport),
                    )

                if packet.haslayer(UDP):
                    src = ip_src or str(getattr(record, "src", "") or "")
                    dst = ip_dst or str(getattr(record, "dst", "") or "")
                    sport = int(packet[UDP].sport)
                    dport = int(packet[UDP].dport)
                    self._accumulate_entry(
                        grouped["UDP"],
                        stream_maps,
                        next_stream,
                        tab_name="UDP",
                        forward=(src, sport, dst, dport),
                        reverse=(dst, dport, src, sport),
                        addr_src=src,
                        addr_dst=dst,
                        port_src=sport,
                        port_dst=dport,
                        pkt_len=pkt_len,
                        pkt_time=pkt_time,
                        src_origin=(src, sport),
                    )
            except Exception:
                continue

        self.tabs.clear()
        self.tables.clear()
        self._table_models.clear()

        total_conversations = 0
        for tab_name in tabs_order:
            entries_map = grouped[tab_name]
            if not entries_map:
                continue
            rows = [self._entry_to_row(tab_name, entry) for entry in entries_map.values()]
            rows = sorted(rows, key=lambda row: str(row["Address A"]))
            total_conversations += len(rows)
            self._create_tab(tab_name, rows)

        self.title.setText(f"Total Conversations: {total_conversations}")

    def _accumulate_entry(
        self,
        group,
        stream_maps,
        next_stream,
        tab_name,
        forward,
        reverse,
        addr_src,
        addr_dst,
        port_src,
        port_dst,
        pkt_len,
        pkt_time,
        src_origin,
    ):
        stream_map = stream_maps[tab_name]
        if forward in stream_map:
            stream_id = stream_map[forward]
            lookup_key = forward
        elif reverse in stream_map:
            stream_id = stream_map[reverse]
            lookup_key = reverse
        else:
            stream_id = next_stream[tab_name]
            next_stream[tab_name] += 1
            stream_map[forward] = stream_id
            lookup_key = forward

        entry = group.get(lookup_key)
        if entry is None:
            entry = ConversationEntry(
                key=lookup_key,
                stream_id=stream_id,
                addr_a=addr_src,
                addr_b=addr_dst,
                port_a=port_src,
                port_b=port_dst,
                src_origin=src_origin,
            )
            group[lookup_key] = entry

        stats = entry.stats
        stats.packets += 1
        stats.bytes += pkt_len
        if stats.first_time is None:
            stats.first_time = pkt_time
        stats.last_time = pkt_time

        if src_origin == entry.src_origin:
            stats.packets_ab += 1
            stats.bytes_ab += pkt_len
        else:
            stats.packets_ba += 1
            stats.bytes_ba += pkt_len

    def _entry_to_row(self, tab_name, entry):
        stats = entry.stats
        duration = 0.0
        if stats.first_time is not None and stats.last_time is not None:
            duration = max(0.0, stats.last_time - stats.first_time)

        bits_ab = int((stats.bytes_ab * 8) / duration) if duration > 0 else 0
        bits_ba = int((stats.bytes_ba * 8) / duration) if duration > 0 else 0

        row = {
            "Address A": entry.addr_a,
            "Address B": entry.addr_b,
            "Packets": stats.packets,
            "Bytes": stats.bytes,
            "Stream ID": entry.stream_id,
            "Packets A -> B": stats.packets_ab,
            "Bytes A -> B": stats.bytes_ab,
            "Packets B -> A": stats.packets_ba,
            "Bytes B -> A": stats.bytes_ba,
            "Duration": duration,
            "Bits/s A -> B": bits_ab,
            "Bits/s B -> A": bits_ba,
        }
        if tab_name in ("TCP", "UDP"):
            row["Port A"] = entry.port_a if entry.port_a is not None else ""
            row["Port B"] = entry.port_b if entry.port_b is not None else ""
            row["Flows"] = f"{entry.addr_a}:{entry.port_a} <-> {entry.addr_b}:{entry.port_b}"
        return row

    def _create_tab(self, tab_name, rows):
        tab = QWidget()
        tab_layout = QVBoxLayout(tab)
        tab_layout.setContentsMargins(0, 0, 0, 0)

        table = QTableWidget()
        table.setSortingEnabled(False)
        self._style_table(table)

        if tab_name in ("TCP", "UDP"):
            columns = [
                "Address A",
                "Port A",
                "Address B",
                "Port B",
                "Packets",
                "Bytes",
                "Stream ID",
                "Packets A -> B",
                "Bytes A -> B",
                "Packets B -> A",
                "Bytes B -> A",
                "Duration",
                "Bits/s A -> B",
                "Bits/s B -> A",
                "Flows",
            ]
        else:
            columns = [
                "Address A",
                "Address B",
                "Packets",
                "Bytes",
                "Stream ID",
                "Packets A -> B",
                "Bytes A -> B",
                "Packets B -> A",
                "Bytes B -> A",
                "Duration",
                "Bits/s A -> B",
                "Bits/s B -> A",
            ]

        table.setColumnCount(len(columns))
        table.setHorizontalHeaderLabels(columns)
        header = table.horizontalHeader()
        header.setSectionsClickable(True)
        for column in range(len(columns)):
            header.setSectionResizeMode(column, QHeaderView.ResizeToContents)

        model = {
            "rows": rows,
            "columns": columns,
            "sort_column": None,
            "sort_state": 0,
        }
        self._table_models[tab_name] = model
        header.sectionClicked.connect(lambda col, name=tab_name: self._on_header_clicked(name, col))

        self._render_rows(table, rows, columns)

        tab_layout.addWidget(table)
        self.tabs.addTab(tab, f"{tab_name} · {len(rows)}")
        self.tables[tab_name] = table

    def _render_rows(self, table, rows, columns):
        table.setRowCount(len(rows))
        for row_idx, row_data in enumerate(rows):
            for col_idx, col_name in enumerate(columns):
                value = row_data.get(col_name, "")
                if col_name == "Duration":
                    text = f"{float(value):.4f}"
                elif col_name in ("Bits/s A -> B", "Bits/s B -> A"):
                    text = f"{int(value)} bits/s"
                else:
                    text = str(value)
                item = QTableWidgetItem(text)
                item.setFlags(item.flags() & ~Qt.ItemIsEditable)
                table.setItem(row_idx, col_idx, item)

    def _on_header_clicked(self, tab_name, col):
        model = self._table_models[tab_name]
        columns = model["columns"]
        clicked_name = columns[col]

        if model["sort_column"] != clicked_name:
            model["sort_column"] = clicked_name
            model["sort_state"] = 1
        else:
            model["sort_state"] = (model["sort_state"] + 1) % 3

        rows = model["rows"]
        state = model["sort_state"]
        if state == 0:
            sorted_rows = sorted(rows, key=lambda row: str(row["Address A"]))
        else:
            sorted_rows = sorted(
                rows,
                key=lambda row: self._sort_key(row.get(clicked_name)),
                reverse=(state == 2),
            )
        self._render_rows(self.tables[tab_name], sorted_rows, columns)

    def _sort_key(self, value):
        if value is None:
            return (2, "")
        if isinstance(value, (int, float)):
            return (0, value)
        text = str(value)
        try:
            if text.isdigit():
                return (0, int(text))
            return (1, text)
        except Exception:
            return (1, text)
