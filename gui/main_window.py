import logging
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QMainWindow,
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QFileDialog,
    QMessageBox,
    QSplitter,
    QLineEdit,
    QLabel,
    QToolButton,
    QMenuBar,
)

from core.capture import PacketSniffer
from core.parser import parse_packet
from utils.pcap_io import save_pcap, load_pcap

log = logging.getLogger("main_window")


class MainWindow(QMainWindow):
    def __init__(self, iface):
        super().__init__()
        self.iface = iface
        self.setWindowTitle(f"*{self.iface}")
        self.resize(1400, 850)

        self.packets = []
        self.parsed_packets = []
        self.packet_count = 0
        self.sniffer = None

        log.info(f"MainWindow khởi tạo với iface={self.iface!r}")
        self.init_ui()

    def init_ui(self):
        root = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # ===== Menu + Toolbar (giao diện giống Wireshark) =====
        menu_bar = QMenuBar()
        for name in ["File", "Edit", "View", "Go", "Capture", "Analyze", "Statistics", "Telephony", "Wireless", "Tools", "Help"]:
            menu_bar.addMenu(name)
        layout.addWidget(menu_bar)

        toolbar = QHBoxLayout()
        toolbar.setContentsMargins(8, 4, 8, 4)
        toolbar.setSpacing(4)

        for text in ["▶", "■", "⟳", "⚙", "📂", "💾", "🔍", "↶", "↷"]:
            btn = QToolButton()
            btn.setText(text)
            btn.setEnabled(False)
            btn.setFixedSize(28, 24)
            toolbar.addWidget(btn)

        toolbar.addSpacing(6)
        self.start_btn = QPushButton("Start")
        self.stop_btn = QPushButton("Stop")
        self.save_btn = QPushButton("Save PCAP")
        self.load_btn = QPushButton("Load PCAP")
        self.stop_btn.setEnabled(False)

        toolbar.addWidget(self.start_btn)
        toolbar.addWidget(self.stop_btn)
        toolbar.addWidget(self.save_btn)
        toolbar.addWidget(self.load_btn)
        toolbar.addStretch()

        toolbar_wrap = QWidget()
        toolbar_wrap.setLayout(toolbar)
        layout.addWidget(toolbar_wrap)

        # ===== Display filter row =====
        filter_row = QHBoxLayout()
        filter_row.setContentsMargins(8, 0, 8, 4)
        filter_row.setSpacing(6)

        self.display_filter_input = QLineEdit()
        self.display_filter_input.setPlaceholderText("Apply a display filter ... <Ctrl-/>")

        self.apply_filter_btn = QPushButton("➡")
        self.apply_filter_btn.setEnabled(True)
        self.apply_filter_btn.setFixedWidth(36)

        self.clear_filter_btn = QPushButton("✕")
        self.clear_filter_btn.setFixedWidth(28)

        filter_row.addWidget(self.display_filter_input)
        filter_row.addWidget(self.apply_filter_btn)
        filter_row.addWidget(self.clear_filter_btn)

        filter_wrap = QWidget()
        filter_wrap.setLayout(filter_row)
        layout.addWidget(filter_wrap)

        # ===== Packet Table =====
        self.table = QTableWidget()
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels(
            ["No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"]
        )
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.setSortingEnabled(False)
        self.table.cellClicked.connect(self.show_details)

        # ===== Bottom split (details + bytes pane text) =====
        bottom_splitter = QSplitter(Qt.Horizontal)

        self.details = QTextEdit()
        self.details.setReadOnly(True)

        self.bytes_text = QTextEdit()
        self.bytes_text.setReadOnly(True)
        self.bytes_text.setPlaceholderText("Raw bytes / hex view (text) sẽ hiển thị ở đây")

        bottom_splitter.addWidget(self.details)
        bottom_splitter.addWidget(self.bytes_text)
        bottom_splitter.setSizes([850, 550])

        main_splitter = QSplitter(Qt.Vertical)
        main_splitter.addWidget(self.table)
        main_splitter.addWidget(bottom_splitter)
        main_splitter.setSizes([500, 280])

        layout.addWidget(main_splitter)

        # ===== Status/footer giống feel Wireshark =====
        self.footer = QLabel("Packets: 0 | Displayed: 0 | Protocols: -")
        self.footer.setContentsMargins(8, 4, 8, 4)
        layout.addWidget(self.footer)

        root.setLayout(layout)
        self.setCentralWidget(root)

        self.start_btn.clicked.connect(self.start_capture)
        self.stop_btn.clicked.connect(self.stop_capture)
        self.save_btn.clicked.connect(self.save_file)
        self.load_btn.clicked.connect(self.load_file)
        self.apply_filter_btn.clicked.connect(self.apply_display_filter)
        self.clear_filter_btn.clicked.connect(self.clear_display_filter)
        self.display_filter_input.returnPressed.connect(self.apply_display_filter)

    # ===== Capture =====

    def start_capture(self):
        if self.sniffer and self.sniffer.isRunning():
            log.warning("Sniffer đang chạy, bỏ qua start_capture()")
            return

        log.info(f"Bắt đầu capture trên {self.iface!r}")
        self.sniffer = PacketSniffer(self.iface)
        self.sniffer.packet_captured.connect(self.add_packet)
        self.sniffer.error_occurred.connect(self.on_sniffer_error)
        self.sniffer.start()
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)

    def stop_capture(self):
        if self.sniffer and self.sniffer.isRunning():
            log.info("Dừng capture...")
            self.sniffer.stop()
            self.sniffer.wait()
            log.info("Capture đã dừng.")

        self.sniffer = None
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    def closeEvent(self, event):
        # đảm bảo thread sniff được dừng khi đóng cửa sổ
        self.stop_capture()
        super().closeEvent(event)

    def on_sniffer_error(self, msg):
        log.error(f"Sniffer lỗi: {msg}")
        QMessageBox.critical(self, "Capture Error", msg)
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

    # ===== Packet Handling =====

    def add_packet(self, packet):
        self.packet_count += 1
        parsed = parse_packet(packet, self.packet_count)
        self.packets.append(packet)
        self.parsed_packets.append(parsed)

        if self._matches_filter(parsed, self.display_filter_input.text()):
            self._append_row(parsed)

        self.update_footer()

    def _append_row(self, parsed):
        row = self.table.rowCount()
        self.table.insertRow(row)

        self.table.setItem(row, 0, QTableWidgetItem(str(parsed["no"])))
        self.table.setItem(row, 1, QTableWidgetItem(parsed["time"]))
        self.table.setItem(row, 2, QTableWidgetItem(parsed["src"]))
        self.table.setItem(row, 3, QTableWidgetItem(parsed["dst"]))
        self.table.setItem(row, 4, QTableWidgetItem(parsed["proto"]))
        self.table.setItem(row, 5, QTableWidgetItem(str(parsed["length"])))
        self.table.setItem(row, 6, QTableWidgetItem(parsed["info"]))

        self._colorize_row(row, parsed["proto"])
        self.table.scrollToBottom()

    def _colorize_row(self, row, proto):
        palette = {
            "TCP": QColor(230, 245, 255),
            "UDP": QColor(235, 255, 235),
            "DNS": QColor(255, 243, 224),
            "ARP": QColor(255, 224, 224),
            "ICMP": QColor(245, 235, 255),
        }
        color = palette.get(proto)
        if not color:
            return
        for col in range(self.table.columnCount()):
            item = self.table.item(row, col)
            if item:
                item.setBackground(color)

    def _matches_filter(self, parsed, filter_text):
        text = (filter_text or "").strip().lower()
        if not text:
            return True

        if text in {"tcp", "udp", "dns", "arp", "icmp"}:
            return parsed["proto"].lower() == text

        if text.startswith("ip.addr=="):
            value = text.split("==", 1)[1].strip()
            return value and (parsed["src"] == value or parsed["dst"] == value)

        if text.startswith("tcp.port==") or text.startswith("udp.port=="):
            try:
                port = int(text.split("==", 1)[1].strip())
            except ValueError:
                return False
            return parsed["sport"] == port or parsed["dport"] == port

        haystack = " ".join(
            [
                str(parsed["src"]),
                str(parsed["dst"]),
                str(parsed["proto"]),
                str(parsed["length"]),
                str(parsed["info"]),
                " ".join(parsed["layers"]),
            ]
        ).lower()
        return text in haystack

    def apply_display_filter(self):
        self.table.setRowCount(0)
        for parsed in self.parsed_packets:
            if self._matches_filter(parsed, self.display_filter_input.text()):
                self._append_row(parsed)
        self.update_footer()

    def clear_display_filter(self):
        self.display_filter_input.clear()
        self.apply_display_filter()

    def update_footer(self):
        visible = self.table.rowCount()
        protos = {}
        for p in self.parsed_packets:
            protos[p["proto"]] = protos.get(p["proto"], 0) + 1
        proto_str = ", ".join(f"{k}:{v}" for k, v in sorted(protos.items())) if protos else "-"
        self.footer.setText(
            f"Packets: {self.packet_count} | Displayed: {visible} | Protocols: {proto_str}"
        )

    def show_details(self, row, col):
        if row < 0 or row >= self.table.rowCount():
            log.warning(
                f"show_details: row {row} ngoài phạm vi (có {self.table.rowCount()} hàng hiển thị)"
            )
            return

        packet_no_item = self.table.item(row, 0)
        if not packet_no_item:
            return
        packet_no = int(packet_no_item.text())
        packet = self.packets[packet_no - 1]
        self.details.setText(packet.show(dump=True))

        try:
            raw_bytes = bytes(packet)
            hex_chunks = [f"{b:02x}" for b in raw_bytes]
            grouped = []
            for i in range(0, len(hex_chunks), 16):
                offset = f"{i:04x}"
                line = " ".join(hex_chunks[i:i + 16])
                grouped.append(f"{offset}  {line}")
            self.bytes_text.setText("\n".join(grouped))
        except Exception as e:
            self.bytes_text.setText(f"Không thể render bytes: {e}")

    # ===== PCAP =====

    def save_file(self):
        if not self.packets:
            QMessageBox.warning(self, "Warning", "Không có packet nào để lưu.")
            return

        filename, _ = QFileDialog.getSaveFileName(self, "Save PCAP", "", "PCAP Files (*.pcap)")
        if filename:
            log.info(f"Lưu {len(self.packets)} packets → {filename}")
            save_pcap(filename, self.packets)

    def load_file(self):
        filename, _ = QFileDialog.getOpenFileName(self, "Open PCAP", "", "PCAP Files (*.pcap)")
        if filename:
            log.info(f"Tải PCAP từ {filename}")
            self.stop_capture()
            self.packets.clear()
            self.parsed_packets.clear()
            self.packet_count = 0
            self.table.setRowCount(0)
            packets = load_pcap(filename)
            for p in packets:
                self.add_packet(p)
            log.info(f"Đã load {len(packets)} packets.")