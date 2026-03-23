import logging
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QTableWidget, QTableWidgetItem,
    QTextEdit, QFileDialog, QMessageBox
)

from core.capture import PacketSniffer
from core.parser import parse_packet
from utils.pcap_io import save_pcap, load_pcap

log = logging.getLogger("main_window")


class MainWindow(QMainWindow):
    def __init__(self, iface):
        super().__init__()
        self.iface = iface
        self.setWindowTitle(f"Packetra - {self.iface}")
        self.resize(1000, 700)

        self.packets = []
        self.packet_count = 0
        self.sniffer = None

        log.info(f"MainWindow khởi tạo với iface={self.iface!r}")
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        # ===== Toolbar =====
        toolbar = QHBoxLayout()

        self.start_btn = QPushButton("Start")
        self.stop_btn  = QPushButton("Stop")
        self.save_btn  = QPushButton("Save PCAP")
        self.load_btn  = QPushButton("Load PCAP")
        self.stop_btn.setEnabled(False)

        toolbar.addWidget(self.start_btn)
        toolbar.addWidget(self.stop_btn)
        toolbar.addWidget(self.save_btn)
        toolbar.addWidget(self.load_btn)

        # ===== Packet Table =====
        self.table = QTableWidget()
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels(
            ["No", "Time", "Source", "Destination", "Protocol", "Length", "Info"]
        )
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.cellClicked.connect(self.show_details)

        # ===== Details =====
        self.details = QTextEdit()
        self.details.setReadOnly(True)

        layout.addLayout(toolbar)
        layout.addWidget(self.table)
        layout.addWidget(self.details)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

        self.start_btn.clicked.connect(self.start_capture)
        self.stop_btn.clicked.connect(self.stop_capture)
        self.save_btn.clicked.connect(self.save_file)
        self.load_btn.clicked.connect(self.load_file)

    # ===== Capture =====

    def start_capture(self):
        log.info(f"Bắt đầu capture trên {self.iface!r}")
        self.sniffer = PacketSniffer(self.iface)
        self.sniffer.packet_captured.connect(self.add_packet)
        self.sniffer.error_occurred.connect(self.on_sniffer_error)
        self.sniffer.start()
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)

    def stop_capture(self):
        if self.sniffer:
            log.info("Dừng capture...")
            self.sniffer.stop()
            self.sniffer.wait()
            log.info("Capture đã dừng.")
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)

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

        row = self.table.rowCount()
        self.table.insertRow(row)

        self.table.setItem(row, 0, QTableWidgetItem(str(parsed["no"])))
        self.table.setItem(row, 1, QTableWidgetItem(parsed["time"]))
        self.table.setItem(row, 2, QTableWidgetItem(parsed["src"]))
        self.table.setItem(row, 3, QTableWidgetItem(parsed["dst"]))
        self.table.setItem(row, 4, QTableWidgetItem(parsed["proto"]))
        self.table.setItem(row, 5, QTableWidgetItem(str(parsed["length"])))
        self.table.setItem(row, 6, QTableWidgetItem(parsed["info"]))

    def show_details(self, row, col):
        if row < 0 or row >= len(self.packets):
            log.warning(f"show_details: row {row} ngoài phạm vi (có {len(self.packets)} packets)")
            return
        packet = self.packets[row]
        self.details.setText(packet.show(dump=True))

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
            packets = load_pcap(filename)
            for p in packets:
                self.add_packet(p)
            log.info(f"Đã load {len(packets)} packets.")