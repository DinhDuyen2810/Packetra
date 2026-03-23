from PySide6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QTableWidget, QTableWidgetItem,
    QTextEdit, QFileDialog
)

from core.capture import PacketSniffer
from core.parser import parse_packet
from utils.pcap_io import save_pcap, load_pcap


class MainWindow(QMainWindow):
    def __init__(self, iface):
        super().__init__()
        self.iface = iface

        self.setWindowTitle(f"Packetra - {self.iface}")
        self.resize(1000, 700)

        self.packets = []
        self.packet_count = 0

        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        # ===== Toolbar =====
        toolbar = QHBoxLayout()

        self.start_btn = QPushButton("Start")
        self.stop_btn = QPushButton("Stop")
        self.save_btn = QPushButton("Save PCAP")
        self.load_btn = QPushButton("Load PCAP")

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

        # ===== Events =====
        self.start_btn.clicked.connect(self.start_capture)
        self.stop_btn.clicked.connect(self.stop_capture)
        self.save_btn.clicked.connect(self.save_file)
        self.load_btn.clicked.connect(self.load_file)

    # ===== Capture =====

    def start_capture(self):
        self.sniffer = PacketSniffer(self.iface)
        self.sniffer.packet_captured.connect(self.add_packet)
        self.sniffer.start()

    def stop_capture(self):
        if hasattr(self, 'sniffer'):
            self.sniffer.stop()
            self.sniffer.wait()

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
        packet = self.packets[row]
        self.details.setText(packet.show(dump=True))

    # ===== PCAP =====

    def save_file(self):
        filename, _ = QFileDialog.getSaveFileName(self, "Save PCAP", "", "*.pcap")
        if filename:
            save_pcap(filename, self.packets)

    def load_file(self):
        filename, _ = QFileDialog.getOpenFileName(self, "Open PCAP", "", "*.pcap")
        if filename:
            packets = load_pcap(filename)
            for p in packets:
                self.add_packet(p)