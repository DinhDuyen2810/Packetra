import logging
from collections import Counter
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFileDialog, QHBoxLayout, QLabel, QLineEdit, QMainWindow, QMenuBar, QMessageBox,
    QPushButton, QSplitter, QToolButton, QVBoxLayout, QWidget
)

from core.capture import PacketSniffer
from core.filtering import DisplayFilter
from core.parser import PacketParser
from gui.hex_view import PacketHexView
from gui.packet_details import PacketDetailsTree
from gui.packet_table import PacketTable
from utils.pcap_io import load_pcap, save_pcap

log = logging.getLogger('main_window')


class MainWindow(QMainWindow):
    def __init__(self, iface: str, iface_display_name: str, capture_filter: str = ''):
        super().__init__()
        self.iface = iface
        self.iface_display_name = iface_display_name
        self.capture_filter = capture_filter
        self.setWindowTitle(f'*{iface_display_name}')
        self.resize(1700, 930)

        self.parser = PacketParser()
        self.display_filter = DisplayFilter()
        self.records = []
        self.visible_indices = []
        self.sniffer = None

        self._build_ui()
        self._update_status('Ready')

    def _build_ui(self):
        root = QWidget()
        layout = QVBoxLayout(root)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        menu_bar = QMenuBar()
        for name in ['File', 'Edit', 'View', 'Go', 'Capture', 'Analyze', 'Statistics', 'Telephony', 'Wireless', 'Tools', 'Help']:
            menu_bar.addMenu(name)
        layout.addWidget(menu_bar)

        toolbar = QHBoxLayout()
        toolbar.setContentsMargins(8, 4, 8, 4)
        for text in ['▶', '■', '⟳', '⚙', '📂', '💾', '🔍']:
            btn = QToolButton()
            btn.setText(text)
            btn.setEnabled(False)
            btn.setFixedSize(28, 24)
            toolbar.addWidget(btn)
        self.start_btn = QPushButton('Start')
        self.stop_btn = QPushButton('Stop')
        self.reload_btn = QPushButton('Reload View')
        self.save_btn = QPushButton('Save PCAP')
        self.load_btn = QPushButton('Load PCAP')
        self.stop_btn.setEnabled(False)
        toolbar.addSpacing(8)
        for w in [self.start_btn, self.stop_btn, self.reload_btn, self.save_btn, self.load_btn]:
            toolbar.addWidget(w)
        toolbar.addStretch()
        toolbar_widget = QWidget()
        toolbar_widget.setLayout(toolbar)
        layout.addWidget(toolbar_widget)

        filter_row = QHBoxLayout()
        filter_row.setContentsMargins(8, 0, 8, 4)
        self.display_filter_input = QLineEdit()
        self.display_filter_input.setPlaceholderText('Apply a display filter ... <Ctrl+/>')
        self.apply_filter_btn = QPushButton('➡')
        self.clear_filter_btn = QPushButton('✕')
        self.apply_filter_btn.setFixedWidth(38)
        self.clear_filter_btn.setFixedWidth(38)
        filter_row.addWidget(self.display_filter_input)
        filter_row.addWidget(self.apply_filter_btn)
        filter_row.addWidget(self.clear_filter_btn)
        filter_widget = QWidget()
        filter_widget.setLayout(filter_row)
        layout.addWidget(filter_widget)

        self.table = PacketTable()
        self.details_tree = PacketDetailsTree()
        self.hex_view = PacketHexView()

        lower_splitter = QSplitter(Qt.Horizontal)
        lower_splitter.addWidget(self.details_tree)
        lower_splitter.addWidget(self.hex_view)
        lower_splitter.setSizes([980, 650])
        lower_splitter.setChildrenCollapsible(False)

        main_splitter = QSplitter(Qt.Vertical)
        main_splitter.addWidget(self.table)
        main_splitter.addWidget(lower_splitter)
        main_splitter.setSizes([500, 360])
        main_splitter.setChildrenCollapsible(False)
        layout.addWidget(main_splitter)

        self.footer = QLabel()
        self.footer.setContentsMargins(8, 4, 8, 4)
        layout.addWidget(self.footer)

        self.setCentralWidget(root)

        self.start_btn.clicked.connect(self.start_capture)
        self.stop_btn.clicked.connect(self.stop_capture)
        self.reload_btn.clicked.connect(self.apply_display_filter)
        self.save_btn.clicked.connect(self.save_file)
        self.load_btn.clicked.connect(self.load_file)
        self.apply_filter_btn.clicked.connect(self.apply_display_filter)
        self.clear_filter_btn.clicked.connect(self.clear_display_filter)
        self.display_filter_input.returnPressed.connect(self.apply_display_filter)
        self.table.cellClicked.connect(self.show_details)
        self.details_tree.item_selected.connect(self.hex_view.highlight_bytes)
        self.hex_view.bytes_selected.connect(self.details_tree.select_offset)

    def _update_status(self, message):
        proto_counts = Counter(r.protocol for r in self.records)
        proto_text = ', '.join(f'{k}:{v}' for k, v in sorted(proto_counts.items())) if proto_counts else '-'
        self.footer.setText(
            f'Interface: {self.iface_display_name} | Capture filter: {self.capture_filter or "(none)"} | '
            f'Packets: {len(self.records)} | Displayed: {len(self.visible_indices)} | Protocols: {proto_text} | {message}'
        )

    def start_capture(self):
        if self.sniffer and self.sniffer.isRunning():
            return
        self.sniffer = PacketSniffer(self.iface, self.capture_filter)
        self.sniffer.packet_captured.connect(self.add_packet)
        self.sniffer.error_occurred.connect(self.on_sniffer_error)
        self.sniffer.status_changed.connect(self._update_status)
        self.sniffer.start()
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)

    def stop_capture(self):
        if self.sniffer and self.sniffer.isRunning():
            self.sniffer.stop()
            self.sniffer.wait()
        self.sniffer = None
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self._update_status('Capture stopped')

    def closeEvent(self, event):
        self.stop_capture()
        super().closeEvent(event)

    def on_sniffer_error(self, msg):
        QMessageBox.critical(self, 'Capture error', msg)
        self.stop_capture()

    def add_packet(self, packet):
        record = self.parser.parse(packet, len(self.records) + 1)
        self.records.append(record)
        if self.display_filter.matches(record, self.display_filter_input.text()):
            self.visible_indices.append(len(self.records) - 1)
            self.table.append_record(record)
        self._update_status('Live capture')

    def apply_display_filter(self):
        self.table.setRowCount(0)
        self.visible_indices.clear()
        expr = self.display_filter_input.text()
        for idx, record in enumerate(self.records):
            if self.display_filter.matches(record, expr):
                self.visible_indices.append(idx)
                self.table.append_record(record)
        self._update_status('Display filter applied')

    def clear_display_filter(self):
        self.display_filter_input.clear()
        self.apply_display_filter()

    def show_details(self, row, _col):
        if row < 0 or row >= len(self.visible_indices):
            return
        record = self.records[self.visible_indices[row]]
        self.details_tree.show_packet(record)
        self.hex_view.show_packet(record)
        self._update_status(f'Selected frame {record.number}')

    def save_file(self):
        if not self.records:
            QMessageBox.warning(self, 'Warning', 'Không có packet nào để lưu.')
            return
        filename, _ = QFileDialog.getSaveFileName(self, 'Save PCAP', '', 'PCAP Files (*.pcap)')
        if filename:
            save_pcap(filename, [r.raw for r in self.records])
            self._update_status(f'Saved to {filename}')

    def load_file(self):
        filename, _ = QFileDialog.getOpenFileName(self, 'Open PCAP', '', 'PCAP Files (*.pcap *.pcapng)')
        if not filename:
            return
        self.stop_capture()
        self.records.clear()
        self.visible_indices.clear()
        self.table.setRowCount(0)
        self.details_tree.show_packet(None)
        self.hex_view.show_packet(None)
        self.parser = PacketParser()
        packets, metadata = load_pcap(filename)
        for idx, packet in enumerate(packets, start=1):
            self.records.append(self.parser.parse(packet, idx))
        self.apply_display_filter()
        self._update_status(f'Loaded {len(self.records)} packets from {filename}')
