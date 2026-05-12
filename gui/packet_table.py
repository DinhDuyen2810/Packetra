from PySide6.QtGui import QColor
from PySide6.QtWidgets import QAbstractItemView, QHeaderView, QTableWidget, QTableWidgetItem


class PacketTable(QTableWidget):
    COLOR_MAP = {
        'TCP': QColor(227, 240, 255),
        'UDP': QColor(233, 255, 233),
        'DNS': QColor(247, 238, 220),
        'MDNS': QColor(247, 238, 220),
        'ARP': QColor(255, 228, 228),
        'ICMP': QColor(245, 236, 255),
        'ICMPV6': QColor(245, 236, 255),
        'TLS': QColor(237, 233, 255),
        'QUIC': QColor(216, 237, 255),
        'HTTP': QColor(255, 245, 219),
        'DHCP': QColor(229, 245, 238),
    }

    def __init__(self):
        super().__init__()
        self._color_rules_enabled = True
        self.setColumnCount(7)
        self.setHorizontalHeaderLabels(['No.', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info'])
        self.setEditTriggers(QTableWidget.NoEditTriggers)
        self.setSelectionBehavior(QTableWidget.SelectRows)
        self.setSelectionMode(QAbstractItemView.SingleSelection)
        self.setAlternatingRowColors(True)
        self.setSortingEnabled(False)
        self.setWordWrap(False)
        self.verticalHeader().setVisible(False)
        self.setShowGrid(True)
        header = self.horizontalHeader()
        header.setStretchLastSection(True)
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.Interactive)
        header.setSectionResizeMode(3, QHeaderView.Interactive)
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeToContents)
        self.setColumnWidth(2, 170)
        self.setColumnWidth(3, 170)
        self.setColumnWidth(6, 720)
        self.apply_content_resize_layout()

    def append_record(self, record):
        row = self.rowCount()
        self.insertRow(row)
        values = [
            str(record.number),
            f'{record.relative_time:.9f}',
            record.src,
            record.dst,
            record.protocol,
            str(record.length),
            record.info,
        ]
        for col, value in enumerate(values):
            self.setItem(row, col, QTableWidgetItem(value))
        self._paint_row(row, record.protocol)
        return row

    def _paint_row(self, row, proto):
        if not self._color_rules_enabled:
            for col in range(self.columnCount()):
                item = self.item(row, col)
                if item:
                    item.setBackground(QColor(255, 255, 255))
            return

        color = self.COLOR_MAP.get(proto)
        for col in range(self.columnCount()):
            item = self.item(row, col)
            if item:
                if color:
                    item.setBackground(color)
                else:
                    item.setBackground(QColor(255, 255, 255))

    def set_color_rules_enabled(self, enabled: bool):
        self._color_rules_enabled = bool(enabled)
        for row in range(self.rowCount()):
            proto_item = self.item(row, 4)
            proto = proto_item.text() if proto_item else ''
            self._paint_row(row, proto)

    def apply_content_resize_layout(self):
        header = self.horizontalHeader()
        # Keep Info as stretch so the table always fills available width.
        header.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.Interactive)
        header.setSectionResizeMode(3, QHeaderView.Interactive)
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(6, QHeaderView.Stretch)
