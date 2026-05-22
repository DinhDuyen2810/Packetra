from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QAbstractItemView, QHeaderView, QTableWidget, QTableWidgetItem


class PacketTable(QTableWidget):
    INFO_COLUMN = 6

    COLOR_MAP = {
        'TCP': QColor(227, 240, 255),
        'UDP': QColor(233, 255, 233),
        'DNS': QColor(247, 238, 220),
        'MDNS': QColor(247, 238, 220),
        'ARP': QColor(255, 228, 228),
        'ICMP': QColor(245, 236, 255),
        'ICMPV6': QColor(245, 236, 255),
        'ICMPv6': QColor(245, 236, 255),
        'IGMP': QColor(235, 245, 255),
        'IGMPv3': QColor(235, 245, 255),
        'TLS': QColor(237, 233, 255),
        'TLSv1.0': QColor(237, 233, 255),
        'TLSv1.1': QColor(237, 233, 255),
        'TLSv1.2': QColor(237, 233, 255),
        'TLSv1.3': QColor(237, 233, 255),
        'RIPng': QColor(233, 255, 233),
        'RIPv2': QColor(233, 255, 233),
        'STP': QColor(255, 244, 222),
        'Syslog': QColor(233, 255, 233),
        'NTP': QColor(233, 255, 233),
        'LACP': QColor(255, 244, 222),
        'VTP': QColor(255, 244, 222),
        'DTP': QColor(255, 244, 222),
        '0x6002': QColor(255, 244, 222),
        'UDLD': QColor(255, 244, 222),
        'LLDP': QColor(255, 244, 222),
        'HSRPv2': QColor(242, 236, 255),
        'LOOP': QColor(255, 255, 255),
        'QUIC': QColor(216, 237, 255),
        'HTTP': QColor(255, 245, 219),
        'SSDP': QColor(255, 245, 219),
        'SSHv2': QColor(227, 240, 255),
        'SMTP': QColor(255, 240, 216),
        'SMTP/IMF': QColor(255, 240, 216),
        'DHCP': QColor(229, 245, 238),
        'DHCPv6': QColor(229, 245, 238),
        'TFTP': QColor(229, 245, 238),
        'ESP': QColor(237, 233, 255),
        'ISAKMP': QColor(237, 233, 255),
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
        self.setHorizontalScrollMode(QAbstractItemView.ScrollPerPixel)
        self.setWordWrap(False)
        self.setTextElideMode(Qt.ElideRight)
        self.verticalHeader().setVisible(False)
        self.verticalHeader().setDefaultSectionSize(20)
        self.verticalHeader().setMinimumSectionSize(18)
        self.setShowGrid(True)
        header = self.horizontalHeader()
        header.setSectionsMovable(False)
        header.setStretchLastSection(True)
        self.setColumnWidth(0, 60)
        self.setColumnWidth(1, 130)
        self.setColumnWidth(2, 170)
        self.setColumnWidth(3, 170)
        self.setColumnWidth(4, 90)
        self.setColumnWidth(5, 80)
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

    def replace_records(self, records):
        records = list(records or [])
        self.setRowCount(len(records))

        for row, record in enumerate(records):
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
                item = self.item(row, col)
                if item is None:
                    item = QTableWidgetItem()
                    self.setItem(row, col, item)
                item.setText(value)
            self._paint_row(row, record.protocol)

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
        for col in range(self.INFO_COLUMN):
            header.setSectionResizeMode(col, QHeaderView.Interactive)
        header.setSectionResizeMode(self.INFO_COLUMN, QHeaderView.Stretch)

    def sync_row_height_to_font(self):
        row_height = max(16, self.fontMetrics().height() + 4)
        self.verticalHeader().setDefaultSectionSize(row_height)

    def scrollTo(self, index, hint=None):
        """Override scrollTo to preserve horizontal scroll position.
        Only allow vertical scrolling, not horizontal."""
        # Save current horizontal scroll position
        horizontal_value = self.horizontalScrollBar().value()
        
        # Call parent scrollTo (this may adjust horizontal position)
        if hint is not None:
            super().scrollTo(index, hint)
        else:
            super().scrollTo(index)
        
        # Restore horizontal scroll position to prevent unwanted horizontal scrolling
        self.horizontalScrollBar().setValue(horizontal_value)
