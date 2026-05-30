from PySide6.QtCore import Qt
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QAbstractItemView, QHeaderView, QTableWidget, QTableWidgetItem


class PacketTable(QTableWidget):
    INFO_COLUMN = 6
    MARKED_ROLE = int(Qt.UserRole) + 100
    IGNORED_ROLE = int(Qt.UserRole) + 101

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
    DEFAULT_MARKED_COLOR = QColor(255, 243, 176)
    DEFAULT_IGNORED_COLOR = QColor(224, 224, 224)

    def __init__(self):
        super().__init__()
        self._color_rules_enabled = True
        self._marked_color = QColor(self.DEFAULT_MARKED_COLOR)
        self._ignored_color = QColor(self.DEFAULT_IGNORED_COLOR)
        self.setColumnCount(7)
        self.setHorizontalHeaderLabels(['No.', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info'])
        self.setEditTriggers(QTableWidget.NoEditTriggers)
        self.setSelectionBehavior(QTableWidget.SelectRows)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
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

    @staticmethod
    def display_values(record):
        ignored = bool(getattr(record, 'ignored', False))
        src = record.src
        dst = record.dst
        proto = record.protocol
        info = record.info
        if ignored:
            src = ''
            dst = ''
            proto = 'packet'
            info = '<IGNORED>'
        return [
            str(record.number),
            f'{record.relative_time:.9f}',
            src,
            dst,
            proto,
            str(record.length),
            info,
        ]

    def append_record(self, record):
        row = self.rowCount()
        self.insertRow(row)
        values = self.display_values(record)
        for col, value in enumerate(values):
            self.setItem(row, col, QTableWidgetItem(value))
        self._store_row_state(row, record)
        self._paint_row(row, record)
        return row

    def append_records(self, records):
        records = list(records or [])
        if not records:
            return
        start = self.rowCount()
        self.setRowCount(start + len(records))
        for rel, record in enumerate(records):
            row = start + rel
            values = self.display_values(record)
            for col, value in enumerate(values):
                item = self.item(row, col)
                if item is None:
                    item = QTableWidgetItem()
                    self.setItem(row, col, item)
                item.setText(value)
            self._store_row_state(row, record)
            self._paint_row(row, record)

    def replace_records(self, records):
        records = list(records or [])
        self.setRowCount(len(records))

        for row, record in enumerate(records):
            values = self.display_values(record)
            for col, value in enumerate(values):
                item = self.item(row, col)
                if item is None:
                    item = QTableWidgetItem()
                    self.setItem(row, col, item)
                item.setText(value)
            self._store_row_state(row, record)
            self._paint_row(row, record)

    def _store_row_state(self, row: int, record):
        marker = self.item(row, 0)
        if marker is None:
            marker = QTableWidgetItem()
            self.setItem(row, 0, marker)
        marker.setData(self.MARKED_ROLE, bool(getattr(record, 'marked', False)))
        marker.setData(self.IGNORED_ROLE, bool(getattr(record, 'ignored', False)))

    def _paint_row(self, row, record_or_proto):
        if isinstance(record_or_proto, str):
            proto = record_or_proto
            marker = self.item(row, 0)
            marked = bool(marker.data(self.MARKED_ROLE)) if marker is not None else False
            ignored = bool(marker.data(self.IGNORED_ROLE)) if marker is not None else False
        else:
            proto = str(getattr(record_or_proto, 'protocol', '') or '')
            marked = bool(getattr(record_or_proto, 'marked', False))
            ignored = bool(getattr(record_or_proto, 'ignored', False))

        if not self._color_rules_enabled:
            for col in range(self.columnCount()):
                item = self.item(row, col)
                if item:
                    item.setBackground(QColor(255, 255, 255))
                    item.setForeground(QColor(0, 0, 0))
            return

        if ignored:
            color = self._ignored_color
        elif marked:
            color = self._marked_color
        else:
            color = self.COLOR_MAP.get(proto)

        text_color = QColor(100, 100, 100) if ignored else QColor(0, 0, 0)
        for col in range(self.columnCount()):
            item = self.item(row, col)
            if item:
                if color:
                    item.setBackground(color)
                else:
                    item.setBackground(QColor(255, 255, 255))
                item.setForeground(text_color)

    def set_color_rules_enabled(self, enabled: bool):
        self._color_rules_enabled = bool(enabled)
        for row in range(self.rowCount()):
            proto_item = self.item(row, 4)
            proto = proto_item.text() if proto_item else ''
            self._paint_row(row, proto)

    def set_marked_color(self, color: QColor):
        if isinstance(color, QColor) and color.isValid():
            self._marked_color = QColor(color)
            self.set_color_rules_enabled(self._color_rules_enabled)

    def set_ignored_color(self, color: QColor):
        if isinstance(color, QColor) and color.isValid():
            self._ignored_color = QColor(color)
            self.set_color_rules_enabled(self._color_rules_enabled)

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
