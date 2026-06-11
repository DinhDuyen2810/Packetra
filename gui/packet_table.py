from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor
from PySide6.QtWidgets import QApplication, QAbstractItemView, QHeaderView, QTableWidget, QTableWidgetItem

from gui.filter_drag import build_filter_drag, packet_filter_expression


class PacketTable(QTableWidget):
    context_menu_requested = Signal(int, int, object)
    INFO_COLUMN = 6
    DRAGGABLE_COLUMNS = {2, 3, 4, 5}
    MARKED_ROLE = int(Qt.UserRole) + 100
    IGNORED_ROLE = int(Qt.UserRole) + 101
    ROW_RECORD_ROLE = int(Qt.UserRole) + 102

    WIRESHARK_DEFAULT_RULES = [
        {'name': 'Bad TCP', 'filter': 'tcp.analysis.flags && !tcp.analysis.window_update && !tcp.analysis.keep_alive && !tcp.analysis.keep_alive_ack', 'bg': QColor('#0B2C36'), 'fg': QColor('#FF6D6D')},
        {'name': 'HSRP State Change', 'filter': 'hsrp.state != 8 && hsrp.state != 16', 'bg': QColor('#0B2C36'), 'fg': QColor('#E4FF75')},
        {'name': 'Spanning Tree Topology Change', 'filter': 'stp.type == 0x80', 'bg': QColor('#0B2C36'), 'fg': QColor('#FFE082')},
        {'name': 'OSPF State Change', 'filter': 'ospf.msg != 1', 'bg': QColor('#0B2C36'), 'fg': QColor('#FFF59D')},
        {'name': 'ICMP errors', 'filter': 'icmp.type in {3,5,11} || icmpv6.type in {1,4}', 'bg': QColor('#0B2C36'), 'fg': QColor('#B7FF5A')},
        {'name': 'ARP', 'filter': 'arp', 'bg': QColor('#F2EED8'), 'fg': QColor('#111111')},
        {'name': 'ICMP', 'filter': 'icmp || icmpv6', 'bg': QColor('#E8D8EE'), 'fg': QColor('#111111')},
        {'name': 'TCP RST', 'filter': 'tcp.flags.reset == 1', 'bg': QColor('#CC0000'), 'fg': QColor('#FFFFFF')},
        {'name': 'SCTP ABORT', 'filter': 'sctp.chunk_type == ABORT', 'bg': QColor('#CC0000'), 'fg': QColor('#FFFFFF')},
        {'name': 'IPv4 TTL low or unexpected', 'filter': '(ip.dst != 224.0.0.0/4 && ip.ttl < 5)', 'bg': QColor('#CC0000'), 'fg': QColor('#FFFFFF')},
        {'name': 'IPv6 hop limit low or unexpected', 'filter': '(ipv6.dst != ff00::/8 && ipv6.hlim < 5)', 'bg': QColor('#CC0000'), 'fg': QColor('#FFFFFF')},
        {'name': 'Checksum Errors', 'filter': 'ip.checksum.status=="Bad" || tcp.checksum.status=="Bad" || udp.checksum.status=="Bad"', 'bg': QColor('#102A43'), 'fg': QColor('#FFC1E3')},
        {'name': 'SMB', 'filter': 'smb || nbss || nbns || netbios', 'bg': QColor('#F0EFD5'), 'fg': QColor('#111111')},
        {'name': 'HTTP', 'filter': 'http || tcp.port == 80 || http2', 'bg': QColor('#CFE8B4'), 'fg': QColor('#111111')},
        {'name': 'DCERPC', 'filter': 'dcerpc', 'bg': QColor('#B897EA'), 'fg': QColor('#111111')},
        {'name': 'Routing', 'filter': 'hsrp || eigrp || ospf || bgp || cdp || vrrp || carp || gvrp || igmp || ismp', 'bg': QColor('#EFE4C6'), 'fg': QColor('#111111')},
        {'name': 'TCP SYN/FIN', 'filter': 'tcp.flags & 0x02 || tcp.flags.fin == 1', 'bg': QColor('#A9A9A9'), 'fg': QColor('#111111')},
        {'name': 'TCP', 'filter': 'tcp', 'bg': QColor('#D8D8E8'), 'fg': QColor('#111111')},
        {'name': 'UDP', 'filter': 'udp', 'bg': QColor('#D2E9F7'), 'fg': QColor('#111111')},
        {'name': 'Broadcast', 'filter': 'eth[0] & 1', 'bg': QColor('#E6E6E6'), 'fg': QColor('#111111')},
        {'name': 'System Event', 'filter': 'systemd_journal || sysdig', 'bg': QColor('#DCDCDC'), 'fg': QColor('#1C5D99')},
    ]
    DEFAULT_MARKED_COLOR = QColor(255, 243, 176)
    DEFAULT_IGNORED_COLOR = QColor(224, 224, 224)

    def __init__(self):
        super().__init__()
        self._color_rules_enabled = True
        self._marked_color = QColor(self.DEFAULT_MARKED_COLOR)
        self._ignored_color = QColor(self.DEFAULT_IGNORED_COLOR)
        self._rule_background_overrides = {}
        self._column_alignment_map = {}
        self._related_indicators = {}
        self._immediate_indicator_row = None
        self._protocol_color_cache = {}
        self._color_cache_max_size = 256
        self.setColumnCount(7)
        self.setHorizontalHeaderLabels(['No.', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info'])
        self.setEditTriggers(QTableWidget.NoEditTriggers)
        self.setSelectionBehavior(QTableWidget.SelectRows)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setDragEnabled(True)
        self.setDragDropMode(QAbstractItemView.DragOnly)
        self.setContextMenuPolicy(Qt.CustomContextMenu)
        self.customContextMenuRequested.connect(self._on_custom_context_menu)
        self.setAlternatingRowColors(True)
        self.setSortingEnabled(False)
        self.setHorizontalScrollMode(QAbstractItemView.ScrollPerPixel)
        self.setWordWrap(False)
        self.setTextElideMode(Qt.ElideRight)
        self.setStyleSheet(
            'QTableWidget::item:selected { background-color: #2F80ED; color: #FFFFFF; } '
            'QTableWidget::item:selected:!active { background-color: #2F80ED; color: #FFFFFF; }'
        )
        vheader = self.verticalHeader()
        vheader.setVisible(True)
        vheader.setFixedWidth(38)
        vheader.setDefaultAlignment(Qt.AlignCenter)
        vheader.setDefaultSectionSize(20)
        vheader.setMinimumSectionSize(18)
        vheader.setStyleSheet('QHeaderView::section { font-size: 20px; font-weight: 700; padding-left: 3px; padding-right: 3px; }')
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
        self._default_column_widths = [self.columnWidth(i) for i in range(self.columnCount())]
        self._resize_all_columns_enabled = False
        self._drag_start_pos = None
        self._drag_cell = None
        self.apply_content_resize_layout()

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            index = self.indexAt(event.pos())
            if index.isValid() and int(index.column()) in self.DRAGGABLE_COLUMNS:
                self._drag_start_pos = event.pos()
                self._drag_cell = (int(index.row()), int(index.column()))
            else:
                self._drag_start_pos = None
                self._drag_cell = None
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event):
        if (
            self._drag_start_pos is not None
            and self._drag_cell is not None
            and bool(event.buttons() & Qt.LeftButton)
            and (event.pos() - self._drag_start_pos).manhattanLength() >= QApplication.startDragDistance()
        ):
            row, column = self._drag_cell
            expression = self._filter_expression_for_cell(row, column)
            drag = build_filter_drag(expression, self)
            self._drag_start_pos = None
            self._drag_cell = None
            if drag is not None:
                drag.exec(Qt.CopyAction)
                return
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event):
        self._drag_start_pos = None
        self._drag_cell = None
        super().mouseReleaseEvent(event)

    def _on_custom_context_menu(self, pos):
        item = self.itemAt(pos)
        if item is None:
            return
        row = int(item.row())
        column = int(item.column())
        self.context_menu_requested.emit(row, column, self.viewport().mapToGlobal(pos))

    def _row_record(self, row: int):
        if row < 0 or row >= self.rowCount():
            return None
        marker = self.item(row, 0)
        return marker.data(self.ROW_RECORD_ROLE) if marker is not None else None

    def _filter_expression_for_cell(self, row: int, column: int) -> str:
        record = self._row_record(row)
        return packet_filter_expression(record, column)

    def set_column_text_alignment(self, column: int, alignment):
        try:
            col = int(column)
        except Exception:
            return
        if col < 0:
            return
        self._column_alignment_map[col] = int(alignment)
        for row in range(self.rowCount()):
            item = self.item(row, col)
            if item is not None:
                item.setTextAlignment(int(alignment))

    def _apply_item_alignment(self, item: QTableWidgetItem, column: int):
        if item is None:
            return
        try:
            col = int(column)
        except Exception:
            col = -1
        alignment = self._column_alignment_map.get(col)
        if alignment is not None and int(item.textAlignment()) != int(alignment):
            item.setTextAlignment(int(alignment))

    def wireshark_coloring_rules(self):
        return [
            {
                'name': str(rule['name']),
                'filter': str(rule['filter']),
                'background': QColor(self._effective_rule_background(str(rule['name']))),
                'foreground': QColor(rule['fg']),
            }
            for rule in self.WIRESHARK_DEFAULT_RULES
        ]

    def _effective_rule_background(self, rule_name: str) -> QColor:
        name = str(rule_name or '').strip()
        override = self._rule_background_overrides.get(name)
        if isinstance(override, QColor) and override.isValid():
            return QColor(override)
        for rule in self.WIRESHARK_DEFAULT_RULES:
            if str(rule.get('name', '')).strip() == name:
                return QColor(rule['bg'])
        return QColor('#FFFFFF')

    def set_rule_background_overrides(self, overrides: dict | None):
        normalized = {}
        if isinstance(overrides, dict):
            for key, value in overrides.items():
                name = str(key or '').strip()
                if not name:
                    continue
                color = QColor(str(value or '').strip())
                if color.isValid():
                    normalized[name] = color
        self._rule_background_overrides = normalized
        self.set_color_rules_enabled(self._color_rules_enabled)

    def get_rule_background_overrides(self) -> dict[str, str]:
        return {name: color.name() for name, color in self._rule_background_overrides.items()}

    def _record_metadata(self, record_or_proto):
        if isinstance(record_or_proto, str):
            return {}
        metadata = getattr(record_or_proto, 'metadata', None)
        return metadata if isinstance(metadata, dict) else {}

    def _info_lower(self, record_or_proto):
        if isinstance(record_or_proto, str):
            return ''
        return str(getattr(record_or_proto, 'info', '') or '').lower()

    def _protocol_upper(self, record_or_proto):
        if isinstance(record_or_proto, str):
            return str(record_or_proto or '').upper()
        return str(getattr(record_or_proto, 'protocol', '') or '').upper()

    def _tcp_flags_value(self, metadata) -> int:
        raw_flags = metadata.get('tcp_flags', 0)
        if isinstance(raw_flags, int):
            return int(raw_flags)
        text = str(raw_flags or '').upper()
        value = 0
        if 'F' in text:
            value |= 0x01
        if 'S' in text:
            value |= 0x02
        if 'R' in text:
            value |= 0x04
        if 'P' in text:
            value |= 0x08
        if 'A' in text:
            value |= 0x10
        if 'U' in text:
            value |= 0x20
        return value

    def _has_bad_checksum(self, metadata, info_low: str) -> bool:
        if 'bad checksum' in info_low or 'checksum status: bad' in info_low:
            return True
        for value in metadata.values():
            if isinstance(value, dict):
                if str(value.get('checksum_status', '')).strip().lower() == 'bad':
                    return True
        return False

    def _is_multicast_or_broadcast_dst(self, record_or_proto) -> bool:
        if isinstance(record_or_proto, str):
            return False
        dst = str(getattr(record_or_proto, 'dst', '') or '').strip().lower()
        if not dst:
            return False
        if dst == 'ff:ff:ff:ff:ff:ff':
            return True
        if dst.startswith('224.'):
            return True
        if dst.startswith('ff') and ':' in dst:
            return True
        return False

    def _match_wireshark_style(self, record_or_proto):
        proto = self._protocol_upper(record_or_proto)
        metadata = self._record_metadata(record_or_proto)
        info_low = self._info_lower(record_or_proto)
        flags = self._tcp_flags_value(metadata)

        def _rule_matches(name: str) -> bool:
            rule_name = str(name or '').strip().lower()
            if rule_name == 'bad tcp':
                return (
                    proto == 'TCP' and (
                        bool(metadata.get('tcp_is_retransmission', False))
                        or bool(metadata.get('tcp_is_duplicate_ack', False))
                        or bool(metadata.get('tcp_previous_segment_not_captured', False))
                        or bool(metadata.get('tcp_is_acked_unseen_segment', False))
                        or bool(metadata.get('tcp_is_window_full', False))
                        or bool(metadata.get('tcp_is_spurious_retransmission', False))
                    )
                )
            if rule_name == 'hsrp state change':
                return proto in {'HSRP', 'HSRPV2'}
            if rule_name == 'spanning tree topology change':
                return proto == 'STP'
            if rule_name == 'ospf state change':
                return proto == 'OSPF' and 'hello' not in info_low
            if rule_name == 'icmp errors':
                return proto in {'ICMP', 'ICMPV6'} and any(
                    token in info_low for token in ('unreachable', 'time exceeded', 'parameter problem', 'redirect')
                )
            if rule_name == 'arp':
                return proto == 'ARP'
            if rule_name == 'icmp':
                return proto in {'ICMP', 'ICMPV6'}
            if rule_name == 'tcp rst':
                return proto == 'TCP' and bool(flags & 0x04)
            if rule_name == 'sctp abort':
                return proto == 'SCTP' and 'abort' in info_low
            if rule_name == 'ipv4 ttl low or unexpected':
                try:
                    ttl_value = int(metadata.get('ttl', -1))
                except Exception:
                    ttl_value = -1
                return ttl_value >= 0 and ttl_value < 5 and not self._is_multicast_or_broadcast_dst(record_or_proto)
            if rule_name == 'ipv6 hop limit low or unexpected':
                try:
                    hlim_value = int(metadata.get('hlim', -1))
                except Exception:
                    hlim_value = -1
                return hlim_value >= 0 and hlim_value < 5 and not self._is_multicast_or_broadcast_dst(record_or_proto)
            if rule_name == 'checksum errors':
                return self._has_bad_checksum(metadata, info_low)
            if rule_name == 'smb':
                return proto in {'SMB', 'SMB2', 'NBSS', 'NBNS', 'NETBIOS'}
            if rule_name == 'http':
                return proto in {'HTTP', 'HTTP/XML', 'HTTP2'}
            if rule_name == 'dcerpc':
                return proto in {'DCERPC', 'DRSUAPI', 'RPC_NETLOGON', 'SAMR'}
            if rule_name == 'routing':
                return proto in {
                    'EIGRP', 'OSPF', 'BGP', 'CDP', 'VRRP', 'CARP', 'GVRP', 'IGMP', 'ISMP',
                    'RIPNG', 'RIPV2', 'PIMV1', 'PIMV2', 'GRE',
                }
            if rule_name == 'tcp syn/fin':
                return proto == 'TCP' and bool(flags & (0x02 | 0x01))
            if rule_name == 'tcp':
                return proto == 'TCP'
            if rule_name == 'udp':
                return proto == 'UDP'
            if rule_name == 'broadcast':
                return self._is_multicast_or_broadcast_dst(record_or_proto)
            if rule_name == 'system event':
                return proto in {'SYSTEM EVENT', 'SYSTEMD_JOURNAL', 'SYSDIG'}
            return False

        # Rules are applied from top to bottom; first match wins.
        for rule in self.WIRESHARK_DEFAULT_RULES:
            if _rule_matches(str(rule.get('name', ''))):
                return QColor(self._effective_rule_background(str(rule.get('name', '')))), QColor(rule['fg'])

        return None, None

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

    def _populate_row_from_record(self, row: int, record, clear_extra_columns: bool = True):
        self._ensure_related_indicator_cell(row)
        values = self.display_values(record)
        info_col = max(0, self.columnCount() - 1)
        for col in range(self.columnCount()):
            # Custom columns (between Length and Info) are populated lazily to keep initial
            # loading and scrolling responsive on large captures.
            if 6 <= col < info_col and clear_extra_columns:
                if self.item(row, col) is None:
                    continue
            item = self.item(row, col)
            if item is None:
                item = QTableWidgetItem()
                self.setItem(row, col, item)
            if col == info_col:
                text = values[6]
            elif 0 <= col <= 5:
                text = values[col]
            else:
                text = '' if clear_extra_columns else str(item.text() or '')
            text = str(text)
            if item.text() != text:
                item.setText(text)
            self._apply_item_alignment(item, col)

    def append_record(self, record):
        row = self.rowCount()
        self.insertRow(row)
        self._ensure_related_indicator_cell(row)
        self._populate_row_from_record(row, record)
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
            self._ensure_related_indicator_cell(row)
            self._populate_row_from_record(row, record)
            self._store_row_state(row, record)
            self._paint_row(row, record)

    def replace_records(self, records):
        records = list(records or [])
        self.setRowCount(len(records))

        for row, record in enumerate(records):
            self._ensure_related_indicator_cell(row)
            self._populate_row_from_record(row, record)
            self._store_row_state(row, record)
            self._paint_row(row, record)

    def _store_row_state(self, row: int, record):
        marker = self.item(row, 0)
        if marker is None:
            marker = QTableWidgetItem()
            self.setItem(row, 0, marker)
        marker.setData(self.MARKED_ROLE, bool(getattr(record, 'marked', False)))
        marker.setData(self.IGNORED_ROLE, bool(getattr(record, 'ignored', False)))
        marker.setData(self.ROW_RECORD_ROLE, record)

    def _paint_row(self, row, record_or_proto):
        if isinstance(record_or_proto, str):
            proto = record_or_proto
            marker = self.item(row, 0)
            marked = bool(marker.data(self.MARKED_ROLE)) if marker is not None else False
            ignored = bool(marker.data(self.IGNORED_ROLE)) if marker is not None else False
            record_obj = marker.data(self.ROW_RECORD_ROLE) if marker is not None else None
            if record_obj is not None:
                record_or_proto = record_obj
        else:
            proto = str(getattr(record_or_proto, 'protocol', '') or '')
            marked = bool(getattr(record_or_proto, 'marked', False))
            ignored = bool(getattr(record_or_proto, 'ignored', False))

        if not self._color_rules_enabled:
            white = QColor(255, 255, 255)
            black = QColor(0, 0, 0)
            for col in range(self.columnCount()):
                item = self.item(row, col)
                if item:
                    if item.background().color() != white:
                        item.setBackground(white)
                    if item.foreground().color() != black:
                        item.setForeground(black)
            return

        if ignored:
            color = self._ignored_color
            text_color = QColor(100, 100, 100)
        elif marked:
            color = self._marked_color
            text_color = QColor(0, 0, 0)
        else:
            cache_key = str(proto or '').upper()
            if cache_key in self._protocol_color_cache:
                color, text_color = self._protocol_color_cache[cache_key]
            else:
                color, text_color = self._match_wireshark_style(record_or_proto)
                if text_color is None:
                    text_color = QColor(0, 0, 0)
                if len(self._protocol_color_cache) < self._color_cache_max_size:
                    self._protocol_color_cache[cache_key] = (color, text_color)

        background_color = color if color else QColor(255, 255, 255)
        for col in range(self.columnCount()):
            item = self.item(row, col)
            if item:
                if item.background().color() != background_color:
                    item.setBackground(background_color)
                if item.foreground().color() != text_color:
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
        info_col = max(0, self.columnCount() - 1)
        for col in range(self.columnCount()):
            mode = QHeaderView.Stretch if col == info_col else QHeaderView.Interactive
            header.setSectionResizeMode(col, mode)

    def set_resize_all_columns_mode(self, enabled: bool):
        self._resize_all_columns_enabled = bool(enabled)
        if self._resize_all_columns_enabled:
            self.resizeColumnsToContents()
            self.apply_content_resize_layout()
            return
        for col, width in enumerate(self._default_column_widths):
            self.setColumnWidth(col, int(width))
        self.apply_content_resize_layout()

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

    def _ensure_related_indicator_cell(self, row: int):
        if row < 0 or row >= self.rowCount():
            return
        item = self.verticalHeaderItem(row)
        if item is None:
            item = QTableWidgetItem('')
            self.setVerticalHeaderItem(row, item)
        if item.text() and item.text().strip().isdigit():
            item.setText('')
        item.setTextAlignment(int(Qt.AlignCenter))

    def set_related_indicators(self, indicators: dict | None):
        normalized = {}
        if isinstance(indicators, dict):
            for key, value in indicators.items():
                try:
                    row = int(key)
                except Exception:
                    continue
                if row < 0 or row >= self.rowCount():
                    continue
                text = str(value or '').strip()
                if text:
                    normalized[row] = text
        if normalized == self._related_indicators:
            return

        changed_rows = set(self._related_indicators.keys()) | set(normalized.keys())
        for row in changed_rows:
            if row < 0 or row >= self.rowCount():
                continue
            item = self.verticalHeaderItem(row)
            if item is None:
                item = QTableWidgetItem()
                self.setVerticalHeaderItem(row, item)
            text = normalized.get(row, '')
            item.setText(text)
            item.setTextAlignment(int(Qt.AlignCenter))
            item.setToolTip('Related packet indicator' if text else '')
        self._related_indicators = normalized
        self._immediate_indicator_row = None

    def set_selected_indicator_immediate(self, row: int, symbol: str = '◆'):
        try:
            target = int(row)
        except Exception:
            return
        if target < 0 or target >= self.rowCount():
            return

        prev = self._immediate_indicator_row
        if prev is not None and prev != target and 0 <= int(prev) < self.rowCount():
            prev_item = self.verticalHeaderItem(int(prev))
            if prev_item is None:
                prev_item = QTableWidgetItem()
                self.setVerticalHeaderItem(int(prev), prev_item)
            fallback = str(self._related_indicators.get(int(prev), '') or '')
            prev_item.setText(fallback)
            prev_item.setTextAlignment(int(Qt.AlignCenter))
            prev_item.setToolTip('Related packet indicator' if fallback else '')

        item = self.verticalHeaderItem(target)
        if item is None:
            item = QTableWidgetItem()
            self.setVerticalHeaderItem(target, item)
        text = str(symbol or '').strip()
        item.setText(text)
        item.setTextAlignment(int(Qt.AlignCenter))
        item.setToolTip('Related packet indicator' if text else '')
        self._immediate_indicator_row = int(target)
