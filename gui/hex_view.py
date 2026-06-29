from PySide6.QtCore import Qt, Signal, QPoint
from PySide6.QtGui import QFont, QTextCursor, QTextCharFormat, QColor
from PySide6.QtWidgets import QApplication, QPlainTextEdit, QStackedWidget, QTabBar, QWidget, QStatusBar

from core.formatters import hex_dump


def _record_packet_bytes(record) -> bytes:
    if not record:
        return b''
    raw = getattr(record, 'raw', None)
    if raw is None:
        return b''
    frame_raw = getattr(raw, 'frame_raw_bytes', None)
    if isinstance(frame_raw, (bytes, bytearray)):
        return bytes(frame_raw)
    try:
        return bytes(raw)
    except Exception:
        return b''


class PacketHexView(QPlainTextEdit):
    BYTES_PER_LINE = 16
    OFFSET_WIDTH = 4
    OFFSET_SEPARATOR_WIDTH = 4
    HEX_BYTE_WIDTH = 3
    HEX_GROUP_BREAK_INDEX = 8
    HEX_SECTION_WIDTH = 48
    ASCII_SEPARATOR_WIDTH = 4
    HEX_START_COLUMN = OFFSET_WIDTH + OFFSET_SEPARATOR_WIDTH
    ASCII_START_COLUMN = HEX_START_COLUMN + HEX_SECTION_WIDTH + ASCII_SEPARATOR_WIDTH

    bytes_selected = Signal(int)
    bytes_range_selected = Signal(int, int)  # (offset, length)
    bytes_hovered = Signal(int)  # byte offset under mouse
    hover_left = Signal()
    context_menu_requested = Signal(object)

    def __init__(self):
        super().__init__()
        self.setReadOnly(True)
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self._on_custom_context_menu)
        font = QFont('Consolas')
        font.setStyleHint(QFont.Monospace)
        self.setFont(font)
        self.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.setMouseTracking(True)  # Enable mouseMoveEvent when not dragging
        self._selected_ranges = []
        self._hover_highlight_ranges = []
        self._last_hovered_byte = None
        self._raw_data = b''
        self.setViewportMargins(0, 0, 0, 0)

    def _on_custom_context_menu(self, pos):
        self.context_menu_requested.emit(self.viewport().mapToGlobal(pos))

    def show_packet(self, record):
        self.show_bytes(_record_packet_bytes(record))

    def show_bytes(self, data):
        self._raw_data = bytes(data or b'')
        self._selected_ranges = []
        self._hover_highlight_ranges = []
        self._last_hovered_byte = None
        self.setPlainText(hex_dump(self._raw_data) if self._raw_data else '')

    def selected_raw_bytes(self) -> bytes:
        if not self._selected_ranges:
            return b''
        chunks = []
        data = self._raw_data or b''
        for start, length in self._selected_ranges:
            s = max(0, int(start))
            e = max(s, min(len(data), s + int(length)))
            if e > s:
                chunks.append(data[s:e])
        return b''.join(chunks)

    def _line_byte_count(self, line: str) -> int:
        if len(line) <= self.ASCII_START_COLUMN:
            return 0
        return min(self.BYTES_PER_LINE, len(line) - self.ASCII_START_COLUMN)

    def _hex_byte_start_column(self, byte_index: int) -> int:
        column = self.HEX_START_COLUMN + byte_index * self.HEX_BYTE_WIDTH
        if byte_index >= self.HEX_GROUP_BREAK_INDEX:
            column += 1
        return column

    def _parse_line_context(self, cursor):
        line = cursor.block().text()
        if not line or len(line) < self.HEX_START_COLUMN:
            return None, 0, line

        try:
            line_offset = int(line[:self.OFFSET_WIDTH], 16)
        except ValueError:
            return None, 0, line

        return line_offset, self._line_byte_count(line), line

    def _byte_index_in_hex_area(self, pos_in_line: int, byte_count: int):
        for byte_index in range(byte_count):
            start = self._hex_byte_start_column(byte_index)
            if byte_index + 1 < byte_count:
                next_start = self._hex_byte_start_column(byte_index + 1)
            else:
                next_start = self.ASCII_START_COLUMN - self.ASCII_SEPARATOR_WIDTH
            if start <= pos_in_line < next_start:
                return byte_index
        return None

    def _byte_index_at_cursor(self, cursor):
        line_offset, byte_count, _line = self._parse_line_context(cursor)
        if line_offset is None or byte_count <= 0:
            return None

        pos_in_line = cursor.positionInBlock()
        byte_index = self._byte_index_in_hex_area(pos_in_line, byte_count)
        if byte_index is not None:
            return line_offset + byte_index

        ascii_end = self.ASCII_START_COLUMN + byte_count
        if self.ASCII_START_COLUMN <= pos_in_line < ascii_end:
            return line_offset + (pos_in_line - self.ASCII_START_COLUMN)

        return None

    def mouseReleaseEvent(self, event):
        super().mouseReleaseEvent(event)
        try:
            cursor = self.cursorForPosition(event.position().toPoint())
        except AttributeError:
            cursor = self.cursorForPosition(event.pos())
        self._emit_selected_byte(cursor)

    def mouseMoveEvent(self, event):
        """Emit hovered byte offset so CaptureView can resolve full detail range."""
        super().mouseMoveEvent(event)
        try:
            cursor = self.cursorForPosition(event.position().toPoint())
        except AttributeError:
            cursor = self.cursorForPosition(event.pos())
        byte_offset = self._get_byte_at_cursor(cursor)
        if byte_offset is None:
            if self._last_hovered_byte is not None:
                self._last_hovered_byte = None
                self.hover_left.emit()
            return

        if byte_offset != self._last_hovered_byte:
            self._last_hovered_byte = byte_offset
            self.bytes_hovered.emit(byte_offset)

    def leaveEvent(self, event):
        """Clear hover state when mouse leaves widget."""
        super().leaveEvent(event)
        self._last_hovered_byte = None
        self.hover_left.emit()

    def _emit_selected_byte(self, cursor):
        absolute_offset = self._byte_index_at_cursor(cursor)
        if absolute_offset is None:
            return
        self.bytes_selected.emit(absolute_offset)
        self.bytes_range_selected.emit(absolute_offset, 1)

    def highlight_bytes(self, offset: int, length: int):
        self.highlight_matches([(offset, length)])

    def highlight_matches(self, ranges):
        self._selected_ranges = [
            (int(start), int(length))
            for start, length in (ranges or [])
            if int(length) > 0
        ]
        self._render_highlights(focus_selected=True)

    def set_hover_range(self, offset: int, length: int):
        self._hover_highlight_ranges = []
        if length > 0:
            self._hover_highlight_ranges = [(int(offset), int(length))]
        self._render_highlights(focus_selected=False)

    def clear_hover_range(self):
        self._hover_highlight_ranges = []
        self._render_highlights(focus_selected=False)

    def _get_byte_at_cursor(self, cursor):
        """Get byte offset under cursor, or None if not in hex/ascii area"""
        return self._byte_index_at_cursor(cursor)

    def _render_highlights(self, focus_selected: bool):
        if not self.toPlainText():
            return

        cursor = self.textCursor()
        cursor.select(QTextCursor.SelectionType.Document)

        default_format = QTextCharFormat()
        default_format.clearBackground()
        default_format.setFontWeight(QFont.Normal)
        cursor.setCharFormat(default_format)

        selected_format = QTextCharFormat()
        selected_format.setBackground(Qt.GlobalColor.yellow)
        selected_format.setFontWeight(QFont.Bold)
        self._apply_ranges(self._selected_ranges, selected_format)

        hover_format = QTextCharFormat()
        hover_format.setBackground(Qt.GlobalColor.yellow)
        hover_format.setFontWeight(QFont.Normal)
        self._apply_ranges(self._hover_highlight_ranges, hover_format)

        if focus_selected and self._selected_ranges:
            focus_offset = self._selected_ranges[0][0]
            line_index = max(0, int(focus_offset) // 16)
            block = self.document().findBlockByLineNumber(line_index)
            if block.isValid():
                focus_cursor = self.textCursor()
                focus_cursor.setPosition(block.position())
                self.setTextCursor(focus_cursor)
                self.centerCursor()

    def _apply_ranges(self, ranges, text_format):
        valid_ranges = [
            (int(start), int(length))
            for start, length in (ranges or [])
            if int(length) > 0
        ]
        if not valid_ranges:
            return

        cursor = self.textCursor()
        text = self.toPlainText()
        doc_length = len(text)
        lines = text.split('\n')
        start_pos = 0

        for line in lines:
            if not line:
                start_pos += 1
                continue

            try:
                line_offset = int(line[:self.OFFSET_WIDTH], 16)
            except ValueError:
                start_pos += len(line) + 1
                continue

            byte_count = self._line_byte_count(line)
            if byte_count <= 0:
                start_pos += len(line) + 1
                continue

            hex_start = start_pos + self.HEX_START_COLUMN

            def byte_pos(byte_index: int) -> int:
                pos = hex_start + byte_index * self.HEX_BYTE_WIDTH
                if byte_index >= self.HEX_GROUP_BREAK_INDEX:
                    pos += 1
                return pos

            def clamp_selection(start: int, end: int):
                if doc_length <= 0:
                    return None
                start = max(0, min(start, doc_length - 1))
                end = max(start, min(end, doc_length))
                if end <= start:
                    return None
                return start, end

            for offset, length in valid_ranges:
                if offset >= line_offset + byte_count or offset + length <= line_offset:
                    continue

                line_start_byte = max(0, offset - line_offset)
                line_end_byte = min(byte_count, offset + length - line_offset)
                if line_start_byte >= line_end_byte:
                    continue

                hex_byte_start = byte_pos(line_start_byte)
                hex_byte_end = byte_pos(line_end_byte) - 1
                if line_end_byte == self.HEX_GROUP_BREAK_INDEX:
                    hex_byte_end -= 1

                hex_bounds = clamp_selection(hex_byte_start, hex_byte_end)
                if hex_bounds is not None:
                    cursor.setPosition(hex_bounds[0])
                    cursor.setPosition(hex_bounds[1], QTextCursor.MoveMode.KeepAnchor)
                    cursor.setCharFormat(text_format)

                ascii_start = start_pos + self.ASCII_START_COLUMN
                ascii_byte_start = ascii_start + line_start_byte
                ascii_byte_end = ascii_start + line_end_byte
                ascii_bounds = clamp_selection(ascii_byte_start, ascii_byte_end)
                if ascii_bounds is not None:
                    cursor.setPosition(ascii_bounds[0])
                    cursor.setPosition(ascii_bounds[1], QTextCursor.MoveMode.KeepAnchor)
                    cursor.setCharFormat(text_format)

            start_pos += len(line) + 1


class PacketBytesView(QWidget):
    bytes_range_selected = Signal(int, int, str)
    bytes_hovered = Signal(int, str)
    hover_left = Signal(str)
    context_menu_requested = Signal(str, object)

    def __init__(self):
        super().__init__()
        self._views = {
            'packet': PacketHexView(),
            'tcp_reassembled': PacketHexView(),
            'quic_decrypted': PacketHexView(),
            'h264_reassembled': PacketHexView(),
            'rdpudp_unwrapped': PacketHexView(),
            'rdpudp_tls_fragment': PacketHexView(),
            'radius_eap_reassembled': PacketHexView(),
            'radius_eap_tls_reassembled': PacketHexView(),
            'http_dechunked': PacketHexView(),
            'zabbix_uncompressed': PacketHexView(),
        }
        self._tab_sources = []
        self._stack = QStackedWidget(self)
        self._stack.setContentsMargins(0, 0, 0, 0)
        self._tab_bar = QTabBar(self)
        self._tab_bar.setObjectName("PacketBytesTabBar")
        self._tab_bar.setShape(QTabBar.Shape.RoundedSouth)
        self._tab_bar.setDrawBase(False)
        self._tab_bar.setUsesScrollButtons(True)
        self._tab_bar.setElideMode(Qt.TextElideMode.ElideRight)
        self._tab_bar.currentChanged.connect(self._on_tab_changed)

        for source, view in self._views.items():
            self._stack.addWidget(view)
            view.bytes_range_selected.connect(
                lambda offset, length, key=source: self.bytes_range_selected.emit(offset, length, key)
            )
            view.bytes_hovered.connect(
                lambda offset, key=source: self.bytes_hovered.emit(offset, key)
            )
            view.hover_left.connect(
                lambda key=source: self.hover_left.emit(key)
            )
            view.context_menu_requested.connect(
                lambda global_pos, key=source: self.context_menu_requested.emit(key, global_pos)
            )

        self.show_packet(None)

    def font(self):
        return self._views['packet'].font()

    def setFont(self, font):
        super().setFont(font)
        self._stack.setFont(font)
        self._tab_bar.setFont(font)
        for view in self._views.values():
            view.setFont(font)

    def _reset_tabs(self, sources):
        while self._tab_bar.count() > 0:
            self._tab_bar.removeTab(0)
        self._tab_sources = []
        for source, title, data in sources:
            view = self._views[source]
            view.show_bytes(data)
            self._tab_bar.addTab(title)
            self._tab_sources.append(source)
        self._tab_bar.setVisible(bool(self._tab_sources))
        self._layout_children()

    def show_packet(self, record):
        metadata = getattr(record, 'metadata', {}) if record else {}
        protocol_name = str(getattr(record, 'protocol', '') or '')
        packet_data = _record_packet_bytes(record)
        sources = [
            ('packet', f'Packet ({len(packet_data)} bytes)', packet_data),
        ]
        tls_family = {'SSL', 'TLS', 'TLSv1.0', 'TLSv1.1', 'TLSv1.2', 'TLSv1.3'}

        reassembled_data = b''
        reassembled_hex = str(metadata.get('tcp_reassembled_data_hex', '') or '')
        if reassembled_hex:
            try:
                reassembled_data = bytes.fromhex(reassembled_hex)
            except ValueError:
                reassembled_data = b''
        if not reassembled_data:
            _tls_payload = bytes(metadata.get('tls_reassembled_payload', b'') or b'')
            _tls_pdu_len = int(metadata.get('tls_reassembled_length', 0) or 0)
            # Truncate to the reassembled PDU length (e.g. Certificate record only, not SKE/SHD)
            if _tls_pdu_len and _tls_pdu_len < len(_tls_payload):
                reassembled_data = _tls_payload[:_tls_pdu_len]
            else:
                reassembled_data = _tls_payload
        if reassembled_data and protocol_name not in tls_family:
            sources.append(
                ('tcp_reassembled', f'Reassembled ({len(reassembled_data)} bytes)', reassembled_data)
            )

        quic_decrypted = bytes(metadata.get('quic_decrypted_payload', b'') or b'')
        if quic_decrypted:
            sources.append(
                ('quic_decrypted', f'Decrypted QUIC ({len(quic_decrypted)} bytes)', quic_decrypted)
            )

        h264_reassembled_hex = str(metadata.get('h264_ts_reassembled_pes_hex', '') or '')
        if h264_reassembled_hex:
            try:
                h264_reassembled = bytes.fromhex(h264_reassembled_hex)
            except ValueError:
                h264_reassembled = b''
            if h264_reassembled:
                sources.append(
                    ('h264_reassembled', f'Reassembled H.264 PES ({len(h264_reassembled)} bytes)', h264_reassembled)
                )

        rdpudp_unwrapped = bytes(metadata.get('rdpudp_unwrapped_payload', b'') or b'')
        if rdpudp_unwrapped:
            sources.append(
                ('rdpudp_unwrapped', f'Unwrapped RDPUDP2 packet ({len(rdpudp_unwrapped)} bytes)', rdpudp_unwrapped)
            )

        rdpudp_tls_fragment = bytes(metadata.get('rdpudp_tls_fragment_payload', b'') or b'')
        if rdpudp_tls_fragment:
            sources.append(
                ('rdpudp_tls_fragment', f'SSL fragment ({len(rdpudp_tls_fragment)} bytes)', rdpudp_tls_fragment)
            )

        eap_reassembled_hex = str(metadata.get('radius_eap_reassembled_hex', '') or '')
        if eap_reassembled_hex:
            try:
                eap_reassembled = bytes.fromhex(eap_reassembled_hex)
            except ValueError:
                eap_reassembled = b''
            if eap_reassembled:
                sources.append(
                    ('radius_eap_reassembled', f'Reassembled EAP ({len(eap_reassembled)} bytes)', eap_reassembled)
                )

        eap_tls_reassembled_hex = str(metadata.get('radius_eap_tls_reassembled_hex', '') or '')
        if eap_tls_reassembled_hex:
            try:
                eap_tls_reassembled = bytes.fromhex(eap_tls_reassembled_hex)
            except ValueError:
                eap_tls_reassembled = b''
            if eap_tls_reassembled:
                sources.append(
                    ('radius_eap_tls_reassembled', f'Reassembled EAP-TLS ({len(eap_tls_reassembled)} bytes)', eap_tls_reassembled)
                )

        dechunked_body = bytes(metadata.get('http_dechunked_body', b'') or b'')
        if dechunked_body:
            sources.append(
                ('http_dechunked', f'De-chunked entity body ({len(dechunked_body)} bytes)', dechunked_body)
            )

        zabbix_uncompressed = bytes(metadata.get('zabbix_uncompressed_body', b'') or b'')
        zabbix_body = bytes(metadata.get('zabbix_body', b'') or b'')
        if protocol_name == 'Zabbix' and zabbix_uncompressed and zabbix_uncompressed != zabbix_body:
            sources.append(
                ('zabbix_uncompressed', f'Uncompressed entity body ({len(zabbix_uncompressed)} bytes)', zabbix_uncompressed)
            )

        self._reset_tabs(sources)
        if self._tab_bar.count() > 0:
            self._tab_bar.setCurrentIndex(0)
            self._on_tab_changed(0)

    def _active_source(self, requested_source: str | None = None) -> str:
        if requested_source in self._tab_sources:
            index = self._tab_sources.index(requested_source)
            self._tab_bar.setCurrentIndex(index)
            return requested_source
        current_index = self._tab_bar.currentIndex()
        if 0 <= current_index < len(self._tab_sources):
            return self._tab_sources[current_index]
        return 'packet'

    def _on_tab_changed(self, index: int):
        if 0 <= index < len(self._tab_sources):
            source = self._tab_sources[index]
            view = self._views.get(source)
            if view is not None:
                self._stack.setCurrentWidget(view)

    def _layout_children(self):
        bounds = self.rect()
        self._stack.setGeometry(bounds)
        if self._tab_bar.count() > 0 and not self._tab_bar.isHidden():
            host = self.window()
            if isinstance(host, QWidget):
                statusbar = host.statusBar() if hasattr(host, "statusBar") and callable(getattr(host, "statusBar")) else None
                statusbar = statusbar if isinstance(statusbar, QStatusBar) else None
                bar_height = max(19, self._tab_bar.sizeHint().height())
                bar_width = min(max(110, self._tab_bar.sizeHint().width() + 6), max(0, self.width() - 12))
                if statusbar is not None:
                    if self._tab_bar.parentWidget() is not host:
                        self._tab_bar.setParent(host)
                        self._tab_bar.show()
                    local_x = self.mapTo(host, QPoint(6, 0)).x()
                    top_y = self.mapTo(host, QPoint(0, self.height())).y()
                    status_rect = statusbar.geometry()
                    top_y = max(status_rect.top() - 3, top_y - 2)
                    self._tab_bar.setGeometry(local_x, max(0, top_y), bar_width, bar_height)
                    self._tab_bar.raise_()
                else:
                    if self._tab_bar.parentWidget() is not self:
                        self._tab_bar.setParent(self)
                        self._tab_bar.show()
                    self._tab_bar.setGeometry(6, max(0, bounds.height() - bar_height + 1), bar_width, bar_height)
                    self._tab_bar.raise_()
            else:
                bar_height = max(19, self._tab_bar.sizeHint().height())
                bar_width = min(max(110, self._tab_bar.sizeHint().width() + 6), max(0, bounds.width() - 12))
                self._tab_bar.setParent(self)
                self._tab_bar.setGeometry(6, max(0, bounds.height() - bar_height + 1), bar_width, bar_height)
                self._tab_bar.raise_()
        for source in self._tab_sources:
            view = self._views.get(source)
            if view is not None:
                view.setViewportMargins(0, 0, 0, 0)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._layout_children()

    def showEvent(self, event):
        super().showEvent(event)
        self._layout_children()

    def hideEvent(self, event):
        super().hideEvent(event)
        self._tab_bar.hide()

    def highlight_bytes(self, offset: int, length: int, byte_source: str = 'packet'):
        if offset < 0 or length <= 0:
            for source in self._tab_sources:
                self._views[source].highlight_matches([])
            return

        active_source = self._active_source(byte_source)
        for source in self._tab_sources:
            if source == active_source:
                self._views[source].highlight_bytes(offset, length)
            else:
                self._views[source].highlight_matches([])

    def set_hover_range(self, offset: int, length: int, byte_source: str = 'packet'):
        active_source = self._active_source(byte_source)
        for source in self._tab_sources:
            if source == active_source:
                self._views[source].set_hover_range(offset, length)
            else:
                self._views[source].clear_hover_range()

    def clear_hover_range(self, byte_source: str | None = None):
        if byte_source in self._tab_sources:
            self._views[str(byte_source)].clear_hover_range()
            return
        for source in self._tab_sources:
            self._views[source].clear_hover_range()

    def copy_selected_bytes_to_clipboard(self) -> bool:
        if not self._tab_sources:
            return False
        source = self._active_source()
        view = self._views.get(source)
        if view is None:
            return False

        payload = view.selected_raw_bytes()
        if payload:
            text = ' '.join(f'{byte:02X}' for byte in payload)
            QApplication.clipboard().setText(text)
            return True

        cursor_text = str(view.textCursor().selectedText() or '').strip()
        if cursor_text:
            QApplication.clipboard().setText(cursor_text)
            return True
        return False

    def copy_visible_bytes_to_clipboard(self, byte_source: str | None = None) -> bool:
        if not self._tab_sources:
            return False
        source = self._active_source(byte_source)
        view = self._views.get(source)
        if view is None:
            return False
        text = str(view.toPlainText() or '').strip()
        if not text:
            return False
        QApplication.clipboard().setText(text)
        return True
