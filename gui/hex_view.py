from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont, QTextCursor, QTextCharFormat, QColor
from PySide6.QtWidgets import QPlainTextEdit

from core.formatters import hex_dump


class PacketHexView(QPlainTextEdit):
    bytes_selected = Signal(int)
    bytes_range_selected = Signal(int, int)  # (offset, length)
    bytes_hovered = Signal(int)  # byte offset under mouse
    hover_left = Signal()

    def __init__(self):
        super().__init__()
        self.setReadOnly(True)
        font = QFont('Consolas')
        font.setStyleHint(QFont.Monospace)
        self.setFont(font)
        self.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.setMouseTracking(True)  # Enable mouseMoveEvent when not dragging
        self._selected_ranges = []
        self._hover_highlight_ranges = []
        self._last_hovered_byte = None
        

    def show_packet(self, record):
        self._selected_ranges = []
        self._hover_highlight_ranges = []
        self._last_hovered_byte = None
        self.setPlainText(hex_dump(record.raw) if record else '')

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
        line = cursor.block().text()
        if not line or len(line) < 5:
            return
        try:
            line_offset = int(line[:4], 16)
        except ValueError:
            return
        pos_in_line = cursor.positionInBlock()
        hex_start = 5
        hex_end = line.rfind('  ')
        if hex_end <= hex_start:
            hex_end = len(line)
        if pos_in_line >= hex_start and pos_in_line < hex_end:
            byte_index = min(15, max(0, (pos_in_line - hex_start) // 3))
            absolute_offset = line_offset + byte_index
            self.bytes_selected.emit(absolute_offset)
            self.bytes_range_selected.emit(absolute_offset, 1)
            return
        ascii_start = hex_end + 2
        if pos_in_line >= ascii_start:
            byte_index = min(15, max(0, pos_in_line - ascii_start))
            absolute_offset = line_offset + byte_index
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
        line = cursor.block().text()
        if not line or len(line) < 5:
            return None
        
        try:
            line_offset = int(line[:4], 16)
        except ValueError:
            return None
        
        pos_in_line = cursor.positionInBlock()
        hex_start = 5
        hex_end = line.rfind('  ')
        if hex_end <= hex_start:
            hex_end = len(line)
        
        if pos_in_line >= hex_start and pos_in_line < hex_end:
            byte_index = min(15, max(0, (pos_in_line - hex_start) // 3))
            return line_offset + byte_index
        
        ascii_start = hex_end + 2
        if pos_in_line >= ascii_start:
            byte_index = min(15, max(0, pos_in_line - ascii_start))
            return line_offset + byte_index
        
        return None

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
                line_offset = int(line[:4], 16)
            except ValueError:
                start_pos += len(line) + 1
                continue

            hex_start = start_pos + 6

            def byte_pos(byte_index: int) -> int:
                pos = hex_start + byte_index * 3
                if byte_index >= 8:
                    pos += 1
                return pos

            for offset, length in valid_ranges:
                if offset >= line_offset + 16 or offset + length <= line_offset:
                    continue

                line_start_byte = max(0, offset - line_offset)
                line_end_byte = min(16, offset + length - line_offset)

                hex_byte_start = byte_pos(line_start_byte)
                hex_byte_end = byte_pos(line_end_byte) - 1
                if line_end_byte == 8:
                    hex_byte_end -= 1

                hex_byte_start = max(0, min(hex_byte_start, doc_length - 1))
                hex_byte_end = max(hex_byte_start, min(hex_byte_end, doc_length - 1))

                cursor.setPosition(hex_byte_start)
                cursor.setPosition(hex_byte_end, QTextCursor.MoveMode.KeepAnchor)
                cursor.setCharFormat(text_format)

                ascii_start = hex_start + 48 + 2
                ascii_byte_start = ascii_start + line_start_byte
                ascii_byte_end = ascii_start + line_end_byte
                ascii_byte_start = max(0, min(ascii_byte_start, doc_length - 1))
                ascii_byte_end = max(ascii_byte_start, min(ascii_byte_end, doc_length - 1))

                cursor.setPosition(ascii_byte_start)
                cursor.setPosition(ascii_byte_end, QTextCursor.MoveMode.KeepAnchor)
                cursor.setCharFormat(text_format)

            start_pos += len(line) + 1
