from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont, QTextCursor, QTextCharFormat
from PySide6.QtWidgets import QPlainTextEdit

from core.formatters import hex_dump


class PacketHexView(QPlainTextEdit):
    bytes_selected = Signal(int)

    def __init__(self):
        super().__init__()
        self.setReadOnly(True)
        font = QFont('Consolas')
        font.setStyleHint(QFont.Monospace)
        self.setFont(font)
        self.setLineWrapMode(QPlainTextEdit.NoWrap)
        

    def show_packet(self, record):
        self.setPlainText(hex_dump(record.raw) if record else '')

    def mouseReleaseEvent(self, event):
        super().mouseReleaseEvent(event)
        try:
            cursor = self.cursorForPosition(event.position().toPoint())
        except AttributeError:
            cursor = self.cursorForPosition(event.pos())
        self._emit_selected_byte(cursor)

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
            self.bytes_selected.emit(line_offset + byte_index)
            return
        ascii_start = hex_end + 2
        if pos_in_line >= ascii_start:
            byte_index = min(15, max(0, pos_in_line - ascii_start))
            self.bytes_selected.emit(line_offset + byte_index)

    def highlight_bytes(self, offset: int, length: int):
        self.highlight_matches([(offset, length)])

    def highlight_matches(self, ranges):
        if not self.toPlainText():
            return

        cursor = self.textCursor()

        cursor.select(QTextCursor.SelectionType.Document)

        default_format = QTextCharFormat()
        default_format.clearBackground()
        default_format.setFontWeight(QFont.Normal)

        cursor.setCharFormat(default_format)

        valid_ranges = [
            (int(start), int(length))
            for start, length in (ranges or [])
            if int(length) > 0
        ]
        if not valid_ranges:
            return

        lines = self.toPlainText().split('\n')

        start_pos = 0

        focus_offset = valid_ranges[0][0]

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
                # Convert byte index -> text position considering extra space after byte 8.
                pos = hex_start + byte_index * 3
                if byte_index >= 8:
                    pos += 1
                return pos

            highlight_format = QTextCharFormat()
            highlight_format.setBackground(Qt.GlobalColor.yellow)
            highlight_format.setFontWeight(QFont.Bold)

            for offset, length in valid_ranges:
                if offset >= line_offset + 16 or offset + length <= line_offset:
                    continue

                line_start_byte = max(0, offset - line_offset)
                line_end_byte = min(16, offset + length - line_offset)

                hex_byte_start = byte_pos(line_start_byte)
                hex_byte_end = byte_pos(line_end_byte) - 1

                cursor.setPosition(hex_byte_start)
                cursor.setPosition(
                    hex_byte_end,
                    QTextCursor.MoveMode.KeepAnchor
                )
                cursor.setCharFormat(highlight_format)

                ascii_start = hex_start + 48 + 2
                ascii_byte_start = ascii_start + line_start_byte
                ascii_byte_end = ascii_start + line_end_byte

                cursor.setPosition(ascii_byte_start)
                cursor.setPosition(
                    ascii_byte_end,
                    QTextCursor.MoveMode.KeepAnchor
                )

                cursor.setCharFormat(highlight_format)

            start_pos += len(line) + 1

        # Scroll to the first highlighted byte.
        line_index = max(0, int(focus_offset) // 16)
        block = self.document().findBlockByLineNumber(line_index)
        if block.isValid():
            cursor = self.textCursor()
            cursor.setPosition(block.position())
            self.setTextCursor(cursor)
            self.centerCursor()
