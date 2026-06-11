from __future__ import annotations

from PySide6.QtCore import Qt, QMimeData, Signal
from PySide6.QtGui import QDrag
from PySide6.QtWidgets import QLineEdit


PACKET_FILTER_MIME = 'application/x-packetra-filter-expression'


def _quote_filter_value(value) -> str:
    text = str(value or '')
    text = text.replace('\\', '\\\\').replace('"', '\\"')
    return f'"{text}"'


def packet_filter_expression(record, column: int) -> str:
    if record is None:
        return ''
    try:
        col = int(column)
    except Exception:
        return ''
    if col == 2:
        value = str(getattr(record, 'src', '') or '').strip()
        return f'src == {_quote_filter_value(value)}' if value else ''
    if col == 3:
        value = str(getattr(record, 'dst', '') or '').strip()
        return f'dst == {_quote_filter_value(value)}' if value else ''
    if col == 4:
        value = str(getattr(record, 'protocol', '') or '').strip()
        return f'protocol == {_quote_filter_value(value)}' if value else ''
    if col == 5:
        try:
            return f'frame.len == {int(getattr(record, "length", 0) or 0)}'
        except Exception:
            return ''
    return ''


def build_filter_drag(expression: str, source) -> QDrag | None:
    expr = str(expression or '').strip()
    if not expr:
        return None
    mime = QMimeData()
    mime.setData(PACKET_FILTER_MIME, expr.encode('utf-8'))
    mime.setText(expr)
    drag = QDrag(source)
    drag.setMimeData(mime)
    return drag


class PacketFilterLineEdit(QLineEdit):
    filterExpressionDropped = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)

    def dragEnterEvent(self, event):
        mime = event.mimeData()
        if mime is not None and (mime.hasFormat(PACKET_FILTER_MIME) or mime.hasText()):
            event.acceptProposedAction()
            return
        super().dragEnterEvent(event)

    def dragMoveEvent(self, event):
        mime = event.mimeData()
        if mime is not None and (mime.hasFormat(PACKET_FILTER_MIME) or mime.hasText()):
            event.acceptProposedAction()
            return
        super().dragMoveEvent(event)

    def dropEvent(self, event):
        mime = event.mimeData()
        expr = ''
        if mime is not None:
            if mime.hasFormat(PACKET_FILTER_MIME):
                try:
                    expr = bytes(mime.data(PACKET_FILTER_MIME)).decode('utf-8', errors='ignore').strip()
                except Exception:
                    expr = ''
            if not expr and mime.hasText():
                expr = str(mime.text() or '').strip()
        if expr:
            self.setText(expr)
            self.setFocus(Qt.MouseFocusReason)
            self.selectAll()
            self.filterExpressionDropped.emit(expr)
            event.acceptProposedAction()
            return
        super().dropEvent(event)
