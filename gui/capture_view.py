import logging
import re
import os
import json
import hashlib
import time
import itertools
import threading
import queue
from datetime import datetime
from pathlib import Path
from collections import Counter, deque
from scapy.all import TCP, ICMP, IP
from PySide6.QtCore import Qt, Signal, QSettings, QDateTime, QTimer, QStringListModel, QEvent
from PySide6.QtWidgets import (
    QApplication, QFileDialog, QDialog, QHBoxLayout, QLabel, QLineEdit, QMessageBox,
    QPushButton, QSplitter, QTextEdit, QVBoxLayout, QWidget, QComboBox, QCheckBox,
    QMenu, QStyle, QTableWidget, QTableWidgetItem, QHeaderView, QSizePolicy, QStackedWidget, QCompleter,
    QToolButton
)
from PySide6.QtGui import QAction, QPainter, QColor, QPen, QPixmap

from core.capture import PacketSniffer
from core.filtering import DisplayFilter
from core.formatters import packet_summary_tree
from core.models import PacketRecord
from core.parser import PacketParser
from gui.hex_view import PacketBytesView
from gui.packet_details import PacketDetailsTree
from gui.packet_table import PacketTable
from utils.pcap_io import (
    load_capture_metadata,
    iter_pcap_packets,
    normalize_capture_extension,
    save_capture_file,
    save_pcapng_file_comment,
    save_pcapng_packet_comments,
)

log = logging.getLogger('capture_view')


class _ProtocolSparkline(QLabel):
    """Sparkline label for one protocol â€” identical style to interface traffic chart."""
    HISTORY_LEN = 30

    def __init__(self, parent=None):
        super().__init__(parent)
        self._history = [0.0] * self.HISTORY_LEN
        self.setFixedHeight(24)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

    def push(self, value: float):
        self._history.append(value)
        if len(self._history) > self.HISTORY_LEN:
            self._history.pop(0)
        self._redraw()

    def _redraw(self):
        w = max(60, self.width())
        h = self.height()
        pix = QPixmap(w, h)
        pix.fill(Qt.GlobalColor.transparent)
        painter = QPainter(pix)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)

        painter.setPen(QPen(QColor('#D9DEE6'), 1))
        painter.drawLine(0, h - 2, w, h - 2)

        values = self._history
        if values and max(values) > 0:
            max_val = max(values)
            pen = QPen(QColor('#2C7FB8'), 2)
            painter.setPen(pen)
            x_step = max(1.0, (w - 4) / max(1, len(values) - 1))
            pts = []
            for i, v in enumerate(values):
                x = int(2 + i * x_step)
                y = int((h - 4) - (v / max_val) * (h - 8))
                pts.append((x, y))
            for i in range(1, len(pts)):
                painter.drawLine(pts[i-1][0], pts[i-1][1], pts[i][0], pts[i][1])

        painter.end()
        self.setPixmap(pix)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._redraw()


def _sparkline_pixmap(values, width=280, height=24):
    """Standalone sparkline pixmap â€” same style as interface traffic chart."""
    pix = QPixmap(width, height)
    pix.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pix)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)

    painter.setPen(QPen(QColor('#D9DEE6'), 1))
    painter.drawLine(0, height - 2, width, height - 2)

    if values and max(values) > 0:
        max_value = max(values)
        pen = QPen(QColor('#2C7FB8'), 2)
        painter.setPen(pen)
        x_step = max(1.0, (width - 4) / max(1, len(values) - 1))
        points = []
        for i, v in enumerate(values):
            x = int(2 + i * x_step)
            y = int((height - 4) - (v / max_value) * (height - 8))
            points.append((x, y))
        for i in range(1, len(points)):
            painter.drawLine(points[i-1][0], points[i-1][1], points[i][0], points[i][1])

    painter.end()
    return pix


class _PacketListMinimap(QWidget):
    """Compact color minimap synced with packet list rows."""

    def __init__(self, capture_view, table: PacketTable, parent=None):
        super().__init__(parent)
        self._capture_view = capture_view
        self._table = table
        self.setMinimumWidth(42)
        self.setMaximumWidth(42)
        self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Expanding)
        self.setToolTip('Packet list minimap')
        self._cache_pixmap = None
        self._cache_key = None

    def _row_color(self, row: int) -> QColor:
        item = self._table.item(row, 0)
        if item is None:
            return QColor('#FFFFFF')
        try:
            role_marked = int(getattr(self._table, 'MARKED_ROLE', int(Qt.UserRole) + 100))
            role_ignored = int(getattr(self._table, 'IGNORED_ROLE', int(Qt.UserRole) + 101))
            if bool(item.data(role_marked)):
                color = QColor(getattr(self._table, '_marked_color', QColor('#FFF3B0')))
                if color.isValid():
                    return color
            if bool(item.data(role_ignored)):
                color = QColor(getattr(self._table, '_ignored_color', QColor('#E0E0E0')))
                if color.isValid():
                    return color
        except Exception:
            pass
        color = item.background().color()
        return color if color.isValid() else QColor('#FFFFFF')

    def _bucket_color(self, start: int, end: int) -> QColor:
        if start < 0:
            start = 0
        if end <= start:
            end = start + 1
        rows = self._table.rowCount()
        if rows <= 0:
            return QColor('#FFFFFF')
        end = min(rows, end)
        if start >= rows:
            return QColor('#FFFFFF')
        span = max(0, int(end - start))
        if span <= 1:
            return self._row_color(start)
        if span <= 8:
            sample_rows = list(range(start, end))
        else:
            # Sampling keeps minimap fast even while table data is changing heavily.
            sample_rows = []
            steps = 6
            for i in range(steps):
                row = int(start + ((span - 1) * i) / max(1, steps - 1))
                if not sample_rows or row != sample_rows[-1]:
                    sample_rows.append(row)
        counts = {}
        top_color = QColor('#FFFFFF')
        top_count = 0
        for row in sample_rows:
            color = self._row_color(row)
            key = color.name().lower()
            count = int(counts.get(key, 0)) + 1
            counts[key] = count
            if count > top_count:
                top_count = count
                top_color = color
        return top_color if top_color.isValid() else QColor('#FFFFFF')

    def invalidate_cache(self):
        self._cache_pixmap = None
        self._cache_key = None

    def _rebuild_cache(self, w: int, h: int, window_start: int, window_end: int, rows: int):
        window_rows = max(0, int(window_end - window_start))
        if window_rows <= 0 or w <= 0 or h <= 0:
            self._cache_pixmap = None
            self._cache_key = None
            return
        pix = QPixmap(w, h)
        pix.fill(QColor('#F4F6F8'))
        painter = QPainter(pix)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, False)
        for y in range(h):
            local_start = int((y * window_rows) / h)
            local_end = int(((y + 1) * window_rows) / h)
            start = int(window_start + local_start)
            end = int(window_start + local_end)
            if end <= start:
                end = start + 1
            end = min(window_end, end)
            color = self._bucket_color(start, end)
            painter.setPen(QPen(color, 1))
            painter.drawLine(0, y, w - 1, y)
        painter.setPen(QPen(QColor('#9AA4B2'), 1))
        painter.drawRect(0, 0, w - 1, h - 1)
        painter.end()
        self._cache_pixmap = pix
        self._cache_key = (int(w), int(h), int(window_start), int(window_end))

    def _active_packet_window(self) -> tuple[int, int, int]:
        rows = int(self._table.rowCount() or 0)
        if rows <= 0:
            return 0, 0, 0
        max_window = 500
        if rows <= max_window:
            return 0, max_window, rows
        anchor = int(self._table.currentRow())
        if anchor < 0 or anchor >= rows:
            anchor = int(self._table.rowAt(0))
        if anchor < 0 or anchor >= rows:
            anchor = 0
        half = max_window // 2
        start = anchor - half
        start = max(0, min(start, rows - max_window))
        end = min(rows, start + max_window)
        return start, end, rows

    def paintEvent(self, event):
        super().paintEvent(event)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, False)
        w = max(1, self.width())
        h = max(1, self.height())
        window_start, window_end, rows = self._active_packet_window()
        fast_mode = bool(getattr(self._capture_view, '_startup_priority_mode', False))
        if rows <= 0:
            painter.fillRect(0, 0, w, h, QColor('#F4F6F8'))
            painter.setPen(QPen(QColor('#9AA4B2'), 1))
            painter.drawRect(0, 0, w - 1, h - 1)
            return
        window_rows = max(0, int(window_end - window_start))
        if window_rows <= 0:
            painter.fillRect(0, 0, w, h, QColor('#F4F6F8'))
            painter.setPen(QPen(QColor('#9AA4B2'), 1))
            painter.drawRect(0, 0, w - 1, h - 1)
            return
        key = (int(w), int(h), int(window_start), int(window_end))
        if self._cache_pixmap is None or self._cache_key != key:
            if not fast_mode:
                self._rebuild_cache(w, h, window_start, window_end, rows)
        if self._cache_pixmap is not None:
            painter.drawPixmap(0, 0, self._cache_pixmap)
        else:
            painter.fillRect(0, 0, w, h, QColor('#F4F6F8'))
            painter.setPen(QPen(QColor('#9AA4B2'), 1))
            painter.drawRect(0, 0, w - 1, h - 1)

        top = int(self._table.rowAt(0))
        bottom = int(self._table.rowAt(max(0, self._table.viewport().height() - 1)))
        if top < 0:
            top = 0
        if bottom < 0:
            bottom = min(rows - 1, top + 1)
        clip_top = max(top, window_start)
        clip_bottom = min(bottom, window_end - 1)
        if clip_bottom < clip_top:
            if top < window_start:
                clip_top = window_start
                clip_bottom = window_start
            else:
                clip_top = max(window_start, window_end - 1)
                clip_bottom = clip_top
        view_top = int(((clip_top - window_start) * h) / max(1, window_rows))
        view_bottom = int((((clip_bottom - window_start) + 1) * h) / max(1, window_rows))
        view_bottom = max(view_top + 1, min(h - 1, view_bottom))
        painter.setPen(QPen(QColor('#111111'), 1))
        painter.drawRect(0, view_top, w - 1, max(1, view_bottom - view_top))

        selected_row = int(self._table.currentRow())
        if window_start <= selected_row < window_end:
            sy = int(((selected_row - window_start) * h) / max(1, window_rows))
            painter.setPen(QPen(QColor('#FF6B00'), 1))
            painter.drawLine(0, sy, w - 1, sy)

    def mousePressEvent(self, event):
        window_start, window_end, rows = self._active_packet_window()
        if rows <= 0:
            return super().mousePressEvent(event)
        window_rows = max(0, int(window_end - window_start))
        if window_rows <= 0:
            return super().mousePressEvent(event)
        y = float(event.position().y()) if hasattr(event, 'position') else float(event.y())
        ratio = max(0.0, min(1.0, y / max(1.0, float(self.height() - 1))))
        local_target = int(round(ratio * max(0, window_rows - 1)))
        target = int(window_start + local_target)
        target = max(0, min(rows - 1, target))
        if event.button() == Qt.MouseButton.LeftButton:
            try:
                self._capture_view.goto_row(target)
            except Exception:
                item = self._table.item(target, 0)
                if item is not None:
                    self._table.scrollToItem(item, self._table.ScrollHint.PositionAtCenter)
        else:
            item = self._table.item(target, 0)
            if item is not None:
                self._table.scrollToItem(item, self._table.ScrollHint.PositionAtCenter)
        self.update()
        super().mousePressEvent(event)


class CaptureInformationDialog(QDialog):
    """Live capture statistics â€” sparkline per protocol, same style as Interface traffic chart."""

    stop_requested = Signal()

    def __init__(self, parent=None):
        super().__init__(parent, Qt.WindowType.Window)
        self.setWindowTitle('Capture Information')
        self.setMinimumWidth(460)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose, False)
        self._row_map = {}       # protocol -> row index
        self._sparkline_map = {} # protocol -> _ProtocolSparkline
        self._counts = {}        # protocol -> cumulative count
        self._prev_counts = {}   # protocol -> count at last tick

        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)

        self.table = QTableWidget(0, 2, self)
        self.table.horizontalHeader().setVisible(False)
        self.table.verticalHeader().setVisible(False)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.setSelectionMode(QTableWidget.SelectionMode.NoSelection)
        self.table.verticalHeader().setDefaultSectionSize(28)
        layout.addWidget(self.table)

        stop_btn = QPushButton('Stop Capture')
        stop_btn.clicked.connect(self.stop_requested.emit)
        layout.addWidget(stop_btn)

        # Tick every 1 s â€” push delta counts into each sparkline
        self._timer = QTimer(self)
        self._timer.setInterval(1000)
        self._timer.timeout.connect(self._tick)

    def update_protocol(self, protocol: str, count: int):
        self._counts[protocol] = count
        if protocol not in self._row_map:
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem(protocol))
            spark = _ProtocolSparkline()
            self.table.setCellWidget(row, 1, spark)
            self._row_map[protocol] = row
            self._sparkline_map[protocol] = spark
            self._prev_counts[protocol] = 0

    def _tick(self):
        """Push per-second deltas into sparklines."""
        for proto, spark in self._sparkline_map.items():
            current = self._counts.get(proto, 0)
            prev = self._prev_counts.get(proto, 0)
            spark.push(float(current - prev))
            self._prev_counts[proto] = current

    def reset(self):
        self._timer.stop()
        self.table.setRowCount(0)
        self._row_map.clear()
        self._sparkline_map.clear()
        self._counts.clear()
        self._prev_counts.clear()

    def show(self):
        super().show()
        self._timer.start()

    def hide(self):
        self._timer.stop()
        super().hide()



class CaptureView(QWidget):
    status_changed = Signal(str)
    capture_state_changed = Signal(bool)
    find_panel_visibility_changed = Signal(bool)
    detail_status_changed = Signal(str, int)
    display_filter_applied = Signal()
    records_refined = Signal(object)
    open_packet_window_requested = Signal()
    go_state_changed = Signal(dict)

    def __init__(self, iface: str = '', iface_display_name: str = '', capture_filter: str = ''):
        super().__init__()
        self.iface = iface
        self.iface_display_name = iface_display_name
        self.capture_filter = capture_filter
        self.output_settings = {}  # Output tab settings from Capture Options dialog
        self.options_settings = {}  # Options tab settings from Capture Options dialog

        self.parser = PacketParser()
        self._configure_parser_capture_context(self.parser, '')
        self.display_filter = DisplayFilter()
        self.records = []
        self.visible_indices = []
        self.sniffer = None
        self.loaded_file_path = None
        self.auto_scroll_enabled = True
        self.realtime_update_enabled = True
        self.color_rules_enabled = True
        self._is_stopping = False
        self._last_live_status_count = 0
        self._capture_started_at = None
        self._capture_info_dialog = None
        self._protocol_counts = {}
        self._captured_bytes = 0
        self.interface_config = {}
        self.default_main_splitter_sizes = [500, 360]
        self.default_lower_splitter_sizes = [980, 650]
        self._current_pane_layout = 'Layout 2'
        self._pane_assignments = ('packet_list', 'packet_details', 'packet_bytes')
        self._pane_component_visibility = {
            'packet_list': True,
            'packet_details': True,
            'packet_bytes': True,
            'packet_diagram': True,
        }
        self._show_file_format_view = False
        self._file_format_record = None
        self._file_format_raw_bytes = b''
        self._base_fonts = {}
        self._last_find_row = None
        self._last_find_signature = None
        self._last_find_offset = None
        self._last_find_detail_index = None
        self._selected_record_index = -1
        self._packet_history: list[int] = []
        self._history_index = -1
        self._conversation_highlight_indexes = set()
        self._conversation_highlight_color = QColor('#FFF2A8')
        self._filter_history = self._load_filter_history()
        self.capture_comments = ''
        self.capture_metadata = None  # pcapng metadata (interfaces, file comment, packet comments)
        self._packet_state_by_number = {}
        self._is_dirty = False
        self._auto_output_written_files = []
        self._auto_output_base_path = ''
        self._rollover_file_counter = 0
        self._refine_thread = None
        self._refine_queue = queue.Queue(maxsize=1024)
        self._refine_stop = threading.Event()
        self._visible_row_lookup = {}
        self._related_indicator_rows = {}
        self._last_related_indicator_signature = None
        self._refine_max_rows_per_tick = 80
        self._refine_max_tick_seconds = 0.006
        self._is_bulk_loading = False
        self._file_load_thread = None
        self._file_load_queue = queue.Queue(maxsize=128)
        self._file_load_stop = threading.Event()
        self._file_load_timer = QTimer(self)
        self._file_load_timer.setInterval(16)
        self._file_load_timer.timeout.connect(self._drain_file_load_queue)
        self._file_load_filter_expr = ''
        self._file_load_requires_filter_rebuild = False
        self._file_load_loaded_count = 0
        self._file_load_last_status_count = 0
        self._file_load_error_message = ''
        self._visible_append_queue = deque()
        self._file_load_done_pending_finalize = False
        self._visible_append_timer = QTimer(self)
        self._visible_append_timer.setInterval(8)
        self._visible_append_timer.timeout.connect(self._drain_visible_append_queue)
        self._refine_timer = QTimer(self)
        self._refine_timer.setInterval(16)
        self._refine_timer.timeout.connect(self._drain_refine_queue)
        self._packet_list_aux_refresh_timer = QTimer(self)
        self._packet_list_aux_refresh_timer.setSingleShot(True)
        self._packet_list_aux_refresh_timer.setInterval(8)
        self._packet_list_aux_refresh_timer.timeout.connect(self._flush_packet_list_aux_refresh)
        self._pending_related_indicator_refresh = False
        self._pending_minimap_refresh = False
        self._last_minimap_refresh_monotonic = 0.0
        self._minimap_refresh_interval_during_bulk = 0.12
        self._minimap_cache_dirty = True
        self._startup_priority_mode = False

        self._build_ui()
        self.refresh_preferences_from_settings()
        self._update_status('Ready')

    def _settings(self):
        return QSettings('Packetra', 'Packetra')

    def _is_pipe_interface(self, iface: str) -> bool:
        return str(iface or '').lower().startswith('\\\\.\\pipe\\')

    def is_bulk_loading(self) -> bool:
        return bool(self._is_bulk_loading)

    def _reset_visible_row_lookup(self):
        self._visible_row_lookup = {}

    def _rebuild_visible_row_lookup(self):
        self._visible_row_lookup = {int(rec_idx): int(row) for row, rec_idx in enumerate(self.visible_indices)}

    def _configure_parser_capture_context(self, parser: PacketParser, capture_path: str):
        if parser is None:
            return
        try:
            parser.set_capture_file_path(capture_path or '')
        except Exception:
            pass

    def _load_filter_history(self):
        try:
            values = self._settings().value('filter_history', [], list)
            if not isinstance(values, list):
                return []
            limit = int(self._settings().value('preferences/show_up_to_filter_entries', 10, int) or 10)
            limit = max(1, min(limit, 100))
            return [str(v) for v in values][:limit]
        except Exception:
            return []

    def _save_filter_history(self):
        limit = int(self._settings().value('preferences/show_up_to_filter_entries', 10, int) or 10)
        limit = max(1, min(limit, 100))
        self._settings().setValue('filter_history', self._filter_history[:limit])

    def _remember_filter(self, expr: str):
        expr = (expr or '').strip()
        if not expr:
            return
        limit = int(self._settings().value('preferences/show_up_to_filter_entries', 10, int) or 10)
        limit = max(1, min(limit, 100))
        self._filter_history = [f for f in self._filter_history if f != expr]
        self._filter_history.insert(0, expr)
        self._filter_history = self._filter_history[:limit]
        self._save_filter_history()
        self._update_filter_autocomplete_model()
        self._refresh_filter_history_menu()

    def _load_display_filter_macros(self) -> list[dict]:
        try:
            raw = str(self._settings().value('analyze/display_filter_macros', '[]', str) or '[]')
            payload = json.loads(raw)
        except Exception:
            return []
        if not isinstance(payload, list):
            return []
        result = []
        for item in payload:
            if not isinstance(item, dict):
                continue
            name = str(item.get('name', '') or '').strip()
            expression = str(item.get('expression', '') or '').strip()
            if name and expression:
                result.append({'name': name, 'expression': expression})
        return result

    def _expand_display_filter_macros(self, expression: str) -> str:
        expr = str(expression or '').strip()
        if not expr:
            return ''

        macros = {}
        for item in self._load_display_filter_macros():
            name = str(item.get('name', '') or '').strip()
            macro_expr = str(item.get('expression', '') or '').strip()
            if name and macro_expr:
                macros[name.casefold()] = macro_expr

        if not macros:
            return expr

        pattern = re.compile(r'\$\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?::([^}]*))?\}')
        expanded = expr
        for _ in range(10):
            changed = False

            def repl(match):
                nonlocal changed
                macro_name = str(match.group(1) or '').strip()
                params_blob = str(match.group(2) or '')
                template = macros.get(macro_name.casefold())
                if not template:
                    return match.group(0)
                params = [part.strip() for part in params_blob.split(';')] if params_blob != '' else []
                resolved = template
                for idx, value in enumerate(params, start=1):
                    resolved = resolved.replace(f'${idx}', value)
                changed = True
                return resolved

            updated = pattern.sub(repl, expanded)
            expanded = updated
            if not changed:
                break
        return expanded

    def _load_recent_files(self):
        try:
            values = self._settings().value('recent_capture_files', [], list)
            if not isinstance(values, list):
                return []
            limit = int(self._settings().value('preferences/show_up_to_recent_files', 10, int) or 10)
            limit = max(1, min(limit, 100))
            return [str(v) for v in values][:limit]
        except Exception:
            return []

    def _preferred_open_directory(self) -> str:
        settings = self._settings()
        mode = str(settings.value('preferences/open_files_mode', 'recent_folder', str) or 'recent_folder')
        fixed_dir = str(settings.value('preferences/open_files_fixed_directory', '', str) or '').strip()
        if mode == 'fixed_folder' and fixed_dir and os.path.isdir(fixed_dir):
            return fixed_dir

        recent = self._load_recent_files()
        if recent:
            first_path = str(recent[0] or '').strip()
            if first_path:
                folder = os.path.dirname(first_path)
                if folder and os.path.isdir(folder):
                    return folder
        return str(Path.cwd())

    def refresh_preferences_from_settings(self):
        settings = self._settings()
        autocomplete = bool(settings.value('preferences/display_filter_autocomplete', True, bool))
        if hasattr(self, 'filter_history_action'):
            self.filter_history_action.setVisible(True)
        if autocomplete:
            if hasattr(self, 'display_filter_completer'):
                self.display_filter_input.setCompleter(self.display_filter_completer)
            if hasattr(self, 'find_type_combo') and self.find_type_combo.currentText() == 'Display filter':
                self.find_input.setCompleter(getattr(self, 'find_filter_completer', None))
        else:
            self.display_filter_input.setCompleter(None)
            if hasattr(self, 'find_input'):
                self.find_input.setCompleter(None)
        self._update_filter_autocomplete_model()

    def _save_recent_files(self, paths: list[str]):
        limit = int(self._settings().value('preferences/show_up_to_recent_files', 10, int) or 10)
        limit = max(1, min(limit, 100))
        self._settings().setValue('recent_capture_files', paths[:limit])

    def _remember_recent_file(self, path: str):
        if not path:
            return
        path = os.path.normpath(path)
        recent = [p for p in self._load_recent_files() if os.path.normpath(p) != path]
        recent.insert(0, path)
        self._save_recent_files(recent)

    def set_interface(self, iface: str, iface_display_name: str, capture_filter: str = ''):
        """Đặt interface và khởi động lại"""
        self.iface = iface
        self.iface_display_name = iface_display_name
        self.capture_filter = capture_filter
        self.interface_config = {}
        self.stop_capture()
        self._stop_file_load_thread()
        self._is_bulk_loading = False
        self._startup_priority_mode = False
        self.records.clear()
        self.visible_indices.clear()
        self._reset_visible_row_lookup()
        self._selected_record_index = -1
        self._packet_history = []
        self._history_index = -1
        self.table.setRowCount(0)
        timer = getattr(self, '_packet_list_aux_refresh_timer', None)
        if timer is not None:
            timer.stop()
        self._pending_related_indicator_refresh = False
        self._pending_minimap_refresh = False
        self._clear_related_packet_indicators()
        self.details_tree.show_packet(None)
        self.hex_view.show_packet(None)
        self.parser = PacketParser()
        self._configure_parser_capture_context(self.parser, '')
        self.capture_comments = ''
        self.capture_metadata = None
        self._packet_state_by_number = {}
        self.loaded_file_path = None
        self._auto_output_written_files = []
        self._auto_output_base_path = ''
        self._rollover_file_counter = 0
        self.clear_conversation_highlight()
        self.set_file_format_view_mode(False)
        self._set_dirty(False)
        self.capture_state_changed.emit(False)
        self._update_packet_minimap()
        self._emit_go_state_changed()
        self._update_status('Ready')
    
    def set_output_settings(self, output_settings):
        """Set Output tab settings from Capture Options dialog"""
        self.output_settings = output_settings.copy() if output_settings else {}

    def set_options_settings(self, options_settings):
        """Set Options tab settings from Capture Options dialog"""
        self.options_settings = options_settings.copy() if options_settings else {}
        self.realtime_update_enabled = bool(self.options_settings.get('realtime', True))
        self.auto_scroll_enabled = bool(self.options_settings.get('autoscroll', True))

    def _capture_output_format(self) -> str:
        fmt = str((self.output_settings or {}).get('format', 'pcapng')).strip().lower()
        return 'pcapng' if fmt == 'pcapng' else 'pcap'

    def _capture_compression(self) -> str:
        comp = str((self.output_settings or {}).get('compression', 'none')).strip().lower()
        if comp in ('gzip', 'lz4'):
            return comp
        return 'none'

    def _ensure_extension_for_output(self, path: str) -> str:
        return normalize_capture_extension(path, self._capture_output_format())

    def _compression_label_map(self):
        return {
            'none': 'Uncompressed',
            'gzip': 'Compress with gzip',
            'lz4': 'Compress with LZ4',
        }

    def _compression_value_from_label(self, label: str) -> str:
        label = (label or '').strip().lower()
        if 'gzip' in label:
            return 'gzip'
        if 'lz4' in label:
            return 'lz4'
        return 'none'

    def _build_auto_output_path(self) -> str:
        output = self.output_settings or {}
        configured = str(output.get('file_path', '') or '').strip()

        if configured:
            return self._ensure_extension_for_output(configured)

        default_name = f"capture_{time.strftime('%Y%m%d_%H%M%S')}"
        temp_dir = str((self.options_settings or {}).get('temp_dir', '') or '').strip()
        if not temp_dir:
            temp_dir = os.getcwd()
        return self._ensure_extension_for_output(os.path.join(temp_dir, default_name))

    def _rollover_duration_seconds(self) -> int:
        output = self.output_settings or {}
        value = int(output.get('rollover_duration_value', 1) or 1)
        unit = str(output.get('rollover_duration_unit', 'seconds')).strip().lower()
        if unit == 'minutes':
            return value * 60
        if unit == 'hours':
            return value * 3600
        return value

    def _rollover_size_bytes(self) -> int:
        output = self.output_settings or {}
        value = int(output.get('rollover_size_value', 1) or 1)
        unit = str(output.get('rollover_size_unit', 'kilobytes')).strip().lower()
        mult = {
            'kilobytes': 1024,
            'megabytes': 1024 * 1024,
            'gigabytes': 1024 * 1024 * 1024,
        }.get(unit, 1024)
        return value * mult

    def _rollover_wallclock_seconds(self) -> int:
        output = self.output_settings or {}
        value = int(output.get('rollover_wallclock_value', 1) or 1)
        unit = str(output.get('rollover_wallclock_unit', 'hours')).strip().lower()
        return value * (86400 if unit == 'days' else 3600)

    def _has_auto_create_rollover_condition(self) -> bool:
        output = self.output_settings or {}
        return any([
            bool(output.get('rollover_packets_enabled')),
            bool(output.get('rollover_size_enabled')),
            bool(output.get('rollover_duration_enabled')),
            bool(output.get('rollover_wallclock_enabled')),
        ])

    def _next_output_target_path(self, chunk_records, auto_create_mode: bool) -> str:
        base_path = self._auto_output_base_path or self._build_auto_output_path()
        if not auto_create_mode:
            return base_path

        output = self.output_settings or {}
        ring_enabled = bool(output.get('ring_buffer_enabled'))
        ring_limit = max(2, int(output.get('ring_buffer_files', 2) or 2))
        slot = (self._rollover_file_counter % ring_limit) if ring_enabled else None
        target_path = self._build_rotated_file_path(base_path, self._rollover_file_counter, chunk_records, slot)
        self._rollover_file_counter += 1
        return target_path

    def _should_rollover_chunk(self, chunk_records, chunk_bytes: int) -> bool:
        output = self.output_settings or {}
        if not chunk_records:
            return False

        if bool(output.get('rollover_packets_enabled')):
            packet_limit = int(output.get('rollover_packets_value', 100000) or 100000)
            if len(chunk_records) >= packet_limit:
                return True

        if bool(output.get('rollover_size_enabled')):
            if chunk_bytes >= self._rollover_size_bytes():
                return True

        if bool(output.get('rollover_duration_enabled')):
            first_epoch = float(chunk_records[0].epoch_time)
            last_epoch = float(chunk_records[-1].epoch_time)
            if (last_epoch - first_epoch) >= self._rollover_duration_seconds():
                return True

        if bool(output.get('rollover_wallclock_enabled')):
            boundary = self._rollover_wallclock_seconds()
            first_bucket = int(float(chunk_records[0].epoch_time) // boundary)
            last_bucket = int(float(chunk_records[-1].epoch_time) // boundary)
            if last_bucket > first_bucket:
                return True

        return False

    def _split_records_for_rollover(self, records):
        output = self.output_settings or {}
        if not bool(output.get('auto_create')):
            return [records]

        has_any_condition = any([
            bool(output.get('rollover_packets_enabled')),
            bool(output.get('rollover_size_enabled')),
            bool(output.get('rollover_duration_enabled')),
            bool(output.get('rollover_wallclock_enabled')),
        ])
        if not has_any_condition:
            return [records]

        chunks = []
        current_chunk = []
        current_bytes = 0

        for idx, rec in enumerate(records):
            current_chunk.append(rec)
            current_bytes += int(rec.length)

            is_last = idx == len(records) - 1
            if not is_last and self._should_rollover_chunk(current_chunk, current_bytes):
                chunks.append(current_chunk)
                current_chunk = []
                current_bytes = 0

        if current_chunk:
            chunks.append(current_chunk)

        return chunks if chunks else [records]

    def _build_rotated_file_path(self, base_path: str, chunk_index: int, chunk_records, ring_slot=None) -> str:
        root, ext = os.path.splitext(base_path)
        if base_path.lower().endswith('.gz') or base_path.lower().endswith('.lz4'):
            root, ext2 = os.path.splitext(root)
            ext = ext2

        output = self.output_settings or {}
        pattern = str(output.get('infix_pattern', 'timestamp_first')).strip().lower()
        counter = ring_slot if ring_slot is not None else chunk_index
        ts = time.strftime('%Y%m%d%H%M%S', time.localtime(float(chunk_records[0].epoch_time)))

        if pattern == 'counter_first':
            infix = f'_{counter:05d}_{ts}'
        else:
            infix = f'_{ts}_{counter:05d}'

        return f'{root}{infix}{ext}'

    def _packet_number_from_record(self, record) -> int:
        try:
            return int(getattr(record, 'number', 0) or 0)
        except Exception:
            return 0

    def _runtime_packet_state(self, packet_number: int) -> dict:
        key = int(packet_number or 0)
        state = self._packet_state_by_number.get(key)
        if state is None:
            state = {
                'marked': False,
                'ignored': False,
                'comment': '',
            }
            self._packet_state_by_number[key] = state
        return state

    def _apply_runtime_state_to_record(self, record):
        if record is None:
            return record
        packet_number = self._packet_number_from_record(record)
        state = self._runtime_packet_state(packet_number)
        record.marked = bool(state.get('marked', False))
        record.ignored = bool(state.get('ignored', False))
        runtime_comment = str(state.get('comment', '') or '')
        if runtime_comment:
            record.packet_comment = runtime_comment
        return record

    def _sync_runtime_state_from_record(self, record):
        if record is None:
            return
        packet_number = self._packet_number_from_record(record)
        state = self._runtime_packet_state(packet_number)
        state['marked'] = bool(getattr(record, 'marked', False))
        state['ignored'] = bool(getattr(record, 'ignored', False))
        state['comment'] = str(getattr(record, 'packet_comment', '') or '')

    def _apply_capture_metadata_to_record(self, record, packet_number: int):
        if record is None:
            return record

        self._apply_runtime_state_to_record(record)
        file_path = str(self.loaded_file_path or '').strip()
        if file_path:
            record.metadata['capture_file_path'] = file_path

        packet_number = int(packet_number)
        if self.capture_metadata is None:
            self._sync_runtime_state_from_record(record)
            return record

        packet_comments = getattr(self.capture_metadata, 'packet_comments', {}) or {}
        packet_comment = str(packet_comments.get(packet_number, '') or '')
        if packet_comment and not str(getattr(record, 'packet_comment', '') or '').strip():
            record.packet_comment = packet_comment

        interfaces = list(getattr(self.capture_metadata, 'interfaces', []) or [])
        if not interfaces:
            return record

        selected_interface = None
        packet_interfaces = getattr(self.capture_metadata, 'packet_interfaces', {}) or {}
        packet_interface_id = packet_interfaces.get(packet_number, None)
        if packet_interface_id is not None:
            for interface in interfaces:
                if int(interface.get('interface_id', -1) or -1) == int(packet_interface_id):
                    selected_interface = interface
                    break

        iface_text = str(getattr(record, 'iface', '') or '').strip().lower()
        if selected_interface is None and iface_text:
            for interface in interfaces:
                name = str(interface.get('name', '') or '').strip().lower()
                description = str(interface.get('description', '') or '').strip().lower()
                if iface_text and iface_text in {name, description}:
                    selected_interface = interface
                    break

        if selected_interface is None and len(interfaces) == 1:
            selected_interface = interfaces[0]

        if selected_interface is None:
            return record

        interface_id = int(selected_interface.get('interface_id', 0) or 0)
        interface_name = str(selected_interface.get('name', '') or '').strip()
        interface_description = str(selected_interface.get('description', '') or '').strip()

        record.interface_id = interface_id
        if not str(getattr(record, 'iface', '') or '').strip() and interface_name:
            record.iface = interface_name

        record.metadata['frame_interface_id'] = interface_id
        if interface_name:
            record.metadata['frame_interface_name'] = interface_name
        if interface_description:
            record.metadata['frame_interface_description'] = interface_description

        self._sync_runtime_state_from_record(record)
        return record

    def _persist_capture_records(self, records, file_path: str, file_format: str, compression: str) -> str:
        packets = [r.raw for r in records]
        return save_capture_file(file_path, packets, file_format=file_format, compression=compression)

    def _apply_ring_buffer_limit(self):
        output = self.output_settings or {}
        if not bool(output.get('ring_buffer_enabled')):
            return
        limit = int(output.get('ring_buffer_files', 2) or 2)
        while len(self._auto_output_written_files) > limit:
            oldest = self._auto_output_written_files.pop(0)
            try:
                if os.path.exists(oldest):
                    os.remove(oldest)
            except OSError:
                pass

    def _auto_save_capture_output(self) -> bool:
        if not self.records:
            return False

        output = self.output_settings or {}
        file_format = self._capture_output_format()
        compression = self._capture_compression()
        chunks = self._split_records_for_rollover(self.records)
        auto_create_mode = bool(output.get('auto_create')) and self._has_auto_create_rollover_condition()

        written = []

        for chunk in chunks:
            target_path = self._next_output_target_path(chunk, auto_create_mode)

            actual_path = self._persist_capture_records(chunk, target_path, file_format, compression)
            written.append(actual_path)
            self._auto_output_written_files.append(actual_path)
            self._apply_ring_buffer_limit()

        if written:
            self.loaded_file_path = written[-1]
            self._remember_recent_file(self.loaded_file_path)
            self._set_dirty(False)
            if len(written) == 1:
                self._update_status(f'Saved capture to {written[0]}')
            else:
                self._update_status(f'Saved capture to {len(written)} files. Last file: {written[-1]}')
            return True

        return False

    def _show_save_with_options_dialog(self):
        output = self.output_settings or {}
        default_format = self._capture_output_format()
        default_compression = self._capture_compression()

        dialog = QFileDialog(self, 'Save Capture')
        dialog.setOption(QFileDialog.DontUseNativeDialog, True)
        dialog.setAcceptMode(QFileDialog.AcceptSave)

        if default_format == 'pcapng':
            dialog.setNameFilters(['PCAPNG Files (*.pcapng)', 'PCAP Files (*.pcap)', 'All Files (*)'])
            dialog.selectNameFilter('PCAPNG Files (*.pcapng)')
            dialog.setDefaultSuffix('pcapng')
        else:
            dialog.setNameFilters(['PCAP Files (*.pcap)', 'PCAPNG Files (*.pcapng)', 'All Files (*)'])
            dialog.selectNameFilter('PCAP Files (*.pcap)')
            dialog.setDefaultSuffix('pcap')

        initial_path = str(output.get('file_path', '') or '').strip()
        if not initial_path:
            initial_path = self.loaded_file_path or ''
        if initial_path:
            dialog.selectFile(initial_path)

        compression_combo = QComboBox(dialog)
        compression_combo.addItems([
            'Uncompressed',
            'Compress with gzip',
            'Compress with LZ4',
        ])
        compression_combo.setCurrentText(self._compression_label_map().get(default_compression, 'Uncompressed'))

        layout = dialog.layout()
        if layout is not None:
            row = QHBoxLayout()
            row.addWidget(QLabel('Compression options:'))
            row.addWidget(compression_combo)
            container = QWidget(dialog)
            container.setLayout(row)
            try:
                layout.addWidget(container, layout.rowCount(), 0, 1, layout.columnCount())
            except TypeError:
                layout.addWidget(container)

        if not dialog.exec():
            return None, None, None

        selected = dialog.selectedFiles()
        if not selected:
            return None, None, None

        selected_path = selected[0]
        selected_filter = dialog.selectedNameFilter()
        if 'pcapng' in selected_filter.lower():
            selected_format = 'pcapng'
        elif 'pcap' in selected_filter.lower():
            selected_format = 'pcap'
        else:
            selected_format = default_format

        selected_compression = self._compression_value_from_label(compression_combo.currentText())
        return selected_path, selected_format, selected_compression

    def _build_ui(self):
        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # Filter row
        filter_row = QHBoxLayout()
        filter_row.setContentsMargins(8, 4, 8, 4)
        self.display_filter_input = QLineEdit()
        self.display_filter_input.setPlaceholderText('Apply a display filter ... <Ctrl+/>')
        self.apply_filter_btn = QToolButton()
        self.apply_filter_btn.setText('→')
        self.apply_filter_btn.setToolTip('Apply display filter')
        self.filter_history_menu = QMenu(self)
        self.filter_history_action = self.display_filter_input.addAction(
            self.style().standardIcon(QStyle.StandardPixmap.SP_ArrowDown),
            QLineEdit.ActionPosition.TrailingPosition,
        )
        self.clear_filter_btn = QToolButton()
        self.clear_filter_btn.setText('x')
        self.clear_filter_btn.setToolTip('Clear display filter')
        self.apply_filter_btn.setFixedWidth(28)
        self.clear_filter_btn.setFixedWidth(28)
        filter_row.addWidget(self.display_filter_input)
        filter_row.addWidget(self.apply_filter_btn)
        filter_row.addWidget(self.clear_filter_btn)
        self.filter_toolbar_widget = QWidget()
        self.filter_toolbar_widget.setLayout(filter_row)
        root_layout.addWidget(self.filter_toolbar_widget)

        # Find row (similar behavior), hidden by default.
        find_root = QVBoxLayout()
        find_root.setContentsMargins(8, 0, 8, 4)
        find_root.setSpacing(4)

        find_row_1 = QHBoxLayout()
        find_row_1.setContentsMargins(0, 0, 0, 0)

        self.find_scope_combo = QComboBox()
        self.find_scope_combo.addItems(['Packet list', 'Packet details', 'Packet bytes'])

        self.find_type_combo = QComboBox()
        self.find_type_combo.addItems(['Display filter', 'Hexadecimal Value', 'String', 'Regular Expression'])

        self.find_input = QLineEdit()
        self.find_input.setPlaceholderText('Enter a find expression ...')

        self.find_go_btn = QPushButton('Find')
        self.find_cancel_btn = QPushButton('Cancel')

        find_row_1.addWidget(self.find_scope_combo)
        find_row_1.addWidget(self.find_type_combo)
        find_row_1.addWidget(self.find_input, 1)
        find_row_1.addWidget(self.find_go_btn)
        find_row_1.addWidget(self.find_cancel_btn)

        find_row_2 = QHBoxLayout()
        find_row_2.setContentsMargins(0, 0, 0, 0)

        self.find_encoding_combo = QComboBox()
        self.find_encoding_combo.addItems(['Narrow & Wide', 'Narrow (UTF-8 / ASCII)', 'Wide (UTF-16)'])

        self.find_case_cb = QCheckBox('Case sensitive')
        self.find_backwards_cb = QCheckBox('Backwards')
        self.find_multiple_cb = QCheckBox('Multiple occurrences')

        find_row_2.addWidget(QLabel('Options:'))
        find_row_2.addWidget(self.find_encoding_combo)
        find_row_2.addWidget(self.find_case_cb)
        find_row_2.addWidget(self.find_backwards_cb)
        find_row_2.addWidget(self.find_multiple_cb)
        find_row_2.addStretch()

        find_root.addLayout(find_row_1)
        find_root.addLayout(find_row_2)

        self.find_widget = QWidget()
        self.find_widget.setLayout(find_root)
        self.find_widget.setVisible(False)
        root_layout.addWidget(self.find_widget)

        # Go-to packet row (shown by toolbar jump action)
        packet_row = QHBoxLayout()
        packet_row.setContentsMargins(8, 0, 8, 4)
        packet_row.addWidget(QLabel('Packet:'))
        self.goto_packet_input = QLineEdit()
        self.goto_packet_input.setFixedWidth(120)
        self.goto_packet_go_btn = QPushButton('Go to packet')
        self.goto_packet_cancel_btn = QPushButton('Cancel')
        packet_row.addWidget(self.goto_packet_input)
        packet_row.addWidget(self.goto_packet_go_btn)
        packet_row.addWidget(self.goto_packet_cancel_btn)
        packet_row.addStretch()

        self.goto_packet_widget = QWidget()
        self.goto_packet_widget.setLayout(packet_row)
        self.goto_packet_widget.setVisible(False)
        root_layout.addWidget(self.goto_packet_widget)

        # Packet table
        self.table = PacketTable()
        self.packet_minimap = _PacketListMinimap(self, self.table, self.table.viewport())
        self.packet_minimap.show()
        self.packet_list_container = QWidget()
        packet_list_layout = QHBoxLayout(self.packet_list_container)
        packet_list_layout.setContentsMargins(0, 0, 0, 0)
        packet_list_layout.setSpacing(0)
        packet_list_layout.addWidget(self.table, 1)
        scrollbar = self.table.verticalScrollBar()
        self.table.installEventFilter(self)
        self.table.viewport().installEventFilter(self)
        if scrollbar is not None:
            scrollbar.installEventFilter(self)
            scrollbar.rangeChanged.connect(lambda *_args: self._layout_packet_minimap_overlay())
            scrollbar.valueChanged.connect(lambda *_args: self._layout_packet_minimap_overlay())
        self._layout_packet_minimap_overlay()
        self.details_tree = PacketDetailsTree()
        self.hex_view = PacketBytesView()
        self.packet_diagram_view = QTextEdit()
        self.packet_diagram_view.setReadOnly(True)
        self.packet_diagram_view.setPlainText('Packet Diagram is not available yet.')
        self._empty_pane_widgets = [QWidget(), QWidget(), QWidget()]
        self._sync_fonts_to_hex_reference()
        self._base_fonts = {
            'table': self.hex_view.font().pointSizeF(),
            'details': self.hex_view.font().pointSizeF(),
            'hex': self.hex_view.font().pointSizeF(),
        }

        # Lower splitter
        self.lower_splitter = QSplitter(Qt.Horizontal)
        self.lower_splitter.addWidget(self.details_tree)
        self.lower_splitter.addWidget(self.hex_view)
        self.lower_splitter.setSizes(self.default_lower_splitter_sizes)
        self.lower_splitter.setChildrenCollapsible(False)

        # Main splitter
        self.main_splitter = QSplitter(Qt.Vertical)
        self.main_splitter.addWidget(self.packet_list_container)
        self.main_splitter.addWidget(self.lower_splitter)
        self.main_splitter.setSizes(self.default_main_splitter_sizes)
        self.main_splitter.setChildrenCollapsible(False)

        self.packet_panes_placeholder = QWidget()
        self.packet_panes_placeholder.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        placeholder_layout = QVBoxLayout(self.packet_panes_placeholder)
        placeholder_layout.setContentsMargins(16, 16, 16, 16)
        placeholder_layout.addStretch(1)
        self.packet_panes_placeholder_label = QLabel('File format view mode')
        self.packet_panes_placeholder_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        placeholder_layout.addWidget(self.packet_panes_placeholder_label)
        placeholder_layout.addStretch(1)

        self.packet_panes_stack = QStackedWidget()
        self.packet_panes_stack.addWidget(self.main_splitter)
        self.packet_panes_stack.addWidget(self.packet_panes_placeholder)
        self.packet_panes_stack.setCurrentWidget(self.main_splitter)

        root_layout.addWidget(self.packet_panes_stack, 1)

        # Connect signals
        self.apply_filter_btn.clicked.connect(self.apply_display_filter)
        self.clear_filter_btn.clicked.connect(self.clear_display_filter)
        self.display_filter_input.returnPressed.connect(self.apply_display_filter)
        self.goto_packet_go_btn.clicked.connect(self._on_go_to_packet_row_submit)
        self.goto_packet_cancel_btn.clicked.connect(self._on_go_to_packet_row_cancel)
        self.goto_packet_input.returnPressed.connect(self._on_go_to_packet_row_submit)
        self.find_go_btn.clicked.connect(self._on_find_clicked)
        self.find_cancel_btn.clicked.connect(self._on_find_cancel)
        self.find_input.returnPressed.connect(self._on_find_clicked)
        self.find_type_combo.currentIndexChanged.connect(self._on_find_option_changed)
        self.find_scope_combo.currentIndexChanged.connect(self._on_find_option_changed)
        self.find_input.textChanged.connect(self._on_find_query_changed)
        self.filter_history_action.triggered.connect(self._show_filter_history_menu)
        self.table.cellClicked.connect(self.show_details)
        self.table.cellDoubleClicked.connect(self._on_table_double_clicked)
        self.table.itemSelectionChanged.connect(self._on_packet_table_selection_changed)
        self.table.verticalScrollBar().valueChanged.connect(
            lambda _value: getattr(self, 'packet_minimap', None).update() if getattr(self, 'packet_minimap', None) is not None else None
        )
        model = self.table.model()
        if model is not None:
            model.rowsInserted.connect(lambda *_args: self._schedule_packet_list_aux_refresh(minimap=True, minimap_data_changed=True))
            model.rowsRemoved.connect(lambda *_args: self._schedule_packet_list_aux_refresh(minimap=True, minimap_data_changed=True))
            model.modelReset.connect(lambda *_args: self._schedule_packet_list_aux_refresh(minimap=True, minimap_data_changed=True))
        self.details_tree.detail_field_selected.connect(self._on_detail_field_selected)
        self.details_tree.item_bytes_selected.connect(self.hex_view.highlight_bytes)
        self.hex_view.bytes_range_selected.connect(self._on_bytes_range_selected)
        self.hex_view.bytes_hovered.connect(self._on_bytes_hovered)
        self.hex_view.hover_left.connect(self._on_hex_hover_left)

        self._on_find_option_changed()
        self._setup_filter_autocomplete()
        self._update_filter_autocomplete_model()
        self._refresh_filter_history_menu()

    def _refresh_filter_history_menu(self):
        self.filter_history_menu.clear()
        if not self._filter_history:
            action = QAction('(No recent filters)', self.filter_history_menu)
            action.setEnabled(False)
            self.filter_history_menu.addAction(action)
            return

        limit = int(self._settings().value('preferences/show_up_to_filter_entries', 10, int) or 10)
        limit = max(1, min(limit, 100))
        for expr in self._filter_history[:limit]:
            action = QAction(expr, self.filter_history_menu)
            action.triggered.connect(lambda checked=False, value=expr: self._apply_filter_from_history(value))
            self.filter_history_menu.addAction(action)

    def _filter_autocomplete_tokens(self) -> list[str]:
        protocol_tokens = sorted({str(token).lower() for token in getattr(DisplayFilter, 'PROTOCOL_ALIASES', set())})
        field_tokens = [
            'frame.number', 'frame.len', 'frame.time_delta',
            'eth.addr', 'eth.src', 'eth.dst', 'eth.type',
            'vlan.id',
            'arp.opcode', 'arp.src.proto_ipv4', 'arp.dst.proto_ipv4',
            'ip.addr', 'ip.src', 'ip.dst', 'ip.proto', 'ip.ttl',
            'ipv6.addr', 'ipv6.src', 'ipv6.dst', 'ipv6.nxt', 'ipv6.hlim',
            'tcp.port', 'tcp.srcport', 'tcp.dstport', 'tcp.flags',
            'udp.port', 'udp.srcport', 'udp.dstport',
            'icmp.type', 'icmp.code',
            'dns.id', 'dns.qry.name',
            'detail', 'detail.title', 'detail.key', 'detail.value', 'detail.pair', 'detail.path',
        ]
        keywords = ['and', 'or', 'not', 'contains', '==', '!=', '>=', '<=', '>', '<', '(', ')']
        values = list(self._filter_history) + protocol_tokens + field_tokens + keywords
        seen = set()
        unique = []
        for value in values:
            text = str(value or '').strip()
            if not text:
                continue
            key = text.lower()
            if key in seen:
                continue
            seen.add(key)
            unique.append(text)
        return unique

    def _setup_filter_autocomplete(self):
        self.filter_autocomplete_model = QStringListModel(self)
        self.display_filter_completer = QCompleter(self.filter_autocomplete_model, self)
        self.display_filter_completer.setCaseSensitivity(Qt.CaseInsensitive)
        self.display_filter_completer.setFilterMode(Qt.MatchContains)
        self.display_filter_completer.setCompletionMode(QCompleter.PopupCompletion)
        self.display_filter_input.setCompleter(self.display_filter_completer)

        self.find_filter_completer = QCompleter(self.filter_autocomplete_model, self)
        self.find_filter_completer.setCaseSensitivity(Qt.CaseInsensitive)
        self.find_filter_completer.setFilterMode(Qt.MatchContains)
        self.find_filter_completer.setCompletionMode(QCompleter.PopupCompletion)

    def _update_filter_autocomplete_model(self):
        if hasattr(self, 'filter_autocomplete_model'):
            self.filter_autocomplete_model.setStringList(self._filter_autocomplete_tokens())

    def _set_packet_panes_updates_enabled(self, enabled: bool):
        enabled = bool(enabled)
        self.main_splitter.setUpdatesEnabled(enabled)
        self.lower_splitter.setUpdatesEnabled(enabled)
        self.table.setUpdatesEnabled(enabled)
        self.details_tree.setUpdatesEnabled(enabled)
        self.hex_view.setUpdatesEnabled(enabled)

    def _set_packet_panes_visible(self, visible: bool):
        self.packet_panes_stack.setCurrentWidget(self.main_splitter if bool(visible) else self.packet_panes_placeholder)

    def eventFilter(self, obj, event):
        try:
            table = getattr(self, 'table', None)
            scrollbar = table.verticalScrollBar() if table is not None else None
            viewport = table.viewport() if table is not None else None
            if obj is table or obj is scrollbar or obj is viewport:
                et = event.type()
                if et in (QEvent.Type.Resize, QEvent.Type.Move, QEvent.Type.Show, QEvent.Type.Hide):
                    QTimer.singleShot(0, self._layout_packet_minimap_overlay)
        except Exception:
            pass
        return super().eventFilter(obj, event)

    def _layout_packet_minimap_overlay(self):
        table = getattr(self, 'table', None)
        minimap = getattr(self, 'packet_minimap', None)
        if table is None or minimap is None:
            return
        try:
            viewport = table.viewport()
            if viewport is None:
                minimap.hide()
                return
            if minimap.parent() is not viewport:
                minimap.setParent(viewport)
            vp_rect = viewport.rect()
            if vp_rect.width() <= 0 or vp_rect.height() <= 0:
                minimap.hide()
                return
            minimap_width = 42
            minimap_x = max(0, int(vp_rect.width() - minimap_width))
            minimap.setGeometry(minimap_x, 0, minimap_width, int(vp_rect.height()))
            minimap.show()
            minimap.raise_()
        except RuntimeError:
            pass
        except Exception:
            pass

    def _clear_splitter(self, splitter: QSplitter):
        while splitter.count() > 0:
            widget = splitter.widget(0)
            if widget is None:
                break
            widget.setParent(None)

    def _normalize_layout_name(self, layout_name: str) -> str:
        mode = str(layout_name or 'Layout 2').strip()
        mode = {
            'Layout A': 'Layout 2',
            'Layout B': 'Layout 3',
            'Layout C': 'Layout 6',
        }.get(mode, mode)
        if mode not in {'Layout 1', 'Layout 2', 'Layout 3', 'Layout 4', 'Layout 5', 'Layout 6'}:
            mode = 'Layout 2'
        return mode

    def _normalize_pane_assignments(self, pane_assignments) -> tuple[str, str, str]:
        allowed = {'packet_list', 'packet_details', 'packet_bytes', 'packet_diagram', 'none'}
        values = list(pane_assignments or self._pane_assignments or ('packet_list', 'packet_details', 'packet_bytes'))[:3]
        while len(values) < 3:
            values.append('none')
        normalized = []
        for value in values:
            text = str(value or 'none').strip().lower()
            normalized.append(text if text in allowed else 'none')
        return tuple(normalized[:3])

    def set_pane_assignments(self, pane_assignments) -> bool:
        normalized = self._normalize_pane_assignments(pane_assignments)
        assigned = [value for value in normalized if value != 'none']
        if len(assigned) != len(set(assigned)):
            return False
        self._pane_assignments = normalized
        if hasattr(self, 'main_splitter'):
            self.apply_pane_layout(self._current_pane_layout)
        return True

    def _pane_widget(self, pane_key: str, pane_index: int):
        key = str(pane_key or 'none').strip().lower()
        if key in self._pane_component_visibility and not self._pane_component_visibility.get(key, True):
            key = 'none'
        if key == 'packet_list':
            return self.packet_list_container
        if key == 'packet_details':
            return self.details_tree
        if key == 'packet_bytes':
            return self.hex_view
        if key == 'packet_diagram':
            return self.packet_diagram_view
        return self._empty_pane_widgets[max(0, min(int(pane_index), len(self._empty_pane_widgets) - 1))]

    def is_filter_toolbar_visible(self) -> bool:
        return bool(getattr(self, 'filter_toolbar_widget', None) and self.filter_toolbar_widget.isVisible())

    def set_filter_toolbar_visible(self, visible: bool):
        if hasattr(self, 'filter_toolbar_widget'):
            self.filter_toolbar_widget.setVisible(bool(visible))

    def is_component_visible(self, component_name: str) -> bool:
        key = str(component_name or '').strip().lower()
        if key not in self._pane_component_visibility:
            return True
        return bool(self._pane_component_visibility.get(key, True))

    def set_component_visible(self, component_name: str, visible: bool):
        key = str(component_name or '').strip().lower()
        if key not in self._pane_component_visibility:
            return
        self._pane_component_visibility[key] = bool(visible)
        self.apply_pane_layout(self._current_pane_layout)

    def is_file_format_view_mode(self) -> bool:
        return bool(self._show_file_format_view)

    def _build_file_format_mode_record(self):
        if not self.loaded_file_path or not os.path.exists(self.loaded_file_path):
            return None
        try:
            raw_bytes = Path(self.loaded_file_path).read_bytes()
        except Exception:
            return None

        self._file_format_raw_bytes = bytes(raw_bytes)
        file_name = os.path.basename(self.loaded_file_path)
        file_size = len(self._file_format_raw_bytes)

        block_type_names = {
            0x0A0D0D0A: 'Section Header Block',
            0x00000001: 'Interface Description Block',
            0x00000002: 'Packet Block (obsolete)',
            0x00000003: 'Simple Packet Block',
            0x00000004: 'Name Resolution Block',
            0x00000005: 'Interface Statistics Block',
            0x00000006: 'Enhanced Packet Block',
            0x0000000A: 'Decryption Secrets Block',
            0x00000BAD: 'Custom Block',
            0x40000BAD: 'Custom Block (copy-safe)',
        }

        def _u16(data: bytes, off: int, endian: str):
            if off + 2 > len(data):
                return None
            return int.from_bytes(data[off:off + 2], endian)

        def _u32(data: bytes, off: int, endian: str):
            if off + 4 > len(data):
                return None
            return int.from_bytes(data[off:off + 4], endian)

        def _u64(data: bytes, off: int, endian: str, signed: bool = False):
            if off + 8 > len(data):
                return None
            return int.from_bytes(data[off:off + 8], endian, signed=signed)

        def _parse_options(start: int, end: int, endian: str):
            nodes = []
            parsed = []
            cursor = start
            while cursor + 4 <= end:
                code = _u16(self._file_format_raw_bytes, cursor, endian)
                length = _u16(self._file_format_raw_bytes, cursor + 2, endian)
                if code is None or length is None:
                    break
                value_start = cursor + 4
                value_end = value_start + int(length)
                if value_end > end:
                    break
                total_len = 4 + int(length)
                padding = (4 - (total_len % 4)) % 4
                full_len = total_len + padding
                if cursor + full_len > end:
                    break

                value_bytes = self._file_format_raw_bytes[value_start:value_end]
                parsed.append((int(code), bytes(value_bytes)))

                if int(code) == 0:
                    nodes.append({
                        'title': 'Option: End of Options',
                        'offset': cursor,
                        'length': full_len,
                        'children': [
                            {'title': 'Code: End of Options (0)', 'offset': cursor, 'length': 2},
                            {'title': 'Length: 0', 'offset': cursor + 2, 'length': 2},
                        ],
                    })
                    cursor += full_len
                    break

                nodes.append({
                    'title': f'Option code {int(code)}, length {int(length)}',
                    'offset': cursor,
                    'length': full_len,
                    'children': [
                        {'title': f'Code: {int(code)}', 'offset': cursor, 'length': 2},
                        {'title': f'Length: {int(length)}', 'offset': cursor + 2, 'length': 2},
                        {'title': f'Option Value ({int(length)} bytes)', 'offset': value_start, 'length': int(length)},
                    ],
                })
                cursor += full_len
            return nodes, parsed

        def _format_timestamp(ts_value: int | None, resolution: float):
            if ts_value is None:
                return ''
            try:
                seconds = float(ts_value) * float(resolution)
                dt = datetime.fromtimestamp(seconds)
                tz_name = time.tzname[0] if time.tzname else 'Local Time'
                return f'[Timestamp: {dt.strftime("%b %d, %Y %H:%M:%S")}.{dt.microsecond:06d}000 {tz_name}]'
            except Exception:
                return ''

        blocks = []
        mapping_nodes = []
        offset = 0
        total = len(self._file_format_raw_bytes)
        section_endian = 'little'
        section_index = 0
        current_interface_tsres = []
        epb_index = 0

        while offset + 12 <= total:
            block_type = _u32(self._file_format_raw_bytes, offset, section_endian)
            block_len = _u32(self._file_format_raw_bytes, offset + 4, section_endian)

            if block_len is None or int(block_len) < 12 or offset + int(block_len) > total:
                alt_endian = 'big' if section_endian == 'little' else 'little'
                alt_type = _u32(self._file_format_raw_bytes, offset, alt_endian)
                alt_len = _u32(self._file_format_raw_bytes, offset + 4, alt_endian)
                if alt_len is None or int(alt_len) < 12 or offset + int(alt_len) > total:
                    break
                block_type = alt_type
                block_len = alt_len
                section_endian = alt_endian

            block_type = int(block_type)
            block_len = int(block_len)
            body_offset = offset + 8
            body_end = offset + block_len - 4
            body_len = max(0, body_end - body_offset)
            trailer_len = _u32(self._file_format_raw_bytes, body_end, section_endian)
            name = block_type_names.get(block_type, f'Unknown Block 0x{block_type:08x}')

            block_type_vendor = bool(block_type & 0x80000000)
            block_type_value = int(block_type & 0x7FFFFFFF)

            block_data_children = []
            block_title_suffix = ''

            if block_type == 0x0A0D0D0A:
                section_index += 1
                current_interface_tsres = []
                block_title_suffix = f' {section_index}'

                bom_bytes = self._file_format_raw_bytes[body_offset:body_offset + 4]
                if bom_bytes == b'\x4d\x3c\x2b\x1a':
                    section_endian = 'little'
                    bom_label = 'Little-endian'
                elif bom_bytes == b'\x1a\x2b\x3c\x4d':
                    section_endian = 'big'
                    bom_label = 'Big-endian'
                else:
                    bom_label = 'Unknown-endian'

                major = _u16(self._file_format_raw_bytes, body_offset + 4, section_endian)
                minor = _u16(self._file_format_raw_bytes, body_offset + 6, section_endian)
                section_len = _u64(self._file_format_raw_bytes, body_offset + 8, section_endian, signed=True)

                block_data_children.extend([
                    {'title': f'Byte Order Magic: {bom_bytes.hex()} ({bom_label})', 'offset': body_offset, 'length': 4},
                    {'title': f'Major Version: {major if major is not None else "?"}', 'offset': body_offset + 4, 'length': 2},
                    {'title': f'Minor Version: {minor if minor is not None else "?"}', 'offset': body_offset + 6, 'length': 2},
                    {'title': f'Section Length: {section_len if section_len is not None else "?"}', 'offset': body_offset + 8, 'length': 8},
                ])
                option_nodes, _ = _parse_options(body_offset + 16, body_end, section_endian)
                if option_nodes:
                    block_data_children.append({'title': 'Options', 'children': option_nodes})

            elif block_type == 0x00000001:
                interface_id = len(current_interface_tsres)
                block_title_suffix = f' {interface_id}'

                linktype = _u16(self._file_format_raw_bytes, body_offset, section_endian)
                snaplen = _u32(self._file_format_raw_bytes, body_offset + 4, section_endian)
                block_data_children.extend([
                    {'title': f'Link Type: ETHERNET ({linktype})' if linktype == 1 else f'Link Type: {linktype if linktype is not None else "?"}', 'offset': body_offset, 'length': 2},
                    {'title': 'Reserved: 0x0000', 'offset': body_offset + 2, 'length': 2},
                    {'title': f'Snap Length: {snaplen if snaplen is not None else "?"}', 'offset': body_offset + 4, 'length': 4},
                ])
                option_nodes, option_values = _parse_options(body_offset + 8, body_end, section_endian)
                resolution = 1e-6
                for opt_code, opt_value in option_values:
                    if opt_code == 9 and len(opt_value) >= 1:
                        raw_val = int(opt_value[0])
                        if raw_val & 0x80:
                            exp = raw_val & 0x7F
                            resolution = 2.0 ** (-exp)
                        else:
                            resolution = 10.0 ** (-raw_val)
                current_interface_tsres.append(float(resolution))
                if option_nodes:
                    block_data_children.append({'title': 'Options', 'children': option_nodes})

            elif block_type == 0x00000006:
                epb_index += 1
                block_title_suffix = f' {epb_index}'

                iface_id = _u32(self._file_format_raw_bytes, body_offset, section_endian)
                ts_hi = _u32(self._file_format_raw_bytes, body_offset + 4, section_endian)
                ts_lo = _u32(self._file_format_raw_bytes, body_offset + 8, section_endian)
                cap_len = int(_u32(self._file_format_raw_bytes, body_offset + 12, section_endian) or 0)
                orig_len = _u32(self._file_format_raw_bytes, body_offset + 16, section_endian)

                ts_value = None
                if ts_hi is not None and ts_lo is not None:
                    ts_value = (int(ts_hi) << 32) | int(ts_lo)
                if_index = int(iface_id or 0)
                if 0 <= if_index < len(current_interface_tsres):
                    ts_res = current_interface_tsres[if_index]
                else:
                    ts_res = 1e-6

                pkt_off = body_offset + 20
                pkt_len = min(cap_len, max(0, body_end - pkt_off))
                pad_len = (4 - (pkt_len % 4)) % 4
                opts_start = pkt_off + pkt_len + pad_len

                block_data_children.extend([
                    {'title': f'Interface: {iface_id if iface_id is not None else "?"}', 'offset': body_offset, 'length': 4},
                    {'title': f'Timestamp (High): {ts_hi if ts_hi is not None else "?"}', 'offset': body_offset + 4, 'length': 4},
                    {'title': f'Timestamp (Low): {ts_lo if ts_lo is not None else "?"}', 'offset': body_offset + 8, 'length': 4},
                ])
                timestamp_line = _format_timestamp(ts_value, ts_res)
                if timestamp_line:
                    block_data_children.append({'title': timestamp_line})
                block_data_children.extend([
                    {'title': f'Captured Packet Length: {cap_len}', 'offset': body_offset + 12, 'length': 4},
                    {'title': f'Original Packet Length: {orig_len if orig_len is not None else "?"}', 'offset': body_offset + 16, 'length': 4},
                    {'title': 'Packet Data', 'offset': pkt_off, 'length': pkt_len},
                ])
                option_nodes, _ = _parse_options(opts_start, body_end, section_endian)
                if option_nodes:
                    block_data_children.append({'title': 'Options', 'children': option_nodes})

                mapping_nodes.append({'title': f'Block {len(blocks) + 1} -> Packet {epb_index}'})

            elif block_type == 0x00000003:
                orig_len = _u32(self._file_format_raw_bytes, body_offset, section_endian)
                data_len = max(0, body_len - 4)
                block_data_children.extend([
                    {'title': f'Original Packet Length: {orig_len if orig_len is not None else "?"}', 'offset': body_offset, 'length': 4},
                    {'title': 'Packet Data', 'offset': body_offset + 4, 'length': data_len},
                ])

            elif block_type == 0x00000004:
                records = []
                cursor = body_offset
                while cursor + 4 <= body_end:
                    rec_type = _u16(self._file_format_raw_bytes, cursor, section_endian)
                    rec_len = _u16(self._file_format_raw_bytes, cursor + 2, section_endian)
                    if rec_type is None or rec_len is None:
                        break
                    full = 4 + int(rec_len)
                    full += (4 - (full % 4)) % 4
                    if cursor + full > body_end:
                        break
                    if int(rec_type) == 0:
                        records.append({
                            'title': 'Record: End of Records',
                            'offset': cursor,
                            'length': full,
                            'children': [
                                {'title': 'Code: End of Records (0)', 'offset': cursor, 'length': 2},
                                {'title': 'Length: 0', 'offset': cursor + 2, 'length': 2},
                            ],
                        })
                        cursor += full
                        break
                    records.append({'title': f'Record type {int(rec_type)}, length {int(rec_len)}', 'offset': cursor, 'length': full})
                    cursor += full
                if records:
                    block_data_children.append({'title': 'Name Records', 'children': records})
                option_nodes, _ = _parse_options(cursor, body_end, section_endian)
                if option_nodes:
                    block_data_children.append({'title': 'Options', 'children': option_nodes})

            elif block_type == 0x00000005:
                iface_id = _u32(self._file_format_raw_bytes, body_offset, section_endian)
                ts_hi = _u32(self._file_format_raw_bytes, body_offset + 4, section_endian)
                ts_lo = _u32(self._file_format_raw_bytes, body_offset + 8, section_endian)
                block_data_children.extend([
                    {'title': f'Interface ID: {iface_id if iface_id is not None else "?"}', 'offset': body_offset, 'length': 4},
                    {'title': f'Timestamp (High): {ts_hi if ts_hi is not None else "?"}', 'offset': body_offset + 4, 'length': 4},
                    {'title': f'Timestamp (Low): {ts_lo if ts_lo is not None else "?"}', 'offset': body_offset + 8, 'length': 4},
                ])
                option_nodes, _ = _parse_options(body_offset + 12, body_end, section_endian)
                if option_nodes:
                    block_data_children.append({'title': 'Options', 'children': option_nodes})

            else:
                if body_len > 0:
                    block_data_children.append({'title': f'Raw Block Data ({body_len} bytes)', 'offset': body_offset, 'length': body_len})

            block_children = [
                {
                    'title': f'Block Type: 0x{block_type:08x}: ({name})',
                    'offset': offset,
                    'length': 4,
                    'children': [
                        {'title': f'Block Type Vendor: {"True" if block_type_vendor else "False"}'},
                        {'title': f'Block Type Value: 0x{block_type_value:08x}: ({name})'},
                    ],
                },
                {'title': f'Block Length: {block_len}', 'offset': offset + 4, 'length': 4},
            ]

            if block_data_children:
                block_children.append({'title': 'Block Data', 'offset': body_offset, 'length': body_len, 'children': block_data_children})
            block_children.append({'title': f'Block Length (trailer): {int(trailer_len) if trailer_len is not None else "?"}', 'offset': body_end, 'length': 4})

            block_number = len(blocks) + 1
            blocks.append({
                'title': f'Block {block_number}: {name}{block_title_suffix}',
                'offset': offset,
                'length': block_len,
                'children': block_children,
            })
            offset += block_len

        if offset < total:
            blocks.append({
                'title': f'Trailing/Invalid bytes: {total - offset}',
                'offset': offset,
                'length': total - offset,
            })

        detail_tree = [
            {
                'title': f'Frame 1: Packet, {file_size} bytes on wire ({file_size * 8} bits), {file_size} bytes captured ({file_size * 8} bits)',
                'offset': 0,
                'length': file_size,
                'children': [
                    {'title': 'Encapsulation type: MIME (134)'},
                    {'title': 'Frame Number: 1'},
                    {'title': f'Frame Length: {file_size} bytes ({file_size * 8} bits)'},
                    {'title': f'Capture Length: {file_size} bytes ({file_size * 8} bits)'},
                    {'title': '[Frame is marked: False]'},
                    {'title': '[Frame is ignored: False]'},
                    {'title': '[Protocols in frame: mime_dlt:file-pcapng]'},
                    {'title': 'Character encoding: ASCII (0)'},
                    {'title': f'File name: {file_name}'},
                ],
            },
            {
                'title': 'MIME file',
                'children': [
                    {
                        'title': f'PCAPNG File Format ({len(blocks)} blocks)',
                        'children': blocks + ([{'title': 'Mapping', 'children': mapping_nodes}] if mapping_nodes else []),
                    }
                ],
            },
        ]

        return PacketRecord(
            number=1,
            epoch_time=0.0,
            relative_time=0.0,
            length=file_size,
            src='',
            dst='',
            protocol='MIME_FILE',
            info=f'PCAPNG file format view: {file_name}',
            layers=['mime_dlt', 'file-pcapng'],
            raw=self._file_format_raw_bytes,
            metadata={'_detail_tree_cache': detail_tree},
        )

    def set_file_format_view_mode(self, enabled: bool):
        self._show_file_format_view = bool(enabled)
        if self._show_file_format_view:
            self._file_format_record = self._build_file_format_mode_record()
            if self._file_format_record is None:
                self._show_file_format_view = False
                QMessageBox.information(None, 'Reload as File Format/Capture', 'Chế độ File Format chỉ hỗ trợ khi đang mở file capture từ đĩa.')
                return
            self.packet_panes_stack.setCurrentWidget(self.main_splitter)
            self.table.replace_records([self._file_format_record])
            self.table.selectRow(0)
            self.table.setCurrentCell(0, 0)
            self.show_details(0, 0)
            self._update_status('Reloaded as File Format mode')
            return
        self._file_format_record = None
        self._file_format_raw_bytes = b''
        self.packet_panes_stack.setCurrentWidget(self.main_splitter)
        self.apply_display_filter()
        if self.visible_indices:
            self.goto_first_packet()
        self._update_status('Returned to Capture packet view mode')

    def _iter_subtree_items(self, root_item):
        yield root_item
        for idx in range(root_item.childCount()):
            child = root_item.child(idx)
            yield from self._iter_subtree_items(child)

    def expand_selected_subtrees(self):
        selected = self.details_tree.selectedItems()
        if not selected:
            return
        for item in selected:
            for node in self._iter_subtree_items(item):
                self.details_tree.expandItem(node)

    def collapse_selected_subtrees(self):
        selected = self.details_tree.selectedItems()
        if not selected:
            return
        for item in selected:
            for node in self._iter_subtree_items(item):
                self.details_tree.collapseItem(node)

    def expand_all_details(self):
        self.details_tree.expandAll()

    def collapse_all_details(self):
        self.details_tree.collapseAll()

    def _apply_conversation_highlight_to_row(self, row: int):
        rec_idx = self._record_index_for_visible_row(row)
        if rec_idx < 0:
            return
        highlighted = rec_idx in self._conversation_highlight_indexes
        for col in range(self.table.columnCount()):
            item = self.table.item(row, col)
            if item is None:
                continue
            if highlighted:
                item.setBackground(self._conversation_highlight_color)

    def _apply_visible_conversation_highlight(self):
        if not self._conversation_highlight_indexes:
            return
        for row, rec_idx in enumerate(self.visible_indices):
            if rec_idx in self._conversation_highlight_indexes:
                self._apply_conversation_highlight_to_row(int(row))

    def clear_conversation_highlight(self):
        if not self._conversation_highlight_indexes:
            return
        self._conversation_highlight_indexes.clear()
        self._refresh_all_visible_row_styles()

    def set_conversation_highlight(self, record_indexes, color: QColor | None = None):
        normalized_indexes = set()
        for index in (record_indexes or []):
            try:
                value = int(index)
            except Exception:
                continue
            if 0 <= value < len(self.records):
                normalized_indexes.add(value)
        self._conversation_highlight_indexes = normalized_indexes
        if color is not None:
            self._conversation_highlight_color = QColor(color)
        self._refresh_all_visible_row_styles()

    def apply_pane_layout(self, layout_name: str):
        mode = self._normalize_layout_name(layout_name)
        self._current_pane_layout = mode
        pane_widgets = [self._pane_widget(key, idx) for idx, key in enumerate(self._pane_assignments)]

        # Detach current arrangement before rebuilding.
        self._clear_splitter(self.main_splitter)
        self._clear_splitter(self.lower_splitter)
        self.main_splitter.setChildrenCollapsible(False)
        self.lower_splitter.setChildrenCollapsible(False)

        if mode == 'Layout 1':
            self.main_splitter.setOrientation(Qt.Vertical)
            for widget in pane_widgets:
                self.main_splitter.addWidget(widget)
            self.main_splitter.setSizes([360, 280, 280])
            return

        if mode == 'Layout 2':
            # Pane 1 on top, Pane 2 + Pane 3 below.
            self.lower_splitter.setOrientation(Qt.Horizontal)
            self.lower_splitter.addWidget(pane_widgets[1])
            self.lower_splitter.addWidget(pane_widgets[2])
            self.lower_splitter.setSizes(self.default_lower_splitter_sizes)

            self.main_splitter.setOrientation(Qt.Vertical)
            self.main_splitter.addWidget(pane_widgets[0])
            self.main_splitter.addWidget(self.lower_splitter)
            self.main_splitter.setSizes(self.default_main_splitter_sizes)
            return

        if mode == 'Layout 3':
            # Pane 1 + Pane 2 on top, Pane 3 below.
            self.lower_splitter.setOrientation(Qt.Horizontal)
            self.lower_splitter.addWidget(pane_widgets[0])
            self.lower_splitter.addWidget(pane_widgets[1])
            self.lower_splitter.setSizes(self.default_lower_splitter_sizes)

            self.main_splitter.setOrientation(Qt.Vertical)
            self.main_splitter.addWidget(self.lower_splitter)
            self.main_splitter.addWidget(pane_widgets[2])
            self.main_splitter.setSizes(self.default_main_splitter_sizes)
            return

        if mode == 'Layout 4':
            # Pane 1 left, Pane 2 top-right, Pane 3 bottom-right.
            self.lower_splitter.setOrientation(Qt.Vertical)
            self.lower_splitter.addWidget(pane_widgets[1])
            self.lower_splitter.addWidget(pane_widgets[2])
            self.lower_splitter.setSizes([260, 260])

            self.main_splitter.setOrientation(Qt.Horizontal)
            self.main_splitter.addWidget(pane_widgets[0])
            self.main_splitter.addWidget(self.lower_splitter)
            self.main_splitter.setSizes([520, 520])
            return

        if mode == 'Layout 5':
            # Pane 1 top-left, Pane 2 bottom-left, Pane 3 right.
            self.lower_splitter.setOrientation(Qt.Vertical)
            self.lower_splitter.addWidget(pane_widgets[0])
            self.lower_splitter.addWidget(pane_widgets[1])
            self.lower_splitter.setSizes([260, 260])

            self.main_splitter.setOrientation(Qt.Horizontal)
            self.main_splitter.addWidget(self.lower_splitter)
            self.main_splitter.addWidget(pane_widgets[2])
            self.main_splitter.setSizes([520, 520])
            return

        # Layout 6: Pane 1 | Pane 2 | Pane 3 side-by-side.
        self.main_splitter.setOrientation(Qt.Horizontal)
        for widget in pane_widgets:
            self.main_splitter.addWidget(widget)
        self.main_splitter.setSizes([420, 320, 420])

    def _show_filter_history_menu(self):
        pos = self.display_filter_input.mapToGlobal(self.display_filter_input.rect().bottomRight())
        self.filter_history_menu.exec(pos)

    def _apply_filter_from_history(self, expr: str):
        self.display_filter_input.setText(expr)
        self.apply_display_filter()

    def start_capture(self):
        if self._is_stopping:
            return
        if self.sniffer and self.sniffer.isRunning():
            return
        iface_cfg = getattr(self, 'interface_config', {}) if isinstance(getattr(self, 'interface_config', {}), dict) else {}
        promisc_cfg = iface_cfg.get('promiscuous', None)
        if promisc_cfg is None:
            promisc_cfg = self._settings().value('capture/promiscuous_mode', True, bool)
        promiscuous = bool(promisc_cfg)
        if self._is_pipe_interface(self.iface):
            promiscuous = False
        effective_filter = self._resolve_capture_filter_alias(self.capture_filter)
        # Use RemotePacketSniffer if iface is remote://
        if str(self.iface).startswith('remote://'):
            from core.capture import RemotePacketSniffer
            self.sniffer = RemotePacketSniffer(self.iface, effective_filter, promiscuous=promiscuous)
        else:
            self.sniffer = PacketSniffer(self.iface, effective_filter, promiscuous=promiscuous)
        self.capture_filter = effective_filter
        self._capture_started_at = time.monotonic()
        self._captured_bytes = 0
        self._auto_output_written_files = []
        self._auto_output_base_path = self._build_auto_output_path()
        self._rollover_file_counter = 0
        self._protocol_counts = {}
        self.sniffer.packet_captured.connect(self.add_packet)
        self.sniffer.error_occurred.connect(self.on_sniffer_error)
        self.sniffer.status_changed.connect(self._update_status)
        self.sniffer.finished.connect(self._on_sniffer_finished)
        self.sniffer.start()
        self.capture_state_changed.emit(True)
        self._update_status('Live capture')

        # Open Capture Information window if enabled
        if bool((self.options_settings or {}).get('show_info', False)):
            self._open_capture_info_dialog()

    def _resolve_capture_filter_alias(self, expression: str) -> str:
        expr = str(expression or '').strip()
        if not expr:
            return ''
        try:
            raw = str(self._settings().value('capture/filter_presets', '[]', str) or '[]')
            presets = json.loads(raw)
        except Exception:
            return expr
        if not isinstance(presets, list):
            return expr
        lookup = {}
        for item in presets:
            if not isinstance(item, dict):
                continue
            name = str(item.get('name', '') or '').strip()
            value = str(item.get('expression', '') or '').strip()
            if name and value:
                lookup[name.casefold()] = value
        return lookup.get(expr.casefold(), expr)


    def stop_capture(self):
        if self.sniffer and self.sniffer.isRunning() and not self._is_stopping:
            self._is_stopping = True
            # Update UI immediately; thread shutdown completes asynchronously.
            self.capture_state_changed.emit(False)
            self._update_status('Capture stopping...')
            # Reduce queued UI work on high-traffic captures.
            try:
                self.sniffer.packet_captured.disconnect(self.add_packet)
            except Exception:
                pass
            try:
                self.sniffer.status_changed.disconnect(self._update_status)
            except Exception:
                pass
            self.sniffer.stop()
            return

        if not self.sniffer or not self.sniffer.isRunning():
            self.sniffer = None
            self._is_stopping = False
            if not self.realtime_update_enabled:
                self.apply_display_filter()
            self.capture_state_changed.emit(False)
            self._update_status('Capture stopped')

    def restart_capture(self):
        self.stop_capture()
        self.clear_packets(reset_file_path=True)
        self.start_capture()

    def start_new_capture(self):
        self.stop_capture()
        self.clear_packets(reset_file_path=True)
        self.start_capture()

    def is_capturing(self):
        return self.sniffer and self.sniffer.isRunning()

    def is_stopping(self) -> bool:
        return bool(self._is_stopping)

    def has_packets(self) -> bool:
        if self._show_file_format_view and self._file_format_record is not None:
            return True
        return len(self.records) > 0

    def _open_capture_info_dialog(self):
        if self._capture_info_dialog is None:
            self._capture_info_dialog = CaptureInformationDialog(self.window())
            self._capture_info_dialog.stop_requested.connect(self.stop_capture)
        self._capture_info_dialog.reset()
        self._capture_info_dialog.show()
        self._capture_info_dialog.raise_()

    def _close_capture_info_dialog(self):
        if self._capture_info_dialog is not None:
            self._capture_info_dialog.hide()


    def clear_packets(self, reset_file_path: bool = False):
        self._stop_file_load_thread()
        self._is_bulk_loading = False
        self._startup_priority_mode = False
        self._stop_refine_thread()
        self._show_file_format_view = False
        self._file_format_record = None
        self._file_format_raw_bytes = b''
        self.records.clear()
        self.visible_indices.clear()
        self._reset_visible_row_lookup()
        self._selected_record_index = -1
        self._packet_history = []
        self._history_index = -1
        self.table.setRowCount(0)
        timer = getattr(self, '_packet_list_aux_refresh_timer', None)
        if timer is not None:
            timer.stop()
        self._pending_related_indicator_refresh = False
        self._pending_minimap_refresh = False
        self._clear_related_packet_indicators()
        self.details_tree.show_packet(None)
        self.hex_view.show_packet(None)
        self.parser = PacketParser()
        self._configure_parser_capture_context(self.parser, '')
        self.capture_comments = ''
        self.capture_metadata = None
        self._packet_state_by_number = {}
        self._captured_bytes = 0
        self._capture_started_at = None
        self._last_live_status_count = 0
        self._auto_output_written_files = []
        self._auto_output_base_path = ''
        self._rollover_file_counter = 0
        self._set_dirty(False)
        if reset_file_path:
            self.loaded_file_path = None
        self._update_packet_minimap()
        self._emit_go_state_changed()

    def _stop_refine_thread(self):
        self._refine_stop.set()
        self._refine_timer.stop()
        try:
            if self._refine_thread is not None and self._refine_thread.is_alive():
                self._refine_thread.join(timeout=0.2)
        except Exception:
            pass
        self._refine_thread = None
        self._refine_stop = threading.Event()
        while True:
            try:
                self._refine_queue.get_nowait()
            except Exception:
                break

    def _stop_file_load_thread(self):
        self._file_load_stop.set()
        self._file_load_timer.stop()
        self._visible_append_timer.stop()
        try:
            if self._file_load_thread is not None and self._file_load_thread.is_alive():
                self._file_load_thread.join(timeout=0.2)
        except Exception:
            pass
        self._file_load_thread = None
        self._file_load_stop = threading.Event()
        self._file_load_filter_expr = ''
        self._file_load_requires_filter_rebuild = False
        self._file_load_loaded_count = 0
        self._file_load_last_status_count = 0
        self._file_load_error_message = ''
        self._file_load_done_pending_finalize = False
        self._visible_append_queue.clear()
        while True:
            try:
                self._file_load_queue.get_nowait()
            except Exception:
                break

    def _enqueue_file_load_item(self, item, stop_event: threading.Event) -> bool:
        while not stop_event.is_set():
            try:
                self._file_load_queue.put(item, timeout=0.05)
                return True
            except queue.Full:
                continue
        return False

    def _start_background_file_load(self, packet_iter, start_index: int, display_expr: str, no_filter: bool):
        self._stop_file_load_thread()
        self._file_load_filter_expr = str(display_expr or '')
        self._file_load_requires_filter_rebuild = False
        self._file_load_loaded_count = max(0, int(start_index) - 1)
        self._file_load_last_status_count = self._file_load_loaded_count
        self._file_load_error_message = ''
        self._is_bulk_loading = True
        stop_event = self._file_load_stop

        def worker():
            parser = PacketParser()
            self._configure_parser_capture_context(parser, str(self.loaded_file_path or ''))
            matcher = DisplayFilter()
            index = max(0, int(start_index) - 1)
            batch = []
            has_custom_columns = bool(self.table.columnCount() > 7)
            # Smaller UI batches prevent long main-thread pauses while custom columns exist.
            batch_size = 80 if has_custom_columns else 400
            try:
                for packet in packet_iter:
                    if stop_event.is_set():
                        break
                    index += 1
                    try:
                        record = parser.parse_fast(packet, index)
                    except Exception:
                        continue
                    matched = bool(no_filter) or bool(matcher.matches(record, display_expr))
                    batch.append((record, matched))
                    if len(batch) >= batch_size:
                        payload = list(batch)
                        batch.clear()
                        if not self._enqueue_file_load_item(('batch', payload), stop_event):
                            return
                if batch and not stop_event.is_set():
                    if not self._enqueue_file_load_item(('batch', list(batch)), stop_event):
                        return
                self._enqueue_file_load_item(('done', index), stop_event)
            except Exception as exc:
                self._enqueue_file_load_item(('error', str(exc or 'unknown load error')), stop_event)
                self._enqueue_file_load_item(('done', index), stop_event)

        self._file_load_thread = threading.Thread(target=worker, daemon=True)
        self._file_load_thread.start()
        self._file_load_timer.start()

    def _consume_loaded_batch(self, batch):
        if not batch:
            return
        current_expr = self._expand_display_filter_macros(self.display_filter_input.text())
        filter_unchanged = current_expr == self._file_load_filter_expr
        append_visible = []

        for record, matched in batch:
            applied = self._apply_capture_metadata_to_record(record, int(getattr(record, 'number', 0) or 0))
            self.records.append(applied)
            rec_idx = len(self.records) - 1
            if filter_unchanged:
                if bool(matched):
                    self.visible_indices.append(rec_idx)
                    append_visible.append((applied, rec_idx))
            else:
                self._file_load_requires_filter_rebuild = True

        self._file_load_loaded_count = len(self.records)
        if filter_unchanged and append_visible:
            self._visible_append_queue.extend(append_visible)
            if not self._visible_append_timer.isActive():
                self._visible_append_timer.start()
        if self.table.rowCount() > 0 and self.table.currentRow() < 0:
            self.table.selectRow(0)
            self.table.setCurrentCell(0, 0)
            self.table.setFocus()
            self._schedule_packet_list_aux_refresh(related=True, minimap=False)

    def _drain_visible_append_queue(self):
        if not self._visible_append_queue:
            self._visible_append_timer.stop()
            if bool(self._file_load_done_pending_finalize):
                self._file_load_done_pending_finalize = False
                self._finalize_background_file_load()
            return
        table = self.table
        max_rows = 40
        if bool(self._startup_priority_mode):
            max_rows = 10
        elif table.columnCount() > 7:
            max_rows = 16
        try:
            scrollbar = table.verticalScrollBar()
            if scrollbar is not None and bool(scrollbar.isSliderDown()):
                max_rows = max(6, int(max_rows // 2))
        except Exception:
            pass
        chunk = []
        while self._visible_append_queue and len(chunk) < max_rows:
            chunk.append(self._visible_append_queue.popleft())
        if not chunk:
            return
        start_row = int(table.rowCount() or 0)
        records = [pair[0] for pair in chunk]
        rec_indices = [int(pair[1]) for pair in chunk]
        table.setUpdatesEnabled(False)
        try:
            table.append_records(records)
        finally:
            table.setUpdatesEnabled(True)
        for rel, rec_idx in enumerate(rec_indices):
            self._visible_row_lookup[int(rec_idx)] = int(start_row + rel)
        if bool(self._startup_priority_mode):
            self._force_visible_feedback_now(minimap_data_changed=True)
        else:
            self._schedule_packet_list_aux_refresh(minimap=True, minimap_data_changed=True)
        if table.rowCount() > 0 and table.currentRow() < 0:
            table.selectRow(0)
            table.setCurrentCell(0, 0)
            table.setFocus()
            if bool(self._startup_priority_mode):
                self._force_visible_feedback_now(minimap_data_changed=False)
            else:
                self._schedule_packet_list_aux_refresh(related=True, minimap=False)

    def _finalize_background_file_load(self):
        self._file_load_timer.stop()
        self._visible_append_timer.stop()
        self._file_load_thread = None
        self._is_bulk_loading = False
        self._startup_priority_mode = False
        self._set_dirty(False)
        self._remember_recent_file(self.loaded_file_path)
        self._rebuild_visible_row_lookup()
        if self.table.rowCount() > 0 and self.table.currentRow() < 0:
            self.table.selectRow(0)
            self.table.setCurrentCell(0, 0)
            self.table.setFocus()
        if self._file_load_requires_filter_rebuild:
            self.apply_display_filter()
        else:
            self.display_filter_applied.emit()
            self._emit_go_state_changed()
            self._schedule_packet_list_aux_refresh(minimap=True, minimap_data_changed=True)
            self._schedule_packet_list_aux_refresh(related=True, minimap=False)
        self._start_refine_thread()
        warning = str(self._file_load_error_message or '').strip()
        if warning:
            self._update_status(f'Loaded {len(self.records)} packets with warning: {warning}')
        else:
            self._update_status(f'Loaded {len(self.records)} packets from {self.loaded_file_path}')

    def _drain_file_load_queue(self):
        done = False
        start = time.perf_counter()
        max_batches = 3
        max_tick_seconds = 0.008
        if bool(self._startup_priority_mode):
            max_batches = 1
            max_tick_seconds = 0.0022
        if self.table.columnCount() > 7:
            # Keep the UI responsive when custom columns are present.
            max_batches = 1
            max_tick_seconds = 0.003
        try:
            scrollbar = self.table.verticalScrollBar()
            if scrollbar is not None and bool(scrollbar.isSliderDown()):
                max_batches = 1
                max_tick_seconds = 0.003
        except Exception:
            pass
        processed_batches = 0
        while processed_batches < max_batches and (time.perf_counter() - start) < max_tick_seconds:
            try:
                item = self._file_load_queue.get_nowait()
            except Exception:
                break
            if not item:
                continue
            kind = str(item[0] or '')
            if kind == 'batch':
                self._consume_loaded_batch(item[1])
                processed_batches += 1
                continue
            if kind == 'error':
                self._file_load_error_message = str(item[1] or '')
                continue
            if kind == 'done':
                done = True
                break

        loaded = int(self._file_load_loaded_count or len(self.records))
        if loaded - int(self._file_load_last_status_count or 0) >= 500:
            self._file_load_last_status_count = loaded
            self._update_status(f'Loaded {loaded} packets...')

        if done:
            self._file_load_done_pending_finalize = True
            if not self._visible_append_queue:
                self._file_load_done_pending_finalize = False
                self._finalize_background_file_load()
            elif not self._visible_append_timer.isActive():
                self._visible_append_timer.start()

    def _start_refine_thread(self):
        self._stop_refine_thread()
        if not self.records:
            return

        snapshot = list(self.records)
        index_by_frame = {int(getattr(rec, 'number', 0) or 0): idx for idx, rec in enumerate(snapshot)}
        stop_event = self._refine_stop
        out_q = self._refine_queue

        def worker():
            parser = PacketParser()
            self._configure_parser_capture_context(parser, str(self.loaded_file_path or ''))
            parsed_by_frame = {}

            def _enqueue(item):
                while not stop_event.is_set():
                    try:
                        out_q.put(item, timeout=0.05)
                        return True
                    except queue.Full:
                        continue
                return False

            for idx, fast_record in enumerate(snapshot):
                if stop_event.is_set():
                    break
                metadata = getattr(fast_record, 'metadata', {}) or {}
                if bool(metadata.get('full_preloaded', False)):
                    continue
                try:
                    full_record = parser.parse(fast_record.raw, int(fast_record.number), fast_record.iface)
                except Exception:
                    continue
                parsed_by_frame[int(full_record.number)] = full_record
                if not _enqueue((idx, full_record)):
                    break
                segments = list(full_record.metadata.get('tcp_reassembled_segments', []) or [])
                if len(segments) > 1:
                    for segment in segments[:-1]:
                        seg_frame = int(segment.get('frame_number', 0) or 0)
                        seg_idx = index_by_frame.get(seg_frame, -1)
                        seg_record = parsed_by_frame.get(seg_frame)
                        if seg_idx >= 0 and seg_record is not None:
                            if not _enqueue((seg_idx, seg_record)):
                                break
            _enqueue((-1, None))

        self._refine_thread = threading.Thread(target=worker, daemon=True)
        self._refine_thread.start()
        self._refine_timer.start()

    def _update_table_row_from_record(self, row: int, record):
        if hasattr(self.table, '_populate_row_from_record'):
            self.table._populate_row_from_record(row, record, clear_extra_columns=False)
        else:
            values = self.table.display_values(record)
            for col, value in enumerate(values):
                item = self.table.item(row, col)
                if item is not None:
                    item.setText(value)
        self.table._store_row_state(row, record)
        self.table._paint_row(row, record)
        self._apply_conversation_highlight_to_row(row)

    def _drain_refine_queue(self):
        processed = 0
        started = time.perf_counter()
        visible_row_by_index = self._visible_row_lookup
        pending_row_updates = []
        changed_rows = set()
        selected_refresh_record = None
        reached_end = False
        max_rows = int(self._refine_max_rows_per_tick)
        max_tick_seconds = float(self._refine_max_tick_seconds)
        startup_priority = bool(self._startup_priority_mode)
        if startup_priority:
            max_rows = min(max_rows, 6)
            max_tick_seconds = min(max_tick_seconds, 0.0012)
        if self.table.columnCount() > 7:
            # With custom columns, keep refine ticks short to avoid post-load hitching.
            max_rows = min(max_rows, 20)
            max_tick_seconds = min(max_tick_seconds, 0.0025)
        try:
            scrollbar = self.table.verticalScrollBar()
            if scrollbar is not None and bool(scrollbar.isSliderDown()):
                max_rows = max(8, int(max_rows // 3))
                max_tick_seconds = min(max_tick_seconds, 0.002)
        except Exception:
            pass
        while processed < max_rows:
            if (time.perf_counter() - started) >= max_tick_seconds:
                break
            try:
                idx, full_record = self._refine_queue.get_nowait()
            except Exception:
                break
            if idx == -1:
                reached_end = True
                break
            if full_record is None or idx < 0 or idx >= len(self.records):
                continue
            applied = self._apply_capture_metadata_to_record(full_record, int(full_record.number))
            self.records[idx] = applied
            # Update row only if currently visible.
            row = visible_row_by_index.get(idx, -1)
            if row >= 0:
                if (not startup_priority) or (idx == self._selected_record_index):
                    pending_row_updates.append((int(row), applied))
                    changed_rows.add(int(row))
            if idx == self._selected_record_index:
                selected_refresh_record = applied
            processed += 1
        if pending_row_updates:
            self.table.setUpdatesEnabled(False)
            try:
                for row, record in pending_row_updates:
                    self._update_table_row_from_record(row, record)
            finally:
                self.table.setUpdatesEnabled(True)
        if selected_refresh_record is not None:
            # Selected packet should refresh as soon as full parse is available.
            self.details_tree.show_packet(selected_refresh_record)
            self.hex_view.show_packet(selected_refresh_record)
        if processed > 0 and changed_rows:
            self.records_refined.emit(sorted(changed_rows))
            self._schedule_packet_list_aux_refresh(minimap=True, minimap_data_changed=True)
        if reached_end:
            self._refine_timer.stop()

    def _rollover_live_output_if_needed(self):
        output = self.output_settings or {}
        if not bool(output.get('auto_create')):
            return
        if not self._has_auto_create_rollover_condition():
            return
        if not self.records:
            return

        current_bytes = sum(int(r.length) for r in self.records)
        if not self._should_rollover_chunk(self.records, current_bytes):
            return

        file_format = self._capture_output_format()
        compression = self._capture_compression()
        target_path = self._next_output_target_path(self.records, auto_create_mode=True)

        saved_path = self._persist_capture_records(self.records, target_path, file_format, compression)
        self._auto_output_written_files.append(saved_path)
        self._apply_ring_buffer_limit()

        # Switch GUI packet list to the new active file: clear old file packets from table.
        self.records.clear()
        self.visible_indices.clear()
        self._reset_visible_row_lookup()
        self.table.setRowCount(0)
        self._clear_related_packet_indicators()
        self.details_tree.show_packet(None)
        self.hex_view.show_packet(None)
        self.parser = PacketParser()
        self._configure_parser_capture_context(self.parser, '')
        self.capture_metadata = None
        self._captured_bytes = 0
        self._last_live_status_count = 0
        self._set_dirty(False)
        self._schedule_packet_list_aux_refresh(minimap=True, minimap_data_changed=True)

        # Keep window/file name as the last written file (newest completed file).
        self.loaded_file_path = saved_path
        self._remember_recent_file(saved_path)
        self._update_status(f'Rollover completed. New file segment started after {saved_path}')

    def on_sniffer_error(self, msg):
        QMessageBox.critical(None, 'Capture error', msg)
        self.stop_capture()

    def _on_sniffer_finished(self):
        self.sniffer = None
        self._is_stopping = False

        file_path_cfg = str((self.output_settings or {}).get('file_path', '') or '').strip()
        auto_create_cfg = bool((self.output_settings or {}).get('auto_create', False))
        should_auto_save = bool(self.records) and (bool(file_path_cfg) or auto_create_cfg)

        if should_auto_save:
            try:
                self._auto_save_capture_output()
            except Exception as exc:
                self._update_status(f'Auto-save failed: {exc}')

        if not self.realtime_update_enabled:
            self.apply_display_filter()
        self.capture_state_changed.emit(False)
        self._update_status('Capture stopped')
        self._close_capture_info_dialog()

    def add_packet(self, packet):
        if self._is_stopping:
            return
        record = self.parser.parse(packet, len(self.records) + 1, self.iface)
        self.records.append(record)
        self._set_dirty(True)
        raw_len = len(record.raw) if getattr(record, 'raw', None) is not None else 0
        self._captured_bytes += raw_len

        if self.realtime_update_enabled and self.display_filter.matches(record, self.display_filter_input.text()):
            self.visible_indices.append(len(self.records) - 1)
            self._visible_row_lookup[int(len(self.records) - 1)] = int(len(self.visible_indices) - 1)
            self.table.append_record(record)
            if self.auto_scroll_enabled:
                self.table.scrollToBottom()
            self._schedule_packet_list_aux_refresh(minimap=True, minimap_data_changed=True)

        # Update Capture Information dialog
        if self._capture_info_dialog is not None and self._capture_info_dialog.isVisible():
            proto = getattr(record, 'protocol', None) or 'Other'
            self._protocol_counts[proto] = self._protocol_counts.get(proto, 0) + 1
            self._capture_info_dialog.update_protocol(proto, self._protocol_counts[proto])

        # Throttle expensive status recomputation during live capture.
        current_count = len(self.records)
        if current_count - self._last_live_status_count >= 20:
            self._last_live_status_count = current_count
            self._update_status('Live capture')

        self._rollover_live_output_if_needed()

        if self._should_stop_capture():
            self.stop_capture()

        self._emit_go_state_changed()

    def _should_stop_capture(self) -> bool:
        """Evaluate stop conditions from Options tab settings"""
        opts = self.options_settings or {}

        if opts.get('stop_packets_enabled'):
            packet_limit = int(opts.get('stop_packets_value', 1) or 1)
            if len(self.records) >= packet_limit:
                return True

        if opts.get('stop_size_enabled'):
            size_limit = int(opts.get('stop_size_value', 1) or 1)
            size_unit = str(opts.get('stop_size_unit', 'kilobytes'))
            multiplier = {
                'kilobytes': 1024,
                'megabytes': 1024 * 1024,
                'gigabytes': 1024 * 1024 * 1024,
            }.get(size_unit, 1024)
            if self._captured_bytes >= size_limit * multiplier:
                return True

        if opts.get('stop_duration_enabled'):
            duration_limit = int(opts.get('stop_duration_value', 1) or 1)
            duration_unit = str(opts.get('stop_duration_unit', 'seconds'))
            seconds = duration_limit
            if duration_unit == 'minutes':
                seconds *= 60
            elif duration_unit == 'hours':
                seconds *= 3600
            if self._capture_started_at is not None and (time.monotonic() - self._capture_started_at) >= seconds:
                return True

        return False

    def apply_display_filter(self):
        if self._visible_append_queue:
            self._visible_append_queue.clear()
            self._visible_append_timer.stop()
            self._file_load_done_pending_finalize = False
        if self._show_file_format_view and self._file_format_record is not None:
            self.table.replace_records([self._file_format_record])
            self._reset_visible_row_lookup()
            self._update_status('File format mode is active')
            self.display_filter_applied.emit()
            self._emit_go_state_changed()
            self._clear_related_packet_indicators()
            self._schedule_packet_list_aux_refresh(minimap=True, minimap_data_changed=True)
            return
        self.visible_indices.clear()
        expr = self._expand_display_filter_macros(self.display_filter_input.text())
        if expr != str(self.display_filter_input.text() or ''):
            self.display_filter_input.setText(expr)
        self._remember_filter(expr)
        visible_records = []
        for idx, record in enumerate(self.records):
            if self.display_filter.matches(record, expr):
                self.visible_indices.append(idx)
                visible_records.append(record)
        self._rebuild_visible_row_lookup()
        self.table.replace_records(visible_records)
        if getattr(self.table, '_color_rules_enabled', self.color_rules_enabled) != self.color_rules_enabled:
            self.table.set_color_rules_enabled(self.color_rules_enabled)
        self._apply_visible_conversation_highlight()
        self._update_status('Display filter applied')
        self.display_filter_applied.emit()
        self._schedule_packet_list_aux_refresh(related=True, minimap=True, minimap_data_changed=True)
        self._emit_go_state_changed()

    def _update_packet_minimap(self):
        minimap = getattr(self, 'packet_minimap', None)
        if minimap is None:
            return
        try:
            if bool(self._minimap_cache_dirty) and hasattr(minimap, 'invalidate_cache'):
                minimap.invalidate_cache()
                self._minimap_cache_dirty = False
            if (not minimap.isVisible()) or (minimap.height() != self.table.viewport().height()):
                self._layout_packet_minimap_overlay()
            minimap.update()
        except Exception:
            pass

    def _force_visible_feedback_now(self, minimap_data_changed: bool = False):
        if minimap_data_changed:
            self._minimap_cache_dirty = True
        self._set_selected_indicator_immediate()
        # Keep immediate feedback lightweight; related-arrows are resolved asynchronously.
        self._update_packet_minimap()
        try:
            self.table.verticalHeader().viewport().repaint()
        except Exception:
            pass
        minimap = getattr(self, 'packet_minimap', None)
        if minimap is not None:
            try:
                minimap.repaint()
            except Exception:
                pass

    def _schedule_packet_list_aux_refresh(self, related: bool = False, minimap: bool = False, minimap_data_changed: bool = False):
        if bool(getattr(self, '_startup_priority_mode', False)) and (bool(related) or bool(minimap)):
            # Startup UX-first: render what user sees immediately.
            self._force_visible_feedback_now(minimap_data_changed=bool(minimap_data_changed))
            return
        if bool(related):
            self._pending_related_indicator_refresh = True
        if bool(minimap):
            self._pending_minimap_refresh = True
        if bool(minimap_data_changed):
            self._minimap_cache_dirty = True
        if not (self._pending_related_indicator_refresh or self._pending_minimap_refresh):
            return
        start_delay_ms = 0
        if bool(minimap) and not bool(related):
            try:
                if bool(self._is_bulk_loading) and int(self.table.rowCount() or 0) > 50:
                    now = time.monotonic()
                    min_interval = float(self._minimap_refresh_interval_during_bulk)
                    elapsed = float(now - float(self._last_minimap_refresh_monotonic))
                    if elapsed < min_interval:
                        start_delay_ms = int(max(1.0, (min_interval - elapsed) * 1000.0))
            except Exception:
                start_delay_ms = 0
        timer = getattr(self, '_packet_list_aux_refresh_timer', None)
        if timer is None:
            try:
                timer = QTimer(self)
                timer.setSingleShot(True)
                timer.setInterval(8)
                timer.timeout.connect(self._flush_packet_list_aux_refresh)
                self._packet_list_aux_refresh_timer = timer
            except Exception:
                self._flush_packet_list_aux_refresh()
                return
        try:
            is_active = bool(timer.isActive())
        except RuntimeError:
            try:
                timer = QTimer(self)
                timer.setSingleShot(True)
                timer.setInterval(8)
                timer.timeout.connect(self._flush_packet_list_aux_refresh)
                self._packet_list_aux_refresh_timer = timer
                is_active = False
            except Exception:
                self._flush_packet_list_aux_refresh()
                return
        if is_active:
            return
        try:
            if start_delay_ms > 0:
                timer.start(start_delay_ms)
            else:
                timer.start()
        except RuntimeError:
            # QObject is being torn down; skip scheduling safely.
            pass

    def _flush_packet_list_aux_refresh(self):
        refresh_related = bool(self._pending_related_indicator_refresh)
        refresh_minimap = bool(self._pending_minimap_refresh)
        self._pending_related_indicator_refresh = False
        self._pending_minimap_refresh = False
        if refresh_related:
            self._update_related_packet_indicators()
        if refresh_minimap:
            self._last_minimap_refresh_monotonic = time.monotonic()
            self._update_packet_minimap()

    def _clear_related_packet_indicators(self):
        self._related_indicator_rows = {}
        self._last_related_indicator_signature = None
        if hasattr(self.table, 'set_related_indicators'):
            self.table.set_related_indicators({})

    def _set_selected_indicator_immediate(self):
        if hasattr(self.table, 'set_selected_indicator_immediate'):
            row = self.get_current_visible_row()
            if row >= 0 and row < int(self.table.rowCount() or 0):
                try:
                    self.table.set_selected_indicator_immediate(int(row), '◆')
                    return
                except Exception:
                    pass
        if not hasattr(self.table, 'set_related_indicators'):
            return
        row = self.get_current_visible_row()
        if row < 0 or row >= int(self.table.rowCount() or 0):
            return
        indicators = {int(row): '◆'}
        self._related_indicator_rows = indicators
        self._last_related_indicator_signature = None
        self.table.set_related_indicators(indicators)

    def _relation_arrow_for_rows(self, selected_record, candidate_record) -> str:
        sel_src = str(getattr(selected_record, 'src', '') or '')
        sel_dst = str(getattr(selected_record, 'dst', '') or '')
        cur_src = str(getattr(candidate_record, 'src', '') or '')
        cur_dst = str(getattr(candidate_record, 'dst', '') or '')
        if sel_src and sel_dst and cur_src and cur_dst:
            if cur_src == sel_src and cur_dst == sel_dst:
                return '→'
            if cur_src == sel_dst and cur_dst == sel_src:
                return '←'
        return '┆'

    def _update_related_packet_indicators(self):
        if self._show_file_format_view and self._file_format_record is not None:
            self._clear_related_packet_indicators()
            return
        if not hasattr(self.table, 'set_related_indicators'):
            return
        row_count = int(self.table.rowCount() or 0)
        if row_count <= 0 or not self.visible_indices:
            self._clear_related_packet_indicators()
            return
        selected_row = self.get_current_visible_row()
        if selected_row < 0 or selected_row >= len(self.visible_indices):
            self._clear_related_packet_indicators()
            return
        selected_record = self.get_current_record()
        if selected_record is None:
            self._clear_related_packet_indicators()
            return
        if bool(self._is_bulk_loading):
            indicators = {int(selected_row): '◆'}
            self._related_indicator_rows = indicators
            self._last_related_indicator_signature = (
                int(selected_row),
                int(getattr(selected_record, 'number', 0) or 0),
                int(len(self.visible_indices)),
                int(self.table.rowCount() or 0),
                'bulk_selected_only',
            )
            self.table.set_related_indicators(indicators)
            return
        signature = (
            int(selected_row),
            int(getattr(selected_record, 'number', 0) or 0),
            int(len(self.visible_indices)),
            int(self.table.rowCount() or 0),
            int(self.visible_indices[0]) if self.visible_indices else -1,
            int(self.visible_indices[-1]) if self.visible_indices else -1,
        )
        if signature == self._last_related_indicator_signature and self._related_indicator_rows:
            return

        indicators = {}
        conv_rows = self._conversation_rows_for_current()
        if not conv_rows:
            indicators[selected_row] = '◆'
            self._related_indicator_rows = indicators
            self._last_related_indicator_signature = signature
            self.table.set_related_indicators(indicators)
            return

        first_row = int(conv_rows[0])
        last_row = int(conv_rows[-1])
        for row in conv_rows:
            row = int(row)
            rec_idx = self._record_index_for_visible_row(row)
            if rec_idx < 0:
                continue
            record = self.records[rec_idx]
            symbol = self._relation_arrow_for_rows(selected_record, record)
            if row == first_row and symbol == '┆':
                symbol = '┌'
            if row == last_row and symbol == '┆':
                symbol = '└'
            indicators[row] = symbol

        indicators[int(selected_row)] = '◆'
        corresponding_frame = self._first_corresponding_frame(selected_record)
        if corresponding_frame is not None:
            corr_row = self._visible_row_for_packet_number(int(corresponding_frame))
            if corr_row >= 0 and corr_row != selected_row:
                indicators[int(corr_row)] = '↔'

        self._related_indicator_rows = indicators
        self._last_related_indicator_signature = signature
        self.table.set_related_indicators(indicators)

    def _on_packet_table_selection_changed(self):
        self._set_selected_indicator_immediate()
        self._schedule_packet_list_aux_refresh(related=True, minimap=False)
        minimap = getattr(self, 'packet_minimap', None)
        if minimap is not None:
            minimap.update()

    def get_selected_records(self):
        selected_rows = sorted({index.row() for index in self.table.selectionModel().selectedRows()}) if self.table.selectionModel() else []
        records = []
        for row in selected_rows:
            if 0 <= row < len(self.visible_indices):
                rec_idx = self.visible_indices[row]
                if 0 <= rec_idx < len(self.records):
                    records.append(self.records[rec_idx])
        return records

    def get_selected_raw_packets(self):
        packets = []
        for record in self.get_selected_records():
            raw = getattr(record, "raw", None)
            if raw is not None:
                packets.append(raw)
        return packets

    def clear_display_filter(self):
        self.display_filter_input.clear()
        self.apply_display_filter()

    def show_details(self, row, _col, add_to_history: bool = True):
        if self._show_file_format_view and self._file_format_record is not None:
            if row != 0:
                return
            self._selected_record_index = -1
            self.details_tree.show_packet(self._file_format_record)
            self.hex_view.show_packet(self._file_format_record)
            self.detail_status_changed.emit('', 0)
            self._update_status('Selected file format frame')
            self._clear_related_packet_indicators()
            self._schedule_packet_list_aux_refresh(minimap=False)
            self._emit_go_state_changed()
            return
        if row < 0 or row >= len(self.visible_indices):
            return
        record_index = self.visible_indices[row]
        self._selected_record_index = record_index
        record = self.records[record_index]
        if add_to_history:
            self._add_packet_to_history(int(getattr(record, 'number', 0) or 0))
        self.details_tree.show_packet(record)
        self.hex_view.show_packet(record)
        self.detail_status_changed.emit('', 0)
        self._update_status(f'Selected frame {record.number}')
        self._set_selected_indicator_immediate()
        self._schedule_packet_list_aux_refresh(related=True, minimap=False)
        minimap = getattr(self, 'packet_minimap', None)
        if minimap is not None:
            minimap.update()
        self._emit_go_state_changed()

    def _on_detail_field_selected(self, field_name: str, byte_count: int):
        self.detail_status_changed.emit(str(field_name or ''), int(byte_count or 0))

    def _on_bytes_range_selected(self, offset: int, length: int, byte_source: str):
        """Handle bytes range selection from hex view -> select and highlight detail"""
        best_item = self._resolve_detail_item_for_range(offset, length, byte_source)
        if best_item:
            self.details_tree.setCurrentItem(best_item)

    def _on_bytes_hovered(self, offset: int, byte_source: str):
        """Hover over bytes should preview full detail field in hex/ascii without changing selection."""
        best_item = self._resolve_detail_item_for_range(offset, 1, byte_source)
        if not best_item:
            self.hex_view.clear_hover_range()
            return

        from PySide6.QtCore import Qt
        data = best_item.data(0, Qt.ItemDataRole.UserRole)
        item_source = str(best_item.data(0, self.details_tree.BYTE_SOURCE_ROLE) or 'packet')
        if isinstance(data, tuple):
            start, item_length = data
            if start >= 0 and item_length > 0:
                self.hex_view.set_hover_range(start, item_length, item_source)
                return

        self.hex_view.clear_hover_range()

    def _on_hex_hover_left(self, byte_source: str):
        self.hex_view.clear_hover_range(byte_source)

    def _resolve_detail_item_for_range(self, offset: int, length: int, byte_source: str = 'packet'):
        """Resolve deepest detail node for a byte range, excluding Frame subtree and bracketed analysis nodes."""
        best_item = None
        best_depth = -1

        def visit(item, depth=0, in_frame_section=False):
            nonlocal best_item, best_depth
            from PySide6.QtCore import Qt

            if in_frame_section:
                return

            data = item.data(0, Qt.ItemDataRole.UserRole)
            item_source = str(item.data(0, self.details_tree.BYTE_SOURCE_ROLE) or 'packet')
            selectable = bool(item.data(0, self.details_tree.BYTE_SELECTABLE_ROLE))
            if isinstance(data, tuple):
                start, item_length = data
                if selectable and item_source == byte_source and start >= 0 and item_length > 0:
                    if start == offset and item_length == length:
                        best_item = item
                        best_depth = depth + 1000
                    elif start <= offset and offset + length <= start + item_length:
                        if depth > best_depth:
                            best_item = item
                            best_depth = depth

            for i in range(item.childCount()):
                visit(item.child(i), depth + 1, in_frame_section)

        root = self.details_tree.invisibleRootItem()
        for i in range(root.childCount()):
            child = root.child(i)
            top_title = child.text(0).strip().lower()
            visit(child, 0, top_title.startswith('frame'))

        return best_item

    def save_file(self, force_dialog: bool = False):
        if not self.records:
            QMessageBox.warning(None, 'Warning', 'Không có packet nào để lưu.')
            return False
        if self.loaded_file_path and not force_dialog:
            if not self._is_dirty:
                self._update_status('No changes to save')
                return True
            file_path = self.loaded_file_path
            lowered = file_path.lower()
            compression = 'none'
            if lowered.endswith('.gz'):
                compression = 'gzip'
            elif lowered.endswith('.lz4'):
                compression = 'lz4'

            fmt_path = file_path
            if compression != 'none':
                fmt_path = os.path.splitext(file_path)[0]
            file_format = 'pcapng' if fmt_path.lower().endswith('.pcapng') else 'pcap'

            save_capture_file(file_path, [r.raw for r in self.records], file_format=file_format, compression=compression)
            self._remember_recent_file(self.loaded_file_path)
            self._set_dirty(False)
            if file_format == 'pcapng':
                self.save_packet_comments_to_file()
            self._update_status(f'Saved to {self.loaded_file_path}')
            return True

        filename, selected_format, selected_compression = self._show_save_with_options_dialog()
        if not filename:
            return False

        saved_path = save_capture_file(
            filename,
            [r.raw for r in self.records],
            file_format=selected_format,
            compression=selected_compression,
        )
        self.loaded_file_path = saved_path
        self._remember_recent_file(saved_path)
        self._set_dirty(False)
        if selected_format == 'pcapng':
            self.save_packet_comments_to_file()
        self._update_status(f'Saved to {saved_path}')
        return True

    def _load_capture_from_path(self, filename: str):
        if not filename:
            return
        self.stop_capture()
        self._stop_file_load_thread()
        self._is_bulk_loading = True
        self._startup_priority_mode = True
        try:
            self.clear_packets(reset_file_path=False)
            self._is_bulk_loading = True
            self.loaded_file_path = filename
            self._configure_parser_capture_context(self.parser, filename)
            self.capture_metadata = load_capture_metadata(filename)
            display_expr = self._expand_display_filter_macros(self.display_filter_input.text())
            if display_expr != str(self.display_filter_input.text() or ''):
                self.display_filter_input.setText(display_expr)
            no_filter = (display_expr == '')
            full_preload_count = 50
            loaded = 0
            batch_new_visible = []
            first_remaining_packet = None
            packet_iter = iter_pcap_packets(filename)

            for idx, packet in enumerate(packet_iter, start=1):
                if idx > full_preload_count:
                    first_remaining_packet = packet
                    break
                try:
                    record = self.parser.parse_fast(packet, idx)
                except Exception:
                    record = self.parser.parse(packet, idx)
                record = self._apply_capture_metadata_to_record(record, idx)
                self.records.append(record)
                loaded = idx

                if no_filter:
                    self.visible_indices.append(idx - 1)
                    batch_new_visible.append(record)
                elif self.display_filter.matches(record, display_expr):
                    self.visible_indices.append(idx - 1)
                    batch_new_visible.append(record)

            if batch_new_visible:
                self.table.setUpdatesEnabled(False)
                try:
                    self.table.append_records(batch_new_visible)
                finally:
                    self.table.setUpdatesEnabled(True)
            batch_new_visible.clear()

            self._rebuild_visible_row_lookup()
            if self.visible_indices:
                self.table.selectRow(0)
                self.table.setCurrentCell(0, 0)
                self.table.setFocus()
            self._force_visible_feedback_now(minimap_data_changed=True)
            self.display_filter_applied.emit()
            self._emit_go_state_changed()
            self._update_status(f'Loaded {loaded} packets...')
            QApplication.processEvents()

            if first_remaining_packet is None:
                self._set_dirty(False)
                self._startup_priority_mode = False
                self._start_refine_thread()
                self._remember_recent_file(self.loaded_file_path)
                self._schedule_packet_list_aux_refresh(minimap=True, minimap_data_changed=True)
                self._schedule_packet_list_aux_refresh(related=True, minimap=False)
                self._update_status(f'Loaded {loaded} packets from {self.loaded_file_path}')
                return

            remaining_packets = itertools.chain([first_remaining_packet], packet_iter)
            self._start_background_file_load(
                packet_iter=remaining_packets,
                start_index=loaded + 1,
                display_expr=display_expr,
                no_filter=no_filter,
            )
        finally:
            if self._file_load_thread is None or not self._file_load_thread.is_alive():
                self._is_bulk_loading = False

    def _parse_next_batch(self, initial=False):
        # Legacy incremental loader kept for compatibility.
        # File loading now uses foreground preload + background worker.
        return

    def load_file(self, file_path: str = ''):
        filename = (file_path or '').strip()
        if not filename:
            dialog = QFileDialog(self, 'Open PCAP')
            dialog.setFileMode(QFileDialog.ExistingFile)
            dialog.setNameFilter('PCAP Files (*.pcap *.pcapng)')
            dialog.setDirectory(self._preferred_open_directory())
            dialog.resize(1100, 700)
            self._fit_widget_90(dialog)

            if not dialog.exec():
                return
            selected = dialog.selectedFiles()
            if not selected:
                return
            filename = selected[0]

        self._load_capture_from_path(filename)

    def reload_file(self):
        if not self.records:
            QMessageBox.information(None, 'Reload', 'Không có capture hiện tại để reload.')
            return

        packets = [r.raw for r in self.records]
        self.stop_capture()
        self._set_packet_panes_visible(False)
        self._set_packet_panes_updates_enabled(False)
        try:
            self.clear_packets(reset_file_path=False)
            for idx, packet in enumerate(packets, start=1):
                record = self.parser.parse(packet, idx, self.iface)
                self.records.append(self._apply_capture_metadata_to_record(record, idx))
            self.apply_display_filter()
            if self.visible_indices:
                self.goto_first_packet()
            self._update_status(f'Reloaded analysis for {len(self.records)} packets in current capture')
        finally:
            self._set_packet_panes_updates_enabled(True)
            self._set_packet_panes_visible(True)

    def set_auto_scroll_enabled(self, enabled: bool):
        self.auto_scroll_enabled = bool(enabled)
        self._emit_go_state_changed()

    def set_color_rules_enabled(self, enabled: bool):
        self.color_rules_enabled = bool(enabled)
        self.table.set_color_rules_enabled(self.color_rules_enabled)
        self._schedule_packet_list_aux_refresh(minimap=True, minimap_data_changed=True)

    def _navigate_to_row(self, row: int, add_to_history: bool = True) -> bool:
        if row < 0 or row >= len(self.visible_indices):
            return False
        self.table.selectRow(row)
        self.table.setCurrentCell(row, 0)
        self.table.setFocus()
        self.table.scrollToItem(self.table.item(row, 0), self.table.ScrollHint.PositionAtCenter)
        self.show_details(row, 0, add_to_history=add_to_history)
        return True

    def goto_row(self, row: int) -> bool:
        return self._navigate_to_row(row, add_to_history=True)

    def goto_previous_packet(self) -> bool:
        row = self.table.currentRow()
        if row <= 0:
            return False
        return self._navigate_to_row(row - 1, add_to_history=True)

    def goto_next_packet(self) -> bool:
        row = self.table.currentRow()
        if row < 0 and len(self.visible_indices) > 0:
            return self._navigate_to_row(0, add_to_history=True)
        if row < 0 or row >= len(self.visible_indices) - 1:
            return False
        return self._navigate_to_row(row + 1, add_to_history=True)

    def goto_first_packet(self) -> bool:
        if not self.visible_indices:
            return False
        return self._navigate_to_row(0, add_to_history=True)

    def goto_last_packet(self) -> bool:
        if not self.visible_indices:
            return False
        return self._navigate_to_row(len(self.visible_indices) - 1, add_to_history=True)

    def goto_packet_number(self, packet_number: int) -> bool:
        target = int(packet_number)
        for row, rec_idx in enumerate(self.visible_indices):
            if int(self.records[rec_idx].number) == target:
                return self._navigate_to_row(row, add_to_history=True)
        return False

    def _record_exists_by_number(self, packet_number: int) -> bool:
        target = int(packet_number)
        return any(int(getattr(r, 'number', 0) or 0) == target for r in self.records)

    def _add_packet_to_history(self, packet_number: int):
        packet_number = int(packet_number or 0)
        if packet_number <= 0:
            return
        if self._history_index >= 0 and self._history_index < len(self._packet_history):
            if int(self._packet_history[self._history_index]) == packet_number:
                return
        if self._history_index < len(self._packet_history) - 1:
            self._packet_history = self._packet_history[: self._history_index + 1]
        self._packet_history.append(packet_number)
        self._history_index = len(self._packet_history) - 1

    def can_go_back(self) -> bool:
        return self._history_index > 0

    def can_go_forward(self) -> bool:
        return 0 <= self._history_index < len(self._packet_history) - 1

    def go_back(self) -> bool:
        if not self.can_go_back():
            return False
        target_index = self._history_index - 1
        target_packet = int(self._packet_history[target_index])
        if not self._record_exists_by_number(target_packet):
            self._prune_invalid_history_entries()
            self._emit_go_state_changed()
            return False
        row = self._visible_row_for_packet_number(target_packet)
        if row < 0:
            self._history_index = target_index
            self._update_status(f'Frame {target_packet} is hidden by the current display filter')
            self._emit_go_state_changed()
            return False
        self._history_index = target_index
        return self._navigate_to_row(row, add_to_history=False)

    def go_forward(self) -> bool:
        if not self.can_go_forward():
            return False
        target_index = self._history_index + 1
        target_packet = int(self._packet_history[target_index])
        if not self._record_exists_by_number(target_packet):
            self._prune_invalid_history_entries()
            self._emit_go_state_changed()
            return False
        row = self._visible_row_for_packet_number(target_packet)
        if row < 0:
            self._history_index = target_index
            self._update_status(f'Frame {target_packet} is hidden by the current display filter')
            self._emit_go_state_changed()
            return False
        self._history_index = target_index
        return self._navigate_to_row(row, add_to_history=False)

    def _prune_invalid_history_entries(self):
        valid_numbers = {int(getattr(r, 'number', 0) or 0) for r in self.records}
        if not valid_numbers:
            self._packet_history = []
            self._history_index = -1
            return
        old_selected = None
        if 0 <= self._history_index < len(self._packet_history):
            old_selected = int(self._packet_history[self._history_index])
        self._packet_history = [n for n in self._packet_history if int(n) in valid_numbers]
        if not self._packet_history:
            self._history_index = -1
            return
        if old_selected is not None and old_selected in self._packet_history:
            self._history_index = self._packet_history.index(old_selected)
        else:
            self._history_index = len(self._packet_history) - 1

    def _visible_row_for_packet_number(self, packet_number: int) -> int:
        target = int(packet_number)
        for row, rec_idx in enumerate(self.visible_indices):
            if int(getattr(self.records[rec_idx], 'number', 0) or 0) == target:
                return row
        return -1

    def _conversation_key_for_record(self, record):
        if record is None:
            return None
        metadata = getattr(record, 'metadata', {}) or {}
        tcp_stream = metadata.get('tcp_stream_index')
        if isinstance(tcp_stream, int) and tcp_stream >= 0:
            return ('tcp_stream', int(tcp_stream))
        udp_stream = metadata.get('udp_stream_index')
        if isinstance(udp_stream, int) and udp_stream >= 0:
            return ('udp_stream', int(udp_stream))
        src = str(getattr(record, 'src', '') or '')
        dst = str(getattr(record, 'dst', '') or '')
        sport = str(getattr(record, 'sport', '') or '')
        dport = str(getattr(record, 'dport', '') or '')
        proto = str(getattr(record, 'protocol', '') or '').upper()
        if not src and not dst:
            return None
        endpoints = tuple(sorted([(src, sport), (dst, dport)]))
        return (proto, endpoints)

    def _conversation_rows_for_current(self) -> list[int]:
        row = self.get_current_visible_row()
        if row < 0 or row >= len(self.visible_indices):
            return []
        current_rec_idx = self.visible_indices[row]
        if current_rec_idx < 0 or current_rec_idx >= len(self.records):
            return []
        current_key = self._conversation_key_for_record(self.records[current_rec_idx])
        if current_key is None:
            return []
        rows = []
        for visible_row, rec_idx in enumerate(self.visible_indices):
            if 0 <= rec_idx < len(self.records) and self._conversation_key_for_record(self.records[rec_idx]) == current_key:
                rows.append(visible_row)
        return rows

    def has_previous_packet_in_conversation(self) -> bool:
        rows = self._conversation_rows_for_current()
        if not rows:
            return False
        current = self.get_current_visible_row()
        return current in rows and rows.index(current) > 0

    def has_next_packet_in_conversation(self) -> bool:
        rows = self._conversation_rows_for_current()
        if not rows:
            return False
        current = self.get_current_visible_row()
        return current in rows and rows.index(current) < len(rows) - 1

    def goto_previous_packet_in_conversation(self) -> bool:
        rows = self._conversation_rows_for_current()
        current = self.get_current_visible_row()
        if current not in rows:
            return False
        idx = rows.index(current)
        if idx <= 0:
            self._update_status('No previous packet in this conversation')
            return False
        return self._navigate_to_row(rows[idx - 1], add_to_history=True)

    def goto_next_packet_in_conversation(self) -> bool:
        rows = self._conversation_rows_for_current()
        current = self.get_current_visible_row()
        if current not in rows:
            return False
        idx = rows.index(current)
        if idx >= len(rows) - 1:
            self._update_status('No next packet in this conversation')
            return False
        return self._navigate_to_row(rows[idx + 1], add_to_history=True)

    def _first_corresponding_frame(self, record) -> int | None:
        if record is None:
            return None
        metadata = getattr(record, 'metadata', {}) or {}
        current_number = int(getattr(record, 'number', 0) or 0)
        candidate_keys = [
            'http_response_frame', 'http_request_frame',
            'dns_response_frame', 'dns_request_frame',
            'icmp_response_frame', 'icmp_request_frame',
            'icmpv6_response_frame', 'icmpv6_request_frame',
            'smtp_response_frame', 'smtp_request_frame',
            'imap_response_frame', 'imap_request_frame',
            'sip_response_frame', 'sip_request_frame',
            'snmp_response_frame', 'snmp_request_frame',
            'whois_answer_frame', 'whois_query_frame',
            'radius_response_frame', 'radius_request_frame',
            'ntp_response_frame', 'ntp_request_frame',
            'zabbix_response_frame', 'zabbix_request_frame',
            'ldap_response_to_frame', 'dcerpc_request_frame',
            'tftp_request_frame',
            'tcp_ack_frame_number', 'tcp_duplicate_ack_frame_number',
            'ip_reassembled_in_frame',
            'tcp_reassembled_pdu_in_frame', 'tls_reassembled_pdu_in_frame',
            'smtp_reassembled_data_in_frame', 'rtp_setup_frame',
        ]
        for key in candidate_keys:
            value = metadata.get(key)
            try:
                frame = int(value)
            except Exception:
                continue
            if frame > 0 and frame != current_number:
                return frame
        return None

    def has_corresponding_packet(self) -> bool:
        record = self.get_current_record()
        frame = self._first_corresponding_frame(record)
        return frame is not None and self._record_exists_by_number(int(frame))

    def goto_corresponding_packet(self) -> bool:
        record = self.get_current_record()
        frame = self._first_corresponding_frame(record)
        if frame is None:
            return False
        row = self._visible_row_for_packet_number(int(frame))
        if row < 0:
            self._update_status(f'Corresponding frame {frame} is hidden by the current display filter')
            return False
        return self._navigate_to_row(row, add_to_history=True)

    def get_go_state(self) -> dict:
        row = self.get_current_visible_row()
        has_visible = len(self.visible_indices) > 0
        return {
            'has_packets': self.has_packets(),
            'has_visible_packets': has_visible,
            'has_selection': row >= 0,
            'is_file_format_mode': self.is_file_format_view_mode(),
            'can_go_back': self.can_go_back(),
            'can_go_forward': self.can_go_forward(),
            'can_go_to_packet': self.has_packets() and not self.is_file_format_view_mode(),
            'can_previous_packet': row > 0,
            'can_next_packet': has_visible and row >= 0 and row < len(self.visible_indices) - 1,
            'can_first_packet': has_visible and row != 0,
            'can_last_packet': has_visible and row != len(self.visible_indices) - 1,
            'can_previous_conversation': self.has_previous_packet_in_conversation(),
            'can_next_conversation': self.has_next_packet_in_conversation(),
            'can_corresponding': self.has_corresponding_packet(),
            'auto_scroll_enabled': bool(self.auto_scroll_enabled),
        }

    def _emit_go_state_changed(self):
        try:
            self.go_state_changed.emit(self.get_go_state())
        except Exception:
            pass

    def get_current_visible_row(self) -> int:
        row = int(self.table.currentRow())
        return row if row >= 0 else -1

    def get_current_record(self):
        if self._show_file_format_view and self._file_format_record is not None:
            row = self.get_current_visible_row()
            return self._file_format_record if row == 0 else None
        row = self.get_current_visible_row()
        if row < 0 or row >= len(self.visible_indices):
            return None
        rec_idx = self.visible_indices[row]
        if rec_idx < 0 or rec_idx >= len(self.records):
            return None
        return self.records[rec_idx]

    def _selected_visible_rows(self) -> list[int]:
        if not self.table.selectionModel():
            return []
        rows = sorted({index.row() for index in self.table.selectionModel().selectedRows()})
        return [row for row in rows if 0 <= row < len(self.visible_indices)]

    def _selected_record_indexes(self) -> list[int]:
        indexes = []
        for row in self._selected_visible_rows():
            rec_idx = self.visible_indices[row]
            if 0 <= rec_idx < len(self.records):
                indexes.append(rec_idx)
        return indexes

    def _record_index_for_visible_row(self, row: int) -> int:
        if row < 0 or row >= len(self.visible_indices):
            return -1
        rec_idx = self.visible_indices[row]
        if rec_idx < 0 or rec_idx >= len(self.records):
            return -1
        return rec_idx

    def _refresh_row_style(self, row: int):
        rec_idx = self._record_index_for_visible_row(row)
        if rec_idx < 0:
            return
        record = self.records[rec_idx]
        self._update_table_row_from_record(row, record)

    def _refresh_all_visible_row_styles(self):
        for row in range(len(self.visible_indices)):
            self._refresh_row_style(row)
        self._schedule_packet_list_aux_refresh(minimap=True, minimap_data_changed=True)

    def toggle_go_to_packet_row(self):
        visible = not self.goto_packet_widget.isVisible()
        self.goto_packet_widget.setVisible(visible)
        if visible:
            self.goto_packet_input.clear()
            self.goto_packet_input.setFocus()

    def toggle_find_panel(self):
        visible = not self.find_widget.isVisible()
        self.find_widget.setVisible(visible)
        self.find_panel_visibility_changed.emit(visible)
        if visible:
            self.find_input.setFocus()
            self.find_input.selectAll()

    def _on_find_cancel(self):
        self.find_widget.setVisible(False)
        self.find_panel_visibility_changed.emit(False)

    def _on_find_option_changed(self):
        search_type = self.find_type_combo.currentText()
        scope = self.find_scope_combo.currentText()

        scope_enabled = search_type in ('String', 'Regular Expression')
        self.find_scope_combo.setEnabled(scope_enabled)

        case_enabled = search_type in ('String', 'Regular Expression')
        self.find_case_cb.setEnabled(case_enabled)

        multiple_enabled = (
            search_type == 'Hexadecimal Value'
            or (search_type in ('String', 'Regular Expression') and scope != 'Packet list')
        )
        self.find_multiple_cb.setEnabled(multiple_enabled)
        if not multiple_enabled:
            self.find_multiple_cb.setChecked(False)

        encoding_enabled = scope_enabled and scope == 'Packet bytes'
        self.find_encoding_combo.setEnabled(encoding_enabled)

        if search_type == 'Display filter':
            self.find_input.setCompleter(getattr(self, 'find_filter_completer', None))
        else:
            self.find_input.setCompleter(None)

        self._on_find_query_changed()
        self._last_find_signature = None
        self._last_find_offset = None
        self._last_find_detail_index = None

    def _effective_find_scope(self, search_type: str, selected_scope: str) -> str:
        if search_type == 'Display filter':
            return 'Packet list'
        if search_type == 'Hexadecimal Value':
            return 'Packet bytes'
        return selected_scope

    def _on_find_query_changed(self):
        if self.find_type_combo.currentText() != 'Display filter':
            self.find_input.setStyleSheet('')
            return

        text = self.find_input.text().strip()
        if not text:
            self.find_input.setStyleSheet('')
            return

        # Approximate syntax feedback: valid if expression can be evaluated without error.
        is_valid = True
        try:
            if self.records:
                _ = self.display_filter.matches(self.records[0], text)
            else:
                _ = self.display_filter.matches(type('R', (), {
                    'number': 1,
                    'relative_time': 0.0,
                    'src': '',
                    'dst': '',
                    'protocol': '',
                    'length': 0,
                    'info': '',
                    'layers': [],
                    'stream_hint': '',
                    'sport': None,
                    'dport': None,
                })(), text)
        except Exception:
            is_valid = False

        if is_valid:
            self.find_input.setStyleSheet('QLineEdit { background-color: #d9f7d9; }')
        else:
            self.find_input.setStyleSheet('QLineEdit { background-color: #f8d7da; }')

        self._last_find_signature = None
        self._last_find_offset = None
        self._last_find_detail_index = None

    def _iter_search_rows(self, backwards: bool, include_current: bool = False):
        total = len(self.visible_indices)
        if total == 0:
            return []

        current = self.table.currentRow()
        had_selection = current >= 0
        if current < 0:
            current = total - 1 if backwards else 0

        rows = []
        if include_current or not had_selection:
            rows.append(current)

        if backwards:
            rows.extend(list(range(current - 1, -1, -1)))
            rows.extend(list(range(total - 1, current, -1)))
        else:
            rows.extend(list(range(current + 1, total)))
            rows.extend(list(range(0, current)))
        return rows

    def _parse_hex_query(self, text: str):
        cleaned = text.replace(' ', '').replace(':', '').replace('-', '')
        if not cleaned or len(cleaned) % 2 != 0:
            return None
        try:
            return bytes.fromhex(cleaned)
        except ValueError:
            return None

    def _find_all_bytes(self, data: bytes, needle: bytes):
        matches = []
        start = 0
        while True:
            idx = data.find(needle, start)
            if idx < 0:
                break
            matches.append(idx)
            start = idx + 1
        return matches

    def _flatten_detail_titles(self, record):
        titles = []

        def walk(nodes):
            for node in nodes:
                title = str(node.get('title', ''))
                if title:
                    titles.append(title)
                children = node.get('children', []) or []
                if children:
                    walk(children)

        try:
            walk(packet_summary_tree(record.raw, record))
        except Exception:
            pass
        return titles

    def _match_packet_list_text(self, record):
        return ' | '.join([
            str(record.number),
            f'{record.relative_time:.9f}',
            record.src,
            record.dst,
            record.protocol,
            str(record.length),
            record.info,
        ])

    def _run_find_on_record(self, record, query: str, search_type: str, scope: str, case_sensitive: bool, encoding_mode: str):
        if search_type == 'Display filter':
            return {'matched': self.display_filter.matches(record, query), 'offsets': [], 'length': 0}

        if search_type == 'Hexadecimal Value':
            needle = self._parse_hex_query(query)
            if not needle:
                return {'matched': False, 'offsets': [], 'length': 0}
            data = bytes(record.raw)
            offsets = self._find_all_bytes(data, needle)
            return {'matched': bool(offsets), 'offsets': offsets, 'length': len(needle)}

        flags = 0 if case_sensitive else re.IGNORECASE

        if scope == 'Packet list':
            text = self._match_packet_list_text(record)
            if search_type == 'String':
                source = text if case_sensitive else text.lower()
                needle = query if case_sensitive else query.lower()
                return {'matched': needle in source, 'offsets': [], 'length': 0}
            try:
                return {'matched': re.search(query, text, flags) is not None, 'offsets': [], 'length': 0}
            except re.error:
                return {'matched': False, 'offsets': [], 'length': 0}

        if scope == 'Packet details':
            details_text = '\n'.join(self._flatten_detail_titles(record))
            if search_type == 'String':
                source = details_text if case_sensitive else details_text.lower()
                needle = query if case_sensitive else query.lower()
                return {'matched': needle in source, 'offsets': [], 'length': 0}
            try:
                return {'matched': re.search(query, details_text, flags) is not None, 'offsets': [], 'length': 0}
            except re.error:
                return {'matched': False, 'offsets': [], 'length': 0}

        # Packet bytes + String/Regex
        data = bytes(record.raw)
        if search_type == 'String':
            if encoding_mode == 'Wide (UTF-16)':
                try:
                    needle = query.encode('utf-16-le')
                except Exception:
                    return {'matched': False, 'offsets': [], 'length': 0}
                if not needle:
                    return {'matched': False, 'offsets': [], 'length': 0}
                offsets = self._find_all_bytes(data, needle)
                return {'matched': bool(offsets), 'offsets': offsets, 'length': len(needle)}

            if encoding_mode == 'Narrow & Wide':
                narrow = query.encode('utf-8', errors='ignore')
                wide = query.encode('utf-16-le', errors='ignore')
                all_offsets = []
                if narrow:
                    all_offsets.extend(self._find_all_bytes(data, narrow))
                if wide:
                    all_offsets.extend(self._find_all_bytes(data, wide))
                hex_needle = self._parse_hex_query(query)
                if hex_needle:
                    all_offsets.extend(self._find_all_bytes(data, hex_needle))
                all_offsets = sorted(set(all_offsets))
                length = len(narrow) if narrow else (len(wide) if wide else 0)
                return {'matched': bool(all_offsets), 'offsets': all_offsets, 'length': length}

            # Narrow (UTF-8 / ASCII)
            else:
                enc = 'utf-8' if query else 'ascii'
                try:
                    needle = query.encode(enc, errors='ignore')
                except Exception:
                    return {'matched': False, 'offsets': [], 'length': 0}

            if not needle:
                return {'matched': False, 'offsets': [], 'length': 0}
            offsets = self._find_all_bytes(data, needle)
            # Also treat pure-hex input in String mode so values like "31" match byte 0x31 across packets.
            hex_needle = self._parse_hex_query(query)
            if hex_needle:
                offsets = sorted(set(offsets + self._find_all_bytes(data, hex_needle)))
            return {'matched': bool(offsets), 'offsets': offsets, 'length': len(needle)}

        # Regex on bytes (narrow/wide approximation)
        try:
            if encoding_mode == 'Wide (UTF-16)':
                text = data.decode('utf-16-le', errors='ignore')
                hits = [m.start() * 2 for m in re.finditer(query, text, flags)]
                first_len = 0
                m0 = re.search(query, text, flags)
                if m0:
                    first_len = max(1, len(m0.group(0).encode('utf-16-le', errors='ignore')))
                return {'matched': bool(hits), 'offsets': hits, 'length': first_len}

            if encoding_mode == 'Narrow & Wide':
                text_narrow = data.decode('latin-1', errors='ignore')
                hits_narrow = [m.start() for m in re.finditer(query, text_narrow, flags)]

                text_wide = data.decode('utf-16-le', errors='ignore')
                hits_wide = [m.start() * 2 for m in re.finditer(query, text_wide, flags)]

                hits = sorted(set(hits_narrow + hits_wide))

                first_len = 0
                m0 = re.search(query, text_narrow, flags)
                if m0:
                    first_len = max(1, len(m0.group(0)))
                else:
                    m1 = re.search(query, text_wide, flags)
                    if m1:
                        first_len = max(1, len(m1.group(0).encode('utf-16-le', errors='ignore')))

                return {'matched': bool(hits), 'offsets': hits, 'length': first_len}

            text = data.decode('latin-1', errors='ignore')
            hits = [m.start() for m in re.finditer(query, text, flags)]
            first_len = 0
            m0 = re.search(query, text, flags)
            if m0:
                first_len = max(1, len(m0.group(0)))
            return {'matched': bool(hits), 'offsets': hits, 'length': first_len}
        except re.error:
            return {'matched': False, 'offsets': [], 'length': 0}

    def _highlight_detail_match(self, query: str, case_sensitive: bool, regex_mode: bool):
        pattern = None
        if regex_mode:
            try:
                pattern = re.compile(query, 0 if case_sensitive else re.IGNORECASE)
            except re.error:
                return

        source_query = query if case_sensitive else query.lower()

        root = self.details_tree.invisibleRootItem()

        def visit(item):
            text = item.text(0)
            source = text if case_sensitive else text.lower()
            matched = False
            if regex_mode and pattern is not None:
                matched = pattern.search(text) is not None
            elif source_query:
                matched = source_query in source

            if matched:
                parent = item.parent()
                while parent is not None:
                    parent.setExpanded(True)
                    parent = parent.parent()
                self.details_tree.setCurrentItem(item)
                self.details_tree.scrollToItem(item)
                return True

            for i in range(item.childCount()):
                if visit(item.child(i)):
                    return True
            return False

        for i in range(root.childCount()):
            if visit(root.child(i)):
                return

    def _collect_detail_match_items_in_tree(self, query: str, case_sensitive: bool, regex_mode: bool):
        pattern = None
        if regex_mode:
            try:
                pattern = re.compile(query, 0 if case_sensitive else re.IGNORECASE)
            except re.error:
                return []

        source_query = query if case_sensitive else query.lower()
        matches = []
        root = self.details_tree.invisibleRootItem()

        def visit(item):
            text = item.text(0)
            source = text if case_sensitive else text.lower()
            matched = False
            if regex_mode and pattern is not None:
                matched = pattern.search(text) is not None
            elif source_query:
                matched = source_query in source

            if matched:
                matches.append(item)

            for i in range(item.childCount()):
                visit(item.child(i))

        for i in range(root.childCount()):
            visit(root.child(i))

        return matches

    def _select_detail_match_in_current_tree(self, query: str, case_sensitive: bool, regex_mode: bool, row: int, backwards: bool, multiple: bool):
        items = self._collect_detail_match_items_in_tree(query, case_sensitive, regex_mode)
        if not items:
            return False, False

        selected_index = None
        if multiple and self._last_find_row == row and self._last_find_detail_index is not None:
            if backwards:
                candidates = [i for i in range(len(items)) if i < self._last_find_detail_index]
                if candidates:
                    selected_index = candidates[-1]
            else:
                candidates = [i for i in range(len(items)) if i > self._last_find_detail_index]
                if candidates:
                    selected_index = candidates[0]

            if selected_index is None:
                return False, True
        else:
            selected_index = len(items) - 1 if backwards else 0

        item = items[selected_index]
        parent = item.parent()
        while parent is not None:
            parent.setExpanded(True)
            parent = parent.parent()

        self.details_tree.setCurrentItem(item)
        self.details_tree.scrollToItem(item)
        self._last_find_row = row
        self._last_find_detail_index = selected_index
        self._last_find_offset = None
        return True, False

    def _select_next_offset_in_row(self, row: int, offsets, backwards: bool, multiple: bool):
        if not offsets:
            return None, False

        if not multiple:
            return (offsets[-1] if backwards else offsets[0]), True

        if self._last_find_row == row and self._last_find_offset is not None:
            if backwards:
                candidates = [off for off in offsets if off < self._last_find_offset]
                if candidates:
                    return candidates[-1], True
            else:
                candidates = [off for off in offsets if off > self._last_find_offset]
                if candidates:
                    return candidates[0], True
            # No further match in current packet.
            return None, False

        return (offsets[-1] if backwards else offsets[0]), True

    def _on_find_clicked(self):
        query = self.find_input.text().strip()
        if not query:
            return

        search_type = self.find_type_combo.currentText()
        selected_scope = self.find_scope_combo.currentText()
        scope = self._effective_find_scope(search_type, selected_scope)
        encoding_mode = self.find_encoding_combo.currentText()
        case_sensitive = self.find_case_cb.isChecked() and self.find_case_cb.isEnabled()
        backwards = self.find_backwards_cb.isChecked()
        multiple = self.find_multiple_cb.isChecked() and self.find_multiple_cb.isEnabled()

        find_signature = (
            query,
            search_type,
            selected_scope,
            encoding_mode,
            bool(case_sensitive),
            bool(backwards),
            bool(multiple),
        )

        if self._last_find_signature != find_signature:
            self._last_find_signature = find_signature
            self._last_find_row = None
            self._last_find_offset = None
            self._last_find_detail_index = None

        bytes_mode = scope == 'Packet bytes' and search_type in ('Hexadecimal Value', 'String', 'Regular Expression')
        details_mode = scope == 'Packet details' and search_type in ('String', 'Regular Expression')

        # In multiple mode for bytes, keep searching within current packet first.
        if bytes_mode and multiple:
            current_row = self.table.currentRow()
            if current_row < 0 and self.visible_indices:
                current_row = len(self.visible_indices) - 1 if backwards else 0

            if 0 <= current_row < len(self.visible_indices):
                rec_idx = self.visible_indices[current_row]
                record = self.records[rec_idx]
                current_result = self._run_find_on_record(record, query, search_type, scope, case_sensitive, encoding_mode)
                if current_result.get('matched'):
                    offsets = current_result.get('offsets', [])
                    match_len = max(1, int(current_result.get('length', 1) or 1))
                    selected_offset, found_in_current = self._select_next_offset_in_row(
                        current_row,
                        offsets,
                        backwards,
                        multiple,
                    )
                    if found_in_current and selected_offset is not None:
                        self.goto_row(current_row)
                        self._last_find_row = current_row
                        self._last_find_offset = int(selected_offset)
                        self.hex_view.highlight_bytes(int(selected_offset), match_len)
                        return

        if details_mode and multiple:
            current_row = self.table.currentRow()
            if current_row < 0 and self.visible_indices:
                current_row = len(self.visible_indices) - 1 if backwards else 0

            if 0 <= current_row < len(self.visible_indices):
                self.goto_row(current_row)
                selected, exhausted = self._select_detail_match_in_current_tree(
                    query,
                    case_sensitive,
                    search_type == 'Regular Expression',
                    current_row,
                    backwards,
                    multiple,
                )
                if selected:
                    return

        if details_mode:
            for row in self._iter_search_rows(backwards, include_current=False):
                self.goto_row(row)
                selected, _ = self._select_detail_match_in_current_tree(
                    query,
                    case_sensitive,
                    search_type == 'Regular Expression',
                    row,
                    backwards,
                    multiple,
                )
                if selected:
                    self._last_find_row = row
                    self._last_find_offset = None
                    return
            QMessageBox.information(self, 'Find', 'Không tìm thấy kết quả phù hợp.')
            return

        for row in self._iter_search_rows(backwards, include_current=False):
            rec_idx = self.visible_indices[row]
            record = self.records[rec_idx]
            result = self._run_find_on_record(record, query, search_type, scope, case_sensitive, encoding_mode)
            if not result.get('matched'):
                continue

            selected_offset = None
            offsets = result.get('offsets', [])
            match_len = max(1, int(result.get('length', 1) or 1))

            if search_type in ('Hexadecimal Value', 'String', 'Regular Expression') and scope == 'Packet bytes' and offsets:
                selected_offset, found = self._select_next_offset_in_row(
                    row,
                    offsets,
                    backwards,
                    multiple,
                )
                if not found or selected_offset is None:
                    continue

            self.goto_row(row)
            self._last_find_row = row

            if search_type in ('Hexadecimal Value', 'String', 'Regular Expression') and scope == 'Packet bytes':
                if selected_offset is not None:
                    self._last_find_offset = int(selected_offset)
                    self.hex_view.highlight_bytes(int(selected_offset), match_len)
                else:
                    self._last_find_offset = None

            if search_type in ('String', 'Regular Expression') and scope == 'Packet details':
                selected, _ = self._select_detail_match_in_current_tree(
                    query,
                    case_sensitive,
                    search_type == 'Regular Expression',
                    row,
                    backwards,
                    multiple,
                )
                if not selected:
                    continue

            if not (scope == 'Packet bytes' and search_type in ('Hexadecimal Value', 'String', 'Regular Expression')):
                self._last_find_offset = None

            return

        QMessageBox.information(self, 'Find', 'Không tìm thấy kết quả phù hợp.')

    def find_next(self) -> bool:
        query = self.find_input.text().strip()
        if not query:
            return False
        previous = self.find_backwards_cb.isChecked()
        before_row = self.get_current_visible_row()
        self.find_backwards_cb.setChecked(False)
        self._on_find_clicked()
        self.find_backwards_cb.setChecked(previous)
        return self.get_current_visible_row() != before_row

    def find_previous(self) -> bool:
        query = self.find_input.text().strip()
        if not query:
            return False
        previous = self.find_backwards_cb.isChecked()
        before_row = self.get_current_visible_row()
        self.find_backwards_cb.setChecked(True)
        self._on_find_clicked()
        self.find_backwards_cb.setChecked(previous)
        return self.get_current_visible_row() != before_row

    def _toggle_state_for_record_indexes(self, record_indexes: list[int], state_key: str) -> bool:
        targets = [idx for idx in record_indexes if 0 <= idx < len(self.records)]
        if not targets:
            return False
        all_enabled = all(bool(getattr(self.records[idx], state_key, False)) for idx in targets)
        next_value = not all_enabled
        visible_rows = {rec_idx: row for row, rec_idx in enumerate(self.visible_indices)}
        for rec_idx in targets:
            record = self.records[rec_idx]
            setattr(record, state_key, next_value)
            self._sync_runtime_state_from_record(record)
            row = visible_rows.get(rec_idx, -1)
            if row >= 0:
                self._refresh_row_style(row)
        self._schedule_packet_list_aux_refresh(minimap=True, minimap_data_changed=True)
        self._set_dirty(True)
        return True

    def _record_indexes_for_selected_or_current(self) -> list[int]:
        selected = self._selected_record_indexes()
        if selected:
            return selected
        current_row = self.get_current_visible_row()
        if current_row >= 0:
            rec_idx = self._record_index_for_visible_row(current_row)
            if rec_idx >= 0:
                return [rec_idx]
        return []

    def toggle_mark_selected(self) -> bool:
        indexes = self._record_indexes_for_selected_or_current()
        changed = self._toggle_state_for_record_indexes(indexes, 'marked')
        if changed:
            self._update_status('Updated mark state for selected packet(s)')
        return changed

    def toggle_mark_all_displayed(self) -> bool:
        if not self.visible_indices:
            return False
        changed = self._toggle_state_for_record_indexes(list(self.visible_indices), 'marked')
        if changed:
            self._update_status('Updated mark state for displayed packet(s)')
        return changed

    def _goto_mark(self, backwards: bool) -> bool:
        total = len(self.visible_indices)
        if total <= 0:
            return False
        current = self.get_current_visible_row()
        if current < 0:
            current = total if backwards else -1
        candidates = []
        if backwards:
            candidates.extend(range(current - 1, -1, -1))
            candidates.extend(range(total - 1, current, -1))
        else:
            candidates.extend(range(current + 1, total))
            candidates.extend(range(0, current))
        for row in candidates:
            rec_idx = self._record_index_for_visible_row(row)
            if rec_idx < 0:
                continue
            if bool(getattr(self.records[rec_idx], 'marked', False)):
                return self.goto_row(row)
        return False

    def goto_next_mark(self) -> bool:
        found = self._goto_mark(backwards=False)
        if found:
            self._update_status('Moved to next marked packet')
        return found

    def goto_previous_mark(self) -> bool:
        found = self._goto_mark(backwards=True)
        if found:
            self._update_status('Moved to previous marked packet')
        return found

    def toggle_ignore_selected(self) -> bool:
        indexes = self._record_indexes_for_selected_or_current()
        changed = self._toggle_state_for_record_indexes(indexes, 'ignored')
        if changed:
            self._update_status('Updated ignore state for selected packet(s)')
        return changed

    def toggle_ignore_all_displayed(self) -> bool:
        if not self.visible_indices:
            return False
        changed = self._toggle_state_for_record_indexes(list(self.visible_indices), 'ignored')
        if changed:
            self._update_status('Updated ignore state for displayed packet(s)')
        return changed

    def set_comment_for_selected(self, comment: str) -> bool:
        indexes = self._record_indexes_for_selected_or_current()
        targets = [idx for idx in indexes if 0 <= idx < len(self.records)]
        if not targets:
            return False
        normalized = str(comment or '')
        for rec_idx in targets:
            record = self.records[rec_idx]
            record.packet_comment = normalized
            self._sync_runtime_state_from_record(record)
            if rec_idx == self._selected_record_index:
                self.details_tree.show_packet(record)
        self._set_dirty(True)
        self._update_status('Updated packet comment')
        return True

    def get_selected_packet_comment(self) -> str:
        current = self.get_current_record()
        if current is None:
            return ''
        return str(getattr(current, 'packet_comment', '') or '')

    def delete_all_packet_comments(self) -> int:
        changed = 0
        for record in self.records:
            if str(getattr(record, 'packet_comment', '') or ''):
                record.packet_comment = ''
                self._sync_runtime_state_from_record(record)
                changed += 1
        if changed > 0:
            if 0 <= self._selected_record_index < len(self.records):
                self.details_tree.show_packet(self.records[self._selected_record_index])
            self._set_dirty(True)
            self._update_status('Deleted all packet comments')
        return changed

    def _collect_packet_comments_for_persistence(self) -> dict[int, str]:
        comments: dict[int, str] = {}
        for record in self.records:
            try:
                packet_no = int(getattr(record, 'number', 0) or 0)
            except Exception:
                continue
            if packet_no <= 0:
                continue
            comment = str(getattr(record, 'packet_comment', '') or '').strip()
            if comment:
                comments[packet_no] = comment
        return comments

    def save_packet_comments_to_file(self) -> bool:
        if not self.loaded_file_path or not str(self.loaded_file_path).lower().endswith('.pcapng'):
            return False
        comments = self._collect_packet_comments_for_persistence()
        ok = save_pcapng_packet_comments(self.loaded_file_path, comments)
        if not ok:
            return False
        if self.capture_metadata is not None:
            self.capture_metadata.packet_comments = dict(comments)
        self._set_dirty(False)
        return True

    def save_as_pcapng(self, target_path: str) -> bool:
        filename = str(target_path or '').strip()
        if not filename:
            return False
        try:
            filename = normalize_capture_extension(filename, 'pcapng')
            saved_path = save_capture_file(
                filename,
                [r.raw for r in self.records],
                file_format='pcapng',
                compression='none',
            )
            self.loaded_file_path = saved_path
            self.capture_metadata = load_capture_metadata(saved_path)
            self._remember_recent_file(saved_path)
            self._set_dirty(False)
            return True
        except Exception:
            return False

    def _on_go_to_packet_row_submit(self):
        text = self.goto_packet_input.text().strip()
        if not text.isdigit():
            QMessageBox.warning(self, 'Invalid packet', 'Vui lòng nhập số packet hợp lệ.')
            return
        target = int(text)
        if not self.goto_packet_number(target):
            if self._record_exists_by_number(target):
                QMessageBox.information(self, 'Hidden by filter', f'Packet {text} tồn tại nhưng đang bị ẩn bởi display filter hiện tại.')
            else:
                QMessageBox.information(self, 'Not found', f'Không tìm thấy packet số {text}.')
            return
        self.goto_packet_widget.setVisible(False)

    def _on_go_to_packet_row_cancel(self):
        self.goto_packet_widget.setVisible(False)

    def _apply_font_delta(self, delta: float):
        ref_font = self.hex_view.font()
        current = ref_font.pointSizeF()
        if current <= 0:
            current = self._base_fonts.get('hex', 10.0)
        new_size = max(7.0, min(32.0, current + delta))
        self._sync_fonts_to_hex_reference(point_size=new_size)

    def increase_main_text_size(self):
        self._apply_font_delta(1.0)

    def decrease_main_text_size(self):
        self._apply_font_delta(-1.0)

    def reset_main_text_size(self):
        base_size = self._base_fonts.get('hex', 10.0)
        if base_size > 0:
            self._sync_fonts_to_hex_reference(point_size=base_size)

    def _sync_fonts_to_hex_reference(self, point_size: float | None = None):
        """Use Packet Bytes font as canonical font for packet list and details."""
        ref_font = self.hex_view.font()
        if point_size is not None and point_size > 0:
            ref_font.setPointSizeF(float(point_size))

        self.hex_view.setFont(ref_font)
        self.table.setFont(ref_font)
        self.details_tree.setFont(ref_font)

        if hasattr(self.table, 'sync_row_height_to_font'):
            self.table.sync_row_height_to_font()

    def _set_dirty(self, value: bool):
        self._is_dirty = bool(value)

    def has_unsaved_changes(self) -> bool:
        return bool(self._is_dirty)

    def get_current_filename(self) -> str:
        if not self.loaded_file_path:
            return ''
        return os.path.basename(self.loaded_file_path)

    def resize_columns_to_content(self):
        self.table.set_resize_all_columns_mode(True)

    def set_resize_all_columns_enabled(self, enabled: bool):
        self.table.set_resize_all_columns_mode(bool(enabled))

    def is_resize_all_columns_enabled(self) -> bool:
        return bool(getattr(self.table, '_resize_all_columns_enabled', False))

    def reset_layout_to_default_size(self):
        self.main_splitter.setSizes(self.default_main_splitter_sizes)
        self.lower_splitter.setSizes(self.default_lower_splitter_sizes)

    def _on_table_double_clicked(self, row: int, _col: int):
        if row < 0:
            return
        self.show_details(row, 0)
        self.open_packet_window_requested.emit()

    def _update_status(self, message):
        proto_counts = Counter(r.protocol for r in self.records)
        proto_text = ', '.join(f'{k}:{v}' for k, v in sorted(proto_counts.items())) if proto_counts else '-'
        status = (
            f'Interface: {self.iface_display_name} | Capture filter: {self.capture_filter or "(none)"} | '
            f'Packets: {len(self.records)} | Displayed: {len(self.visible_indices)} | Protocols: {proto_text} | {message}'
        )
        self.status_changed.emit(status)

    def get_status_metrics(self):
        return {
            'packets': len(self.records),
            'dropped': 0,
            'displayed': len(self.visible_indices),
        }

    def set_capture_comment(self, comment: str):
        self.capture_comments = comment or ''
        self._set_dirty(True)
    
    def save_capture_comment_to_file(self):
        """Save capture comment to current pcapng file."""
        if not self.loaded_file_path or not self.loaded_file_path.lower().endswith('.pcapng'):
            return False
        ok = save_pcapng_file_comment(self.loaded_file_path, self.capture_comments)
        if ok and self.capture_metadata is not None:
            self.capture_metadata.file_comment = self.capture_comments
            self._set_dirty(False)
        return ok

    def get_capture_properties(self):
        path = self.loaded_file_path or '(live capture / unsaved)'
        total_packets = len(self.records)
        displayed_packets = len(self.visible_indices)
        total_bytes = sum(r.length for r in self.records)
        first_time_text = '-'
        last_time_text = '-'
        elapsed_text = '00:00:00'
        sha256 = ''
        sha1 = ''

        first_epoch = None
        last_epoch = None
        if self.records:
            first_epoch = self.records[0].epoch_time
            last_epoch = self.records[-1].epoch_time
            first_time_text = QDateTime.fromSecsSinceEpoch(int(first_epoch)).toString('yyyy-MM-dd HH:mm:ss')
            last_time_text = QDateTime.fromSecsSinceEpoch(int(last_epoch)).toString('yyyy-MM-dd HH:mm:ss')
            elapsed_seconds = max(0.0, float(last_epoch - first_epoch))
            total_seconds = int(elapsed_seconds)
            days = total_seconds // 86400
            rem = total_seconds % 86400
            h = rem // 3600
            m = (rem % 3600) // 60
            s = rem % 60
            if days > 0:
                elapsed_text = f'{days} days {h:02d}:{m:02d}:{s:02d}'
            else:
                elapsed_text = f'{h:02d}:{m:02d}:{s:02d}'

        if self.loaded_file_path and os.path.exists(self.loaded_file_path):
            try:
                hasher256 = hashlib.sha256()
                hasher1 = hashlib.sha1()
                with open(self.loaded_file_path, 'rb') as f:
                    for chunk in iter(lambda: f.read(1024 * 1024), b''):
                        hasher256.update(chunk)
                        hasher1.update(chunk)
                sha256 = hasher256.hexdigest()
                sha1 = hasher1.hexdigest()
            except Exception:
                sha256 = ''
                sha1 = ''
        elif self.records:
            try:
                hasher256 = hashlib.sha256()
                hasher1 = hashlib.sha1()
                for rec in self.records:
                    try:
                        packet_bytes = bytes(rec.raw)
                    except Exception:
                        packet_bytes = b''
                    hasher256.update(packet_bytes)
                    hasher1.update(packet_bytes)
                sha256 = hasher256.hexdigest()
                sha1 = hasher1.hexdigest()
            except Exception:
                sha256 = ''
                sha1 = ''

        ext = ''
        if self.loaded_file_path:
            ext = os.path.splitext(self.loaded_file_path.lower())[1].lstrip('.')
        if not ext:
            ext = 'pcap'
        format_text = f'Capture format - {ext}'

        elapsed_seconds = 0.0
        if first_epoch is not None and last_epoch is not None:
            elapsed_seconds = max(0.0, float(last_epoch - first_epoch))
        avg_pps = (float(total_packets) / elapsed_seconds) if elapsed_seconds > 0 else 0.0
        avg_pkt_size = (float(total_bytes) / float(total_packets)) if total_packets > 0 else 0.0
        avg_bytes_per_sec = (float(total_bytes) / elapsed_seconds) if elapsed_seconds > 0 else 0.0
        avg_bits_per_sec = avg_bytes_per_sec * 8.0

        displayed_ratio = 100.0 if total_packets == 0 else (float(displayed_packets) / float(total_packets)) * 100.0
        displayed_bytes = sum(self.records[i].length for i in self.visible_indices) if self.visible_indices else 0
        byte_ratio = 100.0 if total_bytes == 0 else (float(displayed_bytes) / float(total_bytes)) * 100.0
        marked_packets = [record for record in self.records if bool(getattr(record, 'marked', False))]
        marked_count = len(marked_packets)
        marked_bytes = sum(int(getattr(record, 'length', 0) or 0) for record in marked_packets)

        file_length_text = f'{max(1, (total_bytes + 1023) // 1024)} kB'
        if self.loaded_file_path and os.path.exists(self.loaded_file_path):
            try:
                size_bytes = os.path.getsize(self.loaded_file_path)
                file_length_text = f'{max(1, (size_bytes + 1023) // 1024)} kB'
            except Exception:
                pass

        # Extract interfaces from metadata
        interfaces_list = []
        if self.capture_metadata and self.capture_metadata.interfaces:
            for iface in self.capture_metadata.interfaces:
                interfaces_list.append({
                    'name': iface.get('name', '-'),
                    'description': iface.get('description', 'Unknown'),
                    'dropped_packets': iface.get('dropped_packets', '0 (0.0%)'),
                    'capture_filter': iface.get('capture_filter', 'none'),
                    'link_type': iface.get('link_type', 'Ethernet'),
                    'snaplen': iface.get('snaplen', '262144 bytes'),
                    'comment': iface.get('comment', 'Unknown'),
                })
        else:
            # Fallback: create single interface from current settings
            interfaces_list.append({
                'name': self.iface or self.iface_display_name or '-',
                'description': self.iface_display_name or self.iface or 'Unknown',
                'dropped_packets': '0 (0.0%)',
                'capture_filter': self.capture_filter or 'none',
                'link_type': 'Ethernet',
                'snaplen': '262144 bytes',
                'comment': 'Unknown',
            })

        encapsulation_values = []
        for iface in interfaces_list:
            link_type = str(iface.get('link_type', '')).strip()
            if not link_type or link_type.startswith('Unknown'):
                continue
            if link_type not in encapsulation_values:
                encapsulation_values.append(link_type)
        encapsulation_text = ', '.join(encapsulation_values) if encapsulation_values else 'Unknown'

        # Get file-level comment from metadata
        file_comment = ''
        if self.capture_metadata and self.capture_metadata.file_comment:
            file_comment = self.capture_metadata.file_comment
        elif self.capture_comments:
            file_comment = self.capture_comments

        return {
            'file_name': os.path.basename(path),
            'file_path': path,
            'file_length': file_length_text,
            'sha256': sha256,
            'sha1': sha1,
            'format': format_text,
            'encapsulation': encapsulation_text,
            'first_packet': first_time_text,
            'last_packet': last_time_text,
            'elapsed': elapsed_text,
            'time_span_seconds': elapsed_seconds,
            'capture_hardware': (self.capture_metadata.section_hardware if self.capture_metadata else '') or '-',
            'capture_os': (self.capture_metadata.section_os if self.capture_metadata else '') or '-',
            'capture_application': (self.capture_metadata.section_application if self.capture_metadata else '') or '-',
            'interface_name': self.iface or self.iface_display_name,
            'interface_description': self.iface_display_name or self.iface or '-',
            'interface_dropped': '0 (0.0%)',
            'interface_capture_filter': self.capture_filter or 'none',
            'interface_link_type': 'Ethernet',
            'interface_snaplen': '262144 bytes',
            'packet_count': total_packets,
            'displayed_count': displayed_packets,
            'dropped_count': 0,
            'total_bytes': total_bytes,
            'comment': file_comment,
            'interfaces': interfaces_list,
            'stats_packets_displayed': f'{displayed_packets} ({displayed_ratio:.1f}%)',
            'stats_packets_marked': str(marked_count),
            'stats_time_span': f'{elapsed_seconds:.3f}',
            'stats_average_pps': f'{avg_pps:.1f}',
            'stats_average_packet_size': f'{avg_pkt_size:.0f}',
            'stats_bytes_displayed': f'{displayed_bytes} ({byte_ratio:.1f}%)',
            'stats_bytes_marked': str(marked_bytes),
            'stats_average_bytes_s': f'{avg_bytes_per_sec / 1000.0:.0f} k',
            'stats_average_bits_s': f'{avg_bits_per_sec / 1000.0:.0f} k',
        }

    def get_effective_records(self, include_ignored: bool = False):
        if include_ignored:
            return list(self.records)
        return [record for record in self.records if not bool(getattr(record, 'ignored', False))]

    def get_expert_information(self):
        entries = []

        severity_map = {
            'warn': 'Warning',
            'warning': 'Warning',
            'error': 'Error',
            'note': 'Note',
            'chat': 'Chat',
        }
        protocol_alias = {
            'MDNS': 'mDNS',
            'LLMNR': 'LLMNR',
            'ICMPV6': 'ICMPv6',
            'MPEG TS': 'MP2T',
            'PIMV1': 'PIM',
            'PIMV2': 'PIM',
            'SRTCP': 'RTCP',
            'RDTUDP': 'RDTUDP',
            'H.264': 'H.264',
            'KRB5': 'KRB5',
            'POP/IMF': 'POP',
            'IEEE 802.11': 'IEEE 802.11',
            'IPV6': 'IPv6',
            'IPV4': 'IPv4',
            'DHCPV6': 'DHCPv6',
        }

        def _canon_protocol(protocol_name: str) -> str:
            p = str(protocol_name or '').strip()
            if not p:
                return ''
            upper = p.upper()
            if upper.startswith('TLS'):
                return 'TLS'
            return protocol_alias.get(upper, p)

        def _walk_nodes(node):
            if isinstance(node, dict):
                yield node
                yield from _walk_nodes(node.get('children', []))
            elif isinstance(node, (list, tuple)):
                for child in node:
                    yield from _walk_nodes(child)

        def _contains_all(haystack: str, needles: list[str]) -> bool:
            return all(str(needle).lower() in haystack for needle in needles)

        def _contains_any(haystack: str, needles: list[str]) -> bool:
            return any(str(needle).lower() in haystack for needle in needles)

        def _canonical_summary(summary: str, protocol_value: str) -> str:
            text = str(summary or '').strip()
            while text.startswith('[') and text.endswith(']') and len(text) > 2:
                text = text[1:-1].strip()

            lowered = text.lower()
            if lowered.startswith('connection establish request (syn)'):
                return 'Connection establish request (SYN)'
            if lowered.startswith('connection establish acknowledge (syn+ack)'):
                return 'Connection establish acknowledge (SYN+ACK)'
            if lowered.startswith('duplicate ack'):
                return 'Duplicate ACK'
            if lowered == 'tag length is longer than remaining payload':
                return 'Bad tag length'
            if lowered == 'no response seen to icmp request':
                if protocol_value == 'ICMPv6':
                    return 'Response not found'
                return 'Response not found'
            if lowered == '[not decoded yet]' or lowered == 'not decoded yet':
                return '[Not decoded yet]'
            if lowered == 'this frame undergoes the connection closing':
                return 'This frame undergoes the connection closing'
            if lowered == 'this frame initiates the connection closing':
                return 'This frame initiates the connection closing'
            return text

        canonical_signatures = [
            {'severity': 'Error', 'summary': 'This message type is not permitted to use OPTION_CLIENT_FQDN', 'group': 'Protocol', 'protocol': 'DHCPv6', 'all': ['option_client_fqdn', 'not permitted'], 'protocols': ['DHCPV6']},
            {'severity': 'Error', 'summary': 'Bad tag length', 'group': 'Malformed', 'protocol': 'IEEE 802.11', 'all': ['tag length is longer than remaining payload']},
            {'severity': 'Error', 'summary': 'Malformed Packet (Exception occurred)', 'group': 'Malformed', 'protocol': 'IEEE 802.11', 'all': ['malformed packet (exception occurred)'], 'any': ['802.11', 'wireless management']},
            {'severity': 'Warning', 'summary': 'DNS query retransmission', 'group': 'Protocol', 'protocol': 'DNS', 'all': ['dns query retransmission'], 'protocols': ['DNS']},
            {'severity': 'Warning', 'summary': 'No dissector for algorithm', 'group': 'Undecoded', 'protocol': 'DNS', 'all': ['no dissector for algorithm']},
            {'severity': 'Warning', 'summary': 'DNS response missing', 'group': 'Protocol', 'protocol': 'DNS', 'all': ['dns response missing'], 'protocols': ['DNS']},
            {'severity': 'Warning', 'summary': 'D-SACK Sequence', 'group': 'Sequence', 'protocol': 'TCP', 'all': ['d-sack sequence']},
            {'severity': 'Warning', 'summary': 'Previous segment(s) not captured (common at capture start)', 'group': 'Sequence', 'protocol': 'TCP', 'all': ['previous segment(s) not captured']},
            {'severity': 'Warning', 'summary': 'Response not found', 'group': 'Sequence', 'protocol': 'ICMP', 'any': ['no response seen to icmp request', '[no response seen]'], 'protocols': ['ICMP']},
            {'severity': 'Note', 'summary': 'Message conforms to neither RFC 5424 nor RFC 3164; trailing data appended', 'group': 'Protocol', 'protocol': 'Syslog', 'all': ['rfc 5424', 'rfc 3164']},
            {'severity': 'Note', 'summary': 'Time To Live', 'group': 'Sequence', 'protocol': 'IPv4', 'all': ['time to live'], 'protocols': ['IP', 'IPV4']},
            {'severity': 'Note', 'summary': 'Undecoded option', 'group': 'Undecoded', 'protocol': 'DNS', 'all': ['undecoded option']},
            {'severity': 'Note', 'summary': 'Partial Acknowledgement of a segment', 'group': 'Sequence', 'protocol': 'TCP', 'all': ['partial acknowledgement of a segment']},
            {'severity': 'Note', 'summary': "This packet's length exceeds MSS (common with TSO or incomplete conversations)", 'group': 'Protocol', 'protocol': 'TCP', 'all': ['length exceeds mss']},
            {'severity': 'Note', 'summary': 'The SYN packet does not contain a SACK_PERM option', 'group': 'Protocol', 'protocol': 'TCP', 'all': ['syn packet does not contain a sack_perm option']},
            {'severity': 'Note', 'summary': 'This frame undergoes the connection closing', 'group': 'Sequence', 'protocol': 'TCP', 'all': ['undergoes the connection closing']},
            {'severity': 'Note', 'summary': 'This frame initiates the connection closing', 'group': 'Sequence', 'protocol': 'TCP', 'all': ['initiates the connection closing']},
            {'severity': 'Note', 'summary': 'Duplicate ACK', 'group': 'Sequence', 'protocol': 'TCP', 'all': ['duplicate ack']},
            {'severity': 'Note', 'summary': "Ambiguous ACK following Karn's definition", 'group': 'Sequence', 'protocol': 'TCP', 'all': ["ambiguous ack following karn's definition"]},
            {'severity': 'Note', 'summary': 'This frame is a (suspected) retransmission', 'group': 'Sequence', 'protocol': 'TCP', 'all': ['(suspected) retransmission']},
            {'severity': 'Chat', 'summary': 'Connection establish acknowledge (SYN+ACK)', 'group': 'Sequence', 'protocol': 'TCP', 'all': ['connection establish acknowledge (syn+ack)']},
            {'severity': 'Chat', 'summary': 'Connection establish request (SYN)', 'group': 'Sequence', 'protocol': 'TCP', 'all': ['connection establish request (syn)']},
            {'severity': 'Chat', 'summary': 'TCP window update', 'group': 'Sequence', 'protocol': 'TCP', 'all': ['tcp window update']},
            {'severity': 'Chat', 'summary': 'Connection finish (FIN)', 'group': 'Sequence', 'protocol': 'TCP', 'all': ['connection finish (fin)']},
            {'severity': 'Chat', 'summary': 'GTSM is not supported by the source', 'group': 'Protocol', 'protocol': 'LDP', 'all': ['gtsm is not supported by the source']},
            {'severity': 'Warning', 'summary': 'This frame is a (suspected) out-of-order segment', 'group': 'Sequence', 'protocol': 'TCP', 'all': ['out-of-order segment']},
            {'severity': 'Warning', 'summary': 'DNS response missing', 'group': 'Protocol', 'protocol': 'mDNS', 'all': ['dns response missing'], 'protocols': ['MDNS']},
            {'severity': 'Warning', 'summary': 'DNS response retransmission', 'group': 'Protocol', 'protocol': 'mDNS', 'all': ['dns response retransmission'], 'protocols': ['MDNS']},
            {'severity': 'Warning', 'summary': 'DNS query retransmission', 'group': 'Protocol', 'protocol': 'mDNS', 'all': ['dns query retransmission'], 'protocols': ['MDNS']},
            {'severity': 'Warning', 'summary': 'Connection reset (RST)', 'group': 'Sequence', 'protocol': 'TCP', 'all': ['connection reset (rst)']},
            {'severity': 'Note', 'summary': 'ACK to a TCP keep-alive segment', 'group': 'Sequence', 'protocol': 'TCP', 'all': ['ack to a tcp keep-alive segment']},
            {'severity': 'Note', 'summary': 'TCP keep-alive segment', 'group': 'Sequence', 'protocol': 'TCP', 'all': ['tcp keep-alive segment']},
            {'severity': 'Note', 'summary': 'This frame is a (suspected) fast retransmission', 'group': 'Sequence', 'protocol': 'TCP', 'all': ['fast retransmission']},
            {'severity': 'Note', 'summary': 'Time To Live too small', 'group': 'Sequence', 'protocol': 'IPv4', 'all': ['time to live', 'too small']},
            {'severity': 'Note', 'summary': 'Type indicates an error', 'group': 'Response', 'protocol': 'ICMPv6', 'all': ['type indicates an error'], 'protocols': ['ICMPV6']},
            {'severity': 'Note', 'summary': 'This frame is a (suspected) spurious retransmission', 'group': 'Sequence', 'protocol': 'TCP', 'all': ['spurious retransmission']},
            {'severity': 'Error', 'summary': 'Malformed Packet (Exception occurred)', 'group': 'Malformed', 'protocol': 'DNS', 'all': ['malformed packet', 'dns']},
            {'severity': 'Warning', 'summary': 'Ignored Unknown Record', 'group': 'Protocol', 'protocol': 'TLS', 'all': ['ignored unknown record']},
            {'severity': 'Warning', 'summary': "ACKed segment that wasn't captured (common at capture start)", 'group': 'Sequence', 'protocol': 'TCP', 'all': ["acked segment that wasn't captured"]},
            {'severity': 'Note', 'summary': 'Extraneous data', 'group': 'Undecoded', 'protocol': 'DNS', 'all': ['extraneous data']},
            {'severity': 'Note', 'summary': 'Padding identification may be inaccurate and impact trailer dissector', 'group': 'Protocol', 'protocol': 'Ethertype', 'all': ['padding identification may be inaccurate']},
            {'severity': 'Chat', 'summary': 'This legacy_version field MUST be ignored. The supported_versions extension is present and MUST be used instead.', 'group': 'Deprecated', 'protocol': 'TLS', 'all': ['legacy_version field must be ignored', 'supported_versions extension is present']},
            {'severity': 'Warning', 'summary': 'Response not found', 'group': 'Sequence', 'protocol': 'ICMPv6', 'any': ['no response seen to icmp request', '[no response seen]'], 'protocols': ['ICMPV6']},
            {'severity': 'Note', 'summary': 'Type indicates an error', 'group': 'Response', 'protocol': 'ICMP', 'all': ['type indicates an error'], 'protocols': ['ICMP']},
            {'severity': 'Note', 'summary': 'Unrecognized SIP header', 'group': 'Undecoded', 'protocol': 'SIP', 'all': ['unrecognized sip header']},
            {'severity': 'Error', 'summary': 'Short CLV', 'group': 'Malformed', 'protocol': 'ISIS LSP', 'all': ['short e/is reachability']},
            {'severity': 'Warning', 'summary': 'TCP window specified by the receiver is now completely full', 'group': 'Sequence', 'protocol': 'TCP', 'all': ['window specified by the receiver is now completely full']},
            {'severity': 'Note', 'summary': 'This session reuses previously negotiated keys (Session resumption)', 'group': 'Sequence', 'protocol': 'TLS', 'all': ['session resumption']},
            {'severity': 'Warning', 'summary': 'Duplicate IP address configured', 'group': 'Sequence', 'protocol': 'ARP/ARP', 'all': ['duplicate ip address detected']},
            {'severity': 'Error', 'summary': 'Length must be a string containing an integer', 'group': 'Malformed', 'protocol': 'POP', 'all': ['length must be a string containing an integer']},
            {'severity': 'Warning', 'summary': 'DNS response retransmission', 'group': 'Protocol', 'protocol': 'DNS', 'all': ['dns response retransmission'], 'protocols': ['DNS']},
            {'severity': 'Warning', 'summary': 'Missing keytype', 'group': 'Decryption', 'protocol': 'KRB5', 'all': ['missing keytype']},
            {'severity': 'Warning', 'summary': 'DNS query retransmission', 'group': 'Protocol', 'protocol': 'LLMNR', 'all': ['dns query retransmission'], 'protocols': ['LLMNR']},
            {'severity': 'Warning', 'summary': 'DNS response missing', 'group': 'Protocol', 'protocol': 'LLMNR', 'all': ['dns response missing'], 'protocols': ['LLMNR']},
            {'severity': 'Warning', 'summary': 'Deprecated option', 'group': 'Deprecated', 'protocol': 'DHCPv6', 'all': ['deprecated option'], 'protocols': ['DHCPV6']},
            {'severity': 'Warning', 'summary': 'Vulnerable to MITM attacks. If possible, change EAP type.', 'group': 'Security', 'protocol': 'EAP', 'all': ['vulnerable to mitm attacks']},
            {'severity': 'Note', 'summary': 'Undecoded class', 'group': 'Undecoded', 'protocol': 'DNS', 'all': ['undecoded class']},
            {'severity': 'Note', 'summary': 'A new tcp session is started with the same ports as an earlier session in this trace', 'group': 'Sequence', 'protocol': 'TCP', 'all': ['new tcp session is started with the same ports']},
            {'severity': 'Chat', 'summary': 'Possible traceroute', 'group': 'Sequence', 'protocol': 'UDP', 'all': ['possible traceroute']},
            {'severity': 'Warning', 'summary': 'Unknown header', 'group': 'Protocol', 'protocol': 'GSS-API', 'all': ['unknown header']},
            {'severity': 'Note', 'summary': 'No bind info for interface Context ID', 'group': 'Undecoded', 'protocol': 'DCERPC', 'all': ['no bind info for interface context id']},
            {'severity': 'Chat', 'summary': 'Authenticated NT HASH', 'group': 'Security', 'protocol': 'NTLMSSP', 'all': ['authenticated nt hash']},
            {'severity': 'Chat', 'summary': 'SessionBaseKey', 'group': 'Security', 'protocol': 'NTLMSSP', 'all': ['sessionbasekey']},
            {'severity': 'Chat', 'summary': 'SessionKey', 'group': 'Security', 'protocol': 'NTLMSSP', 'all': ['sessionkey']},
            {'severity': 'Error', 'summary': 'IPv6 payload length equals 0 and Hop-By-Hop present and Jumbo Payload option missing', 'group': 'Malformed', 'protocol': 'IPv6', 'all': ['payload length: 0'], 'any': ['hop-by-hop', 'hop by hop']},
            {'severity': 'Error', 'summary': 'Malformed Packet (Exception occurred)', 'group': 'Malformed', 'protocol': 'IPv6 Hop-by-Hop', 'all': ['malformed packet', 'ipv6 hop-by-hop']},
            {'severity': 'Error', 'summary': 'Detected missing TS frames', 'group': 'Sequence', 'protocol': 'MP2T', 'all': ['missing ts frames']},
            {'severity': 'Error', 'summary': 'Malformed Packet (Exception occurred)', 'group': 'Malformed', 'protocol': 'PIM', 'all': ['malformed packet', 'pim']},
            {'severity': 'Error', 'summary': 'Malformed Packet (Exception occurred)', 'group': 'Malformed', 'protocol': 'RTCP', 'all': ['malformed packet', 'rtcp']},
            {'severity': 'Error', 'summary': 'Malformed Packet (Exception occurred)', 'group': 'Malformed', 'protocol': 'RDTUDP', 'all': ['malformed packet', 'rdtudp']},
            {'severity': 'Warning', 'summary': '[Not decoded yet]', 'group': 'Undecoded', 'protocol': 'H.264', 'all': ['not decoded yet'], 'protocols': ['H.264']},
            {'severity': 'Warning', 'summary': 'Failed to decrypt handshake', 'group': 'Decryption', 'protocol': 'QUIC', 'any': ['failed to decrypt handshake', 'failed to create decryption context']},
            {'severity': 'Warning', 'summary': 'Too many packet chunks (more than packet status count)', 'group': 'Malformed', 'protocol': 'RTCP', 'all': ['too many packet chunks']},
            {'severity': 'Warning', 'summary': 'Padding flag set on not final packet (see RFC3550, section 6.4.1)', 'group': 'Protocol', 'protocol': 'RTCP', 'all': ['padding flag set on not final packet']},
            {'severity': 'Warning', 'summary': 'Encrypted RTCP Payload - not dissected', 'group': 'Undecoded', 'protocol': 'RTCP', 'all': ['encrypted rtcp payload - not dissected']},
            {'severity': 'Note', 'summary': 'Unknown QUIC connection. Missing Initial Packet or migrated connection?', 'group': 'Protocol', 'protocol': 'QUIC', 'all': ['unknown quic connection']},
            {'severity': 'Note', 'summary': 'This QUIC frame has a reused stream offset (retransmission?)', 'group': 'Sequence', 'protocol': 'QUIC', 'all': ['reused stream offset']},
            {'severity': 'Note', 'summary': 'Coalesced Padding Data', 'group': 'Protocol', 'protocol': 'QUIC', 'all': ['coalesced padding data', 'padding data appended']},
        ]

        for rec in self.get_effective_records(include_ignored=False):
            seen = set()
            title_lowers = []
            protocol_text = _canon_protocol(str(rec.protocol or ''))
            protocol_upper = str(rec.protocol or '').strip().upper()
            info_text = str(rec.info or '')
            md = rec.metadata if isinstance(rec.metadata, dict) else {}

            try:
                tree = packet_summary_tree(rec.raw, rec)
            except Exception:
                tree = None

            nodes = list(_walk_nodes(tree))
            for node in nodes:
                title = str(node.get('title', '') or '').strip()
                if title:
                    title_lowers.append(title.lower())
            blob = '\n'.join(title_lowers)

            def _add_entry(severity: str, summary: str, group: str, protocol_value: str):
                norm_severity = severity_map.get(str(severity or '').strip().lower(), str(severity or '').strip())
                norm_protocol = _canon_protocol(protocol_value)
                norm_summary = _canonical_summary(summary, norm_protocol)
                key = (norm_severity, norm_summary, str(group or '').strip(), norm_protocol)
                if key in seen:
                    return
                seen.add(key)
                entries.append({
                    'packet': rec.number,
                    'info': info_text,
                    'severity': norm_severity,
                    'summary': norm_summary,
                    'group': str(group or '').strip(),
                    'protocol': norm_protocol,
                })

            # 1) Extract explicit [Expert Info (...)] nodes first.
            for node in nodes:
                title = str(node.get('title', '') or '')
                match = re.match(r'^\[Expert Info \(([^/]+)/([^\)]+)\):\s*(.+)\]$', title)
                if not match:
                    continue

                severity_raw = str(match.group(1) or '').strip()
                group_raw = str(match.group(2) or '').strip()
                summary_raw = str(match.group(3) or '').strip()
                if not summary_raw:
                    continue

                detected_protocol = protocol_text
                summary_l = summary_raw.lower()
                if 'gtsm' in summary_l:
                    detected_protocol = 'LDP'
                elif 'dns ' in summary_l and protocol_upper not in {'MDNS', 'LLMNR'}:
                    detected_protocol = 'DNS'
                elif 'syslog' in summary_l or 'rfc 5424' in summary_l or 'rfc 3164' in summary_l:
                    detected_protocol = 'Syslog'
                elif 'quic' in summary_l:
                    detected_protocol = 'QUIC'
                elif 'icmp' in summary_l and protocol_upper == 'ICMPV6':
                    detected_protocol = 'ICMPv6'
                elif 'icmp' in summary_l:
                    detected_protocol = 'ICMP'

                _add_entry(severity_raw, summary_raw, group_raw, detected_protocol)

            # 2) Add deterministic canonical signatures from all descendant titles.
            for rule in canonical_signatures:
                protocols = set(rule.get('protocols', []))
                if protocols and protocol_upper not in protocols:
                    continue

                all_needles = [str(v).lower() for v in rule.get('all', [])]
                any_needles = [str(v).lower() for v in rule.get('any', [])]

                if all_needles and not _contains_all(blob, all_needles):
                    continue
                if any_needles and not _contains_any(blob, any_needles):
                    continue

                _add_entry(
                    str(rule['severity']),
                    str(rule['summary']),
                    str(rule['group']),
                    str(rule['protocol']),
                )

            # 3) Metadata fallback for key TCP signatures when formatter omits children.
            tcp_layer = rec.raw[TCP] if rec.raw is not None and rec.raw.haslayer(TCP) else None
            tcp_flags = int(getattr(tcp_layer, 'flags', 0) or 0) if tcp_layer is not None else 0

            if bool(md.get('tcp_is_window_update', False)):
                _add_entry('Chat', 'TCP window update', 'Sequence', 'TCP')
            if bool(md.get('tcp_is_retransmission', False)):
                if bool(md.get('tcp_is_spurious_retransmission', False)):
                    _add_entry('Note', 'This frame is a (suspected) spurious retransmission', 'Sequence', 'TCP')
                _add_entry('Note', 'This frame is a (suspected) retransmission', 'Sequence', 'TCP')
            if bool(md.get('tcp_previous_segment_not_captured', False)):
                _add_entry('Warning', 'Previous segment(s) not captured (common at capture start)', 'Sequence', 'TCP')
            if bool(md.get('tcp_is_duplicate_ack', False)):
                _add_entry('Note', 'Duplicate ACK', 'Sequence', 'TCP')
            if bool(md.get('tcp_ack_ambiguous', False)):
                _add_entry('Note', "Ambiguous ACK following Karn's definition", 'Sequence', 'TCP')
            if bool(md.get('tcp_port_numbers_reused', False)):
                _add_entry('Note', 'A new tcp session is started with the same ports as an earlier session in this trace', 'Sequence', 'TCP')

            if (tcp_flags & 0x12) == 0x12:
                _add_entry('Chat', 'Connection establish acknowledge (SYN+ACK)', 'Sequence', 'TCP')
            elif (tcp_flags & 0x12) == 0x02:
                _add_entry('Chat', 'Connection establish request (SYN)', 'Sequence', 'TCP')
            if (tcp_flags & 0x01) != 0:
                _add_entry('Chat', 'Connection finish (FIN)', 'Sequence', 'TCP')
            if (tcp_flags & 0x04) != 0:
                _add_entry('Warning', 'Connection reset (RST)', 'Sequence', 'TCP')

        return entries

    def focus_filter(self):
        """Focus vĂ o display filter input"""
        self.display_filter_input.setFocus()
        self.display_filter_input.selectAll()

    def show_summary(self):
        """Xem tong quan capture."""
        effective_records = self.get_effective_records(include_ignored=False)
        if not effective_records:
            QMessageBox.information(None, 'Summary', 'Khong co packet')
            return

        proto_counts = Counter(r.protocol for r in effective_records)
        total_bytes = sum(r.length for r in effective_records)
        ignored_count = max(0, len(self.records) - len(effective_records))

        summary = f"Total Packets: {len(effective_records)}\n"
        if ignored_count > 0:
            summary += f"Ignored Packets: {ignored_count}\n"
        summary += f"Total Bytes: {total_bytes:,}\n\n"
        summary += "Protocol Distribution:\n"
        for proto, count in sorted(proto_counts.items()):
            summary += f"  {proto}: {count}\n"

        dialog = QDialog(self)
        dialog.setWindowTitle('Capture Summary')
        layout = QVBoxLayout(dialog)
        text = QTextEdit(dialog)
        text.setReadOnly(True)
        text.setPlainText(summary)
        layout.addWidget(text)

        close_btn = QPushButton('Close', dialog)
        close_btn.clicked.connect(dialog.accept)
        layout.addWidget(close_btn)

        dialog.resize(900, 600)
        self._fit_widget_90(dialog)
        dialog.exec()

    def show_conversations(self):
        """Xem conversations."""
        effective_records = self.get_effective_records(include_ignored=False)
        if not effective_records:
            QMessageBox.information(None, 'Conversations', 'Khong co conversation')
            return

        from gui.conversations_dialog import ConversationsDialog
        dialog = ConversationsDialog(effective_records, self)
        self._fit_widget_90(dialog)
        dialog.exec()

    def _fit_widget_90(self, widget):
        app = QApplication.instance()
        if app is None:
            return
        screen = app.primaryScreen()
        if screen is None:
            return

        geometry = screen.availableGeometry()
        max_width = int(geometry.width() * 0.9)
        max_height = int(geometry.height() * 0.9)

        widget.setMaximumSize(max_width, max_height)

        current_width = widget.width() if widget.width() > 0 else max_width
        current_height = widget.height() if widget.height() > 0 else max_height

        widget.resize(min(current_width, max_width), min(current_height, max_height))



