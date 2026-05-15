import logging
import re
import os
import hashlib
import time
from collections import Counter
from PySide6.QtCore import Qt, Signal, QSettings, QDateTime, QTimer
from PySide6.QtWidgets import (
    QApplication, QFileDialog, QDialog, QHBoxLayout, QLabel, QLineEdit, QMessageBox,
    QPushButton, QSplitter, QTextEdit, QVBoxLayout, QWidget, QComboBox, QCheckBox,
    QMenu, QStyle, QTableWidget, QTableWidgetItem, QHeaderView, QSizePolicy
)
from PySide6.QtGui import QAction, QPainter, QColor, QPen, QPixmap

from core.capture import PacketSniffer
from core.filtering import DisplayFilter
from core.formatters import packet_summary_tree
from core.parser import PacketParser
from gui.hex_view import PacketHexView
from gui.packet_details import PacketDetailsTree
from gui.packet_table import PacketTable
from utils.pcap_io import (
    load_pcap,
    normalize_capture_extension,
    save_capture_file,
    save_pcapng_file_comment,
)

log = logging.getLogger('capture_view')


class _ProtocolSparkline(QLabel):
    """Sparkline label for one protocol — identical style to interface traffic chart."""
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
    """Standalone sparkline pixmap — same style as interface traffic chart."""
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


class CaptureInformationDialog(QDialog):
    """Live capture statistics — sparkline per protocol, same style as Interface traffic chart."""

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

        # Tick every 1 s — push delta counts into each sparkline
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

    def __init__(self, iface: str = '', iface_display_name: str = '', capture_filter: str = ''):
        super().__init__()
        self.iface = iface
        self.iface_display_name = iface_display_name
        self.capture_filter = capture_filter
        self.output_settings = {}  # Output tab settings from Capture Options dialog
        self.options_settings = {}  # Options tab settings from Capture Options dialog

        self.parser = PacketParser()
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
        self.default_main_splitter_sizes = [500, 360]
        self.default_lower_splitter_sizes = [980, 650]
        self._base_fonts = {}
        self._last_find_row = None
        self._last_find_signature = None
        self._last_find_offset = None
        self._last_find_detail_index = None
        self._filter_history = self._load_filter_history()
        self.capture_comments = ''
        self.capture_metadata = None  # pcapng metadata (interfaces, file comment, packet comments)
        self._is_dirty = False
        self._auto_output_written_files = []
        self._auto_output_base_path = ''
        self._rollover_file_counter = 0

        self._build_ui()
        self._update_status('Ready')

    def _settings(self):
        return QSettings('Packetra', 'Packetra')

    def _load_filter_history(self):
        try:
            values = self._settings().value('filter_history', [], list)
            if not isinstance(values, list):
                return []
            return [str(v) for v in values][:10]
        except Exception:
            return []

    def _save_filter_history(self):
        self._settings().setValue('filter_history', self._filter_history[:10])

    def _remember_filter(self, expr: str):
        expr = (expr or '').strip()
        if not expr:
            return
        self._filter_history = [f for f in self._filter_history if f != expr]
        self._filter_history.insert(0, expr)
        self._filter_history = self._filter_history[:10]
        self._save_filter_history()
        self._refresh_filter_history_menu()

    def _load_recent_files(self):
        try:
            values = self._settings().value('recent_capture_files', [], list)
            if not isinstance(values, list):
                return []
            return [str(v) for v in values][:20]
        except Exception:
            return []

    def _save_recent_files(self, paths: list[str]):
        self._settings().setValue('recent_capture_files', paths[:20])

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
        self.stop_capture()
        self.records.clear()
        self.visible_indices.clear()
        self.table.setRowCount(0)
        self.details_tree.show_packet(None)
        self.hex_view.show_packet(None)
        self.parser = PacketParser()
        self.capture_comments = ''
        self.capture_metadata = None
        self.loaded_file_path = None
        self._auto_output_written_files = []
        self._auto_output_base_path = ''
        self._rollover_file_counter = 0
        self._set_dirty(False)
        self.capture_state_changed.emit(False)
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
        self.apply_filter_btn = QPushButton('➡')
        self.filter_history_menu = QMenu(self)
        self.filter_history_action = self.display_filter_input.addAction(
            self.style().standardIcon(QStyle.StandardPixmap.SP_ArrowDown),
            QLineEdit.ActionPosition.TrailingPosition,
        )
        self.clear_filter_btn = QPushButton('✕')
        self.apply_filter_btn.setFixedWidth(38)
        self.clear_filter_btn.setFixedWidth(38)
        filter_row.addWidget(self.display_filter_input)
        filter_row.addWidget(self.apply_filter_btn)
        filter_row.addWidget(self.clear_filter_btn)
        filter_widget = QWidget()
        filter_widget.setLayout(filter_row)
        root_layout.addWidget(filter_widget)

        # Find row (Wireshark-like), hidden by default.
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
        self.details_tree = PacketDetailsTree()
        self.hex_view = PacketHexView()
        self._base_fonts = {
            'table': self.table.font().pointSizeF(),
            'details': self.details_tree.font().pointSizeF(),
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
        self.main_splitter.addWidget(self.table)
        self.main_splitter.addWidget(self.lower_splitter)
        self.main_splitter.setSizes(self.default_main_splitter_sizes)
        self.main_splitter.setChildrenCollapsible(False)

        root_layout.addWidget(self.main_splitter, 1)

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
        self.details_tree.item_selected.connect(self.hex_view.highlight_bytes)
        self.hex_view.bytes_range_selected.connect(self._on_bytes_range_selected)
        self.hex_view.bytes_hovered.connect(self._on_bytes_hovered)
        self.hex_view.hover_left.connect(self._on_hex_hover_left)

        self._on_find_option_changed()
        self._refresh_filter_history_menu()

    def _refresh_filter_history_menu(self):
        self.filter_history_menu.clear()
        if not self._filter_history:
            action = QAction('(No recent filters)', self.filter_history_menu)
            action.setEnabled(False)
            self.filter_history_menu.addAction(action)
            return

        for expr in self._filter_history[:10]:
            action = QAction(expr, self.filter_history_menu)
            action.triggered.connect(lambda checked=False, value=expr: self._apply_filter_from_history(value))
            self.filter_history_menu.addAction(action)

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
        self.sniffer = PacketSniffer(self.iface, self.capture_filter)
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
        self.records.clear()
        self.visible_indices.clear()
        self.table.setRowCount(0)
        self.details_tree.show_packet(None)
        self.hex_view.show_packet(None)
        self.parser = PacketParser()
        self.capture_comments = ''
        self.capture_metadata = None
        self._captured_bytes = 0
        self._capture_started_at = None
        self._last_live_status_count = 0
        self._auto_output_written_files = []
        self._auto_output_base_path = ''
        self._rollover_file_counter = 0
        self._set_dirty(False)
        if reset_file_path:
            self.loaded_file_path = None

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
        self.table.setRowCount(0)
        self.details_tree.show_packet(None)
        self.hex_view.show_packet(None)
        self.parser = PacketParser()
        self.capture_metadata = None
        self._captured_bytes = 0
        self._last_live_status_count = 0
        self._set_dirty(False)

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
            self.table.append_record(record)
            if self.auto_scroll_enabled:
                self.table.scrollToBottom()

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
        self.table.setRowCount(0)
        self.visible_indices.clear()
        expr = self.display_filter_input.text()
        self._remember_filter(expr)
        for idx, record in enumerate(self.records):
            if self.display_filter.matches(record, expr):
                self.visible_indices.append(idx)
                self.table.append_record(record)
        self.table.set_color_rules_enabled(self.color_rules_enabled)
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

    def _on_bytes_range_selected(self, offset: int, length: int):
        """Handle bytes range selection from hex view -> select and highlight detail"""
        best_item = self._resolve_detail_item_for_range(offset, length)
        if best_item:
            self.details_tree.setCurrentItem(best_item)

    def _on_bytes_hovered(self, offset: int):
        """Hover over bytes should preview full detail field in hex/ascii without changing selection."""
        best_item = self._resolve_detail_item_for_range(offset, 1)
        if not best_item:
            self.hex_view.clear_hover_range()
            return

        from PySide6.QtCore import Qt
        data = best_item.data(0, Qt.ItemDataRole.UserRole)
        if isinstance(data, tuple):
            start, item_length = data
            if start >= 0 and item_length > 0:
                self.hex_view.set_hover_range(start, item_length)
                return

        self.hex_view.clear_hover_range()

    def _on_hex_hover_left(self):
        self.hex_view.clear_hover_range()

    def _resolve_detail_item_for_range(self, offset: int, length: int):
        """Resolve deepest detail node for a byte range, excluding Frame subtree and bracketed analysis nodes."""
        best_item = None
        best_depth = -1

        def visit(item, depth=0, in_frame_section=False):
            nonlocal best_item, best_depth
            from PySide6.QtCore import Qt

            if in_frame_section:
                return

            data = item.data(0, Qt.ItemDataRole.UserRole)
            if isinstance(data, tuple):
                start, item_length = data
                title = item.text(0).strip().lower()
                is_bracketed = title.startswith('[') and title.endswith(']')
                if start >= 0 and item_length > 0 and not is_bracketed:
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
        self._update_status(f'Saved to {saved_path}')
        return True

    def _load_capture_from_path(self, filename: str):
        if not filename:
            return
        self.stop_capture()
        self.clear_packets(reset_file_path=False)
        self.loaded_file_path = filename
        packets, metadata = load_pcap(filename)
        self.capture_metadata = metadata
        self._all_packets = packets
        self._parse_batch_index = 0
        self._parse_batch_size = 100
        self._parse_batch_timer = QTimer(self)
        self._parse_batch_timer.timeout.connect(self._parse_next_batch)
        self._parse_next_batch(initial=True)

    def _parse_next_batch(self, initial=False):
        batch_size = self._parse_batch_size
        start = self._parse_batch_index
        end = min(start + batch_size, len(self._all_packets))
        for idx in range(start, end):
            packet = self._all_packets[idx]
            self.records.append(self.parser.parse(packet, idx + 1))
        self._parse_batch_index = end
        self._set_dirty(False)
        self.apply_display_filter()
        if initial and self.visible_indices:
            self.goto_first_packet()
        self._update_status(f'Loaded {len(self.records)} packets...')
        if self._parse_batch_index < len(self._all_packets):
            self._parse_batch_timer.start(10)
        else:
            self._parse_batch_timer.stop()
            self._remember_recent_file(self.loaded_file_path)
            self._update_status(f'Loaded {len(self.records)} packets from {self.loaded_file_path}')

    def load_file(self, file_path: str = ''):
        filename = (file_path or '').strip()
        if not filename:
            dialog = QFileDialog(self, 'Open PCAP')
            dialog.setFileMode(QFileDialog.ExistingFile)
            dialog.setNameFilter('PCAP Files (*.pcap *.pcapng)')
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
        self.clear_packets(reset_file_path=False)
        for idx, packet in enumerate(packets, start=1):
            self.records.append(self.parser.parse(packet, idx, self.iface))
        self.apply_display_filter()
        self.goto_first_packet()
        self._update_status(f'Reloaded analysis for {len(self.records)} packets in current capture')

    def set_auto_scroll_enabled(self, enabled: bool):
        self.auto_scroll_enabled = bool(enabled)

    def set_color_rules_enabled(self, enabled: bool):
        self.color_rules_enabled = bool(enabled)
        self.table.set_color_rules_enabled(self.color_rules_enabled)

    def goto_row(self, row: int) -> bool:
        if row < 0 or row >= len(self.visible_indices):
            return False
        self.table.selectRow(row)
        self.table.setCurrentCell(row, 0)
        self.table.setFocus()
        self.table.scrollToItem(self.table.item(row, 0), self.table.ScrollHint.PositionAtCenter)
        self.show_details(row, 0)
        return True

    def goto_previous_packet(self) -> bool:
        row = self.table.currentRow()
        if row <= 0:
            return False
        return self.goto_row(row - 1)

    def goto_next_packet(self) -> bool:
        row = self.table.currentRow()
        if row < 0 and len(self.visible_indices) > 0:
            return self.goto_row(0)
        if row < 0 or row >= len(self.visible_indices) - 1:
            return False
        return self.goto_row(row + 1)

    def goto_first_packet(self) -> bool:
        if not self.visible_indices:
            return False
        return self.goto_row(0)

    def goto_last_packet(self) -> bool:
        if not self.visible_indices:
            return False
        return self.goto_row(len(self.visible_indices) - 1)

    def goto_packet_number(self, packet_number: int) -> bool:
        target = int(packet_number)
        for row, rec_idx in enumerate(self.visible_indices):
            if int(self.records[rec_idx].number) == target:
                return self.goto_row(row)

        # If packet exists but is currently filtered out, clear filter and retry.
        exists_in_all = any(int(r.number) == target for r in self.records)
        if exists_in_all:
            self.display_filter_input.clear()
            self.apply_display_filter()
            for row, rec_idx in enumerate(self.visible_indices):
                if int(self.records[rec_idx].number) == target:
                    return self.goto_row(row)
        return False

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

    def _on_go_to_packet_row_submit(self):
        text = self.goto_packet_input.text().strip()
        if not text.isdigit():
            QMessageBox.warning(self, 'Invalid packet', 'Vui lòng nhập số packet hợp lệ.')
            return
        if not self.goto_packet_number(int(text)):
            QMessageBox.information(self, 'Not found', f'Không tìm thấy packet số {text}.')
            return
        self.goto_packet_widget.setVisible(False)

    def _on_go_to_packet_row_cancel(self):
        self.goto_packet_widget.setVisible(False)

    def _apply_font_delta(self, delta: float):
        for widget, key in ((self.table, 'table'), (self.details_tree, 'details'), (self.hex_view, 'hex')):
            font = widget.font()
            current = font.pointSizeF()
            if current <= 0:
                current = self._base_fonts.get(key, 10.0)
            new_size = max(7.0, min(32.0, current + delta))
            font.setPointSizeF(new_size)
            widget.setFont(font)
        if hasattr(self.table, 'sync_row_height_to_font'):
            self.table.sync_row_height_to_font()

    def increase_main_text_size(self):
        self._apply_font_delta(1.0)

    def decrease_main_text_size(self):
        self._apply_font_delta(-1.0)

    def reset_main_text_size(self):
        for widget, key in ((self.table, 'table'), (self.details_tree, 'details'), (self.hex_view, 'hex')):
            font = widget.font()
            base_size = self._base_fonts.get(key, 10.0)
            if base_size > 0:
                font.setPointSizeF(base_size)
                widget.setFont(font)
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
        self.table.resizeColumnsToContents()
        self.table.apply_content_resize_layout()

    def reset_layout_to_default_size(self):
        self.main_splitter.setSizes(self.default_main_splitter_sizes)
        self.lower_splitter.setSizes(self.default_lower_splitter_sizes)

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
        format_text = f'Wireshark/... - {ext}'

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
            'stats_packets_marked': '—',
            'stats_time_span': f'{elapsed_seconds:.3f}',
            'stats_average_pps': f'{avg_pps:.1f}',
            'stats_average_packet_size': f'{avg_pkt_size:.0f}',
            'stats_bytes_displayed': f'{displayed_bytes} ({byte_ratio:.1f}%)',
            'stats_bytes_marked': '0',
            'stats_average_bytes_s': f'{avg_bytes_per_sec / 1000.0:.0f} k',
            'stats_average_bits_s': f'{avg_bits_per_sec / 1000.0:.0f} k',
        }

    def get_expert_information(self):
        entries = []
        for rec in self.records:
            info_text = (rec.info or '').lower()
            proto = (rec.protocol or '').upper()
            severity = 'Note'
            group = 'General'
            summary = None

            if 'retransmission' in info_text:
                severity = 'Warn'
                group = 'TCP'
                summary = 'Possible TCP retransmission'
            elif 'out-of-order' in info_text or 'out of order' in info_text:
                severity = 'Warn'
                group = 'TCP'
                summary = 'TCP out-of-order segment'
            elif 'reset' in info_text or 'rst' in info_text:
                severity = 'Warn'
                group = 'TCP'
                summary = 'Connection reset observed'
            elif proto == 'ICMP':
                severity = 'Note'
                group = 'Network'
                summary = 'ICMP diagnostic traffic'
            elif proto == 'DNS' and ('fail' in info_text or 'error' in info_text):
                severity = 'Warn'
                group = 'Name Resolution'
                summary = 'DNS response indicates failure'

            if summary:
                entries.append({
                    'packet': rec.number,
                    'severity': severity,
                    'group': group,
                    'protocol': rec.protocol,
                    'summary': summary,
                })

        return entries

    def focus_filter(self):
        """Focus vào display filter input"""
        self.display_filter_input.setFocus()
        self.display_filter_input.selectAll()

    def show_summary(self):
        """Xem tóm tắt"""
        if not self.records:
            QMessageBox.information(None, 'Summary', 'Không có packet')
            return

        proto_counts = Counter(r.protocol for r in self.records)
        total_bytes = sum(r.length for r in self.records)

        summary = f"Total Packets: {len(self.records)}\n"
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
        """Xem conversations"""
        if not self.records:
            QMessageBox.information(None, 'Conversations', 'Không có conversation')
            return

        from gui.conversations_dialog import ConversationsDialog
        dialog = ConversationsDialog(self.records, self)
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



