import logging
import socket
import json
import base64
import math
import ipaddress
import pickle
import csv
import os
import re
import time
from collections import Counter, defaultdict, deque
from datetime import datetime
from pathlib import Path
from PySide6.QtCore import Qt, QTimer, QSize, QPoint, QPointF, QSettings, QRectF
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QStackedWidget,
    QMenuBar, QToolBar, QLabel, QMenu, QMessageBox, QFileDialog,
    QSizePolicy, QToolButton, QDialog, QTableWidget, QTableWidgetItem,
    QHeaderView, QPushButton, QTextEdit, QInputDialog, QGridLayout, QScrollArea,
    QFrame, QTextBrowser, QTabWidget, QCheckBox, QSpinBox, QLineEdit, QComboBox,
    QAbstractItemView, QTreeWidget, QTreeWidgetItem, QToolTip, QRadioButton, QGroupBox, QButtonGroup,
    QListWidget, QSplitter, QGraphicsView, QGraphicsScene, QGraphicsEllipseItem, QGraphicsLineItem, QGraphicsSimpleTextItem, QGraphicsItem, QGraphicsPixmapItem
)
from PySide6.QtGui import QAction, QCursor, QFontMetrics, QIcon, QKeySequence, QPixmap, QTextDocument, QColor, QFont, QPainter, QPen, QBrush
from PySide6.QtWidgets import QColorDialog, QFontDialog
from PySide6.QtPrintSupport import QPrintDialog, QPrinter
from scapy.all import ARP, DNS, Ether, IP, IPv6, TCP, UDP
from core.filtering import DisplayFilter
from core.firewall_acl import (
    ACTION_ALLOW,
    ACTION_DENY,
    DIRECTION_INBOUND,
    DIRECTION_OUTBOUND,
    PRODUCT_CISCO,
    PRODUCT_IPFILTER,
    PRODUCT_IPFW,
    PRODUCT_IPTABLES,
    PRODUCT_NETSH_NEW,
    PRODUCT_NETSH_OLD,
    PRODUCT_PF,
    PacketAclSnapshot,
    generate_rules_bundle,
)
from core.formatters import get_mac_vendor

from gui.interface_selector_view import InterfaceSelectorView
from gui.capture_view import CaptureView
from gui.packet_details import PacketDetailsTree
from gui.hex_view import PacketBytesView
from gui.manage_interfaces_dialog import ManageInterfacesDialog
from core.flow_engine import (
    analyze_flows,
    export_packets_to_csv,
    export_pcap_to_csv,
    PacketraModelAdapter,
    FlowFeatureExtractor,
)
from utils.pcap_io import (
    CaptureMetadata,
    clone_capture_metadata,
    iter_pcap_packets,
    load_capture_metadata,
    normalize_capture_extension,
    save_capture_file,
    save_capture_file_with_metadata,
)

log = logging.getLogger('application')


class NonScrollableTableWidget(QTableWidget):
    def wheelEvent(self, event):
        # Let the outer scroll area handle wheel scrolling.
        event.ignore()


class InterfaceTreeWidget(QTreeWidget):
    """Custom QTreeWidget for Capture Options with hover tooltip support"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.tooltip_item = None
        self.parent_dialog = None
        self.setMouseTracking(True)
    
    def mouseMoveEvent(self, event):
        """Show IP tooltip on hover"""
        item = self.itemAt(event.pos())
        if item and item.parent() is None:  # Top-level interface item
            iface_name = item.data(0, Qt.UserRole) or item.text(0).strip()
            if self.parent_dialog:
                ips = self.parent_dialog._get_interface_ips(iface_name)
                if ips and item != self.tooltip_item:
                    self.tooltip_item = item
                    # Show tooltip at mouse position - each IP on separate line
                    popup_text = "\n".join(ips)
                    global_pos = self.mapToGlobal(event.pos())
                    QToolTip.showText(global_pos, popup_text, self)
        else:
            self.tooltip_item = None
        super().mouseMoveEvent(event)


class TopologyGraphView(QGraphicsView):
    def __init__(self, scene: QGraphicsScene, parent=None):
        super().__init__(scene, parent)
        self._panning = False
        self._pan_start = QPoint()
        self.setRenderHint(QPainter.Antialiasing, True)
        self.setDragMode(QGraphicsView.NoDrag)
        self.setViewportUpdateMode(QGraphicsView.BoundingRectViewportUpdate)
        self.setTransformationAnchor(QGraphicsView.AnchorUnderMouse)
        self.setResizeAnchor(QGraphicsView.AnchorViewCenter)

    def wheelEvent(self, event):
        delta = int(event.angleDelta().y() or 0)
        if delta == 0:
            return super().wheelEvent(event)
        factor = 1.15 if delta > 0 else 1.0 / 1.15
        self.scale(factor, factor)
        event.accept()

    def mousePressEvent(self, event):
        if event.button() == Qt.RightButton:
            self._panning = True
            self._pan_start = event.pos()
            self.setCursor(Qt.ClosedHandCursor)
            event.accept()
            return
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event):
        if self._panning:
            delta = event.pos() - self._pan_start
            self._pan_start = event.pos()
            self.horizontalScrollBar().setValue(self.horizontalScrollBar().value() - int(delta.x()))
            self.verticalScrollBar().setValue(self.verticalScrollBar().value() - int(delta.y()))
            event.accept()
            return
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.RightButton and self._panning:
            self._panning = False
            self.setCursor(Qt.ArrowCursor)
            event.accept()
            return
        super().mouseReleaseEvent(event)


class TopologyNodeItem(QGraphicsEllipseItem):
    def __init__(self, node_id: str, label: str, radius: float, color: QColor, on_move, on_select, icon: QPixmap | None = None):
        super().__init__(-radius, -radius, radius * 2.0, radius * 2.0)
        self.node_id = str(node_id)
        self._on_move = on_move
        self._on_select = on_select
        self._radius = float(radius)
        self.setBrush(QBrush(color))
        self.setPen(QPen(QColor(50, 50, 50), 1.1))
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsMovable, True)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemIsSelectable, True)
        self.setFlag(QGraphicsItem.GraphicsItemFlag.ItemSendsGeometryChanges, True)
        self.setZValue(40)

        if isinstance(icon, QPixmap) and not icon.isNull():
            target = int(max(18, min(42, round(radius * 1.55))))
            scaled = icon.scaled(target, target, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            self.icon_item = QGraphicsPixmapItem(scaled, self)
            self.icon_item.setPos(-scaled.width() / 2.0, -scaled.height() / 2.0)
            self.icon_item.setZValue(45)

        self.label_item = QGraphicsSimpleTextItem(str(label), self)
        self.label_item.setBrush(QBrush(QColor(20, 20, 20)))
        metrics = QFontMetrics(self.label_item.font())
        text_w = metrics.horizontalAdvance(str(label))
        self.label_item.setPos(-text_w / 2.0, radius + 12.0)

    def itemChange(self, change, value):
        if change == QGraphicsItem.GraphicsItemChange.ItemPositionHasChanged and callable(self._on_move):
            try:
                self._on_move(self.node_id, QPointF(value))
            except Exception:
                pass
        return super().itemChange(change, value)

    def mousePressEvent(self, event):
        if callable(self._on_select):
            try:
                self._on_select('node', self.node_id)
            except Exception:
                pass
        super().mousePressEvent(event)


class TopologyEdgeItem(QGraphicsLineItem):
    def __init__(self, edge_id: str, on_select):
        super().__init__()
        self.edge_id = str(edge_id)
        self._on_select = on_select
        self.setZValue(10)

    def mousePressEvent(self, event):
        if callable(self._on_select):
            try:
                self._on_select('edge', self.edge_id)
            except Exception:
                pass
        super().mousePressEvent(event)

class CaptureFiltersDialog(QDialog):
    def __init__(self, parent, presets: list[dict], validator):
        super().__init__(parent)
        self.setWindowTitle('Capture Filters')
        self.resize(900, 520)
        self._validator = validator
        self._presets: list[dict] = [
            {
                'name': str(item.get('name', '') or '').strip(),
                'expression': str(item.get('expression', '') or '').strip(),
                'comment': str(item.get('comment', '') or '').strip(),
            }
            for item in (presets or [])
            if isinstance(item, dict)
        ]

        root = QVBoxLayout(self)

        self.table = QTableWidget(0, 3, self)
        self.table.setHorizontalHeaderLabels(['Name', 'Filter Expression', 'Comment'])
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        root.addWidget(self.table)

        form = QGridLayout()
        form.addWidget(QLabel('Name:'), 0, 0)
        self.name_input = QLineEdit(self)
        form.addWidget(self.name_input, 0, 1)
        form.addWidget(QLabel('Filter Expression:'), 1, 0)
        self.expr_input = QLineEdit(self)
        form.addWidget(self.expr_input, 1, 1)
        form.addWidget(QLabel('Comment:'), 2, 0)
        self.comment_input = QLineEdit(self)
        form.addWidget(self.comment_input, 2, 1)
        root.addLayout(form)

        self.status_label = QLabel('', self)
        root.addWidget(self.status_label)

        row_actions = QHBoxLayout()
        self.new_btn = QPushButton('New', self)
        self.copy_btn = QPushButton('Copy', self)
        self.delete_btn = QPushButton('Delete', self)
        self.validate_btn = QPushButton('Validate', self)
        self.apply_btn = QPushButton('Apply', self)
        row_actions.addWidget(self.new_btn)
        row_actions.addWidget(self.copy_btn)
        row_actions.addWidget(self.delete_btn)
        row_actions.addWidget(self.validate_btn)
        row_actions.addWidget(self.apply_btn)
        row_actions.addStretch(1)
        root.addLayout(row_actions)

        bottom = QHBoxLayout()
        bottom.addStretch(1)
        self.ok_btn = QPushButton('OK', self)
        self.cancel_btn = QPushButton('Cancel', self)
        bottom.addWidget(self.ok_btn)
        bottom.addWidget(self.cancel_btn)
        root.addLayout(bottom)

        self.table.itemSelectionChanged.connect(self._on_selection_changed)
        self.new_btn.clicked.connect(self._on_new)
        self.copy_btn.clicked.connect(self._on_copy)
        self.delete_btn.clicked.connect(self._on_delete)
        self.validate_btn.clicked.connect(self._on_validate)
        self.apply_btn.clicked.connect(self._on_apply)
        self.ok_btn.clicked.connect(self._on_ok)
        self.cancel_btn.clicked.connect(self.reject)

        self._reload_table()

    def presets(self) -> list[dict]:
        return list(self._presets)

    def _selected_row(self) -> int:
        row = self.table.currentRow()
        return row if 0 <= row < len(self._presets) else -1

    def _reload_table(self):
        self.table.setRowCount(0)
        for preset in self._presets:
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setItem(row, 0, QTableWidgetItem(str(preset.get('name', ''))))
            self.table.setItem(row, 1, QTableWidgetItem(str(preset.get('expression', ''))))
            self.table.setItem(row, 2, QTableWidgetItem(str(preset.get('comment', ''))))
        if self.table.rowCount() > 0:
            self.table.selectRow(0)
        else:
            self._on_selection_changed()

    def _on_selection_changed(self):
        row = self._selected_row()
        enabled = row >= 0
        self.copy_btn.setEnabled(enabled)
        self.delete_btn.setEnabled(enabled)
        if not enabled:
            self.name_input.clear()
            self.expr_input.clear()
            self.comment_input.clear()
            return
        preset = self._presets[row]
        self.name_input.setText(str(preset.get('name', '')))
        self.expr_input.setText(str(preset.get('expression', '')))
        self.comment_input.setText(str(preset.get('comment', '')))

    def _build_current_preset(self) -> dict:
        return {
            'name': self.name_input.text().strip(),
            'expression': self.expr_input.text().strip(),
            'comment': self.comment_input.text().strip(),
        }

    def _validate_current_expression(self, show_ok: bool = False) -> bool:
        expression = self.expr_input.text().strip()
        ok, err = self._validator(expression, None)
        if ok:
            self.status_label.setText('Valid capture filter')
            if show_ok:
                QMessageBox.information(self, 'Capture Filter', 'Valid capture filter.')
            return True
        self.status_label.setText(f'Invalid capture filter: {err}')
        QMessageBox.warning(self, 'Invalid Capture Filter', f'Capture filter syntax error:\n{err}')
        return False

    def _on_new(self):
        self.name_input.setText('New Filter')
        self.expr_input.clear()
        self.comment_input.clear()
        self.status_label.clear()
        self.table.clearSelection()

    def _on_copy(self):
        row = self._selected_row()
        if row < 0:
            return
        current = self._presets[row]
        self.name_input.setText(f"{str(current.get('name', '')).strip()} Copy")
        self.expr_input.setText(str(current.get('expression', '')))
        self.comment_input.setText(str(current.get('comment', '')))

    def _on_delete(self):
        row = self._selected_row()
        if row < 0:
            return
        del self._presets[row]
        self._reload_table()

    def _on_validate(self):
        self._validate_current_expression(show_ok=True)

    def _on_apply(self):
        candidate = self._build_current_preset()
        if not candidate['name']:
            QMessageBox.warning(self, 'Capture Filter', 'Filter name is required.')
            return
        if not self._validate_current_expression(show_ok=False):
            return

        row = self._selected_row()
        if row >= 0:
            self._presets[row] = candidate
        else:
            self._presets.append(candidate)
        self._reload_table()

        for idx, preset in enumerate(self._presets):
            if preset.get('name') == candidate['name'] and preset.get('expression') == candidate['expression']:
                self.table.selectRow(idx)
                break

    def _on_ok(self):
        if self.name_input.text().strip() or self.expr_input.text().strip() or self.comment_input.text().strip():
            self._on_apply()
        self.accept()


class CaptureOptionsDialog(QDialog):
    """Capture Options dialog với 3 tabs: Input, Output, Options"""
    
    def __init__(self, parent, capture_view, read_only: bool = False):
        super().__init__(parent)
        self.setWindowTitle('Capture Options')
        self.capture_view = capture_view
        self._read_only_mode = bool(read_only)
        self.resize(1100, 600)
        
        # Initialize state model for Output tab
        self.output_state = {
            'file_path': '',
            'format': 'pcapng',  # pcapng or pcap
            'compression': 'none',  # none, gzip, lz4
            'auto_create': False,
            'rollover_packets_enabled': False,
            'rollover_packets_value': 100000,
            'rollover_size_enabled': False,
            'rollover_size_value': 1,
            'rollover_size_unit': 'kilobytes',  # kilobytes, megabytes, gigabytes
            'rollover_duration_enabled': False,
            'rollover_duration_value': 1,
            'rollover_duration_unit': 'seconds',  # seconds, minutes, hours
            'rollover_wallclock_enabled': False,
            'rollover_wallclock_value': 1,
            'rollover_wallclock_unit': 'hours',  # hours, days
            'infix_pattern': 'timestamp_first',  # timestamp_first or counter_first
            'ring_buffer_enabled': False,
            'ring_buffer_files': 2,
        }
        self.options_state = {
            'realtime': True,
            'autoscroll': True,
            'show_info': False,
            'resolve_mac': True,
            'resolve_network': False,
            'resolve_transport': False,
            'stop_packets_enabled': False,
            'stop_packets_value': 1,
            'stop_files_enabled': False,
            'stop_files_value': 1,
            'stop_size_enabled': False,
            'stop_size_value': 1,
            'stop_size_unit': 'kilobytes',
            'stop_duration_enabled': False,
            'stop_duration_value': 1,
            'stop_duration_unit': 'seconds',
        }
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)
        
        # Tabs
        self.tabs = QTabWidget()
        self.input_tab = QWidget()
        self.output_tab = QWidget()
        self.options_tab = QWidget()
        
        self.tabs.addTab(self.input_tab, "Input")
        self.tabs.addTab(self.output_tab, "Output")
        self.tabs.addTab(self.options_tab, "Options")
        
        layout.addWidget(self.tabs)
        
        # Buttons
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        self.start_btn = QPushButton('Start')
        self.start_btn.clicked.connect(self._on_start_from_options)
        self.start_btn.setEnabled(False)
        btn_layout.addWidget(self.start_btn)
        
        close_btn = QPushButton('Close')
        close_btn.clicked.connect(self.reject)
        btn_layout.addWidget(close_btn)
        
        help_btn = QPushButton('Help')
        btn_layout.addWidget(help_btn)
        
        layout.addLayout(btn_layout)
        
        # Build tabs
        self._build_input_tab()
        self._build_output_tab()
        self._build_options_tab()
        
        # Load persistent settings
        self._load_output_settings()
        self._load_options_settings()
        self._update_start_button_state()
        if self._read_only_mode:
            self._apply_read_only_mode()

    def _apply_read_only_mode(self):
        self.start_btn.setEnabled(False)
        self.start_btn.setVisible(False)
        for widget in [self.input_tab, self.output_tab, self.options_tab]:
            widget.setEnabled(False)
    
    def _load_output_settings(self):
        """Load Output tab settings from QSettings and apply to widgets"""
        settings = QSettings('Packetra', 'Packetra')
        
        # Load Output tab settings
        file_path = settings.value('output/file_path', '', str)
        format_val = settings.value('output/format', 'pcapng', str)
        compression = settings.value('output/compression', 'none', str)
        auto_create = settings.value('output/auto_create', False, bool)
        
        # Load rollover settings
        rollover_packets_enabled = settings.value('output/rollover_packets_enabled', False, bool)
        rollover_packets_value = settings.value('output/rollover_packets_value', 100000, int)
        rollover_size_enabled = settings.value('output/rollover_size_enabled', False, bool)
        rollover_size_value = settings.value('output/rollover_size_value', 1, int)
        rollover_size_unit = settings.value('output/rollover_size_unit', 'kilobytes', str)
        rollover_duration_enabled = settings.value('output/rollover_duration_enabled', False, bool)
        rollover_duration_value = settings.value('output/rollover_duration_value', 1, int)
        rollover_duration_unit = settings.value('output/rollover_duration_unit', 'seconds', str)
        rollover_wallclock_enabled = settings.value('output/rollover_wallclock_enabled', False, bool)
        rollover_wallclock_value = settings.value('output/rollover_wallclock_value', 1, int)
        rollover_wallclock_unit = settings.value('output/rollover_wallclock_unit', 'hours', str)
        infix_pattern = settings.value('output/infix_pattern', 'timestamp_first', str)
        ring_buffer_enabled = settings.value('output/ring_buffer_enabled', False, bool)
        ring_buffer_files = settings.value('output/ring_buffer_files', 2, int)
        
        # Update state model
        self.output_state.update({
            'file_path': file_path,
            'format': format_val,
            'compression': compression,
            'auto_create': auto_create,
            'rollover_packets_enabled': rollover_packets_enabled,
            'rollover_packets_value': rollover_packets_value,
            'rollover_size_enabled': rollover_size_enabled,
            'rollover_size_value': rollover_size_value,
            'rollover_size_unit': rollover_size_unit,
            'rollover_duration_enabled': rollover_duration_enabled,
            'rollover_duration_value': rollover_duration_value,
            'rollover_duration_unit': rollover_duration_unit,
            'rollover_wallclock_enabled': rollover_wallclock_enabled,
            'rollover_wallclock_value': rollover_wallclock_value,
            'rollover_wallclock_unit': rollover_wallclock_unit,
            'infix_pattern': infix_pattern,
            'ring_buffer_enabled': ring_buffer_enabled,
            'ring_buffer_files': ring_buffer_files,
        })
        
        # Apply settings to widgets (if they exist)
        if hasattr(self, 'file_path_input'):
            self.file_path_input.setText(file_path)
            self.fmt_pcapng.setChecked(format_val == 'pcapng')
            self.fmt_pcap.setChecked(format_val == 'pcap')
            self.comp_none.setChecked(compression == 'none')
            self.comp_gzip.setChecked(compression == 'gzip')
            self.comp_lz4.setChecked(compression == 'lz4')
            self.auto_create_cb.setChecked(auto_create)
            
            # Rollover settings
            self.rollover_packets_cb.setChecked(rollover_packets_enabled)
            self.rollover_packets_spin.setValue(rollover_packets_value)
            self.rollover_size_cb.setChecked(rollover_size_enabled)
            self.rollover_size_spin.setValue(rollover_size_value)
            self.rollover_size_unit.setCurrentText(rollover_size_unit)
            self.rollover_duration_cb.setChecked(rollover_duration_enabled)
            self.rollover_duration_spin.setValue(rollover_duration_value)
            self.rollover_duration_unit.setCurrentText(rollover_duration_unit)
            self.rollover_wallclock_cb.setChecked(rollover_wallclock_enabled)
            self.rollover_wallclock_spin.setValue(rollover_wallclock_value)
            self.rollover_wallclock_unit.setCurrentText(rollover_wallclock_unit)
            
            # Infix pattern
            self.infix_pattern_ts_first.setChecked(infix_pattern == 'timestamp_first')
            self.infix_pattern_counter_first.setChecked(infix_pattern == 'counter_first')
            
            # Ring buffer
            self.ring_buffer_cb.setChecked(ring_buffer_enabled)
            self.ring_buffer_spin.setValue(ring_buffer_files)
    
    def _save_output_settings(self):
        """Save Output tab settings to QSettings"""
        settings = QSettings('Packetra', 'Packetra')
        
        # Get current values from widgets
        if hasattr(self, 'file_path_input'):
            self.output_state['file_path'] = self.file_path_input.text()
            self.output_state['format'] = 'pcapng' if self.fmt_pcapng.isChecked() else 'pcap'
            self.output_state['compression'] = 'gzip' if self.comp_gzip.isChecked() else ('lz4' if self.comp_lz4.isChecked() else 'none')
            self.output_state['auto_create'] = self.auto_create_cb.isChecked()
            self.output_state['rollover_packets_enabled'] = self.rollover_packets_cb.isChecked()
            self.output_state['rollover_packets_value'] = self.rollover_packets_spin.value()
            self.output_state['rollover_size_enabled'] = self.rollover_size_cb.isChecked()
            self.output_state['rollover_size_value'] = self.rollover_size_spin.value()
            self.output_state['rollover_size_unit'] = self.rollover_size_unit.currentText()
            self.output_state['rollover_duration_enabled'] = self.rollover_duration_cb.isChecked()
            self.output_state['rollover_duration_value'] = self.rollover_duration_spin.value()
            self.output_state['rollover_duration_unit'] = self.rollover_duration_unit.currentText()
            self.output_state['rollover_wallclock_enabled'] = self.rollover_wallclock_cb.isChecked()
            self.output_state['rollover_wallclock_value'] = self.rollover_wallclock_spin.value()
            self.output_state['rollover_wallclock_unit'] = self.rollover_wallclock_unit.currentText()
            self.output_state['infix_pattern'] = 'timestamp_first' if self.infix_pattern_ts_first.isChecked() else 'counter_first'
            self.output_state['ring_buffer_enabled'] = self.ring_buffer_cb.isChecked()
            self.output_state['ring_buffer_files'] = self.ring_buffer_spin.value()
        
        # Save all settings to QSettings
        for key, value in self.output_state.items():
            settings.setValue(f'output/{key}', value)

    def _load_options_settings(self):
        """Load Options tab settings from QSettings and apply to widgets"""
        import tempfile

        settings = QSettings('Packetra', 'Packetra')
        defaults = {
            'realtime': True,
            'autoscroll': True,
            'show_info': False,
            'resolve_mac': True,
            'resolve_network': False,
            'resolve_transport': False,
            'stop_packets_enabled': False,
            'stop_packets_value': 1,
            'stop_files_enabled': False,
            'stop_files_value': 1,
            'stop_size_enabled': False,
            'stop_size_value': 1,
            'stop_size_unit': 'kilobytes',
            'stop_duration_enabled': False,
            'stop_duration_value': 1,
            'stop_duration_unit': 'seconds',
        }

        for key, default_value in defaults.items():
            value_type = bool if isinstance(default_value, bool) else int if isinstance(default_value, int) else str
            self.options_state[key] = settings.value(f'options/{key}', default_value, value_type)

        if hasattr(self, 'opt_realtime'):
            self.opt_realtime.setChecked(bool(self.options_state['realtime']))
            self.opt_autoscroll.setChecked(bool(self.options_state['autoscroll']))
            self.opt_showinfo.setChecked(bool(self.options_state['show_info']))
            self.opt_resolve_mac.setChecked(bool(self.options_state['resolve_mac']))
            self.opt_resolve_net.setChecked(bool(self.options_state['resolve_network']))
            self.opt_resolve_trans.setChecked(bool(self.options_state['resolve_transport']))
            self.stop_packets_cb.setChecked(bool(self.options_state['stop_packets_enabled']))
            self.stop_packets_spin.setValue(int(self.options_state['stop_packets_value']))
            self.stop_files_cb.setChecked(bool(self.options_state['stop_files_enabled']))
            self.stop_files_spin.setValue(int(self.options_state['stop_files_value']))
            self.stop_size_cb.setChecked(bool(self.options_state['stop_size_enabled']))
            self.stop_size_spin.setValue(int(self.options_state['stop_size_value']))
            self.stop_size_unit.setCurrentText(str(self.options_state['stop_size_unit']))
            self.stop_duration_cb.setChecked(bool(self.options_state['stop_duration_enabled']))
            self.stop_duration_spin.setValue(int(self.options_state['stop_duration_value']))
            self.stop_duration_unit.setCurrentText(str(self.options_state['stop_duration_unit']))

    def _save_options_settings(self):
        """Save Options tab settings to QSettings"""
        settings = QSettings('Packetra', 'Packetra')
        current = self.get_options_settings()
        for key, value in current.items():
            self.options_state[key] = value
            settings.setValue(f'options/{key}', value)
    
    def accept(self):
        """Override accept to save settings before closing"""
        if not self._validate_output_settings():
            return
        if not self._validate_options_settings():
            return
        self._save_output_settings()
        self._save_options_settings()
        super().accept()
    
    def reject(self):
        """Override reject to NOT save settings when user clicks Cancel or closes dialog."""
        super().reject()
    
    def reset_output_to_defaults(self):
        """Reset Output tab settings to defaults (for app close/shutdown)."""
        from PySide6.QtCore import QSettings
        settings = QSettings('Packetra', 'Packetra')
        for key in list(settings.allKeys()):
            if key.startswith('output/'):
                settings.remove(key)
    
    def reset_options_to_defaults(self):
        """Reset Options tab 'Stop capture' settings to defaults, but keep 'Display options' and 'Name resolution'."""
        from PySide6.QtCore import QSettings
        settings = QSettings('Packetra', 'Packetra')
        stop_keys = ['stop_packets_enabled', 'stop_packets_value', 'stop_files_enabled', 'stop_files_value',
                     'stop_size_enabled', 'stop_size_value', 'stop_size_unit',
                     'stop_duration_enabled', 'stop_duration_value', 'stop_duration_unit']
        for key in stop_keys:
            settings.remove(f'options/{key}')
    
    def _validate_output_settings(self):
        """Validate Output tab settings"""
        import os
        
        # Validate file path if provided
        if hasattr(self, 'file_path_input'):
            file_path = self.file_path_input.text().strip()
            if file_path:
                # Check if directory exists and is writable
                dir_path = os.path.dirname(file_path)
                if not dir_path:
                    dir_path = '.'
                
                if not os.path.exists(dir_path):
                    QMessageBox.warning(self, 'Invalid Path', f'Directory does not exist: {dir_path}')
                    return False
                
                if not os.access(dir_path, os.W_OK):
                    QMessageBox.warning(self, 'Invalid Path', f'Directory is not writable: {dir_path}')
                    return False
        
        # Validate Create new file automatically conditions
        if hasattr(self, 'auto_create_cb') and self.auto_create_cb.isChecked():
            packets_ok = self.rollover_packets_cb.isChecked()
            size_ok = self.rollover_size_cb.isChecked()
            duration_ok = self.rollover_duration_cb.isChecked()
            wallclock_ok = self.rollover_wallclock_cb.isChecked()
            
            if not (packets_ok or size_ok or duration_ok or wallclock_ok):
                QMessageBox.warning(self, 'No Rollover Condition', 
                    'When "Create a new file automatically" is checked, at least one rollover condition must be enabled.')
                return False
        
        return True

    def _validate_options_settings(self):
        """Validate Options tab settings"""
        return True
    
    def _build_input_tab(self):
        """Build Input tab with interface tree (like)"""
        layout = QVBoxLayout(self.input_tab)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)
        
        # Interface tree widget
        self.iface_tree = InterfaceTreeWidget()
        self.iface_tree.parent_dialog = self
        self.iface_tree.setColumnCount(8)
        self.iface_tree.setHeaderLabels([
            'Interface', 'Traffic', 'Link-layer Header', 'Promiscuous',
            'Snaplen (B)', 'Buffer (MB)', 'Capture Filter', 'Comment'
        ])
        self.iface_tree.header().setStretchLastSection(False)
        self.iface_tree.setColumnWidth(0, 200)
        self.iface_tree.setColumnWidth(1, 100)
        self.iface_tree.setColumnWidth(2, 130)
        self.iface_tree.setColumnWidth(3, 90)
        self.iface_tree.setColumnWidth(4, 100)
        self.iface_tree.setColumnWidth(5, 100)
        self.iface_tree.setColumnWidth(6, 150)
        self.iface_tree.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.iface_tree.setTextElideMode(Qt.TextElideMode.ElideNone)
        self.iface_tree.setUniformRowHeights(True)
        self.iface_tree.itemSelectionChanged.connect(self._update_start_button_state)
        self.iface_tree.itemSelectionChanged.connect(self._sync_filter_input_from_selection)
        
        # Double-click starts capture
        self.iface_tree.doubleClicked.connect(self._on_interface_double_clicked)
        # Expand/collapse on header click
        self.iface_tree.header().sectionClicked.connect(self._on_tree_header_clicked)
        self.iface_tree.header().sectionResized.connect(self._on_input_tree_section_resized)
        
        layout.addWidget(self.iface_tree)
        
        # Bottom controls section
        bottom_layout = QVBoxLayout()
        bottom_layout.setSpacing(8)
        
        # Checkboxes
        cb_layout = QHBoxLayout()
        self.promisc_all_cb = QCheckBox('Enable promiscuous mode on all interfaces')
        self.promisc_all_cb.setChecked(True)
        self.promisc_all_cb.stateChanged.connect(self._on_promisc_all_changed)
        cb_layout.addWidget(self.promisc_all_cb)
        
        # self.monitor_all_cb = QCheckBox('Enable monitor mode on all 802.11 interfaces')
        # cb_layout.addWidget(self.monitor_all_cb)
        self.manage_interfaces_btn = QPushButton('Manage Interfaces')
        self.manage_interfaces_btn.clicked.connect(self._on_manage_interfaces)
        cb_layout.addWidget(self.manage_interfaces_btn)
        cb_layout.addStretch()
        bottom_layout.addLayout(cb_layout)
        
        # Capture filter for selected interfaces
        filter_layout = QHBoxLayout()
        filter_label = QLabel('Capture filter for selected interfaces:')
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText('Enter a capture filter ...')
        self.apply_filter_btn = QPushButton('Apply')
        self.capture_filters_btn = QPushButton('Capture Filters...')
        self.apply_filter_btn.clicked.connect(self._apply_filter_to_selected_interface)
        self.capture_filters_btn.clicked.connect(self._open_capture_filters_manager)
        filter_layout.addWidget(filter_label)
        filter_layout.addWidget(self.filter_input)
        filter_layout.addWidget(self.apply_filter_btn)
        filter_layout.addWidget(self.capture_filters_btn)
        bottom_layout.addLayout(filter_layout)
        
        layout.addLayout(bottom_layout)
        
        # Populate tree with interfaces
        self._populate_interfaces()

        # Live traffic refresh for sparkline column.
        self.traffic_timer = QTimer(self)
        self.traffic_timer.timeout.connect(self._refresh_interface_traffic)
        self.traffic_timer.start(1000)
        
        # Setup hover tooltip
        self.tooltip_item = None
        self.iface_tree.setMouseTracking(True)
        self._sync_filter_input_from_selection()
    
    def _on_tree_header_clicked(self, section):
        """Prevent default header behavior"""
        pass
    
    def _on_tree_mouse_move(self, event):
        """Handle mouse move over tree to show IP popup"""
        item = self.iface_tree.itemAt(event.pos())
        if item and item.parent() is None:  # Top-level interface item
            iface_name = item.text(0).strip()
            ips = self._get_interface_ips(iface_name)
            
            if ips and item != self.tooltip_item:
                self.tooltip_item = item
                # Show tooltip at mouse position
                popup_text = "Addresses:\n" + "\n".join(ips)
                global_pos = self.iface_tree.mapToGlobal(event.pos())
                QToolTip.showText(global_pos, popup_text, self.iface_tree)
        else:
            self.tooltip_item = None
    
    def _get_interface_ips(self, iface_name):
        """Get all IP addresses for an interface"""
        import psutil
        try:
            addrs = psutil.net_if_addrs().get(iface_name, [])
            ips = []
            for addr in addrs:
                if addr.family in (socket.AF_INET, socket.AF_INET6) and addr.address:
                    ips.append(str(addr.address))
            return ips
        except Exception:
            return []
    
    def _get_sparkline_pixmap(self, iface_name, width=80, height=24):
        """Generate sparkline pixmap for traffic history (like interface_selector_view)"""
        from PySide6.QtGui import QPainter, QPen, QColor
        traffic_history = getattr(self, 'traffic_history', {}).get(iface_name, [])
        
        pix = QPixmap(width, height)
        pix.fill(Qt.transparent)
        painter = QPainter(pix)
        painter.setRenderHint(QPainter.Antialiasing, True)
        
        # Baseline
        painter.setPen(QPen(QColor('#D9DEE6'), 1))
        painter.drawLine(0, height - 2, width, height - 2)
        
        # Sparkline
        if traffic_history and max(traffic_history) > 0:
            max_value = max(traffic_history)
            pen = QPen(QColor('#2C7FB8'), 2)
            painter.setPen(pen)
            x_step = max(1.0, (width - 4) / max(1, (len(traffic_history) - 1)))
            points = []
            for i, v in enumerate(traffic_history):
                x = int(2 + i * x_step)
                y = int((height - 4) - (v / max_value) * (height - 8))
                points.append((x, y))
            for i in range(1, len(points)):
                painter.drawLine(points[i - 1][0], points[i - 1][1], points[i][0], points[i][1])
        
        painter.end()
        return pix

    def _on_input_tree_section_resized(self, logical_index, _old_size, new_size):
        """Resize traffic sparkline width when Traffic column width changes."""
        if logical_index != 1:
            return
        chart_width = max(40, int(new_size) - 8)
        for iface_name, label in self.traffic_widgets.items():
            if label:
                label.setPixmap(self._get_sparkline_pixmap(iface_name, width=chart_width))
    
    def _populate_interfaces(self):
        """Populate interface tree with available interfaces"""
        from utils.network_utils import get_interfaces, get_traffic
        import json
        from PySide6.QtCore import QSettings
        
        # Clear existing items first to avoid duplicates
        self.iface_tree.clear()
        
        interfaces = get_interfaces()
        settings = QSettings('Packetra', 'Packetra')
        default_promiscuous = bool(settings.value('capture/promiscuous_mode', True, bool))
        pipe_paths = [p.strip() for p in settings.value('pipes', '', str).splitlines() if p.strip()]
        for pipe_path in pipe_paths:
            interfaces[pipe_path] = pipe_path

        remotes_json = settings.value('remote_interfaces', '[]', str)
        try:
            remote_cfgs = json.loads(remotes_json)
        except Exception:
            remote_cfgs = []

        from urllib.parse import quote
        for remote in remote_cfgs:
            if not remote.get('show', True):
                continue
            host = str(remote.get('host', '')).strip()
            username = str(remote.get('username', '')).strip()
            port = int(remote.get('port', 22) or 22)
            if not host or not username:
                continue
            for iface in remote.get('interfaces', []):
                iface_name = str(iface.get('name', '')).strip()
                iface_target = str(iface.get('target', iface_name)).strip()
                iface_show = bool(iface.get('show', True))
                if not iface_name or not iface_show:
                    continue
                key = f"remote://{quote(username, safe='')}@{host}:{port}/{quote(iface_target, safe='')}"
                interfaces[key] = f"Remote: {username}@{host}:{iface_name}"

        settings_json = settings.value('interface_settings', '{}', str)
        try:
            saved_settings = json.loads(settings_json)
        except Exception:
            saved_settings = {}
        self.promisc_checkboxes = {}
        self.iface_items = {}
        self.traffic_widgets = {}
        traffic = get_traffic()
        self.prev_traffic = dict(traffic)
        self.smoothed_speed = {name: 0.0 for name in interfaces}
        self.traffic_history = {name: [0.0] * 24 for name in interfaces}
        
        for iface_name in interfaces:
            iface_key = f"interface_{iface_name}"
            iface_pref = saved_settings.get(iface_key, {})
            if not iface_pref.get('show', True):
                continue

            iface_item = QTreeWidgetItem()
            is_pipe = str(iface_name).startswith('\\\\.\\pipe\\')
            ips = [] if is_pipe else self._get_interface_ips(iface_name)
            # Column 0: Interface display name (friendly hoáº·c comment:friendly)
            friendly_name = iface_pref.get('friendly_name', interfaces.get(iface_name, iface_name))
            comment = iface_pref.get('comment', '')
            show_with_comment = iface_pref.get('show_with_comment', False)
            display_name = f"{comment}:{friendly_name}" if show_with_comment and comment else friendly_name
            iface_item.setText(0, display_name)
            iface_item.setData(0, Qt.UserRole, iface_name)
            iface_item.setFirstColumnSpanned(False)
            self.iface_tree.addTopLevelItem(iface_item)
            self.iface_items[iface_name] = iface_item
            # Column 1: Traffic (show sparkline)
            chart_width = max(40, self.iface_tree.columnWidth(1) - 8)
            pix = self._get_sparkline_pixmap(iface_name, width=chart_width)
            traffic_label = QLabel()
            traffic_label.setPixmap(pix)
            traffic_label._traffic_bytes = traffic.get(iface_name, 0)
            self.iface_tree.setItemWidget(iface_item, 1, traffic_label)
            self.traffic_widgets[iface_name] = traffic_label
            # Column 2: Link-layer Header (text, double-click to edit)
            iface_item.setText(2, "Named pipe" if is_pipe else "Ethernet")
            iface_item.setData(2, Qt.UserRole, "Named pipe" if is_pipe else "Ethernet")
            # Column 3: Promiscuous (checkbox widget)
            promisc_cb = QCheckBox()
            promisc_cb.setChecked(False if is_pipe else default_promiscuous)
            promisc_cb.setEnabled(not is_pipe)
            self.promisc_checkboxes[iface_name] = promisc_cb
            promisc_cb.stateChanged.connect(lambda state, i=iface_name: self._on_promisc_changed(i, state))
            self.iface_tree.setItemWidget(iface_item, 3, promisc_cb)
            # Column 4: Snaplen (text, double-click to edit)
            iface_item.setText(4, "default")
            iface_item.setData(4, Qt.UserRole, 262144)
            # Column 5: Buffer (text, double-click to edit)
            iface_item.setText(5, "2")
            iface_item.setData(5, Qt.UserRole, 2)
            # Column 6: Capture Filter (text, double-click to edit)
            iface_item.setText(6, "")
            iface_item.setData(6, Qt.UserRole, "")
            # Column 7: Comment (editable, double click)
            iface_item.setText(7, comment)
            iface_item.setData(7, Qt.UserRole, comment)
            # Add IP children (comma-separated for expand view)
            if ips:
                ip_item = QTreeWidgetItem(iface_item)
                ip_text = ", ".join(ips)
                ip_item.setText(0, ip_text)
                ip_item.setFlags(ip_item.flags() & ~Qt.ItemFlag.ItemIsSelectable)
                ip_item.setFirstColumnSpanned(True)

        if hasattr(self, 'promisc_all_cb'):
            eligible = [cb for cb in self.promisc_checkboxes.values() if cb.isEnabled()]
            total_count = len(eligible)
            checked_count = sum(1 for cb in eligible if cb.isChecked())
            self.promisc_all_cb.blockSignals(True)
            if total_count > 0 and checked_count == total_count:
                self.promisc_all_cb.setCheckState(Qt.CheckState.Checked)
            elif checked_count <= 0:
                self.promisc_all_cb.setCheckState(Qt.CheckState.Unchecked)
            else:
                self.promisc_all_cb.setCheckState(Qt.CheckState.PartiallyChecked)
            self.promisc_all_cb.blockSignals(False)

    def _refresh_interface_traffic(self):
        """Refresh traffic sparkline for each interface row."""
        from utils.network_utils import get_traffic

        current = get_traffic()
        alpha = 0.35
        for iface_name, item in self.iface_items.items():
            if str(iface_name).startswith('\\\\.\\pipe\\'):
                label = self.traffic_widgets.get(iface_name)
                if label:
                    label.setToolTip('Named pipe source')
                continue
            prev = self.prev_traffic.get(iface_name, 0)
            now = current.get(iface_name, 0)
            speed = max(now - prev, 0)
            smooth = alpha * speed + (1 - alpha) * self.smoothed_speed.get(iface_name, 0.0)
            self.smoothed_speed[iface_name] = smooth
            history = self.traffic_history.setdefault(iface_name, [0.0] * 24)
            history.append(smooth)
            history[:] = history[-24:]

            label = self.traffic_widgets.get(iface_name)
            if label:
                chart_width = max(40, self.iface_tree.columnWidth(1) - 8)
                label.setPixmap(self._get_sparkline_pixmap(iface_name, width=chart_width))
                label.setToolTip(f"{speed / 1024:.2f} KB/s")

        self.prev_traffic = current
    
    def _on_promisc_changed(self, iface_name, state):
        """Handle individual promiscuous checkbox change"""
        eligible = [cb for cb in self.promisc_checkboxes.values() if cb.isEnabled()]
        checked_count = sum(1 for cb in eligible if cb.isChecked())
        total_count = len(eligible)
        if total_count <= 0:
            return
        if checked_count < total_count:
            self.promisc_all_cb.blockSignals(True)
            self.promisc_all_cb.setCheckState(Qt.CheckState.PartiallyChecked if checked_count > 0 else Qt.CheckState.Unchecked)
            self.promisc_all_cb.blockSignals(False)
        else:
            self.promisc_all_cb.blockSignals(True)
            self.promisc_all_cb.setCheckState(Qt.CheckState.Checked)
            self.promisc_all_cb.blockSignals(False)
    
    def _on_promisc_all_changed(self, state):
        """Handle 'Enable promiscuous on all' checkbox"""
        if state == Qt.CheckState.PartiallyChecked:
            return
        checked = state == Qt.CheckState.Checked
        for cb in self.promisc_checkboxes.values():
            if not cb.isEnabled():
                continue
            cb.blockSignals(True)
            cb.setChecked(checked)
            cb.blockSignals(False)
    
    def _on_monitor_all_changed(self, state):
        # Removed monitor mode logic (not needed)
        pass
    
    def _on_start_from_options(self):
        """Handle Start button click in Capture Options"""
        self._apply_filter_to_selected_interface()
        item = self._get_selected_interface_item()
        if not item:
            QMessageBox.warning(self, 'No Interface', 'Please select an interface in the Input tab.')
            return
        self._start_capture_with_item(item)

    def _sync_filter_input_from_selection(self):
        if not hasattr(self, 'filter_input'):
            return
        item = self._get_selected_interface_item()
        if item is None:
            self.filter_input.setEnabled(False)
            if hasattr(self, 'apply_filter_btn'):
                self.apply_filter_btn.setEnabled(False)
            if hasattr(self, 'capture_filters_btn'):
                self.capture_filters_btn.setEnabled(True)
            self.filter_input.clear()
            return
        self.filter_input.setEnabled(True)
        if hasattr(self, 'apply_filter_btn'):
            self.apply_filter_btn.setEnabled(True)
        value = str(item.data(6, Qt.UserRole) or item.text(6) or '').strip()
        self.filter_input.setText(value)

    def _apply_filter_to_selected_interface(self):
        item = self._get_selected_interface_item()
        if item is None:
            return
        expression = self.filter_input.text().strip() if hasattr(self, 'filter_input') else ''
        item.setText(6, expression)
        item.setData(6, Qt.UserRole, expression)

    def _open_capture_filters_manager(self):
        parent_window = self.parent()
        if parent_window is None:
            return
        presets = []
        if hasattr(parent_window, '_load_capture_filter_presets'):
            presets = parent_window._load_capture_filter_presets()
        validator = getattr(parent_window, '_validate_capture_filter_expression', lambda expr, iface: (True, ''))
        dialog = CaptureFiltersDialog(self, presets, validator)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        if hasattr(parent_window, '_save_capture_filter_presets'):
            parent_window._save_capture_filter_presets(dialog.presets())

        applied = False
        if dialog.table.currentRow() >= 0:
            idx = dialog.table.currentRow()
            values = dialog.presets()
            if 0 <= idx < len(values):
                expression = str(values[idx].get('expression', '') or '').strip()
                self.filter_input.setText(expression)
                self._apply_filter_to_selected_interface()
                applied = True
        if not applied:
            self._sync_filter_input_from_selection()

    def _get_selected_interface_item(self):
        """Return selected top-level interface item or None"""
        if not hasattr(self, 'iface_tree'):
            return None
        selected = self.iface_tree.selectedItems()
        if not selected:
            return None
        item = selected[0]
        if item.parent() is not None:
            return None
        return item

    def _update_start_button_state(self):
        """Enable Start only when a valid interface row is selected"""
        if hasattr(self, 'start_btn'):
            self.start_btn.setEnabled(self._get_selected_interface_item() is not None)

    def _validate_capture_filter_expression(self, expression, iface_name=None):
        """Validate BPF capture filter syntax using libpcap-compatible compilers.

        This keeps support broad for advanced BPF primitives/operators instead of
        restricting users to a subset of protocol/IP/MAC/port patterns.
        """
        expr = (expression or '').strip()
        if not expr:
            return True, ''

        compile_errors = []
        compile_backends = []

        # Backend 1: scapy.arch.pcapdnet.compile_filter (pcap_compile semantics).
        try:
            from scapy.arch.pcapdnet import compile_filter as pcap_compile_filter
            compile_backends.append(lambda: pcap_compile_filter(expr, iface_name or None))
        except Exception:
            pass

        # Backend 2: scapy.all.compile_filter (if available in installed Scapy).
        try:
            from scapy.all import compile_filter as scapy_compile_filter
            compile_backends.append(lambda: scapy_compile_filter(expr, iface=iface_name or None))
        except Exception:
            pass

        for backend in compile_backends:
            try:
                backend()
                return True, ''
            except Exception as exc:
                compile_errors.append(str(exc))

        if compile_backends:
            return False, compile_errors[-1] if compile_errors else 'Unknown capture filter syntax error.'

        # If no compiler backend is discoverable, do not apply custom regex restrictions
        # that could reject valid BPF syntax. Runtime capture backend will validate.
        return True, ''

    def _start_capture_with_item(self, item):
        """Start capture using selected interface and current Output/Options settings"""
        if not self._validate_output_settings() or not self._validate_options_settings():
            return
        # Validate capture filter syntax (nếu có)
        capture_filter = str(item.data(6, Qt.UserRole) or '').strip()
        parent_window = self.parent()
        if hasattr(parent_window, '_resolve_capture_filter_alias'):
            capture_filter = str(parent_window._resolve_capture_filter_alias(capture_filter) or '').strip()
        iface_name = item.data(0, Qt.UserRole) or item.text(0).strip()
        is_valid_filter, filter_error = self._validate_capture_filter_expression(capture_filter, iface_name=iface_name)
        if not is_valid_filter:
            QMessageBox.warning(self, 'Invalid Capture Filter', f'Capture filter syntax error:\n{filter_error}')
            return

        self._save_output_settings()
        self._save_options_settings()

        iface_name = item.data(0, Qt.UserRole) or item.text(0).strip()
        iface_display_name = item.text(0).strip()
        # Gather all config from columns
        link_layer = item.data(2, Qt.UserRole)
        promisc = False
        if iface_name in self.promisc_checkboxes:
            promisc = self.promisc_checkboxes[iface_name].isChecked()
        snaplen = item.data(4, Qt.UserRole)
        buffer_mb = item.data(5, Qt.UserRole)
        # Compose config dict
        iface_config = {
            'iface_name': iface_name,
            'display_name': iface_display_name,
            'link_layer': link_layer,
            'promiscuous': promisc,
            'snaplen': snaplen,
            'buffer_mb': buffer_mb,
            'capture_filter': capture_filter,
        }
        # Thêm thông tin pipes và remote interfaces từ settings nếu có
        from PySide6.QtCore import QSettings
        import json
        settings = QSettings('Packetra', 'Packetra')
        pipes = settings.value('pipes', '', str)
        iface_config['pipes'] = [p.strip() for p in pipes.splitlines() if p.strip()]
        remotes_json = settings.value('remote_interfaces', '[]', str)
        try:
            iface_config['remote_interfaces'] = json.loads(remotes_json)
        except Exception:
            iface_config['remote_interfaces'] = []

        parent_window = self.parent()
        if hasattr(parent_window, 'show_capture_view'):
            parent_window.show_capture_view(iface_name, iface_display_name, capture_filter)
            if getattr(parent_window, 'capture_view', None):
                parent_window.capture_view.interface_config = iface_config
                parent_window.capture_view.set_output_settings(self.get_output_settings())
                parent_window.capture_view.set_options_settings(self.get_options_settings())
            if hasattr(parent_window, '_apply_capture_defaults_to_view'):
                parent_window._apply_capture_defaults_to_view()
            if hasattr(parent_window, '_on_start_capture'):
                parent_window._on_start_capture()
                if getattr(parent_window, 'capture_view', None) and parent_window.capture_view.is_capturing():
                    self.accept()
                return

        if self.capture_view is None:
            QMessageBox.warning(self, 'Capture Unavailable', 'Cannot start capture: capture view is not initialized.')
            return

        self.capture_view.interface_config = iface_config
        self.capture_view.set_interface(iface_name, iface_display_name, capture_filter)
        self.capture_view.set_output_settings(self.get_output_settings())
        self.capture_view.set_options_settings(self.get_options_settings())
        self.capture_view.start_new_capture()
        self.accept()
    
    def _on_interface_double_clicked(self, index):
        """Handle double-click based on column - inline editing"""
        item = self.iface_tree.itemFromIndex(index)
        if not item or item.parent() is not None:
            return

        column = index.column()
        # Column 0 (Interface name) - Start capture
        if column == 0:
            self.iface_tree.setCurrentItem(item)
            self._update_start_button_state()
            self._start_capture_with_item(item)

        # Column 2 (Link-layer Header) - Inline combo edit, chỉ cho phép các giá trị hợp lệ tùy loại interface
        elif column == 2:
            iface_name = item.data(0, Qt.UserRole) or item.text(0)
            # Lấy loại interface từ network_utils (nếu có)
            from utils.network_utils import get_interface_details
            details = get_interface_details().get(iface_name, {})
            iface_type = details.get('type', '').lower()
            # Mapping loại interface sang các header hợp lệ
            if 'ethernet' in iface_type:
                options = ['Ethernet', 'DOCSIS']
            elif 'wifi' in iface_type or '802.11' in iface_type:
                options = ['802.11']
            elif 'ppp' in iface_type:
                options = ['PPP over serial']
            elif 'hdlc' in iface_type:
                options = ['Cisco HDLC']
            elif 'atm' in iface_type:
                options = ['RFC 1483 IP-over-ATM', 'Sun raw ATM']
            elif 'loopback' in iface_type:
                options = ['BSD loopback']
            elif 'raw' in iface_type:
                options = ['Raw IP']
            else:
                # Nếu không xác định, cho phép tất cả
                options = ['Ethernet', 'DOCSIS', '802.11', 'PPP over serial', 'Cisco HDLC',
                           'RFC 1483 IP-over-ATM', 'Sun raw ATM', 'Raw IP', 'BSD loopback']
            self._edit_inline_combobox(item, column, options)

        # Column 4 (Snaplen) - Inline spinbox edit
        elif column == 4:
            self._edit_inline_spinbox(item, column, 0, 262144)

        # Column 5 (Buffer) - Inline spinbox edit
        elif column == 5:
            self._edit_inline_spinbox(item, column, 1, 512)

        # Column 6 (Capture Filter) - Inline text edit
        elif column == 6:
            self._edit_inline_text(item, column)
        # Column 7 (Comment) - Inline text edit
        elif column == 7:
            self._edit_inline_text(item, column)
    
    def _edit_inline_combobox(self, item, column, options):
        """Edit item inline with combobox"""
        combo = QComboBox()
        combo.addItems(options)
        current_text = item.text(column)
        if current_text in options:
            combo.setCurrentText(current_text)
        
        self.iface_tree.setItemWidget(item, column, combo)
        combo.setFocus()
        combo.showPopup()
        
        def finish_edit():
            item.setText(column, combo.currentText())
            item.setData(column, Qt.UserRole, combo.currentText())
            self.iface_tree.setItemWidget(item, column, None)
        
        combo.currentTextChanged.connect(finish_edit)
    
    def _edit_inline_spinbox(self, item, column, min_val, max_val):
        """Edit item inline with spinbox"""
        spin = QSpinBox()
        spin.setMinimum(min_val)
        spin.setMaximum(max_val)
        current_value = item.data(column, Qt.UserRole)
        if current_value is None:
            current_text = item.text(column).strip().lower()
            if column == 4 and current_text == 'default':
                current_value = 262144
            else:
                current_value = min_val
        spin.setValue(int(current_value))
        
        self.iface_tree.setItemWidget(item, column, spin)
        spin.setFocus()
        spin.selectAll()
        
        def finish_edit():
            value = spin.value()
            if column == 4 and value == 262144:
                item.setText(column, "default")
            else:
                item.setText(column, str(value))
            item.setData(column, Qt.UserRole, value)
            self.iface_tree.setItemWidget(item, column, None)
        
        spin.editingFinished.connect(finish_edit)
    
    def _edit_inline_text(self, item, column):
        """Edit item inline with text input"""
        line_edit = QLineEdit()
        line_edit.setText(item.text(column))
        
        self.iface_tree.setItemWidget(item, column, line_edit)
        line_edit.setFocus()
        line_edit.selectAll()
        
        def finish_edit():
            item.setText(column, line_edit.text())
            item.setData(column, Qt.UserRole, line_edit.text())
            self.iface_tree.setItemWidget(item, column, None)
        
        line_edit.editingFinished.connect(finish_edit)
    
    def _on_manage_interfaces(self):
        """Open Manage Interfaces dialog"""
        dialog = ManageInterfacesDialog(self)
        dialog.exec()
        # Always refresh after dialog closes
        self._on_interface_preferences_changed()
        self._update_start_button_state()

    def _on_interface_preferences_changed(self):
        """Refresh Input tab and forward interface preference changes to main window."""
        current_iface = None
        current_item = self._get_selected_interface_item()
        if current_item:
            current_iface = current_item.data(0, Qt.UserRole)

        self._populate_interfaces()

        if current_iface and current_iface in self.iface_items:
            self.iface_tree.setCurrentItem(self.iface_items[current_iface])

        main_window = self.parent()
        if main_window and hasattr(main_window, '_on_interface_preferences_changed'):
            main_window._on_interface_preferences_changed()
    
    def _build_output_tab(self):
        """Build Output tab"""
        from PySide6.QtWidgets import QGroupBox, QFileDialog
        layout = QVBoxLayout(self.output_tab)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(12)

        # --- Capture to a permanent file ---
        file_group = QGroupBox('Capture to a permanent file')
        file_layout = QHBoxLayout()
        self.file_path_input = QLineEdit()
        self.file_path_input.setPlaceholderText('Leave blank to use a temporary file')
        self.file_path_input.setToolTip('Specify capture file location. Leave blank to use temporary file.')
        self.file_path_input.textChanged.connect(lambda text: self._on_file_path_changed(text))
        file_layout.addWidget(QLabel('File:'))
        file_layout.addWidget(self.file_path_input)
        browse_btn = QPushButton('Browse...')
        browse_btn.setToolTip('Browse for capture file location')
        def on_browse():
            path, _ = QFileDialog.getSaveFileName(self, 'Select Capture File', '', 'PCAP Files (*.pcap *.pcapng);;All Files (*)')
            if path:
                selected_format = 'pcapng' if self.fmt_pcapng.isChecked() else 'pcap'
                path = normalize_capture_extension(path, selected_format)
                self.file_path_input.setText(path)
        browse_btn.clicked.connect(on_browse)
        file_layout.addWidget(browse_btn)
        file_group.setLayout(file_layout)
        layout.addWidget(file_group)

        # --- Output format ---
        fmt_layout = QHBoxLayout()
        fmt_layout.addWidget(QLabel('Output format:'))
        self.fmt_pcapng = QRadioButton('pcapng')
        self.fmt_pcap = QRadioButton('pcap')
        self.output_format_group = QButtonGroup(self)
        self.output_format_group.setExclusive(True)
        self.output_format_group.addButton(self.fmt_pcapng)
        self.output_format_group.addButton(self.fmt_pcap)
        self.fmt_pcapng.setChecked(True)
        self.fmt_pcapng.setToolTip('pcapng supports more metadata and multiple interfaces.')
        self.fmt_pcap.setToolTip('Legacy format.')
        self.fmt_pcapng.toggled.connect(lambda: self._on_format_changed())
        self.fmt_pcap.toggled.connect(lambda: self._on_format_changed())
        fmt_layout.addWidget(self.fmt_pcapng)
        fmt_layout.addWidget(self.fmt_pcap)
        fmt_layout.addStretch()
        layout.addLayout(fmt_layout)

        # --- Compression ---
        comp_layout = QHBoxLayout()
        comp_layout.addWidget(QLabel('Compression:'))
        self.comp_none = QRadioButton('None')
        self.comp_gzip = QRadioButton('gzip')
        self.comp_lz4 = QRadioButton('LZ4')
        self.compression_group = QButtonGroup(self)
        self.compression_group.setExclusive(True)
        self.compression_group.addButton(self.comp_none)
        self.compression_group.addButton(self.comp_gzip)
        self.compression_group.addButton(self.comp_lz4)
        self.comp_none.setChecked(True)
        self.comp_none.setToolTip('No compression.')
        self.comp_gzip.setToolTip('Compress capture output files with gzip.')
        self.comp_lz4.setToolTip('Compress capture output files with LZ4.')
        self.comp_none.toggled.connect(lambda: self._on_compression_changed())
        self.comp_gzip.toggled.connect(lambda: self._on_compression_changed())
        self.comp_lz4.toggled.connect(lambda: self._on_compression_changed())
        comp_layout.addWidget(self.comp_none)
        comp_layout.addWidget(self.comp_gzip)
        comp_layout.addWidget(self.comp_lz4)
        comp_layout.addStretch()
        layout.addLayout(comp_layout)

        # --- Create a new file automatically ---
        self.auto_create_cb = QCheckBox('Create a new file automatically...')
        self.auto_create_cb.setToolTip('Switch to a new capture file based on rollover conditions.')
        self.auto_create_cb.toggled.connect(lambda checked: self._on_auto_create_changed(checked))
        layout.addWidget(self.auto_create_cb)

        # --- Rollover conditions ---
        rollover_grid = QGridLayout()
        # after N packets
        self.rollover_packets_cb = QCheckBox('after')
        self.rollover_packets_spin = QSpinBox()
        self.rollover_packets_spin.setMinimum(1)
        self.rollover_packets_spin.setMaximum(100000000)
        self.rollover_packets_spin.setValue(100000)
        self.rollover_packets_spin.setToolTip('Switch file after this many packets.')
        self.rollover_packets_cb.toggled.connect(lambda: self._on_rollover_packets_changed())
        self.rollover_packets_spin.valueChanged.connect(lambda: self._on_rollover_packets_changed())
        rollover_grid.addWidget(self.rollover_packets_cb, 0, 0)
        rollover_grid.addWidget(self.rollover_packets_spin, 0, 1)
        rollover_grid.addWidget(QLabel('packets'), 0, 2)
        # after N kilobytes/megabytes/gigabytes
        self.rollover_size_cb = QCheckBox('after')
        self.rollover_size_spin = QSpinBox()
        self.rollover_size_spin.setMinimum(1)
        self.rollover_size_spin.setMaximum(100000000)
        self.rollover_size_spin.setValue(1)
        self.rollover_size_unit = QComboBox()
        self.rollover_size_unit.addItems(['kilobytes', 'megabytes', 'gigabytes'])
        self.rollover_size_unit.setCurrentIndex(0)
        self.rollover_size_cb.toggled.connect(lambda: self._on_rollover_size_changed())
        self.rollover_size_spin.valueChanged.connect(lambda: self._on_rollover_size_changed())
        self.rollover_size_unit.currentTextChanged.connect(lambda: self._on_rollover_size_changed())
        rollover_grid.addWidget(self.rollover_size_cb, 1, 0)
        rollover_grid.addWidget(self.rollover_size_spin, 1, 1)
        rollover_grid.addWidget(self.rollover_size_unit, 1, 2)
        # after N seconds/minutes/hours
        self.rollover_duration_cb = QCheckBox('after')
        self.rollover_duration_spin = QSpinBox()
        self.rollover_duration_spin.setMinimum(1)
        self.rollover_duration_spin.setMaximum(100000000)
        self.rollover_duration_spin.setValue(1)
        self.rollover_duration_unit = QComboBox()
        self.rollover_duration_unit.addItems(['seconds', 'minutes', 'hours'])
        self.rollover_duration_unit.setCurrentIndex(0)
        self.rollover_duration_cb.toggled.connect(lambda: self._on_rollover_duration_changed())
        self.rollover_duration_spin.valueChanged.connect(lambda: self._on_rollover_duration_changed())
        self.rollover_duration_unit.currentTextChanged.connect(lambda: self._on_rollover_duration_changed())
        rollover_grid.addWidget(self.rollover_duration_cb, 2, 0)
        rollover_grid.addWidget(self.rollover_duration_spin, 2, 1)
        rollover_grid.addWidget(self.rollover_duration_unit, 2, 2)
        # when time is a multiple of N hours/days
        self.rollover_wallclock_cb = QCheckBox('when time is a multiple of')
        self.rollover_wallclock_spin = QSpinBox()
        self.rollover_wallclock_spin.setMinimum(1)
        self.rollover_wallclock_spin.setMaximum(100000000)
        self.rollover_wallclock_spin.setValue(1)
        self.rollover_wallclock_unit = QComboBox()
        self.rollover_wallclock_unit.addItems(['hours', 'days'])
        self.rollover_wallclock_unit.setCurrentIndex(0)
        self.rollover_wallclock_cb.toggled.connect(lambda: self._on_rollover_wallclock_changed())
        self.rollover_wallclock_spin.valueChanged.connect(lambda: self._on_rollover_wallclock_changed())
        self.rollover_wallclock_unit.currentTextChanged.connect(lambda: self._on_rollover_wallclock_changed())
        rollover_grid.addWidget(self.rollover_wallclock_cb, 3, 0)
        rollover_grid.addWidget(self.rollover_wallclock_spin, 3, 1)
        rollover_grid.addWidget(self.rollover_wallclock_unit, 3, 2)
        layout.addLayout(rollover_grid)

        # --- File infix pattern group ---
        infix_group = QGroupBox('File infix pattern')
        infix_layout = QVBoxLayout()
        self.infix_pattern_ts_first = QRadioButton('YYYYmmDDHHMMSS_NNNNN')
        self.infix_pattern_counter_first = QRadioButton('NNNNN_YYYYmmDDHHMMSS')
        self.infix_pattern_ts_first.setChecked(True)
        self.infix_pattern_ts_first.toggled.connect(lambda: self._on_infix_pattern_changed())
        self.infix_pattern_counter_first.toggled.connect(lambda: self._on_infix_pattern_changed())
        infix_layout.addWidget(self.infix_pattern_ts_first)
        infix_layout.addWidget(self.infix_pattern_counter_first)
        infix_group.setLayout(infix_layout)
        layout.addWidget(infix_group)

        # --- Ring buffer ---
        ring_layout = QHBoxLayout()
        self.ring_buffer_cb = QCheckBox('Use a ring buffer with')
        self.ring_buffer_cb.setToolTip('Overwrite oldest files after file limit reached.')
        self.ring_buffer_spin = QSpinBox()
        self.ring_buffer_spin.setMinimum(2)
        self.ring_buffer_spin.setMaximum(1000000)
        self.ring_buffer_spin.setValue(2)
        self.ring_buffer_cb.toggled.connect(lambda: self._on_ring_buffer_changed())
        self.ring_buffer_spin.valueChanged.connect(lambda: self._on_ring_buffer_changed())
        ring_layout.addWidget(self.ring_buffer_cb)
        ring_layout.addWidget(self.ring_buffer_spin)
        ring_layout.addWidget(QLabel('files'))
        ring_layout.addStretch()
        layout.addLayout(ring_layout)

        layout.addStretch()

        # --- Enable/disable logic ---
        def update_enable():
            auto = self.auto_create_cb.isChecked()
            for w in [self.rollover_packets_cb, self.rollover_packets_spin, self.rollover_size_cb, self.rollover_size_spin, self.rollover_size_unit,
                      self.rollover_duration_cb, self.rollover_duration_spin, self.rollover_duration_unit,
                      self.rollover_wallclock_cb, self.rollover_wallclock_spin, self.rollover_wallclock_unit,
                      self.infix_pattern_ts_first, self.infix_pattern_counter_first]:
                w.setEnabled(auto)
            # Each condition
            self.rollover_packets_spin.setEnabled(auto and self.rollover_packets_cb.isChecked())
            self.rollover_size_spin.setEnabled(auto and self.rollover_size_cb.isChecked())
            self.rollover_size_unit.setEnabled(auto and self.rollover_size_cb.isChecked())
            self.rollover_duration_spin.setEnabled(auto and self.rollover_duration_cb.isChecked())
            self.rollover_duration_unit.setEnabled(auto and self.rollover_duration_cb.isChecked())
            self.rollover_wallclock_spin.setEnabled(auto and self.rollover_wallclock_cb.isChecked())
            self.rollover_wallclock_unit.setEnabled(auto and self.rollover_wallclock_cb.isChecked())
            # Ring buffer does not depend on auto-create
            self.ring_buffer_cb.setEnabled(True)
            self.ring_buffer_spin.setEnabled(self.ring_buffer_cb.isChecked())

        self.auto_create_cb.toggled.connect(update_enable)
        self.rollover_packets_cb.toggled.connect(update_enable)
        self.rollover_size_cb.toggled.connect(update_enable)
        self.rollover_duration_cb.toggled.connect(update_enable)
        self.rollover_wallclock_cb.toggled.connect(update_enable)
        self.ring_buffer_cb.toggled.connect(update_enable)
        update_enable()
        self._on_format_changed()
        self._on_compression_changed()
        self._on_rollover_packets_changed()
        self._on_rollover_size_changed()
        self._on_rollover_duration_changed()
        self._on_rollover_wallclock_changed()
        self._on_infix_pattern_changed()
        self._on_ring_buffer_changed()
    
    def _on_format_changed(self):
        """Handle Output format radio button change"""
        if self.fmt_pcapng.isChecked():
            self.output_state['format'] = 'pcapng'
        else:
            self.output_state['format'] = 'pcap'

        # Keep permanent file path extension in sync with selected output format.
        if hasattr(self, 'file_path_input'):
            current_path = self.file_path_input.text().strip()
            if current_path:
                normalized_path = normalize_capture_extension(current_path, self.output_state['format'])
                if normalized_path != current_path:
                    self.file_path_input.blockSignals(True)
                    self.file_path_input.setText(normalized_path)
                    self.file_path_input.blockSignals(False)
                    self.output_state['file_path'] = normalized_path
    
    def _on_compression_changed(self):
        """Handle Compression radio button change"""
        if self.comp_gzip.isChecked():
            self.output_state['compression'] = 'gzip'
        elif self.comp_lz4.isChecked():
            self.output_state['compression'] = 'lz4'
        else:
            self.output_state['compression'] = 'none'
    
    def _on_auto_create_changed(self, checked):
        """Handle Create new file automatically checkbox change"""
        self.output_state['auto_create'] = checked
    
    def _on_file_path_changed(self, text):
        """Handle file path input change"""
        self.output_state['file_path'] = text
    
    def _on_rollover_packets_changed(self):
        """Handle rollover packets checkbox/spinbox change"""
        self.output_state['rollover_packets_enabled'] = self.rollover_packets_cb.isChecked()
        self.output_state['rollover_packets_value'] = self.rollover_packets_spin.value()
    
    def _on_rollover_size_changed(self):
        """Handle rollover size checkbox/spinbox/combo change"""
        self.output_state['rollover_size_enabled'] = self.rollover_size_cb.isChecked()
        self.output_state['rollover_size_value'] = self.rollover_size_spin.value()
        self.output_state['rollover_size_unit'] = self.rollover_size_unit.currentText()
    
    def _on_rollover_duration_changed(self):
        """Handle rollover duration checkbox/spinbox/combo change"""
        self.output_state['rollover_duration_enabled'] = self.rollover_duration_cb.isChecked()
        self.output_state['rollover_duration_value'] = self.rollover_duration_spin.value()
        self.output_state['rollover_duration_unit'] = self.rollover_duration_unit.currentText()
    
    def _on_rollover_wallclock_changed(self):
        """Handle rollover wallclock checkbox/spinbox/combo change"""
        self.output_state['rollover_wallclock_enabled'] = self.rollover_wallclock_cb.isChecked()
        self.output_state['rollover_wallclock_value'] = self.rollover_wallclock_spin.value()
        self.output_state['rollover_wallclock_unit'] = self.rollover_wallclock_unit.currentText()
    
    def _on_infix_pattern_changed(self):
        """Handle infix pattern radio button change"""
        self.output_state['infix_pattern'] = 'timestamp_first' if self.infix_pattern_ts_first.isChecked() else 'counter_first'
    
    def _on_ring_buffer_changed(self):
        """Handle ring buffer checkbox/spinbox change"""
        self.output_state['ring_buffer_enabled'] = self.ring_buffer_cb.isChecked()
        self.output_state['ring_buffer_files'] = self.ring_buffer_spin.value()
    
    def get_output_settings(self):
        """Get current Output tab settings"""
        # Update state model from widgets before returning
        if hasattr(self, 'file_path_input'):
            self.output_state['file_path'] = self.file_path_input.text()
            self.output_state['format'] = 'pcapng' if self.fmt_pcapng.isChecked() else 'pcap'
            self.output_state['compression'] = 'gzip' if self.comp_gzip.isChecked() else ('lz4' if self.comp_lz4.isChecked() else 'none')
            self.output_state['auto_create'] = self.auto_create_cb.isChecked()
            self.output_state['rollover_packets_enabled'] = self.rollover_packets_cb.isChecked()
            self.output_state['rollover_packets_value'] = self.rollover_packets_spin.value()
            self.output_state['rollover_size_enabled'] = self.rollover_size_cb.isChecked()
            self.output_state['rollover_size_value'] = self.rollover_size_spin.value()
            self.output_state['rollover_size_unit'] = self.rollover_size_unit.currentText()
            self.output_state['rollover_duration_enabled'] = self.rollover_duration_cb.isChecked()
            self.output_state['rollover_duration_value'] = self.rollover_duration_spin.value()
            self.output_state['rollover_duration_unit'] = self.rollover_duration_unit.currentText()
            self.output_state['rollover_wallclock_enabled'] = self.rollover_wallclock_cb.isChecked()
            self.output_state['rollover_wallclock_value'] = self.rollover_wallclock_spin.value()
            self.output_state['rollover_wallclock_unit'] = self.rollover_wallclock_unit.currentText()
            self.output_state['infix_pattern'] = 'timestamp_first' if self.infix_pattern_ts_first.isChecked() else 'counter_first'
            self.output_state['ring_buffer_enabled'] = self.ring_buffer_cb.isChecked()
            self.output_state['ring_buffer_files'] = self.ring_buffer_spin.value()
        
        return self.output_state.copy()

    def get_options_settings(self):
        """Get current Options tab settings"""
        if not hasattr(self, 'opt_realtime'):
            return {}
        self.options_state.update({
            'realtime': self.opt_realtime.isChecked(),
            'autoscroll': self.opt_autoscroll.isChecked(),
            'show_info': self.opt_showinfo.isChecked(),
            'resolve_mac': self.opt_resolve_mac.isChecked(),
            'resolve_network': self.opt_resolve_net.isChecked(),
            'resolve_transport': self.opt_resolve_trans.isChecked(),
            'stop_packets_enabled': self.stop_packets_cb.isChecked(),
            'stop_packets_value': self.stop_packets_spin.value(),
            'stop_files_enabled': self.stop_files_cb.isChecked(),
            'stop_files_value': self.stop_files_spin.value(),
            'stop_size_enabled': self.stop_size_cb.isChecked(),
            'stop_size_value': self.stop_size_spin.value(),
            'stop_size_unit': self.stop_size_unit.currentText(),
            'stop_duration_enabled': self.stop_duration_cb.isChecked(),
            'stop_duration_value': self.stop_duration_spin.value(),
            'stop_duration_unit': self.stop_duration_unit.currentText(),
        })
        return self.options_state.copy()
    
    def _build_options_tab(self):
        """Build Options tab"""
        from PySide6.QtWidgets import QFileDialog
        layout = QVBoxLayout(self.options_tab)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(12)

        # --- Display Options ---
        disp_group = QGroupBox('Display Options')
        disp_layout = QVBoxLayout()
        self.opt_realtime = QCheckBox('Update list of packets in real-time')
        self.opt_realtime.setChecked(True)
        self.opt_realtime.setToolTip('Update packet list while capture is running.')
        self.opt_autoscroll = QCheckBox('Automatically scroll during live capture')
        self.opt_autoscroll.setChecked(True)
        self.opt_autoscroll.setToolTip('Automatically scroll to newest packets.')
        self.opt_showinfo = QCheckBox('Show capture information during live capture')
        self.opt_showinfo.setChecked(False)
        self.opt_showinfo.setToolTip('Display live capture statistics dialog.')
        disp_layout.addWidget(self.opt_realtime)
        disp_layout.addWidget(self.opt_autoscroll)
        disp_layout.addWidget(self.opt_showinfo)
        disp_group.setLayout(disp_layout)
        layout.addWidget(disp_group)

        # --- Name Resolution ---
        name_group = QGroupBox('Name Resolution')
        name_layout = QVBoxLayout()
        self.opt_resolve_mac = QCheckBox('Resolve MAC addresses')
        self.opt_resolve_mac.setChecked(True)
        self.opt_resolve_mac.setToolTip('Translate MAC addresses into names.')
        self.opt_resolve_net = QCheckBox('Resolve network names')
        self.opt_resolve_net.setChecked(False)
        self.opt_resolve_net.setToolTip('Perform hostname resolution.')
        self.opt_resolve_trans = QCheckBox('Resolve transport names')
        self.opt_resolve_trans.setChecked(False)
        self.opt_resolve_trans.setToolTip('Translate TCP/UDP ports into names.')
        name_layout.addWidget(self.opt_resolve_mac)
        name_layout.addWidget(self.opt_resolve_net)
        name_layout.addWidget(self.opt_resolve_trans)
        name_group.setLayout(name_layout)
        layout.addWidget(name_group)

        # --- Stop capture automatically after... ---
        stop_group = QGroupBox('Stop capture automatically after...')
        stop_layout = QGridLayout()
        # Row 1: packets
        self.stop_packets_cb = QCheckBox()
        self.stop_packets_spin = QSpinBox()
        self.stop_packets_spin.setMinimum(1)
        self.stop_packets_spin.setMaximum(100000000)
        self.stop_packets_spin.setValue(1)
        stop_layout.addWidget(self.stop_packets_cb, 0, 0)
        stop_layout.addWidget(self.stop_packets_spin, 0, 1)
        stop_layout.addWidget(QLabel('packets'), 0, 2)
        # Row 2: files
        self.stop_files_cb = QCheckBox()
        self.stop_files_spin = QSpinBox()
        self.stop_files_spin.setMinimum(1)
        self.stop_files_spin.setMaximum(1000000)
        self.stop_files_spin.setValue(1)
        stop_layout.addWidget(self.stop_files_cb, 1, 0)
        stop_layout.addWidget(self.stop_files_spin, 1, 1)
        stop_layout.addWidget(QLabel('files'), 1, 2)
        # Row 3: size
        self.stop_size_cb = QCheckBox()
        self.stop_size_spin = QSpinBox()
        self.stop_size_spin.setMinimum(1)
        self.stop_size_spin.setMaximum(100000000)
        self.stop_size_spin.setValue(1)
        self.stop_size_unit = QComboBox()
        self.stop_size_unit.addItems(['kilobytes', 'megabytes', 'gigabytes'])
        stop_layout.addWidget(self.stop_size_cb, 2, 0)
        stop_layout.addWidget(self.stop_size_spin, 2, 1)
        stop_layout.addWidget(self.stop_size_unit, 2, 2)
        # Row 4: duration
        self.stop_duration_cb = QCheckBox()
        self.stop_duration_spin = QSpinBox()
        self.stop_duration_spin.setMinimum(1)
        self.stop_duration_spin.setMaximum(100000000)
        self.stop_duration_spin.setValue(1)
        self.stop_duration_unit = QComboBox()
        self.stop_duration_unit.addItems(['seconds', 'minutes', 'hours'])
        stop_layout.addWidget(self.stop_duration_cb, 3, 0)
        stop_layout.addWidget(self.stop_duration_spin, 3, 1)
        stop_layout.addWidget(self.stop_duration_unit, 3, 2)
        stop_group.setLayout(stop_layout)
        layout.addWidget(stop_group)

        layout.addStretch()

        # --- Enable/disable logic ---
        def update_enable():
            # Auto scroll only enabled if realtime enabled
            self.opt_autoscroll.setEnabled(self.opt_realtime.isChecked())
            # Stop conditions
            self.stop_packets_spin.setEnabled(self.stop_packets_cb.isChecked())
            self.stop_files_spin.setEnabled(self.stop_files_cb.isChecked())
            self.stop_size_spin.setEnabled(self.stop_size_cb.isChecked())
            self.stop_size_unit.setEnabled(self.stop_size_cb.isChecked())
            self.stop_duration_spin.setEnabled(self.stop_duration_cb.isChecked())
            self.stop_duration_unit.setEnabled(self.stop_duration_cb.isChecked())
        self.opt_realtime.toggled.connect(update_enable)
        self.stop_packets_cb.toggled.connect(update_enable)
        self.stop_files_cb.toggled.connect(update_enable)
        self.stop_size_cb.toggled.connect(update_enable)
        self.stop_duration_cb.toggled.connect(update_enable)
        update_enable()


class ApplicationWindow(QMainWindow):
    AI_TRAFFIC_COLUMNS = [
        'Flow ID', 'Source IP', 'Source Port', 'Destination IP', 'Destination Port', 'Protocol', 'Timestamp',
        'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets', 'Total Length of Fwd Packets',
        'Total Length of Bwd Packets', 'Fwd Packet Length Max', 'Fwd Packet Length Min', 'Fwd Packet Length Mean',
        'Fwd Packet Length Std', 'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean',
        'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 'Flow IAT Std',
        'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean', 'Fwd IAT Std', 'Fwd IAT Max',
        'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean', 'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min',
        'Fwd PSH Flags', 'Bwd PSH Flags', 'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length',
        'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s', 'Min Packet Length', 'Max Packet Length',
        'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance', 'FIN Flag Count', 'SYN Flag Count',
        'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count', 'CWE Flag Count',
        'ECE Flag Count', 'Down/Up Ratio', 'Average Packet Size', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size',
        'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate',
        'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate', 'Subflow Fwd Packets',
        'Subflow Fwd Bytes', 'Subflow Bwd Packets', 'Subflow Bwd Bytes', 'Init_Win_bytes_forward',
        'Init_Win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward', 'Active Mean', 'Active Std',
        'Active Max', 'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min', 'Label'
    ]

    AI_DROP_FOR_ML = {'Flow ID', 'Source IP', 'Source Port', 'Destination IP', 'Protocol', 'Timestamp'}
    AI_DROP_FOR_INFERENCE = AI_DROP_FOR_ML | {'Label'}
    AI_MODEL_DIR = Path(__file__).resolve().parents[1] / 'ai'
    AI_MODEL_FILE = 'ft_transformer_torchscript.pt'
    AI_SCALER_FILE = 'standard_scaler.pkl'
    AI_LABEL_ENCODER_FILE = 'label_encoder.pkl'
    AI_MODEL_INFO_FILE = 'model_info.json'
    DEMO_DOC_PATH = Path(__file__).resolve().parents[1] / 'docs' / 'md' / 'demo packet.md'
    DEMO_DIR = Path(__file__).resolve().parents[1] / 'demo'
    AI_FALLBACK_LABELS = [
        'BENIGN',
        'Bot',
        'DDoS',
        'DoS GoldenEye',
        'DoS Hulk',
        'DoS Slowhttptest',
        'DoS slowloris',
        'FTP-Patator',
        'Heartbleed',
        'Infiltration',
        'PortScan',
        'SSH-Patator',
        'Web Attack - Brute Force',
        'Web Attack - Sql Injection',
        'Web Attack - XSS',
    ]
    AI_LABEL_DESCRIPTIONS = {
        'BENIGN': 'Luu luong binh thuong, chua thay dau hieu tan cong ro rang trong cac flow da chon.',
        'Benign': 'Luu luong binh thuong, chua thay dau hieu tan cong ro rang trong cac flow da chon.',
        'Bot': 'Co dau hieu bot/botnet: may nguon co the dang bi dieu khien tu xa hoac tu dong tao ket noi bat thuong.',
        'DDoS': 'Co dau hieu tan cong DDoS: nhieu goi/flow tao tai lon ve dich trong thoi gian ngan.',
        'DoS GoldenEye': 'Co mau DoS GoldenEye: tan cong HTTP lam can kiet tai nguyen dich vu web.',
        'DoS Hulk': 'Co mau DoS Hulk: luu luong HTTP tan cong voi cuong do cao vao may chu web.',
        'DoS Slowhttptest': 'Co mau DoS SlowHTTPTest: giu ket noi HTTP cham de lam can kiet tai nguyen server.',
        'DoS slowloris': 'Co mau Slowloris: mo/giu nhieu ket noi HTTP chua hoan tat de lam treo web server.',
        'FTP-Patator': 'Co dau hieu brute force FTP: nhieu thu nghiem dang nhap hoac flow FTP bat thuong.',
        'Heartbleed': 'Co dau hieu Heartbleed/TLS heartbeat bat thuong, can kiem tra dich vu TLS lien quan.',
        'Infiltration': 'Co dau hieu xam nhap/di chuyen du lieu bat thuong, nen kiem tra host nguon va dich.',
        'PortScan': 'Co dau hieu quet cong: mot nguon truy van nhieu cong/dich vu de do tim be mat tan cong.',
        'SSH-Patator': 'Co dau hieu brute force SSH: nhieu thu nghiem ket noi/dang nhap SSH.',
        'Web Attack - Brute Force': 'Co dau hieu brute force tren ung dung web.',
        'Web Attack - Sql Injection': 'Co dau hieu tan cong SQL Injection vao ung dung web.',
        'Web Attack - XSS': 'Co dau hieu tan cong Cross-Site Scripting vao ung dung web.',
        'Web Attack - Brute Force': 'Co dau hieu brute force tren ung dung web.',
        'Web Attack - Sql Injection': 'Co dau hieu tan cong SQL Injection vao ung dung web.',
        'Web Attack - XSS': 'Co dau hieu tan cong Cross-Site Scripting vao ung dung web.',
    }

    def __init__(self):
        super().__init__()
        self.setWindowTitle('Packetra - Network Packet Analyzer')
        self.resize(1700, 930)
        self._ai_model_bundle = None
        self._fw_acl_dialog = None
        self._demo_packet_entries = None

        # Trạng thái ứng dụng
        self.current_view = None
        self.capture_view = None
        self.iface_selector_view = None
        self._toolbar_defaults = {
            'main_splitter': [500, 360],
            'lower_splitter': [980, 650],
        }
        self._search_icon_off = QIcon()
        self._search_icon_on = QIcon()
        self._status_mode = 'activity'
        self._status_activity_kind = 'load'
        self._selected_packet_number = None
        self._last_loaded_seconds = None
        self._capture_started_monotonic = None
        self._last_capture_seconds = None
        self._display_filter_helper = DisplayFilter()
        self._analyze_custom_columns = []
        self._custom_column_refresh_generation = 0
        self._custom_column_refresh_pending_rows = deque()
        self._custom_column_refresh_pending_set = set()
        self._custom_column_fit_timer = None
        self._custom_column_refresh_dispatch_timer = QTimer(self)
        self._custom_column_refresh_dispatch_timer.setSingleShot(True)
        self._custom_column_refresh_dispatch_timer.setInterval(12)
        self._custom_column_refresh_dispatch_timer.timeout.connect(self._dispatch_custom_column_refresh)
        self._custom_column_refresh_dispatch_generation = 0

        # Build UI
        self._build_ui()
        self._connect_signals()
        self._restore_main_window_placement_if_needed()

        # Show interface selector by default
        self.show_interface_selector()

    def _restore_main_window_placement_if_needed(self):
        settings = QSettings('Packetra', 'Packetra')
        enabled = bool(settings.value('preferences/remember_main_window_size_and_placement', True, bool))
        if not enabled:
            return
        geometry_hex = settings.value('preferences/main_window_geometry', '', str)
        if geometry_hex:
            try:
                self.restoreGeometry(bytes.fromhex(str(geometry_hex)))
            except Exception:
                pass

    def _save_main_window_placement_if_needed(self):
        settings = QSettings('Packetra', 'Packetra')
        enabled = bool(settings.value('preferences/remember_main_window_size_and_placement', True, bool))
        if not enabled:
            settings.remove('preferences/main_window_geometry')
            return
        try:
            settings.setValue('preferences/main_window_geometry', bytes(self.saveGeometry()).hex())
        except Exception:
            pass

    def _build_ui(self):
        """Xây dựng giao diện chính"""
        # Central widget
        central = QWidget()
        layout = QVBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Menubar
        self._build_menubar()

        # Toolbar
        self._build_toolbar()
        layout.addWidget(self.toolbar)

        # Stacked widget cho hai view
        self.stacked_widget = QStackedWidget()
        layout.addWidget(self.stacked_widget)

        # Status bar
        self.statusbar = self.statusBar()
        self.statusbar.setStyleSheet("border-top: 1px solid #ddd;")
        status_icon_dir = Path(__file__).resolve().parent.parent / 'image' / 'statusbar'

        self.expert_btn = QToolButton(self)
        self.expert_btn.setToolTip('Expert Information')
        self.expert_btn.setIcon(QIcon(str(status_icon_dir / 'exp_info.png')))
        self.expert_btn.setAutoRaise(True)

        self.properties_btn = QToolButton(self)
        self.properties_btn.setToolTip('Capture File Properties')
        self.properties_btn.setIcon(QIcon(str(status_icon_dir / 'cap_properties.png')))
        self.properties_btn.setAutoRaise(True)

        self.detail_field_label = QLabel('Field: - | Byte: 0')
        self.detail_field_label.setMinimumWidth(260)
        self.packet_label = QLabel('Loaded in -')
        self.dropped_label = QLabel('Dropped: 0')

        self.statusbar.addWidget(self.expert_btn)
        self.statusbar.addWidget(self.properties_btn)
        self.statusbar.addWidget(self.detail_field_label)
        self.statusbar.addWidget(self.packet_label)
        self.statusbar.addWidget(self.dropped_label)

        self.setCentralWidget(central)

    def _build_menubar(self):
        """Xay dung menu bar theo nhom tab feature."""
        menubar = self.menuBar()
        menubar.clear()

        # File menu
        file_menu = menubar.addMenu('&File')
        self.action_open = QAction('&Open...', self)
        self.action_open.setShortcut(QKeySequence.Open)
        file_menu.addAction(self.action_open)
        self.action_merge = QAction('&Merge...', self)
        file_menu.addAction(self.action_merge)
        file_menu.addSeparator()
        self.action_save = QAction('&Save', self)
        self.action_save.setShortcut(QKeySequence.Save)
        file_menu.addAction(self.action_save)
        self.action_save_as = QAction('Save &As...', self)
        self.action_save_as.setShortcut(QKeySequence.SaveAs)
        file_menu.addAction(self.action_save_as)
        self.action_separate = QAction('S&eparate', self)
        file_menu.addAction(self.action_separate)
        file_menu.addSeparator()
        self.action_export = QAction('&Export Specified Packets...', self)
        file_menu.addAction(self.action_export)
        file_menu.addSeparator()
        self.action_print = QAction('&Print...', self)
        self.action_print.setShortcut(QKeySequence.Print)
        file_menu.addAction(self.action_print)
        file_menu.addSeparator()
        self.action_exit = QAction('&Quit', self)
        self.action_exit.setShortcut(QKeySequence.Quit)
        file_menu.addAction(self.action_exit)

        # Hidden non-spec file actions (keep backend, remove from menu)
        self.action_export_flow_csv = QAction('Export &Flow CSV (Current Capture)', self)
        self.action_export_selected_flow_csv = QAction('Export Selected Packets to &Flow CSV', self)

        # Edit menu
        edit_menu = menubar.addMenu('&Edit')
        self.action_copy = QAction('&Copy', self)
        self.action_copy.setShortcut(QKeySequence.Copy)
        edit_menu.addAction(self.action_copy)
        edit_menu.addSeparator()
        self.action_find = QAction('Find &Packet...', self)
        self.action_find.setShortcut(QKeySequence.Find)
        edit_menu.addAction(self.action_find)
        self.action_find_next = QAction('Find &Next', self)
        self.action_find_next.setShortcut(QKeySequence.FindNext)
        edit_menu.addAction(self.action_find_next)
        self.action_find_previous = QAction('Find &Previous', self)
        self.action_find_previous.setShortcut(QKeySequence.FindPrevious)
        edit_menu.addAction(self.action_find_previous)
        edit_menu.addSeparator()
        self.action_mark_unmark_selected = QAction('Mark/Unmark &Selected', self)
        edit_menu.addAction(self.action_mark_unmark_selected)
        self.action_mark_unmark_all_displayed = QAction('Mark/Unmark &All Displayed Packets', self)
        edit_menu.addAction(self.action_mark_unmark_all_displayed)
        self.action_next_mark = QAction('&Next Mark', self)
        edit_menu.addAction(self.action_next_mark)
        self.action_previous_mark = QAction('&Previous Mark', self)
        edit_menu.addAction(self.action_previous_mark)
        edit_menu.addSeparator()
        self.action_ignore_unignore_selected = QAction('Ignore/Unignore S&elected', self)
        edit_menu.addAction(self.action_ignore_unignore_selected)
        self.action_ignore_unignore_all_displayed = QAction('Ignore/Unignore A&ll Displayed', self)
        edit_menu.addAction(self.action_ignore_unignore_all_displayed)
        edit_menu.addSeparator()
        self.action_packet_comment = QAction('Packet &Comment...', self)
        edit_menu.addAction(self.action_packet_comment)
        self.action_delete_all_packet_comments = QAction('&Delete All Packet Comments', self)
        edit_menu.addAction(self.action_delete_all_packet_comments)
        edit_menu.addSeparator()
        self.action_preferences = QAction('&Preferences...', self)
        edit_menu.addAction(self.action_preferences)

        # Hidden non-spec edit actions (keep object compatibility)
        self.action_undo = QAction('&Undo', self)
        self.action_redo = QAction('&Redo', self)
        self.action_cut = QAction('Cu&t', self)
        self.action_paste = QAction('&Paste', self)

        # View menu
        view_menu = menubar.addMenu('&View')
        self.action_view_main_toolbar = QAction('&Main Toolbar', self)
        self.action_view_main_toolbar.setCheckable(True)
        self.action_view_main_toolbar.setChecked(True)
        view_menu.addAction(self.action_view_main_toolbar)
        self.action_view_filter_toolbar = QAction('&Filter Toolbar', self)
        self.action_view_filter_toolbar.setCheckable(True)
        self.action_view_filter_toolbar.setChecked(True)
        view_menu.addAction(self.action_view_filter_toolbar)
        self.action_view_statusbar = QAction('&Statusbar', self)
        self.action_view_statusbar.setCheckable(True)
        self.action_view_statusbar.setChecked(True)
        view_menu.addAction(self.action_view_statusbar)
        view_menu.addSeparator()
        self.action_view_packet_list = QAction('Packet &List', self)
        self.action_view_packet_list.setCheckable(True)
        self.action_view_packet_list.setChecked(True)
        view_menu.addAction(self.action_view_packet_list)
        self.action_view_packet_details = QAction('Packet &Details', self)
        self.action_view_packet_details.setCheckable(True)
        self.action_view_packet_details.setChecked(True)
        view_menu.addAction(self.action_view_packet_details)
        self.action_view_packet_bytes = QAction('Packet &Bytes', self)
        self.action_view_packet_bytes.setCheckable(True)
        self.action_view_packet_bytes.setChecked(True)
        view_menu.addAction(self.action_view_packet_bytes)
        self.action_view_packet_diagram = QAction('Packet &Diagram', self)
        self.action_view_packet_diagram.setCheckable(True)
        self.action_view_packet_diagram.setChecked(True)
        view_menu.addAction(self.action_view_packet_diagram)
        view_menu.addSeparator()
        self.action_zoom_in = QAction('Zoom &In', self)
        self.action_zoom_in.setShortcut(QKeySequence.ZoomIn)
        view_menu.addAction(self.action_zoom_in)
        self.action_zoom_out = QAction('Zoom &Out', self)
        self.action_zoom_out.setShortcut(QKeySequence.ZoomOut)
        view_menu.addAction(self.action_zoom_out)
        self.action_zoom_reset = QAction('&Normal Size', self)
        view_menu.addAction(self.action_zoom_reset)
        view_menu.addSeparator()
        self.action_expand_subtrees = QAction('&Expand Subtrees', self)
        view_menu.addAction(self.action_expand_subtrees)
        self.action_collapse_subtrees = QAction('&Collapse Subtrees', self)
        view_menu.addAction(self.action_collapse_subtrees)
        self.action_expand_all = QAction('Expand &All', self)
        view_menu.addAction(self.action_expand_all)
        self.action_collapse_all = QAction('Collapse A&ll', self)
        view_menu.addAction(self.action_collapse_all)
        view_menu.addSeparator()
        self.action_view_colorize_packet_list = QAction('Colorize Packet &List', self)
        self.action_view_colorize_packet_list.setCheckable(True)
        self.action_view_colorize_packet_list.setChecked(True)
        view_menu.addAction(self.action_view_colorize_packet_list)
        self.action_view_colorize_conversation = QAction('Colorize C&onversation', self)
        view_menu.addAction(self.action_view_colorize_conversation)
        self.action_view_coloring_rules = QAction('Coloring &Rules...', self)
        view_menu.addAction(self.action_view_coloring_rules)
        view_menu.addSeparator()
        self.action_view_resize_all_columns = QAction('&Resize All Columns', self)
        self.action_view_resize_all_columns.setCheckable(True)
        self.action_view_resize_all_columns.setChecked(False)
        view_menu.addAction(self.action_view_resize_all_columns)
        self.action_view_show_packet_new_window = QAction('Show Packet in &New Window', self)
        view_menu.addAction(self.action_view_show_packet_new_window)
        self.action_view_redissect_packets = QAction('&Redissect Packets', self)
        view_menu.addAction(self.action_view_redissect_packets)
        self.action_view_reload_as_format_capture = QAction('Reload as File Format/&Capture', self)
        self.action_view_reload_as_format_capture.setCheckable(True)
        self.action_view_reload_as_format_capture.setChecked(False)
        view_menu.addAction(self.action_view_reload_as_format_capture)
        self.action_view_reload = QAction('&Reload', self)
        self.action_view_reload.setShortcut(QKeySequence.Refresh)
        view_menu.addAction(self.action_view_reload)

        # Hidden non-spec view action
        self.action_fullscreen = QAction('&Fullscreen', self)
        self.action_fullscreen.setShortcut(Qt.Key_F11)

        # Go menu
        go_menu = menubar.addMenu('&Go')
        self.action_go_back = QAction('&Back', self)
        self.action_go_back.setShortcut(QKeySequence('Alt+Left'))
        go_menu.addAction(self.action_go_back)
        self.action_go_forward = QAction('&Forward', self)
        self.action_go_forward.setShortcut(QKeySequence('Alt+Right'))
        go_menu.addAction(self.action_go_forward)
        go_menu.addSeparator()
        self.action_go_to_packet = QAction('Go to &Packet...', self)
        self.action_go_to_packet.setShortcut(QKeySequence('Ctrl+G'))
        go_menu.addAction(self.action_go_to_packet)
        self.action_go_to_corresponding_packet = QAction('Go to C&orresponding Packet', self)
        go_menu.addAction(self.action_go_to_corresponding_packet)
        go_menu.addSeparator()
        self.action_go_previous_packet = QAction('&Previous Packet', self)
        self.action_go_previous_packet.setShortcut(QKeySequence('Ctrl+Up'))
        go_menu.addAction(self.action_go_previous_packet)
        self.action_go_next_packet = QAction('&Next Packet', self)
        self.action_go_next_packet.setShortcut(QKeySequence('Ctrl+Down'))
        go_menu.addAction(self.action_go_next_packet)
        self.action_go_first_packet = QAction('&First Packet', self)
        self.action_go_first_packet.setShortcut(QKeySequence('Ctrl+Home'))
        go_menu.addAction(self.action_go_first_packet)
        self.action_go_last_packet = QAction('&Last Packet', self)
        self.action_go_last_packet.setShortcut(QKeySequence('Ctrl+End'))
        go_menu.addAction(self.action_go_last_packet)
        go_menu.addSeparator()
        self.action_go_previous_packet_conversation = QAction('Previous Packet in C&onversation', self)
        self.action_go_previous_packet_conversation.setShortcut(QKeySequence('Ctrl+,'))
        go_menu.addAction(self.action_go_previous_packet_conversation)
        self.action_go_next_packet_conversation = QAction('Next Packet in Con&versation', self)
        self.action_go_next_packet_conversation.setShortcut(QKeySequence('Ctrl+.'))
        go_menu.addAction(self.action_go_next_packet_conversation)
        go_menu.addSeparator()
        self.action_go_auto_scroll_live_capture = QAction('&Auto Scroll in Live Capture', self)
        self.action_go_auto_scroll_live_capture.setCheckable(True)
        self.action_go_auto_scroll_live_capture.setChecked(True)
        go_menu.addAction(self.action_go_auto_scroll_live_capture)

        # Capture menu
        capture_menu = menubar.addMenu('&Capture')
        self.action_capture_options = QAction('&Options...', self)
        capture_menu.addAction(self.action_capture_options)
        capture_menu.addSeparator()
        self.action_start_capture = QAction('&Start', self)
        self.action_start_capture.setShortcut(Qt.CTRL | Qt.Key_E)
        capture_menu.addAction(self.action_start_capture)
        self.action_stop_capture = QAction('St&op', self)
        capture_menu.addAction(self.action_stop_capture)
        self.action_restart_capture = QAction('&Restart', self)
        capture_menu.addAction(self.action_restart_capture)
        capture_menu.addSeparator()
        self.action_capture_filters = QAction('Capture &Filters...', self)
        capture_menu.addAction(self.action_capture_filters)
        self.action_refresh_interfaces = QAction('&Refresh Interfaces', self)
        capture_menu.addAction(self.action_refresh_interfaces)

        # Legacy compatibility alias (not shown in menu)
        self.action_interfaces = QAction('&Interfaces...', self)

        # Analyze menu
        analyze_menu = menubar.addMenu('&Analyze')
        self.action_display_filter_macros = QAction('Display Filter &Macros...', self)
        analyze_menu.addAction(self.action_display_filter_macros)
        self.action_display_filter_expression = QAction('Display Filter E&xpression...', self)
        analyze_menu.addAction(self.action_display_filter_expression)
        analyze_menu.addSeparator()
        self.action_apply_as_column = QAction('Apply as &Column', self)
        analyze_menu.addAction(self.action_apply_as_column)
        self.action_apply_as_filter = QAction('Apply as &Filter', self)
        analyze_menu.addAction(self.action_apply_as_filter)
        self.action_conversation_filter = QAction('Conversation F&ilter', self)
        analyze_menu.addAction(self.action_conversation_filter)
        analyze_menu.addSeparator()
        self.action_follow_stream = QAction('&Follow', self)
        analyze_menu.addAction(self.action_follow_stream)
        self.action_expert_info = QAction('&Expert Info', self)
        analyze_menu.addAction(self.action_expert_info)

        # Hidden non-spec analyze actions
        self.action_decode_as = QAction('&Decode As...', self)
        self.action_display_filters = QAction('&Display Filters', self)

        # Statistics menu
        statistics_menu = menubar.addMenu('&Statistics')
        self.action_capture_file_properties = QAction('Capture File &Properties', self)
        statistics_menu.addAction(self.action_capture_file_properties)
        self.action_resolved_addresses = QAction('&Resolved Addresses', self)
        statistics_menu.addAction(self.action_resolved_addresses)
        self.action_protocol_hierarchy = QAction('Protocol &Hierarchy', self)
        statistics_menu.addAction(self.action_protocol_hierarchy)
        self.action_conversations = QAction('&Conversations', self)
        statistics_menu.addAction(self.action_conversations)
        self.action_endpoints = QAction('&Endpoints', self)
        statistics_menu.addAction(self.action_endpoints)
        self.action_packet_lengths = QAction('Packet &Lengths', self)
        statistics_menu.addAction(self.action_packet_lengths)
        self.action_flow_graph = QAction('&Flow Graph', self)
        statistics_menu.addAction(self.action_flow_graph)
        self.action_http_statistics = QAction('&HTTP', self)
        statistics_menu.addAction(self.action_http_statistics)
        self.action_ipv4_statistics = QAction('I&Pv4 Statistics', self)
        statistics_menu.addAction(self.action_ipv4_statistics)
        self.action_ipv6_statistics = QAction('IPv&6 Statistics', self)
        statistics_menu.addAction(self.action_ipv6_statistics)

        # Tools menu
        tools_menu = menubar.addMenu('&Tools')

        # Hidden non-spec statistics actions
        self.action_summary = QAction('&Summary', self)
        self.action_io_graph = QAction('&I/O Graph', self)

        # Advanced tools actions
        self.action_advanced_dashboard = QAction('&Dashboard', self)
        self.action_advanced_demo_packet = QAction('&Demo Packet', self)
        self.action_advanced_draw_topo = QAction('&Network Topology Graph', self)
        self.action_advanced_ai_analyst = QAction('&AI Analyst', self)
        self.action_advanced_fwrule = QAction('&Firewall ACL Rules', self)

        # Keep original order expected by users
        tools_menu.addAction(self.action_advanced_ai_analyst)
        tools_menu.addAction(self.action_advanced_demo_packet)
        tools_menu.addAction(self.action_advanced_draw_topo)
        tools_menu.addAction(self.action_advanced_dashboard)
        tools_menu.addAction(self.action_advanced_fwrule)

        self.action_contents = QAction('&Contents', self)
        self.action_contents.setShortcut(QKeySequence.HelpContents)
        self.action_about = QAction('&About Packetra', self)
        self.action_about_qt = QAction('About &Qt', self)

    def _build_toolbar(self):
        """Xây dựng toolbar"""
        icon_dir = Path(__file__).resolve().parent.parent / 'image' / 'main_toolbar_items'

        def toolbar_icon(name: str) -> QIcon:
            path = icon_dir / name
            return QIcon(str(path)) if path.exists() else QIcon()

        self.toolbar = QToolBar('Main Toolbar')
        self.toolbar.setMovable(False)
        self.toolbar.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonIconOnly)
        self.toolbar.setIconSize(QSize(18, 18))

        # Start capture
        self.action_start_btn = QAction(toolbar_icon('x-capture-start.png'), 'Start', self)
        self.action_start_btn.setToolTip('Start')
        self.toolbar.addAction(self.action_start_btn)

        # Stop capture
        self.action_stop_btn = QAction(toolbar_icon('x-capture-stop.png'), 'Stop', self)
        self.action_stop_btn.setToolTip('Stop')
        self.toolbar.addAction(self.action_stop_btn)

        # Restart
        self.action_restart_btn = QAction(toolbar_icon('x-capture-restart.png'), 'Restart', self)
        self.action_restart_btn.setToolTip('Restart')
        self.toolbar.addAction(self.action_restart_btn)

        self.toolbar.addSeparator()

        # Settings
        self.action_settings_btn = QAction(toolbar_icon('x-capture-options.png'), 'Options', self)
        self.action_settings_btn.setToolTip('Options')
        self.toolbar.addAction(self.action_settings_btn)

        self.toolbar.addSeparator()

        # Open file
        self.action_open_btn = QAction(toolbar_icon('document-open.png'), 'Open a capture file', self)
        self.action_open_btn.setToolTip('Open a capture file')
        self.toolbar.addAction(self.action_open_btn)

        # Save file
        self.action_save_btn = QAction(toolbar_icon('x-capture-file-save.png'), 'Save this capture file', self)
        self.action_save_btn.setToolTip('Save this capture file')
        self.toolbar.addAction(self.action_save_btn)

        self.action_close_btn = QAction(toolbar_icon('x-capture-file-close.png'), 'Close this capture file', self)
        self.action_close_btn.setToolTip('Close this capture file')
        self.toolbar.addAction(self.action_close_btn)

        self.action_reload_btn = QAction(toolbar_icon('x-capture-file-reload.png'), 'Reload this file', self)
        self.action_reload_btn.setToolTip('Reload this file')
        self.toolbar.addAction(self.action_reload_btn)

        self.toolbar.addSeparator()

        # Find
        self.action_search_btn = QAction(toolbar_icon('edit-find.png'), 'Filter', self)
        self.action_search_btn.setToolTip('Filter')
        self.action_search_btn.setCheckable(True)
        self._search_icon_off = toolbar_icon('edit-find.png')
        self._search_icon_on = self._search_icon_off
        self.action_search_btn.setIcon(self._search_icon_off)
        self.action_search_btn.setChecked(False)
        self.toolbar.addAction(self.action_search_btn)

        # Color rules
        self.action_color_btn = QAction(toolbar_icon('x-colorize-packets.png'), 'Draw packet using color rules', self)
        self.action_color_btn.setToolTip('Draw packet using color rules')
        self.toolbar.addAction(self.action_color_btn)

        self.toolbar.addSeparator()

        self.action_prev_btn = QAction(toolbar_icon('go-previous.png'), 'Go to previous packet', self)
        self.action_prev_btn.setToolTip('Go to previous packet')
        self.toolbar.addAction(self.action_prev_btn)

        self.action_next_btn = QAction(toolbar_icon('go-next.png'), 'Go to next packet', self)
        self.action_next_btn.setToolTip('Go to next packet')
        self.toolbar.addAction(self.action_next_btn)

        self.action_jump_btn = QAction(toolbar_icon('go-jump.png'), 'Go to specified packet', self)
        self.action_jump_btn.setToolTip('Go to specified packet')
        self.toolbar.addAction(self.action_jump_btn)

        self.action_first_btn = QAction(toolbar_icon('go-first.png'), 'Go to first packet', self)
        self.action_first_btn.setToolTip('Go to first packet')
        self.toolbar.addAction(self.action_first_btn)

        self.action_last_btn = QAction(toolbar_icon('go-last.png'), 'Go to last packet', self)
        self.action_last_btn.setToolTip('Go to last packet')
        self.toolbar.addAction(self.action_last_btn)

        self.action_stay_last_btn = QAction(toolbar_icon('x-stay-last.png'), 'Auto scroll to last packet in live capture', self)
        self.action_stay_last_btn.setToolTip('Auto scroll to last packet in live capture')
        self.action_stay_last_btn.setCheckable(True)
        self.action_stay_last_btn.setChecked(True)
        self.toolbar.addAction(self.action_stay_last_btn)

        self.toolbar.addSeparator()

        self.action_zoom_in_btn = QAction(toolbar_icon('zoom-in.png'), 'Enlarge the main window text', self)
        self.action_zoom_in_btn.setToolTip('Enlarge the main window text')
        self.toolbar.addAction(self.action_zoom_in_btn)

        self.action_zoom_out_btn = QAction(toolbar_icon('zoom-out.png'), 'Shrink the main window text', self)
        self.action_zoom_out_btn.setToolTip('Shrink the main window text')
        self.toolbar.addAction(self.action_zoom_out_btn)

        self.action_zoom_reset_btn = QAction(toolbar_icon('zoom-original.png'), 'Return the main window text to its normal size', self)
        self.action_zoom_reset_btn.setToolTip('Return the main window text to its normal size')
        self.toolbar.addAction(self.action_zoom_reset_btn)

        self.action_resize_cols_btn = QAction(toolbar_icon('x-resize-columns.png'), 'Resize to fit content', self)
        self.action_resize_cols_btn.setToolTip('Resize to fit content')
        self.action_resize_cols_btn.setCheckable(True)
        self.action_resize_cols_btn.setChecked(False)
        self.toolbar.addAction(self.action_resize_cols_btn)

        self.action_reset_layout_btn = QAction(toolbar_icon('x-reset-layout_2.png'), 'Reset layout to default size', self)
        self.action_reset_layout_btn.setToolTip('Reset layout to default size')
        self.toolbar.addAction(self.action_reset_layout_btn)

        # Add stretch spacer
        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        self.toolbar.addWidget(spacer)

    def _connect_signals(self):
        """Ket noi tat ca signals."""
        # File menu
        self.action_open.triggered.connect(self._on_open_file)
        self.action_merge.triggered.connect(self._on_merge_file)
        self.action_save.triggered.connect(self._on_save_file)
        self.action_save_as.triggered.connect(self._on_save_as_file)
        self.action_separate.triggered.connect(self._on_separate_packets)
        self.action_export.triggered.connect(self._on_export_specified_packets)
        self.action_print.triggered.connect(self._on_print_packets)
        self.action_export_flow_csv.triggered.connect(self._on_export_flow_csv_current)
        self.action_export_selected_flow_csv.triggered.connect(self._on_export_flow_csv_selected)
        self.action_exit.triggered.connect(self._on_quit)

        # Edit menu
        self.action_copy.triggered.connect(self._on_copy)
        self.action_find.triggered.connect(self._on_search)
        self.action_find_next.triggered.connect(self._on_find_next)
        self.action_find_previous.triggered.connect(self._on_find_previous)
        self.action_mark_unmark_selected.triggered.connect(self._on_mark_unmark_selected)
        self.action_mark_unmark_all_displayed.triggered.connect(self._on_mark_unmark_all_displayed)
        self.action_next_mark.triggered.connect(self._on_next_mark)
        self.action_previous_mark.triggered.connect(self._on_previous_mark)
        self.action_ignore_unignore_selected.triggered.connect(self._on_ignore_unignore_selected)
        self.action_ignore_unignore_all_displayed.triggered.connect(self._on_ignore_unignore_all_displayed)
        self.action_packet_comment.triggered.connect(self._on_packet_comment)
        self.action_delete_all_packet_comments.triggered.connect(self._on_delete_all_packet_comments)
        self.action_preferences.triggered.connect(self._on_preferences)

        # View menu
        self.action_view_main_toolbar.triggered.connect(self._on_toggle_main_toolbar)
        self.action_view_filter_toolbar.triggered.connect(self._on_toggle_filter_toolbar)
        self.action_view_statusbar.triggered.connect(self._on_toggle_statusbar)
        self.action_view_packet_list.triggered.connect(lambda checked: self._on_toggle_packet_pane('packet_list', checked))
        self.action_view_packet_details.triggered.connect(lambda checked: self._on_toggle_packet_pane('packet_details', checked))
        self.action_view_packet_bytes.triggered.connect(lambda checked: self._on_toggle_packet_pane('packet_bytes', checked))
        self.action_view_packet_diagram.triggered.connect(lambda checked: self._on_toggle_packet_pane('packet_diagram', checked))
        self.action_zoom_in.triggered.connect(self._on_zoom_in)
        self.action_zoom_out.triggered.connect(self._on_zoom_out)
        self.action_zoom_reset.triggered.connect(self._on_zoom_reset)
        self.action_expand_subtrees.triggered.connect(self._on_expand_subtrees)
        self.action_collapse_subtrees.triggered.connect(self._on_collapse_subtrees)
        self.action_expand_all.triggered.connect(self._on_expand_all)
        self.action_collapse_all.triggered.connect(self._on_collapse_all)
        self.action_view_colorize_packet_list.triggered.connect(self._on_toggle_color_rules)
        self.action_view_colorize_conversation.triggered.connect(self._on_colorize_conversation)
        self.action_view_coloring_rules.triggered.connect(self._on_coloring_rules)
        self.action_view_resize_all_columns.triggered.connect(self._on_resize_columns)
        self.action_view_show_packet_new_window.triggered.connect(self._on_show_packet_new_window)
        self.action_view_redissect_packets.triggered.connect(self._on_redissect_packets)
        self.action_view_reload_as_format_capture.triggered.connect(self._on_reload_as_format_capture)
        self.action_view_reload.triggered.connect(self._on_reload_file)

        # Go menu
        self.action_go_back.triggered.connect(self._on_go_back)
        self.action_go_forward.triggered.connect(self._on_go_forward)
        self.action_go_to_packet.triggered.connect(self._on_toggle_go_to_packet)
        self.action_go_to_corresponding_packet.triggered.connect(self._on_go_to_corresponding_packet)
        self.action_go_previous_packet.triggered.connect(self._on_go_previous_packet)
        self.action_go_next_packet.triggered.connect(self._on_go_next_packet)
        self.action_go_first_packet.triggered.connect(self._on_go_first_packet)
        self.action_go_last_packet.triggered.connect(self._on_go_last_packet)
        self.action_go_previous_packet_conversation.triggered.connect(self._on_go_previous_packet_conversation)
        self.action_go_next_packet_conversation.triggered.connect(self._on_go_next_packet_conversation)
        self.action_go_auto_scroll_live_capture.triggered.connect(self._on_toggle_auto_scroll)

        # Capture menu
        self.action_capture_options.triggered.connect(self._on_capture_options)
        self.action_start_capture.triggered.connect(self._on_start_capture)
        self.action_stop_capture.triggered.connect(self._on_stop_capture)
        self.action_restart_capture.triggered.connect(self._on_restart_capture)
        self.action_capture_filters.triggered.connect(self._on_capture_filters)
        self.action_refresh_interfaces.triggered.connect(self._on_refresh_interfaces)

        # Analyze menu
        self.action_display_filter_macros.triggered.connect(self._on_display_filter_macros)
        self.action_display_filter_expression.triggered.connect(self._on_display_filter_expression)
        self.action_apply_as_column.triggered.connect(self._on_apply_as_column)
        self.action_apply_as_filter.triggered.connect(self._on_apply_as_filter)
        self.action_conversation_filter.triggered.connect(self._on_conversation_filter)
        self.action_follow_stream.triggered.connect(self._on_follow_stream)
        self.action_expert_info.triggered.connect(self._on_open_expert_information)

        # Statistics menu
        self.action_capture_file_properties.triggered.connect(self._on_open_capture_properties)
        self.action_resolved_addresses.triggered.connect(self._on_statistics_resolved_addresses)
        self.action_protocol_hierarchy.triggered.connect(self._on_statistics_protocol_hierarchy)
        self.action_conversations.triggered.connect(self._on_conversations)
        self.action_endpoints.triggered.connect(self._on_statistics_endpoints)
        self.action_packet_lengths.triggered.connect(self._on_statistics_packet_lengths)
        self.action_flow_graph.triggered.connect(self._on_statistics_flow_graph)
        self.action_http_statistics.triggered.connect(self._on_statistics_http)
        self.action_ipv4_statistics.triggered.connect(self._on_statistics_ipv4)
        self.action_ipv6_statistics.triggered.connect(self._on_statistics_ipv6)

        # Advanced Analysis
        self.action_advanced_dashboard.triggered.connect(lambda: self._on_advanced_analysis_action('Dashboard'))
        self.action_advanced_demo_packet.triggered.connect(lambda: self._on_advanced_analysis_action('Demo Packet'))
        self.action_advanced_draw_topo.triggered.connect(lambda: self._on_advanced_analysis_action('Network Topology Graph'))
        self.action_advanced_ai_analyst.triggered.connect(lambda: self._on_advanced_analysis_action('AI Analyst'))
        self.action_advanced_fwrule.triggered.connect(lambda: self._on_advanced_analysis_action('Firewall ACL Rules'))

        # Help
        self.action_about.triggered.connect(self._on_about)
        self.action_about_qt.triggered.connect(self._on_about_qt)

        # Toolbar
        self.action_start_btn.triggered.connect(self._on_start_capture)
        self.action_stop_btn.triggered.connect(self._on_stop_capture)
        self.action_restart_btn.triggered.connect(self._on_restart_capture)
        self.action_settings_btn.triggered.connect(self._on_capture_options)
        self.action_open_btn.triggered.connect(self._on_open_file)
        self.action_save_btn.triggered.connect(self._on_save_file)
        self.action_close_btn.triggered.connect(self._on_close_capture_file)
        self.action_reload_btn.triggered.connect(self._on_reload_file)
        self.action_search_btn.triggered.connect(self._on_search)
        self.action_prev_btn.triggered.connect(self._on_go_previous_packet)
        self.action_next_btn.triggered.connect(self._on_go_next_packet)
        self.action_first_btn.triggered.connect(self._on_go_first_packet)
        self.action_last_btn.triggered.connect(self._on_go_last_packet)
        self.action_jump_btn.triggered.connect(self._on_toggle_go_to_packet)
        self.action_stay_last_btn.triggered.connect(self._on_toggle_auto_scroll)
        self.action_color_btn.setCheckable(True)
        self.action_color_btn.setChecked(True)
        self.action_color_btn.triggered.connect(self._on_toggle_color_rules)
        self.action_zoom_in_btn.triggered.connect(self._on_zoom_in)
        self.action_zoom_out_btn.triggered.connect(self._on_zoom_out)
        self.action_zoom_reset_btn.triggered.connect(self._on_zoom_reset)
        self.action_resize_cols_btn.triggered.connect(self._on_resize_columns)
        self.action_reset_layout_btn.triggered.connect(self._on_reset_layout)
        self.expert_btn.clicked.connect(self._on_open_expert_information)
        self.properties_btn.clicked.connect(self._on_open_capture_properties)

    def _on_advanced_analysis_action(self, feature_name: str):
        if str(feature_name) == 'AI Analyst':
            self._open_ai_analyst_dialog()
            return
        if str(feature_name) == 'Dashboard':
            self._on_open_analysis_dashboard()
            return
        if str(feature_name) in {'Demo Packet', 'Demo'}:
            self._on_open_demo_packet()
            return
        if str(feature_name) in {'Draw Topo', 'Network Topology Graph', 'Topo'}:
            self._on_open_network_topology_graph()
            return
        if str(feature_name) in {'FWrule', 'Firewall ACL Rules'}:
            self._on_open_firewall_acl_rules()
            return

        QMessageBox.information(
            self,
            'Coming soon',
            f'"{feature_name}" coming soon.',
        )

    def _parse_ai_numeric_selector(self, selector: str, available_numbers: list[int], subject_label: str) -> list[int]:
        text = str(selector or '').strip().lower()
        available = sorted(set(int(v) for v in available_numbers))
        available_set = set(available)
        if not available:
            return []

        if text in {'all', '*'}:
            return available

        result = set()
        tokens = [t.strip() for t in text.split(',') if t.strip()]
        if not tokens:
            raise ValueError(f'Hãy nhập {subject_label} (vd: 5,8,10-20) hoặc all.')

        for token in tokens:
            if '-' in token:
                parts = [p.strip() for p in token.split('-', 1)]
                if len(parts) != 2 or not parts[0].isdigit() or not parts[1].isdigit():
                    raise ValueError(f'Khoảng không hợp lệ: {token}')
                start = int(parts[0])
                end = int(parts[1])
                if start > end:
                    start, end = end, start
                for value in range(start, end + 1):
                    if value in available_set:
                        result.add(value)
                continue

            if not token.isdigit():
                raise ValueError(f'Giá trị không hợp lệ: {token}')
            value = int(token)
            if value in available_set:
                result.add(value)

        selected = sorted(result)
        if not selected:
            raise ValueError(f'Không có {subject_label} nào khớp với lựa chọn hiện tại.')
        return selected

    def _parse_ai_conversation_selector(self, selector: str, available_numbers: list[int]) -> list[int]:
        return self._parse_ai_numeric_selector(selector, available_numbers, 'conversation')

    def _parse_ai_packet_selector(self, selector: str, available_numbers: list[int]) -> list[int]:
        return self._parse_ai_numeric_selector(selector, available_numbers, 'gói tin')
        text = str(selector or '').strip().lower()
        available = sorted(set(int(v) for v in available_numbers))
        available_set = set(available)
        if not available:
            return []

        if text in {'all', '*'}:
            return available

        result = set()
        tokens = [t.strip() for t in text.split(',') if t.strip()]
        if not tokens:
            raise ValueError('Hãy nhập gói tin (vd: 5,8,10-20) hoặc all.')

        for token in tokens:
            if '-' in token:
                parts = [p.strip() for p in token.split('-', 1)]
                if len(parts) != 2 or not parts[0].isdigit() or not parts[1].isdigit():
                    raise ValueError(f'Khoảng không hợp lệ: {token}')
                start = int(parts[0])
                end = int(parts[1])
                if start > end:
                    start, end = end, start
                for value in range(start, end + 1):
                    if value in available_set:
                        result.add(value)
                continue

            if not token.isdigit():
                raise ValueError(f'Giá trị không hợp lệ: {token}')
            value = int(token)
            if value in available_set:
                result.add(value)

        selected = sorted(result)
        if not selected:
            raise ValueError('Không có gói nào khớp với lựa chọn hiện tại.')
        return selected

    def _protocol_number_from_record(self, record) -> int:
        raw = getattr(record, 'raw', None)
        if raw is None:
            return 0
        try:
            if raw.haslayer(IP):
                return int(getattr(raw[IP], 'proto', 0) or 0)
            if raw.haslayer(IPv6):
                return int(getattr(raw[IPv6], 'nh', 0) or 0)
        except Exception:
            return 0
        return 0

    def _calc_basic_stats(self, values: list[float]) -> tuple[float, float, float, float]:
        if not values:
            return 0.0, 0.0, 0.0, 0.0
        n = float(len(values))
        mean_v = float(sum(values) / n)
        min_v = float(min(values))
        max_v = float(max(values))
        if len(values) <= 1:
            return mean_v, 0.0, max_v, min_v
        variance = sum((float(v) - mean_v) ** 2 for v in values) / n
        std_v = variance ** 0.5
        return mean_v, std_v, max_v, min_v

    def _build_ai_flows(self, records: list):
        packets = [getattr(r, 'raw', None) for r in records if getattr(r, 'raw', None) is not None]
        if not packets:
            return []
        return FlowFeatureExtractor(flow_timeout_seconds=240.0, cic_compat_mode=False).extract_from_packets(packets)

    def _build_ai_traffic_rows_from_flows(self, flows) -> list[list]:
        rows = []
        source_key_map = {
            'Flow ID': 'Flow ID',
            'Source IP': 'Src IP',
            'Source Port': 'Src Port',
            'Destination IP': 'Dst IP',
            'Destination Port': 'Dst Port',
            'Protocol': 'Protocol',
            'Timestamp': 'Timestamp',
            'Flow Duration': 'Flow Duration',
            'Total Fwd Packets': 'Total Fwd Packets',
            'Total Backward Packets': 'Total Backward Packets',
            'Total Length of Fwd Packets': 'Total Length of Fwd Packets',
            'Total Length of Bwd Packets': 'Total Length of Bwd Packets',
            'Fwd Packet Length Max': 'Fwd Packet Length Max',
            'Fwd Packet Length Min': 'Fwd Packet Length Min',
            'Fwd Packet Length Mean': 'Fwd Packet Length Mean',
            'Fwd Packet Length Std': 'Fwd Packet Length Std',
            'Bwd Packet Length Max': 'Bwd Packet Length Max',
            'Bwd Packet Length Min': 'Bwd Packet Length Min',
            'Bwd Packet Length Mean': 'Bwd Packet Length Mean',
            'Bwd Packet Length Std': 'Bwd Packet Length Std',
            'Flow Bytes/s': 'Flow Bytes/s',
            'Flow Packets/s': 'Flow Packets/s',
            'Flow IAT Mean': 'Flow IAT Mean',
            'Flow IAT Std': 'Flow IAT Std',
            'Flow IAT Max': 'Flow IAT Max',
            'Flow IAT Min': 'Flow IAT Min',
            'Fwd IAT Total': 'Fwd IAT Total',
            'Fwd IAT Mean': 'Fwd IAT Mean',
            'Fwd IAT Std': 'Fwd IAT Std',
            'Fwd IAT Max': 'Fwd IAT Max',
            'Fwd IAT Min': 'Fwd IAT Min',
            'Bwd IAT Total': 'Bwd IAT Total',
            'Bwd IAT Mean': 'Bwd IAT Mean',
            'Bwd IAT Std': 'Bwd IAT Std',
            'Bwd IAT Max': 'Bwd IAT Max',
            'Bwd IAT Min': 'Bwd IAT Min',
            'Fwd PSH Flags': 'Fwd PSH Flags',
            'Bwd PSH Flags': 'Bwd PSH Flags',
            'Fwd URG Flags': 'Fwd URG Flags',
            'Bwd URG Flags': 'Bwd URG Flags',
            'Fwd Header Length': 'Fwd Header Length',
            'Bwd Header Length': 'Bwd Header Length',
            'Fwd Packets/s': 'Fwd Packets/s',
            'Bwd Packets/s': 'Bwd Packets/s',
            'Min Packet Length': 'Min Packet Length',
            'Max Packet Length': 'Max Packet Length',
            'Packet Length Mean': 'Packet Length Mean',
            'Packet Length Std': 'Packet Length Std',
            'Packet Length Variance': 'Packet Length Variance',
            'FIN Flag Count': 'FIN Flag Count',
            'SYN Flag Count': 'SYN Flag Count',
            'RST Flag Count': 'RST Flag Count',
            'PSH Flag Count': 'PSH Flag Count',
            'ACK Flag Count': 'ACK Flag Count',
            'URG Flag Count': 'URG Flag Count',
            'CWE Flag Count': 'CWE Flag Count',
            'ECE Flag Count': 'ECE Flag Count',
            'Down/Up Ratio': 'Down/Up Ratio',
            'Average Packet Size': 'Average Packet Size',
            'Avg Fwd Segment Size': 'Avg Fwd Segment Size',
            'Avg Bwd Segment Size': 'Avg Bwd Segment Size',
            'Fwd Avg Bytes/Bulk': 'Fwd Avg Bytes/Bulk',
            'Fwd Avg Packets/Bulk': 'Fwd Avg Packets/Bulk',
            'Fwd Avg Bulk Rate': 'Fwd Avg Bulk Rate',
            'Bwd Avg Bytes/Bulk': 'Bwd Avg Bytes/Bulk',
            'Bwd Avg Packets/Bulk': 'Bwd Avg Packets/Bulk',
            'Bwd Avg Bulk Rate': 'Bwd Avg Bulk Rate',
            'Subflow Fwd Packets': 'Subflow Fwd Packets',
            'Subflow Fwd Bytes': 'Subflow Fwd Bytes',
            'Subflow Bwd Packets': 'Subflow Bwd Packets',
            'Subflow Bwd Bytes': 'Subflow Bwd Bytes',
            'Init_Win_bytes_forward': 'Init_Win_bytes_forward',
            'Init_Win_bytes_backward': 'Init_Win_bytes_backward',
            'act_data_pkt_fwd': 'act_data_pkt_fwd',
            'min_seg_size_forward': 'min_seg_size_forward',
            'Active Mean': 'Active Mean',
            'Active Std': 'Active Std',
            'Active Max': 'Active Max',
            'Active Min': 'Active Min',
            'Idle Mean': 'Idle Mean',
            'Idle Std': 'Idle Std',
            'Idle Max': 'Idle Max',
            'Idle Min': 'Idle Min',
        }
        for flow in flows:
            feat = flow.to_features()
            flow_id = str(feat.get('Flow ID', ''))
            row = []
            for col in self.AI_TRAFFIC_COLUMNS:
                name = str(col).strip()
                if name == 'Label':
                    row.append('BENIGN')
                elif name == 'Flow ID':
                    row.append(flow_id)
                else:
                    row.append(feat.get(source_key_map.get(name, ''), 0))
            rows.append(row)
        return rows

    def _ai_conversation_filter_expression(self, record) -> str:
        if record is None:
            return ''
        metadata = getattr(record, 'metadata', {}) or {}
        src = str(getattr(record, 'src', '') or '')
        dst = str(getattr(record, 'dst', '') or '')
        raw = getattr(record, 'raw', None)
        tcp_stream = metadata.get('tcp_stream_index')
        if isinstance(tcp_stream, int) and tcp_stream >= 0:
            return f'tcp.stream == {int(tcp_stream)}'
        udp_stream = metadata.get('udp_stream_index')
        if isinstance(udp_stream, int) and udp_stream >= 0:
            return f'udp.stream == {int(udp_stream)}'
        if raw is not None and raw.haslayer(IPv6) and src and dst:
            return f'ipv6.addr == {src} && ipv6.addr == {dst}'
        if raw is not None and raw.haslayer(IP) and src and dst:
            return f'ip.addr == {src} && ip.addr == {dst}'
        if src and dst:
            return f'eth.addr == {src} && eth.addr == {dst}'
        return ''

    def _format_ai_conversation_label(self, entry: dict) -> str:
        protocol = str(entry.get('protocol', '') or '').upper()
        src = str(entry.get('src', '') or '')
        dst = str(entry.get('dst', '') or '')
        sport = entry.get('sport', None)
        dport = entry.get('dport', None)
        left = f'{src}:{sport}' if sport not in (None, '', 'None') else src
        right = f'{dst}:{dport}' if dport not in (None, '', 'None') else dst
        packet_count = int(entry.get('packet_count', 0) or 0)
        return f'#{int(entry.get("index", 0) or 0)} [{protocol}] {left} <-> {right} ({packet_count} packets)'

    def _build_ai_conversation_catalog(self, records: list) -> list[dict]:
        cv = self.capture_view
        if cv is None:
            return []
        grouped = {}
        for record in list(records or []):
            key = cv._conversation_key_for_record(record)
            if key is None:
                continue
            grouped.setdefault(key, []).append(record)
        entries = []
        sorted_groups = sorted(
            grouped.values(),
            key=lambda rows: min(int(getattr(row, 'number', 0) or 0) for row in rows) if rows else 0,
        )
        for idx, rows in enumerate(sorted_groups, start=1):
            first = rows[0]
            metadata = getattr(first, 'metadata', {}) or {}
            protocol = str(getattr(first, 'protocol', '') or '').upper()
            if isinstance(metadata.get('tcp_stream_index'), int):
                protocol = 'TCP'
            elif isinstance(metadata.get('udp_stream_index'), int):
                protocol = 'UDP'
            entry = {
                'index': int(idx),
                'key': cv._conversation_key_for_record(first),
                'records': list(rows),
                'first_packet': int(getattr(first, 'number', 0) or 0),
                'filter_expression': self._ai_conversation_filter_expression(first),
                'protocol': protocol,
                'src': str(getattr(first, 'src', '') or ''),
                'dst': str(getattr(first, 'dst', '') or ''),
                'sport': getattr(first, 'sport', None),
                'dport': getattr(first, 'dport', None),
                'packet_count': len(rows),
                'tcp_stream_index': metadata.get('tcp_stream_index', None),
                'udp_stream_index': metadata.get('udp_stream_index', None),
            }
            entry['label'] = self._format_ai_conversation_label(entry)
            entries.append(entry)
        return entries

    def _ai_flow_lookup_key_from_row(self, row: list, traffic_header: list[str]):
        index = {str(name): idx for idx, name in enumerate(traffic_header)}

        def _row_value(field, default=''):
            idx = index.get(str(field), None)
            if idx is None or idx >= len(row):
                return default
            return row[idx]

        proto = str(_row_value('Protocol', '') or '').upper()
        src = str(_row_value('Source IP', '') or '')
        dst = str(_row_value('Destination IP', '') or '')
        sport = str(_row_value('Source Port', '') or '')
        dport = str(_row_value('Destination Port', '') or '')
        endpoints = tuple(sorted([(src, sport), (dst, dport)]))
        return proto, endpoints

    def _build_ai_action_groups(self, traffic_header: list[str], traffic_rows: list[list], predictions: list[dict], conversation_catalog: list[dict]) -> list[dict]:
        conversation_by_endpoint = {}
        for entry in list(conversation_catalog or []):
            proto = str(entry.get('protocol', '') or '').upper()
            src = str(entry.get('src', '') or '')
            dst = str(entry.get('dst', '') or '')
            sport = str(entry.get('sport', '') or '')
            dport = str(entry.get('dport', '') or '')
            endpoints = tuple(sorted([(src, sport), (dst, dport)]))
            conversation_by_endpoint.setdefault((proto, endpoints), entry)

        index = {str(name): idx for idx, name in enumerate(traffic_header)}
        grouped = {}
        for row, pred in zip(traffic_rows, predictions):
            label = str(pred.get('label', pred.get('prediction', 'Unknown')) or 'Unknown')
            description = self.AI_LABEL_DESCRIPTIONS.get(label, self.AI_LABEL_DESCRIPTIONS.get(label.upper(), ''))
            confidence = float(pred.get('confidence', pred.get('anomaly_score', 0.0)) or 0.0)
            conversation = conversation_by_endpoint.get(self._ai_flow_lookup_key_from_row(row, traffic_header))
            src = str(row[index['Source IP']]) if 'Source IP' in index and index['Source IP'] < len(row) else ''
            dst = str(row[index['Destination IP']]) if 'Destination IP' in index and index['Destination IP'] < len(row) else ''
            sport = str(row[index['Source Port']]) if 'Source Port' in index and index['Source Port'] < len(row) else ''
            dport = str(row[index['Destination Port']]) if 'Destination Port' in index and index['Destination Port'] < len(row) else ''
            proto = str(row[index['Protocol']]) if 'Protocol' in index and index['Protocol'] < len(row) else ''
            flow_text = f'{src}:{sport} -> {dst}:{dport} | {proto} | confidence {confidence:.2%}'
            group = grouped.setdefault(
                label,
                {
                    'action': label,
                    'description': description,
                    'count': 0,
                    'children': [],
                },
            )
            group['count'] += 1
            child_text = flow_text
            filter_expression = ''
            first_packet = None
            if conversation is not None:
                child_text = f'{conversation["label"]} | {flow_text}'
                filter_expression = str(conversation.get('filter_expression', '') or '')
                first_packet = int(conversation.get('first_packet', 0) or 0)
            group['children'].append(
                {
                    'text': child_text,
                    'filter_expression': filter_expression,
                    'first_packet': first_packet,
                }
            )
        return sorted(grouped.values(), key=lambda item: (-int(item.get('count', 0) or 0), str(item.get('action', ''))))

    def _build_ai_traffic_rows(self, records: list) -> list[list]:
        return self._build_ai_traffic_rows_from_flows(self._build_ai_flows(records))

    def _traffic_to_ml(self, traffic_header: list[str], traffic_rows: list[list]) -> tuple[list[str], list[list]]:
        keep_indices = [
            idx for idx, col in enumerate(traffic_header)
            if str(col).strip() not in self.AI_DROP_FOR_INFERENCE
        ]
        ml_header = [traffic_header[i] for i in keep_indices]
        ml_rows = [[row[i] for i in keep_indices] for row in traffic_rows]
        return ml_header, ml_rows

    def _dedupe_ai_header(self, header: list[str]) -> list[str]:
        counts = {}
        result = []
        for col in header:
            name = str(col).strip()
            seen = counts.get(name, 0)
            counts[name] = seen + 1
            result.append(name if seen == 0 else f'{name}.{seen}')
        return result

    def _predict_ai_labels(self, ml_header: list[str], ml_rows: list[list]) -> list[dict]:
        if not ml_rows:
            return []
        adapter = self._build_flow_model_adapter()
        if not adapter.loaded:
            raise RuntimeError(
                'AI model package is not ready. Hay cai torch, joblib va scikit-learn '
                'bang cach chay: pip install -r requirements.txt'
            )
        predictions = adapter.predict(ml_rows)
        if not isinstance(predictions, list):
            if isinstance(predictions, str) and predictions == 'torch_not_available':
                raise RuntimeError(
                    'AI model package is missing torch/joblib/scikit-learn. '
                    'Hay chay: pip install -r requirements.txt'
                )
            raise RuntimeError(f'AI model predict failed: {predictions}')
        return predictions

    def _build_ai_analysis_text(self, traffic_header: list[str], traffic_rows: list[list], predictions: list[dict]) -> str:
        index = {name: idx for idx, name in enumerate(traffic_header)}

        def get(row, name, default=''):
            idx = index.get(name)
            if idx is None or idx >= len(row):
                return default
            return row[idx]

        total = len(predictions)
        counts = Counter(str(pred.get('label', pred.get('prediction', '')) or '') for pred in predictions)
        attack_counts = Counter({label: count for label, count in counts.items() if str(label).lower() != 'benign'})

        lines = ['AI Analyst result', '']
        lines.append(f'Total flows analyzed: {total}')
        lines.append('Predicted labels:')
        for label, count in counts.most_common():
            percent = (count * 100.0 / total) if total else 0.0
            lines.append(f'- {label}: {count} flow(s), {percent:.1f}%')

        lines.append('')
        if not attack_counts:
            lines.append('Current situation: mostly BENIGN traffic.')
            lines.append(
                self.AI_LABEL_DESCRIPTIONS.get(
                    'Benign',
                    self.AI_LABEL_DESCRIPTIONS.get('BENIGN', 'Traffic looks normal.')
                )
            )
        else:
            lines.append('Current situation: suspicious or attack traffic detected.')
            for label, count in attack_counts.most_common():
                description = self.AI_LABEL_DESCRIPTIONS.get(
                    label,
                    self.AI_LABEL_DESCRIPTIONS.get('Benign', self.AI_LABEL_DESCRIPTIONS.get('BENIGN', 'Can kiem tra them flow lien quan.'))
                )
                lines.append(f'- {label}: {description}')

        grouped_sources = defaultdict(Counter)
        grouped_targets = defaultdict(Counter)
        for row, pred in zip(traffic_rows, predictions):
            label = pred['label']
            if str(label).lower() == 'benign':
                continue
            grouped_sources[label][str(get(row, 'Source IP', '-'))] += 1
            target = f"{get(row, 'Destination IP', '-')}: {get(row, 'Destination Port', '-')}"
            grouped_targets[label][target] += 1

        if attack_counts:
            lines.append('')
            lines.append('Traffic Labeling context:')
            for label in attack_counts:
                srcs = ', '.join(f'{src} ({cnt})' for src, cnt in grouped_sources[label].most_common(5))
                dsts = ', '.join(f'{dst} ({cnt})' for dst, cnt in grouped_targets[label].most_common(5))
                lines.append(f'- {label} sources: {srcs or "-"}')
                lines.append(f'- {label} targets: {dsts or "-"}')

            lines.append('')
            lines.append('Top suspicious flows:')
            suspicious = [
                (row, pred) for row, pred in zip(traffic_rows, predictions)
                if str(pred.get('label', pred.get('prediction', ''))).lower() != 'benign'
            ]
            suspicious.sort(key=lambda pair: pair[1].get('confidence', 0.0), reverse=True)
            for row, pred in suspicious[:15]:
                src = f"{get(row, 'Source IP', '-')}: {get(row, 'Source Port', '-')}"
                dst = f"{get(row, 'Destination IP', '-')}: {get(row, 'Destination Port', '-')}"
                proto = get(row, 'Protocol', '-')
                duration = get(row, 'Flow Duration', '-')
                packets = get(row, 'Total Fwd Packets', '-')
                bytes_ = get(row, 'Total Length of Fwd Packets', '-')
                label = pred.get('label', pred.get('prediction', '-'))
                confidence = float(pred.get('confidence', pred.get('anomaly_score', 0.0)) or 0.0)
                lines.append(
                    f"- {label} ({confidence:.2%}) | {src} -> {dst} | "
                    f'proto={proto} | duration_us={duration} | fwd_pkts={packets} | fwd_bytes={bytes_}'
                )

        lines.append('')
        lines.append('Per-flow predictions:')
        for i, (row, pred) in enumerate(zip(traffic_rows, predictions), start=1):
            flow_id = get(row, 'Flow ID', '-')
            src = f"{get(row, 'Source IP', '-')}: {get(row, 'Source Port', '-')}"
            dst = f"{get(row, 'Destination IP', '-')}: {get(row, 'Destination Port', '-')}"
            proto = get(row, 'Protocol', '-')
            label = pred.get('label', pred.get('prediction', '-'))
            confidence = float(pred.get('confidence', pred.get('anomaly_score', 0.0)) or 0.0)
            lines.append(
                f"- flow#{i} {flow_id} | {src} -> {dst} | proto={proto} | "
                f"label={label} | confidence={confidence:.2%}"
            )

        return '\n'.join(lines)

    def _on_open_analysis_dashboard(self):
        """Open Analysis Dashboard with current capture view"""
        if not self.capture_view or not getattr(self.capture_view, 'records', None):
            QMessageBox.information(self, 'Analysis Dashboard', 'No capture is loaded. Please start or load a capture.')
            return
        
        # Import dashboard components
        from gui.dashboard import (
            DashboardOverviewDialog, DashboardRepository, DashboardTemplateRepository,
            DataSourceRegistry, QueryEngine, CaptureDataSourceBuilder,
            DashboardService, create_default_visualization_registry,
            get_dashboard_templates_path, get_user_dashboards_path,
        )
        
        # Initialize repositories
        template_repo = DashboardTemplateRepository(str(get_dashboard_templates_path()))
        dashboard_repo = DashboardRepository(str(get_user_dashboards_path()))
        
        # Setup data source registry with capture data for this session
        data_registry = DataSourceRegistry()
        CaptureDataSourceBuilder.register_all_sources(data_registry, self.capture_view)
        
        # Create visualization registry
        viz_registry = create_default_visualization_registry()
        
        # Create dashboard service and store for later use
        self.dashboard_service = DashboardService(
            dashboard_repo=dashboard_repo,
            template_repo=template_repo,
            data_source_registry=data_registry,
            visualization_registry=viz_registry
        )
        self.dashboard_data_registry = data_registry
        
        # Create query engine for dashboard queries
        query_engine = QueryEngine(data_registry)
        
        # Open dashboard overview dialog with full dashboard system
        dialog = DashboardOverviewDialog(
            template_repo=template_repo,
            dashboard_repo=dashboard_repo,
            query_engine=query_engine,
            viz_registry=viz_registry,
            parent=self
        )
        
        dialog.exec()

    def _default_demo_packet_entries(self):
        entries = []
        for index in range(1, 101):
            file_name = f"{index:03d}.pcapng"
            entries.append({
                'id': index,
                'category': 'Demo',
                'name': f'Demo Packet {index:03d}',
                'protocol': '',
                'file': file_name,
                'description': '',
                'path': str((self.DEMO_DIR / file_name).resolve()),
            })
        return entries

    def _load_demo_packet_entries(self):
        if isinstance(self._demo_packet_entries, list) and self._demo_packet_entries:
            return self._demo_packet_entries

        entries = {}
        doc_path = self.DEMO_DOC_PATH
        if doc_path.exists():
            try:
                line_pattern = re.compile(
                    r"^\|\s*(\d{1,3})\s*\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|\s*`?([^|`]+\.pcapng)`?\s*\|\s*([^|]+?)\s*\|\s*$"
                )
                with open(doc_path, 'r', encoding='utf-8') as handle:
                    for line in handle:
                        match = line_pattern.match(line.strip())
                        if not match:
                            continue
                        demo_id = int(match.group(1))
                        file_text = str(match.group(5) or '').strip().replace('\\', '/').split('/')[-1]
                        entries[demo_id] = {
                            'id': demo_id,
                            'category': str(match.group(2) or '').strip(),
                            'name': str(match.group(3) or '').strip(),
                            'protocol': str(match.group(4) or '').strip(),
                            'file': file_text,
                            'description': str(match.group(6) or '').strip(),
                            'path': str((self.DEMO_DIR / file_text).resolve()),
                        }
            except Exception:
                entries = {}

        merged = []
        defaults = self._default_demo_packet_entries()
        for fallback in defaults:
            demo_id = int(fallback['id'])
            merged.append(entries.get(demo_id, fallback))

        self._demo_packet_entries = sorted(merged, key=lambda item: int(item.get('id', 0) or 0))
        return self._demo_packet_entries

    def _on_open_demo_packet(self):
        entries = self._load_demo_packet_entries()
        if not entries:
            QMessageBox.warning(self, 'Demo Packet', 'Khong the tai danh sach demo packet.')
            return

        dialog = QDialog(self)
        dialog.setWindowTitle('Demo Packet')
        root = QVBoxLayout(dialog)

        root.addWidget(QLabel('Chon hanh vi demo:'))
        combo = QComboBox(dialog)
        entry_by_id = {}
        for entry in entries:
            demo_id = int(entry.get('id', 0) or 0)
            entry_by_id[demo_id] = entry
            combo.addItem(f"{demo_id:03d} - {entry.get('name', '')}", demo_id)
        root.addWidget(combo)

        info = QTextEdit(dialog)
        info.setReadOnly(True)
        info.setMinimumHeight(180)
        root.addWidget(info)

        button_row = QHBoxLayout()
        open_btn = QPushButton('Mo demo', dialog)
        close_btn = QPushButton('Dong', dialog)
        button_row.addWidget(open_btn)
        button_row.addStretch(1)
        button_row.addWidget(close_btn)
        root.addLayout(button_row)

        def _selected_entry():
            selected_id = int(combo.currentData() or 0)
            return entry_by_id.get(selected_id)

        def _refresh_info():
            entry = _selected_entry()
            if not entry:
                info.setPlainText('Khong co du lieu demo duoc chon.')
                open_btn.setEnabled(False)
                return
            demo_path = str(entry.get('path') or '')
            exists = os.path.exists(demo_path)
            open_btn.setEnabled(exists)
            lines = [
                f"ID: {int(entry.get('id', 0) or 0):03d}",
                f"Loai: {str(entry.get('category', '') or '-').strip() or '-'}",
                f"Protocol: {str(entry.get('protocol', '') or '-').strip() or '-'}",
                '',
                f"Mo ta: {str(entry.get('description', '') or '').strip()}",
            ]
            info.setPlainText("\n".join(lines))

        def _open_selected_demo():
            entry = _selected_entry()
            if not entry:
                QMessageBox.warning(dialog, 'Demo Packet', 'Khong tim thay demo duoc chon.')
                return

            demo_id = int(entry.get('id', 0) or 0)
            demo_name = str(entry.get('name', '') or '').strip() or f'Demo {demo_id:03d}'
            demo_path = str(entry.get('path') or '')
            if not os.path.exists(demo_path):
                QMessageBox.critical(dialog, 'Demo Packet', f'Khong tim thay file demo cho muc {demo_id:03d}.')
                return

            proceed = self._prompt_save_before_destructive_action(
                'Project hien tai co thay doi chua luu. Ban co muon luu truoc khi mo demo packet moi khong?'
            )
            if not proceed:
                return

            self.show_capture_view('', 'Offline', '')
            if not self.capture_view:
                QMessageBox.critical(dialog, 'Demo Packet', 'Khong tao duoc Capture View de mo demo packet.')
                return

            started = time.perf_counter()
            try:
                packets = list(iter_pcap_packets(demo_path))
            except Exception as exc:
                QMessageBox.critical(dialog, 'Demo Packet', f'Khong doc duoc file demo cho muc {demo_id:03d}.\n\n{exc}')
                return

            if not packets:
                QMessageBox.warning(dialog, 'Demo Packet', f'Demo {demo_id:03d} khong co packet hop le.')
                return

            self._replace_capture_packets(
                packets,
                preserve_metadata=False,
                preserve_loaded_path=False,
                mark_dirty=True,
                status_message=f'Loaded demo {demo_id:03d} - {demo_name}. Capture dang o trang thai chua luu.',
                preserve_display_filter=False,
            )

            self.capture_view.loaded_file_path = None
            self.capture_view._configure_parser_capture_context(self.capture_view.parser, '')
            self.capture_view._set_dirty(True)

            self._last_loaded_seconds = max(0.0, time.perf_counter() - started)
            self._status_mode = 'activity'
            self._status_activity_kind = 'load'
            self._selected_packet_number = None
            self._capture_started_monotonic = None
            self._update_packet_status_label()
            self.detail_field_label.setText('Field: - | Byte: 0')
            self._sync_capture_buttons()
            self._refresh_capture_menu_state()
            self._refresh_status_metrics()
            self._refresh_file_menu_state()
            self._update_capture_window_title()
            dialog.accept()

        combo.currentIndexChanged.connect(_refresh_info)
        open_btn.clicked.connect(_open_selected_demo)
        close_btn.clicked.connect(dialog.reject)
        _refresh_info()

        dialog.resize(760, 420)
        self._fit_widget_90(dialog)
        dialog.exec()

    def _open_ai_analyst_dialog(self):
        existing_dialog = getattr(self, '_ai_analyst_dialog', None)
        if existing_dialog is not None:
            try:
                existing_dialog.show()
                existing_dialog.raise_()
                existing_dialog.activateWindow()
                return
            except Exception:
                self._ai_analyst_dialog = None
        if not self.capture_view or not getattr(self.capture_view, 'records', None):
            QMessageBox.information(self, 'AI Analyst', 'Khong co capture de phan tich.')
            return

        records = list(self.capture_view.get_effective_records(include_ignored=False))
        if not records:
            QMessageBox.information(self, 'AI Analyst', 'Tat ca packet hien tai dang o trang thai ignored.')
            return
        packet_numbers = sorted(int(r.number) for r in records)
        record_by_number = {}
        for rec in records:
            record_by_number.setdefault(int(rec.number), rec)
        conversation_catalog = self._build_ai_conversation_catalog(records)
        conversation_numbers = [int(item.get('index', 0) or 0) for item in conversation_catalog]
        conversation_by_number = {int(item.get('index', 0) or 0): item for item in conversation_catalog}

        dialog = QDialog(self)
        dialog.setWindowTitle('AI Analyst')
        root = QVBoxLayout(dialog)

        selector_panel = QFrame(dialog)
        selector_panel.setFrameShape(QFrame.Shape.StyledPanel)
        selector_layout = QHBoxLayout(selector_panel)

        left_panel = QWidget(selector_panel)
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 0, 0)

        mode_row = QHBoxLayout()
        mode_row.addWidget(QLabel('Mode phân tích:'))
        mode_combo = QComboBox(left_panel)
        mode_combo.addItems(['Theo gói tin', 'Theo conversation'])
        mode_row.addWidget(mode_combo, 1)
        left_layout.addLayout(mode_row)

        input_title = QLabel('Nhập gói tin', left_panel)
        left_layout.addWidget(input_title)
        input_hint = QLabel('Hỗ trợ: 1 gói, nhiều gói cách nhau dấu phẩy, khoảng a-b, hoặc all', left_panel)
        left_layout.addWidget(input_hint)

        packet_input = QLineEdit(left_panel)
        packet_input.setPlaceholderText('Ví dụ: 5,8,10-20 hoặc all')
        packet_input.setText('all')
        left_layout.addWidget(packet_input)

        conversation_input = QLineEdit(left_panel)
        conversation_input.setPlaceholderText('Ví dụ: 1,3,5-8 hoặc all')
        conversation_input.setText('all')
        left_layout.addWidget(conversation_input)

        button_row = QHBoxLayout()
        analyze_btn = QPushButton('Phân tích', left_panel)
        close_btn = QPushButton('Đóng', left_panel)
        button_row.addWidget(analyze_btn)
        button_row.addStretch()
        button_row.addWidget(close_btn)
        left_layout.addLayout(button_row)

        right_panel = QWidget(selector_panel)
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(0, 0, 0, 0)
        conversation_list = QListWidget(right_panel)
        for entry in conversation_catalog:
            conversation_list.addItem(str(entry.get('label', '') or ''))
        right_layout.addWidget(conversation_list, 1)

        selector_layout.addWidget(left_panel, 3)
        selector_layout.addWidget(right_panel, 2)
        root.addWidget(selector_panel)

        result_summary = QLabel(
            f'Sẵn sàng phân tích. Có {len(packet_numbers)} gói tin và {len(conversation_catalog)} conversation khả dụng.',
            dialog,
        )
        root.addWidget(result_summary)

        result_tree = QTreeWidget(dialog)
        result_tree.setColumnCount(2)
        result_tree.setHeaderLabels(['Action', 'Count'])
        result_tree.setRootIsDecorated(True)
        result_tree.setAlternatingRowColors(True)
        result_tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        result_tree.header().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        root.addWidget(result_tree, 1)

        def _update_mode_ui():
            is_conversation_mode = (mode_combo.currentIndex() == 1)
            input_title.setText('Nhập số thứ tự conversation' if is_conversation_mode else 'Nhập gói tin')
            input_hint.setText(
                'Hỗ trợ: 1 mục, nhiều mục cách nhau dấu phẩy, khoảng a-b, hoặc all'
                if is_conversation_mode
                else 'Hỗ trợ: 1 gói, nhiều gói cách nhau dấu phẩy, khoảng a-b, hoặc all'
            )
            packet_input.setVisible(not is_conversation_mode)
            conversation_input.setVisible(is_conversation_mode)
            right_panel.setVisible(is_conversation_mode)

        def _collect_selected_records():
            mode = str(mode_combo.currentText() or '')
            if mode == 'Theo conversation':
                selected_conversations = self._parse_ai_conversation_selector(conversation_input.text(), conversation_numbers)
                seen_numbers = set()
                selected_records = []
                for conv_no in selected_conversations:
                    entry = conversation_by_number.get(int(conv_no))
                    if not entry:
                        continue
                    for rec in list(entry.get('records', []) or []):
                        packet_no = int(getattr(rec, 'number', 0) or 0)
                        if packet_no in seen_numbers:
                            continue
                        seen_numbers.add(packet_no)
                        selected_records.append(rec)
                return selected_records, f'{len(selected_conversations)} conversation'
            selected_numbers = self._parse_ai_packet_selector(packet_input.text(), packet_numbers)
            selected_records = [record_by_number[n] for n in selected_numbers if n in record_by_number]
            return selected_records, f'{len(selected_numbers)} gói tin'

        def _render_result_groups(groups):
            result_tree.clear()
            for group in list(groups or []):
                description = str(group.get('description', '') or '').strip()
                parent_text = str(group.get('action', '') or '')
                if description:
                    parent_text = f'{parent_text} - {description}'
                parent = QTreeWidgetItem(result_tree)
                parent.setText(0, parent_text)
                parent.setText(1, str(int(group.get('count', 0) or 0)))
                for child_info in list(group.get('children', []) or []):
                    child = QTreeWidgetItem(parent)
                    child.setText(0, str(child_info.get('text', '') or ''))
                    child.setText(1, '')
                    child.setData(0, Qt.UserRole, str(child_info.get('filter_expression', '') or ''))
                    child.setData(0, Qt.UserRole + 1, int(child_info.get('first_packet', 0) or 0))
            result_tree.collapseAll()

        def _apply_conversation_entry(entry):
            if not isinstance(entry, dict):
                return
            filter_expression = str(entry.get('filter_expression', '') or '').strip()
            first_packet = int(entry.get('first_packet', 0) or 0)
            if not filter_expression:
                return
            self._set_display_filter_text(filter_expression, apply_now=True)
            if first_packet > 0 and self.capture_view is not None:
                self.capture_view.goto_packet_number(first_packet)
            self.raise_()
            self.activateWindow()

        def _build():
            QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
            analyze_btn.setEnabled(False)
            result_summary.setText('Loading... đang phân tích dữ liệu AI Analyst.')
            QApplication.processEvents()
            try:
                selected_records, selection_text = _collect_selected_records()
                if not selected_records:
                    raise ValueError('Không chọn được dữ liệu hợp lệ để phân tích.')

                flows = self._build_ai_flows(selected_records)
                traffic_header = list(self.AI_TRAFFIC_COLUMNS)
                traffic_rows = self._build_ai_traffic_rows_from_flows(flows)
                if any(len(row) != len(traffic_header) for row in traffic_rows):
                    raise ValueError('Lỗi schema: số cột TrafficLabelling không khớp header.')

                ml_header, ml_rows = self._traffic_to_ml(traffic_header, traffic_rows)
                if any(len(row) != len(ml_header) for row in ml_rows):
                    raise ValueError('Lỗi schema: số cột inference feature không khớp header.')
                if any(str(col).strip().lower() == 'label' for col in ml_header):
                    raise ValueError('Lỗi schema: cột Label vẫn còn trong feature inference.')

                predictions = self._predict_ai_labels(ml_header, ml_rows)
                action_groups = self._build_ai_action_groups(traffic_header, traffic_rows, predictions, conversation_catalog)
                _render_result_groups(action_groups)
                result_summary.setText(
                    f'Đã phân tích {selection_text} -> {len(flows)} flow, {len(action_groups)} action.'
                )
            except Exception as exc:
                result_tree.clear()
                result_summary.setText(f'Lỗi AI Analyst: {exc}')
            finally:
                analyze_btn.setEnabled(True)
                QApplication.restoreOverrideCursor()
                QApplication.processEvents()

        def _handle_result_click(item, _column):
            if item is None:
                return
            filter_expression = str(item.data(0, Qt.UserRole) or '').strip()
            first_packet = int(item.data(0, Qt.UserRole + 1) or 0)
            if not filter_expression:
                item.setExpanded(not item.isExpanded())
                return
            self._set_display_filter_text(filter_expression, apply_now=True)
            if first_packet > 0 and self.capture_view is not None:
                self.capture_view.goto_packet_number(first_packet)
            self.raise_()
            self.activateWindow()

        def _use_conversation_number():
            row = int(conversation_list.currentRow())
            if row < 0 or row >= len(conversation_catalog):
                return
            conversation_input.setText(str(int(conversation_catalog[row].get('index', 0) or 0)))

        def _filter_selected_conversation():
            row = int(conversation_list.currentRow())
            if row < 0 or row >= len(conversation_catalog):
                return
            entry = conversation_catalog[row]
            conversation_input.setText(str(int(entry.get('index', 0) or 0)))
            _apply_conversation_entry(entry)

        mode_combo.currentIndexChanged.connect(_update_mode_ui)
        analyze_btn.clicked.connect(_build)
        close_btn.clicked.connect(dialog.accept)
        packet_input.returnPressed.connect(_build)
        conversation_input.returnPressed.connect(_build)
        result_tree.itemClicked.connect(_handle_result_click)
        result_tree.itemDoubleClicked.connect(_handle_result_click)
        conversation_list.itemDoubleClicked.connect(lambda _item: _filter_selected_conversation())
        _update_mode_ui()

        dialog.resize(1120, 760)
        selector_panel.setMaximumHeight(max(140, int(dialog.height() * 0.2)))
        self._fit_widget_90(dialog)
        dialog.setModal(False)
        dialog.setWindowModality(Qt.WindowModality.NonModal)
        dialog.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose, True)
        self._ai_analyst_dialog = dialog
        dialog.destroyed.connect(lambda *_args: setattr(self, '_ai_analyst_dialog', None))
        dialog.show()
        dialog.raise_()
        dialog.activateWindow()

    def show_interface_selector(self):
        """Hiển thị màn hình chọn interface"""
        self._close_firewall_acl_dialog()
        if not self.iface_selector_view:
            self.iface_selector_view = InterfaceSelectorView()
            self.iface_selector_view.capture_started.connect(self._on_capture_started)
            self.iface_selector_view.open_file_requested.connect(self._on_open_recent_file)
            self.stacked_widget.addWidget(self.iface_selector_view)

        self.iface_selector_view.refresh_recent_files()
        self.iface_selector_view.refresh_interface_preferences()

        self.stacked_widget.setCurrentWidget(self.iface_selector_view)
        self.setWindowTitle('Packetra - Select Interface')
        self._on_find_panel_visibility_changed(False)
        self._update_toolbar_state('selector')
        self._refresh_capture_menu_state()
        self._refresh_analyze_menu_state()

    def _on_interface_preferences_changed(self):
        """Apply interface preference updates to start screen in real time."""
        if self.iface_selector_view:
            self.iface_selector_view.refresh_interface_preferences()

    def show_capture_view(self, iface: str, iface_display_name: str, capture_filter: str = ''):
        """Hiển thị màn hình capture"""
        if not self.capture_view:
            self.capture_view = CaptureView(iface, iface_display_name, capture_filter)
            self.capture_view.status_changed.connect(self._on_capture_status_changed)
            self.capture_view.capture_state_changed.connect(lambda _running: self._sync_capture_buttons())
            self.capture_view.find_panel_visibility_changed.connect(self._on_find_panel_visibility_changed)
            self.capture_view.detail_status_changed.connect(self._on_detail_status_changed)
            self.capture_view.display_filter_applied.connect(self._on_display_filter_applied)
            self.capture_view.records_refined.connect(self._on_records_refined_rows)
            self.capture_view.open_packet_window_requested.connect(self._on_show_packet_new_window)
            self.capture_view.go_state_changed.connect(lambda _state: self._refresh_go_menu_state())
            self.capture_view.table.itemSelectionChanged.connect(self._refresh_analyze_menu_state)
            self.capture_view.details_tree.itemSelectionChanged.connect(self._refresh_analyze_menu_state)
            self.capture_view.table.context_menu_requested.connect(self._on_packet_list_context_menu)
            self.capture_view.details_tree.context_menu_requested.connect(self._on_packet_detail_context_menu)
            self.capture_view.hex_view.context_menu_requested.connect(self._on_packet_bytes_context_menu)
            self.capture_view.table.verticalScrollBar().valueChanged.connect(
                lambda _value: self._schedule_visible_custom_column_refresh()
            )
            self.stacked_widget.addWidget(self.capture_view)

        self.capture_view.set_interface(iface, iface_display_name, capture_filter)
        self._apply_capture_defaults_to_view()
        try:
            settings = QSettings('Packetra', 'Packetra')
            raw_overrides = str(settings.value('view/rule_background_overrides', '', str) or '').strip()
            overrides = json.loads(raw_overrides) if raw_overrides else {}
            if not isinstance(overrides, dict):
                overrides = {}
        except Exception:
            overrides = {}
        self.capture_view.table.set_rule_background_overrides(overrides)
        self.capture_view.set_color_rules_enabled(self.action_color_btn.isChecked())
        self._analyze_custom_columns = self._load_analyze_custom_columns()
        self._ensure_analyze_custom_columns_applied()
        self._apply_edit_preferences(self._load_edit_preferences())
        self.stacked_widget.setCurrentWidget(self.capture_view)
        self._sync_view_action_states()
        self._update_capture_window_title()
        self._update_toolbar_state('capture')
        self._status_mode = 'activity'
        self._selected_packet_number = None
        self._status_activity_kind = 'load'
        self._update_packet_status_label()
        self.detail_field_label.setText('Field: - | Byte: 0')
        self._refresh_status_metrics()
        self._refresh_capture_menu_state()
        self._refresh_go_menu_state()
        self._refresh_analyze_menu_state()

    def _update_capture_window_title(self):
        if not self.capture_view:
            self.setWindowTitle('Packetra - Network Packet Analyzer')
            return
        current_name = self.capture_view.get_current_filename()
        if current_name:
            dirty = ' *' if self.capture_view.has_unsaved_changes() else ''
            self.setWindowTitle(f'Packetra - {current_name}{dirty}')
            return
        label = self.capture_view.iface_display_name or 'Offline'
        dirty = ' *' if self.capture_view.has_unsaved_changes() else ''
        self.setWindowTitle(f'Packetra - {label}{dirty}')

    def _on_find_panel_visibility_changed(self, visible: bool):
        self.action_search_btn.blockSignals(True)
        self.action_search_btn.setChecked(bool(visible))
        self.action_search_btn.setIcon(self._search_icon_off)
        self.action_search_btn.blockSignals(False)

    def _sync_view_action_states(self):
        if not self.capture_view:
            return

        pairs = [
            (getattr(self, 'action_view_filter_toolbar', None), self.capture_view.is_filter_toolbar_visible()),
            (getattr(self, 'action_view_packet_list', None), self.capture_view.is_component_visible('packet_list')),
            (getattr(self, 'action_view_packet_details', None), self.capture_view.is_component_visible('packet_details')),
            (getattr(self, 'action_view_packet_bytes', None), self.capture_view.is_component_visible('packet_bytes')),
            (getattr(self, 'action_view_packet_diagram', None), self.capture_view.is_component_visible('packet_diagram')),
            (getattr(self, 'action_view_resize_all_columns', None), self.capture_view.is_resize_all_columns_enabled()),
            (getattr(self, 'action_view_reload_as_format_capture', None), self.capture_view.is_file_format_view_mode()),
        ]
        for action, checked in pairs:
            if action is None:
                continue
            action.blockSignals(True)
            action.setChecked(bool(checked))
            action.blockSignals(False)

        if hasattr(self, 'action_resize_cols_btn'):
            self.action_resize_cols_btn.blockSignals(True)
            self.action_resize_cols_btn.setChecked(self.capture_view.is_resize_all_columns_enabled())
            self.action_resize_cols_btn.blockSignals(False)

    def _load_capture_defaults(self):
        """Load default Output/Options capture settings from QSettings"""
        import tempfile

        settings = QSettings('Packetra', 'Packetra')
        output_defaults = {
            'file_path': settings.value('output/file_path', '', str),
            'format': settings.value('output/format', 'pcapng', str),
            'compression': settings.value('output/compression', 'none', str),
            'auto_create': settings.value('output/auto_create', False, bool),
            'rollover_packets_enabled': settings.value('output/rollover_packets_enabled', False, bool),
            'rollover_packets_value': settings.value('output/rollover_packets_value', 100000, int),
            'rollover_size_enabled': settings.value('output/rollover_size_enabled', False, bool),
            'rollover_size_value': settings.value('output/rollover_size_value', 1, int),
            'rollover_size_unit': settings.value('output/rollover_size_unit', 'kilobytes', str),
            'rollover_duration_enabled': settings.value('output/rollover_duration_enabled', False, bool),
            'rollover_duration_value': settings.value('output/rollover_duration_value', 1, int),
            'rollover_duration_unit': settings.value('output/rollover_duration_unit', 'seconds', str),
            'rollover_wallclock_enabled': settings.value('output/rollover_wallclock_enabled', False, bool),
            'rollover_wallclock_value': settings.value('output/rollover_wallclock_value', 1, int),
            'rollover_wallclock_unit': settings.value('output/rollover_wallclock_unit', 'hours', str),
            'infix_pattern': settings.value('output/infix_pattern', 'timestamp_first', str),
            'ring_buffer_enabled': settings.value('output/ring_buffer_enabled', False, bool),
            'ring_buffer_files': settings.value('output/ring_buffer_files', 2, int),
        }
        options_defaults = {
            'realtime': settings.value('options/realtime', True, bool),
            'autoscroll': settings.value('options/autoscroll', True, bool),
            'show_info': settings.value('options/show_info', False, bool),
            'resolve_mac': settings.value('options/resolve_mac', True, bool),
            'resolve_network': settings.value('options/resolve_network', False, bool),
            'resolve_transport': settings.value('options/resolve_transport', False, bool),
            'stop_packets_enabled': settings.value('options/stop_packets_enabled', False, bool),
            'stop_packets_value': settings.value('options/stop_packets_value', 1, int),
            'stop_files_enabled': settings.value('options/stop_files_enabled', False, bool),
            'stop_files_value': settings.value('options/stop_files_value', 1, int),
            'stop_size_enabled': settings.value('options/stop_size_enabled', False, bool),
            'stop_size_value': settings.value('options/stop_size_value', 1, int),
            'stop_size_unit': settings.value('options/stop_size_unit', 'kilobytes', str),
            'stop_duration_enabled': settings.value('options/stop_duration_enabled', False, bool),
            'stop_duration_value': settings.value('options/stop_duration_value', 1, int),
            'stop_duration_unit': settings.value('options/stop_duration_unit', 'seconds', str),
            'temp_dir': settings.value('options/temp_dir', tempfile.gettempdir(), str),
        }
        return output_defaults, options_defaults

    def _apply_capture_defaults_to_view(self):
        """Apply default Output/Options settings to current capture view"""
        if not self.capture_view:
            return
        output_defaults, options_defaults = self._load_capture_defaults()
        self.capture_view.set_output_settings(output_defaults)
        self.capture_view.set_options_settings(options_defaults)
        self.capture_view.set_auto_scroll_enabled(bool(options_defaults.get('autoscroll', True)))

        if hasattr(self, 'action_stay_last_btn'):
            self.action_stay_last_btn.blockSignals(True)
            self.action_stay_last_btn.setChecked(bool(options_defaults.get('autoscroll', True)))
            self.action_stay_last_btn.blockSignals(False)
        if hasattr(self, 'action_go_auto_scroll_live_capture'):
            self.action_go_auto_scroll_live_capture.blockSignals(True)
            self.action_go_auto_scroll_live_capture.setChecked(bool(options_defaults.get('autoscroll', True)))
            self.action_go_auto_scroll_live_capture.blockSignals(False)

    def _update_toolbar_state(self, mode: str):
        """Cáº­p nháº­t tráº¡ng thĂ¡i toolbar theo mode"""
        has_capture = bool(self.capture_view)

        if mode == 'selector':
            self.action_start_btn.setEnabled(False)
            self.action_stop_btn.setEnabled(False)
            self.action_restart_btn.setEnabled(False)
            self.action_save_btn.setEnabled(False)
            self.action_close_btn.setEnabled(False)
            self.action_reload_btn.setEnabled(False)
            self.action_prev_btn.setEnabled(False)
            self.action_next_btn.setEnabled(False)
            self.action_jump_btn.setEnabled(False)
            self.action_first_btn.setEnabled(False)
            self.action_last_btn.setEnabled(False)
            self.action_stay_last_btn.setEnabled(False)
            self.action_zoom_in_btn.setEnabled(False)
            self.action_zoom_out_btn.setEnabled(False)
            self.action_zoom_reset_btn.setEnabled(False)
            self.action_resize_cols_btn.setEnabled(False)
            self.action_reset_layout_btn.setEnabled(False)
            self.action_open_btn.setEnabled(True)
            self.action_settings_btn.setEnabled(True)
            self.action_search_btn.setEnabled(False)
            self.action_color_btn.setEnabled(False)
        else:
            self._sync_capture_buttons()
            self.action_open_btn.setEnabled(True)
            self.action_settings_btn.setEnabled(True)
            self.action_save_btn.setEnabled(has_capture)
            self.action_close_btn.setEnabled(has_capture)
            self.action_reload_btn.setEnabled(has_capture)
            self.action_prev_btn.setEnabled(has_capture)
            self.action_next_btn.setEnabled(has_capture)
            self.action_jump_btn.setEnabled(has_capture)
            self.action_first_btn.setEnabled(has_capture)
            self.action_last_btn.setEnabled(has_capture)
            self.action_stay_last_btn.setEnabled(True)
            self.action_zoom_in_btn.setEnabled(has_capture)
            self.action_zoom_out_btn.setEnabled(has_capture)
            self.action_zoom_reset_btn.setEnabled(has_capture)
            self.action_resize_cols_btn.setEnabled(has_capture)
            self.action_reset_layout_btn.setEnabled(has_capture)
            self.action_search_btn.setEnabled(has_capture)
            self.action_color_btn.setEnabled(has_capture)
        self._refresh_file_menu_state()
        self._refresh_go_menu_state()

    def _refresh_file_menu_state(self):
        active_capture = bool(
            self.capture_view
            and self.stacked_widget.currentWidget() is self.capture_view
        )
        has_packets = bool(active_capture and self.capture_view.has_packets())
        is_running = bool(active_capture and self.capture_view.is_capturing())

        if hasattr(self, 'action_open'):
            self.action_open.setEnabled(True)
        if hasattr(self, 'action_merge'):
            self.action_merge.setEnabled(has_packets and not is_running)
        if hasattr(self, 'action_save'):
            self.action_save.setEnabled(has_packets and not is_running)
        if hasattr(self, 'action_save_as'):
            self.action_save_as.setEnabled(has_packets and not is_running)
        if hasattr(self, 'action_separate'):
            self.action_separate.setEnabled(has_packets and not is_running)
        if hasattr(self, 'action_export'):
            self.action_export.setEnabled(has_packets and not is_running)
        if hasattr(self, 'action_print'):
            self.action_print.setEnabled(has_packets)
        if hasattr(self, 'action_exit'):
            self.action_exit.setEnabled(True)
        self._refresh_edit_menu_state()
        self._refresh_go_menu_state()

    def _refresh_edit_menu_state(self):
        active_capture = bool(
            self.capture_view
            and self.stacked_widget.currentWidget() is self.capture_view
        )
        has_packets = bool(active_capture and self.capture_view.has_packets())
        if hasattr(self, 'action_copy'):
            self.action_copy.setEnabled(active_capture)
        if hasattr(self, 'action_find'):
            self.action_find.setEnabled(has_packets)
        if hasattr(self, 'action_find_next'):
            self.action_find_next.setEnabled(has_packets)
        if hasattr(self, 'action_find_previous'):
            self.action_find_previous.setEnabled(has_packets)
        if hasattr(self, 'action_mark_unmark_selected'):
            self.action_mark_unmark_selected.setEnabled(has_packets)
        if hasattr(self, 'action_mark_unmark_all_displayed'):
            self.action_mark_unmark_all_displayed.setEnabled(has_packets)
        if hasattr(self, 'action_next_mark'):
            self.action_next_mark.setEnabled(has_packets)
        if hasattr(self, 'action_previous_mark'):
            self.action_previous_mark.setEnabled(has_packets)
        if hasattr(self, 'action_ignore_unignore_selected'):
            self.action_ignore_unignore_selected.setEnabled(has_packets)
        if hasattr(self, 'action_ignore_unignore_all_displayed'):
            self.action_ignore_unignore_all_displayed.setEnabled(has_packets)
        if hasattr(self, 'action_packet_comment'):
            self.action_packet_comment.setEnabled(has_packets)
        if hasattr(self, 'action_delete_all_packet_comments'):
            self.action_delete_all_packet_comments.setEnabled(has_packets)
        if hasattr(self, 'action_preferences'):
            self.action_preferences.setEnabled(True)

    def _refresh_go_menu_state(self):
        active_capture = bool(
            self.capture_view
            and self.stacked_widget.currentWidget() is self.capture_view
        )
        default_state = {
            'can_go_back': False,
            'can_go_forward': False,
            'can_go_to_packet': False,
            'can_corresponding': False,
            'can_previous_packet': False,
            'can_next_packet': False,
            'can_first_packet': False,
            'can_last_packet': False,
            'can_previous_conversation': False,
            'can_next_conversation': False,
            'auto_scroll_enabled': True,
        }

        state = dict(default_state)
        if active_capture:
            try:
                state.update(self.capture_view.get_go_state())
            except Exception:
                pass

        mapping = [
            ('action_go_back', 'can_go_back'),
            ('action_go_forward', 'can_go_forward'),
            ('action_go_to_packet', 'can_go_to_packet'),
            ('action_go_to_corresponding_packet', 'can_corresponding'),
            ('action_go_previous_packet', 'can_previous_packet'),
            ('action_go_next_packet', 'can_next_packet'),
            ('action_go_first_packet', 'can_first_packet'),
            ('action_go_last_packet', 'can_last_packet'),
            ('action_go_previous_packet_conversation', 'can_previous_conversation'),
            ('action_go_next_packet_conversation', 'can_next_conversation'),
        ]
        for action_name, key in mapping:
            action = getattr(self, action_name, None)
            if action is not None:
                action.setEnabled(bool(state.get(key, False)))

        if hasattr(self, 'action_go_auto_scroll_live_capture'):
            self.action_go_auto_scroll_live_capture.setEnabled(True)
            self.action_go_auto_scroll_live_capture.blockSignals(True)
            self.action_go_auto_scroll_live_capture.setChecked(bool(state.get('auto_scroll_enabled', True)))
            self.action_go_auto_scroll_live_capture.blockSignals(False)
        if hasattr(self, 'action_stay_last_btn'):
            self.action_stay_last_btn.setEnabled(active_capture)
            self.action_stay_last_btn.blockSignals(True)
            self.action_stay_last_btn.setChecked(bool(state.get('auto_scroll_enabled', True)))
            self.action_stay_last_btn.blockSignals(False)

    def _sync_capture_buttons(self):
        is_running = bool(self.capture_view and self.capture_view.is_capturing())
        is_stopping = bool(self.capture_view and self.capture_view.is_stopping())
        has_capture = bool(self.capture_view)
        self.action_start_btn.setEnabled(has_capture and not is_running and not is_stopping)
        self.action_restart_btn.setEnabled(has_capture and is_running and not is_stopping)
        self.action_stop_btn.setEnabled(has_capture and (is_running or is_stopping))
        self._refresh_capture_menu_state()

    def _refresh_capture_menu_state(self):
        active_capture = bool(self.capture_view and self.stacked_widget.currentWidget() is self.capture_view)
        is_running = bool(active_capture and self.capture_view.is_capturing())
        is_stopping = bool(active_capture and self.capture_view.is_stopping())
        has_iface = bool(active_capture and str(getattr(self.capture_view, 'iface', '') or '').strip())

        if not active_capture:
            if hasattr(self, 'action_capture_options'):
                self.action_capture_options.setEnabled(True)
            if hasattr(self, 'action_start_capture'):
                self.action_start_capture.setEnabled(True)
            if hasattr(self, 'action_stop_capture'):
                self.action_stop_capture.setEnabled(False)
            if hasattr(self, 'action_restart_capture'):
                self.action_restart_capture.setEnabled(False)
            if hasattr(self, 'action_capture_filters'):
                self.action_capture_filters.setEnabled(True)
            if hasattr(self, 'action_refresh_interfaces'):
                self.action_refresh_interfaces.setEnabled(True)
            return

        if hasattr(self, 'action_capture_options'):
            self.action_capture_options.setEnabled(active_capture)
        if hasattr(self, 'action_start_capture'):
            self.action_start_capture.setEnabled(active_capture and has_iface and not is_running and not is_stopping)
        if hasattr(self, 'action_stop_capture'):
            self.action_stop_capture.setEnabled(active_capture and (is_running or is_stopping))
        if hasattr(self, 'action_restart_capture'):
            self.action_restart_capture.setEnabled(active_capture and is_running and not is_stopping)
        if hasattr(self, 'action_capture_filters'):
            self.action_capture_filters.setEnabled(active_capture)
        if hasattr(self, 'action_refresh_interfaces'):
            self.action_refresh_interfaces.setEnabled(not is_running and not is_stopping)

    def _load_capture_filter_presets(self) -> list[dict]:
        settings = QSettings('Packetra', 'Packetra')
        raw = str(settings.value('capture/filter_presets', '[]', str) or '[]')
        try:
            values = json.loads(raw)
        except Exception:
            values = []
        presets = []
        if isinstance(values, list):
            for entry in values:
                if not isinstance(entry, dict):
                    continue
                name = str(entry.get('name', '') or '').strip()
                expression = str(entry.get('expression', '') or '').strip()
                comment = str(entry.get('comment', '') or '').strip()
                if not name and not expression:
                    continue
                presets.append({'name': name, 'expression': expression, 'comment': comment})
        return presets

    def _save_capture_filter_presets(self, presets: list[dict]):
        normalized = []
        for item in presets or []:
            if not isinstance(item, dict):
                continue
            name = str(item.get('name', '') or '').strip()
            expression = str(item.get('expression', '') or '').strip()
            comment = str(item.get('comment', '') or '').strip()
            if not name and not expression:
                continue
            normalized.append({'name': name, 'expression': expression, 'comment': comment})
        settings = QSettings('Packetra', 'Packetra')
        settings.setValue('capture/filter_presets', json.dumps(normalized, ensure_ascii=True))

    def _resolve_capture_filter_alias(self, expression: str) -> str:
        expr = str(expression or '').strip()
        if not expr:
            return ''
        lookup = {}
        for item in self._load_capture_filter_presets():
            if not isinstance(item, dict):
                continue
            name = str(item.get('name', '') or '').strip()
            value = str(item.get('expression', '') or '').strip()
            if name and value:
                lookup[name.casefold()] = value
        return lookup.get(expr.casefold(), expr)

    def _validate_capture_filter_expression(self, expression, iface_name=None):
        expr = self._resolve_capture_filter_alias(expression)
        if not expr:
            return True, ''

        compile_errors = []
        compile_backends = []

        try:
            from scapy.arch.pcapdnet import compile_filter as pcap_compile_filter
            compile_backends.append(lambda: pcap_compile_filter(expr, iface_name or None))
        except Exception:
            pass

        try:
            from scapy.all import compile_filter as scapy_compile_filter
            compile_backends.append(lambda: scapy_compile_filter(expr, iface=iface_name or None))
        except Exception:
            pass

        for backend in compile_backends:
            try:
                backend()
                return True, ''
            except Exception as exc:
                compile_errors.append(str(exc))

        if compile_backends:
            return False, compile_errors[-1] if compile_errors else 'Unknown capture filter syntax error.'
        return True, ''

    def _on_capture_filters(self):
        presets = self._load_capture_filter_presets()
        dialog = CaptureFiltersDialog(self, presets, self._validate_capture_filter_expression)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        self._save_capture_filter_presets(dialog.presets())

    def _on_capture_started(self, iface, iface_display_name, capture_filter):
        """Xử lý khi bắt đầu capture"""
        self.show_capture_view(iface, iface_display_name, capture_filter)
        self._apply_capture_defaults_to_view()
        self._on_start_capture()
        self._refresh_capture_menu_state()

    def _on_open_recent_file(self, path: str):
        candidate = str(path or '').strip()
        if not candidate:
            return
        normalized_path = os.path.abspath(os.path.normpath(candidate))
        if not os.path.exists(normalized_path):
            QMessageBox.warning(self, 'Open', f'File khong ton tai:\n{normalized_path}')
            return
        proceed = self._prompt_save_before_destructive_action('Mở file mới sẽ thay thế dữ liệu hiện tại. Bạn có muốn lưu trước không?')
        if not proceed:
            return
        self.show_capture_view('', 'Offline', '')
        if not self.capture_view:
            QMessageBox.critical(self, 'Open', 'Khong tao duoc Capture View de mo file.')
            return
        started = time.perf_counter()
        try:
            self.capture_view.load_file(normalized_path)
        except Exception as exc:
            QMessageBox.critical(self, 'Open', f'Khong mo duoc file:\n{normalized_path}\n\n{exc}')
            return
        self._last_loaded_seconds = max(0.0, time.perf_counter() - started)
        self._status_mode = 'activity'
        self._status_activity_kind = 'load'
        self._selected_packet_number = None
        self._capture_started_monotonic = None
        self._update_packet_status_label()
        self.detail_field_label.setText('Field: - | Byte: 0')
        if not getattr(self.capture_view, 'records', None):
            QMessageBox.warning(self, 'Open', f'Mo file xong nhung khong co packet:\n{normalized_path}')
            return
        self._sync_capture_buttons()
        self._update_capture_window_title()
        self._refresh_status_metrics()
        self._refresh_file_menu_state()

    def _on_start_capture(self):
        """Bắt đầu capture"""
        if not self.capture_view:
            self._on_capture_options()
            return

        if self.capture_view.is_capturing():
            return

        if not str(getattr(self.capture_view, 'iface', '') or '').strip():
            self._on_capture_options()
            return

        self.capture_view.capture_filter = self._resolve_capture_filter_alias(getattr(self.capture_view, 'capture_filter', ''))

        proceed = self._prompt_save_before_destructive_action('Start capture mới sẽ thay thế dữ liệu hiện tại. Bạn có muốn lưu trước không?')
        if not proceed:
            return

        self._apply_capture_defaults_to_view()
        self.capture_view.start_new_capture()
        self._capture_started_monotonic = time.monotonic()
        self._last_capture_seconds = 0.0
        self._status_mode = 'activity'
        self._status_activity_kind = 'capture'
        self._selected_packet_number = None
        self._update_packet_status_label()
        self.detail_field_label.setText('Field: - | Byte: 0')
        self._sync_capture_buttons()
        self._refresh_capture_menu_state()
        self._update_capture_window_title()

    def _on_stop_capture(self):
        """Dừng capture"""
        if not self.capture_view:
            return
        self.capture_view.stop_capture()
        if self._capture_started_monotonic is not None:
            self._last_capture_seconds = max(0.0, time.monotonic() - float(self._capture_started_monotonic))
            self._capture_started_monotonic = None
        self._status_mode = 'activity'
        self._status_activity_kind = 'capture'
        self._selected_packet_number = None
        self._update_packet_status_label()
        self._sync_capture_buttons()
        self._refresh_capture_menu_state()

    def _on_restart_capture(self):
        """Khởi động lại capture"""
        if not self.capture_view:
            return

        if not self.capture_view.is_capturing():
            return

        proceed = self._prompt_save_before_destructive_action('Restart capture sẽ thay thế dữ liệu hiện tại. Bạn có muốn lưu trước không?')
        if not proceed:
            return

        self.capture_view.restart_capture()
        self._capture_started_monotonic = time.monotonic()
        self._last_capture_seconds = 0.0
        self._status_mode = 'activity'
        self._status_activity_kind = 'capture'
        self._selected_packet_number = None
        self._update_packet_status_label()
        self.detail_field_label.setText('Field: - | Byte: 0')
        self._sync_capture_buttons()
        self._refresh_capture_menu_state()
        self._update_capture_window_title()

    def _on_open_file(self):
        """Mở file PCAP"""
        settings = QSettings('Packetra', 'Packetra')
        mode = str(settings.value('preferences/open_files_mode', 'recent_folder', str) or 'recent_folder')
        fixed_dir = str(settings.value('preferences/open_files_fixed_directory', '', str) or '').strip()
        initial_dir = ''
        if mode == 'fixed_folder' and fixed_dir and os.path.isdir(fixed_dir):
            initial_dir = fixed_dir
        else:
            recent = settings.value('recent_capture_files', [], list)
            if isinstance(recent, list):
                for path in recent:
                    normalized = os.path.normpath(str(path or '').strip())
                    if normalized and os.path.exists(normalized):
                        folder = os.path.dirname(normalized)
                        if folder and os.path.isdir(folder):
                            initial_dir = folder
                            break
        if not initial_dir:
            initial_dir = str(Path.cwd())

        selected_path, _ = QFileDialog.getOpenFileName(
            self,
            'Open PCAP',
            initial_dir,
            'PCAP Files (*.pcap *.pcapng)',
        )
        if not selected_path:
            return

        self._on_open_recent_file(selected_path)

    def _on_save_file(self):
        """Lưu file PCAP"""
        if self.capture_view:
            if self.capture_view.is_capturing():
                QMessageBox.information(self, 'Save', 'Khong the Save khi dang capture. Vui long dung capture truoc.')
                return
            self.capture_view.save_file()
            self._update_capture_window_title()
            if self.iface_selector_view:
                self.iface_selector_view.refresh_recent_files()
            self._refresh_file_menu_state()
        else:
            QMessageBox.information(self, 'Info', 'Không có dữ liệu để lưu.')

    def _on_save_as_file(self):
        """Lưu file PCAP với tên mới"""
        if self.capture_view:
            if self.capture_view.is_capturing():
                QMessageBox.information(self, 'Save As', 'Khong the Save As khi dang capture. Vui long dung capture truoc.')
                return
            self.capture_view.save_file(force_dialog=True)
            self._update_capture_window_title()
            if self.iface_selector_view:
                self.iface_selector_view.refresh_recent_files()
            self._refresh_file_menu_state()
        else:
            QMessageBox.information(self, 'Info', 'Không có dữ liệu để lưu.')

    def _on_merge_file(self):
        cv = self.capture_view
        if not cv or not cv.has_packets():
            QMessageBox.information(self, 'Merge', 'Khong co capture hien tai de merge. Vui long mo hoac bat capture truoc.')
            return
        if cv.is_capturing():
            QMessageBox.warning(self, 'Merge', 'Vui long dung capture truoc khi merge.')
            return

        dialog = QFileDialog(self, 'Merge Capture File')
        dialog.setFileMode(QFileDialog.ExistingFile)
        dialog.setNameFilter('Capture Files (*.pcap *.pcapng)')
        if not dialog.exec():
            return
        selected = dialog.selectedFiles()
        if not selected:
            return
        merge_path = selected[0]

        mode_dialog = QMessageBox(self)
        mode_dialog.setWindowTitle('Merge Mode')
        mode_dialog.setText('Chon cach merge packet:')
        append_btn = mode_dialog.addButton('Them vao cuoi danh sach', QMessageBox.AcceptRole)
        chrono_btn = mode_dialog.addButton('Sap xep lai theo thoi gian', QMessageBox.ActionRole)
        cancel_btn = mode_dialog.addButton(QMessageBox.Cancel)
        mode_dialog.setDefaultButton(append_btn)
        mode_dialog.exec()
        clicked = mode_dialog.clickedButton()
        if clicked == cancel_btn or clicked is None:
            return
        chronological = clicked == chrono_btn

        try:
            incoming_packets = list(iter_pcap_packets(merge_path))
            incoming_metadata = load_capture_metadata(merge_path)
        except Exception as exc:
            QMessageBox.critical(self, 'Merge', f'Khong the doc file merge:\n{exc}')
            return

        if not incoming_packets:
            QMessageBox.warning(self, 'Merge', 'File duoc chon khong co packet hop le de merge.')
            return

        merged_entries = [self._packet_entry_from_record(r) for r in cv.records if getattr(r, 'raw', None) is not None]
        packet_comments = dict(getattr(incoming_metadata, 'packet_comments', {}) or {})
        packet_interfaces = dict(getattr(incoming_metadata, 'packet_interfaces', {}) or {})
        incoming_interfaces = list(getattr(incoming_metadata, 'interfaces', []) or [])
        for idx, pkt in enumerate(incoming_packets, start=1):
            interface_info = None
            if idx in packet_interfaces:
                incoming_interface_id = int(packet_interfaces.get(idx, 0) or 0)
                for interface in incoming_interfaces:
                    try:
                        raw_interface_id = interface.get('interface_id', -1)
                        parsed_interface_id = -1 if raw_interface_id is None else int(raw_interface_id)
                        if parsed_interface_id == incoming_interface_id:
                            interface_info = dict(interface)
                            break
                    except Exception:
                        continue
            snapshot = {
                'marked': False,
                'ignored': False,
                'comment': str(packet_comments.get(idx, '') or ''),
                'interface_id': int(packet_interfaces.get(idx, 0) or 0) if idx in packet_interfaces else 0,
                'has_interface_id': idx in packet_interfaces,
            }
            merged_entries.append({'raw': pkt, 'snapshot': snapshot, 'interface_info': interface_info})
        if chronological:
            merged_entries.sort(key=lambda entry: float(getattr(entry.get('raw'), 'time', 0.0) or 0.0))

        self._replace_capture_packets(
            merged_entries,
            preserve_metadata=True,
            preserve_loaded_path=True,
            mark_dirty=True,
            status_message=f'Merged {len(incoming_packets)} packets from {os.path.basename(merge_path)}',
        )
        self._update_capture_window_title()
        self._refresh_status_metrics()
        self._refresh_file_menu_state()

    def _on_separate_packets(self):
        cv = self.capture_view
        if not cv or not cv.has_packets():
            QMessageBox.information(self, 'Separate', 'Khong co packet de tach.')
            return
        if cv.is_capturing():
            QMessageBox.warning(self, 'Separate', 'Vui long dung capture truoc khi tach packet.')
            return

        dialog = QDialog(self)
        dialog.setWindowTitle('Separate Packets')
        layout = QVBoxLayout(dialog)
        total_packets = len(cv.records)
        layout.addWidget(QLabel(f'Tong so packet hien tai: {total_packets}'))

        layout.addWidget(QLabel('Mode:'))
        mode_combo = QComboBox(dialog)
        mode_combo.addItems([
            'Mode 1: Tach 1 file ra thanh nhieu file',
            'Mode 2: Xoa goi tin trong file',
        ])
        layout.addWidget(mode_combo)

        mode_stack = QStackedWidget(dialog)
        layout.addWidget(mode_stack)

        # Mode 1 UI
        split_page = QWidget(dialog)
        split_layout = QVBoxLayout(split_page)
        split_toolbar = QHBoxLayout()
        split_toolbar.addWidget(QLabel('Danh sach file tach:'))
        split_remove_btn = QPushButton('-', split_page)
        split_add_btn = QPushButton('+', split_page)
        split_count_label = QLabel('', split_page)
        split_toolbar.addStretch()
        split_toolbar.addWidget(split_remove_btn)
        split_toolbar.addWidget(split_add_btn)
        split_toolbar.addWidget(split_count_label)
        split_layout.addLayout(split_toolbar)

        split_table = QTableWidget(0, 3, split_page)
        split_table.setHorizontalHeaderLabels(['File', 'From', 'To'])
        split_table.verticalHeader().setVisible(False)
        split_table.horizontalHeader().setStretchLastSection(True)
        split_layout.addWidget(split_table)

        split_note = QLabel(
            'Co the sua cot "To". From cua file sau se tu dong = To truoc + 1.',
            split_page,
        )
        split_note.setWordWrap(True)
        split_layout.addWidget(split_note)

        mode_stack.addWidget(split_page)

        # Mode 2 UI
        delete_page = QWidget(dialog)
        delete_layout = QVBoxLayout(delete_page)

        delete_selected_cb = QCheckBox('Xoa goi tin dang chon (Selected packets)', delete_page)
        delete_layout.addWidget(delete_selected_cb)

        delete_protocol_cb = QCheckBox('Xoa theo protocol', delete_page)
        delete_layout.addWidget(delete_protocol_cb)
        delete_protocol_input = QLineEdit(delete_page)
        delete_protocol_input.setPlaceholderText('VD: TCP,UDP,DNS')
        delete_layout.addWidget(delete_protocol_input)

        delete_ranges_cb = QCheckBox('Xoa theo khoang packet (nhieu khoang)', delete_page)
        delete_layout.addWidget(delete_ranges_cb)
        delete_ranges_input = QTextEdit(delete_page)
        delete_ranges_input.setPlaceholderText('VD: 1-100, 150, 200-260')
        delete_ranges_input.setMinimumHeight(90)
        delete_layout.addWidget(delete_ranges_input)

        delete_criteria_cbs = [delete_selected_cb, delete_protocol_cb, delete_ranges_cb]

        def _on_delete_criteria_toggled(changed_cb, checked: bool):
            if not checked:
                return
            for cb in delete_criteria_cbs:
                if cb is not changed_cb:
                    cb.blockSignals(True)
                    cb.setChecked(False)
                    cb.blockSignals(False)
            _toggle_delete_fields()

        mode_stack.addWidget(delete_page)

        btn_row = QHBoxLayout()
        ok_btn = QPushButton('Separate', dialog)
        cancel_btn = QPushButton('Cancel', dialog)
        btn_row.addStretch()
        btn_row.addWidget(ok_btn)
        btn_row.addWidget(cancel_btn)
        layout.addLayout(btn_row)

        split_state = {'file_count': 2, 'manual_edit': False}
        split_guard = {'busy': False}

        def _build_even_ranges(packet_total: int, file_count: int):
            if packet_total <= 0 or file_count <= 0:
                return []
            base = packet_total // file_count
            rem = packet_total % file_count
            ranges = []
            start = 1
            for i in range(file_count):
                length = base + (1 if i < rem else 0)
                end = start + max(0, length) - 1
                ranges.append((start, end))
                start = end + 1
            return ranges

        def _renumber_split_rows():
            for r in range(split_table.rowCount()):
                name_item = split_table.item(r, 0)
                if name_item is None:
                    name_item = QTableWidgetItem()
                    name_item.setFlags(name_item.flags() & ~Qt.ItemIsEditable)
                    split_table.setItem(r, 0, name_item)
                name_item.setText(f'File {r + 1}')

        def _render_split_ranges(ranges):
            split_guard['busy'] = True
            try:
                split_table.setRowCount(len(ranges))
                for row, (frm, to_) in enumerate(ranges, start=1):
                    name_item = QTableWidgetItem(f'File {row}')
                    from_item = QTableWidgetItem(str(frm))
                    to_item = QTableWidgetItem(str(to_))
                    name_item.setFlags(name_item.flags() & ~Qt.ItemIsEditable)
                    from_item.setFlags(from_item.flags() & ~Qt.ItemIsEditable)
                    split_table.setItem(row - 1, 0, name_item)
                    split_table.setItem(row - 1, 1, from_item)
                    split_table.setItem(row - 1, 2, to_item)
                split_count_label.setText(f'So file: {len(ranges)}')
                split_table.resizeColumnsToContents()
            finally:
                split_guard['busy'] = False

        def _reset_split_even():
            count = int(split_state['file_count'])
            count = max(2, min(count, total_packets))
            split_state['file_count'] = count
            _render_split_ranges(_build_even_ranges(total_packets, count))
            split_state['manual_edit'] = False

        def _collect_split_ranges_from_table():
            rows = split_table.rowCount()
            if rows < 2:
                raise ValueError('Can it nhat 2 file de tach.')
            ranges = []
            expected_from = 1
            for r in range(rows):
                from_item = split_table.item(r, 1)
                to_item = split_table.item(r, 2)
                if from_item is None or to_item is None:
                    raise ValueError('Bang tach file dang thieu du lieu.')
                frm = int((from_item.text() or '0').strip())
                to_ = int((to_item.text() or '0').strip())
                if frm != expected_from:
                    raise ValueError(f'From cua File {r+1} phai bang {expected_from}.')
                if to_ < frm:
                    raise ValueError(f'To cua File {r+1} phai >= From.')
                ranges.append((frm, to_))
                expected_from = to_ + 1
            if ranges[-1][1] != total_packets:
                raise ValueError(f'To cua file cuoi phai bang {total_packets}.')
            return ranges

        def _on_split_to_changed(item):
            if split_guard['busy'] or item is None or item.column() != 2:
                return
            row = int(item.row())
            rows = split_table.rowCount()
            if row < 0 or row >= rows:
                return
            if row == rows - 1:
                split_guard['busy'] = True
                try:
                    split_table.item(row, 2).setText(str(total_packets))
                finally:
                    split_guard['busy'] = False
                return

            try:
                frm = int((split_table.item(row, 1).text() or '1').strip())
            except Exception:
                frm = 1
            min_to = frm
            try:
                next_to = int((split_table.item(row + 1, 2).text() or str(total_packets)).strip())
            except Exception:
                next_to = total_packets
            max_to = max(min_to, next_to - 1)
            try:
                new_to = int((item.text() or '').strip())
            except Exception:
                new_to = min_to
            new_to = max(min_to, min(max_to, new_to))

            split_guard['busy'] = True
            try:
                split_table.item(row, 2).setText(str(new_to))
                for rr in range(row + 1, rows):
                    prev_to = int((split_table.item(rr - 1, 2).text() or '0').strip())
                    new_from = prev_to + 1
                    split_table.item(rr, 1).setText(str(new_from))
            finally:
                split_guard['busy'] = False
            split_state['manual_edit'] = True

        def _split_last_file_in_half():
            rows = split_table.rowCount()
            if rows <= 0:
                return
            last_row = rows - 1
            last_from = int((split_table.item(last_row, 1).text() or '1').strip())
            last_to = int((split_table.item(last_row, 2).text() or str(total_packets)).strip())
            last_len = last_to - last_from + 1
            if last_len < 2:
                QMessageBox.warning(dialog, 'Separate', 'Khong the tach them: file cuoi qua nho de chia doi.')
                return

            left_len = last_len // 2
            left_to = last_from + left_len - 1
            right_from = left_to + 1
            right_to = last_to

            split_guard['busy'] = True
            try:
                split_table.item(last_row, 2).setText(str(left_to))
                split_table.insertRow(rows)

                name_item = QTableWidgetItem('')
                name_item.setFlags(name_item.flags() & ~Qt.ItemIsEditable)
                from_item = QTableWidgetItem(str(right_from))
                from_item.setFlags(from_item.flags() & ~Qt.ItemIsEditable)
                to_item = QTableWidgetItem(str(right_to))

                split_table.setItem(rows, 0, name_item)
                split_table.setItem(rows, 1, from_item)
                split_table.setItem(rows, 2, to_item)
                _renumber_split_rows()
                split_count_label.setText(f'So file: {split_table.rowCount()}')
                split_table.resizeColumnsToContents()
            finally:
                split_guard['busy'] = False

        def _on_split_add():
            current_rows = split_table.rowCount()
            if current_rows >= total_packets:
                QMessageBox.warning(dialog, 'Separate', 'So file khong the lon hon tong so packet.')
                return
            if split_state['manual_edit']:
                _split_last_file_in_half()
                split_state['file_count'] = split_table.rowCount()
            else:
                split_state['file_count'] += 1
                _reset_split_even()

        def _on_split_remove():
            current_rows = split_table.rowCount()
            if current_rows <= 2:
                return
            if split_state['manual_edit']:
                split_guard['busy'] = True
                try:
                    last_row = split_table.rowCount() - 1
                    prev_row = last_row - 1
                    last_to = int((split_table.item(last_row, 2).text() or str(total_packets)).strip())
                    split_table.item(prev_row, 2).setText(str(last_to))
                    split_table.removeRow(last_row)
                    _renumber_split_rows()
                    split_count_label.setText(f'So file: {split_table.rowCount()}')
                finally:
                    split_guard['busy'] = False
                split_state['file_count'] = split_table.rowCount()
            else:
                split_state['file_count'] -= 1
                _reset_split_even()

        split_add_btn.clicked.connect(_on_split_add)
        split_remove_btn.clicked.connect(_on_split_remove)
        split_table.itemChanged.connect(_on_split_to_changed)

        def _toggle_delete_fields():
            delete_protocol_input.setEnabled(delete_protocol_cb.isChecked())
            delete_ranges_input.setEnabled(delete_ranges_cb.isChecked())

        def _on_mode_changed():
            mode_stack.setCurrentIndex(mode_combo.currentIndex())

        _on_mode_changed()
        _toggle_delete_fields()
        _reset_split_even()

        mode_combo.currentIndexChanged.connect(_on_mode_changed)
        delete_selected_cb.toggled.connect(lambda checked: _on_delete_criteria_toggled(delete_selected_cb, checked))
        delete_protocol_cb.toggled.connect(lambda checked: _on_delete_criteria_toggled(delete_protocol_cb, checked))
        delete_ranges_cb.toggled.connect(lambda checked: _on_delete_criteria_toggled(delete_ranges_cb, checked))
        delete_protocol_cb.toggled.connect(lambda _checked: _toggle_delete_fields())
        delete_ranges_cb.toggled.connect(lambda _checked: _toggle_delete_fields())
        ok_btn.clicked.connect(dialog.accept)
        cancel_btn.clicked.connect(dialog.reject)

        if dialog.exec() != QDialog.DialogCode.Accepted:
            return

        if mode_combo.currentIndex() == 0:
            try:
                ranges = _collect_split_ranges_from_table()
            except Exception as exc:
                QMessageBox.warning(self, 'Separate', str(exc))
                return

            default_dir = os.path.dirname(str(cv.loaded_file_path)) if cv.loaded_file_path else str(Path.cwd())
            output_dir = QFileDialog.getExistingDirectory(self, 'Chon thu muc luu cac file tach', default_dir)
            if not output_dir:
                return

            default_base = Path(cv.loaded_file_path).stem if cv.loaded_file_path else 'separated_capture'
            base_name, ok = QInputDialog.getText(
                self,
                'Ten file tach',
                'Nhap tien to ten file:',
                text=str(default_base or 'separated_capture'),
            )
            if not ok:
                return
            base_name = str(base_name or '').strip()
            if not base_name:
                QMessageBox.warning(self, 'Separate', 'Ten file khong duoc de trong.')
                return

            file_format = 'pcapng'
            compression = 'none'
            loaded = str(cv.loaded_file_path or '').lower()
            base_path = loaded
            if loaded.endswith('.gz'):
                compression = 'gzip'
                base_path = os.path.splitext(loaded)[0]
            elif loaded.endswith('.lz4'):
                compression = 'lz4'
                base_path = os.path.splitext(loaded)[0]
            if base_path.endswith('.pcap'):
                file_format = 'pcap'

            saved_paths = []
            try:
                for part_no, (frm, to_) in enumerate(ranges, start=1):
                    chunk_records = [
                        rec
                        for rec in cv.records
                        if frm <= int(getattr(rec, 'number', 0) or 0) <= to_
                        and getattr(rec, 'raw', None) is not None
                    ]
                    chunk_packets = [rec.raw for rec in chunk_records]
                    target = os.path.join(output_dir, f'{base_name}_part{part_no:03d}')
                    chunk_metadata = self._derive_output_metadata_for_records(chunk_records) if file_format == 'pcapng' else None
                    saved_path = save_capture_file_with_metadata(
                        target,
                        chunk_packets,
                        metadata=chunk_metadata,
                        file_format=file_format,
                        compression=compression,
                    )
                    saved_paths.append(saved_path)
            except Exception as exc:
                QMessageBox.critical(self, 'Separate', f'Tach thanh nhieu file that bai:\n{exc}')
                return

            QMessageBox.information(
                self,
                'Separate',
                f'Da tach thanh {len(saved_paths)} file.\nThu muc: {output_dir}',
            )
            return

        # Mode 2: delete packets in current file
        delete_indices = set()
        criteria_used = False

        if delete_selected_cb.isChecked():
            criteria_used = True
            delete_indices.update(self._resolve_record_indices('Selected packets'))

        if delete_protocol_cb.isChecked():
            criteria_used = True
            protocol_indices = self._resolve_indices_by_protocol_text(delete_protocol_input.text())
            delete_indices.update(protocol_indices)

        if delete_ranges_cb.isChecked():
            criteria_used = True
            range_indices = self._resolve_indices_by_ranges_text(delete_ranges_input.toPlainText())
            delete_indices.update(range_indices)

        if not criteria_used:
            QMessageBox.warning(self, 'Separate', 'Hay chon it nhat 1 tieu chi xoa packet.')
            return
        if not delete_indices:
            QMessageBox.warning(self, 'Separate', 'Khong co packet nao phu hop de xoa.')
            return

        confirm = QMessageBox.question(
            self,
            'Separate',
            f'Ban chac chan muon xoa {len(delete_indices)} packet khoi file hien tai?',
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if confirm != QMessageBox.Yes:
            return

        remaining_entries = [
            self._packet_entry_from_record(rec)
            for i, rec in enumerate(cv.records)
            if i not in delete_indices and getattr(rec, 'raw', None) is not None
        ]
        self._replace_capture_packets(
            remaining_entries,
            preserve_metadata=True,
            preserve_loaded_path=True,
            mark_dirty=True,
            status_message=f'Deleted {len(delete_indices)} packets from current capture',
        )
        self._update_capture_window_title()
        self._refresh_status_metrics()
        self._refresh_file_menu_state()

    def _on_export_specified_packets(self):
        cv = self.capture_view
        if not cv or not cv.has_packets():
            QMessageBox.information(self, 'Export Specified Packets', 'Khong co packet de export.')
            return
        if cv.is_capturing():
            QMessageBox.warning(self, 'Export Specified Packets', 'Vui long dung capture truoc khi export.')
            return

        dialog = QDialog(self)
        dialog.setWindowTitle('Export Specified Packets')
        layout = QVBoxLayout(dialog)
        layout.addWidget(QLabel('Tao file PCAP moi tu cac packet theo tieu chi:'))

        export_selected_cb = QCheckBox('Packet dang chon (Selected packets)', dialog)
        layout.addWidget(export_selected_cb)

        export_protocol_cb = QCheckBox('Theo protocol', dialog)
        layout.addWidget(export_protocol_cb)
        export_protocol_input = QLineEdit(dialog)
        export_protocol_input.setPlaceholderText('VD: TCP,UDP,DNS')
        layout.addWidget(export_protocol_input)

        export_ranges_cb = QCheckBox('Theo khoang packet (nhieu khoang)', dialog)
        layout.addWidget(export_ranges_cb)
        export_ranges_input = QTextEdit(dialog)
        export_ranges_input.setPlaceholderText('VD: 1-100, 150, 200-260')
        export_ranges_input.setMinimumHeight(90)
        layout.addWidget(export_ranges_input)

        export_criteria_cbs = [export_selected_cb, export_protocol_cb, export_ranges_cb]

        def _on_export_criteria_toggled(changed_cb, checked: bool):
            if not checked:
                return
            for cb in export_criteria_cbs:
                if cb is not changed_cb:
                    cb.blockSignals(True)
                    cb.setChecked(False)
                    cb.blockSignals(False)
            _toggle_export_fields()

        btn_row = QHBoxLayout()
        ok_btn = QPushButton('Choose Output...', dialog)
        cancel_btn = QPushButton('Cancel', dialog)
        btn_row.addStretch()
        btn_row.addWidget(ok_btn)
        btn_row.addWidget(cancel_btn)
        layout.addLayout(btn_row)

        def _toggle_export_fields():
            export_protocol_input.setEnabled(export_protocol_cb.isChecked())
            export_ranges_input.setEnabled(export_ranges_cb.isChecked())

        _toggle_export_fields()
        export_selected_cb.toggled.connect(lambda checked: _on_export_criteria_toggled(export_selected_cb, checked))
        export_protocol_cb.toggled.connect(lambda checked: _on_export_criteria_toggled(export_protocol_cb, checked))
        export_ranges_cb.toggled.connect(lambda checked: _on_export_criteria_toggled(export_ranges_cb, checked))
        export_protocol_cb.toggled.connect(lambda _checked: _toggle_export_fields())
        export_ranges_cb.toggled.connect(lambda _checked: _toggle_export_fields())
        ok_btn.clicked.connect(dialog.accept)
        cancel_btn.clicked.connect(dialog.reject)

        if dialog.exec() != QDialog.DialogCode.Accepted:
            return

        export_indices = set()
        criteria_used = False

        if export_selected_cb.isChecked():
            criteria_used = True
            export_indices.update(self._resolve_record_indices('Selected packets'))

        if export_protocol_cb.isChecked():
            criteria_used = True
            export_indices.update(self._resolve_indices_by_protocol_text(export_protocol_input.text()))

        if export_ranges_cb.isChecked():
            criteria_used = True
            export_indices.update(self._resolve_indices_by_ranges_text(export_ranges_input.toPlainText()))

        if not criteria_used:
            QMessageBox.warning(self, 'Export Specified Packets', 'Hay chon it nhat 1 tieu chi export.')
            return

        if not export_indices:
            QMessageBox.warning(self, 'Export Specified Packets', 'Khong co packet phu hop de export.')
            return

        export_records = [cv.records[i] for i in sorted(export_indices) if getattr(cv.records[i], 'raw', None) is not None]
        packets = [rec.raw for rec in export_records]
        if not packets:
            QMessageBox.warning(self, 'Export Specified Packets', 'Khong co packet hop le de export.')
            return

        filename, selected_format, selected_compression = cv._show_save_with_options_dialog()
        if not filename:
            return

        try:
            export_metadata = self._derive_output_metadata_for_records(export_records) if selected_format == 'pcapng' else None
            out_path = save_capture_file_with_metadata(
                filename,
                packets,
                metadata=export_metadata,
                file_format=selected_format,
                compression=selected_compression,
            )
            QMessageBox.information(
                self,
                'Export Specified Packets',
                f'Export thanh cong {len(packets)} packet:\n{out_path}',
            )
        except Exception as exc:
            QMessageBox.critical(self, 'Export Specified Packets', f'Export that bai:\n{exc}')

    def _parse_packet_ranges_to_numbers(self, ranges_text: str):
        text = str(ranges_text or '').strip()
        if not text:
            return set()
        tokens = [tok.strip() for tok in re.split(r'[,\s;]+', text) if tok.strip()]
        if not tokens:
            return set()
        numbers = set()
        for tok in tokens:
            if '-' in tok:
                parts = [p.strip() for p in tok.split('-', 1)]
                if len(parts) != 2 or not parts[0].isdigit() or not parts[1].isdigit():
                    raise ValueError(f'Khoang khong hop le: {tok}')
                lo = int(parts[0])
                hi = int(parts[1])
                if lo > hi:
                    lo, hi = hi, lo
                for n in range(lo, hi + 1):
                    numbers.add(n)
            else:
                if not tok.isdigit():
                    raise ValueError(f'Gia tri khong hop le: {tok}')
                numbers.add(int(tok))
        return numbers

    def _resolve_indices_by_ranges_text(self, ranges_text: str):
        cv = self.capture_view
        if not cv:
            return set()
        try:
            numbers = self._parse_packet_ranges_to_numbers(ranges_text)
        except Exception as exc:
            QMessageBox.warning(self, 'Range', str(exc))
            return set()
        if not numbers:
            return set()
        return {
            i for i, rec in enumerate(cv.records)
            if int(getattr(rec, 'number', 0) or 0) in numbers
        }

    def _resolve_indices_by_protocol_text(self, protocol_text: str):
        cv = self.capture_view
        if not cv:
            return set()
        text = str(protocol_text or '').strip()
        if not text:
            QMessageBox.warning(self, 'Protocol', 'Vui long nhap protocol can loc/xoa.')
            return set()
        tokens = [t.strip().lower() for t in re.split(r'[,\s;]+', text) if t.strip()]
        if not tokens:
            QMessageBox.warning(self, 'Protocol', 'Protocol khong hop le.')
            return set()
        token_set = set(tokens)
        return {
            i for i, rec in enumerate(cv.records)
            if str(getattr(rec, 'protocol', '') or '').strip().lower() in token_set
        }

    def _on_print_packets(self):
        cv = self.capture_view
        if not cv or not cv.has_packets():
            QMessageBox.information(self, 'Print', 'Khong co packet de in.')
            return

        dialog = QDialog(self)
        dialog.setWindowTitle('Print Packets')
        layout = QVBoxLayout(dialog)

        layout.addWidget(QLabel('Print range:'))
        scope_combo = QComboBox(dialog)
        scope_combo.addItems(['All packets', 'Displayed packets', 'Selected packets'])
        layout.addWidget(scope_combo)

        summary_cb = QCheckBox('Packet summary', dialog)
        summary_cb.setChecked(True)
        detail_cb = QCheckBox('Packet details', dialog)
        detail_cb.setChecked(False)
        bytes_cb = QCheckBox('Packet bytes (hex)', dialog)
        bytes_cb.setChecked(False)
        layout.addWidget(summary_cb)
        layout.addWidget(detail_cb)
        layout.addWidget(bytes_cb)

        btn_row = QHBoxLayout()
        print_btn = QPushButton('Print...', dialog)
        cancel_btn = QPushButton('Cancel', dialog)
        btn_row.addStretch()
        btn_row.addWidget(print_btn)
        btn_row.addWidget(cancel_btn)
        layout.addLayout(btn_row)

        print_btn.clicked.connect(dialog.accept)
        cancel_btn.clicked.connect(dialog.reject)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return

        if not (summary_cb.isChecked() or detail_cb.isChecked() or bytes_cb.isChecked()):
            QMessageBox.warning(self, 'Print', 'Can chon it nhat 1 noi dung de in.')
            return

        scope = scope_combo.currentText()
        indexes = self._resolve_record_indices(scope, from_no=None, to_no=None, filter_expr='')
        if not indexes:
            QMessageBox.warning(self, 'Print', 'Khong co packet phu hop de in.')
            return

        lines = []
        lines.append('Packetra - Print Packets')
        lines.append(f'Time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')
        lines.append(f'Range: {scope}')
        lines.append(f'Total packets: {len(indexes)}')
        lines.append('')

        for i, rec_idx in enumerate(indexes, start=1):
            record = cv.records[rec_idx]
            lines.append(f'[{i}] No={record.number} Time={record.relative_time:.6f} Src={record.src} Dst={record.dst} Proto={record.protocol} Len={record.length}')
            if summary_cb.isChecked():
                lines.append(f'  Info: {record.info}')
            if detail_cb.isChecked():
                layer_text = ', '.join(record.layers or [])
                lines.append(f'  Layers: {layer_text}')
                if getattr(record, 'stream_hint', ''):
                    lines.append(f'  Stream: {record.stream_hint}')
            if bytes_cb.isChecked():
                raw_bytes = bytes(record.raw) if getattr(record, 'raw', None) is not None else b''
                lines.append('  Raw bytes:')
                for off in range(0, len(raw_bytes), 16):
                    chunk = raw_bytes[off:off + 16]
                    hex_part = ' '.join(f'{b:02x}' for b in chunk)
                    ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
                    lines.append(f'    {off:04x}  {hex_part:<47}  {ascii_part}')
            lines.append('')

        document = QTextDocument(self)
        document.setPlainText('\n'.join(lines))
        printer = QPrinter(QPrinter.HighResolution)
        print_dialog = QPrintDialog(printer, self)
        print_dialog.setWindowTitle('Print Packets')
        if print_dialog.exec() != QDialog.DialogCode.Accepted:
            return
        document.print(printer)
        QMessageBox.information(self, 'Print', 'Da gui tai lieu den may in.')

    def _on_quit(self):
        self.close()

    def _resolve_record_indices(self, scope: str, from_no=None, to_no=None, filter_expr: str = ''):
        cv = self.capture_view
        if not cv:
            return []

        scope = str(scope or '').strip()
        if scope in ('All packets',):
            return list(range(len(cv.records)))
        if scope in ('Displayed packets',):
            return list(cv.visible_indices)
        if scope in ('Selected packets',):
            selected_rows = (
                sorted({idx.row() for idx in cv.table.selectionModel().selectedRows()})
                if cv.table.selectionModel()
                else []
            )
            indexes = []
            for row in selected_rows:
                if 0 <= row < len(cv.visible_indices):
                    indexes.append(cv.visible_indices[row])
            return indexes
        if scope in ('Packet number range',):
            if from_no is None or to_no is None:
                return []
            lo = min(int(from_no), int(to_no))
            hi = max(int(from_no), int(to_no))
            return [i for i, rec in enumerate(cv.records) if lo <= int(getattr(rec, 'number', 0) or 0) <= hi]
        if scope in ('By display filter expression',):
            expr = str(filter_expr or '').strip()
            if not expr:
                return []
            try:
                return [i for i, rec in enumerate(cv.records) if cv.display_filter.matches(rec, expr)]
            except Exception as exc:
                QMessageBox.warning(self, 'Filter', f'Filter khong hop le:\n{exc}')
                return []
        return []

    def _replace_capture_packets(
        self,
        packets,
        preserve_metadata: bool,
        preserve_loaded_path: bool,
        mark_dirty: bool,
        status_message: str,
        preserve_display_filter: bool = True,
    ):
        cv = self.capture_view
        if not cv:
            return

        packet_entries = []
        for item in list(packets or []):
            if isinstance(item, dict) and item.get('raw') is not None:
                packet_entries.append(dict(item))
            elif not isinstance(item, dict):
                packet_entries.append({'raw': item})
        packet_entries = [entry for entry in packet_entries if entry.get('raw') is not None]
        old_loaded_path = cv.loaded_file_path
        old_metadata = clone_capture_metadata(cv.capture_metadata) if preserve_metadata else CaptureMetadata()
        old_comments = cv.capture_comments
        old_filter = str(cv.display_filter_input.text() or '') if preserve_display_filter else ''

        def _snapshot_from_record(record):
            if record is None:
                return {}
            metadata = getattr(record, 'metadata', {}) or {}
            has_interface_id = 'frame_interface_id' in metadata or hasattr(record, 'interface_id')
            interface_id = metadata.get('frame_interface_id', getattr(record, 'interface_id', 0))
            try:
                interface_id = int(interface_id or 0)
            except Exception:
                interface_id = 0
            return {
                'marked': bool(getattr(record, 'marked', False)),
                'ignored': bool(getattr(record, 'ignored', False)),
                'comment': str(getattr(record, 'packet_comment', '') or ''),
                'interface_id': interface_id,
                'has_interface_id': bool(has_interface_id),
            }

        def _register_interface(catalog, catalog_by_signature, interface_info):
            normalized = self._normalize_interface_info(interface_info)
            if normalized is None:
                return None
            signature = self._interface_signature(normalized)
            existing_id = catalog_by_signature.get(signature, None)
            if existing_id is not None:
                return int(existing_id)
            assigned_id = len(catalog)
            normalized['interface_id'] = int(assigned_id)
            catalog.append(normalized)
            catalog_by_signature[signature] = int(assigned_id)
            return int(assigned_id)

        derived_metadata = CaptureMetadata()
        runtime_state = {}
        interface_catalog = []
        interface_catalog_by_signature = {}
        if preserve_metadata:
            derived_metadata.file_comment = str(old_comments or '')
            derived_metadata.section_hardware = str(old_metadata.section_hardware or '')
            derived_metadata.section_os = str(old_metadata.section_os or '')
            derived_metadata.section_application = str(old_metadata.section_application or '')

        cv.stop_capture()
        cv._set_packet_panes_visible(False)
        cv._set_packet_panes_updates_enabled(False)
        try:
            cv.clear_packets(reset_file_path=True)
            if preserve_loaded_path:
                cv.loaded_file_path = old_loaded_path

            cv._configure_parser_capture_context(cv.parser, str(cv.loaded_file_path or ''))
            for idx, entry in enumerate(packet_entries, start=1):
                packet = entry.get('raw', None)
                if packet is None:
                    continue
                record = cv.parser.parse(packet, idx, cv.iface)
                source_record = entry.get('record')
                snapshot = dict(entry.get('snapshot') or {})
                if source_record is not None and not snapshot:
                    snapshot = _snapshot_from_record(source_record)
                interface_info = entry.get('interface_info', None)
                if interface_info is None and source_record is not None:
                    interface_info = self._interface_info_from_record(source_record, old_metadata)
                if snapshot:
                    record.marked = bool(snapshot.get('marked', False))
                    record.ignored = bool(snapshot.get('ignored', False))
                    if str(snapshot.get('comment', '') or '').strip():
                        record.packet_comment = str(snapshot.get('comment', '') or '')
                    runtime_state[int(idx)] = {
                        'marked': bool(record.marked),
                        'ignored': bool(record.ignored),
                        'comment': str(getattr(record, 'packet_comment', '') or ''),
                    }
                    if preserve_metadata and str(getattr(record, 'packet_comment', '') or '').strip():
                        derived_metadata.packet_comments[int(idx)] = str(getattr(record, 'packet_comment', '') or '')
                if preserve_metadata:
                    assigned_interface_id = _register_interface(interface_catalog, interface_catalog_by_signature, interface_info)
                    if assigned_interface_id is not None:
                        derived_metadata.packet_interfaces[int(idx)] = int(assigned_interface_id)
                cv.records.append(record)

            if preserve_metadata:
                derived_metadata.interfaces = list(interface_catalog)
                cv.capture_metadata = derived_metadata
                cv.capture_comments = old_comments
            else:
                cv.capture_metadata = None
                cv.capture_comments = ''

            cv._packet_state_by_number = dict(runtime_state)
            for idx, record in enumerate(cv.records, start=1):
                cv._apply_capture_metadata_to_record(record, idx)

            cv.display_filter_input.setText(old_filter)
            cv.apply_display_filter()
            if cv.visible_indices:
                cv.goto_first_packet()
            cv._set_dirty(bool(mark_dirty))
            cv._update_status(status_message)
        finally:
            cv._set_packet_panes_updates_enabled(True)
            cv._set_packet_panes_visible(True)

    def _packet_entry_from_record(self, record) -> dict:
        return {
            'raw': getattr(record, 'raw', None),
            'record': record,
            'interface_info': self._interface_info_from_record(record),
        }

    def _derive_output_metadata_for_records(self, records, include_file_comment: bool = True) -> CaptureMetadata:
        cv = self.capture_view
        source_meta = clone_capture_metadata(cv.capture_metadata if cv else None)
        derived = CaptureMetadata()
        if include_file_comment and cv is not None:
            derived.file_comment = str(getattr(cv, 'capture_comments', '') or '')
        derived.section_hardware = str(source_meta.section_hardware or '')
        derived.section_os = str(source_meta.section_os or '')
        derived.section_application = str(source_meta.section_application or '')
        interface_catalog = []
        interface_catalog_by_signature = {}
        for new_idx, record in enumerate(list(records or []), start=1):
            comment = str(getattr(record, 'packet_comment', '') or '').strip()
            if comment:
                derived.packet_comments[int(new_idx)] = comment
            interface_info = self._interface_info_from_record(record, source_meta)
            normalized = self._normalize_interface_info(interface_info)
            if normalized is None:
                continue
            signature = self._interface_signature(normalized)
            assigned_interface_id = interface_catalog_by_signature.get(signature, None)
            if assigned_interface_id is None:
                assigned_interface_id = len(interface_catalog)
                normalized['interface_id'] = int(assigned_interface_id)
                interface_catalog.append(normalized)
                interface_catalog_by_signature[signature] = int(assigned_interface_id)
            derived.packet_interfaces[int(new_idx)] = int(assigned_interface_id)
        derived.interfaces = list(interface_catalog)
        return derived

    def _normalize_interface_info(self, interface_info):
        if not isinstance(interface_info, dict):
            return None
        normalized = {
            'interface_id': 0,
            'name': str(interface_info.get('name', '') or '').strip(),
            'description': str(interface_info.get('description', '') or '').strip(),
            'comment': str(interface_info.get('comment', '') or '').strip(),
            'dropped_packets': str(interface_info.get('dropped_packets', '') or '').strip(),
            'capture_filter': str(interface_info.get('capture_filter', '') or '').strip(),
            'link_type': str(interface_info.get('link_type', '') or '').strip(),
            'snaplen': str(interface_info.get('snaplen', '') or '').strip(),
            'ipv4_addr': str(interface_info.get('ipv4_addr', '') or '').strip(),
            'ipv6_addr': str(interface_info.get('ipv6_addr', '') or '').strip(),
            'mac_addr': str(interface_info.get('mac_addr', '') or '').strip(),
            'speed': str(interface_info.get('speed', '') or '').strip(),
            'os': str(interface_info.get('os', '') or '').strip(),
            'hardware': str(interface_info.get('hardware', '') or '').strip(),
        }
        try:
            normalized['interface_id'] = int(interface_info.get('interface_id', 0) or 0)
        except Exception:
            normalized['interface_id'] = 0
        if not any(str(normalized.get(key, '') or '').strip() for key in normalized if key != 'interface_id'):
            return None
        return normalized

    def _interface_signature(self, interface_info) -> tuple:
        normalized = self._normalize_interface_info(interface_info)
        if normalized is None:
            return tuple()
        return (
            str(normalized.get('name', '') or '').strip().lower(),
            str(normalized.get('description', '') or '').strip().lower(),
            str(normalized.get('comment', '') or '').strip(),
            str(normalized.get('capture_filter', '') or '').strip(),
            str(normalized.get('link_type', '') or '').strip(),
            str(normalized.get('snaplen', '') or '').strip(),
            str(normalized.get('ipv4_addr', '') or '').strip(),
            str(normalized.get('ipv6_addr', '') or '').strip(),
            str(normalized.get('mac_addr', '') or '').strip(),
            str(normalized.get('speed', '') or '').strip(),
            str(normalized.get('os', '') or '').strip(),
            str(normalized.get('hardware', '') or '').strip(),
        )

    def _interface_info_from_record(self, record, metadata: CaptureMetadata | None = None):
        if record is None:
            return None
        source_metadata = metadata
        if source_metadata is None and self.capture_view is not None:
            source_metadata = self.capture_view.capture_metadata
        interfaces = list(getattr(source_metadata, 'interfaces', []) or [])
        record_meta = getattr(record, 'metadata', {}) or {}
        interface_name = str(record_meta.get('frame_interface_name', '') or getattr(record, 'iface', '') or '').strip()
        interface_description = str(record_meta.get('frame_interface_description', '') or '').strip()
        interface_id = record_meta.get('frame_interface_id', getattr(record, 'interface_id', None))
        try:
            interface_id = None if interface_id is None else int(interface_id)
        except Exception:
            interface_id = None

        matched = None
        if interface_id is not None:
            for interface in interfaces:
                try:
                    raw_interface_id = interface.get('interface_id', -1)
                    parsed_interface_id = -1 if raw_interface_id is None else int(raw_interface_id)
                    if parsed_interface_id == int(interface_id):
                        matched = interface
                        break
                except Exception:
                    continue
        if matched is None and interface_name:
            name_lower = interface_name.lower()
            desc_lower = interface_description.lower()
            for interface in interfaces:
                iface_name = str(interface.get('name', '') or '').strip().lower()
                iface_desc = str(interface.get('description', '') or '').strip().lower()
                if name_lower and name_lower in {iface_name, iface_desc}:
                    matched = interface
                    break
                if desc_lower and desc_lower in {iface_name, iface_desc}:
                    matched = interface
                    break
        if matched is not None:
            return self._normalize_interface_info(dict(matched))
        fallback = {
            'interface_id': int(interface_id or 0) if interface_id is not None else 0,
            'name': interface_name,
            'description': interface_description,
        }
        return self._normalize_interface_info(fallback)

    def _render_flow_behavior_text(self, result: dict) -> str:
        flow_count = int(result.get("flow_count", 0) or 0)
        lines = [f"Da trich xuat {flow_count} flows."]
        lines.append(f"Model status: {str(result.get('model_status', 'ok') or 'ok')}")
        summaries = list(result.get("summaries", []) or [])
        if not summaries:
            lines.append("Khong co flow de phan tich hanh vi.")
            return "\n".join(lines)
        lines.append("")
        lines.append("Tom tat hanh vi:")
        for item in summaries[:30]:
            src = item.get("src_ip", "-")
            dst = item.get("dst_ip", "-")
            proto = item.get("protocol", "-")
            sev = item.get("severity", "normal")
            summary = item.get("summary", "")
            lines.append(f"- [{sev}] {src} -> {dst} ({proto}): {summary}")
        if len(summaries) > 30:
            lines.append(f"... va {len(summaries) - 30} flows khac.")
        model_counts = Counter()
        for item in summaries:
            pred = item.get("model_prediction")
            if pred:
                model_counts[str(pred)] += 1
        if model_counts:
            lines.append("")
            lines.append("Phan bo nhan model:")
            for label, cnt in model_counts.most_common(10):
                lines.append(f"- {label}: {cnt} flow(s)")
        return "\n".join(lines)

    def _build_flow_model_adapter(self):
        model_path = self.AI_MODEL_DIR / self.AI_MODEL_FILE
        scaler_path = self.AI_MODEL_DIR / self.AI_SCALER_FILE
        encoder_path = self.AI_MODEL_DIR / self.AI_LABEL_ENCODER_FILE
        model_info_path = self.AI_MODEL_DIR / self.AI_MODEL_INFO_FILE
        return PacketraModelAdapter(
            model_path=str(model_path),
            label_encoder_path=str(encoder_path),
            scaler_path=str(scaler_path),
            model_info_path=str(model_info_path),
            feature_order=self._ai_model_feature_order(),
            fallback_labels=[],
        )

    def _ai_model_feature_order(self) -> list[str]:
        meta = {'Flow ID', 'Source IP', 'Source Port', 'Destination IP', 'Protocol', 'Timestamp', 'Label'}
        return [str(col) for col in self.AI_TRAFFIC_COLUMNS if str(col) not in meta]

    def _on_export_flow_csv_current(self):
        if not self.capture_view or not getattr(self.capture_view, "records", None):
            QMessageBox.information(self, "Export Flow CSV", "Khong co du lieu capture de export.")
            return
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Flow CSV (Current Capture)",
            str(Path.cwd() / f"flow_features_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"),
            "CSV Files (*.csv)",
        )
        if not file_path:
            return
        if not file_path.lower().endswith(".csv"):
            file_path += ".csv"
        try:
            packets = [
                r.raw
                for r in self.capture_view.get_effective_records(include_ignored=False)
                if getattr(r, "raw", None) is not None
            ]
            if not packets:
                QMessageBox.information(self, "Export Flow CSV", "Khong co packet hop le (cac packet co the da ignored).")
                return
            csv_path, flows = export_packets_to_csv(packets, file_path)
            model_adapter = self._build_flow_model_adapter()
            behavior = analyze_flows(flows, use_model=model_adapter.loaded, model_adapter=model_adapter)
            QMessageBox.information(
                self,
                "Export Flow CSV",
                f"Export thanh cong:\n{csv_path}\n\n{self._render_flow_behavior_text(behavior)}",
            )
        except Exception as exc:
            QMessageBox.critical(self, "Export Flow CSV", f"Export that bai: {exc}")

    def _on_export_flow_csv_selected(self):
        if not self.capture_view:
            QMessageBox.information(self, "Export Selected Flow CSV", "Khong co du lieu capture.")
            return
        selected_packets = []
        for record in self.capture_view.get_selected_records():
            if bool(getattr(record, "ignored", False)):
                continue
            raw = getattr(record, "raw", None)
            if raw is not None:
                selected_packets.append(raw)
        if not selected_packets:
            QMessageBox.warning(self, "Export Selected Flow CSV", "Khong co packet hop le de export (co the da ignored).")
            return
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Export Selected Packets to Flow CSV",
            str(Path.cwd() / f"selected_flow_features_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"),
            "CSV Files (*.csv)",
        )
        if not file_path:
            return
        if not file_path.lower().endswith(".csv"):
            file_path += ".csv"
        try:
            csv_path, flows = export_packets_to_csv(selected_packets, file_path)
            model_adapter = self._build_flow_model_adapter()
            behavior = analyze_flows(flows, use_model=model_adapter.loaded, model_adapter=model_adapter)
            warning = (
                "Cac packet duoc chon co the chua du toan bo flow, feature chi phan anh phan luu luong da chon.\n\n"
            )
            QMessageBox.information(
                self,
                "Export Selected Flow CSV",
                f"{warning}Export thanh cong:\n{csv_path}\n\n{self._render_flow_behavior_text(behavior)}",
            )
        except Exception as exc:
            QMessageBox.critical(self, "Export Selected Flow CSV", f"Export that bai: {exc}")

    def _on_search(self):
        """TĂ¬m kiáº¿m"""
        if self.capture_view:
            self.capture_view.toggle_find_panel()

    def _on_copy(self):
        widget = QApplication.focusWidget()
        cv = self.capture_view
        if cv and widget is not None:
            if widget is cv.details_tree or cv.details_tree.isAncestorOf(widget):
                selected_items = cv.details_tree.selectedItems()
                if selected_items:
                    QApplication.clipboard().setText(str(selected_items[0].text(0)))
                    return
                lines = []
                root = cv.details_tree.invisibleRootItem()
                def _walk(item, level=0):
                    lines.append(('  ' * level) + item.text(0))
                    for i in range(item.childCount()):
                        _walk(item.child(i), level + 1)
                for i in range(root.childCount()):
                    _walk(root.child(i), 0)
                if lines:
                    QApplication.clipboard().setText('\n'.join(lines))
                    return

            if widget is cv.hex_view or cv.hex_view.isAncestorOf(widget):
                if cv.hex_view.copy_selected_bytes_to_clipboard():
                    return
                if cv.hex_view.copy_visible_bytes_to_clipboard():
                    return

        if widget is not None and hasattr(widget, 'copy'):
            try:
                widget.copy()
                return
            except Exception:
                pass
        if cv:
            table = cv.table
            selected_rows = []
            if table.selectionModel():
                selected_rows = sorted({index.row() for index in table.selectionModel().selectedRows()})
            if selected_rows:
                lines = []
                header_values = []
                header = table.horizontalHeader()
                for visual_idx in range(table.columnCount()):
                    logical = header.logicalIndex(visual_idx)
                    if table.isColumnHidden(logical):
                        continue
                    header_item = table.horizontalHeaderItem(logical)
                    header_values.append(str(header_item.text() if header_item is not None else ''))
                if header_values:
                    lines.append('\t'.join(header_values))
                for row in selected_rows:
                    values = []
                    for visual_idx in range(table.columnCount()):
                        logical = header.logicalIndex(visual_idx)
                        if table.isColumnHidden(logical):
                            continue
                        item = table.item(row, logical)
                        values.append(str(item.text() if item is not None else ''))
                    lines.append('\t'.join(values))
                QApplication.clipboard().setText('\n'.join(lines))
                return
        QMessageBox.information(self, 'Copy', 'Khong co du lieu de sao chep.')

    def _require_capture_for_edit_action(self) -> bool:
        if self.capture_view and self.stacked_widget.currentWidget() is self.capture_view and self.capture_view.has_packets():
            return True
        QMessageBox.information(self, 'Edit', 'Khong co du lieu packet de thuc hien thao tac.')
        return False

    def _on_find_next(self):
        if not self.capture_view:
            return
        if not self.capture_view.find_input.text().strip():
            if not self.capture_view.find_widget.isVisible():
                self.capture_view.toggle_find_panel()
            self.capture_view.find_input.setFocus()
            self.capture_view.find_input.selectAll()
            QMessageBox.information(self, 'Find Next', 'Hay nhap noi dung tim kiem truoc.')
            return
        self.capture_view.find_next()

    def _on_find_previous(self):
        if not self.capture_view:
            return
        if not self.capture_view.find_input.text().strip():
            if not self.capture_view.find_widget.isVisible():
                self.capture_view.toggle_find_panel()
            self.capture_view.find_input.setFocus()
            self.capture_view.find_input.selectAll()
            QMessageBox.information(self, 'Find Previous', 'Hay nhap noi dung tim kiem truoc.')
            return
        self.capture_view.find_previous()

    def _on_mark_unmark_selected(self):
        if not self._require_capture_for_edit_action():
            return
        if not self.capture_view.toggle_mark_selected():
            QMessageBox.information(self, 'Mark/Unmark Selected', 'Hay chon it nhat mot packet.')
            return
        self._update_capture_window_title()

    def _on_mark_unmark_all_displayed(self):
        if not self._require_capture_for_edit_action():
            return
        if not self.capture_view.visible_indices:
            QMessageBox.information(self, 'Mark/Unmark All Displayed', 'Khong co packet hien thi.')
            return
        if not self.capture_view.toggle_mark_all_displayed():
            QMessageBox.information(self, 'Mark/Unmark All Displayed', 'Khong thay doi du lieu.')
            return
        self._update_capture_window_title()

    def _on_next_mark(self):
        if not self._require_capture_for_edit_action():
            return
        if not self.capture_view.goto_next_mark():
            QMessageBox.information(self, 'Next Mark', 'Khong tim thay packet da danh dau tiep theo.')

    def _on_previous_mark(self):
        if not self._require_capture_for_edit_action():
            return
        if not self.capture_view.goto_previous_mark():
            QMessageBox.information(self, 'Previous Mark', 'Khong tim thay packet da danh dau truoc do.')

    def _on_ignore_unignore_selected(self):
        if not self._require_capture_for_edit_action():
            return
        if not self.capture_view.toggle_ignore_selected():
            QMessageBox.information(self, 'Ignore/Unignore Selected', 'Hay chon it nhat mot packet.')
            return
        self._update_capture_window_title()

    def _on_ignore_unignore_all_displayed(self):
        if not self._require_capture_for_edit_action():
            return
        if not self.capture_view.visible_indices:
            QMessageBox.information(self, 'Ignore/Unignore All Displayed', 'Khong co packet hien thi.')
            return
        if not self.capture_view.toggle_ignore_all_displayed():
            QMessageBox.information(self, 'Ignore/Unignore All Displayed', 'Khong thay doi du lieu.')
            return
        self._update_capture_window_title()

    def _on_packet_comment(self):
        if not self._require_capture_for_edit_action():
            return
        current_comment = self.capture_view.get_selected_packet_comment()
        text, ok = QInputDialog.getMultiLineText(
            self,
            'Packet Comment',
            'Nhap ghi chu cho packet dang chon:',
            current_comment,
        )
        if not ok:
            return
        if not self.capture_view.set_comment_for_selected(text):
            QMessageBox.information(self, 'Packet Comment', 'Hay chon packet can ghi chu.')
            return
        current_path = str(getattr(self.capture_view, 'loaded_file_path', '') or '').strip()
        if current_path and current_path.lower().endswith('.pcap'):
            reply = QMessageBox.question(
                self,
                'Packet Comment',
                'File hien tai la .pcap. Packet comment can dinh dang .pcapng de luu ben vung.\nBan co muon luu moi sang .pcapng ngay bay gio khong?',
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.Yes,
            )
            if reply == QMessageBox.Yes:
                suggested = os.path.splitext(current_path)[0] + '.pcapng'
                target_path, _ = QFileDialog.getSaveFileName(
                    self,
                    'Save As PCAPNG',
                    suggested,
                    'PCAPNG Files (*.pcapng)',
                )
                if target_path:
                    if not target_path.lower().endswith('.pcapng'):
                        target_path += '.pcapng'
                    if not self.capture_view.save_as_pcapng(target_path):
                        QMessageBox.warning(self, 'Packet Comment', 'Khong the luu sang file pcapng.')
                        self._update_capture_window_title()
                        return
                else:
                    self._update_capture_window_title()
                    return

        persisted = self.capture_view.save_packet_comments_to_file()
        if not persisted:
            QMessageBox.information(self, 'Packet Comment', 'Packet comment da cap nhat trong bo nho. Hay luu file pcapng de ghi ben vung.')
        self._update_capture_window_title()

    def _on_delete_all_packet_comments(self):
        if not self._require_capture_for_edit_action():
            return
        reply = QMessageBox.question(
            self,
            'Delete All Packet Comments',
            'Ban co chac muon xoa toan bo ghi chu packet?',
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if reply != QMessageBox.Yes:
            return
        count = int(self.capture_view.delete_all_packet_comments() or 0)
        if count <= 0:
            QMessageBox.information(self, 'Delete All Packet Comments', 'Khong co ghi chu nao de xoa.')
            return
        self.capture_view.save_packet_comments_to_file()
        self._update_capture_window_title()
        QMessageBox.information(self, 'Delete All Packet Comments', f'Da xoa {count} ghi chu packet.')

    def _default_edit_preferences(self) -> dict:
        default_columns = [
            {'index': 0, 'displayed': True, 'title': 'No.', 'field': 'frame.number', 'occurrence': 1, 'alignment': 'Right'},
            {'index': 1, 'displayed': True, 'title': 'Time', 'field': 'frame.time_relative', 'occurrence': 1, 'alignment': 'Right'},
            {'index': 2, 'displayed': True, 'title': 'Source', 'field': 'ip.src', 'occurrence': 1, 'alignment': 'Right'},
            {'index': 3, 'displayed': True, 'title': 'Destination', 'field': 'ip.dst', 'occurrence': 1, 'alignment': 'Right'},
            {'index': 4, 'displayed': True, 'title': 'Protocol', 'field': '_ws.col.protocol', 'occurrence': 1, 'alignment': 'Right'},
            {'index': 5, 'displayed': True, 'title': 'Length', 'field': 'frame.len', 'occurrence': 1, 'alignment': 'Right'},
            {'index': 6, 'displayed': True, 'title': 'Info', 'field': '_ws.col.info', 'occurrence': 1, 'alignment': 'Right'},
        ]
        return {
            'appearance': {
                'remember_main_window_size_and_placement': True,
                'open_files_mode': 'recent_folder',
                'open_files_fixed_directory': '',
                'show_up_to_filter_entries': 10,
                'show_up_to_recent_files': 10,
                'confirm_unsaved_capture_files': True,
                'display_filter_autocomplete': True,
            },
            'columns': default_columns,
            'font_and_colors': {
                'packet_list_font': '',
                'packet_details_font': '',
                'packet_bytes_font': '',
                'marked_packet_color': '#fff3b0',
                'ignored_packet_color': '#e0e0e0',
                'search_highlight_color': '#ffcc00',
            },
            'layout': {
                'pane_layout': 'Layout 2',
                'show_packet_list_separator': False,
                'pane_1': 'packet_list',
                'pane_2': 'packet_details',
                'pane_3': 'packet_bytes',
            },
            'capture': {
                'default_interface': '',
                'promiscuous_mode': True,
                'capture_format_pcapng': True,
                'realtime_update': True,
                'update_interval_ms': 1000,
            },
            'expert_items': [],
            'name_resolution': {
                'resolve_mac_addresses': True,
                'resolve_transport_names': False,
                'resolve_network_ip_addresses': False,
                'use_captured_dns_packet_data': True,
            },
        }

    def _load_edit_preferences(self) -> dict:
        defaults = self._default_edit_preferences()
        settings = QSettings('Packetra', 'Packetra')
        raw = settings.value('preferences/edit_payload', '', str)
        if not raw:
            return defaults
        try:
            loaded = json.loads(raw)
        except Exception:
            return defaults
        if not isinstance(loaded, dict):
            return defaults
        merged = defaults
        for key, value in loaded.items():
            if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
                merged[key].update(value)
            else:
                merged[key] = value
        if not isinstance(merged.get('columns'), list):
            merged['columns'] = defaults['columns']
        appearance = merged.get('appearance', {}) if isinstance(merged.get('appearance'), dict) else {}
        legacy_open = str(appearance.get('open_files_in', '') or '').strip()
        if legacy_open and 'open_files_mode' not in appearance:
            appearance['open_files_mode'] = 'recent_folder' if legacy_open == 'last_used_directory' else 'fixed_folder'
        legacy_show = appearance.get('show_up_to', None)
        if legacy_show is not None:
            try:
                value = int(legacy_show)
            except Exception:
                value = 10
            appearance.setdefault('show_up_to_filter_entries', value)
            appearance.setdefault('show_up_to_recent_files', value)
        appearance.setdefault('remember_main_window_size_and_placement', True)
        appearance.setdefault('open_files_mode', 'recent_folder')
        appearance.setdefault('open_files_fixed_directory', '')
        appearance.setdefault('show_up_to_filter_entries', 10)
        appearance.setdefault('show_up_to_recent_files', 10)
        merged['appearance'] = appearance
        layout_cfg = merged.get('layout', {}) if isinstance(merged.get('layout'), dict) else {}
        legacy_layout = str(layout_cfg.get('pane_layout', 'Layout 2') or 'Layout 2').strip()
        layout_cfg['pane_layout'] = {
            'Layout A': 'Layout 2',
            'Layout B': 'Layout 3',
            'Layout C': 'Layout 6',
        }.get(legacy_layout, legacy_layout if legacy_layout else 'Layout 2')
        layout_cfg.setdefault('show_packet_list_separator', False)
        layout_cfg.setdefault('pane_1', 'packet_list')
        layout_cfg.setdefault('pane_2', 'packet_details')
        layout_cfg.setdefault('pane_3', 'packet_bytes')
        merged['layout'] = layout_cfg
        return merged

    def _save_edit_preferences(self, prefs: dict):
        settings = QSettings('Packetra', 'Packetra')
        settings.setValue('preferences/edit_payload', json.dumps(prefs, ensure_ascii=False))

    def _apply_column_preferences_to_capture_view(self, prefs: dict):
        if not self.capture_view:
            return
        table = self.capture_view.table
        columns = list(prefs.get('columns', []) or [])
        if not columns:
            return

        table.setColumnCount(max(7, len(columns)))
        max_columns = len(columns)

        alignment_map = {
            'Left': Qt.AlignVCenter | Qt.AlignLeft,
            'Center': Qt.AlignVCenter | Qt.AlignHCenter,
            'Right': Qt.AlignVCenter | Qt.AlignRight,
        }

        for visual_idx in range(max_columns):
            spec = columns[visual_idx] if isinstance(columns[visual_idx], dict) else {}
            logical = visual_idx
            if logical < 0 or logical >= table.columnCount():
                continue
            title = str(spec.get('title', '') or '').strip() or str(table.horizontalHeaderItem(logical).text() if table.horizontalHeaderItem(logical) else '')
            displayed = bool(spec.get('displayed', True))
            alignment = alignment_map.get(str(spec.get('alignment', 'Left')), Qt.AlignVCenter | Qt.AlignLeft)
            header_item = table.horizontalHeaderItem(logical)
            if header_item is None:
                header_item = QTableWidgetItem(title)
                table.setHorizontalHeaderItem(logical, header_item)
            else:
                header_item.setText(title)
            table.setColumnHidden(logical, not displayed)
            if hasattr(table, 'set_column_text_alignment'):
                table.set_column_text_alignment(logical, alignment)
            for row in range(table.rowCount()):
                item = table.item(row, logical)
                if item is not None:
                    item.setTextAlignment(alignment)

    def _apply_edit_preferences(self, prefs: dict):
        settings = QSettings('Packetra', 'Packetra')

        appearance = prefs.get('appearance', {}) or {}
        settings.setValue('preferences/remember_main_window_size_and_placement', bool(appearance.get('remember_main_window_size_and_placement', True)))
        settings.setValue('preferences/open_files_mode', str(appearance.get('open_files_mode', 'recent_folder')))
        settings.setValue('preferences/open_files_fixed_directory', str(appearance.get('open_files_fixed_directory', '') or ''))
        settings.setValue('preferences/show_up_to_filter_entries', int(appearance.get('show_up_to_filter_entries', 10) or 10))
        settings.setValue('preferences/show_up_to_recent_files', int(appearance.get('show_up_to_recent_files', 10) or 10))
        settings.setValue('preferences/confirm_unsaved_capture_files', bool(appearance.get('confirm_unsaved_capture_files', True)))
        settings.setValue('preferences/display_filter_autocomplete', bool(appearance.get('display_filter_autocomplete', True)))

        capture = prefs.get('capture', {}) or {}
        settings.setValue('capture/default_interface', str(capture.get('default_interface', '') or ''))
        settings.setValue('capture/promiscuous_mode', bool(capture.get('promiscuous_mode', True)))
        settings.setValue('output/format', 'pcapng' if bool(capture.get('capture_format_pcapng', True)) else 'pcap')
        settings.setValue('options/realtime', bool(capture.get('realtime_update', True)))
        settings.setValue('capture/update_interval_ms', int(capture.get('update_interval_ms', 1000) or 1000))

        name_resolution = prefs.get('name_resolution', {}) or {}
        settings.setValue('options/resolve_mac', bool(name_resolution.get('resolve_mac_addresses', True)))
        settings.setValue('options/resolve_transport', bool(name_resolution.get('resolve_transport_names', False)))
        settings.setValue('options/resolve_network', bool(name_resolution.get('resolve_network_ip_addresses', False)))
        settings.setValue('preferences/use_captured_dns_packet_data', bool(name_resolution.get('use_captured_dns_packet_data', True)))

        settings.setValue('preferences/expert_items', json.dumps(prefs.get('expert_items', []), ensure_ascii=False))
        if not bool(appearance.get('remember_main_window_size_and_placement', True)):
            settings.remove('preferences/main_window_geometry')

        self._apply_column_preferences_to_capture_view(prefs)

        if self.capture_view:
            font_cfg = prefs.get('font_and_colors', {}) or {}
            list_font_text = str(font_cfg.get('packet_list_font', '') or '').strip()
            details_font_text = str(font_cfg.get('packet_details_font', '') or '').strip()
            bytes_font_text = str(font_cfg.get('packet_bytes_font', '') or '').strip()

            list_font = QFont()
            details_font = QFont()
            bytes_font = QFont()
            if list_font_text:
                list_font.fromString(list_font_text)
                self.capture_view.table.setFont(list_font)
            if details_font_text:
                details_font.fromString(details_font_text)
                self.capture_view.details_tree.setFont(details_font)
            if bytes_font_text:
                bytes_font.fromString(bytes_font_text)
                self.capture_view.hex_view.setFont(bytes_font)
            if hasattr(self.capture_view.table, 'sync_row_height_to_font'):
                self.capture_view.table.sync_row_height_to_font()

            marked_hex = str(font_cfg.get('marked_packet_color', '#fff3b0') or '#fff3b0')
            ignored_hex = str(font_cfg.get('ignored_packet_color', '#e0e0e0') or '#e0e0e0')
            self.capture_view.table.set_marked_color(QColor(marked_hex))
            self.capture_view.table.set_ignored_color(QColor(ignored_hex))
            self.capture_view._refresh_all_visible_row_styles()

            layout_cfg = prefs.get('layout', {}) or {}
            show_separator = bool(layout_cfg.get('show_packet_list_separator', False))
            self.capture_view.table.setShowGrid(show_separator)
            if hasattr(self.capture_view, 'set_pane_assignments'):
                self.capture_view.set_pane_assignments([
                    str(layout_cfg.get('pane_1', 'packet_list') or 'packet_list'),
                    str(layout_cfg.get('pane_2', 'packet_details') or 'packet_details'),
                    str(layout_cfg.get('pane_3', 'packet_bytes') or 'packet_bytes'),
                ])
            if hasattr(self.capture_view, 'apply_pane_layout'):
                self.capture_view.apply_pane_layout(str(layout_cfg.get('pane_layout', 'Layout 2') or 'Layout 2'))

            if 'realtime_update' in capture:
                self.capture_view.realtime_update_enabled = bool(capture.get('realtime_update', True))
            current_output = dict(getattr(self.capture_view, 'output_settings', {}) or {})
            current_output['format'] = 'pcapng' if bool(capture.get('capture_format_pcapng', True)) else 'pcap'
            self.capture_view.set_output_settings(current_output)

            current_options = dict(getattr(self.capture_view, 'options_settings', {}) or {})
            current_options['realtime'] = bool(capture.get('realtime_update', True))
            current_options['resolve_mac'] = bool(name_resolution.get('resolve_mac_addresses', True))
            current_options['resolve_transport'] = bool(name_resolution.get('resolve_transport_names', False))
            current_options['resolve_network'] = bool(name_resolution.get('resolve_network_ip_addresses', False))
            self.capture_view.set_options_settings(current_options)
            if hasattr(self.capture_view, 'refresh_preferences_from_settings'):
                self.capture_view.refresh_preferences_from_settings()
            self._analyze_custom_columns = self._load_analyze_custom_columns()
            self._ensure_analyze_custom_columns_applied()
        if self.iface_selector_view and hasattr(self.iface_selector_view, 'refresh_recent_files'):
            self.iface_selector_view.refresh_recent_files()

    def _on_preferences(self):
        prefs = self._load_edit_preferences()
        defaults = self._default_edit_preferences()

        dialog = QDialog(self)
        dialog.setWindowTitle('Preferences')
        app = QApplication.instance()
        if app is not None and app.primaryScreen() is not None:
            geometry = app.primaryScreen().availableGeometry()
            dialog.resize(int(geometry.width() * 0.6), int(geometry.height() * 0.6))

        root = QVBoxLayout(dialog)
        content_layout = QHBoxLayout()
        root.addLayout(content_layout, 1)

        nav_list = QListWidget(dialog)
        nav_list.setFixedWidth(220)
        page_stack = QStackedWidget(dialog)
        content_layout.addWidget(nav_list)
        content_layout.addWidget(page_stack, 1)

        page_keys = [
            ('appearance', 'Appearance'),
            ('columns', 'Columns'),
            ('font_and_colors', 'Font and Colors'),
            ('layout', 'Layout'),
            ('capture', 'Capture'),
            ('expert_items', 'Expert Items'),
            ('name_resolution', 'Name Resolution'),
        ]
        for _key, title in page_keys:
            nav_list.addItem(title)

        # --- Appearance ---
        appearance_page = QWidget(dialog)
        appearance_layout = QGridLayout(appearance_page)
        appearance_cfg = prefs.get('appearance', {}) or {}

        remember_window_cb = QCheckBox('Remember main window size and placement', appearance_page)
        remember_window_cb.setChecked(bool(appearance_cfg.get('remember_main_window_size_and_placement', True)))
        appearance_layout.addWidget(remember_window_cb, 0, 0, 1, 3)

        appearance_layout.addWidget(QLabel('Open files in:'), 1, 0, 1, 3)
        open_recent_radio = QRadioButton('The most recently used folder', appearance_page)
        open_fixed_radio = QRadioButton('This folder:', appearance_page)
        open_mode_group = QButtonGroup(appearance_page)
        open_mode_group.addButton(open_recent_radio)
        open_mode_group.addButton(open_fixed_radio)
        open_mode = str(appearance_cfg.get('open_files_mode', 'recent_folder') or 'recent_folder')
        open_recent_radio.setChecked(open_mode == 'recent_folder')
        open_fixed_radio.setChecked(open_mode == 'fixed_folder')
        fixed_directory_input = QLineEdit(str(appearance_cfg.get('open_files_fixed_directory', '') or ''), appearance_page)
        browse_fixed_dir_btn = QPushButton('Browse...', appearance_page)
        appearance_layout.addWidget(open_recent_radio, 2, 0, 1, 3)
        appearance_layout.addWidget(open_fixed_radio, 3, 0, 1, 1)
        appearance_layout.addWidget(fixed_directory_input, 3, 1, 1, 1)
        appearance_layout.addWidget(browse_fixed_dir_btn, 3, 2, 1, 1)

        appearance_layout.addWidget(QLabel('Show up to'), 4, 0)
        show_filter_entries_spin = QSpinBox(appearance_page)
        show_filter_entries_spin.setRange(1, 100)
        show_filter_entries_spin.setValue(int(appearance_cfg.get('show_up_to_filter_entries', 10) or 10))
        appearance_layout.addWidget(show_filter_entries_spin, 4, 1)
        appearance_layout.addWidget(QLabel('filter entries'), 4, 2)

        show_recent_files_spin = QSpinBox(appearance_page)
        show_recent_files_spin.setRange(1, 100)
        show_recent_files_spin.setValue(int(appearance_cfg.get('show_up_to_recent_files', 10) or 10))
        appearance_layout.addWidget(show_recent_files_spin, 5, 1)
        appearance_layout.addWidget(QLabel('recent files'), 5, 2)

        confirm_unsaved_cb = QCheckBox('Confirm unsaved capture files', appearance_page)
        confirm_unsaved_cb.setChecked(bool(appearance_cfg.get('confirm_unsaved_capture_files', True)))
        appearance_layout.addWidget(confirm_unsaved_cb, 6, 0, 1, 3)
        autocomplete_cb = QCheckBox('Display autocompletion for filter text', appearance_page)
        autocomplete_cb.setChecked(bool(appearance_cfg.get('display_filter_autocomplete', True)))
        appearance_layout.addWidget(autocomplete_cb, 7, 0, 1, 3)
        appearance_layout.setRowStretch(8, 1)

        def _sync_open_mode_widgets():
            use_fixed = open_fixed_radio.isChecked()
            fixed_directory_input.setEnabled(use_fixed)
            browse_fixed_dir_btn.setEnabled(use_fixed)

        def _browse_fixed_directory():
            selected = QFileDialog.getExistingDirectory(
                dialog,
                'Select default folder',
                fixed_directory_input.text().strip() or str(Path.cwd()),
            )
            if selected:
                fixed_directory_input.setText(selected)
                open_fixed_radio.setChecked(True)
                _sync_open_mode_widgets()

        open_recent_radio.toggled.connect(_sync_open_mode_widgets)
        open_fixed_radio.toggled.connect(_sync_open_mode_widgets)
        browse_fixed_dir_btn.clicked.connect(_browse_fixed_directory)
        _sync_open_mode_widgets()

        # --- Columns ---
        columns_page = QWidget(dialog)
        columns_layout = QVBoxLayout(columns_page)
        show_displayed_only_cb = QCheckBox('Show displayed columns only', columns_page)
        show_displayed_only_cb.setChecked(False)
        columns_layout.addWidget(show_displayed_only_cb)

        columns_table = QTableWidget(columns_page)
        columns_table.setColumnCount(5)
        columns_table.setHorizontalHeaderLabels(['Displayed', 'Title', 'Fields', 'Field Occurrence', 'Alignment'])
        columns_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        columns_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        columns_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        columns_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        columns_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        columns_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        columns_layout.addWidget(columns_table, 1)

        col_btn_row = QHBoxLayout()
        col_add_btn = QPushButton('Add column', columns_page)
        col_remove_btn = QPushButton('Remove column', columns_page)
        col_up_btn = QPushButton('Move up', columns_page)
        col_down_btn = QPushButton('Move down', columns_page)
        col_btn_row.addWidget(col_add_btn)
        col_btn_row.addWidget(col_remove_btn)
        col_btn_row.addWidget(col_up_btn)
        col_btn_row.addWidget(col_down_btn)
        col_btn_row.addStretch()
        columns_layout.addLayout(col_btn_row)

        def _normalize_alignment(value: str) -> str:
            text = str(value or '').strip().lower()
            if text == 'right':
                return 'Right'
            if text == 'center':
                return 'Center'
            return 'Left'

        def _set_column_row(row: int, spec: dict):
            logical_index = int(spec.get('index', row) or row)
            displayed = bool(spec.get('displayed', True))
            title = str(spec.get('title', '') or '').strip()
            field = str(spec.get('field', '') or '').strip()
            try:
                occurrence = max(1, int(spec.get('occurrence', 1) or 1))
            except Exception:
                occurrence = 1
            alignment = _normalize_alignment(str(spec.get('alignment', 'Left') or 'Left'))

            displayed_item = QTableWidgetItem('')
            displayed_item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable | Qt.ItemIsUserCheckable)
            displayed_item.setCheckState(Qt.Checked if displayed else Qt.Unchecked)
            displayed_item.setData(Qt.UserRole, logical_index)
            columns_table.setItem(row, 0, displayed_item)
            columns_table.setItem(row, 1, QTableWidgetItem(title))
            columns_table.setItem(row, 2, QTableWidgetItem(field))
            columns_table.setItem(row, 3, QTableWidgetItem(str(occurrence)))
            align_combo = QComboBox(columns_table)
            align_combo.addItems(['Left', 'Center', 'Right'])
            align_combo.setCurrentText(alignment)
            columns_table.setCellWidget(row, 4, align_combo)

        def _read_column_row(row: int) -> dict:
            displayed_item = columns_table.item(row, 0)
            title_item = columns_table.item(row, 1)
            field_item = columns_table.item(row, 2)
            occurrence_item = columns_table.item(row, 3)
            alignment_combo = columns_table.cellWidget(row, 4)
            try:
                occurrence = max(1, int(str(occurrence_item.text() if occurrence_item else '1').strip() or '1'))
            except Exception:
                occurrence = 1
            return {
                'index': row,
                'displayed': bool(displayed_item.checkState() == Qt.Checked) if displayed_item is not None else True,
                'title': str(title_item.text() if title_item is not None else '').strip(),
                'field': str(field_item.text() if field_item is not None else '').strip(),
                'occurrence': occurrence,
                'alignment': _normalize_alignment(str(alignment_combo.currentText() if isinstance(alignment_combo, QComboBox) else 'Left')),
            }

        def _load_columns_rows(specs: list[dict]):
            columns_table.blockSignals(True)
            columns_table.setRowCount(0)
            for row, spec in enumerate(specs):
                columns_table.insertRow(row)
                _set_column_row(row, spec if isinstance(spec, dict) else {})
            columns_table.blockSignals(False)
            _toggle_columns_filter_rows()

        def _toggle_columns_filter_rows():
            only_displayed = bool(show_displayed_only_cb.isChecked())
            for row in range(columns_table.rowCount()):
                displayed_item = columns_table.item(row, 0)
                is_displayed = bool(displayed_item and displayed_item.checkState() == Qt.Checked)
                columns_table.setRowHidden(row, only_displayed and not is_displayed)

        def _move_column_row(delta: int):
            row = columns_table.currentRow()
            if row < 0:
                return
            target = row + delta
            if target < 0 or target >= columns_table.rowCount():
                return
            current = _read_column_row(row)
            other = _read_column_row(target)
            columns_table.blockSignals(True)
            _set_column_row(row, other)
            _set_column_row(target, current)
            columns_table.blockSignals(False)
            columns_table.setCurrentCell(target, 1)
            _toggle_columns_filter_rows()

        def _add_column_row():
            row = columns_table.rowCount()
            columns_table.insertRow(row)
            _set_column_row(
                row,
                {
                    'index': row,
                    'displayed': True,
                    'title': f'New Column {row + 1}',
                    'field': 'frame.number',
                    'occurrence': 1,
                    'alignment': 'Left',
                },
            )
            columns_table.setCurrentCell(row, 1)
            _toggle_columns_filter_rows()

        def _remove_column_row():
            row = columns_table.currentRow()
            if row < 0:
                return
            if columns_table.rowCount() <= 1:
                QMessageBox.warning(dialog, 'Columns', 'Phai giu it nhat 1 cot.')
                return
            columns_table.removeRow(row)
            _toggle_columns_filter_rows()

        col_add_btn.clicked.connect(_add_column_row)
        col_remove_btn.clicked.connect(_remove_column_row)
        col_up_btn.clicked.connect(lambda: _move_column_row(-1))
        col_down_btn.clicked.connect(lambda: _move_column_row(1))
        show_displayed_only_cb.toggled.connect(_toggle_columns_filter_rows)

        _load_columns_rows(list(prefs.get('columns', []) or defaults.get('columns', [])))

        # --- Font and Colors ---
        font_page = QWidget(dialog)
        font_layout = QGridLayout(font_page)
        font_cfg = prefs.get('font_and_colors', {}) or {}
        current_list_font = self.capture_view.table.font() if self.capture_view else dialog.font()
        current_details_font = self.capture_view.details_tree.font() if self.capture_view else dialog.font()
        current_bytes_font = self.capture_view.hex_view.font() if self.capture_view else dialog.font()

        def _font_display_text(font: QFont) -> str:
            size = font.pointSize()
            if size <= 0:
                size = int(round(font.pointSizeF())) if font.pointSizeF() > 0 else 10
            family = str(font.family() or 'Consolas').strip() or 'Consolas'
            return f'{family} {size}'

        def _set_font_choice(label: QLabel, stored_text: str, fallback: QFont) -> None:
            font = QFont(fallback)
            stored = str(stored_text or '').strip()
            if stored:
                parsed = QFont()
                if parsed.fromString(stored):
                    font = parsed
            label.setProperty('font_string', font.toString())
            label.setText(_font_display_text(font))

        list_font_label = QLabel(font_page)
        details_font_label = QLabel(font_page)
        bytes_font_label = QLabel(font_page)
        _set_font_choice(list_font_label, str(font_cfg.get('packet_list_font', '') or ''), current_list_font)
        _set_font_choice(details_font_label, str(font_cfg.get('packet_details_font', '') or ''), current_details_font)
        _set_font_choice(bytes_font_label, str(font_cfg.get('packet_bytes_font', '') or ''), current_bytes_font)
        marked_color_btn = QPushButton(str(font_cfg.get('marked_packet_color', '#fff3b0') or '#fff3b0'), font_page)
        ignored_color_btn = QPushButton(str(font_cfg.get('ignored_packet_color', '#e0e0e0') or '#e0e0e0'), font_page)
        search_color_btn = QPushButton(str(font_cfg.get('search_highlight_color', '#ffcc00') or '#ffcc00'), font_page)
        for btn in (marked_color_btn, ignored_color_btn, search_color_btn):
            btn.setStyleSheet(f"background-color: {btn.text()};")

        font_layout.addWidget(QLabel('Packet List Font:'), 0, 0)
        font_layout.addWidget(list_font_label, 0, 1)
        choose_list_font_btn = QPushButton('Choose...', font_page)
        font_layout.addWidget(choose_list_font_btn, 0, 2)

        font_layout.addWidget(QLabel('Packet Details Font:'), 1, 0)
        font_layout.addWidget(details_font_label, 1, 1)
        choose_details_font_btn = QPushButton('Choose...', font_page)
        font_layout.addWidget(choose_details_font_btn, 1, 2)

        font_layout.addWidget(QLabel('Packet Bytes Font:'), 2, 0)
        font_layout.addWidget(bytes_font_label, 2, 1)
        choose_bytes_font_btn = QPushButton('Choose...', font_page)
        font_layout.addWidget(choose_bytes_font_btn, 2, 2)

        font_layout.addWidget(QLabel('Marked packet color:'), 3, 0)
        font_layout.addWidget(marked_color_btn, 3, 1)
        font_layout.addWidget(QLabel('Ignored packet color:'), 4, 0)
        font_layout.addWidget(ignored_color_btn, 4, 1)
        font_layout.addWidget(QLabel('Search highlight:'), 5, 0)
        font_layout.addWidget(search_color_btn, 5, 1)
        font_layout.setRowStretch(6, 1)

        def _font_from_text_or_default(text: str, fallback: QFont) -> QFont:
            font = QFont(fallback)
            if text and font.fromString(text):
                return font
            return QFont(fallback)

        def _pick_font(label: QLabel):
            initial = _font_from_text_or_default(str(label.property('font_string') or '').strip(), dialog.font())
            selected, ok = QFontDialog.getFont(initial, dialog, 'Choose Font')
            if ok:
                label.setProperty('font_string', selected.toString())
                label.setText(_font_display_text(selected))

        def _pick_color(button: QPushButton):
            initial = QColor(button.text().strip() or '#ffffff')
            selected = QColorDialog.getColor(initial, dialog, 'Choose Color')
            if selected.isValid():
                button.setText(selected.name())
                button.setStyleSheet(f'background-color: {selected.name()};')

        choose_list_font_btn.clicked.connect(lambda checked=False, target=list_font_label: _pick_font(target))
        choose_details_font_btn.clicked.connect(lambda checked=False, target=details_font_label: _pick_font(target))
        choose_bytes_font_btn.clicked.connect(lambda checked=False, target=bytes_font_label: _pick_font(target))
        marked_color_btn.clicked.connect(lambda checked=False, target=marked_color_btn: _pick_color(target))
        ignored_color_btn.clicked.connect(lambda checked=False, target=ignored_color_btn: _pick_color(target))
        search_color_btn.clicked.connect(lambda checked=False, target=search_color_btn: _pick_color(target))

        # --- Layout ---
        layout_page = QWidget(dialog)
        layout_layout = QGridLayout(layout_page)
        layout_cfg = prefs.get('layout', {}) or {}
        selected_layout = {'value': str(layout_cfg.get('pane_layout', 'Layout 2') or 'Layout 2')}

        layout_preview_defs = [
            {'id': 0, 'layout': 'Layout 1', 'image': os.path.join('d:\\DATN-Packetra', 'image', 'layout', 'layout_5.png')},
            {'id': 1, 'layout': 'Layout 2', 'image': os.path.join('d:\\DATN-Packetra', 'image', 'layout', 'layout_2.png')},
            {'id': 2, 'layout': 'Layout 3', 'image': os.path.join('d:\\DATN-Packetra', 'image', 'layout', 'layout_1.png')},
            {'id': 3, 'layout': 'Layout 4', 'image': os.path.join('d:\\DATN-Packetra', 'image', 'layout', 'layout_4.png')},
            {'id': 4, 'layout': 'Layout 5', 'image': os.path.join('d:\\DATN-Packetra', 'image', 'layout', 'layout_3.png')},
            {'id': 5, 'layout': 'Layout 6', 'image': os.path.join('d:\\DATN-Packetra', 'image', 'layout', 'layout_6.png')},
        ]
        layout_btn_group = QButtonGroup(layout_page)
        layout_btn_group.setExclusive(True)
        layout_preview_row = QHBoxLayout()
        layout_preview_row.setContentsMargins(0, 0, 0, 0)
        layout_preview_row.setSpacing(12)
        preview_buttons = []
        for spec in layout_preview_defs:
            btn = QToolButton(layout_page)
            btn.setCheckable(True)
            btn.setAutoRaise(False)
            btn.setIcon(QIcon(spec['image']))
            btn.setIconSize(QSize(72, 72))
            btn.setFixedSize(84, 84)
            btn.setToolButtonStyle(Qt.ToolButtonIconOnly)
            btn.setToolTip(spec['layout'])
            layout_btn_group.addButton(btn, int(spec['id']))
            layout_preview_row.addWidget(btn)
            preview_buttons.append(btn)
        layout_preview_row.addStretch(1)

        pane_defs = [
            ('packet_list', 'Packet List'),
            ('packet_details', 'Packet Details'),
            ('packet_bytes', 'Packet Bytes'),
            ('packet_diagram', 'Packet Diagram'),
            ('none', 'None'),
        ]
        pane_group_box = QGroupBox('Pane contents', layout_page)
        pane_group_layout = QGridLayout(pane_group_box)
        pane_buttons = {}

        def _create_pane_selector(column: int, title: str, selected_key: str):
            group = QButtonGroup(pane_group_box)
            group.setExclusive(True)
            pane_group_layout.addWidget(QLabel(title, pane_group_box), 0, column)
            buttons = {}
            for row, (value, caption) in enumerate(pane_defs, start=1):
                button = QRadioButton(caption, pane_group_box)
                button.setChecked(value == selected_key)
                buttons[value] = button
                group.addButton(button)
                pane_group_layout.addWidget(button, row, column)
            return buttons

        pane_buttons['pane_1'] = _create_pane_selector(0, 'Pane 1:', str(layout_cfg.get('pane_1', 'packet_list') or 'packet_list'))
        pane_buttons['pane_2'] = _create_pane_selector(1, 'Pane 2:', str(layout_cfg.get('pane_2', 'packet_details') or 'packet_details'))
        pane_buttons['pane_3'] = _create_pane_selector(2, 'Pane 3:', str(layout_cfg.get('pane_3', 'packet_bytes') or 'packet_bytes'))

        def _selected_pane_value(key: str) -> str:
            buttons = pane_buttons.get(key, {})
            for value, button in buttons.items():
                if button.isChecked():
                    return value
            return 'none'

        def _apply_preview_selection(layout_name: str):
            target = str(layout_name or 'Layout 2')
            selected_layout['value'] = target
            picked = None
            for spec in layout_preview_defs:
                if spec['layout'] == target:
                    picked = int(spec['id'])
                    break
            if picked is None:
                picked = 0
            button = layout_btn_group.button(picked)
            if button is not None:
                button.setChecked(True)

        def _on_layout_preview_changed(button_id: int):
            for spec in layout_preview_defs:
                if int(spec['id']) == int(button_id):
                    selected_layout['value'] = str(spec['layout'])
                    break

        layout_btn_group.idClicked.connect(_on_layout_preview_changed)
        _apply_preview_selection(selected_layout['value'])

        show_separator_cb = QCheckBox('Show packet list separator', layout_page)
        show_separator_cb.setChecked(bool(layout_cfg.get('show_packet_list_separator', False)))
        restore_layout_btn = QPushButton('Restore Defaults', layout_page)
        layout_layout.addWidget(QLabel('Pane layout:'), 0, 0, 1, 2)
        layout_layout.addLayout(layout_preview_row, 1, 0, 1, 2)
        layout_layout.addWidget(pane_group_box, 2, 0, 1, 2)
        layout_layout.addWidget(show_separator_cb, 3, 0, 1, 2)
        layout_layout.addWidget(restore_layout_btn, 4, 0, 1, 2)
        layout_layout.setRowStretch(5, 1)

        def _restore_layout_defaults():
            reply = QMessageBox.question(
                dialog,
                'Layout',
                'Restore layout preferences to default values?',
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if reply != QMessageBox.Yes:
                return
            _apply_preview_selection('Layout 2')
            show_separator_cb.setChecked(False)
            pane_buttons['pane_1']['packet_list'].setChecked(True)
            pane_buttons['pane_2']['packet_details'].setChecked(True)
            pane_buttons['pane_3']['packet_bytes'].setChecked(True)

        restore_layout_btn.clicked.connect(_restore_layout_defaults)

        # --- Capture ---
        capture_page = QWidget(dialog)
        capture_layout = QGridLayout(capture_page)
        capture_cfg = prefs.get('capture', {}) or {}
        default_interface_combo = QComboBox(capture_page)
        default_interface_combo.setEditable(True)
        default_interface_combo.setInsertPolicy(QComboBox.InsertPolicy.NoInsert)
        default_interfaces = []
        if self.iface_selector_view and hasattr(self.iface_selector_view, 'interfaces'):
            interface_map = getattr(self.iface_selector_view, 'interfaces', {}) or {}
            default_interfaces = [str(name) for name in interface_map.keys()]
        default_interface_combo.addItems(sorted(default_interfaces))
        default_interface_combo.setCurrentText(str(capture_cfg.get('default_interface', '') or ''))
        promiscuous_cb = QCheckBox('Capture packets in promiscuous mode', capture_page)
        promiscuous_cb.setChecked(bool(capture_cfg.get('promiscuous_mode', True)))
        pcapng_cb = QCheckBox('Capture packets in pcapng format', capture_page)
        pcapng_cb.setChecked(bool(capture_cfg.get('capture_format_pcapng', True)))
        realtime_cb = QCheckBox('Update list of packets in real time', capture_page)
        realtime_cb.setChecked(bool(capture_cfg.get('realtime_update', True)))
        interval_spin = QSpinBox(capture_page)
        interval_spin.setRange(100, 10000)
        interval_spin.setSingleStep(100)
        interval_spin.setValue(int(capture_cfg.get('update_interval_ms', 1000) or 1000))
        capture_layout.addWidget(QLabel('Default interface:'), 0, 0)
        capture_layout.addWidget(default_interface_combo, 0, 1)
        capture_layout.addWidget(promiscuous_cb, 1, 0, 1, 2)
        capture_layout.addWidget(pcapng_cb, 2, 0, 1, 2)
        capture_layout.addWidget(realtime_cb, 3, 0, 1, 2)
        capture_layout.addWidget(QLabel('Interval between updates (ms):'), 4, 0)
        capture_layout.addWidget(interval_spin, 4, 1)
        capture_layout.setRowStretch(5, 1)

        def _sync_capture_widgets():
            interval_spin.setEnabled(bool(realtime_cb.isChecked()))

        realtime_cb.toggled.connect(_sync_capture_widgets)
        _sync_capture_widgets()

        # --- Expert Items ---
        expert_page = QWidget(dialog)
        expert_layout = QVBoxLayout(expert_page)
        expert_table = QTableWidget(expert_page)
        expert_table.setColumnCount(2)
        expert_table.setHorizontalHeaderLabels(['Field Name', 'Severity'])
        expert_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        expert_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        expert_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        expert_layout.addWidget(expert_table, 1)

        expert_btn_row = QHBoxLayout()
        expert_add_btn = QPushButton('Add', expert_page)
        expert_remove_btn = QPushButton('Remove', expert_page)
        expert_up_btn = QPushButton('Move up', expert_page)
        expert_down_btn = QPushButton('Move down', expert_page)
        expert_clear_btn = QPushButton('Clear', expert_page)
        expert_btn_row.addWidget(expert_add_btn)
        expert_btn_row.addWidget(expert_remove_btn)
        expert_btn_row.addWidget(expert_up_btn)
        expert_btn_row.addWidget(expert_down_btn)
        expert_btn_row.addWidget(expert_clear_btn)
        expert_btn_row.addStretch()
        expert_layout.addLayout(expert_btn_row)

        severity_values = ['Error', 'Warning', 'Note', 'Chat']

        def _set_expert_row(row: int, field_name: str, severity: str):
            expert_table.setItem(row, 0, QTableWidgetItem(str(field_name or '').strip()))
            severity_combo = QComboBox(expert_table)
            severity_combo.addItems(severity_values)
            severity_text = str(severity or 'Warning').strip().title()
            if severity_text not in severity_values:
                severity_text = 'Warning'
            severity_combo.setCurrentText(severity_text)
            expert_table.setCellWidget(row, 1, severity_combo)

        def _load_expert_rows(items: list[dict]):
            expert_table.setRowCount(0)
            for row, item in enumerate(items):
                expert_table.insertRow(row)
                field_name = str(item.get('field', '') if isinstance(item, dict) else '')
                severity = str(item.get('severity', 'Warning') if isinstance(item, dict) else 'Warning')
                _set_expert_row(row, field_name, severity)

        def _read_expert_row(row: int) -> tuple[str, str]:
            field_item = expert_table.item(row, 0)
            severity_combo = expert_table.cellWidget(row, 1)
            field_name = str(field_item.text() if field_item is not None else '').strip()
            severity = str(severity_combo.currentText() if isinstance(severity_combo, QComboBox) else 'Warning').strip()
            return field_name, severity or 'Warning'

        def _move_expert_row(delta: int):
            row = expert_table.currentRow()
            if row < 0:
                return
            target = row + delta
            if target < 0 or target >= expert_table.rowCount():
                return
            src_field, src_sev = _read_expert_row(row)
            dst_field, dst_sev = _read_expert_row(target)
            _set_expert_row(row, dst_field, dst_sev)
            _set_expert_row(target, src_field, src_sev)
            expert_table.setCurrentCell(target, 0)

        expert_add_btn.clicked.connect(lambda: (expert_table.insertRow(expert_table.rowCount()), _set_expert_row(expert_table.rowCount() - 1, '', 'Warning')))
        expert_remove_btn.clicked.connect(lambda: expert_table.removeRow(expert_table.currentRow()) if expert_table.currentRow() >= 0 else None)
        expert_up_btn.clicked.connect(lambda: _move_expert_row(-1))
        expert_down_btn.clicked.connect(lambda: _move_expert_row(1))
        expert_clear_btn.clicked.connect(lambda: expert_table.setRowCount(0))
        _load_expert_rows(list(prefs.get('expert_items', []) or []))

        # --- Name Resolution ---
        name_page = QWidget(dialog)
        name_layout = QVBoxLayout(name_page)
        name_cfg = prefs.get('name_resolution', {}) or {}
        resolve_mac_cb = QCheckBox('Resolve MAC addresses', name_page)
        resolve_mac_cb.setChecked(bool(name_cfg.get('resolve_mac_addresses', True)))
        resolve_transport_cb = QCheckBox('Resolve transport names', name_page)
        resolve_transport_cb.setChecked(bool(name_cfg.get('resolve_transport_names', False)))
        resolve_network_cb = QCheckBox('Resolve network IP addresses', name_page)
        resolve_network_cb.setChecked(bool(name_cfg.get('resolve_network_ip_addresses', False)))
        use_captured_dns_cb = QCheckBox('Use captured DNS packet data for name resolution', name_page)
        use_captured_dns_cb.setChecked(bool(name_cfg.get('use_captured_dns_packet_data', True)))
        for cb in (resolve_mac_cb, resolve_transport_cb, resolve_network_cb, use_captured_dns_cb):
            name_layout.addWidget(cb)
        name_layout.addStretch()

        for page in (
            appearance_page,
            columns_page,
            font_page,
            layout_page,
            capture_page,
            expert_page,
            name_page,
        ):
            page_stack.addWidget(page)

        nav_list.currentRowChanged.connect(page_stack.setCurrentIndex)
        nav_list.setCurrentRow(0)

        # --- Buttons ---
        bottom_row = QHBoxLayout()
        restore_page_btn = QPushButton('Restore Page Defaults', dialog)
        cancel_btn = QPushButton('Cancel', dialog)
        apply_btn = QPushButton('Apply', dialog)
        ok_btn = QPushButton('OK', dialog)
        bottom_row.addWidget(restore_page_btn)
        bottom_row.addStretch()
        bottom_row.addWidget(cancel_btn)
        bottom_row.addWidget(apply_btn)
        bottom_row.addWidget(ok_btn)
        root.addLayout(bottom_row)

        def _collect_preferences_from_dialog() -> dict | None:
            collected_columns = []
            for row in range(columns_table.rowCount()):
                spec = _read_column_row(row)
                if not spec.get('title'):
                    spec['title'] = f'Column {row + 1}'
                if not spec.get('field'):
                    spec['field'] = 'frame.number'
                collected_columns.append(spec)

            if not collected_columns:
                QMessageBox.warning(dialog, 'Preferences', 'Canh bao: Columns khong duoc de rong.')
                return None
            if not any(bool(spec.get('displayed', True)) for spec in collected_columns):
                QMessageBox.warning(dialog, 'Preferences', 'Canh bao: Phai hien thi it nhat 1 cot.')
                return None

            collected_expert = []
            for row in range(expert_table.rowCount()):
                field_name, severity = _read_expert_row(row)
                if field_name:
                    collected_expert.append({'field': field_name, 'severity': severity})

            pane_values = [
                _selected_pane_value('pane_1'),
                _selected_pane_value('pane_2'),
                _selected_pane_value('pane_3'),
            ]
            non_empty_panes = [value for value in pane_values if value != 'none']
            if len(non_empty_panes) != len(set(non_empty_panes)):
                QMessageBox.warning(dialog, 'Preferences', 'Pane 1, Pane 2 va Pane 3 khong duoc trung noi dung.')
                return None

            new_prefs = dict(prefs)
            new_prefs['appearance'] = {
                'remember_main_window_size_and_placement': bool(remember_window_cb.isChecked()),
                'open_files_mode': 'fixed_folder' if open_fixed_radio.isChecked() else 'recent_folder',
                'open_files_fixed_directory': fixed_directory_input.text().strip(),
                'show_up_to_filter_entries': int(show_filter_entries_spin.value()),
                'show_up_to_recent_files': int(show_recent_files_spin.value()),
                'confirm_unsaved_capture_files': bool(confirm_unsaved_cb.isChecked()),
                'display_filter_autocomplete': bool(autocomplete_cb.isChecked()),
            }
            new_prefs['columns'] = collected_columns
            new_prefs['font_and_colors'] = {
                'packet_list_font': str(list_font_label.property('font_string') or '').strip(),
                'packet_details_font': str(details_font_label.property('font_string') or '').strip(),
                'packet_bytes_font': str(bytes_font_label.property('font_string') or '').strip(),
                'marked_packet_color': marked_color_btn.text().strip() or '#fff3b0',
                'ignored_packet_color': ignored_color_btn.text().strip() or '#e0e0e0',
                'search_highlight_color': search_color_btn.text().strip() or '#ffcc00',
            }
            new_prefs['layout'] = {
                'pane_layout': str(selected_layout.get('value', 'Layout 2') or 'Layout 2'),
                'show_packet_list_separator': bool(show_separator_cb.isChecked()),
                'pane_1': pane_values[0],
                'pane_2': pane_values[1],
                'pane_3': pane_values[2],
            }
            new_prefs['capture'] = {
                'default_interface': default_interface_combo.currentText().strip(),
                'promiscuous_mode': bool(promiscuous_cb.isChecked()),
                'capture_format_pcapng': bool(pcapng_cb.isChecked()),
                'realtime_update': bool(realtime_cb.isChecked()),
                'update_interval_ms': int(interval_spin.value()),
            }
            new_prefs['expert_items'] = collected_expert
            new_prefs['name_resolution'] = {
                'resolve_mac_addresses': bool(resolve_mac_cb.isChecked()),
                'resolve_transport_names': bool(resolve_transport_cb.isChecked()),
                'resolve_network_ip_addresses': bool(resolve_network_cb.isChecked()),
                'use_captured_dns_packet_data': bool(use_captured_dns_cb.isChecked()),
            }
            return new_prefs

        def _apply_current_preferences() -> bool:
            nonlocal prefs
            new_prefs = _collect_preferences_from_dialog()
            if not isinstance(new_prefs, dict):
                return False
            self._save_edit_preferences(new_prefs)
            self._apply_edit_preferences(new_prefs)
            prefs = new_prefs
            return True

        def _restore_current_page_defaults():
            page_index = nav_list.currentRow()
            if page_index < 0 or page_index >= len(page_keys):
                return
            key = page_keys[page_index][0]
            reply = QMessageBox.question(
                dialog,
                'Restore Defaults',
                f'Restore default values for "{page_keys[page_index][1]}"?',
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if reply != QMessageBox.Yes:
                return

            if key == 'appearance':
                default_cfg = defaults.get('appearance', {}) or {}
                remember_window_cb.setChecked(bool(default_cfg.get('remember_main_window_size_and_placement', True)))
                open_mode = str(default_cfg.get('open_files_mode', 'recent_folder') or 'recent_folder')
                open_recent_radio.setChecked(open_mode == 'recent_folder')
                open_fixed_radio.setChecked(open_mode == 'fixed_folder')
                fixed_directory_input.setText(str(default_cfg.get('open_files_fixed_directory', '') or ''))
                show_filter_entries_spin.setValue(int(default_cfg.get('show_up_to_filter_entries', 10) or 10))
                show_recent_files_spin.setValue(int(default_cfg.get('show_up_to_recent_files', 10) or 10))
                confirm_unsaved_cb.setChecked(bool(default_cfg.get('confirm_unsaved_capture_files', True)))
                autocomplete_cb.setChecked(bool(default_cfg.get('display_filter_autocomplete', True)))
                _sync_open_mode_widgets()
                return
            if key == 'columns':
                _load_columns_rows(list(defaults.get('columns', []) or []))
                return
            if key == 'font_and_colors':
                default_cfg = defaults.get('font_and_colors', {}) or {}
                _set_font_choice(list_font_label, str(default_cfg.get('packet_list_font', '') or ''), current_list_font)
                _set_font_choice(details_font_label, str(default_cfg.get('packet_details_font', '') or ''), current_details_font)
                _set_font_choice(bytes_font_label, str(default_cfg.get('packet_bytes_font', '') or ''), current_bytes_font)
                marked_color_btn.setText(str(default_cfg.get('marked_packet_color', '#fff3b0') or '#fff3b0'))
                ignored_color_btn.setText(str(default_cfg.get('ignored_packet_color', '#e0e0e0') or '#e0e0e0'))
                search_color_btn.setText(str(default_cfg.get('search_highlight_color', '#ffcc00') or '#ffcc00'))
                for btn in (marked_color_btn, ignored_color_btn, search_color_btn):
                    btn.setStyleSheet(f'background-color: {btn.text()};')
                return
            if key == 'layout':
                default_cfg = defaults.get('layout', {}) or {}
                _apply_preview_selection(str(default_cfg.get('pane_layout', 'Layout 2') or 'Layout 2'))
                show_separator_cb.setChecked(bool(default_cfg.get('show_packet_list_separator', False)))
                pane_buttons['pane_1'][str(default_cfg.get('pane_1', 'packet_list') or 'packet_list')].setChecked(True)
                pane_buttons['pane_2'][str(default_cfg.get('pane_2', 'packet_details') or 'packet_details')].setChecked(True)
                pane_buttons['pane_3'][str(default_cfg.get('pane_3', 'packet_bytes') or 'packet_bytes')].setChecked(True)
                return
            if key == 'capture':
                default_cfg = defaults.get('capture', {}) or {}
                default_interface_combo.setCurrentText(str(default_cfg.get('default_interface', '') or ''))
                promiscuous_cb.setChecked(bool(default_cfg.get('promiscuous_mode', True)))
                pcapng_cb.setChecked(bool(default_cfg.get('capture_format_pcapng', True)))
                realtime_cb.setChecked(bool(default_cfg.get('realtime_update', True)))
                interval_spin.setValue(int(default_cfg.get('update_interval_ms', 1000) or 1000))
                _sync_capture_widgets()
                return
            if key == 'expert_items':
                _load_expert_rows(list(defaults.get('expert_items', []) or []))
                return
            if key == 'name_resolution':
                default_cfg = defaults.get('name_resolution', {}) or {}
                resolve_mac_cb.setChecked(bool(default_cfg.get('resolve_mac_addresses', True)))
                resolve_transport_cb.setChecked(bool(default_cfg.get('resolve_transport_names', False)))
                resolve_network_cb.setChecked(bool(default_cfg.get('resolve_network_ip_addresses', False)))
                use_captured_dns_cb.setChecked(bool(default_cfg.get('use_captured_dns_packet_data', True)))
                return

        restore_page_btn.clicked.connect(_restore_current_page_defaults)
        apply_btn.clicked.connect(_apply_current_preferences)
        cancel_btn.clicked.connect(dialog.reject)

        def _on_ok_clicked():
            if _apply_current_preferences():
                dialog.accept()

        ok_btn.clicked.connect(_on_ok_clicked)
        dialog.exec()

    def _on_toggle_main_toolbar(self, enabled: bool):
        visible = bool(enabled)
        self.toolbar.setVisible(visible)
        if hasattr(self, 'action_view_main_toolbar'):
            self.action_view_main_toolbar.blockSignals(True)
            self.action_view_main_toolbar.setChecked(visible)
            self.action_view_main_toolbar.blockSignals(False)

    def _on_toggle_filter_toolbar(self, enabled: bool):
        visible = bool(enabled)
        if self.capture_view:
            self.capture_view.set_filter_toolbar_visible(visible)
        if hasattr(self, 'action_view_filter_toolbar'):
            self.action_view_filter_toolbar.blockSignals(True)
            self.action_view_filter_toolbar.setChecked(visible)
            self.action_view_filter_toolbar.blockSignals(False)

    def _on_toggle_statusbar(self, enabled: bool):
        visible = bool(enabled)
        self.statusbar.setVisible(visible)
        if hasattr(self, 'action_view_statusbar'):
            self.action_view_statusbar.blockSignals(True)
            self.action_view_statusbar.setChecked(visible)
            self.action_view_statusbar.blockSignals(False)

    def _on_toggle_packet_pane(self, pane_name: str, enabled: bool):
        checked = bool(enabled)
        if self.capture_view:
            self.capture_view.set_component_visible(pane_name, checked)
        action_name = {
            'packet_list': 'action_view_packet_list',
            'packet_details': 'action_view_packet_details',
            'packet_bytes': 'action_view_packet_bytes',
            'packet_diagram': 'action_view_packet_diagram',
        }.get(str(pane_name or '').strip().lower())
        if action_name and hasattr(self, action_name):
            action = getattr(self, action_name)
            action.blockSignals(True)
            action.setChecked(checked)
            action.blockSignals(False)

    def _on_expand_subtrees(self):
        if self.capture_view:
            self.capture_view.expand_selected_subtrees()

    def _on_collapse_subtrees(self):
        if self.capture_view:
            self.capture_view.collapse_selected_subtrees()

    def _on_expand_all(self):
        if self.capture_view:
            self.capture_view.expand_all_details()

    def _on_collapse_all(self):
        if self.capture_view:
            self.capture_view.collapse_all_details()

    def _conversation_key_for_record(self, record):
        metadata = getattr(record, 'metadata', {}) if record else {}
        stream_index = metadata.get('tcp_stream_index')
        if stream_index is not None:
            return ('tcp_stream', int(stream_index))
        src = str(getattr(record, 'src', '') or '')
        dst = str(getattr(record, 'dst', '') or '')
        sport = str(getattr(record, 'sport', '') or '')
        dport = str(getattr(record, 'dport', '') or '')
        proto = str(getattr(record, 'protocol', '') or '').upper()
        endpoints = sorted([(src, sport), (dst, dport)])
        return (proto, tuple(endpoints))

    def _on_colorize_conversation(self):
        if not self.capture_view:
            return
        current = self.capture_view.get_current_record()
        if current is None:
            QMessageBox.information(self, 'Colorize Conversation', 'Select a packet first.')
            return

        key = self._conversation_key_for_record(current)
        highlight_indexes = []
        for idx, record in enumerate(self.capture_view.records):
            if self._conversation_key_for_record(record) == key:
                highlight_indexes.append(idx)

        if not highlight_indexes:
            QMessageBox.information(self, 'Colorize Conversation', 'No matching packets found for this conversation.')
            return

        settings = QSettings('Packetra', 'Packetra')
        color_hex = str(settings.value('view/conversation_color', '#FFF2A8', str) or '#FFF2A8')
        self.capture_view.set_conversation_highlight(highlight_indexes, QColor(color_hex))
        self.capture_view.status_changed.emit(f'Colorized {len(highlight_indexes)} packets in current conversation')

    def _on_coloring_rules(self):
        if not self.capture_view:
            return

        dialog = QDialog(self)
        dialog.setWindowTitle('Coloring Rules')
        dialog.resize(1020, 640)
        layout = QVBoxLayout(dialog)

        layout.addWidget(QLabel('Select a rule row, then choose color to edit that rule:'))
        rules_table = QTableWidget(dialog)
        rules_table.setColumnCount(3)
        rules_table.setHorizontalHeaderLabels(['Color', 'Name', 'Filter'])
        rules_table.verticalHeader().setVisible(False)
        rules_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        rules_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        rules_table.setSelectionMode(QAbstractItemView.SingleSelection)

        settings = QSettings('Packetra', 'Packetra')
        conversation_color = QColor(str(settings.value('view/conversation_color', '#FFF2A8', str) or '#FFF2A8'))
        rule_overrides = self.capture_view.table.get_rule_background_overrides()

        rules = [
            {
                'name': 'Colorize Conversation',
                'filter': 'temporary conversation highlight',
                'background': QColor(conversation_color),
                'foreground': QColor('#111111'),
            }
        ] + self.capture_view.table.wireshark_coloring_rules()

        def _paint_row(row: int):
            rule = rules[row]
            for col, text in enumerate(['', str(rule['name']), str(rule['filter'])]):
                item = rules_table.item(row, col)
                if item is None:
                    item = QTableWidgetItem()
                    rules_table.setItem(row, col, item)
                item.setText(text)
                item.setBackground(QColor(rule['background']))
                item.setForeground(QColor(rule['foreground']))

        rules_table.setRowCount(len(rules))
        for row in range(len(rules)):
            _paint_row(row)

        rules_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        rules_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        rules_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        layout.addWidget(rules_table, 1)

        edit_row = QHBoxLayout()
        selected_rule_label = QLabel('Rule: Colorize Conversation')
        edit_row.addWidget(selected_rule_label)

        color_preview = QFrame(dialog)
        color_preview.setFrameShape(QFrame.StyledPanel)
        color_preview.setFixedSize(88, 24)
        edit_row.addWidget(color_preview)

        choose_btn = QPushButton('Choose...')
        edit_row.addWidget(choose_btn)
        edit_row.addStretch(1)
        layout.addLayout(edit_row)

        def _selected_row() -> int:
            row = int(rules_table.currentRow())
            return row if 0 <= row < len(rules) else 0

        def _refresh_selected_preview():
            row = _selected_row()
            rule = rules[row]
            selected_rule_label.setText(f'Rule: {rule["name"]}')
            color_preview.setStyleSheet(f'background-color: {QColor(rule["background"]).name()}; border: 1px solid #808080;')

        def _choose_color_for_selected():
            row = _selected_row()
            current = QColor(rules[row]['background'])
            picked = QColorDialog.getColor(current, self, f'Rule Color - {rules[row]["name"]}')
            if not picked.isValid():
                return
            rules[row]['background'] = QColor(picked)
            _paint_row(row)
            _refresh_selected_preview()

        buttons_row = QHBoxLayout()
        choose_btn.clicked.connect(_choose_color_for_selected)
        buttons_row.addStretch(1)
        clear_btn = QPushButton('Clear highlight')
        clear_btn.setFixedWidth(120)
        clear_btn.setFixedHeight(24)
        clear_btn.clicked.connect(lambda: self.capture_view.clear_conversation_highlight())
        buttons_row.addWidget(clear_btn)
        layout.addLayout(buttons_row)

        dialog_buttons = QHBoxLayout()
        apply_btn = QPushButton('Apply')
        close_btn = QPushButton('Close')
        dialog_buttons.addStretch(1)
        dialog_buttons.addWidget(apply_btn)
        dialog_buttons.addWidget(close_btn)
        layout.addLayout(dialog_buttons)

        def _apply_rules():
            conv_bg = QColor(rules[0]['background']).name()
            settings.setValue('view/conversation_color', conv_bg)

            updated_overrides = {}
            for rule in rules[1:]:
                name = str(rule['name'])
                color_hex = QColor(rule['background']).name()
                default_hex = '#ffffff'
                for default_rule in self.capture_view.table.WIRESHARK_DEFAULT_RULES:
                    if str(default_rule.get('name', '')) == name:
                        default_hex = QColor(default_rule.get('bg')).name()
                        break
                if color_hex.lower() != default_hex.lower():
                    updated_overrides[name] = color_hex

            rule_overrides.clear()
            rule_overrides.update(updated_overrides)
            settings.setValue('view/rule_background_overrides', json.dumps(rule_overrides))

            self.capture_view.table.set_rule_background_overrides(rule_overrides)
            self.capture_view.set_conversation_highlight([], QColor(conv_bg))
            self.capture_view.set_color_rules_enabled(True)

        rules_table.currentCellChanged.connect(lambda *_: _refresh_selected_preview())
        apply_btn.clicked.connect(_apply_rules)
        close_btn.clicked.connect(dialog.accept)

        rules_table.selectRow(0)
        _refresh_selected_preview()
        dialog.exec()

    def _on_show_packet_new_window(self):
        if not self.capture_view:
            return
        record = self.capture_view.get_current_record()
        if record is None:
            QMessageBox.information(self, 'Show Packet', 'Select a packet first.')
            return

        dialog = QDialog(self)
        dialog.setWindowTitle(f'Show Packet - Frame {getattr(record, "number", "?")}')
        dialog.resize(900, 620)

        layout = QVBoxLayout(dialog)
        splitter = QSplitter(Qt.Vertical, dialog)
        details_tree = PacketDetailsTree()
        bytes_view = PacketBytesView()
        details_tree.item_bytes_selected.connect(bytes_view.highlight_bytes)
        bytes_view.bytes_hovered.connect(lambda offset, source: details_tree.select_offset(offset, source))
        bytes_view.hover_left.connect(lambda _source: details_tree.clearSelection())
        splitter.addWidget(details_tree)
        splitter.addWidget(bytes_view)
        splitter.setSizes([360, 240])
        layout.addWidget(splitter)

        details_tree.show_packet(record)
        bytes_view.show_packet(record)
        dialog.exec()

    def _on_redissect_packets(self):
        if not self.capture_view:
            return
        self._close_firewall_acl_dialog('Capture data was redissected. Re-open Firewall ACL Rules to regenerate from the updated packet.')
        self.capture_view.reload_file()
        self._refresh_status_metrics()

    def _on_reload_as_format_capture(self, enabled: bool):
        checked = bool(enabled)
        if self.capture_view:
            self.capture_view.set_file_format_view_mode(checked)
            checked = self.capture_view.is_file_format_view_mode()
        if hasattr(self, 'action_view_reload_as_format_capture'):
            self.action_view_reload_as_format_capture.blockSignals(True)
            self.action_view_reload_as_format_capture.setChecked(checked)
            self.action_view_reload_as_format_capture.blockSignals(False)

    def _on_refresh_interfaces(self):
        if self.capture_view and self.capture_view.is_capturing():
            QMessageBox.information(self, 'Refresh Interfaces', 'Cannot refresh interfaces while capture is running.')
            return
        if self.iface_selector_view:
            try:
                self.iface_selector_view.refresh_list_structure()
                if hasattr(self.iface_selector_view, 'refresh_recent_files'):
                    self.iface_selector_view.refresh_recent_files()
                self._refresh_capture_menu_state()
                return
            except Exception:
                pass
        self._on_menu_feature_placeholder('Capture > Refresh Interfaces')

    def _has_capture_document(self) -> bool:
        return bool(self.capture_view and self.stacked_widget.currentWidget() is self.capture_view and self.capture_view.has_packets())

    def _selected_detail_item(self):
        cv = self.capture_view
        if not cv:
            return None
        items = cv.details_tree.selectedItems()
        return items[0] if items else None

    def _packet_list_filter_expression_for_context(self, row: int, column: int) -> str:
        cv = self.capture_view
        if not cv:
            return ''
        try:
            return str(cv.packet_list_filter_expression(int(row), int(column)) or '').strip()
        except Exception:
            return ''

    def _apply_filter_expression_with_mode(self, base_expr: str, mode: str) -> bool:
        expr = str(base_expr or '').strip()
        if not expr:
            return False
        merged = self._build_combined_filter(expr, str(mode or 'selected'))
        self._set_display_filter_text(merged, apply_now=True)
        return True

    def _add_apply_filter_submenu(self, parent_menu, base_expr: str):
        expr = str(base_expr or '').strip()
        submenu = parent_menu.addMenu('Apply as a Filter')
        action_specs = [
            ('Selected', 'selected'),
            ('Not Selected', 'not_selected'),
            ('... and Selected', 'and_selected'),
            ('... or Selected', 'or_selected'),
            ('... and not Selected', 'and_not_selected'),
            ('... or not Selected', 'or_not_selected'),
        ]
        for label, mode in action_specs:
            action = submenu.addAction(label)
            if expr:
                action.triggered.connect(lambda _checked=False, m=mode, e=expr: self._apply_filter_expression_with_mode(e, m))
            else:
                action.setEnabled(False)
        submenu.setEnabled(bool(expr))
        return submenu

    def _on_packet_list_context_menu(self, row: int, column: int, global_pos):
        if not self._has_capture_document() or not self.capture_view:
            return
        cv = self.capture_view
        if not cv.ensure_packet_list_context(int(row), int(column)):
            return
        record = cv.get_record_for_visible_row(int(row))
        if record is None:
            return

        menu = QMenu(self)
        menu.addAction(self.action_mark_unmark_selected)
        menu.addAction(self.action_ignore_unignore_selected)
        menu.addAction(self.action_packet_comment)

        base_expr = self._packet_list_filter_expression_for_context(int(row), int(column))
        if base_expr:
            self._add_apply_filter_submenu(menu, base_expr)

        follow_choices = self._follow_mode_choices_for_record(record)
        if follow_choices:
            follow_menu = menu.addMenu('Follow')
            for label, mode in follow_choices:
                follow_action = follow_menu.addAction(label)
                follow_action.triggered.connect(
                    lambda _checked=False, rec=record, m=mode, text=label: self._open_follow_stream_dialog(rec, m, title_label=text)
                )

        menu.addAction(self.action_copy)
        menu.exec(global_pos)

    def _on_packet_detail_context_menu(self, item, global_pos):
        if not self._has_capture_document() or not self.capture_view or item is None:
            return
        tree = self.capture_view.details_tree
        tree.clearSelection()
        item.setSelected(True)
        tree.setCurrentItem(item)
        tree.setFocus()
        self._refresh_analyze_menu_state()

        menu = QMenu(self)
        menu.addAction(self.action_expand_subtrees)
        menu.addAction(self.action_collapse_subtrees)
        menu.addAction(self.action_expand_all)
        menu.addAction(self.action_collapse_all)

        base_expr, _field_name = self._selected_field_filter_expression()
        self._add_apply_filter_submenu(menu, base_expr)

        copy_menu = menu.addMenu('Copy')
        copy_visible_action = copy_menu.addAction('All visible items')
        copy_visible_action.triggered.connect(lambda _checked=False, t=tree: t.copy_visible_items())
        copy_selected_action = copy_menu.addAction('All visible selected tree items')
        copy_selected_action.triggered.connect(lambda _checked=False, t=tree, it=item: t.copy_visible_selected_subtree(it))
        copy_all_action = copy_menu.addAction('All')
        copy_all_action.triggered.connect(lambda _checked=False, t=tree: t.copy_all_items())

        menu.exec(global_pos)

    def _on_packet_bytes_context_menu(self, byte_source: str, global_pos):
        if not self._has_capture_document() or not self.capture_view:
            return
        menu = QMenu(self)
        copy_action = menu.addAction('Copy')
        copy_action.triggered.connect(
            lambda _checked=False, source=str(byte_source or 'packet'): self.capture_view.hex_view.copy_visible_bytes_to_clipboard(source)
        )
        menu.exec(global_pos)

    def _refresh_analyze_menu_state(self):
        has_capture = self._has_capture_document()
        selected_item = self._selected_detail_item()
        has_field = has_capture and selected_item is not None
        current_record = self.capture_view.get_current_record() if self.capture_view else None
        has_current = has_capture and current_record is not None

        if hasattr(self, 'action_display_filter_macros'):
            self.action_display_filter_macros.setEnabled(True)
        if hasattr(self, 'action_display_filter_expression'):
            self.action_display_filter_expression.setEnabled(True)
        if hasattr(self, 'action_apply_as_column'):
            self.action_apply_as_column.setEnabled(bool(has_field))
        if hasattr(self, 'action_apply_as_filter'):
            self.action_apply_as_filter.setEnabled(bool(has_field))
        if hasattr(self, 'action_conversation_filter'):
            self.action_conversation_filter.setEnabled(bool(has_current))
        if hasattr(self, 'action_follow_stream'):
            self.action_follow_stream.setEnabled(bool(has_current))
        if hasattr(self, 'action_expert_info'):
            self.action_expert_info.setEnabled(bool(has_capture))
        if hasattr(self, 'action_advanced_fwrule'):
            self.action_advanced_fwrule.setEnabled(self._can_open_firewall_acl_rules())

    def _selected_records_from_packet_list(self) -> list:
        cv = self.capture_view
        if not cv or not hasattr(cv, 'table'):
            return []
        table = cv.table
        model = table.selectionModel() if table else None
        if model is None:
            return []
        rows = sorted({idx.row() for idx in model.selectedRows()})
        if not rows:
            return []

        records = []
        for row in rows:
            if row < 0 or row >= len(cv.visible_indices):
                continue
            rec_index = int(cv.visible_indices[row])
            if rec_index < 0 or rec_index >= len(cv.records):
                continue
            records.append(cv.records[rec_index])
        return records

    def _build_acl_snapshot_from_record(self, record) -> PacketAclSnapshot:
        raw = getattr(record, 'raw', None)
        metadata = getattr(record, 'metadata', {}) or {}
        eth_src = ''
        eth_dst = ''
        ip_src = ''
        ip_dst = ''
        ip_proto = None
        tcp_sport = None
        tcp_dport = None
        udp_sport = None
        udp_dport = None

        try:
            if raw is not None and raw.haslayer(Ether):
                eth_src = str(getattr(raw[Ether], 'src', '') or '').strip()
                eth_dst = str(getattr(raw[Ether], 'dst', '') or '').strip()
        except Exception:
            pass
        try:
            if raw is not None and raw.haslayer(IP):
                ip_src = str(getattr(raw[IP], 'src', '') or '').strip()
                ip_dst = str(getattr(raw[IP], 'dst', '') or '').strip()
                proto_value = getattr(raw[IP], 'proto', None)
                ip_proto = int(proto_value) if proto_value is not None else None
        except Exception:
            pass
        try:
            if raw is not None and raw.haslayer(TCP):
                tcp_sport = int(getattr(raw[TCP], 'sport', 0) or 0)
                tcp_dport = int(getattr(raw[TCP], 'dport', 0) or 0)
        except Exception:
            pass
        try:
            if raw is not None and raw.haslayer(UDP):
                udp_sport = int(getattr(raw[UDP], 'sport', 0) or 0)
                udp_dport = int(getattr(raw[UDP], 'dport', 0) or 0)
        except Exception:
            pass

        # Fallback from packet list endpoints so ACL tool can operate on every selected packet.
        rec_src = str(getattr(record, 'src', '') or '').strip()
        rec_dst = str(getattr(record, 'dst', '') or '').strip()
        mac_pat = r'^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$'
        try:
            ipaddress.ip_address(rec_src)
            if not ip_src:
                ip_src = rec_src
        except Exception:
            if re.match(mac_pat, rec_src) and not eth_src:
                eth_src = rec_src
        try:
            ipaddress.ip_address(rec_dst)
            if not ip_dst:
                ip_dst = rec_dst
        except Exception:
            if re.match(mac_pat, rec_dst) and not eth_dst:
                eth_dst = rec_dst

        iface = str(metadata.get('frame_interface_name', '') or metadata.get('interface_name', '') or getattr(record, 'iface', '') or '').strip()
        return PacketAclSnapshot(
            frame_number=int(getattr(record, 'number', 0) or 0),
            protocol=str(getattr(record, 'protocol', '') or '').strip(),
            eth_src=eth_src,
            eth_dst=eth_dst,
            ip_src=ip_src,
            ip_dst=ip_dst,
            ip_proto=ip_proto,
            tcp_src_port=tcp_sport if tcp_sport is not None else None,
            tcp_dst_port=tcp_dport if tcp_dport is not None else None,
            udp_src_port=udp_sport if udp_sport is not None else None,
            udp_dst_port=udp_dport if udp_dport is not None else None,
            interface_name=iface,
        )

    def _can_open_firewall_acl_rules(self) -> bool:
        if not self._has_capture_document():
            return False
        if not self.capture_view:
            return False
        if bool(self.capture_view.is_file_format_view_mode()):
            return False
        selected_records = self._selected_records_from_packet_list()
        if len(selected_records) != 1:
            return False
        return True

    def _on_open_firewall_acl_rules(self):
        if not self.capture_view or not self._has_capture_document():
            QMessageBox.information(self, 'Firewall ACL Rules', 'No capture is loaded.')
            return
        if bool(self.capture_view.is_file_format_view_mode()):
            QMessageBox.information(self, 'Firewall ACL Rules', 'Firewall ACL Rules is not available in file format view mode.')
            return

        selected_records = self._selected_records_from_packet_list()
        if not selected_records:
            QMessageBox.information(self, 'Firewall ACL Rules', 'Please select exactly one packet before creating firewall ACL rules.')
            return
        if len(selected_records) > 1:
            QMessageBox.information(self, 'Firewall ACL Rules', 'Firewall ACL Rules can only be generated from one selected packet.')
            return

        snapshot = self._build_acl_snapshot_from_record(selected_records[0])
        self._show_firewall_acl_dialog(snapshot)

    def _show_firewall_acl_dialog(self, snapshot: PacketAclSnapshot):
        if self._fw_acl_dialog is not None:
            try:
                if self._fw_acl_dialog.isVisible():
                    self._fw_acl_dialog.raise_()
                    self._fw_acl_dialog.activateWindow()
                    return
            except Exception:
                pass
            try:
                self._fw_acl_dialog.close()
            except Exception:
                pass
            self._fw_acl_dialog = None

        dialog = QDialog(self)
        dialog.setWindowTitle('Firewall ACL Rules')
        root = QVBoxLayout(dialog)

        summary_title = QLabel('Selected Packet Summary', dialog)
        summary_title.setStyleSheet('font-weight: 600;')
        root.addWidget(summary_title)

        def _fmt_endpoint(ip_value: str, port_value: int | None) -> str:
            if ip_value:
                return f'{ip_value}:{port_value}' if port_value is not None else ip_value
            return 'N/A'

        source_endpoint = _fmt_endpoint(snapshot.ip_src, snapshot.tcp_src_port if snapshot.tcp_src_port is not None else snapshot.udp_src_port)
        destination_endpoint = _fmt_endpoint(snapshot.ip_dst, snapshot.tcp_dst_port if snapshot.tcp_dst_port is not None else snapshot.udp_dst_port)
        summary_lines = [
            f'Packet No: {int(snapshot.frame_number)}',
            f'Protocol: {snapshot.protocol or "N/A"}',
            f'Source: {source_endpoint}',
            f'Destination: {destination_endpoint}',
            f'Source MAC: {snapshot.eth_src or "N/A"}',
            f'Destination MAC: {snapshot.eth_dst or "N/A"}',
            f'Interface: {snapshot.interface_name or "N/A"}',
        ]
        summary_text = QTextEdit(dialog)
        summary_text.setReadOnly(True)
        summary_text.setFixedHeight(168)
        summary_text.setPlainText('\n'.join(summary_lines))
        root.addWidget(summary_text)

        controls = QGridLayout()
        controls.addWidget(QLabel('Firewall Product', dialog), 0, 0)
        product_combo = QComboBox(dialog)
        product_combo.addItem(PRODUCT_CISCO)
        product_combo.addItem(PRODUCT_IPFILTER)
        product_combo.addItem(PRODUCT_IPFW)
        product_combo.addItem(PRODUCT_IPTABLES)
        product_combo.addItem(PRODUCT_PF)
        product_combo.addItem(PRODUCT_NETSH_OLD)
        product_combo.addItem(PRODUCT_NETSH_NEW)
        controls.addWidget(product_combo, 0, 1, 1, 2)

        controls.addWidget(QLabel('Action', dialog), 1, 0)
        action_allow = QRadioButton('Allow / Permit', dialog)
        action_deny = QRadioButton('Deny / Block', dialog)
        action_allow.setChecked(True)
        action_group = QButtonGroup(dialog)
        action_group.addButton(action_allow)
        action_group.addButton(action_deny)
        controls.addWidget(action_allow, 1, 1)
        controls.addWidget(action_deny, 1, 2)

        controls.addWidget(QLabel('Direction', dialog), 2, 0)
        direction_in = QRadioButton('Inbound', dialog)
        direction_out = QRadioButton('Outbound', dialog)
        direction_in.setChecked(True)
        direction_group = QButtonGroup(dialog)
        direction_group.addButton(direction_in)
        direction_group.addButton(direction_out)
        controls.addWidget(direction_in, 2, 1)
        controls.addWidget(direction_out, 2, 2)
        root.addLayout(controls)

        note = QLabel(
            'Note: Generated rules are templates and assume use on an outside interface. '
            'Review before applying to real firewall.',
            dialog,
        )
        note.setWordWrap(True)
        note.setStyleSheet('color: #555;')
        root.addWidget(note)

        preview_title = QLabel('Generated Rule Preview', dialog)
        preview_title.setStyleSheet('font-weight: 600;')
        root.addWidget(preview_title)
        rule_preview = QTextEdit(dialog)
        rule_preview.setReadOnly(True)
        preview_font = QFont('Consolas')
        preview_font.setStyleHint(QFont.Monospace)
        rule_preview.setFont(preview_font)
        rule_preview.setMinimumHeight(250)
        root.addWidget(rule_preview)

        buttons = QHBoxLayout()
        copy_btn = QPushButton('Copy', dialog)
        save_btn = QPushButton('Save As...', dialog)
        regen_btn = QPushButton('Regenerate', dialog)
        close_btn = QPushButton('Close', dialog)
        buttons.addWidget(copy_btn)
        buttons.addWidget(save_btn)
        buttons.addWidget(regen_btn)
        buttons.addStretch()
        buttons.addWidget(close_btn)
        root.addLayout(buttons)

        def _render_rule():
            product = str(product_combo.currentText() or '')
            action = ACTION_ALLOW if action_allow.isChecked() else ACTION_DENY
            direction = DIRECTION_INBOUND if direction_in.isChecked() else DIRECTION_OUTBOUND
            try:
                text = generate_rules_bundle(snapshot, product, action, direction)
                rule_preview.setPlainText(text)
            except Exception as exc:
                rule_preview.setPlainText(str(exc))

        def _on_copy():
            text = str(rule_preview.toPlainText() or '').strip()
            if not text:
                QMessageBox.information(dialog, 'Firewall ACL Rules', 'No generated rule to copy.')
                return
            try:
                QApplication.clipboard().setText(text)
            except Exception:
                QMessageBox.warning(dialog, 'Firewall ACL Rules', 'Unable to copy the generated rule to clipboard.')

        def _on_save():
            text = str(rule_preview.toPlainText() or '').strip()
            if not text:
                QMessageBox.information(dialog, 'Firewall ACL Rules', 'No generated rule to save.')
                return
            file_path, _ = QFileDialog.getSaveFileName(
                dialog,
                'Save Firewall Rule',
                str(Path.cwd() / f'firewall_rule_frame_{int(snapshot.frame_number)}.txt'),
                'Text Files (*.txt);;All Files (*)',
            )
            if not file_path:
                return
            try:
                Path(file_path).write_text(text + '\n', encoding='utf-8')
            except Exception:
                QMessageBox.warning(
                    dialog,
                    'Firewall ACL Rules',
                    'Unable to save the generated rule file. Please check file permissions.',
                )

        product_combo.currentIndexChanged.connect(lambda _idx: _render_rule())
        action_allow.toggled.connect(lambda _checked: _render_rule())
        action_deny.toggled.connect(lambda _checked: _render_rule())
        direction_in.toggled.connect(lambda _checked: _render_rule())
        direction_out.toggled.connect(lambda _checked: _render_rule())
        copy_btn.clicked.connect(_on_copy)
        save_btn.clicked.connect(_on_save)
        regen_btn.clicked.connect(_render_rule)
        close_btn.clicked.connect(dialog.accept)

        _render_rule()
        dialog.resize(980, 640)
        self._fit_widget_90(dialog)
        self._fw_acl_dialog = dialog
        dialog.finished.connect(lambda _result: setattr(self, '_fw_acl_dialog', None))
        dialog.exec()

    def _close_firewall_acl_dialog(self, reason: str = ''):
        dialog = getattr(self, '_fw_acl_dialog', None)
        if dialog is None:
            return
        if reason:
            try:
                QMessageBox.information(self, 'Firewall ACL Rules', reason)
            except Exception:
                pass
        try:
            dialog.close()
        except Exception:
            pass
        self._fw_acl_dialog = None

    def _topology_protocol_for_record(self, record) -> str:
        proto_raw = str(getattr(record, 'protocol', '') or '').strip().upper()
        low_info = str(getattr(record, 'info', '') or '').lower()

        def _canon(token: str) -> str:
            t = str(token or '').strip().upper()
            if not t:
                return ''
            if t in {'OTHER', 'OTHERS', 'UNKNOWN'}:
                return ''
            if t in {'FRAME', 'RAW', 'PADDING', 'PAYLOAD', 'DATA'}:
                return ''
            if t in {'ETH', 'ETHERNET'}:
                return 'Ethernet'
            if t in {'IPV4', 'IP'}:
                return 'IP'
            if t == 'IPV6':
                return 'IPv6'
            if t in {'ICMPV4'}:
                return 'ICMP'
            if t in {'ICMPV6'}:
                return 'ICMPv6'
            if t.startswith('ISIS'):
                return t
            if re.match(r'^0X[0-9A-F]+$', t):
                eth_map = {
                    '0X0800': 'IP',
                    '0X86DD': 'IPv6',
                    '0X0806': 'ARP',
                    '0X88CC': 'LLDP',
                    '0X8100': 'VLAN',
                }
                return eth_map.get(t, '')
            return t

        tokens = []
        p0 = _canon(proto_raw)
        if p0:
            tokens.append(p0)

        layers = getattr(record, 'layers', [])
        if isinstance(layers, str):
            layers = [layers]
        if isinstance(layers, (list, tuple, set)):
            for item in layers:
                ct = _canon(item)
                if ct:
                    tokens.append(ct)

        # Payload heuristics
        if 'dns' in low_info:
            tokens.append('DNS')
        if 'http' in low_info:
            tokens.append('HTTP')
        if 'tls' in low_info or 'ssl' in low_info:
            tokens.append('TLS')
        if 'whois' in low_info:
            tokens.append('WHOIS')
        if 'ftp' in low_info:
            tokens.append('FTP')

        priority = [
            'DNS', 'HTTP', 'TLS', 'SMB', 'FTP', 'SSH', 'WHOIS', 'DHCP', 'MDNS', 'LLMNR',
            'NTP', 'KERBEROS', 'LDAP', 'CDP', 'STP', 'LOOP', 'ICMPv6', 'ICMP',
            'TCP', 'UDP', 'IPv6', 'IP', 'ARP', 'Ethernet',
        ]
        token_set = set(tokens)
        for p in priority:
            if p in token_set:
                return p
            # match variants like "ISIS HELLO", "ISIS CSNP"
            if p.startswith('ISIS'):
                for t in token_set:
                    if t.startswith('ISIS'):
                        return t

        # Fallbacks: never expose OTHER/OTHERS in UI
        if getattr(record, 'sport', None) is not None or getattr(record, 'dport', None) is not None:
            return 'TCP' if 'tcp' in low_info or str(proto_raw).upper() == 'TCP' else 'UDP' if 'udp' in low_info or str(proto_raw).upper() == 'UDP' else 'IP'
        src = str(getattr(record, 'src', '') or '').strip()
        dst = str(getattr(record, 'dst', '') or '').strip()
        if ':' in src or ':' in dst:
            return 'IPv6'
        if src or dst:
            return 'IP'
        return 'Ethernet'

    def _topology_is_mac(self, text: str) -> bool:
        return bool(re.match(r'^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$', str(text or '').strip()))

    def _topology_addr_filter_expr(self, addr: str) -> str:
        text = str(addr or '').strip()
        if not text:
            return ''
        if self._topology_is_mac(text):
            return f'eth.addr == {text}'
        try:
            ip_obj = ipaddress.ip_address(text)
            if ip_obj.version == 6:
                return f'ipv6.addr == {text}'
            return f'ip.addr == {text}'
        except Exception:
            return f'frame contains "{text}"'

    def _topology_node_type(self, addr: str) -> str:
        text = str(addr or '').strip()
        if not text:
            return 'unknown'
        mac_low = text.lower()
        if mac_low == 'ff:ff:ff:ff:ff:ff' or text == '255.255.255.255':
            return 'broadcast'
        if mac_low.startswith('33:33') or mac_low.startswith('01:00:5e'):
            return 'multicast'
        try:
            ip_obj = ipaddress.ip_address(text)
            if ip_obj.is_multicast:
                return 'multicast'
            if ip_obj.is_private or ip_obj.is_link_local:
                return 'internal'
            return 'external'
        except Exception:
            return 'unknown'

    def _on_open_network_topology_graph(self):
        if not self.capture_view:
            QMessageBox.information(self, 'Network Topology Graph', 'No capture is loaded.')
            return
        if bool(self.capture_view.is_file_format_view_mode()):
            QMessageBox.information(
                self,
                'Network Topology Graph',
                'Topology Graph is unavailable in File Format Mode.\nReload as Capture to view network topology.',
            )
            return

        dialog = QDialog(self)
        dialog.setWindowTitle('Network Topology Graph')
        root = QVBoxLayout(dialog)

        top = QHBoxLayout()
        top.addWidget(QLabel('Layout:', dialog))
        layout_combo = QComboBox(dialog)
        layout_combo.addItems(['Circular', 'Grid'])
        top.addWidget(layout_combo)
        top.addWidget(QLabel('Search endpoint:', dialog))
        search_input = QLineEdit(dialog)
        search_input.setPlaceholderText('IP / IPv6 / MAC / label')
        top.addWidget(search_input, 1)
        refresh_btn = QPushButton('Refresh', dialog)
        top.addWidget(refresh_btn)
        root.addLayout(top)

        protocol_row = QHBoxLayout()
        all_protocol_cb = QCheckBox('All Protocols', dialog)
        all_protocol_cb.setChecked(True)
        protocol_row.addWidget(all_protocol_cb)
        fit_endpoints_btn = QPushButton('Fit Endpoints', dialog)
        fit_btn = QPushButton('Fit View', dialog)
        protocol_row.addWidget(fit_endpoints_btn)
        protocol_row.addWidget(fit_btn)
        protocol_row.addStretch(1)
        root.addLayout(protocol_row)

        protocol_scroll = QScrollArea(dialog)
        protocol_scroll.setWidgetResizable(True)
        protocol_scroll.setFixedHeight(74)
        protocol_host = QWidget(protocol_scroll)
        protocol_layout = QHBoxLayout(protocol_host)
        protocol_layout.setContentsMargins(6, 4, 6, 4)
        protocol_layout.setSpacing(8)
        protocol_layout.addStretch(1)
        protocol_scroll.setWidget(protocol_host)
        root.addWidget(protocol_scroll)

        split = QSplitter(Qt.Orientation.Horizontal, dialog)
        scene = QGraphicsScene(dialog)
        view = TopologyGraphView(scene, dialog)
        split.addWidget(view)

        right_panel = QWidget(dialog)
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(6, 6, 6, 6)
        right_layout.addWidget(QLabel('Details', right_panel))
        details = QTextEdit(right_panel)
        details.setReadOnly(True)
        details.setMinimumWidth(320)
        right_layout.addWidget(details, 1)
        actions = QHBoxLayout()
        apply_filter_btn = QPushButton('Apply Filter', right_panel)
        goto_packet_btn = QPushButton('Go to First Packet', right_panel)
        copy_filter_btn = QPushButton('Copy Filter', right_panel)
        actions.addWidget(apply_filter_btn)
        actions.addWidget(goto_packet_btn)
        actions.addWidget(copy_filter_btn)
        right_layout.addLayout(actions)
        split.addWidget(right_panel)
        split.setSizes([1080, 340])
        root.addWidget(split, 1)

        status_label = QLabel('', dialog)
        root.addWidget(status_label)

        state = {
            'nodes': {},
            'edges': {},
            'protocols': [],
            'enabled_protocols': set(),
            'node_positions': {},
            'protocol_checks': {},
            'selected': {'kind': '', 'id': ''},
            'node_items': {},
            'edge_items': {},
            'edge_label_items': {},
            'edge_port_items': {},
            'node_to_edges': defaultdict(set),
            'visible_nodes': {},
            'visible_edges': {},
            'icon_cache': {},
            'edge_loop_slots': {},
        }
        annotate_timer = QTimer(dialog)
        annotate_timer.setSingleShot(True)
        annotate_timer.setInterval(0)
        annotate_runner = {'fn': None}
        annotate_timer.timeout.connect(lambda: annotate_runner['fn']() if callable(annotate_runner.get('fn')) else None)

        protocol_colors = {
            'DNS': QColor('#0b84f3'),
            'HTTP': QColor('#198754'),
            'TLS': QColor('#6f42c1'),
            'TCP': QColor('#0d6efd'),
            'UDP': QColor('#20c997'),
            'ICMP': QColor('#fd7e14'),
            'ICMPv6': QColor('#ff6b6b'),
            'ARP': QColor('#adb5bd'),
            'SMB': QColor('#7950f2'),
            'SSH': QColor('#dc3545'),
            'FTP': QColor('#ffc107'),
            'WHOIS': QColor('#4c6ef5'),
            'DHCP': QColor('#2f9e44'),
        }
        icon_dir = Path(__file__).resolve().parent.parent / 'image' / 'topo'

        def _get_topology_icon(name: str) -> QPixmap:
            key = str(name or '').strip().lower()
            if key in state['icon_cache']:
                return state['icon_cache'][key]
            candidates = [key]
            if key.endswith('.png'):
                candidates.append(f'{key[:-4]}.jpg')
            elif key.endswith('.jpg'):
                candidates.append(f'{key[:-4]}.png')
            for cand in candidates:
                pix = QPixmap(str(icon_dir / cand))
                if not pix.isNull():
                    state['icon_cache'][key] = pix
                    return pix
            empty = QPixmap()
            state['icon_cache'][key] = empty
            return empty

        def _icon_name_for_node(node: dict) -> str:
            role = str(node.get('role', '') or '').strip().lower()
            ntype = str(node.get('type', '') or '').strip().lower()
            label_low = str(node.get('label', '') or '').strip().lower()
            if role == 'dns_server':
                return 'dns.png'
            if role == 'gateway':
                return 'router.png'
            if role == 'server':
                if 'db' in label_low or 'database' in label_low or 'sql' in label_low:
                    return 'database.png'
                if 'vpn' in label_low:
                    return 'vpn.png'
                return 'server.png'
            if ntype == 'external':
                return 'internet.png'
            if ntype == 'multicast':
                return 'wifi.png'
            if ntype == 'broadcast':
                return 'switch.png'
            if 'vpn' in label_low:
                return 'vpn.png'
            return 'pc.png'

        def _endpoint_id(addr: str) -> str:
            text = str(addr or '').strip()
            if not text:
                return 'special:unknown'
            low = text.lower()
            if low == 'ff:ff:ff:ff:ff:ff' or text == '255.255.255.255':
                return 'special:broadcast'
            if self._topology_is_mac(text):
                return f'mac:{low}'
            try:
                ip_obj = ipaddress.ip_address(text)
                return f'ipv6:{text.lower()}' if ip_obj.version == 6 else f'ip:{text}'
            except Exception:
                return f'id:{low}'

        def _node_label(addr: str) -> str:
            text = str(addr or '').strip()
            if not text:
                return 'Unknown'
            return text

        def _build_graph_data():
            records = self._statistics_scope_records(True)
            nodes = {}
            edges = {}
            for rec in records:
                src = str(getattr(rec, 'src', '') or '').strip()
                dst = str(getattr(rec, 'dst', '') or '').strip()
                if not src or not dst:
                    continue
                proto = self._topology_protocol_for_record(rec)
                size = int(getattr(rec, 'length', 0) or 0)
                pkt_no = int(getattr(rec, 'number', 0) or 0)
                ts = float(getattr(rec, 'epoch_time', 0.0) or 0.0)
                sport = getattr(rec, 'sport', None)
                dport = getattr(rec, 'dport', None)

                src_id = _endpoint_id(src)
                dst_id = _endpoint_id(dst)
                for endpoint_id, endpoint_addr, is_tx in ((src_id, src, True), (dst_id, dst, False)):
                    node = nodes.get(endpoint_id)
                    if node is None:
                        node = {
                            'id': endpoint_id,
                            'addr': endpoint_addr,
                            'label': _node_label(endpoint_addr),
                            'type': self._topology_node_type(endpoint_addr),
                            'protocols': set(),
                            'packet_count': 0,
                            'byte_count': 0,
                            'tx_packets': 0,
                            'rx_packets': 0,
                            'tx_bytes': 0,
                            'rx_bytes': 0,
                            'first_seen': ts,
                            'last_seen': ts,
                            'packets': [],
                            'dns_rx': 0,
                        }
                        nodes[endpoint_id] = node
                    node['protocols'].add(proto)
                    node['packet_count'] += 1
                    node['byte_count'] += size
                    node['packets'].append(pkt_no)
                    node['first_seen'] = min(float(node['first_seen']), ts)
                    node['last_seen'] = max(float(node['last_seen']), ts)
                    if is_tx:
                        node['tx_packets'] += 1
                        node['tx_bytes'] += size
                    else:
                        node['rx_packets'] += 1
                        node['rx_bytes'] += size
                        if str(proto).upper() == 'DNS':
                            node['dns_rx'] += 1

                a_id, b_id = sorted([src_id, dst_id])
                edge_id = f'{a_id}|{b_id}'
                edge = edges.get(edge_id)
                if edge is None:
                    edge = {
                        'id': edge_id,
                        'a': a_id,
                        'b': b_id,
                        'protocols': set(),
                        'protocol_counts': {},
                        'flow_counts': {},
                        'src_ports': set(),
                        'dst_ports': set(),
                        'port_set': set(),
                        'packet_count': 0,
                        'byte_count': 0,
                        'a_to_b_packets': 0,
                        'b_to_a_packets': 0,
                        'a_to_b_bytes': 0,
                        'b_to_a_bytes': 0,
                        'first_seen': ts,
                        'last_seen': ts,
                        'packets': [],
                    }
                    edges[edge_id] = edge
                edge['packet_count'] += 1
                edge['byte_count'] += size
                edge['packets'].append(pkt_no)
                edge['protocols'].add(proto)
                proto_counts = edge.get('protocol_counts', {})
                proto_counts[proto] = int(proto_counts.get(proto, 0) or 0) + 1
                edge['protocol_counts'] = proto_counts
                edge['first_seen'] = min(float(edge['first_seen']), ts)
                edge['last_seen'] = max(float(edge['last_seen']), ts)
                sport_i = int(sport) if sport is not None else None
                dport_i = int(dport) if dport is not None else None
                if sport is not None:
                    edge['src_ports'].add(sport_i)
                    edge['port_set'].add(sport_i)
                if dport is not None:
                    edge['dst_ports'].add(dport_i)
                    edge['port_set'].add(dport_i)
                if src_id == edge['a'] and dst_id == edge['b']:
                    a_port_val = sport_i
                    b_port_val = dport_i
                else:
                    a_port_val = dport_i
                    b_port_val = sport_i
                a_port_text = str(a_port_val) if a_port_val is not None else '-'
                b_port_text = str(b_port_val) if b_port_val is not None else '-'
                flow_key = (str(proto), a_port_text, b_port_text)
                flow_counts = edge.get('flow_counts', {})
                flow_counts[flow_key] = int(flow_counts.get(flow_key, 0) or 0) + 1
                edge['flow_counts'] = flow_counts
                if src_id == edge['a'] and dst_id == edge['b']:
                    edge['a_to_b_packets'] += 1
                    edge['a_to_b_bytes'] += size
                else:
                    edge['b_to_a_packets'] += 1
                    edge['b_to_a_bytes'] += size

            for node in nodes.values():
                if node['type'] == 'broadcast':
                    node['role'] = 'broadcast'
                elif node['type'] == 'multicast':
                    node['role'] = 'multicast'
                elif node['type'] == 'external':
                    node['role'] = 'external'
                elif int(node.get('dns_rx', 0) or 0) >= 2:
                    node['role'] = 'dns_server'
                else:
                    node['role'] = 'server' if node['rx_packets'] > node['tx_packets'] * 1.2 else 'client'

            # Best-effort gateway role: internal node connected to both internal and external.
            neighbors = defaultdict(set)
            for edge in edges.values():
                a = str(edge.get('a'))
                b = str(edge.get('b'))
                neighbors[a].add(b)
                neighbors[b].add(a)
            for node_id, node in nodes.items():
                if str(node.get('type', '') or '') != 'internal':
                    continue
                neigh = neighbors.get(node_id, set())
                if not neigh:
                    continue
                internal_seen = False
                external_seen = False
                for nid in neigh:
                    n = nodes.get(nid)
                    if not n:
                        continue
                    ntype = str(n.get('type', '') or '')
                    if ntype == 'internal':
                        internal_seen = True
                    elif ntype == 'external':
                        external_seen = True
                if internal_seen and external_seen and node.get('role') not in {'dns_server', 'broadcast', 'multicast'}:
                    node['role'] = 'gateway'

            protocols = sorted(
                {
                    str(proto_name or '').strip()
                    for edge in edges.values()
                    for proto_name in set(edge.get('protocols', set()) or set())
                    if str(proto_name or '').strip().upper() not in {'', 'OTHER', 'OTHERS', 'UNKNOWN'}
                }
            )
            state['nodes'] = nodes
            state['edges'] = edges
            state['protocols'] = protocols
            if not state['enabled_protocols']:
                state['enabled_protocols'] = set(protocols)
            else:
                state['enabled_protocols'] = set(p for p in state['enabled_protocols'] if p in protocols)
                if not state['enabled_protocols'] and protocols:
                    state['enabled_protocols'] = set(protocols)

        def _edge_expr(edge: dict) -> str:
            a_node = state['nodes'].get(str(edge.get('a')))
            b_node = state['nodes'].get(str(edge.get('b')))
            if not a_node or not b_node:
                return ''
            expr_a = self._topology_addr_filter_expr(str(a_node.get('addr', '') or ''))
            expr_b = self._topology_addr_filter_expr(str(b_node.get('addr', '') or ''))
            if not expr_a or not expr_b:
                return ''
            expr = f'({expr_a}) && ({expr_b})'
            proto_names = sorted(str(p or '').strip() for p in set(edge.get('protocols', set()) or set()) if str(p or '').strip())
            proto_tokens = []
            for pname in proto_names:
                tok = self._protocol_filter_token(pname)
                if tok:
                    proto_tokens.append(tok)
            if proto_tokens:
                if len(proto_tokens) == 1:
                    expr = f'{expr} && {proto_tokens[0]}'
                else:
                    expr = f'{expr} && ({" || ".join(proto_tokens)})'
            return expr

        def _update_details():
            sel = state['selected']
            kind = str(sel.get('kind', '') or '')
            selected_id = str(sel.get('id', '') or '')
            if kind == 'node':
                node = state['nodes'].get(selected_id)
                if not node:
                    details.setPlainText('No node selected.')
                    return
                lines = [
                    f'Node: {node.get("label", "-")}',
                    f'Address: {node.get("addr", "-")}',
                    f'Role: {node.get("role", "-")}',
                    f'Type: {node.get("type", "-")}',
                    f'Packets: {int(node.get("packet_count", 0) or 0)}',
                    f'Bytes: {int(node.get("byte_count", 0) or 0)}',
                    f'TX/RX Packets: {int(node.get("tx_packets", 0) or 0)} / {int(node.get("rx_packets", 0) or 0)}',
                    f'Protocols: {", ".join(sorted(node.get("protocols", set())))}',
                ]
                details.setPlainText('\n'.join(lines))
                return
            if kind == 'edge':
                edge = state['edges'].get(selected_id)
                if not edge:
                    details.setPlainText('No edge selected.')
                    return
                a_node = state['nodes'].get(str(edge.get('a')))
                b_node = state['nodes'].get(str(edge.get('b')))
                proto_counts = dict(edge.get('protocol_counts', {}) or {})
                proto_parts = [f'{k}({int(v)})' for k, v in sorted(proto_counts.items(), key=lambda kv: (-int(kv[1] or 0), str(kv[0])))]
                proto_text = ', '.join(proto_parts) if proto_parts else '-'
                ports_text = ", ".join(str(v) for v in sorted(edge.get("port_set", set()))[:24]) or "-"
                flow_counts = dict(edge.get('flow_counts', {}) or {})
                proto_agg = {}
                for k, c in flow_counts.items():
                    if not isinstance(k, tuple) or len(k) != 3:
                        continue
                    proto_k = str(k[0] or '').strip()
                    a_port_k = str(k[1] or '').strip() or '-'
                    b_port_k = str(k[2] or '').strip() or '-'
                    cval = int(c or 0)
                    if not proto_k or cval <= 0:
                        continue
                    row = proto_agg.get(proto_k)
                    if row is None:
                        row = {'count': 0, 'a_ports': set(), 'b_ports': set()}
                        proto_agg[proto_k] = row
                    row['count'] += cval
                    if a_port_k != '-':
                        row['a_ports'].add(a_port_k)
                    if b_port_k != '-':
                        row['b_ports'].add(b_port_k)
                flow_rows = sorted(
                    [(p, int(v.get('count', 0) or 0), set(v.get('a_ports', set()) or set()), set(v.get('b_ports', set()) or set())) for p, v in proto_agg.items()],
                    key=lambda r: (-r[1], r[0]),
                )
                def _fmt_port_set(values: set[str]) -> str:
                    vals = sorted(values, key=lambda x: (len(x), x))
                    if not vals:
                        return '-'
                    if len(vals) <= 8:
                        return ','.join(vals)
                    return f'{",".join(vals[:8])} +{len(vals) - 8}'
                flow_preview = '; '.join(f'{p}({n}) <-> A:{_fmt_port_set(a_set)} | B:{_fmt_port_set(b_set)}' for p, n, a_set, b_set in flow_rows[:24]) if flow_rows else '-'
                if len(flow_rows) > 24:
                    flow_preview += f' ... +{len(flow_rows) - 24}'
                packet_list = sorted(int(v) for v in list(edge.get('packets', [])) if int(v) > 0)
                packet_list_text = ", ".join(str(v) for v in packet_list[:200]) if packet_list else "-"
                if len(packet_list) > 200:
                    packet_list_text += f' ... +{len(packet_list) - 200}'
                lines = [
                    f'Edge: {str(a_node.get("label", "-") if a_node else "-")} <-> {str(b_node.get("label", "-") if b_node else "-")}',
                    f'Protocols: {proto_text}',
                    f'Packets: {int(edge.get("packet_count", 0) or 0)}',
                    f'Bytes: {int(edge.get("byte_count", 0) or 0)}',
                    f'A->B / B->A Packets: {int(edge.get("a_to_b_packets", 0) or 0)} / {int(edge.get("b_to_a_packets", 0) or 0)}',
                    f'Ports src: {", ".join(str(v) for v in sorted(edge.get("src_ports", set()))[:12]) or "-"}',
                    f'Ports dst: {", ".join(str(v) for v in sorted(edge.get("dst_ports", set()))[:12]) or "-"}',
                    f'Ports (all): {ports_text}',
                    f'Flow lines: {flow_preview}',
                    f'Packet list: {packet_list_text}',
                    f'Filter: {_edge_expr(edge)}',
                ]
                details.setPlainText('\n'.join(lines))
                return
            details.setPlainText('Select a node or edge to view details.')

        def _set_selected(kind: str, selected_id: str):
            state['selected'] = {'kind': str(kind or ''), 'id': str(selected_id or '')}
            _update_details()
            for node_id, item in state['node_items'].items():
                pen = item.pen()
                pen.setWidthF(2.6 if (kind == 'node' and node_id == selected_id) else 1.1)
                item.setPen(pen)
            for edge_id, item in state['edge_items'].items():
                pen = item.pen()
                pen.setWidthF(max(2.2, pen.widthF()) if (kind == 'edge' and edge_id == selected_id) else max(1.0, pen.widthF() * 0.65))
                item.setPen(pen)

        def _build_protocol_checkboxes():
            existing = dict(state.get('protocol_checks', {}))
            while protocol_layout.count() > 0:
                child = protocol_layout.takeAt(0)
                w = child.widget()
                if w is not None:
                    w.deleteLater()
            checks = {}
            for proto in state.get('protocols', []):
                cb = QCheckBox(proto, protocol_host)
                cb.setChecked(proto in state['enabled_protocols'])
                protocol_layout.addWidget(cb)
                checks[proto] = cb
            protocol_layout.addStretch(1)
            state['protocol_checks'] = checks

            def _on_any_protocol_toggled(_checked=False):
                enabled = {name for name, cb in state['protocol_checks'].items() if cb.isChecked()}
                state['enabled_protocols'] = enabled
                all_protocol_cb.blockSignals(True)
                all_protocol_cb.setChecked(bool(state['protocols']) and len(enabled) == len(state['protocols']))
                all_protocol_cb.blockSignals(False)
                _render_graph(fit_view=True, compact=True)

            for cb in checks.values():
                cb.toggled.connect(_on_any_protocol_toggled)
            if checks:
                _on_any_protocol_toggled()

        def _assign_default_positions(visible_node_ids: list[str], force_reset: bool = False, compact: bool = False):
            if force_reset:
                for nid in visible_node_ids:
                    state['node_positions'].pop(nid, None)
            missing = [nid for nid in visible_node_ids if nid not in state['node_positions']]
            if not missing:
                return
            mode = str(layout_combo.currentText() or 'Circular')
            if mode == 'Grid':
                cols = max(2, int(math.ceil(math.sqrt(len(visible_node_ids)))))
                spacing_x = 130.0 if compact else 180.0
                spacing_y = 96.0 if compact else 130.0
                for idx, nid in enumerate(visible_node_ids):
                    if nid in state['node_positions']:
                        continue
                    col = idx % cols
                    row = idx // cols
                    state['node_positions'][nid] = QPointF(100.0 + col * spacing_x, 90.0 + row * spacing_y)
                return
            radius = max(120.0, 18.0 * len(visible_node_ids)) if compact else max(220.0, 36.0 * len(visible_node_ids))
            center = QPointF(520.0, 360.0)
            total = max(1, len(visible_node_ids))
            for idx, nid in enumerate(visible_node_ids):
                if nid in state['node_positions']:
                    continue
                angle = (2.0 * math.pi * float(idx)) / float(total)
                state['node_positions'][nid] = QPointF(center.x() + radius * math.cos(angle), center.y() + radius * math.sin(angle))

        def _render_graph(fit_view: bool = False, compact: bool = False):
            scene.clear()
            state['node_items'].clear()
            state['edge_items'].clear()
            state['edge_label_items'].clear()
            state['edge_port_items'].clear()
            state['node_to_edges'] = defaultdict(set)

            enabled_protocols = set(state.get('enabled_protocols', set()))
            search_text = str(search_input.text() or '').strip().lower()
            visible_edges = {}
            for edge_id, edge in state['edges'].items():
                edge_protocols = set(str(p or '').strip() for p in set(edge.get('protocols', set()) or set()) if str(p or '').strip())
                if enabled_protocols and edge_protocols and not (edge_protocols & enabled_protocols):
                    continue
                if search_text:
                    a = state['nodes'].get(str(edge.get('a')))
                    b = state['nodes'].get(str(edge.get('b')))
                    a_text = f'{str(a.get("label", "")).lower()} {str(a.get("addr", "")).lower()}' if a else ''
                    b_text = f'{str(b.get("label", "")).lower()} {str(b.get("addr", "")).lower()}' if b else ''
                    proto_text = ' '.join(sorted(p.lower() for p in edge_protocols))
                    if search_text not in a_text and search_text not in b_text and search_text not in proto_text:
                        continue
                visible_edges[edge_id] = edge

            visible_node_ids = set()
            for edge in visible_edges.values():
                visible_node_ids.add(str(edge.get('a')))
                visible_node_ids.add(str(edge.get('b')))
            visible_nodes = {nid: node for nid, node in state['nodes'].items() if nid in visible_node_ids}
            state['visible_nodes'] = visible_nodes
            state['visible_edges'] = visible_edges
            loop_slots = {}
            loop_counts = defaultdict(int)
            for edge_id in sorted(visible_edges.keys()):
                edge = visible_edges.get(edge_id)
                if not edge:
                    continue
                a_id = str(edge.get('a'))
                b_id = str(edge.get('b'))
                if a_id == b_id:
                    slot = int(loop_counts[a_id])
                    loop_counts[a_id] = slot + 1
                    loop_slots[edge_id] = slot
            state['edge_loop_slots'] = loop_slots

            if not visible_nodes:
                status_label.setText('No edges match the selected protocol filter. Enable more protocols or choose All Protocols.')
                details.setPlainText('No visible topology data.')
                scene.setSceneRect(0, 0, 1200, 760)
                return

            _assign_default_positions(sorted(visible_nodes.keys()), force_reset=bool(compact), compact=bool(compact))
            metric_mode = 'Packets'
            max_metric = 1
            for edge in visible_edges.values():
                metric = int(edge.get('byte_count', 0) or 0) if metric_mode == 'Bytes' else int(edge.get('packet_count', 0) or 0)
                max_metric = max(max_metric, metric)

            def _ports_text(values: set[int]) -> str:
                nums = sorted(int(v) for v in set(values or set()))
                if not nums:
                    return ''
                show = nums[:3]
                txt = ','.join(str(v) for v in show)
                if len(nums) > 3:
                    txt += f' +{len(nums) - 3}'
                return txt

            def _edge_protocol_counts(edge: dict, only_enabled: bool = True) -> list[tuple[str, int]]:
                counts = dict(edge.get('protocol_counts', {}) or {})
                if only_enabled and enabled_protocols:
                    counts = {k: v for k, v in counts.items() if k in enabled_protocols}
                if not counts:
                    counts = dict(edge.get('protocol_counts', {}) or {})
                return sorted(
                    [(str(k), int(v)) for k, v in counts.items() if str(k or '').strip() and int(v or 0) > 0],
                    key=lambda kv: (-kv[1], kv[0]),
                )

            def _edge_flow_lines(edge: dict, only_enabled: bool = True) -> list[tuple[str, int, list[str], list[str]]]:
                flow_counts = dict(edge.get('flow_counts', {}) or {})
                proto_agg: dict[str, dict] = {}
                for key, cnt in flow_counts.items():
                    if not isinstance(key, tuple) or len(key) != 3:
                        continue
                    proto = str(key[0] or '').strip()
                    a_ptxt = str(key[1] or '').strip()
                    b_ptxt = str(key[2] or '').strip()
                    cval = int(cnt or 0)
                    if not proto or cval <= 0:
                        continue
                    if only_enabled and enabled_protocols and proto not in enabled_protocols:
                        continue
                    row = proto_agg.get(proto)
                    if row is None:
                        row = {'count': 0, 'a_ports': set(), 'b_ports': set()}
                        proto_agg[proto] = row
                    row['count'] += cval
                    if a_ptxt and a_ptxt != '-':
                        row['a_ports'].add(a_ptxt)
                    if b_ptxt and b_ptxt != '-':
                        row['b_ports'].add(b_ptxt)
                if not proto_agg:
                    # Fallback to protocol summary if no flow rows survive filtering.
                    for proto, cval in _edge_protocol_counts(edge, only_enabled=only_enabled):
                        proto_agg[str(proto)] = {'count': int(cval), 'a_ports': set(), 'b_ports': set()}
                rows: list[tuple[str, int, list[str], list[str]]] = []
                for proto, dat in proto_agg.items():
                    a_vals = sorted(list(dat.get('a_ports', set()) or set()), key=lambda x: (len(x), x))
                    b_vals = sorted(list(dat.get('b_ports', set()) or set()), key=lambda x: (len(x), x))
                    rows.append((str(proto), int(dat.get('count', 0) or 0), a_vals, b_vals))
                rows.sort(key=lambda r: (-int(r[1]), str(r[0])))
                return rows

            def _sort_port_values(values: list[str]) -> list[str]:
                def _key(v: str):
                    t = str(v or '').strip()
                    if t.isdigit():
                        return (0, int(t))
                    return (1, t)
                return sorted(values, key=_key)

            def _fmt_ports_inline(values: list[str]) -> str:
                vals = _sort_port_values([str(v) for v in values if str(v or '').strip() and str(v).strip() != '-'])
                if not vals:
                    return '-'
                # Rule: 1 port -> show 1; 2-3 ports -> show all; >3 -> show first 2 +N
                if len(vals) == 1:
                    return vals[0]
                if len(vals) <= 3:
                    return ','.join(vals)
                return f'{vals[0]},{vals[1]} +{len(vals) - 2}'

            def _edge_protocol_label(edge: dict) -> str:
                rows = _edge_flow_lines(edge, only_enabled=True)
                if not rows:
                    return f'Packets ({int(edge.get("packet_count", 0) or 0)})'
                return '\n'.join(f'{proto}({cnt})' for proto, cnt, _a_ports, _b_ports in rows)

            def _edge_port_labels(edge: dict) -> tuple[str, str]:
                rows = _edge_flow_lines(edge, only_enabled=True)
                if not rows:
                    txt = _ports_text(set(edge.get('port_set', set()) or set()))
                    return txt, txt
                a_txt = '\n'.join(_fmt_ports_inline(a_ports) for _proto, _cnt, a_ports, _b_ports in rows)
                b_txt = '\n'.join(_fmt_ports_inline(b_ports) for _proto, _cnt, _a_ports, b_ports in rows)
                return a_txt, b_txt

            def _edge_color(edge: dict) -> QColor:
                rows = _edge_flow_lines(edge, only_enabled=True)
                key = rows[0][0] if rows else ''
                return QColor(protocol_colors.get(key, QColor('#6c757d')))

            def _edge_points(edge_id: str, edge: dict) -> tuple[QPointF, QPointF]:
                a_id = str(edge.get('a'))
                b_id = str(edge.get('b'))
                pa0 = state['node_positions'].get(a_id, QPointF(0, 0))
                pb0 = state['node_positions'].get(b_id, QPointF(0, 0))
                if a_id != b_id:
                    return pa0, pb0
                # Self-loop: draw a short segment above the node to prevent zero-length overlap at center.
                slot = int(state.get('edge_loop_slots', {}).get(edge_id, 0))
                side = -1.0 if (slot % 2 == 0) else 1.0
                tier = slot // 2
                rise = 34.0 + (16.0 * float(tier))
                span = 22.0 + (7.0 * float(tier))
                cx = pa0.x() + (7.0 * float(tier) * side)
                cy = pa0.y() - rise
                return QPointF(cx - span, cy), QPointF(cx + span, cy)

            def _port_label_pos(pa: QPointF, pb: QPointF, distance: float, is_a_side: bool) -> tuple[float, float]:
                dx = float(pb.x() - pa.x())
                dy = float(pb.y() - pa.y())
                length = max(1.0, math.hypot(dx, dy))
                ux = dx / length
                uy = dy / length
                if length < 90.0:
                    # Keep labels apart on short edges (especially self-loops and compact layouts).
                    dist = max(8.0, min(float(distance), max(8.0, length * 0.36)))
                else:
                    dist = max(28.0, min(float(distance), max(28.0, length - 30.0)))
                if is_a_side:
                    return pa.x() + ux * dist, pa.y() + uy * dist
                return pb.x() - ux * dist, pb.y() - uy * dist

            def _place_text_with_bg(
                text_item: QGraphicsSimpleTextItem,
                bg_item,
                center_x: float,
                center_y: float,
                pad_x: float = 4.0,
                pad_y: float = 1.0,
                angle_deg: float | None = None,
            ):
                br = text_item.boundingRect()
                x = float(center_x) - (br.width() / 2.0)
                y = float(center_y) - (br.height() / 2.0)
                text_item.setPos(x, y)
                text_item.setTransformOriginPoint(br.center())
                text_item.setRotation(float(angle_deg) if angle_deg is not None else 0.0)
                if bg_item is not None:
                    bg_item.setRect(QRectF(x - pad_x, y - pad_y, br.width() + (2.0 * pad_x), br.height() + (2.0 * pad_y)))
                    bg_br = bg_item.rect()
                    bg_item.setTransformOriginPoint(bg_br.center())
                    bg_item.setRotation(float(angle_deg) if angle_deg is not None else 0.0)

            def _place_edge_annotations():
                node_slot_counts = defaultdict(int)
                for edge_id in sorted(visible_edges.keys()):
                    edge = visible_edges.get(edge_id)
                    if not edge:
                        continue
                    pa, pb = _edge_points(edge_id, edge)
                    is_self_loop = str(edge.get('a')) == str(edge.get('b'))
                    loop_slot = int(state.get('edge_loop_slots', {}).get(edge_id, 0))

                    # Keep edge label lightweight and deterministic to avoid UI stalls.
                    label_holder = state['edge_label_items'].get(edge_id) or {}
                    label_item = label_holder.get('text')
                    label_bg = label_holder.get('bg')
                    if label_item is not None:
                        if is_self_loop:
                            cx = (pa.x() + pb.x()) / 2.0
                            cy = min(pa.y(), pb.y()) - 18.0 - (8.0 * float(loop_slot))
                        else:
                            dx = float(pb.x() - pa.x())
                            dy = float(pb.y() - pa.y())
                            length = max(1.0, math.hypot(dx, dy))
                            nx = -dy / length
                            ny = dx / length
                            sign = 1.0 if (hash(edge_id) & 1) else -1.0
                            cx = ((pa.x() + pb.x()) / 2.0) + (nx * 10.0 * sign)
                            cy = ((pa.y() + pb.y()) / 2.0) + (ny * 10.0 * sign)
                        _place_text_with_bg(label_item, label_bg, cx, cy, 5.0, 1.5)

                    # Port labels are pinned near endpoint A/B.
                    port_items = state['edge_port_items'].get(edge_id) or {}
                    for side_key, is_a_side in (('a', True), ('b', False)):
                        holder = port_items.get(side_key)
                        if not holder:
                            continue
                        text_item = holder.get('text')
                        bg_item = holder.get('bg')
                        if text_item is None:
                            continue
                        node_id = str(edge.get('a')) if is_a_side else str(edge.get('b'))
                        degree = len(state['node_to_edges'].get(node_id, set()))
                        if is_self_loop:
                            if is_a_side:
                                cx = pa.x() - 10.0 - (5.0 * float(loop_slot))
                                cy = pa.y() + 10.0 + (5.0 * float(loop_slot))
                            else:
                                cx = pb.x() + 10.0 + (5.0 * float(loop_slot))
                                cy = pb.y() + 10.0 + (5.0 * float(loop_slot))
                            _place_text_with_bg(text_item, bg_item, cx, cy, 4.0, 1.0)
                        else:
                            dx = float(pb.x() - pa.x())
                            dy = float(pb.y() - pa.y())
                            length = max(1.0, math.hypot(dx, dy))
                            nx = -dy / length
                            ny = dx / length
                            if degree > 3:
                                # Dense endpoint: pin label on the line direction and rotate with the wire.
                                ux = dx / length
                                uy = dy / length
                                dir_x = ux if is_a_side else -ux
                                dir_y = uy if is_a_side else -uy
                                anchor = pa if is_a_side else pb
                                br = text_item.boundingRect()
                                endpoint_radius = 22.0
                                gap = 2.0
                                dist_along = endpoint_radius + gap + (br.width() / 2.0)
                                cx = anchor.x() + (dir_x * dist_along)
                                cy = anchor.y() + (dir_y * dist_along)
                                angle = math.degrees(math.atan2(dir_y, dir_x))
                                if angle > 90.0:
                                    angle -= 180.0
                                elif angle < -90.0:
                                    angle += 180.0
                                _place_text_with_bg(text_item, bg_item, cx, cy, 4.0, 1.0, angle_deg=angle)
                            else:
                                sign = 1.0 if (hash(edge_id) & 1) else -1.0
                                dist = 30.0
                                bx, by = _port_label_pos(pa, pb, dist, is_a_side)
                                side_bias = 12.0 + (6.0 * float(loop_slot))
                                cx = bx - (nx * side_bias * sign)
                                cy = by - (ny * side_bias * sign)
                                _place_text_with_bg(text_item, bg_item, cx, cy, 4.0, 1.0)

            annotate_runner['fn'] = _place_edge_annotations

            def _schedule_edge_annotations():
                if not annotate_timer.isActive():
                    annotate_timer.start()

            def _on_node_move(node_id: str, pos: QPointF):
                state['node_positions'][node_id] = QPointF(pos)
                for eid in state['node_to_edges'].get(node_id, set()):
                    edge_item = state['edge_items'].get(eid)
                    edge = state['visible_edges'].get(eid)
                    if edge_item is None or edge is None:
                        continue
                    pa, pb = _edge_points(eid, edge)
                    edge_item.setLine(pa.x(), pa.y(), pb.x(), pb.y())
                _schedule_edge_annotations()

            for edge_id, edge in visible_edges.items():
                a_id = str(edge.get('a'))
                b_id = str(edge.get('b'))
                pa, pb = _edge_points(edge_id, edge)
                color = _edge_color(edge)
                metric = int(edge.get('byte_count', 0) or 0) if metric_mode == 'Bytes' else int(edge.get('packet_count', 0) or 0)
                width = 1.2 + (4.4 * (float(metric) / float(max_metric))) if max_metric > 0 else 1.2
                edge_item = TopologyEdgeItem(edge_id, _set_selected)
                edge_item.setPen(QPen(color, width))
                edge_item.setLine(pa.x(), pa.y(), pb.x(), pb.y())
                scene.addItem(edge_item)
                state['edge_items'][edge_id] = edge_item
                state['node_to_edges'][a_id].add(edge_id)
                state['node_to_edges'][b_id].add(edge_id)
                lbl = scene.addSimpleText(_edge_protocol_label(edge))
                lbl.setBrush(QBrush(QColor(35, 35, 35)))
                lbl_bg = scene.addRect(QRectF(0.0, 0.0, 1.0, 1.0), QPen(Qt.NoPen), QBrush(QColor(255, 255, 255, 220)))
                # Keep protocol/port labels above all nodes/icons.
                lbl_bg.setZValue(119)
                lbl.setZValue(120)
                state['edge_label_items'][edge_id] = {'text': lbl, 'bg': lbl_bg}

                a_ports_text, b_ports_text = _edge_port_labels(edge)
                port_items = {'a': None, 'b': None}
                if a_ports_text:
                    a_item = scene.addSimpleText(a_ports_text)
                    a_item.setBrush(QBrush(QColor(40, 40, 40)))
                    a_item.setZValue(120)
                    a_bg = scene.addRect(QRectF(0.0, 0.0, 1.0, 1.0), QPen(Qt.NoPen), QBrush(QColor(255, 255, 255, 218)))
                    a_bg.setZValue(119)
                    port_items['a'] = {'text': a_item, 'bg': a_bg}
                if b_ports_text:
                    b_item = scene.addSimpleText(b_ports_text)
                    b_item.setBrush(QBrush(QColor(40, 40, 40)))
                    b_item.setZValue(120)
                    b_bg = scene.addRect(QRectF(0.0, 0.0, 1.0, 1.0), QPen(Qt.NoPen), QBrush(QColor(255, 255, 255, 218)))
                    b_bg.setZValue(119)
                    port_items['b'] = {'text': b_item, 'bg': b_bg}
                state['edge_port_items'][edge_id] = port_items

            for node_id, node in visible_nodes.items():
                pos = state['node_positions'].get(node_id, QPointF(0, 0))
                role = str(node.get('role', 'client') or 'client')
                node_color = QColor('#ffd43b') if role == 'server' else (QColor('#4dabf7') if role == 'client' else QColor('#adb5bd'))
                icon_name = _icon_name_for_node(node)
                icon_pix = _get_topology_icon(icon_name)
                item = TopologyNodeItem(node_id, str(node.get('label', node_id)), 22.0, node_color, _on_node_move, _set_selected, icon=icon_pix)
                item.setPos(pos)
                scene.addItem(item)
                state['node_items'][node_id] = item

            _place_edge_annotations()

            rect = scene.itemsBoundingRect()
            if rect.isNull():
                rect = scene.sceneRect()
            rect = rect.adjusted(-80, -80, 80, 80)
            scene.setSceneRect(rect)
            status_label.setText(
                f'Nodes: {len(visible_nodes)} / {len(state["nodes"])} | '
                f'Edges: {len(visible_edges)} / {len(state["edges"])} | '
                f'Protocols: {len(state["enabled_protocols"])} / {len(state["protocols"])}'
            )
            if fit_view:
                try:
                    view.fitInView(scene.sceneRect(), Qt.KeepAspectRatio)
                except Exception:
                    pass
            _update_details()

        def _refresh_topology():
            _build_graph_data()
            _build_protocol_checkboxes()
            _render_graph(fit_view=True)

        def _on_all_protocol_toggled(checked: bool):
            val = bool(checked)
            for cb in state['protocol_checks'].values():
                cb.blockSignals(True)
                cb.setChecked(val)
                cb.blockSignals(False)
            state['enabled_protocols'] = set(state['protocols']) if val else set()
            _render_graph(fit_view=True, compact=True)

        def _fit_endpoints():
            visible_ids = sorted(state.get('visible_nodes', {}).keys())
            if not visible_ids:
                return
            _assign_default_positions(visible_ids, force_reset=True, compact=True)
            _render_graph(fit_view=True)

        def _selected_filter_expr() -> str:
            sel = state['selected']
            kind = str(sel.get('kind', '') or '')
            selected_id = str(sel.get('id', '') or '')
            if kind == 'node':
                node = state['nodes'].get(selected_id)
                return self._topology_addr_filter_expr(str(node.get('addr', '') or '')) if node else ''
            if kind == 'edge':
                edge = state['edges'].get(selected_id)
                return _edge_expr(edge) if edge else ''
            return ''

        def _apply_selected_filter():
            expr = _selected_filter_expr()
            if expr:
                self._set_display_filter_text(expr, apply_now=True)
            else:
                QMessageBox.information(dialog, 'Network Topology Graph', 'Select a node or edge first.')

        def _goto_selected_first_packet():
            sel = state['selected']
            kind = str(sel.get('kind', '') or '')
            selected_id = str(sel.get('id', '') or '')
            packet_no = 0
            if kind == 'node':
                node = state['nodes'].get(selected_id)
                if node and node.get('packets'):
                    packet_no = int(node.get('packets')[0] or 0)
            elif kind == 'edge':
                edge = state['edges'].get(selected_id)
                if edge and edge.get('packets'):
                    packet_no = int(edge.get('packets')[0] or 0)
            if packet_no > 0:
                try:
                    self.capture_view.goto_packet_number(packet_no)
                except Exception:
                    pass
            else:
                QMessageBox.information(dialog, 'Network Topology Graph', 'No packet is associated with the current selection.')

        def _copy_selected_filter():
            expr = _selected_filter_expr()
            if expr:
                QApplication.clipboard().setText(expr)
            else:
                QMessageBox.information(dialog, 'Network Topology Graph', 'No filter expression available for current selection.')

        refresh_btn.clicked.connect(_refresh_topology)
        layout_combo.currentTextChanged.connect(lambda _v: _render_graph(fit_view=True))
        search_input.textChanged.connect(lambda _v: _render_graph())
        all_protocol_cb.toggled.connect(_on_all_protocol_toggled)
        fit_endpoints_btn.clicked.connect(_fit_endpoints)
        fit_btn.clicked.connect(lambda: view.fitInView(scene.sceneRect(), Qt.KeepAspectRatio))
        apply_filter_btn.clicked.connect(_apply_selected_filter)
        goto_packet_btn.clicked.connect(_goto_selected_first_packet)
        copy_filter_btn.clicked.connect(_copy_selected_filter)

        _refresh_topology()
        dialog.resize(1520, 860)
        self._fit_widget_90(dialog)
        dialog.exec()

    def _current_display_filter_text(self) -> str:
        if not self.capture_view:
            return ''
        return str(self.capture_view.display_filter_input.text() or '').strip()

    def _set_display_filter_text(self, expression: str, apply_now: bool):
        if not self.capture_view:
            return
        self.capture_view.display_filter_input.setText(str(expression or '').strip())
        if apply_now:
            self.capture_view.apply_display_filter()

    def _build_combined_filter(self, base_expr: str, mode: str) -> str:
        current = self._current_display_filter_text()
        atom = str(base_expr or '').strip()
        if not atom:
            return current
        mode = str(mode or 'selected').strip().lower()
        if mode == 'selected':
            return atom
        if mode == 'not_selected':
            return f'!({atom})'
        if not current:
            if mode in {'and_not_selected', 'or_not_selected'}:
                return f'!({atom})'
            return atom
        if mode == 'and_selected':
            return f'({current}) && ({atom})'
        if mode == 'or_selected':
            return f'({current}) || ({atom})'
        if mode == 'and_not_selected':
            return f'({current}) && !({atom})'
        if mode == 'or_not_selected':
            return f'({current}) || !({atom})'
        return atom

    def _load_analyze_custom_columns(self) -> list[dict]:
        prefs = self._load_edit_preferences()
        columns = list((prefs or {}).get('columns', []) or [])
        base_fields = {
            'frame.number', 'frame.time_relative', 'ip.src', 'ip.dst', '_ws.col.protocol', 'frame.len', '_ws.col.info'
        }
        result = []
        for item in columns:
            if not isinstance(item, dict):
                continue
            field = str(item.get('field', '') or '').strip()
            detail_query = str(item.get('detail_query', '') or '').strip()
            detail_key = str(item.get('detail_key', '') or '').strip()
            detail_path = item.get('detail_path', [])
            if not isinstance(detail_path, list):
                detail_path = []
            detail_path = [str(v).strip() for v in detail_path if str(v).strip()]
            if field in base_fields and not detail_query:
                continue
            title = str(item.get('title', '') or '').strip() or field or detail_query
            if not title:
                continue
            occurrence = int(item.get('occurrence', 0) or 0)
            result.append({
                'title': title,
                'field': field,
                'detail_query': detail_query,
                'detail_key': detail_key,
                'detail_path': detail_path,
                'occurrence': max(0, occurrence),
                'alignment': str(item.get('alignment', 'Left') or 'Left'),
                'displayed': bool(item.get('displayed', True)),
            })
        return result

    def _save_analyze_custom_columns(self):
        prefs = self._load_edit_preferences()
        base_columns = []
        for item in list((prefs or {}).get('columns', []) or []):
            if not isinstance(item, dict):
                continue
            field = str(item.get('field', '') or '').strip()
            if field in {'frame.number', 'frame.time_relative', 'ip.src', 'ip.dst', '_ws.col.protocol', 'frame.len'}:
                base_columns.append(item)
        info_col = {
            'index': 6,
            'displayed': True,
            'title': 'Info',
            'field': '_ws.col.info',
            'occurrence': 1,
            'alignment': 'Left',
        }
        new_columns = []
        for idx, item in enumerate(base_columns):
            spec = dict(item)
            spec['index'] = idx
            new_columns.append(spec)

        for item in self._analyze_custom_columns:
            if not isinstance(item, dict):
                continue
            title = str(item.get('title', '') or '').strip()
            field = str(item.get('field', '') or '').strip()
            detail_query = str(item.get('detail_query', '') or '').strip()
            detail_key = str(item.get('detail_key', '') or '').strip()
            detail_path = item.get('detail_path', [])
            if not isinstance(detail_path, list):
                detail_path = []
            detail_path = [str(v).strip() for v in detail_path if str(v).strip()]
            if not title:
                continue
            new_columns.append({
                'index': len(new_columns),
                'displayed': bool(item.get('displayed', True)),
                'title': title,
                'field': field,
                'detail_query': detail_query,
                'detail_key': detail_key,
                'detail_path': detail_path,
                'occurrence': int(item.get('occurrence', 0) or 0),
                'alignment': str(item.get('alignment', 'Left') or 'Left'),
            })

        info_col['index'] = len(new_columns)
        new_columns.append(info_col)
        prefs['columns'] = new_columns
        self._save_edit_preferences(prefs)

    def _ensure_analyze_custom_columns_applied(self):
        cv = self.capture_view
        if not cv:
            return
        table = cv.table
        base_headers = ['No.', 'Time', 'Source', 'Destination', 'Protocol', 'Length']
        extra_headers = [str(item.get('title', item.get('field', item.get('detail_query', ''))) or '') for item in self._analyze_custom_columns]
        headers = base_headers + extra_headers + ['Info']
        table.setColumnCount(len(headers))
        table.setHorizontalHeaderLabels(headers)
        custom_width = self._custom_column_default_width(table)
        for idx in range(6, len(headers) - 1):
            table.setColumnWidth(idx, custom_width)
        info_col = len(headers) - 1
        table.setColumnWidth(info_col, max(320, table.columnWidth(info_col) or 320))
        if hasattr(table, 'apply_content_resize_layout'):
            table.apply_content_resize_layout()
        self._refresh_analyze_custom_column_cells()

    def _custom_column_default_width(self, table) -> int:
        if table is None:
            return 72
        viewport_w = table.viewport().width() if table.viewport() is not None else table.width()
        if viewport_w <= 0:
            viewport_w = table.width()
        return max(72, int((float(viewport_w) * 2.0) / 15.0))

    def _fit_all_custom_columns(self):
        cv = self.capture_view
        if not cv or not self._analyze_custom_columns:
            return
        table = cv.table
        custom_width = self._custom_column_default_width(table)
        for extra_idx, _cfg in enumerate(self._analyze_custom_columns):
            col = 6 + extra_idx
            if 0 <= col < table.columnCount():
                table.setColumnWidth(col, custom_width)

    def _extract_field_value_for_column(self, record, field: str, occurrence: int = 0) -> str:
        try:
            values = self._display_filter_helper._resolve_field_values(record, field)
        except Exception:
            values = []
        if not values:
            return ''
        index = int(occurrence or 0)
        if index < 0:
            index = 0
        if index >= len(values):
            index = len(values) - 1
        value = values[index]
        if isinstance(value, bool):
            return 'True' if value else 'False'
        return str(value)

    def _normalize_detail_key(self, title: str) -> str:
        text = str(title or '').strip()
        if not text:
            return ''
        if ': ' in text:
            text = text.split(': ', 1)[0].strip()
        elif ' = ' in text:
            text = text.split(' = ', 1)[0].strip()
        if ',' in text:
            text = text.split(',', 1)[0].strip()
        text = re.sub(r'\s+', ' ', text)
        return text.casefold()

    def _stable_detail_path(self, path_keys) -> list[str]:
        values = [str(v).strip().casefold() for v in (path_keys or []) if str(v).strip()]
        if not values:
            return []
        # Drop packet-specific frame root so custom columns resolve across all packets.
        if values[0].startswith('frame '):
            values = values[1:]
        return values

    def _extract_detail_values_for_column(self, record, detail_query: str, detail_key: str = '', detail_path=None) -> str:
        query = str(detail_query or '').strip().casefold()
        key = str(detail_key or '').strip().casefold()
        target_path = self._stable_detail_path(detail_path)
        if not query and not key and not target_path:
            return ''

        metadata = getattr(record, 'metadata', {}) if record else {}
        cache_key = (query, key, tuple(target_path))
        if isinstance(metadata, dict):
            detail_cache = metadata.setdefault('_custom_detail_value_cache', {})
            if isinstance(detail_cache, dict) and cache_key in detail_cache:
                return str(detail_cache.get(cache_key, '') or '')

        try:
            nodes = self._display_filter_helper._detail_nodes(record)
        except Exception:
            nodes = []

        def _collect_values(require_path: bool) -> list[str]:
            values = []
            for node in nodes or []:
                if not isinstance(node, dict):
                    continue
                node_key = str(node.get('key', '') or '').strip().casefold()
                title = str(node.get('title', '') or '').strip()
                low = title.casefold()
                if key and node_key != key:
                    continue
                if require_path and target_path:
                    node_path = str(node.get('path', '') or '').strip().casefold()
                    target_text = ' / '.join(target_path).casefold()
                    if not node_path or not node_path.endswith(target_text):
                        continue
                if query and query not in low and query != node_key:
                    continue
                value = str(node.get('value', '') or '').strip()
                if not value:
                    if ': ' in title:
                        value = title.split(': ', 1)[1].strip()
                    elif ' = ' in title:
                        value = title.split(' = ', 1)[1].strip()
                    else:
                        value = title
                if value and value not in values:
                    values.append(value)
            return values

        found = _collect_values(require_path=True)
        if not found and target_path:
            found = _collect_values(require_path=False)
        result = ', '.join(found)
        if isinstance(metadata, dict):
            detail_cache = metadata.setdefault('_custom_detail_value_cache', {})
            if isinstance(detail_cache, dict):
                detail_cache[cache_key] = result
        return result

    def _refresh_analyze_custom_column_cells(self):
        cv = self.capture_view
        if not cv or not self._analyze_custom_columns:
            return
        table = cv.table
        if table.columnCount() < 7 + len(self._analyze_custom_columns):
            self._ensure_analyze_custom_columns_applied()
            return
        row_count = int(table.rowCount() or 0)
        visible_count = len(cv.visible_indices)
        if row_count <= 0 or visible_count <= 0:
            return
        if row_count <= 50:
            start, end = self._visible_table_row_range(tight=True)
            if start < 0 or end < start:
                start = 0
                end = min(row_count - 1, 16)
            self._schedule_custom_column_refresh(list(range(start, end + 1)), replace=True)
            return
        start, end = self._visible_table_row_range(tight=False)
        if start < 0 or end < start:
            return
        self._schedule_custom_column_refresh(list(range(start, end + 1)), replace=True)

    def _schedule_visible_custom_column_refresh(self):
        cv = self.capture_view
        if not cv or not self._analyze_custom_columns:
            return
        table = cv.table
        row_count = int(table.rowCount() or 0)
        if row_count <= 0:
            return
        if row_count <= 50:
            start, end = self._visible_table_row_range(tight=True)
            if start < 0 or end < start:
                start = 0
                end = min(row_count - 1, 16)
            self._schedule_custom_column_refresh(list(range(start, end + 1)), replace=True)
            return
        start, end = self._visible_table_row_range(tight=False)
        if start < 0 or end < start:
            return
        self._schedule_custom_column_refresh(list(range(start, end + 1)), replace=True)

    def _visible_table_row_range(self, tight: bool = False) -> tuple[int, int]:
        cv = self.capture_view
        if not cv:
            return -1, -1
        table = cv.table
        row_count = int(table.rowCount() or 0)
        if row_count <= 0:
            return -1, -1
        top = int(table.rowAt(0))
        bottom = int(table.rowAt(max(0, table.viewport().height() - 1)))
        if top < 0:
            top = 0
        if bottom < 0:
            bottom = min(row_count - 1, top + 64)
        if not bool(tight):
            margin = 20
            if row_count <= 200:
                margin = 8
            # Add a small margin to avoid blank cells right after a scroll.
            top = max(0, top - margin)
            bottom = min(row_count - 1, bottom + margin)
        return top, bottom

    def _schedule_custom_column_refresh(self, rows, replace: bool):
        cv = self.capture_view
        if not cv or not self._analyze_custom_columns:
            return
        table = cv.table
        if replace:
            normalized = []
            seen = set()
            for row in rows or []:
                try:
                    idx = int(row)
                except Exception:
                    continue
                if idx < 0 or idx >= table.rowCount():
                    continue
                if idx in seen:
                    continue
                seen.add(idx)
                normalized.append(idx)
            self._custom_column_refresh_pending_rows = deque(normalized)
            self._custom_column_refresh_pending_set = set(normalized)
            self._custom_column_refresh_generation += 1
        else:
            for row in rows or []:
                try:
                    idx = int(row)
                except Exception:
                    continue
                if idx < 0 or idx >= table.rowCount():
                    continue
                if idx in self._custom_column_refresh_pending_set:
                    continue
                self._custom_column_refresh_pending_rows.append(idx)
                self._custom_column_refresh_pending_set.add(idx)
            self._custom_column_refresh_generation += 1
        self._custom_column_refresh_dispatch_generation = int(self._custom_column_refresh_generation)
        if not self._custom_column_refresh_dispatch_timer.isActive():
            self._custom_column_refresh_dispatch_timer.start()

    def _dispatch_custom_column_refresh(self):
        generation = int(self._custom_column_refresh_dispatch_generation)
        self._drain_custom_column_refresh(generation)

    def _drain_custom_column_refresh(self, generation: int):
        if int(generation) != int(self._custom_column_refresh_generation):
            return
        cv = self.capture_view
        if not cv or not self._analyze_custom_columns:
            self._custom_column_refresh_pending_rows = deque()
            self._custom_column_refresh_pending_set = set()
            return
        table = cv.table
        pending = self._custom_column_refresh_pending_rows
        if not pending:
            self._custom_column_refresh_pending_set = set()
            return

        started = time.perf_counter()
        processed = 0
        max_rows_per_tick = 32
        max_tick_seconds = 0.0035
        try:
            startup_priority = bool(getattr(cv, '_startup_priority_mode', False))
            if startup_priority:
                max_rows_per_tick = 4
                max_tick_seconds = 0.0008
            elif bool(cv.is_bulk_loading()):
                # During initial file load, keep UI thread mostly free.
                max_rows_per_tick = 8
                max_tick_seconds = 0.0012
        except Exception:
            pass
        try:
            scrollbar = table.verticalScrollBar()
            if scrollbar is not None and bool(scrollbar.isSliderDown()):
                # Keep interaction smooth while user drags the list.
                max_rows_per_tick = 10
                max_tick_seconds = 0.0018
        except Exception:
            pass
        table.setUpdatesEnabled(False)
        try:
            while pending and processed < max_rows_per_tick and (time.perf_counter() - started) < max_tick_seconds:
                row = pending.popleft()
                self._custom_column_refresh_pending_set.discard(int(row))
                self._refresh_analyze_custom_columns_for_row(int(row))
                processed += 1
        finally:
            table.setUpdatesEnabled(True)

        if pending and int(generation) == int(self._custom_column_refresh_generation):
            QTimer.singleShot(1, lambda gen=generation: self._drain_custom_column_refresh(gen))

    def _refresh_analyze_custom_columns_for_row(self, row: int):
        cv = self.capture_view
        if not cv or not self._analyze_custom_columns:
            return
        table = cv.table
        if row < 0 or row >= table.rowCount() or row >= len(cv.visible_indices):
            return
        rec_idx = cv.visible_indices[row]
        if rec_idx < 0 or rec_idx >= len(cv.records):
            return
        record = cv.records[rec_idx]
        for extra_idx, cfg in enumerate(self._analyze_custom_columns):
            col = 6 + extra_idx
            item = table.item(row, col)
            if item is None:
                item = QTableWidgetItem()
                table.setItem(row, col, item)
                if hasattr(table, '_apply_item_alignment'):
                    try:
                        table._apply_item_alignment(item, col)
                    except Exception:
                        pass
                base_item = table.item(row, 0)
                if base_item is not None:
                    try:
                        item.setBackground(base_item.background())
                        item.setForeground(base_item.foreground())
                    except Exception:
                        pass
            field = str(cfg.get('field', '') or '').strip()
            detail_query = str(cfg.get('detail_query', '') or '').strip()
            detail_key = str(cfg.get('detail_key', '') or '').strip()
            detail_path = cfg.get('detail_path', []) if isinstance(cfg, dict) else []
            occurrence = int(cfg.get('occurrence', 0) or 0)
            value_cache_key = (
                field.casefold(),
                int(occurrence),
                detail_query.casefold(),
                detail_key.casefold(),
                tuple(self._stable_detail_path(detail_path)),
            )
            metadata = getattr(record, 'metadata', {}) if record else {}
            cached_value = None
            if isinstance(metadata, dict):
                value_cache = metadata.setdefault('_custom_column_value_cache', {})
                if isinstance(value_cache, dict):
                    cached_value = value_cache.get(value_cache_key, None)

            if cached_value is None:
                value = self._extract_field_value_for_column(record, field, occurrence) if field else ''
                if not value and detail_query:
                    value = self._extract_detail_values_for_column(record, detail_query, detail_key=detail_key, detail_path=detail_path)
                if isinstance(metadata, dict):
                    value_cache = metadata.setdefault('_custom_column_value_cache', {})
                    if isinstance(value_cache, dict):
                        value_cache[value_cache_key] = str(value or '')
            else:
                value = str(cached_value or '')

            text = str(value or '')
            if item.text() != text:
                item.setText(text)

    def _on_records_refined_rows(self, rows):
        if not rows:
            return
        cv = self.capture_view
        if not cv or not self._analyze_custom_columns:
            return
        start, end = self._visible_table_row_range()
        if start < 0 or end < start:
            return
        visible_rows = set(range(start, end + 1))
        filtered = []
        for row in rows:
            try:
                idx = int(row)
            except Exception:
                continue
            if idx in visible_rows:
                filtered.append(idx)
        if filtered:
            self._schedule_custom_column_refresh(filtered, replace=False)

    def _schedule_custom_column_fit(self, delay_ms: int = 120):
        if self._custom_column_fit_timer is not None:
            try:
                self._custom_column_fit_timer.stop()
            except Exception:
                pass
        timer = QTimer(self)
        timer.setSingleShot(True)
        timer.timeout.connect(self._fit_all_custom_columns)
        timer.start(max(0, int(delay_ms)))
        self._custom_column_fit_timer = timer

    def _fit_custom_column_width(self, column: int):
        cv = self.capture_view
        if not cv:
            return
        table = cv.table
        if column < 0 or column >= table.columnCount():
            return
        table.setColumnWidth(column, self._custom_column_default_width(table))

    def _load_display_filter_macros(self) -> list[dict]:
        settings = QSettings('Packetra', 'Packetra')
        try:
            raw = str(settings.value('analyze/display_filter_macros', '[]', str) or '[]')
            payload = json.loads(raw)
        except Exception:
            payload = []
        result = []
        if isinstance(payload, list):
            for item in payload:
                if not isinstance(item, dict):
                    continue
                name = str(item.get('name', '') or '').strip()
                expression = str(item.get('expression', '') or '').strip()
                comment = str(item.get('comment', '') or '').strip()
                if name and expression:
                    result.append({'name': name, 'expression': expression, 'comment': comment})
        return result

    def _save_display_filter_macros(self, macros: list[dict]):
        normalized = []
        for item in macros or []:
            if not isinstance(item, dict):
                continue
            name = str(item.get('name', '') or '').strip()
            expression = str(item.get('expression', '') or '').strip()
            comment = str(item.get('comment', '') or '').strip()
            if name and expression:
                normalized.append({'name': name, 'expression': expression, 'comment': comment})
        settings = QSettings('Packetra', 'Packetra')
        settings.setValue('analyze/display_filter_macros', json.dumps(normalized, ensure_ascii=True))

    def _on_display_filter_macros(self):
        macros = self._load_display_filter_macros()
        dialog = CaptureFiltersDialog(self, macros, lambda expr, iface=None: (True, ''))
        dialog.setWindowTitle('Display Filter Macros')
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return

        normalized = []
        seen = set()
        for item in dialog.presets():
            name = str(item.get('name', '') or '').strip()
            expression = str(item.get('expression', '') or '').strip()
            comment = str(item.get('comment', '') or '').strip()
            if not name or not expression:
                QMessageBox.warning(self, 'Display Filter Macros', 'Macro name and expression are required.')
                return
            if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', name):
                QMessageBox.warning(self, 'Display Filter Macros', f'Invalid macro name: {name}')
                return
            key = name.casefold()
            if key in seen:
                QMessageBox.warning(self, 'Display Filter Macros', f'Duplicate macro name: {name}')
                return
            seen.add(key)
            normalized.append({'name': name, 'expression': expression, 'comment': comment})

        self._save_display_filter_macros(normalized)
        if self.capture_view:
            try:
                self.capture_view.refresh_preferences_from_settings()
            except Exception:
                pass

    def _display_filter_field_catalog(self) -> list[str]:
        catalog = [
            'frame.number', 'frame.len', 'frame.time_delta',
            'eth.src', 'eth.dst', 'eth.addr', 'eth.type',
            'ip.src', 'ip.dst', 'ip.addr', 'ip.proto', 'ip.ttl',
            'ipv6.src', 'ipv6.dst', 'ipv6.addr',
            'tcp.stream', 'tcp.port', 'tcp.srcport', 'tcp.dstport', 'tcp.flags.syn', 'tcp.flags.ack',
            'udp.stream', 'udp.port', 'udp.srcport', 'udp.dstport',
            'dns.qry.name', 'dns.qry.type', 'dns.flags.response',
            'http.host', 'http.request.method', 'http.request.uri',
            'tls.handshake', 'tls.handshake.type', 'tls.handshake.extensions_server_name',
            'detail', 'detail.title', 'detail.key', 'detail.value', 'detail.pair', 'detail.path',
        ]
        field_pattern = re.compile(r'^[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+$', re.IGNORECASE)
        if self.capture_view:
            try:
                for token in self.capture_view._filter_autocomplete_tokens():
                    text = str(token or '').strip()
                    if field_pattern.fullmatch(text) and text not in catalog:
                        catalog.append(text)
            except Exception:
                pass
        return sorted(catalog)

    def _on_display_filter_expression(self):
        dialog = QDialog(self)
        dialog.setWindowTitle('Display Filter Expression')
        layout = QVBoxLayout(dialog)

        form = QGridLayout()
        form.addWidget(QLabel('Field:'), 0, 0)
        field_combo = QComboBox(dialog)
        field_combo.setEditable(True)
        field_combo.addItems(self._display_filter_field_catalog())
        form.addWidget(field_combo, 0, 1)

        form.addWidget(QLabel('Relation:'), 1, 0)
        relation_combo = QComboBox(dialog)
        relation_combo.addItems(['==', '!=', 'contains', '>=', '<=', '>', '<'])
        form.addWidget(relation_combo, 1, 1)

        form.addWidget(QLabel('Value:'), 2, 0)
        value_input = QLineEdit(dialog)
        form.addWidget(value_input, 2, 1)

        form.addWidget(QLabel('Combine with next filter:'), 3, 0)
        combine_combo = QComboBox(dialog)
        combine_combo.addItems([
            'Replace next filter',
            'AND with next filter',
            'OR with next filter',
            'AND NOT with next filter',
            'OR NOT with next filter',
        ])
        form.addWidget(combine_combo, 3, 1)
        layout.addLayout(form)

        preview_label = QLabel('Preview: ', dialog)
        layout.addWidget(preview_label)

        button_row = QHBoxLayout()
        copy_btn = QPushButton('Copy', dialog)
        insert_btn = QPushButton('Insert into Filter Bar', dialog)
        apply_btn = QPushButton('Apply', dialog)
        ok_btn = QPushButton('OK', dialog)
        cancel_btn = QPushButton('Cancel', dialog)
        for btn in (copy_btn, insert_btn, apply_btn, ok_btn, cancel_btn):
            button_row.addWidget(btn)
        layout.addLayout(button_row)

        def _needs_quotes(field: str, value: str) -> bool:
            if not value:
                return False
            text = str(value)
            if re.fullmatch(r'-?\d+(\.\d+)?', text):
                return False
            if field in {'ip.src', 'ip.dst', 'ip.addr', 'ipv6.src', 'ipv6.dst', 'ipv6.addr'}:
                return False
            return True

        def _expression() -> str:
            field = str(field_combo.currentText() or '').strip()
            relation = str(relation_combo.currentText() or '==').strip()
            value = str(value_input.text() or '').strip()
            if not field:
                return ''
            if not value:
                return field
            right = f'"{value}"' if _needs_quotes(field, value) else value
            return f'{field} {relation} {right}'

        def _combined_expression() -> str:
            base = _expression()
            mode = str(combine_combo.currentText() or '')
            if mode.startswith('AND NOT'):
                return self._build_combined_filter(base, 'and_not_selected')
            if mode.startswith('OR NOT'):
                return self._build_combined_filter(base, 'or_not_selected')
            if mode.startswith('AND'):
                return self._build_combined_filter(base, 'and_selected')
            if mode.startswith('OR'):
                return self._build_combined_filter(base, 'or_selected')
            return self._build_combined_filter(base, 'selected')

        def _refresh_preview():
            preview_label.setText(f'Preview: {_combined_expression()}')

        field_combo.currentTextChanged.connect(lambda _text: _refresh_preview())
        relation_combo.currentTextChanged.connect(lambda _text: _refresh_preview())
        value_input.textChanged.connect(lambda _text: _refresh_preview())
        combine_combo.currentTextChanged.connect(lambda _text: _refresh_preview())
        _refresh_preview()

        copy_btn.clicked.connect(lambda: QApplication.clipboard().setText(_combined_expression()))
        insert_btn.clicked.connect(lambda: self._set_display_filter_text(_combined_expression(), apply_now=False))
        def _apply_and_prepare_next():
            self._set_display_filter_text(_combined_expression(), apply_now=True)
            value_input.clear()

        apply_btn.clicked.connect(_apply_and_prepare_next)

        def _on_ok():
            self._set_display_filter_text(_combined_expression(), apply_now=False)
            dialog.accept()

        ok_btn.clicked.connect(_on_ok)
        cancel_btn.clicked.connect(dialog.reject)
        dialog.resize(820, 280)
        self._fit_widget_90(dialog)
        dialog.exec()

    def _selected_field_filter_expression(self) -> tuple[str, str]:
        cv = self.capture_view
        if not cv:
            return '', ''
        item = self._selected_detail_item()
        record = cv.get_current_record()
        if item is None or record is None:
            return '', ''

        def _parse_title_parts(text: str) -> tuple[str, str]:
            raw = str(text or '').strip()
            if ': ' in raw:
                left, right = raw.split(': ', 1)
                return left.strip(), right.strip()
            if ' = ' in raw:
                left, right = raw.split(' = ', 1)
                return left.strip(), right.strip()
            return raw, ''

        def _strip_bracket_suffix(value: str) -> str:
            text = str(value or '').strip()
            if not text:
                return ''
            # Wireshark-like tails such as "[unverified] [in ICMP error packet]" are annotations,
            # not the core value selected by user.
            text = re.split(r'\s+\[[^\]]*\]', text, 1)[0].strip()
            return text

        def _contains_expr(field: str, value: str) -> str:
            fld = str(field or '').strip()
            val = str(value or '').strip()
            if not fld or not val:
                return ''
            escaped = val.replace('"', '\\"')
            return f'{fld} contains "{escaped}"'

        title = str(item.text(0) or '').strip()
        key, value = _parse_title_parts(title)
        key = str(key or '').strip()
        value = _strip_bracket_suffix(value)

        # Strict behavior requested: filter exactly the selected detail component,
        # not parent protocol and not sibling components.
        if key and value:
            pair_expr = _contains_expr('detail.pair', f'{key}: {value}')
            return pair_expr, 'detail.pair'
        if key:
            return _contains_expr('detail.key', key), 'detail.key'
        if title:
            return _contains_expr('detail.title', title), 'detail.title'
        return '', ''

    def _on_apply_as_filter(self):
        if not self._has_capture_document():
            QMessageBox.information(self, 'Apply as Filter', 'No capture is loaded.')
            return
        base_expr, _field_name = self._selected_field_filter_expression()
        if not base_expr:
            QMessageBox.information(self, 'Apply as Filter', 'Cannot create display filter from selected field.')
            return

        options = [
            'Selected',
            'Not Selected',
            'And Selected',
            'Or Selected',
            'And Not Selected',
            'Or Not Selected',
        ]
        choice, ok = QInputDialog.getItem(self, 'Apply as Filter', 'Mode:', options, 0, False)
        if not ok:
            return
        map_mode = {
            'Selected': 'selected',
            'Not Selected': 'not_selected',
            'And Selected': 'and_selected',
            'Or Selected': 'or_selected',
            'And Not Selected': 'and_not_selected',
            'Or Not Selected': 'or_not_selected',
        }
        merged = self._build_combined_filter(base_expr, map_mode.get(str(choice), 'selected'))
        self._set_display_filter_text(merged, apply_now=True)

    def _on_apply_as_column(self):
        if not self._has_capture_document():
            QMessageBox.information(self, 'Apply as Column', 'No capture is loaded.')
            return
        item = self._selected_detail_item()
        expr, field_name = self._selected_field_filter_expression()
        field = str(field_name or '').strip()
        detail_query = ''
        detail_key = ''
        detail_path = []
        title = ''
        if item is not None:
            title = str(item.text(0) or '').strip()
            detail_query = re.split(r'[:=]', title, 1)[0].strip().casefold()
            detail_key = self._normalize_detail_key(title)

            chain = []
            cur = item
            while cur is not None:
                chain.append(self._normalize_detail_key(str(cur.text(0) or '').strip()))
                cur = cur.parent()
            chain = [v for v in reversed(chain) if v]
            detail_path = self._stable_detail_path(chain)

            # For Detail-driven custom columns, always extract displayed values from detail tree
            # instead of protocol boolean fields (e.g. ipv6 -> True/False).
            field = ''

        if detail_query:
            title = detail_query

        if not title:
            title = str(field or expr or 'Custom Field').strip()

        for cfg in self._analyze_custom_columns:
            cfg_field = str(cfg.get('field', '') or '').strip().casefold()
            cfg_detail = str(cfg.get('detail_query', '') or '').strip().casefold()
            cfg_path = [str(v).strip().casefold() for v in (cfg.get('detail_path', []) or []) if str(v).strip()]
            if (field and cfg_field == field.casefold()) or (detail_query and cfg_detail == detail_query and cfg_path == [str(v).casefold() for v in self._stable_detail_path(detail_path)]):
                QMessageBox.information(self, 'Apply as Column', 'This field is already added as a custom column.')
                return

        if not field:
            field = ''
        self._analyze_custom_columns.append({
            'title': title,
            'field': field,
            'detail_query': detail_query,
            'detail_key': detail_key,
            'detail_path': detail_path,
            'occurrence': 0,
            'alignment': 'Left',
            'displayed': True,
        })
        self._save_analyze_custom_columns()
        self._apply_edit_preferences(self._load_edit_preferences())
        self._ensure_analyze_custom_columns_applied()
        if self.capture_view:
            self.capture_view.apply_display_filter()

    def _conversation_filter_expression_for_mode(self, mode: str):
        cv = self.capture_view
        record = cv.get_current_record() if cv else None
        if record is None:
            return ''
        metadata = getattr(record, 'metadata', {}) or {}
        src = str(getattr(record, 'src', '') or '')
        dst = str(getattr(record, 'dst', '') or '')

        mode = str(mode or '').strip().lower()
        if mode == 'tcp':
            stream = metadata.get('tcp_stream_index')
            if stream is not None:
                return f'tcp.stream == {int(stream)}'
            if src and dst and record.sport is not None and record.dport is not None:
                return f'ip.addr == {src} && ip.addr == {dst} && tcp.port == {int(record.sport)} && tcp.port == {int(record.dport)}'
        if mode == 'udp':
            stream = metadata.get('udp_stream_index')
            if stream is not None:
                return f'udp.stream == {int(stream)}'
            if src and dst and record.sport is not None and record.dport is not None:
                return f'ip.addr == {src} && ip.addr == {dst} && udp.port == {int(record.sport)} && udp.port == {int(record.dport)}'
        if mode == 'ipv4' and src and dst:
            return f'ip.addr == {src} && ip.addr == {dst}'
        if mode == 'ipv6' and src and dst:
            return f'ipv6.addr == {src} && ipv6.addr == {dst}'
        if mode == 'ethernet':
            return f'eth.addr == {src} && eth.addr == {dst}' if src and dst else ''
        return ''

    def _on_conversation_filter(self):
        if not self._has_capture_document():
            QMessageBox.information(self, 'Conversation Filter', 'No capture is loaded.')
            return
        cv = self.capture_view
        record = cv.get_current_record()
        if record is None:
            QMessageBox.information(self, 'Conversation Filter', 'Select a packet first.')
            return

        candidates = []
        raw = getattr(record, 'raw', None)
        protocol = str(getattr(record, 'protocol', '') or '').upper()
        metadata = getattr(record, 'metadata', {}) or {}
        if metadata.get('tcp_stream_index') is not None or protocol == 'TCP':
            candidates.append('TCP')
        if metadata.get('udp_stream_index') is not None or protocol.startswith('UDP'):
            candidates.append('UDP')
        if raw is not None and raw.haslayer(IP):
            candidates.append('IPv4')
        if raw is not None and raw.haslayer(IPv6):
            candidates.append('IPv6')
        candidates.append('Ethernet')
        candidates = [c for i, c in enumerate(candidates) if c not in candidates[:i]]

        choice, ok = QInputDialog.getItem(self, 'Conversation Filter', 'Conversation type:', candidates, 0, False)
        if not ok:
            return
        expr = self._conversation_filter_expression_for_mode(str(choice))
        if not expr:
            QMessageBox.information(self, 'Conversation Filter', 'Cannot determine conversation for selected packet.')
            return
        self._set_display_filter_text(expr, apply_now=True)

    def _follow_stream_records(self, mode: str, record_override=None):
        cv = self.capture_view
        record = record_override if record_override is not None else (cv.get_current_record() if cv else None)
        if record is None:
            return [], ''
        metadata = getattr(record, 'metadata', {}) or {}
        mode = str(mode or '').strip().lower()

        if mode == 'tcp':
            stream = metadata.get('tcp_stream_index')
            if stream is not None:
                rows = [r for r in cv.records if (getattr(r, 'metadata', {}) or {}).get('tcp_stream_index') == stream]
                return rows, f'tcp.stream == {int(stream)}'
        if mode == 'udp':
            stream = metadata.get('udp_stream_index')
            if stream is not None:
                rows = [r for r in cv.records if (getattr(r, 'metadata', {}) or {}).get('udp_stream_index') == stream]
                return rows, f'udp.stream == {int(stream)}'

        key = cv._conversation_key_for_record(record)
        if key is None:
            return [], ''
        rows = [r for r in cv.records if cv._conversation_key_for_record(r) == key]
        fallback_mode = 'ipv6' if getattr(record, 'raw', None) is not None and record.raw.haslayer(IPv6) else 'ipv4'
        return rows, self._conversation_filter_expression_for_mode(fallback_mode)

    def _follow_mode_choices_for_record(self, record) -> list[tuple[str, str]]:
        if record is None:
            return []
        metadata = getattr(record, 'metadata', {}) or {}
        protocol = str(getattr(record, 'protocol', '') or '').upper()
        raw = getattr(record, 'raw', None)
        has_tcp = bool(raw is not None and raw.haslayer(TCP))
        has_udp = bool(raw is not None and raw.haslayer(UDP))
        choices = []
        if has_tcp or protocol in {'TCP', 'TLS', 'SSL'} or protocol.startswith('TLS'):
            choices.append(('TCP Stream', 'tcp'))
        if has_udp or protocol == 'UDP':
            choices.append(('UDP Stream', 'udp'))
        choices.append(('Conversation', 'conversation'))
        deduped = []
        seen = set()
        for label, mode in choices:
            if mode in seen:
                continue
            seen.add(mode)
            deduped.append((label, mode))
        return deduped

    def _packet_payload_bytes(self, record, mode: str) -> bytes:
        raw = getattr(record, 'raw', None)
        if raw is None:
            return b''
        try:
            if mode == 'tcp' and raw.haslayer(TCP):
                return bytes(raw[TCP].payload)
            if mode == 'udp' and raw.haslayer(UDP):
                return bytes(raw[UDP].payload)
            if mode == 'conversation':
                if raw.haslayer(TCP):
                    return bytes(raw[TCP].payload)
                if raw.haslayer(UDP):
                    return bytes(raw[UDP].payload)
        except Exception:
            return b''
        return b''

    def _format_follow_payload(self, payload: bytes, fmt: str) -> str:
        data = bytes(payload or b'')
        if not data:
            return ''
        kind = str(fmt or 'ASCII').strip().lower()
        if kind == 'hex dump':
            lines = []
            for i in range(0, len(data), 16):
                chunk = data[i:i + 16]
                left = chunk[:8]
                right = chunk[8:16]
                left_hex = ' '.join(f'{b:02x}' for b in left)
                right_hex = ' '.join(f'{b:02x}' for b in right)
                hex_part = f'{left_hex:<23}  {right_hex:<23}'
                ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
                lines.append(f'{i:08x}  {hex_part}  {ascii_part}')
            return '\n'.join(lines)
        if kind == 'raw (base64)':
            return base64.b64encode(data).decode('ascii', errors='ignore')
        lines = []
        for i in range(0, len(data), 32):
            chunk = data[i:i + 32]
            ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            lines.append(f'{i:08x}  {ascii_part}')
        return '\n'.join(lines)

    def _open_follow_stream_dialog(self, record, mode: str, title_label: str | None = None):
        if record is None:
            return
        records, stream_filter = self._follow_stream_records(mode, record_override=record)
        if not records:
            QMessageBox.information(self, 'Follow', 'No stream data found for selected packet.')
            return

        first = records[0]
        client_key = (str(getattr(first, 'src', '') or ''), str(getattr(first, 'sport', '') or ''))

        dialog = QDialog(self)
        title_text = str(title_label or mode or 'Conversation').strip()
        dialog.setWindowTitle(f'Follow {title_text}')
        layout = QVBoxLayout(dialog)

        top = QHBoxLayout()
        top.addWidget(QLabel('Show data as:'))
        format_combo = QComboBox(dialog)
        format_combo.addItems(['ASCII', 'Hex Dump', 'Raw (Base64)'])
        top.addWidget(format_combo)
        top.addWidget(QLabel('Direction:'))
        direction_combo = QComboBox(dialog)
        direction_combo.addItems(['Entire conversation', 'Client to server', 'Server to client'])
        top.addWidget(direction_combo)
        top.addStretch(1)
        layout.addLayout(top)

        text = QTextEdit(dialog)
        text.setReadOnly(True)
        if self.capture_view:
            text.setFont(self.capture_view.hex_view.font())
        layout.addWidget(text, 1)

        status_label = QLabel('', dialog)
        layout.addWidget(status_label)

        buttons = QHBoxLayout()
        filter_this_btn = QPushButton('Filter This Stream', dialog)
        filter_out_btn = QPushButton('Filter Out This Stream', dialog)
        copy_btn = QPushButton('Copy', dialog)
        save_btn = QPushButton('Save As', dialog)
        close_btn = QPushButton('Close', dialog)
        for btn in (filter_this_btn, filter_out_btn, copy_btn, save_btn, close_btn):
            buttons.addWidget(btn)
        layout.addLayout(buttons)

        def _refresh_text():
            fmt = str(format_combo.currentText() or 'ASCII')
            direction = str(direction_combo.currentText() or 'Entire conversation')
            lines = []
            total_bytes = 0
            client_bytes = 0
            server_bytes = 0
            packet_count = 0
            for rec in records:
                payload = self._packet_payload_bytes(rec, str(mode or '').strip().lower())
                if not payload:
                    continue
                packet_count += 1
                total_bytes += len(payload)
                is_client = (str(getattr(rec, 'src', '') or ''), str(getattr(rec, 'sport', '') or '')) == client_key
                if is_client:
                    client_bytes += len(payload)
                else:
                    server_bytes += len(payload)

                if direction == 'Client to server' and not is_client:
                    continue
                if direction == 'Server to client' and is_client:
                    continue

                prefix = 'Client -> Server' if is_client else 'Server -> Client'
                body = self._format_follow_payload(payload, fmt)
                if not body:
                    continue
                frame_no = int(getattr(rec, 'number', 0) or 0)
                lines.append(f'{prefix:<18} Frame {frame_no:>6}  Bytes {len(payload):>6}')
                for body_line in str(body).splitlines():
                    lines.append(f'    {body_line}')
                lines.append('')

            text.setPlainText('\n'.join(lines).strip())
            status_label.setText(f'Status: {packet_count} packets, {client_bytes} bytes client, {server_bytes} bytes server, {total_bytes} bytes total')

        format_combo.currentTextChanged.connect(lambda _text: _refresh_text())
        direction_combo.currentTextChanged.connect(lambda _text: _refresh_text())
        _refresh_text()

        filter_this_btn.clicked.connect(lambda: self._set_display_filter_text(stream_filter, apply_now=True))
        filter_out_btn.clicked.connect(lambda: self._set_display_filter_text(f'!({stream_filter})' if stream_filter else '', apply_now=True))
        copy_btn.clicked.connect(lambda: QApplication.clipboard().setText(text.toPlainText()))

        def _save_text():
            path, _ = QFileDialog.getSaveFileName(self, 'Save Follow Stream', str(Path.cwd() / 'follow_stream.txt'), 'Text Files (*.txt);;All Files (*)')
            if not path:
                return
            try:
                Path(path).write_text(text.toPlainText(), encoding='utf-8')
            except Exception as exc:
                QMessageBox.critical(self, 'Follow', f'Cannot save file:\n{exc}')

        save_btn.clicked.connect(_save_text)
        close_btn.clicked.connect(dialog.accept)
        dialog.resize(960, 620)
        self._fit_widget_90(dialog)
        dialog.exec()

    def _on_follow_stream(self):
        if not self._has_capture_document():
            QMessageBox.information(self, 'Follow', 'No capture is loaded.')
            return
        record = self.capture_view.get_current_record() if self.capture_view else None
        if record is None:
            QMessageBox.information(self, 'Follow', 'Select a packet first.')
            return

        choices = self._follow_mode_choices_for_record(record)
        if not choices:
            QMessageBox.information(self, 'Follow', 'No stream data found for selected packet.')
            return
        labels = [label for label, _mode in choices]
        stream_choice, ok = QInputDialog.getItem(self, 'Follow', 'Follow type:', labels, 0, False)
        if not ok:
            return
        mode = next((mode for label, mode in choices if label == str(stream_choice)), 'conversation')
        self._open_follow_stream_dialog(record, mode, title_label=str(stream_choice))

    def _on_menu_feature_placeholder(self, feature_name: str):
        QMessageBox.information(
            self,
            'Menu Feature',
            f'{feature_name}\n\nFeature name has been updated on menubar. Backend will be integrated in a later step.',
        )

    def _on_close_capture_file(self):
        if not self.capture_view:
            return

        proceed = self._prompt_save_before_destructive_action('Đóng file sẽ bỏ dữ liệu hiện tại. Bạn có muốn lưu trước không?')
        if not proceed:
            return

        self._close_firewall_acl_dialog()
        self.capture_view.stop_capture()
        self.show_interface_selector()
        self._refresh_status_metrics()
        self._refresh_file_menu_state()

    def _on_reload_file(self):
        if not self.capture_view:
            return
        self._close_firewall_acl_dialog('The capture file was reloaded. This ACL rule may no longer match the selected packet.')
        self.capture_view.reload_file()
        self._sync_capture_buttons()
        self._refresh_status_metrics()
        self._refresh_file_menu_state()

    def _on_go_previous_packet(self):
        if self.capture_view:
            self.capture_view.goto_previous_packet()
        self._refresh_go_menu_state()

    def _on_go_next_packet(self):
        if self.capture_view:
            self.capture_view.goto_next_packet()
        self._refresh_go_menu_state()

    def _on_go_first_packet(self):
        if self.capture_view:
            self.capture_view.goto_first_packet()
        self._refresh_go_menu_state()

    def _on_go_last_packet(self):
        if self.capture_view:
            self.capture_view.goto_last_packet()
        self._refresh_go_menu_state()

    def _on_go_back(self):
        if self.capture_view:
            self.capture_view.go_back()
        self._refresh_go_menu_state()

    def _on_go_forward(self):
        if self.capture_view:
            self.capture_view.go_forward()
        self._refresh_go_menu_state()

    def _on_go_to_corresponding_packet(self):
        if self.capture_view:
            self.capture_view.goto_corresponding_packet()
        self._refresh_go_menu_state()

    def _on_go_previous_packet_conversation(self):
        if self.capture_view:
            self.capture_view.goto_previous_packet_in_conversation()
        self._refresh_go_menu_state()

    def _on_go_next_packet_conversation(self):
        if self.capture_view:
            self.capture_view.goto_next_packet_in_conversation()
        self._refresh_go_menu_state()

    def _on_toggle_go_to_packet(self):
        if not self.capture_view or not self.capture_view.has_packets():
            return
        self.capture_view.toggle_go_to_packet_row()
        self._refresh_go_menu_state()

    def _on_toggle_auto_scroll(self, enabled: bool):
        checked = bool(enabled)
        if hasattr(self, 'action_stay_last_btn'):
            self.action_stay_last_btn.blockSignals(True)
            self.action_stay_last_btn.setChecked(checked)
            self.action_stay_last_btn.blockSignals(False)
        if hasattr(self, 'action_go_auto_scroll_live_capture'):
            self.action_go_auto_scroll_live_capture.blockSignals(True)
            self.action_go_auto_scroll_live_capture.setChecked(checked)
            self.action_go_auto_scroll_live_capture.blockSignals(False)
        if self.capture_view:
            self.capture_view.set_auto_scroll_enabled(checked)
        self._refresh_go_menu_state()

    def _on_toggle_color_rules(self, enabled: bool):
        checked = bool(enabled)
        if hasattr(self, 'action_color_btn'):
            self.action_color_btn.blockSignals(True)
            self.action_color_btn.setChecked(checked)
            self.action_color_btn.blockSignals(False)
        if hasattr(self, 'action_view_colorize_packet_list'):
            self.action_view_colorize_packet_list.blockSignals(True)
            self.action_view_colorize_packet_list.setChecked(checked)
            self.action_view_colorize_packet_list.blockSignals(False)
        if self.capture_view:
            self.capture_view.set_color_rules_enabled(checked)

    def _on_zoom_in(self):
        if self.capture_view:
            self.capture_view.increase_main_text_size()

    def _on_zoom_out(self):
        if self.capture_view:
            self.capture_view.decrease_main_text_size()

    def _on_zoom_reset(self):
        if self.capture_view:
            self.capture_view.reset_main_text_size()

    def _on_resize_columns(self, enabled: bool = True):
        checked = bool(enabled)
        if hasattr(self, 'action_view_resize_all_columns'):
            self.action_view_resize_all_columns.blockSignals(True)
            self.action_view_resize_all_columns.setChecked(checked)
            self.action_view_resize_all_columns.blockSignals(False)
        if hasattr(self, 'action_resize_cols_btn'):
            self.action_resize_cols_btn.blockSignals(True)
            self.action_resize_cols_btn.setChecked(checked)
            self.action_resize_cols_btn.blockSignals(False)
        if self.capture_view:
            self.capture_view.set_resize_all_columns_enabled(checked)

    def _on_reset_layout(self):
        if self.capture_view:
            self.capture_view.reset_layout_to_default_size()

    def _prompt_save_before_destructive_action(self, message: str) -> bool:
        if not self.capture_view or not self.capture_view.has_unsaved_changes():
            return True

        settings = QSettings('Packetra', 'Packetra')
        confirm_unsaved = bool(settings.value('preferences/confirm_unsaved_capture_files', True, bool))
        if not confirm_unsaved:
            return True

        reply = QMessageBox.question(
            self,
            'Save current capture?',
            message,
            QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel,
            QMessageBox.Yes,
        )

        if reply == QMessageBox.Cancel:
            return False
        if reply == QMessageBox.Yes:
            saved = bool(self.capture_view.save_file())
            if not saved:
                return False
            self._update_capture_window_title()
            return True

        # "No" means continue without saving old capture.
        return True

    def _on_summary(self):
        """Xem tóm tắt"""
        if self.capture_view:
            self.capture_view.show_summary()

    def _statistics_scope_records(self, limit_to_display_filter: bool) -> list:
        cv = self.capture_view
        if not cv:
            return []
        if not bool(limit_to_display_filter):
            return list(cv.records)
        rows = []
        for idx in cv.visible_indices:
            if 0 <= idx < len(cv.records):
                rows.append(cv.records[idx])
        return rows

    def _statistics_make_table(self, columns: list[str], rows: list[dict]) -> QTableWidget:
        table = QTableWidget()
        table.setColumnCount(len(columns))
        table.setHorizontalHeaderLabels(columns)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setAlternatingRowColors(True)
        header = table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self._statistics_fill_table(table, columns, rows)
        return table

    def _statistics_fill_table(self, table: QTableWidget, columns: list[str], rows: list[dict]):
        table.setRowCount(len(rows))
        table._stats_rows = list(rows)
        for r, row in enumerate(rows):
            for c, col in enumerate(columns):
                val = row.get(col, '') if isinstance(row, dict) else ''
                item = QTableWidgetItem(str(val))
                table.setItem(r, c, item)

    def _statistics_copy_rows(self, columns: list[str], rows: list[dict]):
        lines = ['\t'.join(columns)]
        for row in rows:
            lines.append('\t'.join(str(row.get(col, '')) for col in columns))
        QApplication.clipboard().setText('\n'.join(lines))

    def _statistics_export_rows_csv(self, title: str, columns: list[str], rows: list[dict]):
        base_name = re.sub(r'[^A-Za-z0-9]+', '_', str(title or 'statistics').strip()).strip('_').lower() or 'statistics'
        path, _ = QFileDialog.getSaveFileName(
            self,
            f'Export {title}',
            str(Path.cwd() / f'{base_name}.csv'),
            'CSV Files (*.csv);;All Files (*)',
        )
        if not path:
            return
        try:
            with open(path, 'w', newline='', encoding='utf-8') as fh:
                writer = csv.DictWriter(fh, fieldnames=columns)
                writer.writeheader()
                for row in rows:
                    writer.writerow({col: row.get(col, '') for col in columns})
        except Exception as exc:
            QMessageBox.critical(self, title, f'Cannot export CSV:\n{exc}')

    def _statistics_current_row(self, table: QTableWidget) -> dict:
        row = int(table.currentRow())
        rows = getattr(table, '_stats_rows', [])
        if 0 <= row < len(rows):
            return rows[row]
        return {}

    def _protocol_filter_token(self, protocol_name: str) -> str:
        raw = str(protocol_name or '').strip().casefold()
        if not raw:
            return ''
        mapping = {
            'ipv4': 'ip',
            'ipv6': 'ipv6',
            'ethernet': 'eth',
            'frame': 'frame',
        }
        if raw in mapping:
            return mapping[raw]
        token = raw.replace(' ', '').replace('/', '').replace('-', '')
        aliases = {str(v).casefold() for v in getattr(DisplayFilter, 'PROTOCOL_ALIASES', set())}
        return token if token in aliases else ''

    def _stats_rate_ms(self, count: int, duration_sec: float) -> float:
        if duration_sec <= 0:
            return 0.0
        return float(count) / (duration_sec * 1000.0)

    def _stats_burst_rate(self, times: list[float], window_sec: float = 0.1) -> tuple[float, float]:
        if not times:
            return 0.0, 0.0
        series = sorted(float(t) for t in times)
        best = 0
        best_start = series[0]
        left = 0
        for right, ts in enumerate(series):
            while left <= right and ts - series[left] > window_sec:
                left += 1
            size = right - left + 1
            if size > best:
                best = size
                best_start = series[left]
        if window_sec <= 0:
            return 0.0, best_start
        return float(best) / (window_sec * 1000.0), best_start

    def _on_statistics_resolved_addresses(self):
        if not self.capture_view:
            QMessageBox.information(self, 'Resolved Addresses', 'No capture is loaded.')
            return

        dialog = QDialog(self)
        dialog.setWindowTitle('Resolved Addresses')
        layout = QVBoxLayout(dialog)

        top = QHBoxLayout()
        search_input = QLineEdit(dialog)
        search_input.setPlaceholderText('Search MAC or vendor name')
        top.addWidget(search_input, 1)
        limit_check = QCheckBox('Limit to display filter', dialog)
        limit_check.setChecked(True)
        top.addWidget(limit_check)
        layout.addLayout(top)

        columns = ['Address', 'Name']
        table = self._statistics_make_table(columns, [])
        table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(table, 1)

        actions = QHBoxLayout()
        refresh_btn = QPushButton('Refresh', dialog)
        copy_btn = QPushButton('Copy', dialog)
        export_btn = QPushButton('Export CSV', dialog)
        close_btn = QPushButton('Close', dialog)
        for btn in (refresh_btn, copy_btn, export_btn, close_btn):
            actions.addWidget(btn)
        layout.addLayout(actions)

        def _build_rows() -> list[dict]:
            records = self._statistics_scope_records(limit_check.isChecked())
            by_oui = {}

            def _ensure_vendor_bucket(mac_addr: str):
                parts = [p for p in str(mac_addr or '').lower().split(':') if p]
                if len(parts) < 6:
                    return None, None, None
                oui = ':'.join(parts[:3])
                suffix = ':'.join(parts[3:])
                vendor = str(get_mac_vendor(mac_addr) or '').strip()
                if not vendor:
                    return None, None, None
                bucket = by_oui.get(oui)
                if bucket is None:
                    bucket = {'vendor': vendor, 'macs': set()}
                    by_oui[oui] = bucket
                bucket['macs'].add(':'.join(parts[:6]))
                return oui, vendor, suffix

            for rec in records:
                raw = getattr(rec, 'raw', None)
                if raw is not None and raw.haslayer(Ether):
                    eth = raw[Ether]
                    src_mac = str(getattr(eth, 'src', '') or '').lower()
                    dst_mac = str(getattr(eth, 'dst', '') or '').lower()
                    _ensure_vendor_bucket(src_mac)
                    _ensure_vendor_bucket(dst_mac)

            rows = []
            for oui in sorted(by_oui.keys()):
                bucket = by_oui[oui]
                vendor = str(bucket.get('vendor', '') or '').strip()
                if not vendor:
                    continue
                rows.append({'Address': oui, 'Name': vendor})
                for mac_addr in sorted(bucket.get('macs', set())):
                    parts = mac_addr.split(':')
                    suffix = ':'.join(parts[3:6]) if len(parts) >= 6 else ''
                    rows.append({'Address': mac_addr, 'Name': f'{vendor}_{suffix}' if suffix else vendor})

            search_text = str(search_input.text() or '').strip().casefold()
            if search_text:
                rows = [
                    r for r in rows
                    if search_text in (f"{r.get('Address', '')} {r.get('Name', '')}").casefold()
                ]
            return rows

        _scene_state = {'row_area_width': left_margin + lane_w + 90}

        def _refresh():
            rows = _build_rows()
            self._statistics_fill_table(table, columns, rows)

        refresh_btn.clicked.connect(_refresh)
        search_input.textChanged.connect(lambda _v: _refresh())
        limit_check.toggled.connect(lambda _v: _refresh())

        def _copy_current():
            self._statistics_copy_rows(columns, getattr(table, '_stats_rows', []))

        def _export_current():
            self._statistics_export_rows_csv('Resolved Addresses', columns, getattr(table, '_stats_rows', []))

        copy_btn.clicked.connect(_copy_current)
        export_btn.clicked.connect(_export_current)
        close_btn.clicked.connect(dialog.accept)
        _refresh()
        dialog.resize(860, 620)
        self._fit_widget_90(dialog)
        dialog.exec()

    def _on_statistics_protocol_hierarchy(self):
        if not self.capture_view:
            QMessageBox.information(self, 'Protocol Hierarchy', 'No capture is loaded.')
            return

        dialog = QDialog(self)
        dialog.setWindowTitle('Protocol Hierarchy Statistics')
        layout = QVBoxLayout(dialog)

        top = QHBoxLayout()
        limit_check = QCheckBox('Limit to display filter', dialog)
        limit_check.setChecked(True)
        top.addWidget(limit_check)
        refresh_btn = QPushButton('Refresh', dialog)
        top.addWidget(refresh_btn)
        top.addStretch(1)
        layout.addLayout(top)

        tree = QTreeWidget(dialog)
        tree.setColumnCount(10)
        tree.setHeaderLabels([
            'Protocol', 'Percent Packets', 'Packets', 'Percent Bytes', 'Bytes',
            'Bits/s', 'End Packets', 'End Bytes', 'End Bits/s', 'PDUs'
        ])
        header = tree.header()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setStretchLastSection(False)
        tree.setColumnWidth(0, 560)
        for col in range(1, 10):
            tree.setColumnWidth(col, 88)
        layout.addWidget(tree, 1)

        filter_label = QLabel('Display filter: (none)', dialog)
        layout.addWidget(filter_label)

        bottom = QHBoxLayout()
        apply_btn = QPushButton('Apply as Filter', dialog)
        copy_btn = QPushButton('Copy', dialog)
        export_btn = QPushButton('Export CSV', dialog)
        close_btn = QPushButton('Close', dialog)
        bottom.addWidget(apply_btn)
        bottom.addWidget(copy_btn)
        bottom.addWidget(export_btn)
        bottom.addStretch(1)
        bottom.addWidget(close_btn)
        layout.addLayout(bottom)

        canonical = {
            'frame': ('Frame', 'frame'),
            'ether': ('Ethernet', 'eth'),
            'ethernet': ('Ethernet', 'eth'),
            'arp': ('Address Resolution Protocol', 'arp'),
            'ip': ('Internet Protocol Version 4', 'ip'),
            'ipv4': ('Internet Protocol Version 4', 'ip'),
            'ipv6': ('Internet Protocol Version 6', 'ipv6'),
            'tcp': ('Transmission Control Protocol', 'tcp'),
            'udp': ('User Datagram Protocol', 'udp'),
            'dns': ('Domain Name System', 'dns'),
            'icmp': ('Internet Control Message Protocol', 'icmp'),
            'icmpv6': ('Internet Control Message Protocol v6', 'icmpv6'),
            'tls': ('Transport Layer Security', 'tls'),
            'ssl': ('Transport Layer Security', 'tls'),
            'http': ('Hypertext Transfer Protocol', 'http'),
            'quic': ('QUIC', 'quic'),
            'dhcp': ('Dynamic Host Configuration Protocol', 'dhcp'),
        }

        def _normalize_layer(layer_name: str) -> tuple[str, str]:
            raw = str(layer_name or '').strip()
            if not raw:
                return 'Unknown', ''
            key = raw.casefold()
            if key in canonical:
                return canonical[key]
            if key.startswith('dns'):
                return canonical['dns']
            if key.startswith('http'):
                return canonical['http']
            token = re.sub(r'[^a-z0-9]+', '', key)
            return raw, token

        def _packet_layers(rec) -> list[tuple[str, str]]:
            raw = getattr(rec, 'raw', None)
            out = []
            if raw is not None:
                layer = raw
                guard = 0
                while layer is not None and guard < 64:
                    guard += 1
                    cls_name = str(layer.__class__.__name__ or '').strip()
                    if not cls_name or cls_name == 'NoPayload':
                        break
                    out.append(_normalize_layer(cls_name))
                    nxt = getattr(layer, 'payload', None)
                    if nxt is None or nxt is layer:
                        break
                    layer = nxt
            if not out:
                for name in list(getattr(rec, 'layers', []) or []):
                    out.append(_normalize_layer(name))
            if not out:
                out.append(_normalize_layer(str(getattr(rec, 'protocol', '') or 'Unknown')))
            return out

        def _iter_rows(root_item: QTreeWidgetItem):
            rows = []

            def _walk(item: QTreeWidgetItem, depth: int):
                rows.append({
                    'Protocol': ('  ' * depth) + item.text(0),
                    'Percent Packets': item.text(1),
                    'Packets': item.text(2),
                    'Percent Bytes': item.text(3),
                    'Bytes': item.text(4),
                    'Bits/s': item.text(5),
                    'End Packets': item.text(6),
                    'End Bytes': item.text(7),
                    'End Bits/s': item.text(8),
                    'PDUs': item.text(9),
                })
                for idx in range(item.childCount()):
                    _walk(item.child(idx), depth + 1)

            _walk(root_item, 0)
            return rows

        def _refresh_tree():
            records = self._statistics_scope_records(limit_check.isChecked())
            tree.clear()
            expr = ''
            if self.capture_view and hasattr(self.capture_view, 'display_filter_input'):
                expr = str(self.capture_view.display_filter_input.text() or '').strip()
            filter_label.setText(f'Display filter: {expr or "(none)"}')
            if not records:
                return
            total_packets = len(records)
            total_bytes = max(1, sum(int(getattr(r, 'length', 0) or 0) for r in records))
            duration = 0.0
            if len(records) >= 2:
                duration = max(0.0, float(records[-1].epoch_time) - float(records[0].epoch_time))

            root = {
                'children': {},
                'packets': 0,
                'bytes': 0,
                'end_packets': 0,
                'end_bytes': 0,
                'pdus': 0,
                'name': 'Frame',
                'token': 'frame',
            }

            for rec in records:
                pkt_len = int(getattr(rec, 'length', 0) or 0)
                path = [('Frame', 'frame')] + _packet_layers(rec)
                node = root
                node['packets'] += 1
                node['bytes'] += pkt_len
                node['pdus'] += 1
                seen_nodes = {id(node)}
                for name, token in path[1:]:
                    key = f'{name}|{token}'
                    child = node['children'].get(key)
                    if child is None:
                        child = {
                            'children': {},
                            'packets': 0,
                            'bytes': 0,
                            'end_packets': 0,
                            'end_bytes': 0,
                            'pdus': 0,
                            'name': name,
                            'token': token,
                        }
                        node['children'][key] = child
                    child['pdus'] += 1
                    if id(child) not in seen_nodes:
                        child['packets'] += 1
                        child['bytes'] += pkt_len
                        seen_nodes.add(id(child))
                    node = child

                node['end_packets'] += 1
                node['end_bytes'] += pkt_len

            def _append(parent_item, node):
                item = QTreeWidgetItem(parent_item)
                packets = int(node.get('packets', 0) or 0)
                bytes_count = int(node.get('bytes', 0) or 0)
                end_packets = int(node.get('end_packets', 0) or 0)
                end_bytes = int(node.get('end_bytes', 0) or 0)
                p_pct = (packets * 100.0 / total_packets) if total_packets > 0 else 0.0
                b_pct = (bytes_count * 100.0 / total_bytes) if total_bytes > 0 else 0.0
                bits_s = int((bytes_count * 8.0) / duration) if duration > 0 else 0
                end_bits_s = int((end_bytes * 8.0) / duration) if duration > 0 else 0
                item.setText(0, str(node.get('name', '') or 'Unknown'))
                item.setText(1, f'{p_pct:.2f}')
                item.setText(2, str(packets))
                item.setText(3, f'{b_pct:.2f}')
                item.setText(4, str(bytes_count))
                item.setText(5, str(bits_s))
                item.setText(6, str(end_packets))
                item.setText(7, str(end_bytes))
                item.setText(8, str(end_bits_s))
                item.setText(9, str(int(node.get('pdus', 0) or 0)))
                item.setData(0, Qt.UserRole, str(node.get('token', '') or ''))
                for child_key in sorted(node.get('children', {}).keys(), key=lambda k: str(node['children'][k].get('name', '') or '')):
                    _append(item, node['children'][child_key])

            _append(tree, root)
            tree.expandToDepth(1)

        def _apply_selected_filter():
            item = tree.currentItem()
            if item is None:
                return
            token = str(item.data(0, Qt.UserRole) or '').strip() or self._protocol_filter_token(item.text(0))
            if not token:
                QMessageBox.information(dialog, 'Protocol Hierarchy', 'No display-filter token for selected protocol.')
                return
            self._set_display_filter_text(token, apply_now=True)

        def _copy_tree():
            root_item = tree.topLevelItem(0)
            if root_item is None:
                QApplication.clipboard().setText('')
                return
            rows = _iter_rows(root_item)
            menu = QMenu(dialog)
            action_csv = menu.addAction('Copy as CSV')
            action_yaml = menu.addAction('Copy as YAML')
            chosen = menu.exec(QCursor.pos())
            if chosen is action_yaml:
                lines = ['protocol_hierarchy:']
                for row in rows:
                    lines.append('  - protocol: "' + str(row['Protocol']).replace('"', '\\"') + '"')
                    lines.append('    percent_packets: ' + str(row['Percent Packets']))
                    lines.append('    packets: ' + str(row['Packets']))
                    lines.append('    percent_bytes: ' + str(row['Percent Bytes']))
                    lines.append('    bytes: ' + str(row['Bytes']))
                    lines.append('    bits_per_s: ' + str(row['Bits/s']))
                    lines.append('    end_packets: ' + str(row['End Packets']))
                    lines.append('    end_bytes: ' + str(row['End Bytes']))
                    lines.append('    end_bits_per_s: ' + str(row['End Bits/s']))
                    lines.append('    pdus: ' + str(row['PDUs']))
                QApplication.clipboard().setText('\n'.join(lines))
                return

            headers = ['Protocol', 'Percent Packets', 'Packets', 'Percent Bytes', 'Bytes', 'Bits/s', 'End Packets', 'End Bytes', 'End Bits/s', 'PDUs']
            lines = [','.join(headers)]
            for row in rows:
                vals = [str(row[h]).replace('"', '""') for h in headers]
                lines.append(','.join(f'"{v}"' for v in vals))
            QApplication.clipboard().setText('\n'.join(lines))

        refresh_btn.clicked.connect(_refresh_tree)
        limit_check.toggled.connect(lambda _v: _refresh_tree())
        apply_btn.clicked.connect(_apply_selected_filter)
        copy_btn.clicked.connect(_copy_tree)
        export_btn.clicked.connect(lambda: self._statistics_export_rows_csv(
            'Protocol Hierarchy',
            ['Protocol', 'Percent Packets', 'Packets', 'Percent Bytes', 'Bytes', 'Bits/s', 'End Packets', 'End Bytes', 'End Bits/s', 'PDUs'],
            _iter_rows(tree.topLevelItem(0)) if tree.topLevelItem(0) is not None else [],
        ))
        close_btn.clicked.connect(dialog.accept)
        _refresh_tree()
        dialog.resize(1020, 640)
        self._fit_widget_90(dialog)
        dialog.exec()

    def _on_statistics_endpoints(self):
        if not self.capture_view:
            QMessageBox.information(self, 'Endpoints', 'No capture is loaded.')
            return

        dialog = QDialog(self)
        dialog.setWindowTitle('Endpoints')
        layout = QVBoxLayout(dialog)

        top = QHBoxLayout()
        limit_check = QCheckBox('Limit to display filter', dialog)
        limit_check.setChecked(True)
        refresh_btn = QPushButton('Refresh', dialog)
        top.addWidget(limit_check)
        top.addWidget(refresh_btn)
        top.addStretch(1)
        layout.addLayout(top)

        tabs = QTabWidget(dialog)
        layout.addWidget(tabs, 1)

        table_defs = {
            'Ethernet': ['Address', 'Packets', 'Bytes', 'Tx Packets', 'Tx Bytes', 'Rx Packets', 'Rx Bytes'],
            'IPv4': ['Address', 'Packets', 'Bytes', 'Tx Packets', 'Tx Bytes', 'Rx Packets', 'Rx Bytes'],
            'IPv6': ['Address', 'Packets', 'Bytes', 'Tx Packets', 'Tx Bytes', 'Rx Packets', 'Rx Bytes'],
            'TCP': ['Address', 'Port', 'Packets', 'Bytes', 'Tx Packets', 'Tx Bytes', 'Rx Packets', 'Rx Bytes'],
            'UDP': ['Address', 'Port', 'Packets', 'Bytes', 'Tx Packets', 'Tx Bytes', 'Rx Packets', 'Rx Bytes'],
        }
        tables = {}
        for name, cols in table_defs.items():
            table = self._statistics_make_table(cols, [])
            tabs.addTab(table, name)
            tables[name] = table

        bottom = QHBoxLayout()
        apply_btn = QPushButton('Apply as Filter', dialog)
        copy_btn = QPushButton('Copy', dialog)
        export_btn = QPushButton('Export CSV', dialog)
        close_btn = QPushButton('Close', dialog)
        for btn in (apply_btn, copy_btn, export_btn):
            bottom.addWidget(btn)
        bottom.addStretch(1)
        bottom.addWidget(close_btn)
        layout.addLayout(bottom)

        def _accumulate(stats_map, key, pkt_len, direction):
            item = stats_map.get(key)
            if item is None:
                item = {'Packets': 0, 'Bytes': 0, 'Tx Packets': 0, 'Tx Bytes': 0, 'Rx Packets': 0, 'Rx Bytes': 0}
                stats_map[key] = item
            item['Packets'] += 1
            item['Bytes'] += pkt_len
            if direction == 'tx':
                item['Tx Packets'] += 1
                item['Tx Bytes'] += pkt_len
            else:
                item['Rx Packets'] += 1
                item['Rx Bytes'] += pkt_len

        def _refresh():
            records = self._statistics_scope_records(limit_check.isChecked())
            maps = {name: {} for name in table_defs.keys()}
            for rec in records:
                raw = getattr(rec, 'raw', None)
                pkt_len = int(getattr(rec, 'length', 0) or 0)

                if raw is not None and raw.haslayer(Ether):
                    src = str(raw[Ether].src).lower()
                    dst = str(raw[Ether].dst).lower()
                    _accumulate(maps['Ethernet'], (src,), pkt_len, 'tx')
                    _accumulate(maps['Ethernet'], (dst,), pkt_len, 'rx')
                if raw is not None and raw.haslayer(IP):
                    src = str(raw[IP].src)
                    dst = str(raw[IP].dst)
                    _accumulate(maps['IPv4'], (src,), pkt_len, 'tx')
                    _accumulate(maps['IPv4'], (dst,), pkt_len, 'rx')
                if raw is not None and raw.haslayer(IPv6):
                    src = str(raw[IPv6].src)
                    dst = str(raw[IPv6].dst)
                    _accumulate(maps['IPv6'], (src,), pkt_len, 'tx')
                    _accumulate(maps['IPv6'], (dst,), pkt_len, 'rx')

                if raw is not None and raw.haslayer(TCP):
                    if raw.haslayer(IP):
                        src = str(raw[IP].src)
                        dst = str(raw[IP].dst)
                    elif raw.haslayer(IPv6):
                        src = str(raw[IPv6].src)
                        dst = str(raw[IPv6].dst)
                    else:
                        src = str(getattr(rec, 'src', '') or '')
                        dst = str(getattr(rec, 'dst', '') or '')
                    sport = int(getattr(raw[TCP], 'sport', 0) or 0)
                    dport = int(getattr(raw[TCP], 'dport', 0) or 0)
                    _accumulate(maps['TCP'], (src, sport), pkt_len, 'tx')
                    _accumulate(maps['TCP'], (dst, dport), pkt_len, 'rx')

                if raw is not None and raw.haslayer(UDP):
                    if raw.haslayer(IP):
                        src = str(raw[IP].src)
                        dst = str(raw[IP].dst)
                    elif raw.haslayer(IPv6):
                        src = str(raw[IPv6].src)
                        dst = str(raw[IPv6].dst)
                    else:
                        src = str(getattr(rec, 'src', '') or '')
                        dst = str(getattr(rec, 'dst', '') or '')
                    sport = int(getattr(raw[UDP], 'sport', 0) or 0)
                    dport = int(getattr(raw[UDP], 'dport', 0) or 0)
                    _accumulate(maps['UDP'], (src, sport), pkt_len, 'tx')
                    _accumulate(maps['UDP'], (dst, dport), pkt_len, 'rx')

            for tab_name, cols in table_defs.items():
                rows = []
                for key, vals in maps[tab_name].items():
                    if tab_name in {'TCP', 'UDP'}:
                        rows.append({'Address': key[0], 'Port': key[1], **vals})
                    else:
                        rows.append({'Address': key[0], **vals})
                rows.sort(key=lambda r: (str(r.get('Address', '')), int(r.get('Port', 0) or 0)))
                self._statistics_fill_table(tables[tab_name], cols, rows)

        def _selected_table_and_columns():
            name = tabs.tabText(tabs.currentIndex())
            return name, tables[name], table_defs[name]

        def _apply_as_filter():
            tab_name, table, _cols = _selected_table_and_columns()
            row = self._statistics_current_row(table)
            if not row:
                return
            address = str(row.get('Address', '') or '').strip()
            port = row.get('Port', None)
            expr = ''
            if tab_name == 'Ethernet':
                expr = f'eth.addr == {address}'
            elif tab_name == 'IPv4':
                expr = f'ip.addr == {address}'
            elif tab_name == 'IPv6':
                expr = f'ipv6.addr == {address}'
            elif tab_name == 'TCP' and port is not None:
                expr = f'ip.addr == {address} && tcp.port == {int(port)}'
            elif tab_name == 'UDP' and port is not None:
                expr = f'ip.addr == {address} && udp.port == {int(port)}'
            if expr:
                self._set_display_filter_text(expr, apply_now=True)

        def _copy_current():
            _tab_name, table, cols = _selected_table_and_columns()
            self._statistics_copy_rows(cols, getattr(table, '_stats_rows', []))

        def _export_current():
            tab_name, table, cols = _selected_table_and_columns()
            self._statistics_export_rows_csv(f'Endpoints {tab_name}', cols, getattr(table, '_stats_rows', []))

        refresh_btn.clicked.connect(_refresh)
        limit_check.toggled.connect(lambda _v: _refresh())
        apply_btn.clicked.connect(_apply_as_filter)
        copy_btn.clicked.connect(_copy_current)
        export_btn.clicked.connect(_export_current)
        close_btn.clicked.connect(dialog.accept)
        _refresh()
        dialog.resize(1180, 700)
        self._fit_widget_90(dialog)
        dialog.exec()

    def _on_statistics_packet_lengths(self):
        if not self.capture_view:
            QMessageBox.information(self, 'Packet Lengths', 'No capture is loaded.')
            return

        dialog = QDialog(self)
        dialog.setWindowTitle('Packet Lengths')
        layout = QVBoxLayout(dialog)

        top = QHBoxLayout()
        limit_check = QCheckBox('Limit to display filter', dialog)
        limit_check.setChecked(True)
        refresh_btn = QPushButton('Refresh', dialog)
        top.addWidget(limit_check)
        top.addWidget(refresh_btn)
        top.addStretch(1)
        layout.addLayout(top)

        tree = QTreeWidget(dialog)
        tree.setColumnCount(9)
        tree.setHeaderLabels(['Topic / Item', 'Count', 'Average', 'Min Val', 'Max Val', 'Rate (ms)', 'Percent', 'Burst Rate', 'Burst Start'])
        tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(tree, 1)

        bottom = QHBoxLayout()
        copy_btn = QPushButton('Copy', dialog)
        export_btn = QPushButton('Export CSV', dialog)
        close_btn = QPushButton('Close', dialog)
        bottom.addWidget(copy_btn)
        bottom.addWidget(export_btn)
        bottom.addStretch(1)
        bottom.addWidget(close_btn)
        layout.addLayout(bottom)

        buckets = [
            (0, 19), (20, 39), (40, 79), (80, 159), (160, 319),
            (320, 639), (640, 1279), (1280, 2559), (2560, 5119), (5120, None),
        ]

        def _bucket_label(lo: int, hi):
            if hi is None:
                return '5120 and greater'
            return f'{lo}-{hi}'

        def _set_stat_cells(item: QTreeWidgetItem, values: list[str]):
            for idx, text in enumerate(values, start=1):
                item.setText(idx, text)

        def _refresh():
            records = self._statistics_scope_records(limit_check.isChecked())
            total_packets = len(records)
            tree.clear()
            lengths = [int(getattr(r, 'length', 0) or 0) for r in records]
            times = [float(getattr(r, 'epoch_time', 0.0) or 0.0) for r in records]
            duration = max(0.0, (max(times) - min(times))) if len(times) >= 2 else 0.0

            root = QTreeWidgetItem(tree)
            root.setText(0, 'Packet lengths')

            total_avg = (sum(lengths) / len(lengths)) if lengths else 0.0
            total_min = min(lengths) if lengths else 0
            total_max = max(lengths) if lengths else 0
            total_rate = self._stats_rate_ms(total_packets, duration)
            total_burst, total_burst_start = self._stats_burst_rate(times)
            _set_stat_cells(root, [
                str(total_packets),
                f'{total_avg:.2f}' if total_packets else '-',
                str(total_min) if total_packets else '-',
                str(total_max) if total_packets else '-',
                f'{total_rate:.4f}',
                '100%' if total_packets else '0%',
                f'{total_burst:.4f}' if total_packets else '-',
                f'{total_burst_start:.3f}' if total_packets else '-',
            ])

            for lo, hi in buckets:
                if hi is None:
                    vals = [v for v in lengths if v >= lo]
                    tvals = [times[idx] for idx, v in enumerate(lengths) if v >= lo]
                else:
                    vals = [v for v in lengths if lo <= v <= hi]
                    tvals = [times[idx] for idx, v in enumerate(lengths) if lo <= v <= hi]
                count = len(vals)
                avg = (float(sum(vals)) / count) if count > 0 else 0.0
                mn = min(vals) if vals else 0
                mx = max(vals) if vals else 0
                rate = self._stats_rate_ms(count, duration)
                pct = (count * 100.0 / total_packets) if total_packets > 0 else 0.0
                burst_rate, burst_start = self._stats_burst_rate(tvals)
                child = QTreeWidgetItem(root)
                child.setText(0, _bucket_label(lo, hi))
                _set_stat_cells(child, [
                    str(count),
                    f'{avg:.2f}' if count else '-',
                    str(mn) if count else '-',
                    str(mx) if count else '-',
                    f'{rate:.4f}',
                    f'{pct:.2f}%',
                    f'{burst_rate:.4f}' if count else '-',
                    f'{burst_start:.3f}' if count else '-',
                ])

            tree.expandAll()

        refresh_btn.clicked.connect(_refresh)
        limit_check.toggled.connect(lambda _v: _refresh())

        def _copy_tree():
            lines = ['Topic / Item\tCount\tAverage\tMin Val\tMax Val\tRate (ms)\tPercent\tBurst Rate\tBurst Start']

            def _walk(item, depth=0):
                indent = '  ' * depth
                row = [f'{indent}{item.text(0)}'] + [item.text(i) for i in range(1, 9)]
                lines.append('\t'.join(row))
                for i in range(item.childCount()):
                    _walk(item.child(i), depth + 1)

            for i in range(tree.topLevelItemCount()):
                _walk(tree.topLevelItem(i), 0)
            QApplication.clipboard().setText('\n'.join(lines))

        def _export_tree():
            rows = []

            def _walk(item, depth=0):
                rows.append({
                    'Topic / Item': ('  ' * depth) + item.text(0),
                    'Count': item.text(1),
                    'Average': item.text(2),
                    'Min Val': item.text(3),
                    'Max Val': item.text(4),
                    'Rate (ms)': item.text(5),
                    'Percent': item.text(6),
                    'Burst Rate': item.text(7),
                    'Burst Start': item.text(8),
                })
                for i in range(item.childCount()):
                    _walk(item.child(i), depth + 1)

            for i in range(tree.topLevelItemCount()):
                _walk(tree.topLevelItem(i), 0)
            self._statistics_export_rows_csv('Packet Lengths', ['Topic / Item', 'Count', 'Average', 'Min Val', 'Max Val', 'Rate (ms)', 'Percent', 'Burst Rate', 'Burst Start'], rows)

        copy_btn.clicked.connect(_copy_tree)
        export_btn.clicked.connect(_export_tree)
        close_btn.clicked.connect(dialog.accept)
        _refresh()
        dialog.resize(980, 620)
        self._fit_widget_90(dialog)
        dialog.exec()

    def _on_statistics_flow_graph(self):
        if not self.capture_view:
            QMessageBox.information(self, 'Flow Graph', 'No capture is loaded.')
            return

        dialog = QDialog(self)
        dialog.setWindowTitle('Flow Graph')
        layout = QVBoxLayout(dialog)
        top_margin = 40
        row_h = 24
        left_margin = 120
        lane_w = 200

        graph_split = QSplitter(Qt.Orientation.Horizontal, dialog)
        scene = QGraphicsScene(dialog)
        view = QGraphicsView(scene, dialog)
        view.setRenderHint(QPainter.Antialiasing, True)
        view.setAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop)
        graph_split.addWidget(view)

        columns = ['Comment']
        table = self._statistics_make_table(columns, [])
        table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        table.verticalHeader().setVisible(False)
        table.verticalHeader().setDefaultSectionSize(row_h)
        table.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        table.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        table.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        small_font = QFont(table.font())
        small_font.setPointSizeF(max(6.0, small_font.pointSizeF() * 0.78))
        table.setFont(small_font)
        table.setStyleSheet('QTableWidget::item:selected { background-color: #2b78d4; color: white; }')
        graph_split.addWidget(table)
        graph_split.setSizes([1130, 260])
        graph_split.setHandleWidth(0)
        graph_split.setStyleSheet('')
        graph_split.setChildrenCollapsible(False)
        view.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        view.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        layout.addWidget(graph_split, 1)
        table.verticalScrollBar().setSingleStep(row_h)
        table.verticalScrollBar().setPageStep(row_h * 8)

        bottom = QHBoxLayout()
        limit_check = QCheckBox('Limit to display filter', dialog)
        limit_check.setChecked(True)
        bottom.addWidget(limit_check)
        bottom.addStretch(1)
        bottom.addWidget(QLabel('Flow type:', dialog))
        flow_combo = QComboBox(dialog)
        flow_combo.addItems(['All Flows', 'TCP Flows', 'UDP Flows', 'Selected Conversation'])
        bottom.addWidget(flow_combo)
        bottom.addStretch(1)
        bottom.addWidget(QLabel('Addresses:', dialog))
        addr_combo = QComboBox(dialog)
        addr_combo.addItems(['Any', 'IPv4 only', 'IPv6 only'])
        bottom.addWidget(addr_combo)
        refresh_btn = QPushButton('Refresh', dialog)
        reset_btn = QPushButton('Reset Diagram', dialog)
        go_btn = QPushButton('Go to Packet', dialog)
        apply_btn = QPushButton('Apply as Filter', dialog)
        export_btn = QPushButton('Export', dialog)
        help_btn = QPushButton('Help', dialog)
        close_btn = QPushButton('Close', dialog)
        for btn in (refresh_btn, reset_btn, go_btn, apply_btn, export_btn, close_btn, help_btn):
            bottom.addWidget(btn)
        layout.addLayout(bottom)

        def _scope_records() -> list:
            mode = str(flow_combo.currentText() or '')
            records = self._statistics_scope_records(limit_check.isChecked())
            if mode == 'Selected Conversation':
                cv = self.capture_view
                rec = cv.get_current_record() if cv else None
                if rec is None:
                    return []
                key = cv._conversation_key_for_record(rec)
                if key is None:
                    return []
                out = []
                for r in records:
                    if cv._conversation_key_for_record(r) == key:
                        out.append(r)
                return out
            if mode == 'TCP Flows':
                records = [r for r in records if str(getattr(r, 'protocol', '') or '').upper() == 'TCP']
            elif mode == 'UDP Flows':
                records = [r for r in records if str(getattr(r, 'protocol', '') or '').upper() == 'UDP']

            addr_mode = str(addr_combo.currentText() or 'Any')
            if addr_mode == 'IPv4 only':
                records = [r for r in records if '.' in str(getattr(r, 'src', '') or '') or '.' in str(getattr(r, 'dst', '') or '')]
            elif addr_mode == 'IPv6 only':
                records = [r for r in records if ':' in str(getattr(r, 'src', '') or '') or ':' in str(getattr(r, 'dst', '') or '')]
            return records

        def _conv_expr(rec) -> str:
            src = str(getattr(rec, 'src', '') or '')
            dst = str(getattr(rec, 'dst', '') or '')
            proto = str(getattr(rec, 'protocol', '') or '').upper()
            if not src or not dst:
                return ''
            if proto == 'TCP' and rec.sport is not None and rec.dport is not None:
                return f'ip.addr == {src} && ip.addr == {dst} && tcp.port == {int(rec.sport)} && tcp.port == {int(rec.dport)}'
            if proto == 'UDP' and rec.sport is not None and rec.dport is not None:
                return f'ip.addr == {src} && ip.addr == {dst} && udp.port == {int(rec.sport)} && udp.port == {int(rec.dport)}'
            if ':' in src or ':' in dst:
                return f'ipv6.addr == {src} && ipv6.addr == {dst}'
            return f'ip.addr == {src} && ip.addr == {dst}'

        _scene_state = {
            'row_area_width': left_margin + lane_w + 90,
            'header_items': [],
            'header_base_y': 4.0,
            'time_header': None,
            'header_bg': None,
            'header_height': 24,
            'top_margin': top_margin,
        }

        def _refresh():
            recs = sorted(_scope_records(), key=lambda r: int(getattr(r, 'number', 0) or 0))
            scene.clear()
            _scene_state['header_items'] = []
            _scene_state['time_header'] = None
            _scene_state['header_bg'] = None
            rows = []
            prev_scroll = int(table.verticalScrollBar().value() or 0)
            if not recs:
                self._statistics_fill_table(table, columns, rows)
                return

            prev_selected_no = int(self._statistics_current_row(table).get('__packet_no__', 0) or 0)

            first_time = float(getattr(recs[0], 'epoch_time', 0.0) or 0.0)
            endpoints = []
            endpoint_set = set()
            for rec in recs:
                src = str(getattr(rec, 'src', '') or '')
                dst = str(getattr(rec, 'dst', '') or '')
                for ep in (src, dst):
                    if ep and ep not in endpoint_set:
                        endpoint_set.add(ep)
                        endpoints.append(ep)
            if not endpoints:
                endpoints = ['Unknown']

            header_h = int(table.horizontalHeader().height() or 24)
            top_margin = max(24, header_h)
            _scene_state['top_margin'] = top_margin
            _scene_state['header_height'] = top_margin

            max_rows = min(len(recs), 1200)
            pen_axis = QPen(QColor(120, 120, 120))
            pen_arrow = QPen(QColor(20, 20, 20))
            pen_arrow.setWidth(1)
            info_font = QFont(small_font)
            port_font = QFont(info_font)
            port_font.setPointSizeF(max(5.0, info_font.pointSizeF() * 0.82))
            metrics = QFontMetrics(info_font)
            port_metrics = QFontMetrics(port_font)
            header_font = QFont(table.horizontalHeader().font())
            header_font.setBold(True)
            header_metrics = QFontMetrics(header_font)

            cv = self.capture_view
            cv_table = getattr(cv, 'table', None)

            def _row_palette(rec):
                if cv_table is None:
                    return QColor(255, 255, 255), QColor(0, 0, 0)
                try:
                    if not bool(getattr(cv_table, '_color_rules_enabled', True)):
                        return QColor(255, 255, 255), QColor(0, 0, 0)
                    if bool(getattr(rec, 'ignored', False)):
                        color = getattr(cv_table, '_ignored_color', QColor(230, 230, 230))
                        return QColor(color), QColor(100, 100, 100)
                    if bool(getattr(rec, 'marked', False)):
                        color = getattr(cv_table, '_marked_color', QColor(255, 255, 180))
                        return QColor(color), QColor(0, 0, 0)
                    if hasattr(cv_table, '_match_wireshark_style'):
                        color, text = cv_table._match_wireshark_style(rec)
                        if isinstance(color, QColor) and color.isValid():
                            if isinstance(text, QColor) and text.isValid():
                                return QColor(color), QColor(text)
                            return QColor(color), QColor(0, 0, 0)
                except Exception:
                    pass
                return QColor(255, 255, 255), QColor(0, 0, 0)

            def _fg_for_bg(bg: QColor) -> QColor:
                try:
                    if int(bg.lightness()) <= 95:
                        return QColor(255, 255, 255)
                except Exception:
                    pass
                return QColor(0, 0, 0)

            x_for = {}
            content_width = left_margin + max(1, len(endpoints)) * lane_w + 90
            viewport_width = int(max(0, view.viewport().width()))
            left_panel_width = 0
            try:
                split_sizes = graph_split.sizes()
                if split_sizes:
                    left_panel_width = int(max(0, split_sizes[0]))
            except Exception:
                left_panel_width = 0
            _scene_state['row_area_width'] = max(content_width, viewport_width, left_panel_width)
            header_bg = scene.addRect(
                0,
                0,
                int(_scene_state['row_area_width']),
                int(_scene_state['header_height']),
                QPen(Qt.PenStyle.NoPen),
                QColor(245, 245, 245),
            )
            header_bg.setZValue(20)
            _scene_state['header_bg'] = header_bg

            for idx, ep in enumerate(endpoints):
                x = left_margin + (idx * lane_w)
                x_for[ep] = x
                ep_text = header_metrics.elidedText(ep, Qt.TextElideMode.ElideMiddle, max(32, lane_w - 16))
                ep_item = scene.addText(ep_text, header_font)
                ep_item.setDefaultTextColor(QColor(20, 20, 20))
                ep_y = float(max(2, int((_scene_state['header_height'] - header_metrics.height()) / 2)))
                ep_item.setPos(x - (header_metrics.horizontalAdvance(ep_text) / 2.0), ep_y)
                ep_item.setZValue(30)
                _scene_state['header_items'].append(ep_item)
                axis = scene.addLine(x, top_margin - 8, x, top_margin + (max_rows + 2) * row_h, pen_axis)
                axis.setZValue(8)

            time_header = scene.addText('Time', header_font)
            _scene_state['header_base_y'] = float(max(2, int((_scene_state['header_height'] - header_metrics.height()) / 2)))
            time_header.setPos(12, _scene_state['header_base_y'])
            time_header.setZValue(30)
            _scene_state['time_header'] = time_header

            for ridx, rec in enumerate(recs[:max_rows]):
                row_top = top_margin + (ridx * row_h)
                row_center = row_top + (row_h / 2.0)
                t = float(getattr(rec, 'epoch_time', 0.0) or 0.0)
                src = str(getattr(rec, 'src', '') or '')
                dst = str(getattr(rec, 'dst', '') or '')
                proto = str(getattr(rec, 'protocol', '') or '')
                info = str(getattr(rec, 'info', '') or '')
                number = int(getattr(rec, 'number', 0) or 0)
                sport = getattr(rec, 'sport', None)
                dport = getattr(rec, 'dport', None)

                bg, fg = _row_palette(rec)
                row_pen = QPen(fg)
                row_pen.setWidth(1)
                scene.addRect(0, row_top, int(_scene_state['row_area_width']), row_h, QPen(Qt.PenStyle.NoPen), bg)

                rel_t = t - first_time
                t_item = scene.addText(f'{rel_t:.6f}')
                t_item.setDefaultTextColor(fg)
                t_item.setPos(12, row_top + 2)
                x1 = x_for.get(src, left_margin)
                x2 = x_for.get(dst, left_margin)

                text_start = min(x1, x2) + 24
                text_end = max(x1, x2) - 24
                available = max(20, int(text_end - text_start))
                info_text = metrics.elidedText(info, Qt.TextElideMode.ElideRight, available)
                text_w = metrics.horizontalAdvance(info_text)
                center_x = (x1 + x2) / 2.0
                text_x = max(text_start, min(center_x - (text_w / 2.0), text_end - text_w))
                gap_l = max(min(x1, x2), text_x - 5)
                gap_r = min(max(x1, x2), text_x + text_w + 5)

                if x1 <= x2:
                    if gap_l > x1:
                        scene.addLine(x1, row_center, gap_l, row_center, row_pen)
                    if x2 > gap_r:
                        scene.addLine(gap_r, row_center, x2, row_center, row_pen)
                else:
                    if x1 > gap_r:
                        scene.addLine(x1, row_center, gap_r, row_center, row_pen)
                    if gap_l > x2:
                        scene.addLine(gap_l, row_center, x2, row_center, row_pen)
                if x2 >= x1:
                    scene.addLine(x2 - 6, row_center - 3, x2, row_center, row_pen)
                    scene.addLine(x2 - 6, row_center + 3, x2, row_center, row_pen)
                else:
                    scene.addLine(x2 + 6, row_center - 3, x2, row_center, row_pen)
                    scene.addLine(x2 + 6, row_center + 3, x2, row_center, row_pen)

                left_port = str(int(sport)) if sport is not None else ''
                right_port = str(int(dport)) if dport is not None else ''
                if left_port:
                    left_item = scene.addText(left_port, port_font)
                    left_item.setDefaultTextColor(fg)
                    if x1 <= x2:
                        left_item.setPos(x1 - port_metrics.horizontalAdvance(left_port) - 6, row_top + 3)
                    else:
                        left_item.setPos(x1 + 6, row_top + 3)
                if right_port:
                    right_item = scene.addText(right_port, port_font)
                    right_item.setDefaultTextColor(fg)
                    if x2 >= x1:
                        right_item.setPos(x2 + 6, row_top + 3)
                    else:
                        right_item.setPos(x2 - port_metrics.horizontalAdvance(right_port) - 6, row_top + 3)

                info_item = scene.addText(info_text, info_font)
                info_item.setDefaultTextColor(fg)
                info_item.setPos(text_x, row_top + 1)

                comment = f'{proto}: {info}'.strip(': ')
                rows.append({
                    'Comment': comment,
                    '__packet_no__': number,
                    '__filter__': _conv_expr(rec),
                    '__row_color__': bg,
                    '__row_fg__': fg,
                })

            scene.setSceneRect(0, 0, int(_scene_state['row_area_width']), top_margin + (max_rows + 3) * row_h)
            self._statistics_fill_table(table, columns, rows)
            for row_idx in range(len(rows)):
                for col in range(table.columnCount()):
                    item = table.item(row_idx, col)
                    if item is not None:
                        item.setBackground(QColor(255, 255, 255))
                        item.setForeground(QColor(0, 0, 0))

            table.setRowCount(len(rows))
            for row_idx in range(len(rows)):
                table.setRowHeight(row_idx, row_h)

            if prev_selected_no > 0:
                for row_idx, row in enumerate(rows):
                    if int(row.get('__packet_no__', 0) or 0) == prev_selected_no:
                        table.selectRow(row_idx)
                        break

            table.verticalScrollBar().setValue(prev_scroll)
            _sync_scroll_from_table(table.verticalScrollBar().value())
            _update_scene_selection()

        _selection_rect = {'item': None}

        def _update_scene_selection():
            prev = _selection_rect.get('item')
            if prev is not None:
                scene.removeItem(prev)
                _selection_rect['item'] = None
            row = int(table.currentRow())
            if row < 0:
                return
            tm = int(_scene_state.get('top_margin', top_margin))
            y = tm + (row * row_h)
            width = int(_scene_state.get('row_area_width', left_margin + lane_w + 90))
            rect = scene.addRect(0, y, width, row_h, QPen(QColor('#1e90ff')), QColor(30, 144, 255, 70))
            rect.setZValue(1000)
            _selection_rect['item'] = rect

        def _sync_scroll_from_table(val: int):
            vbar = view.verticalScrollBar()
            target = max(0, int(val))
            if vbar.value() != target:
                vbar.setValue(target)
            bg = _scene_state.get('header_bg')
            if bg is not None:
                try:
                    r = bg.rect()
                    bg.setRect(r.x(), float(vbar.value()), r.width(), r.height())
                except Exception:
                    pass
            y = float(vbar.value()) + float(_scene_state.get('header_base_y', 4.0))
            for item in _scene_state.get('header_items', []):
                try:
                    p = item.pos()
                    item.setPos(p.x(), y)
                except Exception:
                    pass
            t_item = _scene_state.get('time_header')
            if t_item is not None:
                try:
                    p = t_item.pos()
                    t_item.setPos(p.x(), y)
                except Exception:
                    pass

        original_wheel = view.wheelEvent

        def _wheel(event):
            try:
                delta = int(event.angleDelta().y() or 0)
                if delta != 0:
                    bar = table.verticalScrollBar()
                    step = bar.singleStep() or 1
                    bar.setValue(bar.value() - (step if delta > 0 else -step))
                    event.accept()
                    return
            except Exception:
                pass
            original_wheel(event)

        original_mouse_press = view.mousePressEvent
        original_resize = view.resizeEvent

        def _mouse_press(event):
            try:
                pt = view.mapToScene(event.pos())
                y = float(pt.y())
                tm = float(_scene_state.get('top_margin', top_margin))
                row = int((y - tm) // row_h)
                if 0 <= row < table.rowCount():
                    table.selectRow(row)
                    _go_to_packet()
            except Exception:
                pass
            original_mouse_press(event)

        def _resize_event(event):
            original_resize(event)
            QTimer.singleShot(0, _refresh)

        def _go_to_packet():
            row = self._statistics_current_row(table)
            if not row:
                return
            try:
                self.capture_view.goto_packet_number(int(row.get('__packet_no__', 0) or 0))
            except Exception:
                pass

        def _apply_filter():
            row = self._statistics_current_row(table)
            expr = str(row.get('__filter__', '') or '').strip()
            if expr:
                self._set_display_filter_text(expr, apply_now=True)

        refresh_btn.clicked.connect(_refresh)
        flow_combo.currentTextChanged.connect(lambda _v: _refresh())
        addr_combo.currentTextChanged.connect(lambda _v: _refresh())
        limit_check.toggled.connect(lambda _v: _refresh())
        reset_btn.clicked.connect(lambda: _refresh())
        go_btn.clicked.connect(_go_to_packet)
        apply_btn.clicked.connect(_apply_filter)
        export_btn.clicked.connect(lambda: self._statistics_export_rows_csv('Flow Graph', columns, getattr(table, '_stats_rows', [])))
        help_btn.clicked.connect(lambda: QMessageBox.information(dialog, 'Flow Graph', 'Select a row then use Go to Packet.\nUse Flow type and Addresses to narrow the sequence diagram.'))
        table.verticalScrollBar().valueChanged.connect(_sync_scroll_from_table)
        view.mousePressEvent = _mouse_press
        view.wheelEvent = _wheel
        view.resizeEvent = _resize_event
        table.itemSelectionChanged.connect(_update_scene_selection)
        table.cellClicked.connect(lambda _r, _c: _go_to_packet())
        table.cellDoubleClicked.connect(lambda _r, _c: _go_to_packet())
        close_btn.clicked.connect(dialog.accept)
        _refresh()
        QTimer.singleShot(0, _refresh)
        dialog.resize(1420, 790)
        self._fit_widget_90(dialog)
        dialog.exec()

    def _on_statistics_http(self):
        if not self.capture_view:
            QMessageBox.information(self, 'HTTP Statistics', 'No capture is loaded.')
            return

        dialog = QDialog(self)
        dialog.setWindowTitle('HTTP / Packet Counter')
        layout = QVBoxLayout(dialog)

        top = QHBoxLayout()
        limit_check = QCheckBox('Limit to display filter', dialog)
        limit_check.setChecked(True)
        refresh_btn = QPushButton('Refresh', dialog)
        top.addWidget(limit_check)
        top.addWidget(refresh_btn)
        top.addStretch(1)
        layout.addLayout(top)

        tree = QTreeWidget(dialog)
        tree.setColumnCount(8)
        tree.setHeaderLabels(['Packet Type', 'Count', 'Average', 'Min Val', 'Max Val', 'Rate (ms)', 'Percent', 'Burst Rate'])
        tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(tree, 1)

        bottom = QHBoxLayout()
        apply_btn = QPushButton('Apply as Filter', dialog)
        copy_btn = QPushButton('Copy', dialog)
        export_btn = QPushButton('Export CSV', dialog)
        close_btn = QPushButton('Close', dialog)
        for btn in (apply_btn, copy_btn, export_btn):
            bottom.addWidget(btn)
        bottom.addStretch(1)
        bottom.addWidget(close_btn)
        layout.addLayout(bottom)

        def _http_request_method(rec) -> str:
            info = str(getattr(rec, 'info', '') or '').strip()
            m = re.match(r'^([A-Z]+)\s+\S+', info)
            return str(m.group(1)) if m else ''

        def _http_response_code(rec) -> str:
            info = str(getattr(rec, 'info', '') or '').strip()
            m = re.match(r'^HTTP/\d(?:\.\d)?\s+(\d{3})', info)
            return str(m.group(1)) if m else ''

        def _http_host(rec) -> str:
            try:
                helper = DisplayFilter()
                host = helper._http_host(rec)
                return str(host or '').strip()
            except Exception:
                return ''

        def _refresh():
            records = self._statistics_scope_records(limit_check.isChecked())
            tree.clear()
            req_counter = Counter()
            rsp_counter = Counter()
            broken = 0
            http_times = []

            for rec in records:
                metadata = getattr(rec, 'metadata', {}) or {}
                kind = str(metadata.get('http_kind', '') or '').strip().lower()
                if not kind and str(getattr(rec, 'protocol', '') or '').upper() == 'HTTP':
                    info = str(getattr(rec, 'info', '') or '').strip()
                    kind = 'response' if info.startswith('HTTP/') else 'request'
                if kind not in {'request', 'response'}:
                    continue
                http_times.append(float(getattr(rec, 'epoch_time', 0.0) or 0.0))
                if kind == 'request':
                    method = _http_request_method(rec)
                    req_counter[method or 'Unknown'] += 1
                else:
                    code = _http_response_code(rec)
                    if code:
                        rsp_counter[code] += 1
                    else:
                        broken += 1

            total_http = sum(req_counter.values()) + sum(rsp_counter.values()) + int(broken)
            duration = max(0.0, (max(http_times) - min(http_times))) if len(http_times) >= 2 else 0.0
            rate = self._stats_rate_ms(total_http, duration)
            burst_rate, _burst_start = self._stats_burst_rate(http_times)

            def _set_metrics(item: QTreeWidgetItem, count: int, percent: float):
                item.setText(1, str(int(count)))
                item.setText(2, '-')
                item.setText(3, '-')
                item.setText(4, '-')
                item.setText(5, f'{self._stats_rate_ms(count, duration):.4f}')
                item.setText(6, f'{percent:.0f}%' if percent in {0.0, 100.0} else f'{percent:.2f}%')
                item.setText(7, f'{burst_rate:.4f}' if count > 0 else '-')

            root = QTreeWidgetItem(tree)
            root.setText(0, 'Total HTTP Packets')
            _set_metrics(root, total_http, 100.0 if total_http > 0 else 0.0)

            other_http = 0
            other = QTreeWidgetItem(root)
            other.setText(0, 'Other HTTP packets')
            _set_metrics(other, other_http, (other_http * 100.0 / total_http) if total_http else 0.0)

            responses_total = sum(rsp_counter.values()) + int(broken)
            response_parent = QTreeWidgetItem(root)
            response_parent.setText(0, 'HTTP Response Packets')
            _set_metrics(response_parent, responses_total, (responses_total * 100.0 / total_http) if total_http else 0.0)

            broken_item = QTreeWidgetItem(response_parent)
            broken_item.setText(0, '???: broken')
            _set_metrics(broken_item, int(broken), (int(broken) * 100.0 / total_http) if total_http else 0.0)

            class_map = [('5xx: Server Error', '5'), ('4xx: Client Error', '4'), ('3xx: Redirection', '3'), ('2xx: Success', '2'), ('1xx: Informational', '1')]
            for label, prefix in class_map:
                cnt = sum(v for code, v in rsp_counter.items() if str(code).startswith(prefix))
                child = QTreeWidgetItem(response_parent)
                child.setText(0, label)
                _set_metrics(child, cnt, (cnt * 100.0 / total_http) if total_http else 0.0)

            request_parent = QTreeWidgetItem(root)
            request_parent.setText(0, 'HTTP Request Packets')
            request_total = sum(req_counter.values())
            _set_metrics(request_parent, request_total, (request_total * 100.0 / total_http) if total_http else 0.0)

            tree.expandAll()

        def _apply_filter():
            item = tree.currentItem()
            if item is None:
                return
            title = str(item.text(0) or '')
            expr = ''
            if title.startswith('1xx'):
                expr = 'detail.pair contains "Status Code: 1"'
            elif title.startswith('2xx'):
                expr = 'detail.pair contains "Status Code: 2"'
            elif title.startswith('3xx'):
                expr = 'detail.pair contains "Status Code: 3"'
            elif title.startswith('4xx'):
                expr = 'detail.pair contains "Status Code: 4"'
            elif title.startswith('5xx'):
                expr = 'detail.pair contains "Status Code: 5"'
            elif 'Request' in title:
                expr = 'detail.key contains "request"'
            elif 'Response' in title:
                expr = 'detail.key contains "response"'
            if expr:
                self._set_display_filter_text(expr, apply_now=True)

        refresh_btn.clicked.connect(_refresh)
        limit_check.toggled.connect(lambda _v: _refresh())
        apply_btn.clicked.connect(_apply_filter)

        def _copy_tree():
            lines = ['Packet Type\tCount\tAverage\tMin Val\tMax Val\tRate (ms)\tPercent\tBurst Rate']

            def _walk(item, depth=0):
                indent = '  ' * depth
                row = [f'{indent}{item.text(0)}'] + [item.text(i) for i in range(1, 8)]
                lines.append('\t'.join(row))
                for i in range(item.childCount()):
                    _walk(item.child(i), depth + 1)

            for i in range(tree.topLevelItemCount()):
                _walk(tree.topLevelItem(i), 0)
            QApplication.clipboard().setText('\n'.join(lines))

        def _export_tree():
            rows = []

            def _walk(item, depth=0):
                rows.append({
                    'Packet Type': ('  ' * depth) + item.text(0),
                    'Count': item.text(1),
                    'Average': item.text(2),
                    'Min Val': item.text(3),
                    'Max Val': item.text(4),
                    'Rate (ms)': item.text(5),
                    'Percent': item.text(6),
                    'Burst Rate': item.text(7),
                })
                for i in range(item.childCount()):
                    _walk(item.child(i), depth + 1)

            for i in range(tree.topLevelItemCount()):
                _walk(tree.topLevelItem(i), 0)
            self._statistics_export_rows_csv('HTTP Packet Counter', ['Packet Type', 'Count', 'Average', 'Min Val', 'Max Val', 'Rate (ms)', 'Percent', 'Burst Rate'], rows)

        copy_btn.clicked.connect(_copy_tree)
        export_btn.clicked.connect(_export_tree)
        close_btn.clicked.connect(dialog.accept)
        _refresh()
        dialog.resize(1020, 620)
        self._fit_widget_90(dialog)
        dialog.exec()

    def _on_statistics_ipv4(self):
        if not self.capture_view:
            QMessageBox.information(self, 'IPv4 Statistics', 'No capture is loaded.')
            return

        dialog = QDialog(self)
        dialog.setWindowTitle('IPv4 Statistics')
        layout = QVBoxLayout(dialog)

        top = QHBoxLayout()
        limit_check = QCheckBox('Limit to display filter', dialog)
        limit_check.setChecked(True)
        refresh_btn = QPushButton('Refresh', dialog)
        top.addWidget(limit_check)
        top.addWidget(refresh_btn)
        top.addStretch(1)
        layout.addLayout(top)

        tree = QTreeWidget(dialog)
        tree.setColumnCount(9)
        tree.setHeaderLabels(['Topic / Item', 'Count', 'Average', 'Min Val', 'Max Val', 'Rate (ms)', 'Percent', 'Burst Rate', 'Burst Start'])
        tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(tree, 1)

        bottom = QHBoxLayout()
        apply_btn = QPushButton('Apply as Filter', dialog)
        copy_btn = QPushButton('Copy', dialog)
        export_btn = QPushButton('Export CSV', dialog)
        close_btn = QPushButton('Close', dialog)
        for btn in (apply_btn, copy_btn, export_btn):
            bottom.addWidget(btn)
        bottom.addStretch(1)
        bottom.addWidget(close_btn)
        layout.addLayout(bottom)

        def _refresh():
            records = self._statistics_scope_records(limit_check.isChecked())
            tree.clear()
            addr_packets = Counter()
            addr_bytes = Counter()
            addr_times = defaultdict(list)
            ip_packet_count = 0
            all_times = []
            for rec in records:
                raw = getattr(rec, 'raw', None)
                if raw is None or not raw.haslayer(IP):
                    continue
                ip = raw[IP]
                ip_packet_count += 1
                ts = float(getattr(rec, 'epoch_time', 0.0) or 0.0)
                all_times.append(ts)
                pkt_len = int(getattr(rec, 'length', 0) or 0)
                for addr in (str(getattr(ip, 'src', '') or ''), str(getattr(ip, 'dst', '') or '')):
                    if not addr:
                        continue
                    addr_packets[addr] += 1
                    addr_bytes[addr] += pkt_len
                    addr_times[addr].append(ts)

            duration = max(0.0, (max(all_times) - min(all_times))) if len(all_times) >= 2 else 0.0
            root = QTreeWidgetItem(tree)
            root.setText(0, 'Ipv4 Statistics/All Addresses')
            root.setText(1, str(ip_packet_count))
            root.setText(2, '')
            root.setText(3, '')
            root.setText(4, '')
            root.setText(5, f'{self._stats_rate_ms(ip_packet_count, duration):.4f}')
            root.setText(6, '100%' if ip_packet_count > 0 else '0%')
            burst_rate, burst_start = self._stats_burst_rate(all_times)
            root.setText(7, f'{burst_rate:.4f}' if ip_packet_count > 0 else '0.0000')
            root.setText(8, f'{burst_start:.3f}' if ip_packet_count > 0 else '0.000')

            denom = max(1, ip_packet_count)
            for addr, cnt in sorted(addr_packets.items(), key=lambda kv: (-kv[1], kv[0])):
                child = QTreeWidgetItem(root)
                child.setText(0, str(addr))
                child.setData(0, Qt.UserRole, f'ip.addr == {addr}')
                child.setText(1, str(cnt))
                child.setText(2, '')
                child.setText(3, '')
                child.setText(4, '')
                child.setText(5, f'{self._stats_rate_ms(cnt, duration):.4f}')
                child.setText(6, f'{(cnt * 100.0 / denom):.2f}%')
                b_rate, b_start = self._stats_burst_rate(addr_times.get(addr, []))
                child.setText(7, f'{b_rate:.4f}')
                child.setText(8, f'{b_start:.3f}')

            tree.expandAll()

        def _apply_filter():
            item = tree.currentItem()
            if item is None:
                return
            expr = str(item.data(0, Qt.UserRole) or '').strip()
            if expr:
                self._set_display_filter_text(expr, apply_now=True)

        refresh_btn.clicked.connect(_refresh)
        limit_check.toggled.connect(lambda _v: _refresh())
        apply_btn.clicked.connect(_apply_filter)

        def _copy_tree():
            lines = ['Topic / Item\tCount\tAverage\tMin Val\tMax Val\tRate (ms)\tPercent\tBurst Rate\tBurst Start']

            def _walk(item: QTreeWidgetItem, depth=0):
                lines.append('\t'.join([('  ' * depth) + item.text(0)] + [item.text(i) for i in range(1, 9)]))
                for i in range(item.childCount()):
                    _walk(item.child(i), depth + 1)

            for i in range(tree.topLevelItemCount()):
                _walk(tree.topLevelItem(i), 0)
            QApplication.clipboard().setText('\n'.join(lines))

        def _export_tree():
            rows = []

            def _walk(item: QTreeWidgetItem, depth=0):
                rows.append({
                    'Topic / Item': ('  ' * depth) + item.text(0),
                    'Count': item.text(1),
                    'Average': item.text(2),
                    'Min Val': item.text(3),
                    'Max Val': item.text(4),
                    'Rate (ms)': item.text(5),
                    'Percent': item.text(6),
                    'Burst Rate': item.text(7),
                    'Burst Start': item.text(8),
                })
                for i in range(item.childCount()):
                    _walk(item.child(i), depth + 1)

            for i in range(tree.topLevelItemCount()):
                _walk(tree.topLevelItem(i), 0)
            self._statistics_export_rows_csv('IPv4 Statistics', ['Topic / Item', 'Count', 'Average', 'Min Val', 'Max Val', 'Rate (ms)', 'Percent', 'Burst Rate', 'Burst Start'], rows)

        copy_btn.clicked.connect(_copy_tree)
        export_btn.clicked.connect(_export_tree)
        close_btn.clicked.connect(dialog.accept)
        _refresh()
        dialog.resize(980, 620)
        self._fit_widget_90(dialog)
        dialog.exec()

    def _on_statistics_ipv6(self):
        if not self.capture_view:
            QMessageBox.information(self, 'IPv6 Statistics', 'No capture is loaded.')
            return

        dialog = QDialog(self)
        dialog.setWindowTitle('IPv6 Statistics')
        layout = QVBoxLayout(dialog)

        top = QHBoxLayout()
        limit_check = QCheckBox('Limit to display filter', dialog)
        limit_check.setChecked(True)
        refresh_btn = QPushButton('Refresh', dialog)
        top.addWidget(limit_check)
        top.addWidget(refresh_btn)
        top.addStretch(1)
        layout.addLayout(top)

        tree = QTreeWidget(dialog)
        tree.setColumnCount(9)
        tree.setHeaderLabels(['Topic / Item', 'Count', 'Average', 'Min Val', 'Max Val', 'Rate (ms)', 'Percent', 'Burst Rate', 'Burst Start'])
        tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(tree, 1)

        bottom = QHBoxLayout()
        apply_btn = QPushButton('Apply as Filter', dialog)
        copy_btn = QPushButton('Copy', dialog)
        export_btn = QPushButton('Export CSV', dialog)
        close_btn = QPushButton('Close', dialog)
        for btn in (apply_btn, copy_btn, export_btn):
            bottom.addWidget(btn)
        bottom.addStretch(1)
        bottom.addWidget(close_btn)
        layout.addLayout(bottom)

        def _refresh():
            records = self._statistics_scope_records(limit_check.isChecked())
            tree.clear()
            addr_packets = Counter()
            addr_bytes = Counter()
            addr_times = defaultdict(list)
            ip_packet_count = 0
            all_times = []
            for rec in records:
                raw = getattr(rec, 'raw', None)
                if raw is None or not raw.haslayer(IPv6):
                    continue
                ip6 = raw[IPv6]
                ip_packet_count += 1
                ts = float(getattr(rec, 'epoch_time', 0.0) or 0.0)
                all_times.append(ts)
                pkt_len = int(getattr(rec, 'length', 0) or 0)
                for addr in (str(getattr(ip6, 'src', '') or ''), str(getattr(ip6, 'dst', '') or '')):
                    if not addr:
                        continue
                    addr_packets[addr] += 1
                    addr_bytes[addr] += pkt_len
                    addr_times[addr].append(ts)

            duration = max(0.0, (max(all_times) - min(all_times))) if len(all_times) >= 2 else 0.0
            root = QTreeWidgetItem(tree)
            root.setText(0, 'Ipv6 Statistics/All Addresses')
            root.setText(1, str(ip_packet_count))
            root.setText(2, '')
            root.setText(3, '')
            root.setText(4, '')
            root.setText(5, f'{self._stats_rate_ms(ip_packet_count, duration):.4f}')
            root.setText(6, '100%' if ip_packet_count > 0 else '0%')
            burst_rate, burst_start = self._stats_burst_rate(all_times)
            root.setText(7, f'{burst_rate:.4f}' if ip_packet_count > 0 else '0.0000')
            root.setText(8, f'{burst_start:.3f}' if ip_packet_count > 0 else '0.000')

            denom = max(1, ip_packet_count)
            for addr, cnt in sorted(addr_packets.items(), key=lambda kv: (-kv[1], kv[0])):
                child = QTreeWidgetItem(root)
                child.setText(0, str(addr))
                child.setData(0, Qt.UserRole, f'ipv6.addr == {addr}')
                child.setText(1, str(cnt))
                child.setText(2, '')
                child.setText(3, '')
                child.setText(4, '')
                child.setText(5, f'{self._stats_rate_ms(cnt, duration):.4f}')
                child.setText(6, f'{(cnt * 100.0 / denom):.2f}%')
                b_rate, b_start = self._stats_burst_rate(addr_times.get(addr, []))
                child.setText(7, f'{b_rate:.4f}')
                child.setText(8, f'{b_start:.3f}')

            tree.expandAll()

        def _apply_filter():
            item = tree.currentItem()
            if item is None:
                return
            expr = str(item.data(0, Qt.UserRole) or '').strip()
            if expr:
                self._set_display_filter_text(expr, apply_now=True)

        refresh_btn.clicked.connect(_refresh)
        limit_check.toggled.connect(lambda _v: _refresh())
        apply_btn.clicked.connect(_apply_filter)

        def _copy_tree():
            lines = ['Topic / Item\tCount\tAverage\tMin Val\tMax Val\tRate (ms)\tPercent\tBurst Rate\tBurst Start']

            def _walk(item: QTreeWidgetItem, depth=0):
                lines.append('\t'.join([('  ' * depth) + item.text(0)] + [item.text(i) for i in range(1, 9)]))
                for i in range(item.childCount()):
                    _walk(item.child(i), depth + 1)

            for i in range(tree.topLevelItemCount()):
                _walk(tree.topLevelItem(i), 0)
            QApplication.clipboard().setText('\n'.join(lines))

        def _export_tree():
            rows = []

            def _walk(item: QTreeWidgetItem, depth=0):
                rows.append({
                    'Topic / Item': ('  ' * depth) + item.text(0),
                    'Count': item.text(1),
                    'Average': item.text(2),
                    'Min Val': item.text(3),
                    'Max Val': item.text(4),
                    'Rate (ms)': item.text(5),
                    'Percent': item.text(6),
                    'Burst Rate': item.text(7),
                    'Burst Start': item.text(8),
                })
                for i in range(item.childCount()):
                    _walk(item.child(i), depth + 1)

            for i in range(tree.topLevelItemCount()):
                _walk(tree.topLevelItem(i), 0)
            self._statistics_export_rows_csv('IPv6 Statistics', ['Topic / Item', 'Count', 'Average', 'Min Val', 'Max Val', 'Rate (ms)', 'Percent', 'Burst Rate', 'Burst Start'], rows)

        copy_btn.clicked.connect(_copy_tree)
        export_btn.clicked.connect(_export_tree)
        close_btn.clicked.connect(dialog.accept)
        _refresh()
        dialog.resize(980, 620)
        self._fit_widget_90(dialog)
        dialog.exec()

    def _on_conversations(self):
        """Xem conversations"""
        if self.capture_view:
            self.capture_view.show_conversations()

    def _on_about(self):
        """Hiển thị về Packetra"""
        dialog = QMessageBox(self)
        dialog.setWindowTitle('About Packetra')
        dialog.setIcon(QMessageBox.Information)
        dialog.setText(
            'Packetra - Network Packet Analyzer\n\n'
            'Version 1.0\n\n'
            'A powerful packet sniffer and analyzer tool.\n\n'
            'Built with Python, Scapy, and PySide6\n\n'
            'https://github.com/packetra/packetra'
        )
        dialog.setStandardButtons(QMessageBox.Ok)
        dialog.resize(900, 600)
        self._fit_widget_90(dialog)
        dialog.exec()

    def _on_about_qt(self):
        """Hiển thị về Qt"""
        dialog = QMessageBox(self)
        dialog.setWindowTitle('About Qt')
        dialog.setIcon(QMessageBox.Information)
        dialog.setText('Qt framework information is available in the official Qt documentation.')
        dialog.setStandardButtons(QMessageBox.Ok)
        dialog.resize(800, 500)
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

    def _on_capture_status_changed(self, status):
        """Cap nhat trang thai capture/statusbar."""
        status_text = str(status or '')
        self._refresh_status_metrics()
        self._sync_capture_buttons()
        self._refresh_go_menu_state()
        self._refresh_analyze_menu_state()
        self._update_capture_window_title()
        match = re.search(r'Selected frame\s+(\d+)', status_text)
        if match:
            self._status_mode = 'selected'
            self._selected_packet_number = int(match.group(1))
            self._update_packet_status_label()
        elif any(token in status_text for token in ('Loaded', 'Reloaded')):
            self._status_mode = 'activity'
            self._status_activity_kind = 'load'
            self._selected_packet_number = None
            self._update_packet_status_label()
        elif 'Display filter applied' in status_text:
            self._status_mode = 'filtered'
            self._selected_packet_number = None
            self._update_packet_status_label()
        elif any(token in status_text for token in ('Live capture', 'Capture stopped', 'Capture stopping')):
            self._status_mode = 'activity'
            self._status_activity_kind = 'capture'
            self._selected_packet_number = None
            self._update_packet_status_label()
        if self.capture_view and self.stacked_widget.currentWidget() is self.capture_view:
            self._update_toolbar_state('capture')

    def _on_display_filter_applied(self):
        cv = self.capture_view
        if cv and hasattr(cv, 'is_bulk_loading') and cv.is_bulk_loading():
            self._fit_all_custom_columns()
            self._refresh_analyze_custom_column_cells()
            return
        self._refresh_analyze_custom_column_cells()

    def _refresh_analyze_custom_column_cells_blocking(self):
        cv = self.capture_view
        if not cv or not self._analyze_custom_columns:
            return
        table = cv.table
        if table.columnCount() < 7 + len(self._analyze_custom_columns):
            return
        row_count = int(table.rowCount() or 0)
        visible_count = len(cv.visible_indices)
        if row_count <= 0 or visible_count <= 0:
            return
        max_rows = min(row_count, visible_count)
        self._custom_column_refresh_pending_rows = deque()
        self._custom_column_refresh_pending_set = set()
        self._custom_column_refresh_generation += 1
        table.setUpdatesEnabled(False)
        try:
            for row in range(max_rows):
                self._refresh_analyze_custom_columns_for_row(row)
        finally:
            table.setUpdatesEnabled(True)

    def _refresh_status_metrics(self):
        dropped = 0
        if self.capture_view:
            metrics = self.capture_view.get_status_metrics()
            dropped = int(metrics.get('dropped', 0) or 0)
        self.dropped_label.setText(f'Dropped: {dropped}')
        if self._status_mode == 'activity':
            self._update_packet_status_label()

    def _current_capture_duration_seconds(self):
        if self.capture_view and getattr(self.capture_view, 'records', None):
            records = self.capture_view.records
            if len(records) >= 2:
                try:
                    first = float(getattr(records[0], 'epoch_time', 0.0) or 0.0)
                    last = float(getattr(records[-1], 'epoch_time', 0.0) or 0.0)
                    return max(0.0, last - first)
                except Exception:
                    pass
        if self.capture_view and self.capture_view.is_capturing() and self._capture_started_monotonic is not None:
            return max(0.0, time.monotonic() - float(self._capture_started_monotonic))
        if self._last_capture_seconds is not None:
            return max(0.0, float(self._last_capture_seconds))
        return None

    def _update_packet_status_label(self):
        if self._status_mode == 'selected' and self._selected_packet_number is not None:
            self.packet_label.setText(f'Selected packet: {self._selected_packet_number}')
            return

        if self._status_mode == 'filtered':
            visible_count = 0
            total_count = 0
            if self.capture_view:
                visible_count = len(getattr(self.capture_view, 'visible_indices', []) or [])
                total_count = len(getattr(self.capture_view, 'records', []) or [])
            percent = (visible_count * 100.0 / total_count) if total_count else 0.0
            self.packet_label.setText(
                f'Filtered: {visible_count} packet{"s" if visible_count != 1 else ""} ({percent:.1f}%)'
            )
            return

        if self._status_activity_kind == 'capture':
            capture_secs = self._current_capture_duration_seconds()
            capture_text = (
                f'Capture in {float(capture_secs):.2f} seconds'
                if capture_secs is not None
                else 'Capture in -'
            )
            self.packet_label.setText(capture_text)
            return

        loaded_text = (
            f'Loaded in {float(self._last_loaded_seconds):.2f} seconds'
            if self._last_loaded_seconds is not None
            else 'Loaded in -'
        )
        self.packet_label.setText(loaded_text)

    def _on_detail_status_changed(self, field_name: str, byte_count: int):
        if field_name and byte_count > 0:
            unit = 'Byte'
            if self.capture_view and getattr(self.capture_view, 'details_tree', None):
                item = self.capture_view.details_tree.currentItem()
                if item:
                    title = str(item.text(0) or '').lower()
                    if ' bit' in title or 'bits' in title or (title and title[0] in '.01' and '=' in title):
                        unit = 'Bit'
            self.detail_field_label.setText(f'Field: {field_name} | {unit}: {byte_count}')
            self._refresh_analyze_menu_state()
            return
        self.detail_field_label.setText('Field: - | Byte: 0')
        self._refresh_analyze_menu_state()

    def _on_open_expert_information(self):
        if not self.capture_view:
            QMessageBox.information(self, 'Expert Information', 'No capture is loaded.')
            return

        entries = self.capture_view.get_expert_information()
        dialog = QDialog(self)
        dialog.setWindowTitle('Expert Information')
        layout = QVBoxLayout(dialog)

        tree = QTreeWidget(dialog)
        tree.setColumnCount(5)
        tree.setHeaderLabels(['Severity', 'Summary', 'Group', 'Protocol', 'Count'])
        tree.setRootIsDecorated(True)
        tree.setAlternatingRowColors(True)
        tree.header().setSectionResizeMode(1, QHeaderView.Stretch)

        grouped = {}
        for item in entries:
            key = (
                str(item.get('severity', '') or ''),
                str(item.get('summary', '') or ''),
                str(item.get('group', '') or ''),
                str(item.get('protocol', '') or ''),
            )
            grouped.setdefault(key, []).append(item)

        severity_order = {'Error': 0, 'Warning': 1, 'Warn': 1, 'Note': 2, 'Chat': 3}

        def _group_sort_key(group_item):
            (severity, summary, group, protocol), rows = group_item
            return (
                severity_order.get(str(severity), 99),
                str(protocol),
                str(group),
                str(summary),
                -len(rows),
            )

        for (severity, summary, group, protocol), rows in sorted(grouped.items(), key=_group_sort_key):
            parent = QTreeWidgetItem(tree)
            parent.setText(0, severity)
            parent.setText(1, summary)
            parent.setText(2, group)
            parent.setText(3, protocol)
            parent.setText(4, str(len(rows)))

            for row_item in sorted(rows, key=lambda x: int(x.get('packet', 0) or 0)):
                child = QTreeWidgetItem(parent)
                child.setText(0, f"Frame {int(row_item.get('packet', 0) or 0)}")
                child.setText(1, str(row_item.get('info', '') or ''))
                child.setText(2, str(row_item.get('group', '') or ''))
                child.setText(3, str(row_item.get('protocol', '') or ''))
                child.setText(4, '')
                child.setData(0, Qt.UserRole, int(row_item.get('packet', 0) or 0))

        tree.collapseAll()

        def _jump_to_packet(item, _column):
            packet_number = item.data(0, Qt.UserRole)
            if packet_number is None:
                return
            try:
                self.capture_view.goto_packet_number(int(packet_number))
                self.raise_()
                self.activateWindow()
            except Exception:
                pass

        tree.itemClicked.connect(_jump_to_packet)
        layout.addWidget(tree)

        if not entries:
            layout.addWidget(QLabel('No expert items were generated for the current capture.'))

        close_btn = QPushButton('Close', dialog)
        close_btn.clicked.connect(dialog.accept)
        layout.addWidget(close_btn)
        dialog.resize(960, 560)
        self._fit_widget_90(dialog)
        dialog.exec()

    def _on_open_capture_properties(self):
        if not self.capture_view:
            QMessageBox.information(self, 'Capture File Properties', 'No capture is loaded.')
            return

        dialog = QDialog(self)
        dialog.setWindowTitle('Capture File Properties')
        main_layout = QVBoxLayout(dialog)
        main_layout.setContentsMargins(8, 8, 8, 8)
        main_layout.setSpacing(8)

        # Single text browser for all content - formatted like a table
        content_browser = QTextBrowser(dialog)
        content_browser.setStyleSheet('QTextBrowser { border: none; background-color: white; }')
        main_layout.addWidget(content_browser)

        button_row = QHBoxLayout()
        button_row.setSpacing(8)
        refresh_btn = QPushButton('Refresh')
        copy_btn = QPushButton('Copy')
        save_text_btn = QPushButton('Save As Text')
        edit_comment_btn = QPushButton('Edit Comments')
        close_btn = QPushButton('Close')
        help_btn = QPushButton('Help')
        button_row.addWidget(refresh_btn)
        button_row.addStretch()
        button_row.addWidget(copy_btn)
        button_row.addWidget(save_text_btn)
        button_row.addWidget(edit_comment_btn)
        button_row.addWidget(close_btn)
        button_row.addWidget(help_btn)
        main_layout.addLayout(button_row)

        for btn in (refresh_btn, copy_btn, save_text_btn, edit_comment_btn, close_btn, help_btn):
            btn.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
            btn.setFixedWidth(btn.fontMetrics().horizontalAdvance(btn.text()) + 24)

        def fill_values():
            def safe_text(value, fallback='-'):
                text = str(value).strip() if value is not None else ''
                return text if text else fallback

            props = self.capture_view.get_capture_properties()
            LBL = 'width: 180px; padding-right: 20px; padding-top: 1px; padding-bottom: 1px;'
            html = ['<html><body style="padding: 0; margin: 0; line-height: 1.2;">']
            
            # File section
            html.append('<b>File</b>')
            html.append('<table cellpadding="1" cellspacing="0" style="border-collapse: collapse; margin-bottom: 10px; margin-top: 2px;">')
            html.append('<tr><td style="' + LBL + '">Name:</td><td>' + safe_text(props.get('file_path', ''), '-') + '</td></tr>')
            html.append('<tr><td style="' + LBL + '">Length:</td><td>' + safe_text(props.get('file_length', '-'), '-') + '</td></tr>')
            html.append('<tr><td style="' + LBL + '">Hash (SHA256):</td><td>' + safe_text(props.get('sha256', ''), '-') + '</td></tr>')
            html.append('<tr><td style="' + LBL + '">Hash (SHA1):</td><td>' + safe_text(props.get('sha1', ''), '-') + '</td></tr>')
            html.append('<tr><td style="' + LBL + '">Format:</td><td>' + safe_text(props.get('format', ''), '-') + '</td></tr>')
            html.append('<tr><td style="' + LBL + '">Encapsulation:</td><td>' + safe_text(props.get('encapsulation', ''), '-') + '</td></tr>')
            html.append('</table>')
            
            # Time section
            html.append('<b>Time</b>')
            html.append('<table cellpadding="1" cellspacing="0" style="border-collapse: collapse; margin-bottom: 10px; margin-top: 2px;">')
            html.append('<tr><td style="' + LBL + '">First packet:</td><td>' + safe_text(props.get('first_packet', '-'), '-') + '</td></tr>')
            html.append('<tr><td style="' + LBL + '">Last packet:</td><td>' + safe_text(props.get('last_packet', '-'), '-') + '</td></tr>')
            html.append('<tr><td style="' + LBL + '">Elapsed:</td><td>' + safe_text(props.get('elapsed', '00:00:00'), '00:00:00') + '</td></tr>')
            html.append('</table>')
            
            # Capture section
            html.append('<b>Capture</b>')
            html.append('<table cellpadding="1" cellspacing="0" style="border-collapse: collapse; margin-bottom: 10px; margin-top: 2px;">')
            html.append('<tr><td style="' + LBL + '">Hardware:</td><td>' + safe_text(props.get('capture_hardware', '-'), '-') + '</td></tr>')
            html.append('<tr><td style="' + LBL + '">OS:</td><td>' + safe_text(props.get('capture_os', '-'), '-') + '</td></tr>')
            html.append('<tr><td style="' + LBL + '">Application:</td><td>' + safe_text(props.get('capture_application', '-'), '-') + '</td></tr>')
            html.append('</table>')
            
            ICOL = 'padding-right: 20px; padding-top: 1px; padding-bottom: 1px;'
            # Interfaces section - display ALL interfaces from metadata
            html.append('<b>Interfaces</b>')
            html.append('<table cellpadding="1" cellspacing="0" style="border-collapse: collapse; margin-bottom: 10px; margin-top: 2px;">')
            html.append('<tr>')
            html.append('<td style="' + ICOL + '"><u>Interface</u></td>')
            html.append('<td style="' + ICOL + '"><u>Interface Description</u></td>')
            html.append('<td style="' + ICOL + '"><u>Dropped packets</u></td>')
            html.append('<td style="' + ICOL + '"><u>Capture filter</u></td>')
            html.append('<td style="' + ICOL + '"><u>Link type</u></td>')
            html.append('<td style="' + ICOL + '"><u>Packet size limit (snaplen)</u></td>')
            html.append('</tr>')
            
            # Display all interfaces from props['interfaces']
            interfaces = props.get('interfaces', [])
            if interfaces:
                for iface in interfaces:
                    html.append('<tr>')
                    iface_name = safe_text(iface.get('name', ''), '-')
                    iface_desc = safe_text(iface.get('description', ''), 'Unknown')
                    dropped = safe_text(iface.get('dropped_packets', '0 (0.0%)'), '0 (0.0%)')
                    capture_filter = safe_text(iface.get('capture_filter', 'none'), 'none')
                    link_type = safe_text(iface.get('link_type', 'Ethernet'), 'Ethernet')
                    snaplen = safe_text(iface.get('snaplen', '262144 bytes'), '262144 bytes')
                    
                    html.append('<td style="' + ICOL + '">' + iface_name + '</td>')
                    html.append('<td style="' + ICOL + '">' + iface_desc + '</td>')
                    html.append('<td style="' + ICOL + '">' + dropped + '</td>')
                    html.append('<td style="' + ICOL + '">' + capture_filter + '</td>')
                    html.append('<td style="' + ICOL + '">' + link_type + '</td>')
                    html.append('<td style="' + ICOL + '">' + snaplen + '</td>')
                    html.append('</tr>')
            else:
                # Fallback to single interface if no interfaces list
                html.append('<tr>')
                html.append('<td style="' + ICOL + '">' + safe_text(props.get('interface_name', '-'), '-') + '</td>')
                html.append('<td style="' + ICOL + '">' + safe_text(props.get('interface_description', 'Unknown'), 'Unknown') + '</td>')
                html.append('<td style="' + ICOL + '">0 (0.0%)</td>')
                html.append('<td style="' + ICOL + '">' + safe_text(props.get('interface_capture_filter', 'none'), 'none') + '</td>')
                html.append('<td style="' + ICOL + '">' + safe_text(props.get('interface_link_type', 'Ethernet'), 'Ethernet') + '</td>')
                html.append('<td style="' + ICOL + '">' + safe_text(props.get('interface_snaplen', '262144 bytes'), '262144 bytes') + '</td>')
                html.append('</tr>')
            
            html.append('</table>')
            
            SCOL = 'padding-right: 25px; padding-top: 1px; padding-bottom: 1px;'
            # Comments section - display file-level comment with proper line breaks
            html.append('<b>Comments</b>')
            file_comment = props.get('comment', '')
            if file_comment:
                # Escape HTML special characters and preserve newlines with <pre>
                file_comment = file_comment.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
                file_comment = file_comment.replace('\n', '<br>')
                html.append('<p style="margin: 2px 0 10px 0; white-space: pre-wrap; word-wrap: break-word;">' + file_comment + '</p>')
            else:
                html.append('<p style="margin: 2px 0 10px 0;">-</p>')
            
            # Statistics section
            html.append('<b>Statistics</b>')
            html.append('<table cellpadding="1" cellspacing="0" style="border-collapse: collapse; margin-bottom: 10px; margin-top: 2px;">')
            html.append('<tr>')
            html.append('<td style="' + SCOL + '"><u>Measurement</u></td>')
            html.append('<td style="' + SCOL + '"><u>Captured</u></td>')
            html.append('<td style="' + SCOL + '"><u>Displayed</u></td>')
            html.append('<td style="' + SCOL + '"><u>Marked</u></td>')
            html.append('</tr>')
            
            measurements = [
                'Packets',
                'Time span, s',
                'Average pps',
                'Average packet size, B',
                'Bytes',
                'Average bytes/s',
                'Average bits/s',
            ]
            stats_values = [
                [safe_text(props.get('packet_count', 0), '0'), safe_text(props.get('stats_packets_displayed', '0 (0.0%)'), '0 (0.0%)'), safe_text(props.get('stats_packets_marked', '-'), '-')],
                [safe_text(props.get('stats_time_span', '0.000'), '0.000'), safe_text(props.get('stats_time_span', '0.000'), '0.000'), '-'],
                [safe_text(props.get('stats_average_pps', '0.0'), '0.0'), safe_text(props.get('stats_average_pps', '0.0'), '0.0'), '-'],
                [safe_text(props.get('stats_average_packet_size', '0'), '0'), safe_text(props.get('stats_average_packet_size', '0'), '0'), '-'],
                [safe_text(props.get('total_bytes', 0), '0'), safe_text(props.get('stats_bytes_displayed', '0 (0.0%)'), '0 (0.0%)'), safe_text(props.get('stats_bytes_marked', '0'), '0')],
                [safe_text(props.get('stats_average_bytes_s', '0 k'), '0 k'), safe_text(props.get('stats_average_bytes_s', '0 k'), '0 k'), '-'],
                [safe_text(props.get('stats_average_bits_s', '0 k'), '0 k'), safe_text(props.get('stats_average_bits_s', '0 k'), '0 k'), '-'],
            ]
            for m, vals in zip(measurements, stats_values):
                html.append('<tr>')
                html.append('<td style="' + SCOL + '">' + m + '</td>')
                html.append('<td style="' + SCOL + '">' + vals[0] + '</td>')
                html.append('<td style="' + SCOL + '">' + vals[1] + '</td>')
                html.append('<td style="' + SCOL + '">' + vals[2] + '</td>')
                html.append('</tr>')
            
            html.append('</table>')
            html.append('</body></html>')
            content_browser.setHtml('\n'.join(html))

        def copy_to_clipboard():
            """Copy all content to clipboard"""
            text = content_browser.toPlainText()
            QApplication.clipboard().setText(text)
            QMessageBox.information(dialog, 'Copy', 'Content copied to clipboard!')

        def save_as_text():
            path, _ = QFileDialog.getSaveFileName(
                dialog,
                'Save Capture File Properties',
                str(Path.cwd() / 'capture_file_properties.txt'),
                'Text Files (*.txt);;Markdown Files (*.md);;All Files (*)',
            )
            if not path:
                return
            try:
                Path(path).write_text(content_browser.toPlainText(), encoding='utf-8')
            except Exception as exc:
                QMessageBox.critical(dialog, 'Save As Text', f'Cannot save file:\n{exc}')

        def edit_comment():
            props = self.capture_view.get_capture_properties()
            current = props.get('comment', '')
            
            text, ok = QInputDialog.getMultiLineText(dialog, 'Capture Comment', 'Comment:', current)
            if ok:
                self.capture_view.set_capture_comment(text)
                if self.capture_view.save_capture_comment_to_file():
                    QMessageBox.information(dialog, 'Comment Saved', 'Comment updated and saved to file successfully.')
                else:
                    QMessageBox.warning(
                        dialog,
                        'Save Failed',
                        'Comment updated in memory but could not be saved to file.\nOnly PCAPNG files support direct comment persistence.'
                    )
                fill_values()

        def show_help():
            QMessageBox.information(
                dialog,
                'Capture File Properties Help',
                'All content is selectable. Copy any text using Ctrl+C or right-click menu, or use the Copy button to copy all content at once. Select and copy as much as you need.'
            )

        fill_values()
        refresh_btn.clicked.connect(fill_values)
        copy_btn.clicked.connect(copy_to_clipboard)
        save_text_btn.clicked.connect(save_as_text)
        edit_comment_btn.clicked.connect(edit_comment)
        close_btn.clicked.connect(dialog.accept)
        help_btn.clicked.connect(show_help)

        dialog.resize(980, 760)
        self._fit_widget_90(dialog)
        dialog.exec()

    def _on_capture_options(self):
        """Mở Capture Options dialog"""
        read_only = bool(self.capture_view and self.capture_view.is_capturing())
        dialog = CaptureOptionsDialog(self, self.capture_view, read_only=read_only)
        result = dialog.exec()
        if result == QDialog.DialogCode.Accepted:
            self._apply_capture_defaults_to_view()
        self._refresh_capture_menu_state()

    def closeEvent(self, event):
        """Xử lý khi đóng ứng dụng"""
        # 1. If capturing, prompt to stop capture first
        if self.capture_view and self.capture_view.is_capturing():
            reply = QMessageBox.question(
                self,
                'Confirm',
                'Đang capture. Bạn có muốn dừng?',
                QMessageBox.Yes | QMessageBox.No
            )
            if reply == QMessageBox.No:
                event.ignore()
                return
            self.capture_view.stop_capture()

        # 2. If there are unsaved changes, prompt to save/discard/cancel
        if self.capture_view and hasattr(self.capture_view, 'has_unsaved_changes') and self.capture_view.has_unsaved_changes():
            reply = QMessageBox.question(
                self,
                'Unsaved Changes',
                'Có thay đổi chưa lưu. Bạn có muốn lưu lại trước khi thoát?',
                QMessageBox.Save | QMessageBox.Discard | QMessageBox.Cancel,
                QMessageBox.Save
            )
            if reply == QMessageBox.Save:
                # Attempt to save, if user cancels save dialog, abort exit
                result = self.capture_view.save_file(force_dialog=False)
                if not result:
                    event.ignore()
                    return
            elif reply == QMessageBox.Cancel:
                event.ignore()
                return
            # If Discard, just continue

        # Reset Output and Options settings before closing app
        self._save_main_window_placement_if_needed()
        self._reset_output_options_on_close()
        
        event.accept()
    
    def _reset_output_options_on_close(self):
        """Reset Output and Options tab settings to defaults when app closes."""
        from PySide6.QtCore import QSettings
        settings = QSettings('Packetra', 'Packetra')
        
        # Reset all output/* settings
        for key in list(settings.allKeys()):
            if key.startswith('output/'):
                settings.remove(key)
        
        # Reset stop_* settings, but keep resolve_* and realtime/autoscroll
        stop_keys = ['stop_packets_enabled', 'stop_packets_value', 'stop_files_enabled', 'stop_files_value',
                     'stop_size_enabled', 'stop_size_value', 'stop_size_unit',
                     'stop_duration_enabled', 'stop_duration_value', 'stop_duration_unit']
        for key in stop_keys:
            settings.remove(f'options/{key}')
