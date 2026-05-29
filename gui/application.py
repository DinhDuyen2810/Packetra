import logging
import socket
import json
import math
import pickle
import csv
import os
import re
import time
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from PySide6.QtCore import Qt, QTimer, QSize, QPoint, QSettings
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QStackedWidget,
    QMenuBar, QToolBar, QLabel, QMenu, QMessageBox, QFileDialog,
    QSizePolicy, QToolButton, QDialog, QTableWidget, QTableWidgetItem,
    QHeaderView, QPushButton, QTextEdit, QInputDialog, QGridLayout, QScrollArea,
    QFrame, QTextBrowser, QTabWidget, QCheckBox, QSpinBox, QLineEdit, QComboBox,
    QAbstractItemView, QTreeWidget, QTreeWidgetItem, QToolTip, QRadioButton, QGroupBox, QButtonGroup
)
from PySide6.QtGui import QAction, QIcon, QKeySequence, QPixmap, QTextDocument
from PySide6.QtPrintSupport import QPrintDialog, QPrinter
from scapy.all import IP, IPv6, TCP, UDP

from gui.interface_selector_view import InterfaceSelectorView
from gui.capture_view import CaptureView
from gui.manage_interfaces_dialog import ManageInterfacesDialog
from core.flow_engine import (
    analyze_flows,
    export_packets_to_csv,
    export_pcap_to_csv,
    PacketraModelAdapter,
    FlowFeatureExtractor,
)
from core.flow_engine.cic_reference import extract_cic_rows_from_packets
from utils.pcap_io import normalize_capture_extension, iter_pcap_packets, save_capture_file

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


class CaptureOptionsDialog(QDialog):
    """Capture Options dialog với 3 tabs: Input, Output, Options"""
    
    def __init__(self, parent, capture_view):
        super().__init__(parent)
        self.setWindowTitle('Capture Options')
        self.capture_view = capture_view
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
        filter_layout.addWidget(filter_label)
        filter_layout.addWidget(self.filter_input)
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
            promisc_cb.setChecked(False if is_pipe else True)
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
        checked_count = sum(1 for cb in self.promisc_checkboxes.values() if cb.isChecked())
        total_count = len(self.promisc_checkboxes)
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
            cb.blockSignals(True)
            cb.setChecked(checked)
            cb.blockSignals(False)
    
    def _on_monitor_all_changed(self, state):
        # Removed monitor mode logic (not needed)
        pass
    
    def _on_start_from_options(self):
        """Handle Start button click in Capture Options"""
        item = self._get_selected_interface_item()
        if not item:
            QMessageBox.warning(self, 'No Interface', 'Please select an interface in the Input tab.')
            return
        self._start_capture_with_item(item)

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
        capture_filter = item.data(6, Qt.UserRole)
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
        'Fwd Header Length', 'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate',
        'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate', 'Subflow Fwd Packets',
        'Subflow Fwd Bytes', 'Subflow Bwd Packets', 'Subflow Bwd Bytes', 'Init_Win_bytes_forward',
        'Init_Win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward', 'Active Mean', 'Active Std',
        'Active Max', 'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min', 'Label'
    ]

    AI_DROP_FOR_ML = {'Flow ID', 'Source IP', 'Source Port', 'Destination IP', 'Protocol', 'Timestamp'}
    AI_DROP_FOR_INFERENCE = AI_DROP_FOR_ML | {'Label'}
    AI_MODEL_DIR = Path(__file__).resolve().parents[1] / 'ai'
    AI_MODEL_FILE = 'xgb_ids_model.json'
    AI_LABEL_ENCODER_FILE = 'label_encoder.pkl'
    AI_FEATURE_COLUMNS_FILE = 'feature_columns.json'
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

        # Build UI
        self._build_ui()
        self._connect_signals()

        # Show interface selector by default
        self.show_interface_selector()

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
        view_menu.addAction(self.action_view_resize_all_columns)
        self.action_view_show_packet_new_window = QAction('Show Packet in &New Window', self)
        view_menu.addAction(self.action_view_show_packet_new_window)
        self.action_view_redissect_packets = QAction('&Redissect Packets', self)
        view_menu.addAction(self.action_view_redissect_packets)
        self.action_view_reload_as_format_capture = QAction('Reload as File Format/&Capture', self)
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
        go_menu.addAction(self.action_go_back)
        self.action_go_forward = QAction('&Forward', self)
        go_menu.addAction(self.action_go_forward)
        go_menu.addSeparator()
        self.action_go_to_packet = QAction('Go to &Packet...', self)
        go_menu.addAction(self.action_go_to_packet)
        self.action_go_to_corresponding_packet = QAction('Go to C&orresponding Packet', self)
        go_menu.addAction(self.action_go_to_corresponding_packet)
        go_menu.addSeparator()
        self.action_go_previous_packet = QAction('&Previous Packet', self)
        go_menu.addAction(self.action_go_previous_packet)
        self.action_go_next_packet = QAction('&Next Packet', self)
        go_menu.addAction(self.action_go_next_packet)
        self.action_go_first_packet = QAction('&First Packet', self)
        go_menu.addAction(self.action_go_first_packet)
        self.action_go_last_packet = QAction('&Last Packet', self)
        go_menu.addAction(self.action_go_last_packet)
        go_menu.addSeparator()
        self.action_go_previous_packet_conversation = QAction('Previous Packet in C&onversation', self)
        go_menu.addAction(self.action_go_previous_packet_conversation)
        self.action_go_next_packet_conversation = QAction('Next Packet in Con&versation', self)
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

        # Hidden non-spec statistics actions
        self.action_summary = QAction('&Summary', self)
        self.action_io_graph = QAction('&I/O Graph', self)

        # Hidden menus not in current tab feature specs (keep actions for compatibility)
        self.action_advanced_dashboard = QAction('&Dashboard', self)
        self.action_advanced_demo_packet = QAction('&Demo Packet', self)
        self.action_advanced_draw_topo = QAction('&Draw Topo', self)
        self.action_advanced_ai_analyst = QAction('&AI Analyst', self)

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
        self.action_find_next.triggered.connect(lambda: self._on_menu_feature_placeholder('Edit > Find Next'))
        self.action_find_previous.triggered.connect(lambda: self._on_menu_feature_placeholder('Edit > Find Previous'))
        self.action_mark_unmark_selected.triggered.connect(lambda: self._on_menu_feature_placeholder('Edit > Mark/Unmark Selected'))
        self.action_mark_unmark_all_displayed.triggered.connect(lambda: self._on_menu_feature_placeholder('Edit > Mark/Unmark All Displayed Packets'))
        self.action_next_mark.triggered.connect(lambda: self._on_menu_feature_placeholder('Edit > Next Mark'))
        self.action_previous_mark.triggered.connect(lambda: self._on_menu_feature_placeholder('Edit > Previous Mark'))
        self.action_ignore_unignore_selected.triggered.connect(lambda: self._on_menu_feature_placeholder('Edit > Ignore/Unignore Selected'))
        self.action_ignore_unignore_all_displayed.triggered.connect(lambda: self._on_menu_feature_placeholder('Edit > Ignore/Unignore All Displayed'))
        self.action_packet_comment.triggered.connect(lambda: self._on_menu_feature_placeholder('Edit > Packet Comment...'))
        self.action_delete_all_packet_comments.triggered.connect(lambda: self._on_menu_feature_placeholder('Edit > Delete All Packet Comments'))
        self.action_preferences.triggered.connect(lambda: self._on_menu_feature_placeholder('Edit > Preferences...'))

        # View menu
        self.action_view_main_toolbar.triggered.connect(self._on_toggle_main_toolbar)
        self.action_view_filter_toolbar.triggered.connect(lambda checked: self._on_menu_feature_placeholder('View > Filter Toolbar'))
        self.action_view_statusbar.triggered.connect(self._on_toggle_statusbar)
        self.action_view_packet_list.triggered.connect(lambda checked: self._on_menu_feature_placeholder('View > Packet List'))
        self.action_view_packet_details.triggered.connect(lambda checked: self._on_menu_feature_placeholder('View > Packet Details'))
        self.action_view_packet_bytes.triggered.connect(lambda checked: self._on_menu_feature_placeholder('View > Packet Bytes'))
        self.action_view_packet_diagram.triggered.connect(lambda checked: self._on_menu_feature_placeholder('View > Packet Diagram'))
        self.action_zoom_in.triggered.connect(self._on_zoom_in)
        self.action_zoom_out.triggered.connect(self._on_zoom_out)
        self.action_zoom_reset.triggered.connect(self._on_zoom_reset)
        self.action_expand_subtrees.triggered.connect(lambda: self._on_menu_feature_placeholder('View > Expand Subtrees'))
        self.action_collapse_subtrees.triggered.connect(lambda: self._on_menu_feature_placeholder('View > Collapse Subtrees'))
        self.action_expand_all.triggered.connect(lambda: self._on_menu_feature_placeholder('View > Expand All'))
        self.action_collapse_all.triggered.connect(lambda: self._on_menu_feature_placeholder('View > Collapse All'))
        self.action_view_colorize_packet_list.triggered.connect(self._on_toggle_color_rules)
        self.action_view_colorize_conversation.triggered.connect(lambda: self._on_menu_feature_placeholder('View > Colorize Conversation'))
        self.action_view_coloring_rules.triggered.connect(lambda: self._on_menu_feature_placeholder('View > Coloring Rules...'))
        self.action_view_resize_all_columns.triggered.connect(self._on_resize_columns)
        self.action_view_show_packet_new_window.triggered.connect(lambda: self._on_menu_feature_placeholder('View > Show Packet in New Window'))
        self.action_view_redissect_packets.triggered.connect(lambda: self._on_menu_feature_placeholder('View > Redissect Packets'))
        self.action_view_reload_as_format_capture.triggered.connect(lambda: self._on_menu_feature_placeholder('View > Reload as File Format/Capture'))
        self.action_view_reload.triggered.connect(self._on_reload_file)

        # Go menu
        self.action_go_back.triggered.connect(lambda: self._on_menu_feature_placeholder('Go > Back'))
        self.action_go_forward.triggered.connect(lambda: self._on_menu_feature_placeholder('Go > Forward'))
        self.action_go_to_packet.triggered.connect(self._on_toggle_go_to_packet)
        self.action_go_to_corresponding_packet.triggered.connect(lambda: self._on_menu_feature_placeholder('Go > Go to Corresponding Packet'))
        self.action_go_previous_packet.triggered.connect(self._on_go_previous_packet)
        self.action_go_next_packet.triggered.connect(self._on_go_next_packet)
        self.action_go_first_packet.triggered.connect(self._on_go_first_packet)
        self.action_go_last_packet.triggered.connect(self._on_go_last_packet)
        self.action_go_previous_packet_conversation.triggered.connect(lambda: self._on_menu_feature_placeholder('Go > Previous Packet In Conversation'))
        self.action_go_next_packet_conversation.triggered.connect(lambda: self._on_menu_feature_placeholder('Go > Next Packet In Conversation'))
        self.action_go_auto_scroll_live_capture.triggered.connect(self._on_toggle_auto_scroll)

        # Capture menu
        self.action_capture_options.triggered.connect(self._on_capture_options)
        self.action_start_capture.triggered.connect(self._on_start_capture)
        self.action_stop_capture.triggered.connect(self._on_stop_capture)
        self.action_restart_capture.triggered.connect(self._on_restart_capture)
        self.action_capture_filters.triggered.connect(lambda: self._on_menu_feature_placeholder('Capture > Capture Filters...'))
        self.action_refresh_interfaces.triggered.connect(self._on_refresh_interfaces)

        # Analyze menu
        self.action_display_filter_macros.triggered.connect(lambda: self._on_menu_feature_placeholder('Analyze > Display Filter Macros...'))
        self.action_display_filter_expression.triggered.connect(lambda: self._on_menu_feature_placeholder('Analyze > Display Filter Expression...'))
        self.action_apply_as_column.triggered.connect(lambda: self._on_menu_feature_placeholder('Analyze > Apply as Column'))
        self.action_apply_as_filter.triggered.connect(lambda: self._on_menu_feature_placeholder('Analyze > Apply as Filter'))
        self.action_conversation_filter.triggered.connect(lambda: self._on_menu_feature_placeholder('Analyze > Conversation Filter'))
        self.action_follow_stream.triggered.connect(lambda: self._on_menu_feature_placeholder('Analyze > Follow'))
        self.action_expert_info.triggered.connect(self._on_open_expert_information)

        # Statistics menu
        self.action_capture_file_properties.triggered.connect(self._on_open_capture_properties)
        self.action_resolved_addresses.triggered.connect(lambda: self._on_menu_feature_placeholder('Statistics > Resolved Addresses'))
        self.action_protocol_hierarchy.triggered.connect(lambda: self._on_menu_feature_placeholder('Statistics > Protocol Hierarchy'))
        self.action_conversations.triggered.connect(self._on_conversations)
        self.action_endpoints.triggered.connect(lambda: self._on_menu_feature_placeholder('Statistics > Endpoints'))
        self.action_packet_lengths.triggered.connect(lambda: self._on_menu_feature_placeholder('Statistics > Packet Lengths'))
        self.action_flow_graph.triggered.connect(lambda: self._on_menu_feature_placeholder('Statistics > Flow Graph'))
        self.action_http_statistics.triggered.connect(lambda: self._on_menu_feature_placeholder('Statistics > HTTP'))
        self.action_ipv4_statistics.triggered.connect(lambda: self._on_menu_feature_placeholder('Statistics > IPv4 Statistics'))
        self.action_ipv6_statistics.triggered.connect(lambda: self._on_menu_feature_placeholder('Statistics > IPv6 Statistics'))

        # Advanced Analysis
        self.action_advanced_dashboard.triggered.connect(lambda: self._on_advanced_analysis_action('Dashboard'))
        self.action_advanced_demo_packet.triggered.connect(lambda: self._on_advanced_analysis_action('Demo Packet'))
        self.action_advanced_draw_topo.triggered.connect(lambda: self._on_advanced_analysis_action('Draw Topo'))
        self.action_advanced_ai_analyst.triggered.connect(lambda: self._on_advanced_analysis_action('AI Analyst'))

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

        QMessageBox.information(
            self,
            'Advanced Analysis',
            f'"{feature_name}" is available in Advanced Analysis and will be integrated with full workflow soon.',
        )

    def _parse_ai_packet_selector(self, selector: str, available_numbers: list[int]) -> list[int]:
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

    def _build_ai_traffic_rows(self, records: list) -> list[list]:
        packets = [getattr(r, 'raw', None) for r in records if getattr(r, 'raw', None) is not None]
        if not packets:
            return []
        source_rows = extract_cic_rows_from_packets(packets)
        rows = []
        source_key_map = {
            'Source IP': 'src_ip',
            'Source Port': 'src_port',
            'Destination IP': 'dst_ip',
            'Destination Port': 'dst_port',
            'Protocol': 'protocol',
            'Timestamp': 'timestamp',
            'Flow Duration': 'flow_duration',
            'Total Fwd Packets': 'tot_fwd_pkts',
            'Total Backward Packets': 'tot_bwd_pkts',
            'Total Length of Fwd Packets': 'totlen_fwd_pkts',
            'Total Length of Bwd Packets': 'totlen_bwd_pkts',
            'Fwd Packet Length Max': 'fwd_pkt_len_max',
            'Fwd Packet Length Min': 'fwd_pkt_len_min',
            'Fwd Packet Length Mean': 'fwd_pkt_len_mean',
            'Fwd Packet Length Std': 'fwd_pkt_len_std',
            'Bwd Packet Length Max': 'bwd_pkt_len_max',
            'Bwd Packet Length Min': 'bwd_pkt_len_min',
            'Bwd Packet Length Mean': 'bwd_pkt_len_mean',
            'Bwd Packet Length Std': 'bwd_pkt_len_std',
            'Flow Bytes/s': 'flow_byts_s',
            'Flow Packets/s': 'flow_pkts_s',
            'Flow IAT Mean': 'flow_iat_mean',
            'Flow IAT Std': 'flow_iat_std',
            'Flow IAT Max': 'flow_iat_max',
            'Flow IAT Min': 'flow_iat_min',
            'Fwd IAT Total': 'fwd_iat_tot',
            'Fwd IAT Mean': 'fwd_iat_mean',
            'Fwd IAT Std': 'fwd_iat_std',
            'Fwd IAT Max': 'fwd_iat_max',
            'Fwd IAT Min': 'fwd_iat_min',
            'Bwd IAT Total': 'bwd_iat_tot',
            'Bwd IAT Mean': 'bwd_iat_mean',
            'Bwd IAT Std': 'bwd_iat_std',
            'Bwd IAT Max': 'bwd_iat_max',
            'Bwd IAT Min': 'bwd_iat_min',
            'Fwd PSH Flags': 'fwd_psh_flags',
            'Bwd PSH Flags': 'bwd_psh_flags',
            'Fwd URG Flags': 'fwd_urg_flags',
            'Bwd URG Flags': 'bwd_urg_flags',
            'Fwd Header Length': 'fwd_header_len',
            'Bwd Header Length': 'bwd_header_len',
            'Fwd Packets/s': 'fwd_pkts_s',
            'Bwd Packets/s': 'bwd_pkts_s',
            'Min Packet Length': 'pkt_len_min',
            'Max Packet Length': 'pkt_len_max',
            'Packet Length Mean': 'pkt_len_mean',
            'Packet Length Std': 'pkt_len_std',
            'Packet Length Variance': 'pkt_len_var',
            'FIN Flag Count': 'fin_flag_cnt',
            'SYN Flag Count': 'syn_flag_cnt',
            'RST Flag Count': 'rst_flag_cnt',
            'PSH Flag Count': 'psh_flag_cnt',
            'ACK Flag Count': 'ack_flag_cnt',
            'URG Flag Count': 'urg_flag_cnt',
            'CWE Flag Count': 'cwr_flag_count',
            'ECE Flag Count': 'ece_flag_cnt',
            'Down/Up Ratio': 'down_up_ratio',
            'Average Packet Size': 'pkt_size_avg',
            'Avg Fwd Segment Size': 'fwd_seg_size_avg',
            'Avg Bwd Segment Size': 'bwd_seg_size_avg',
            'Fwd Avg Bytes/Bulk': 'fwd_byts_b_avg',
            'Fwd Avg Packets/Bulk': 'fwd_pkts_b_avg',
            'Fwd Avg Bulk Rate': 'fwd_blk_rate_avg',
            'Bwd Avg Bytes/Bulk': 'bwd_byts_b_avg',
            'Bwd Avg Packets/Bulk': 'bwd_pkts_b_avg',
            'Bwd Avg Bulk Rate': 'bwd_blk_rate_avg',
            'Subflow Fwd Packets': 'subflow_fwd_pkts',
            'Subflow Fwd Bytes': 'subflow_fwd_byts',
            'Subflow Bwd Packets': 'subflow_bwd_pkts',
            'Subflow Bwd Bytes': 'subflow_bwd_byts',
            'Init_Win_bytes_forward': 'init_fwd_win_byts',
            'Init_Win_bytes_backward': 'init_bwd_win_byts',
            'act_data_pkt_fwd': 'fwd_act_data_pkts',
            'min_seg_size_forward': 'fwd_seg_size_min',
            'Active Mean': 'active_mean',
            'Active Std': 'active_std',
            'Active Max': 'active_max',
            'Active Min': 'active_min',
            'Idle Mean': 'idle_mean',
            'Idle Std': 'idle_std',
            'Idle Max': 'idle_max',
            'Idle Min': 'idle_min',
        }
        for src in source_rows:
            flow_id = f"{src.get('src_ip', '')}-{src.get('dst_ip', '')}-{src.get('src_port', 0)}-{src.get('dst_port', 0)}-{src.get('protocol', '')}"
            row = []
            for col in self.AI_TRAFFIC_COLUMNS:
                name = str(col).strip()
                if name == 'Label':
                    row.append('BENIGN')
                elif name == 'Flow ID':
                    row.append(flow_id)
                else:
                    row.append(src.get(source_key_map.get(name, ''), 0))
            rows.append(row)
        return rows

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

    def _load_ai_model_bundle(self):
        if self._ai_model_bundle is not None:
            return self._ai_model_bundle

        try:
            import numpy as np
            import xgboost as xgb
        except Exception as exc:
            raise RuntimeError(
                'Thieu thu vien AI inference. Hay cai dependencies trong requirements.txt '
                '(numpy, xgboost, scikit-learn) roi chay lai.'
            ) from exc

        model_path = self.AI_MODEL_DIR / self.AI_MODEL_FILE
        feature_path = self.AI_MODEL_DIR / self.AI_FEATURE_COLUMNS_FILE
        encoder_path = self.AI_MODEL_DIR / self.AI_LABEL_ENCODER_FILE
        missing = [str(p) for p in (model_path, feature_path, encoder_path) if not p.exists()]
        if missing:
            raise FileNotFoundError('Thieu file model AI: ' + ', '.join(missing))

        with feature_path.open('r', encoding='utf-8') as f:
            feature_columns = json.load(f)
        if not isinstance(feature_columns, list) or not feature_columns:
            raise ValueError('feature_columns.json khong hop le.')

        labels = list(self.AI_FALLBACK_LABELS)
        try:
            with encoder_path.open('rb') as f:
                encoder = pickle.load(f)
            encoder_classes = getattr(encoder, 'classes_', None)
            if encoder_classes is not None:
                labels = [str(x) for x in list(encoder_classes)]
        except Exception:
            # Fallback keeps inference usable when sklearn is missing, but requirements include it.
            pass

        booster = xgb.Booster()
        booster.load_model(str(model_path))
        self._ai_model_bundle = {
            'np': np,
            'xgb': xgb,
            'booster': booster,
            'feature_columns': [str(c).strip() for c in feature_columns],
            'labels': labels,
        }
        return self._ai_model_bundle

    def _coerce_ai_number(self, value) -> float:
        if value is None:
            return 0.0
        if isinstance(value, bool):
            return 1.0 if value else 0.0
        if isinstance(value, (int, float)):
            number = float(value)
        else:
            text = str(value).strip()
            if not text:
                return 0.0
            if text.lower() in {'inf', '+inf', 'infinity', '+infinity'}:
                return 0.0
            if text.lower() in {'-inf', '-infinity', 'nan', '+nan', '-nan'}:
                return 0.0
            try:
                number = float(text.replace(',', ''))
            except Exception:
                return 0.0
        if math.isnan(number) or math.isinf(number):
            return 0.0
        return number

    def _prepare_ai_feature_matrix(self, ml_header: list[str], ml_rows: list[list], feature_columns: list[str]):
        dedup_header = self._dedupe_ai_header(ml_header)
        col_index = {name: idx for idx, name in enumerate(dedup_header)}
        matrix = []
        for row in ml_rows:
            vector = []
            for feature in feature_columns:
                idx = col_index.get(feature)
                vector.append(self._coerce_ai_number(row[idx]) if idx is not None and idx < len(row) else 0.0)
            matrix.append(vector)
        return matrix

    def _predict_ai_labels(self, ml_header: list[str], ml_rows: list[list]) -> list[dict]:
        if not ml_rows:
            return []
        bundle = self._load_ai_model_bundle()
        matrix = self._prepare_ai_feature_matrix(ml_header, ml_rows, bundle['feature_columns'])
        np = bundle['np']
        xgb = bundle['xgb']
        dmatrix = xgb.DMatrix(np.asarray(matrix, dtype=float), feature_names=bundle['feature_columns'])
        raw_pred = bundle['booster'].predict(dmatrix)
        labels = bundle['labels']

        predictions = []
        for pred in raw_pred:
            arr = np.asarray(pred)
            if arr.ndim == 0:
                class_idx = int(round(float(arr)))
                confidence = 1.0
            else:
                class_idx = int(arr.argmax())
                confidence = float(arr[class_idx])
            label = labels[class_idx] if 0 <= class_idx < len(labels) else str(class_idx)
            predictions.append({
                'label': label,
                'confidence': confidence,
                'class_index': class_idx,
            })
        return predictions

    def _build_ai_analysis_text(self, traffic_header: list[str], traffic_rows: list[list], predictions: list[dict]) -> str:
        index = {name: idx for idx, name in enumerate(traffic_header)}

        def get(row, name, default=''):
            idx = index.get(name)
            if idx is None or idx >= len(row):
                return default
            return row[idx]

        total = len(predictions)
        counts = Counter(pred['label'] for pred in predictions)
        attack_counts = Counter({label: count for label, count in counts.items() if label != 'BENIGN'})

        lines = ['AI Analyst result', '']
        lines.append(f'Total flows analyzed: {total}')
        lines.append('Predicted labels:')
        for label, count in counts.most_common():
            percent = (count * 100.0 / total) if total else 0.0
            lines.append(f'- {label}: {count} flow(s), {percent:.1f}%')

        lines.append('')
        if not attack_counts:
            lines.append('Current situation: mostly BENIGN traffic.')
            lines.append(self.AI_LABEL_DESCRIPTIONS.get('BENIGN', 'Traffic looks normal.'))
        else:
            lines.append('Current situation: suspicious or attack traffic detected.')
            for label, count in attack_counts.most_common():
                description = self.AI_LABEL_DESCRIPTIONS.get(label, 'Can kiem tra them flow lien quan.')
                lines.append(f'- {label}: {description}')

        grouped_sources = defaultdict(Counter)
        grouped_targets = defaultdict(Counter)
        for row, pred in zip(traffic_rows, predictions):
            label = pred['label']
            if label == 'BENIGN':
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
                if pred['label'] != 'BENIGN'
            ]
            suspicious.sort(key=lambda pair: pair[1].get('confidence', 0.0), reverse=True)
            for row, pred in suspicious[:15]:
                src = f"{get(row, 'Source IP', '-')}: {get(row, 'Source Port', '-')}"
                dst = f"{get(row, 'Destination IP', '-')}: {get(row, 'Destination Port', '-')}"
                proto = get(row, 'Protocol', '-')
                duration = get(row, 'Flow Duration', '-')
                packets = get(row, 'Total Fwd Packets', '-')
                bytes_ = get(row, 'Total Length of Fwd Packets', '-')
                lines.append(
                    f"- {pred['label']} ({pred['confidence']:.2%}) | {src} -> {dst} | "
                    f'proto={proto} | duration_us={duration} | fwd_pkts={packets} | fwd_bytes={bytes_}'
                )

        lines.append('')
        lines.append('Per-flow predictions:')
        for i, (row, pred) in enumerate(zip(traffic_rows, predictions), start=1):
            flow_id = get(row, 'Flow ID', '-')
            src = f"{get(row, 'Source IP', '-')}: {get(row, 'Source Port', '-')}"
            dst = f"{get(row, 'Destination IP', '-')}: {get(row, 'Destination Port', '-')}"
            proto = get(row, 'Protocol', '-')
            lines.append(
                f"- flow#{i} {flow_id} | {src} -> {dst} | proto={proto} | "
                f"label={pred.get('label', '-')} | confidence={float(pred.get('confidence', 0.0)):.2%}"
            )

        return '\n'.join(lines)

    def _save_ai_analyst_csv_outputs(
        self,
        traffic_header: list[str],
        traffic_rows: list[list],
        ml_header: list[str],
        ml_rows: list[list],
        predictions: list[dict],
    ) -> tuple[str, str]:
        out_dir = Path.cwd() / 'docs' / 'ai_analyst_outputs'
        out_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        ml_csv_path = out_dir / f'ai_analyst_ml_input_{ts}.csv'
        pred_csv_path = out_dir / f'ai_analyst_predictions_{ts}.csv'

        with ml_csv_path.open('w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(ml_header)
            writer.writerows(ml_rows)

        t_index = {name: idx for idx, name in enumerate(traffic_header)}
        def t_get(row, name, default=''):
            idx = t_index.get(name)
            if idx is None or idx >= len(row):
                return default
            return row[idx]

        pred_header = [
            'Flow Index', 'Flow ID', 'Source IP', 'Source Port', 'Destination IP', 'Destination Port',
            'Protocol', 'Predicted Label', 'Confidence'
        ]
        with pred_csv_path.open('w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(pred_header)
            for i, (row, pred) in enumerate(zip(traffic_rows, predictions), start=1):
                writer.writerow([
                    i,
                    t_get(row, 'Flow ID', ''),
                    t_get(row, 'Source IP', ''),
                    t_get(row, 'Source Port', ''),
                    t_get(row, 'Destination IP', ''),
                    t_get(row, 'Destination Port', ''),
                    t_get(row, 'Protocol', ''),
                    pred.get('label', ''),
                    f"{float(pred.get('confidence', 0.0)):.6f}",
                ])

        return str(ml_csv_path), str(pred_csv_path)

    def _open_ai_analyst_dialog(self):
        if not self.capture_view or not getattr(self.capture_view, 'records', None):
            QMessageBox.information(self, 'AI Analyst', 'Khong co capture de phan tich.')
            return

        records = list(self.capture_view.records)
        packet_numbers = sorted(int(r.number) for r in records)
        record_by_number = {}
        for rec in records:
            record_by_number.setdefault(int(rec.number), rec)

        dialog = QDialog(self)
        dialog.setWindowTitle('AI Analyst')
        root = QVBoxLayout(dialog)

        root.addWidget(QLabel('Nhap goi tin: 1 goi, nhieu goi cach nhau dau phay, khoang a-b, hoac all'))
        packet_input = QLineEdit(dialog)
        packet_input.setPlaceholderText('Vi du: 5,8,10-20 hoac all')
        packet_input.setText('all')
        root.addWidget(packet_input)
        status = QTextEdit(dialog)
        status.setReadOnly(True)
        status.setMinimumHeight(280)
        root.addWidget(status)

        button_row = QHBoxLayout()
        build_btn = QPushButton('Phan tich bang model', dialog)
        close_btn = QPushButton('Dong', dialog)
        button_row.addWidget(build_btn)
        button_row.addStretch()
        button_row.addWidget(close_btn)
        root.addLayout(button_row)

        state = {
            'traffic_header': None,
            'traffic_rows': None,
            'ml_header': None,
            'ml_rows': None,
            'predictions': None,
        }

        def _build():
            try:
                selected_numbers = self._parse_ai_packet_selector(packet_input.text(), packet_numbers)
                selected_records = [record_by_number[n] for n in selected_numbers if n in record_by_number]
                if not selected_records:
                    raise ValueError('Khong chon duoc goi hop le.')

                traffic_header = list(self.AI_TRAFFIC_COLUMNS)
                traffic_rows = self._build_ai_traffic_rows(selected_records)
                if any(len(row) != len(traffic_header) for row in traffic_rows):
                    raise ValueError('Loi schema: so cot TrafficLabelling khong khop header.')

                ml_header, ml_rows = self._traffic_to_ml(traffic_header, traffic_rows)
                if any(len(row) != len(ml_header) for row in ml_rows):
                    raise ValueError('Loi schema: so cot inference feature khong khop header.')
                if any(str(col).strip().lower() == 'label' for col in ml_header):
                    raise ValueError('Loi schema: cot Label van con trong feature inference.')

                predictions = self._predict_ai_labels(ml_header, ml_rows)
                analysis_text = self._build_ai_analysis_text(traffic_header, traffic_rows, predictions)
                ml_csv_path, pred_csv_path = self._save_ai_analyst_csv_outputs(
                    traffic_header, traffic_rows, ml_header, ml_rows, predictions
                )

                state['traffic_header'] = traffic_header
                state['traffic_rows'] = traffic_rows
                state['ml_header'] = ml_header
                state['ml_rows'] = ml_rows
                state['predictions'] = predictions

                status.setPlainText(
                    f"Da phan tich xong bang model AI Analyst\n"
                    f"- So goi chon: {len(selected_records)}\n"
                    f"- TrafficLabelling rows: {len(traffic_rows)} | cols: {len(traffic_header)}\n"
                    f"- Inference feature rows: {len(ml_rows)} | cols: {len(ml_header)} | Label removed\n\n"
                    f"- Flow mode: Strict Upstream (single standard mode)\n"
                    f"CSV ML input (CIC-like): {ml_csv_path}\n"
                    f"CSV Predictions per-flow: {pred_csv_path}\n\n"
                    f"{analysis_text}"
                )
            except Exception as exc:
                status.setPlainText(f'Loi AI Analyst: {exc}')

        build_btn.clicked.connect(_build)
        close_btn.clicked.connect(dialog.accept)
        packet_input.returnPressed.connect(_build)

        dialog.resize(980, 680)
        self._fit_widget_90(dialog)
        dialog.exec()

    def show_interface_selector(self):
        """Hiển thị màn hình chọn interface"""
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
            self.stacked_widget.addWidget(self.capture_view)

        self.capture_view.set_interface(iface, iface_display_name, capture_filter)
        self._apply_capture_defaults_to_view()
        self.capture_view.set_color_rules_enabled(self.action_color_btn.isChecked())
        self.stacked_widget.setCurrentWidget(self.capture_view)
        self._update_capture_window_title()
        self._update_toolbar_state('capture')
        self._status_mode = 'activity'
        self._selected_packet_number = None
        self._status_activity_kind = 'load'
        self._update_packet_status_label()
        self.detail_field_label.setText('Field: - | Byte: 0')
        self._refresh_status_metrics()

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

    def _sync_capture_buttons(self):
        is_running = bool(self.capture_view and self.capture_view.is_capturing())
        is_stopping = bool(self.capture_view and self.capture_view.is_stopping())
        has_capture = bool(self.capture_view)
        self.action_start_btn.setEnabled(has_capture and not is_running and not is_stopping)
        self.action_restart_btn.setEnabled(has_capture and not is_running and not is_stopping)
        self.action_stop_btn.setEnabled(has_capture and (is_running or is_stopping))

    def _on_capture_started(self, iface, iface_display_name, capture_filter):
        """Xử lý khi bắt đầu capture"""
        self.show_capture_view(iface, iface_display_name, capture_filter)
        self._apply_capture_defaults_to_view()
        self._on_start_capture()

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
            return

        if self.capture_view.is_capturing():
            return

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

    def _on_restart_capture(self):
        """Khởi động lại capture"""
        if not self.capture_view:
            return

        if self.capture_view.is_capturing():
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
        self._update_capture_window_title()

    def _on_open_file(self):
        """Mở file PCAP"""
        proceed = self._prompt_save_before_destructive_action('Mở file mới sẽ thay thế dữ liệu hiện tại. Bạn có muốn lưu trước không?')
        if not proceed:
            return

        if not self.capture_view:
            self.show_capture_view('', 'Offline', '')
        if self.capture_view:
            started = time.perf_counter()
            self.capture_view.load_file()
            self._last_loaded_seconds = max(0.0, time.perf_counter() - started)
            self._status_mode = 'activity'
            self._status_activity_kind = 'load'
            self._selected_packet_number = None
            self._capture_started_monotonic = None
            self._update_packet_status_label()
            self.detail_field_label.setText('Field: - | Byte: 0')
            self._sync_capture_buttons()
            self._update_capture_window_title()
            self._refresh_status_metrics()
            self._refresh_file_menu_state()
            if self.iface_selector_view:
                self.iface_selector_view.refresh_recent_files()

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
        except Exception as exc:
            QMessageBox.critical(self, 'Merge', f'Khong the doc file merge:\n{exc}')
            return

        if not incoming_packets:
            QMessageBox.warning(self, 'Merge', 'File duoc chon khong co packet hop le de merge.')
            return

        current_packets = [r.raw for r in cv.records if getattr(r, 'raw', None) is not None]
        merged_packets = current_packets + incoming_packets
        if chronological:
            merged_packets.sort(key=lambda p: float(getattr(p, 'time', 0.0) or 0.0))

        self._replace_capture_packets(
            merged_packets,
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
                    chunk_packets = [
                        rec.raw
                        for rec in cv.records
                        if frm <= int(getattr(rec, 'number', 0) or 0) <= to_
                        and getattr(rec, 'raw', None) is not None
                    ]
                    target = os.path.join(output_dir, f'{base_name}_part{part_no:03d}')
                    saved_path = save_capture_file(
                        target,
                        chunk_packets,
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

        remaining_packets = [
            rec.raw
            for i, rec in enumerate(cv.records)
            if i not in delete_indices and getattr(rec, 'raw', None) is not None
        ]
        self._replace_capture_packets(
            remaining_packets,
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

        packets = [cv.records[i].raw for i in sorted(export_indices) if getattr(cv.records[i], 'raw', None) is not None]
        if not packets:
            QMessageBox.warning(self, 'Export Specified Packets', 'Khong co packet hop le de export.')
            return

        filename, _ = QFileDialog.getSaveFileName(
            self,
            'Export Specified Packets',
            str(Path.cwd() / f'export_packets_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pcap'),
            'PCAP Files (*.pcap)',
        )
        if not filename:
            return

        try:
            out_path = save_capture_file(filename, packets, file_format='pcap', compression='none')
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
    ):
        cv = self.capture_view
        if not cv:
            return

        packets = list(packets or [])
        old_loaded_path = cv.loaded_file_path
        old_metadata = cv.capture_metadata
        old_comments = cv.capture_comments
        old_filter = str(cv.display_filter_input.text() or '')

        cv.stop_capture()
        cv._set_packet_panes_visible(False)
        cv._set_packet_panes_updates_enabled(False)
        try:
            cv.clear_packets(reset_file_path=True)
            if preserve_loaded_path:
                cv.loaded_file_path = old_loaded_path

            cv._configure_parser_capture_context(cv.parser, str(cv.loaded_file_path or ''))
            for idx, packet in enumerate(packets, start=1):
                record = cv.parser.parse(packet, idx, cv.iface)
                cv.records.append(record)

            if preserve_metadata:
                cv.capture_metadata = old_metadata
                cv.capture_comments = old_comments
            else:
                cv.capture_metadata = None
                cv.capture_comments = ''

            cv.display_filter_input.setText(old_filter)
            cv.apply_display_filter()
            if cv.visible_indices:
                cv.goto_first_packet()
            cv._set_dirty(bool(mark_dirty))
            cv._update_status(status_message)
        finally:
            cv._set_packet_panes_updates_enabled(True)
            cv._set_packet_panes_visible(True)

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
        feature_path = self.AI_MODEL_DIR / self.AI_FEATURE_COLUMNS_FILE
        encoder_path = self.AI_MODEL_DIR / self.AI_LABEL_ENCODER_FILE
        return PacketraModelAdapter(
            model_path=str(model_path),
            feature_columns_path=str(feature_path),
            label_encoder_path=str(encoder_path),
            fallback_labels=list(self.AI_FALLBACK_LABELS),
        )

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
            if self.capture_view.loaded_file_path:
                csv_path, flows = export_pcap_to_csv(self.capture_view.loaded_file_path, file_path)
            else:
                packets = [r.raw for r in self.capture_view.records if getattr(r, "raw", None) is not None]
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
        selected_packets = self.capture_view.get_selected_raw_packets()
        if not selected_packets:
            QMessageBox.warning(self, "Export Selected Flow CSV", "Ban can chon packet trong bang truoc khi export.")
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
        if widget is not None and hasattr(widget, 'copy'):
            try:
                widget.copy()
                return
            except Exception:
                pass
        self._on_menu_feature_placeholder('Edit > Copy')

    def _on_toggle_main_toolbar(self, enabled: bool):
        visible = bool(enabled)
        self.toolbar.setVisible(visible)
        if hasattr(self, 'action_view_main_toolbar'):
            self.action_view_main_toolbar.blockSignals(True)
            self.action_view_main_toolbar.setChecked(visible)
            self.action_view_main_toolbar.blockSignals(False)

    def _on_toggle_statusbar(self, enabled: bool):
        visible = bool(enabled)
        self.statusbar.setVisible(visible)
        if hasattr(self, 'action_view_statusbar'):
            self.action_view_statusbar.blockSignals(True)
            self.action_view_statusbar.setChecked(visible)
            self.action_view_statusbar.blockSignals(False)

    def _on_refresh_interfaces(self):
        if self.iface_selector_view:
            try:
                self.iface_selector_view.refresh_list_structure()
                if hasattr(self.iface_selector_view, 'refresh_recent_files'):
                    self.iface_selector_view.refresh_recent_files()
                return
            except Exception:
                pass
        self._on_menu_feature_placeholder('Capture > Refresh Interfaces')

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

        self.capture_view.stop_capture()
        self.show_interface_selector()
        self._refresh_status_metrics()
        self._refresh_file_menu_state()

    def _on_reload_file(self):
        if not self.capture_view:
            return
        self.capture_view.reload_file()
        self._sync_capture_buttons()
        self._refresh_status_metrics()
        self._refresh_file_menu_state()

    def _on_go_previous_packet(self):
        if self.capture_view:
            self.capture_view.goto_previous_packet()

    def _on_go_next_packet(self):
        if self.capture_view:
            self.capture_view.goto_next_packet()

    def _on_go_first_packet(self):
        if self.capture_view:
            self.capture_view.goto_first_packet()

    def _on_go_last_packet(self):
        if self.capture_view:
            self.capture_view.goto_last_packet()

    def _on_toggle_go_to_packet(self):
        if not self.capture_view or not self.capture_view.has_packets():
            return
        self.capture_view.toggle_go_to_packet_row()

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

    def _on_resize_columns(self):
        if self.capture_view:
            self.capture_view.resize_columns_to_content()

    def _on_reset_layout(self):
        if self.capture_view:
            self.capture_view.reset_layout_to_default_size()

    def _prompt_save_before_destructive_action(self, message: str) -> bool:
        if not self.capture_view or not self.capture_view.has_unsaved_changes():
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
        elif any(token in status_text for token in ('Live capture', 'Capture stopped', 'Capture stopping')):
            self._status_mode = 'activity'
            self._status_activity_kind = 'capture'
            self._selected_packet_number = None
            self._update_packet_status_label()
        if self.capture_view and self.stacked_widget.currentWidget() is self.capture_view:
            self._update_toolbar_state('capture')

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
            self.detail_field_label.setText(f'Field: {field_name} | Byte: {byte_count}')
            return
        self.detail_field_label.setText('Field: - | Byte: 0')

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
        edit_comment_btn = QPushButton('Edit Comments')
        close_btn = QPushButton('Close')
        help_btn = QPushButton('Help')
        button_row.addWidget(refresh_btn)
        button_row.addStretch()
        button_row.addWidget(copy_btn)
        button_row.addWidget(edit_comment_btn)
        button_row.addWidget(close_btn)
        button_row.addWidget(help_btn)
        main_layout.addLayout(button_row)

        for btn in (refresh_btn, copy_btn, edit_comment_btn, close_btn, help_btn):
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
        edit_comment_btn.clicked.connect(edit_comment)
        close_btn.clicked.connect(dialog.accept)
        help_btn.clicked.connect(show_help)

        dialog.resize(980, 760)
        self._fit_widget_90(dialog)
        dialog.exec()

    def _on_capture_options(self):
        """Mở Capture Options dialog"""
        dialog = CaptureOptionsDialog(self, self.capture_view)
        result = dialog.exec()
        if result == QDialog.DialogCode.Accepted:
            self._apply_capture_defaults_to_view()

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


