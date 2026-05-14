import os
import socket
import time
import psutil
import json
from PySide6.QtCore import Qt, QTimer, Signal, QSettings, QEvent
from PySide6.QtGui import QPainter, QPen, QPixmap, QColor
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLineEdit, QLabel, QComboBox,
    QTreeWidget, QTreeWidgetItem, QAbstractItemView, QListWidget, QFileDialog,
    QMessageBox, QToolTip
)

from utils.network_utils import get_interfaces, get_traffic


class InterfaceSelectorView(QWidget):
    capture_started = Signal(str, str, str)  # iface, display_name, capture_filter
    open_file_requested = Signal(str)

    def __init__(self):
        super().__init__()
        self.setWindowTitle('Packetra - Select Interface')

        self.main_layout = QVBoxLayout(self)
        self.main_layout.setContentsMargins(10, 8, 10, 10)
        self.main_layout.setSpacing(8)

        self._build_open_section()
        self._build_capture_header()
        self._build_interface_list()

        self.interfaces = get_interfaces()
        self.traffic_history = {name: [0.0] * 24 for name in self.interfaces}
        self.smoothed_speed = {name: 0.0 for name in self.interfaces}

        prev = get_traffic()
        time.sleep(0.25)
        now = get_traffic()
        self.prev_traffic = now
        self.active_interfaces = []
        self.inactive_interfaces = []
        for name in self.interfaces:
            if max(now.get(name, 0) - prev.get(name, 0), 0) > 0:
                self.active_interfaces.append(name)
            else:
                self.inactive_interfaces.append(name)

        self.refresh_list_structure()
        self.update_list()

        self.timer = QTimer(self)
        self.timer.timeout.connect(self.update_list)
        self.timer.start(1000)

    def _load_interface_preferences(self):
        """Load interface preferences saved from Manage Interfaces."""
        settings_json = self._settings().value('interface_settings', '{}', str)
        try:
            return json.loads(settings_json)
        except Exception:
            return {}

    def _is_interface_shown(self, iface_name: str) -> bool:
        prefs = self._load_interface_preferences().get(f"interface_{iface_name}", {})
        return bool(prefs.get('show', True))

    def _display_name_for_interface(self, iface_name: str) -> str:
        prefs = self._load_interface_preferences().get(f"interface_{iface_name}", {})
        friendly = str(prefs.get('friendly_name', self.interfaces.get(iface_name, iface_name)))
        comment = str(prefs.get('comment', '')).strip()
        show_with_comment = bool(prefs.get('show_with_comment', False))
        if show_with_comment and comment:
            return f"{comment}:{friendly}"
        return friendly

    def _settings(self):
        return QSettings('Packetra', 'Packetra')

    def _load_recent_paths(self):
        try:
            values = self._settings().value('recent_capture_files', [], list)
            if not isinstance(values, list):
                return []
            return [str(v) for v in values if os.path.exists(str(v))][:20]
        except Exception:
            return []

    def _save_recent_paths(self, paths):
        self._settings().setValue('recent_capture_files', paths[:20])

    def _remember_recent_path(self, path: str):
        if not path:
            return
        normalized = os.path.normpath(path)
        recent = [p for p in self._load_recent_paths() if os.path.normpath(p) != normalized]
        recent.insert(0, normalized)
        self._save_recent_paths(recent)

    def _build_open_section(self):
        title = QLabel('Open')
        title.setStyleSheet('font-size:24px; font-weight:700;')
        self.main_layout.addWidget(title)

        row = QHBoxLayout()
        self.recent_list = QListWidget()
        self.recent_list.setMinimumHeight(110)
        self.recent_list.itemDoubleClicked.connect(self._on_open_selected_recent)
        row.addWidget(self.recent_list, 1)

        actions = QVBoxLayout()
        self.open_selected_btn = QPushButton('Open Selected')
        self.open_selected_btn.clicked.connect(self._on_open_selected_recent)
        self.open_browse_btn = QPushButton('Open from Disk...')
        self.open_browse_btn.clicked.connect(self._on_open_from_disk)
        self.refresh_recent_btn = QPushButton('Refresh')
        self.refresh_recent_btn.clicked.connect(self.refresh_recent_files)
        actions.addWidget(self.open_selected_btn)
        actions.addWidget(self.open_browse_btn)
        actions.addWidget(self.refresh_recent_btn)
        actions.addStretch(1)
        row.addLayout(actions)

        self.main_layout.addLayout(row)
        self.refresh_recent_files()

    def refresh_recent_files(self):
        self.recent_list.clear()
        for path in self._load_recent_paths()[:10]:
            self.recent_list.addItem(path)

    def _build_capture_header(self):
        title = QLabel('Capture')
        title.setStyleSheet('font-size:34px; font-weight:700;')
        sub = QHBoxLayout()
        label = QLabel('...using this filter')
        label.setStyleSheet('font-weight:600;')
        self.capture_filter_input = QLineEdit()
        self.capture_filter_input.setPlaceholderText('Ví dụ: tcp port 443 or udp port 53')
        self.interface_scope_combo = QComboBox()
        self.interface_scope_combo.addItems([
            'All interfaces shown',
            'wired',
            'bluetooth',
            'wireless',
            'external capture',
            'hidden interface',
        ])
        self.interface_scope_combo.currentTextChanged.connect(self.refresh_list_structure)
        sub.addWidget(label)
        sub.addWidget(self.capture_filter_input)
        sub.addWidget(self.interface_scope_combo)
        self.main_layout.addWidget(title)
        self.main_layout.addLayout(sub)

    def _build_interface_list(self):
        self.list_widget = QTreeWidget()
        self.list_widget.setColumnCount(3)
        self.list_widget.setHeaderLabels(['Interface', 'Traffic Trend', 'Rate'])
        self.list_widget.header().resizeSection(0, 620)
        self.list_widget.header().resizeSection(1, 300)
        self.list_widget.header().resizeSection(2, 120)
        self.list_widget.header().sectionResized.connect(self._on_header_section_resized)
        self.list_widget.setSelectionMode(QAbstractItemView.SingleSelection)
        self.list_widget.setAlternatingRowColors(True)
        self.list_widget.itemDoubleClicked.connect(self._on_start_capture)
        self.list_widget.setMouseTracking(True)
        self.list_widget.viewport().installEventFilter(self)

        self.main_layout.addWidget(self.list_widget, 1)
        self.tooltip_item = None

    def _on_header_section_resized(self, logicalIndex, oldSize, newSize):
        # Nếu là cột Traffic Trend (index 1), vẽ lại sparkline với width mới
        if logicalIndex == 1:
            for idx in range(self.list_widget.topLevelItemCount()):
                item = self.list_widget.topLevelItem(idx)
                name = item.data(0, Qt.UserRole)
                history = self.traffic_history.get(name, [0.0] * 24)
                chart = self.list_widget.itemWidget(item, 1)
                if chart:
                    chart.setPixmap(self._sparkline_pixmap(history, width=newSize))

    def _category_of_interface(self, name: str):
        low = name.lower()
        if any(k in low for k in ('bluetooth', 'bth', 'bt-')):
            return 'bluetooth'
        if any(k in low for k in ('wi-fi', 'wifi', 'wireless', 'wlan', '802.11')):
            return 'wireless'
        if any(k in low for k in ('npcap loopback', 'loopback', 'virtual', 'vmware', 'hyper-v', 'vbox')):
            return 'external capture'
        if any(k in low for k in ('hidden', 'isatap', 'teredo')):
            return 'hidden interface'
        return 'wired'

    def _ordered_interfaces(self):
        choice = self.interface_scope_combo.currentText()
        ordered = [n for n in (self.active_interfaces + self.inactive_interfaces) if self._is_interface_shown(n)]
        if choice == 'All interfaces shown':
            return ordered
        return [name for name in ordered if self._category_of_interface(name) == choice]

    def refresh_list_structure(self):
        selected = self.get_selected_interface_name()
        self.list_widget.clear()
        for iface_name in self._ordered_interfaces():
            item = QTreeWidgetItem([self._display_name_for_interface(iface_name), '', '0.00 KB/s'])
            item.setData(0, Qt.UserRole, iface_name)
            self.list_widget.addTopLevelItem(item)
        if selected:
            self.select_interface(selected)
        elif self.list_widget.topLevelItemCount() > 0:
            self.list_widget.setCurrentItem(self.list_widget.topLevelItem(0))

    def _sparkline_pixmap(self, values, width=280, height=24):
        pix = QPixmap(width, height)
        pix.fill(Qt.transparent)
        painter = QPainter(pix)
        painter.setRenderHint(QPainter.Antialiasing, True)

        painter.setPen(QPen(QColor('#D9DEE6'), 1))
        painter.drawLine(0, height - 2, width, height - 2)

        if values and max(values) > 0:
            max_value = max(values)
            pen = QPen(QColor('#2C7FB8'), 2)
            painter.setPen(pen)
            x_step = max(1.0, (width - 4) / max(1, (len(values) - 1)))
            points = []
            for i, v in enumerate(values):
                x = int(2 + i * x_step)
                y = int((height - 4) - (v / max_value) * (height - 8))
                points.append((x, y))
            for i in range(1, len(points)):
                painter.drawLine(points[i - 1][0], points[i - 1][1], points[i][0], points[i][1])

        painter.end()
        return pix

    def _get_interface_ips(self, iface_name):
        """Get list of IP addresses for an interface"""
        try:
            addrs = psutil.net_if_addrs().get(iface_name, [])
            ips = []
            for addr in addrs:
                if addr.family in (socket.AF_INET, socket.AF_INET6) and addr.address:
                    ips.append(addr.address)
            return ips
        except Exception:
            return []

    def eventFilter(self, obj, event):
        """Handle mouse move events for tooltip"""
        if obj == self.list_widget.viewport() and event.type() == QEvent.MouseMove:
            item = self.list_widget.itemAt(event.pos())
            if item and item.parent() is None:  # Top-level item
                iface_name = item.data(0, Qt.UserRole) or item.text(0).strip()
                ips = self._get_interface_ips(iface_name)
                if ips and item != self.tooltip_item:
                    self.tooltip_item = item
                    popup_text = "\n".join(ips)
                    global_pos = self.list_widget.mapToGlobal(event.pos())
                    QToolTip.showText(global_pos, popup_text, self.list_widget)
            else:
                self.tooltip_item = None
            return False
        return super().eventFilter(obj, event)

    def update_list(self):
        current = get_traffic()
        promoted = []
        for name in list(self.inactive_interfaces):
            speed = max(current.get(name, 0) - self.prev_traffic.get(name, 0), 0)
            if speed > 0:
                self.inactive_interfaces.remove(name)
                self.active_interfaces.append(name)
                promoted.append(name)
        if promoted:
            self.refresh_list_structure()

        # Get the current width of the Traffic Trend column
        trend_col_width = self.list_widget.columnWidth(1)
        for idx in range(self.list_widget.topLevelItemCount()):
            item = self.list_widget.topLevelItem(idx)
            name = item.data(0, Qt.UserRole)
            prev = self.prev_traffic.get(name, 0)
            now = current.get(name, 0)
            speed = max(now - prev, 0)
            alpha = 0.35
            smooth = alpha * speed + (1 - alpha) * self.smoothed_speed.get(name, 0.0)
            self.smoothed_speed[name] = smooth
            history = self.traffic_history.setdefault(name, [0.0] * 24)
            history.append(smooth)
            history[:] = history[-24:]
            display_name = self._display_name_for_interface(name)
            item.setText(0, f'{display_name}  ({self._category_of_interface(name)})')
            item.setText(2, f'{speed / 1024:.2f} KB/s')
            chart = self.list_widget.itemWidget(item, 1)
            if chart is None:
                from PySide6.QtWidgets import QLabel
                chart = QLabel()
                self.list_widget.setItemWidget(item, 1, chart)
            chart.setPixmap(self._sparkline_pixmap(history, width=max(40, trend_col_width-8)))
        self.prev_traffic = current

    def get_selected_interface_name(self):
        item = self.list_widget.currentItem()
        return item.data(0, Qt.UserRole) if item else None

    def select_interface(self, iface_name):
        for i in range(self.list_widget.topLevelItemCount()):
            item = self.list_widget.topLevelItem(i)
            if item.data(0, Qt.UserRole) == iface_name:
                self.list_widget.setCurrentItem(item)
                return

    def get_selected_display_name(self):
        item = self.list_widget.currentItem()
        return item.text(0).strip() if item else None

    def get_selected_interface(self):
        return self.get_selected_interface_name()

    def get_capture_filter(self):
        return self.capture_filter_input.text().strip()

    def _on_open_selected_recent(self):
        item = self.recent_list.currentItem()
        if not item:
            QMessageBox.information(self, 'Open', 'Please select a recent capture file.')
            return
        path = item.text().strip()
        if not path or not os.path.exists(path):
            QMessageBox.warning(self, 'Open', 'Selected file does not exist anymore.')
            return
        self._remember_recent_path(path)
        self.refresh_recent_files()
        self.open_file_requested.emit(path)

    def _on_open_from_disk(self):
        path, _ = QFileDialog.getOpenFileName(
            self,
            'Open PCAP',
            '',
            'PCAP Files (*.pcap *.pcapng)'
        )
        if not path:
            return
        self._remember_recent_path(path)
        self.refresh_recent_files()
        self.open_file_requested.emit(path)

    def _on_start_capture(self, *_args):
        iface = self.get_selected_interface()
        display_name = self.get_selected_display_name()
        capture_filter = self.get_capture_filter()
        if not iface:
            QMessageBox.warning(None, 'Error', 'Vui lòng chọn interface.')
            return
        self.capture_started.emit(iface, display_name or iface, capture_filter)

    def refresh_interface_preferences(self):
        """Reload and apply latest interface preferences in real time."""
        self.refresh_list_structure()
