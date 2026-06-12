import time
from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLineEdit, QLabel, QComboBox,
    QTreeWidget, QTreeWidgetItem, QAbstractItemView, QMenuBar, QToolButton
)

from utils.network_utils import get_interfaces, get_traffic


class InterfaceSelector(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Packetra - Select Interface')
        self.resize(1220, 760)

        self.main_layout = QVBoxLayout(self)
        self.main_layout.setContentsMargins(10, 8, 10, 10)
        self.main_layout.setSpacing(8)

        self._build_menu_bar()
        self._build_toolbar()
        self._build_filter_row()
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

    def _build_menu_bar(self):
        bar = QMenuBar()
        for name in ['File', 'Edit', 'View', 'Go', 'Capture', 'Analyze', 'Statistics', 'Telephony', 'Wireless', 'Tools', 'Help']:
            bar.addMenu(name)
        self.main_layout.addWidget(bar)

    def _build_toolbar(self):
        row = QHBoxLayout()
        for text in ['▶', '■', '⟳', '⚙', '📁', '💾', '🔍']:
            btn = QToolButton()
            btn.setText(text)
            btn.setEnabled(False)
            btn.setFixedSize(28, 24)
            row.addWidget(btn)
        row.addStretch()
        self.main_layout.addLayout(row)

    def _build_filter_row(self):
        row = QHBoxLayout()
        self.display_filter_input = QLineEdit()
        self.display_filter_input.setPlaceholderText('Apply a display filter ... <Ctrl-/>')
        row.addWidget(self.display_filter_input)
        self.main_layout.addLayout(row)

    def _build_capture_header(self):
        title = QLabel('Capture')
        title.setStyleSheet('font-size:34px; font-weight:700;')
        sub = QHBoxLayout()
        label = QLabel('...using this filter')
        label.setStyleSheet('font-weight:600;')
        self.capture_filter_input = QLineEdit()
        self.capture_filter_input.setPlaceholderText('Example: tcp port 443 or udp port 53')
        self.interface_scope_combo = QComboBox()
        self.interface_scope_combo.addItems(['All interfaces shown', 'Only active interfaces', 'Wireless only'])
        sub.addWidget(label)
        sub.addWidget(self.capture_filter_input)
        sub.addWidget(self.interface_scope_combo)
        self.main_layout.addWidget(title)
        self.main_layout.addLayout(sub)

    def _build_interface_list(self):
        self.list_widget = QTreeWidget()
        self.list_widget.setColumnCount(2)
        self.list_widget.setHeaderLabels(['Interface', 'Traffic'])
        self.list_widget.header().resizeSection(0, 760)
        self.list_widget.header().resizeSection(1, 320)
        self.list_widget.setSelectionMode(QAbstractItemView.SingleSelection)
        self.list_widget.setAlternatingRowColors(True)

        self.start_btn = QPushButton('Start Capture')
        self.start_btn.setFixedHeight(34)

        self.main_layout.addWidget(self.list_widget, 1)
        self.main_layout.addWidget(self.start_btn)

    def _ordered_interfaces(self):
        choice = self.interface_scope_combo.currentText()
        ordered = self.active_interfaces + self.inactive_interfaces
        if choice == 'Only active interfaces':
            return self.active_interfaces
        if choice == 'Wireless only':
            return [name for name in ordered if 'wi-fi' in name.lower() or 'wireless' in name.lower() or 'wlan' in name.lower()]
        return ordered

    def refresh_list_structure(self):
        selected = self.get_selected_display_name()
        self.list_widget.clear()
        for display_name in self._ordered_interfaces():
            item = QTreeWidgetItem([display_name, ''])
            item.setData(0, Qt.UserRole, display_name)
            self.list_widget.addTopLevelItem(item)
        if selected:
            self.select_display(selected)
        elif self.list_widget.topLevelItemCount() > 0:
            self.list_widget.setCurrentItem(self.list_widget.topLevelItem(0))

    def _sparkline(self, values):
        bars = '▁▂▃▄▅▆▇█'
        m = max(values) if values else 0
        if m <= 0:
            return '▁' * max(1, len(values))
        return ''.join(bars[min(len(bars) - 1, int((v / m) * (len(bars) - 1)))] for v in values)

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
            item.setText(0, f'{name}  |  {speed / 1024:.2f} KB/s')
            item.setText(1, self._sparkline(history))
        self.prev_traffic = current

    def get_selected_display_name(self):
        item = self.list_widget.currentItem()
        return item.data(0, Qt.UserRole) if item else None

    def select_display(self, display_name):
        for i in range(self.list_widget.topLevelItemCount()):
            item = self.list_widget.topLevelItem(i)
            if item.data(0, Qt.UserRole) == display_name:
                self.list_widget.setCurrentItem(item)
                return

    def get_selected_interface(self):
        display = self.get_selected_display_name()
        return self.interfaces.get(display)

    def get_capture_filter(self):
        return self.capture_filter_input.text().strip()
