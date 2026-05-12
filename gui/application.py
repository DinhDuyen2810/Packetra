import logging
import socket
from pathlib import Path
from PySide6.QtCore import Qt, QTimer, QSize, QPoint
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QStackedWidget,
    QMenuBar, QToolBar, QLabel, QMenu, QMessageBox, QFileDialog,
    QSizePolicy, QToolButton, QDialog, QTableWidget, QTableWidgetItem,
    QHeaderView, QPushButton, QTextEdit, QInputDialog, QGridLayout, QScrollArea,
    QFrame, QTextBrowser, QTabWidget, QCheckBox, QSpinBox, QLineEdit, QComboBox,
    QAbstractItemView, QTreeWidget, QTreeWidgetItem, QToolTip
)
from PySide6.QtGui import QAction, QIcon, QKeySequence, QPixmap

from gui.interface_selector_view import InterfaceSelectorView
from gui.capture_view import CaptureView
from gui.manage_interfaces_dialog import ManageInterfacesDialog

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
            iface_name = item.text(0).strip()
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
        
        manage_interfaces_btn = QPushButton('Manage Interfaces')
        manage_interfaces_btn.clicked.connect(self._on_manage_interfaces)
        btn_layout.addWidget(manage_interfaces_btn)
        
        compile_bpfs_btn = QPushButton('Compile BPFs')
        compile_bpfs_btn.setEnabled(False)
        btn_layout.addWidget(compile_bpfs_btn)
        
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
    
    def _build_input_tab(self):
        """Build Input tab with interface tree (Wireshark-like)"""
        layout = QVBoxLayout(self.input_tab)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)
        
        # Interface tree widget
        self.iface_tree = InterfaceTreeWidget()
        self.iface_tree.parent_dialog = self
        self.iface_tree.setColumnCount(7)
        self.iface_tree.setHeaderLabels([
            'Interface', 'Traffic', 'Link-layer Header', 'Promiscuous',
            'Snaplen (B)', 'Buffer (MB)', 'Capture Filter'
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
        
        # Double-click starts capture
        self.iface_tree.doubleClicked.connect(self._on_interface_double_clicked)
        # Expand/collapse on header click
        self.iface_tree.header().sectionClicked.connect(self._on_tree_header_clicked)
        
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
        
        self.monitor_all_cb = QCheckBox('Enable monitor mode on all 802.11 interfaces')
        cb_layout.addWidget(self.monitor_all_cb)
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
    
    def _populate_interfaces(self):
        """Populate interface tree with available interfaces"""
        from utils.network_utils import get_interfaces, get_traffic
        
        # Clear existing items first to avoid duplicates
        self.iface_tree.clear()
        
        interfaces = get_interfaces()
        self.promisc_checkboxes = {}
        self.iface_items = {}
        self.traffic_widgets = {}
        traffic = get_traffic()
        self.prev_traffic = dict(traffic)
        self.smoothed_speed = {name: 0.0 for name in interfaces}
        self.traffic_history = {name: [0.0] * 24 for name in interfaces}
        
        for iface_name in interfaces:
            iface_item = QTreeWidgetItem()
            ips = self._get_interface_ips(iface_name)
            
            # Column 0: Interface name
            iface_item.setText(0, iface_name)
            iface_item.setFirstColumnSpanned(False)

            # Add row to tree first, then attach widgets to avoid disappearing widgets.
            self.iface_tree.addTopLevelItem(iface_item)
            self.iface_items[iface_name] = iface_item
            
            # Column 1: Traffic (show sparkline)
            pix = self._get_sparkline_pixmap(iface_name)
            traffic_label = QLabel()
            traffic_label.setPixmap(pix)
            traffic_label._traffic_bytes = traffic.get(iface_name, 0)
            self.iface_tree.setItemWidget(iface_item, 1, traffic_label)
            self.traffic_widgets[iface_name] = traffic_label
            
            # Column 2: Link-layer Header (text, double-click to edit)
            iface_item.setText(2, "Ethernet")
            iface_item.setData(2, Qt.UserRole, "Ethernet")
            
            # Column 3: Promiscuous (checkbox widget)
            promisc_cb = QCheckBox()
            promisc_cb.setChecked(True)
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
                label.setPixmap(self._get_sparkline_pixmap(iface_name))
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
        """Handle 'Enable monitor mode on all' checkbox"""
        pass
    
    def _on_start_from_options(self):
        """Handle Start button click in Capture Options"""
        # Get first interface (or could implement interface selection)
        from utils.network_utils import get_interfaces
        interfaces = list(get_interfaces().keys())
        if interfaces:
            iface_name = interfaces[0]
            iface_display_name = get_interfaces()[iface_name]
            self.capture_view.set_interface(iface_name, iface_display_name)
            self.capture_view.start_capture()
            self.reject()
        else:
            QMessageBox.warning(self, 'No Interface', 'No network interface available.')
    
    def _on_interface_double_clicked(self, index):
        """Handle double-click based on column - inline editing"""
        from utils.network_utils import get_interfaces
        
        item = self.iface_tree.itemFromIndex(index)
        if not item or item.parent() is not None:  # Skip child items
            return
        
        column = index.column()
        iface_name = item.text(0).strip()
        parent_window = self.parent()
        
        # Column 0 (Interface name) - Start capture
        if column == 0:
            iface_display_name = get_interfaces()[iface_name]
            capture_filter = item.text(6).strip()
            if hasattr(parent_window, 'show_capture_view'):
                parent_window.show_capture_view(iface_name, iface_display_name, capture_filter)
            if hasattr(parent_window, '_on_start_capture'):
                parent_window._on_start_capture()
            self.accept()
        
        # Column 2 (Link-layer Header) - Inline combo edit
        elif column == 2:
            self._edit_inline_combobox(item, column, ['Ethernet', 'DOCSIS', '802.11', 'PPP over serial', 'Cisco HDLC', 
                                                       'RFC 1483 IP-over-ATM', 'Sun raw ATM', 'Raw IP', 'BSD loopback'])
        
        # Column 4 (Snaplen) - Inline spinbox edit
        elif column == 4:
            self._edit_inline_spinbox(item, column, 0, 262144)
        
        # Column 5 (Buffer) - Inline spinbox edit
        elif column == 5:
            self._edit_inline_spinbox(item, column, 1, 512)
        
        # Column 6 (Capture Filter) - Inline text edit
        elif column == 6:
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
        # Refresh interface list after changes
        self._populate_interfaces()
    
    def _build_output_tab(self):
        """Build Output tab (placeholder)"""
        layout = QVBoxLayout(self.output_tab)
        label = QLabel('Output tab - Coming soon')
        layout.addWidget(label)
        layout.addStretch()
    
    def _build_options_tab(self):
        """Build Options tab (placeholder)"""
        layout = QVBoxLayout(self.options_tab)
        label = QLabel('Options tab - Coming soon')
        layout.addWidget(label)
        layout.addStretch()


class ApplicationWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Packetra - Network Packet Analyzer')
        self.resize(1700, 930)

        # Trạng thái ứng dụng
        self.current_view = None
        self.capture_view = None
        self.iface_selector_view = None
        self._toolbar_defaults = {
            'main_splitter': [500, 360],
            'lower_splitter': [980, 650],
        }

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

        self.packet_label = QLabel('Packet: 0')
        self.dropped_label = QLabel('dropped: 0')

        self.statusbar.addWidget(self.expert_btn)
        self.statusbar.addWidget(self.properties_btn)
        self.statusbar.addWidget(self.packet_label)
        self.statusbar.addWidget(self.dropped_label)

        self.setCentralWidget(central)

    def _build_menubar(self):
        """Xây dựng menu bar"""
        menubar = self.menuBar()

        # File menu
        file_menu = menubar.addMenu('&File')
        self.action_open = QAction('&Open...', self)
        self.action_open.setShortcut(QKeySequence.Open)
        file_menu.addAction(self.action_open)
        file_menu.addSeparator()
        self.action_save = QAction('&Save...', self)
        self.action_save.setShortcut(QKeySequence.Save)
        file_menu.addAction(self.action_save)
        self.action_save_as = QAction('Save &As...', self)
        self.action_save_as.setShortcut(QKeySequence.SaveAs)
        file_menu.addAction(self.action_save_as)
        file_menu.addSeparator()
        self.action_export = QAction('&Export As...', self)
        file_menu.addAction(self.action_export)
        file_menu.addSeparator()
        self.action_print = QAction('&Print...', self)
        self.action_print.setShortcut(QKeySequence.Print)
        file_menu.addAction(self.action_print)
        file_menu.addSeparator()
        self.action_exit = QAction('E&xit', self)
        self.action_exit.setShortcut(QKeySequence.Quit)
        file_menu.addAction(self.action_exit)

        # Edit menu
        edit_menu = menubar.addMenu('&Edit')
        self.action_undo = QAction('&Undo', self)
        self.action_undo.setShortcut(QKeySequence.Undo)
        edit_menu.addAction(self.action_undo)
        self.action_redo = QAction('&Redo', self)
        self.action_redo.setShortcut(QKeySequence.Redo)
        edit_menu.addAction(self.action_redo)
        edit_menu.addSeparator()
        self.action_cut = QAction('Cu&t', self)
        self.action_cut.setShortcut(QKeySequence.Cut)
        edit_menu.addAction(self.action_cut)
        self.action_copy = QAction('&Copy', self)
        self.action_copy.setShortcut(QKeySequence.Copy)
        edit_menu.addAction(self.action_copy)
        self.action_paste = QAction('&Paste', self)
        self.action_paste.setShortcut(QKeySequence.Paste)
        edit_menu.addAction(self.action_paste)
        edit_menu.addSeparator()
        self.action_find = QAction('&Find...', self)
        self.action_find.setShortcut(QKeySequence.Find)
        edit_menu.addAction(self.action_find)
        self.action_find_next = QAction('Find &Next', self)
        self.action_find_next.setShortcut(QKeySequence.FindNext)
        edit_menu.addAction(self.action_find_next)
        edit_menu.addSeparator()
        self.action_preferences = QAction('&Preferences', self)
        edit_menu.addAction(self.action_preferences)

        # View menu
        view_menu = menubar.addMenu('&View')
        self.action_zoom_in = QAction('Zoom &In', self)
        self.action_zoom_in.setShortcut(QKeySequence.ZoomIn)
        view_menu.addAction(self.action_zoom_in)
        self.action_zoom_out = QAction('Zoom &Out', self)
        self.action_zoom_out.setShortcut(QKeySequence.ZoomOut)
        view_menu.addAction(self.action_zoom_out)
        self.action_zoom_reset = QAction('&Reset Zoom', self)
        view_menu.addAction(self.action_zoom_reset)
        view_menu.addSeparator()
        self.action_fullscreen = QAction('&Fullscreen', self)
        self.action_fullscreen.setShortcut(Qt.Key_F11)
        view_menu.addAction(self.action_fullscreen)

        # Capture menu
        capture_menu = menubar.addMenu('&Capture')
        self.action_interfaces = QAction('&Interfaces...', self)
        capture_menu.addAction(self.action_interfaces)
        capture_menu.addSeparator()
        self.action_start_capture = QAction('&Start', self)
        self.action_start_capture.setShortcut(Qt.CTRL | Qt.Key_E)
        capture_menu.addAction(self.action_start_capture)
        self.action_stop_capture = QAction('St&op', self)
        self.action_stop_capture.setShortcut(Qt.CTRL | Qt.Key_E)
        capture_menu.addAction(self.action_stop_capture)
        self.action_restart_capture = QAction('&Restart', self)
        capture_menu.addAction(self.action_restart_capture)

        # Analyze menu
        analyze_menu = menubar.addMenu('&Analyze')
        self.action_follow_stream = QAction('&Follow Stream', self)
        analyze_menu.addAction(self.action_follow_stream)
        self.action_decode_as = QAction('&Decode As...', self)
        analyze_menu.addAction(self.action_decode_as)
        analyze_menu.addSeparator()
        self.action_display_filters = QAction('&Display Filters', self)
        analyze_menu.addAction(self.action_display_filters)

        # Statistics menu
        statistics_menu = menubar.addMenu('&Statistics')
        self.action_summary = QAction('&Summary', self)
        statistics_menu.addAction(self.action_summary)
        self.action_protocol_hierarchy = QAction('&Protocol Hierarchy', self)
        statistics_menu.addAction(self.action_protocol_hierarchy)
        self.action_conversations = QAction('&Conversations', self)
        statistics_menu.addAction(self.action_conversations)
        self.action_endpoints = QAction('&Endpoints', self)
        statistics_menu.addAction(self.action_endpoints)
        self.action_io_graph = QAction('&I/O Graph', self)
        statistics_menu.addAction(self.action_io_graph)

        # Help menu
        help_menu = menubar.addMenu('&Help')
        self.action_contents = QAction('&Contents', self)
        self.action_contents.setShortcut(QKeySequence.HelpContents)
        help_menu.addAction(self.action_contents)
        help_menu.addSeparator()
        self.action_about = QAction('&About Packetra', self)
        help_menu.addAction(self.action_about)
        self.action_about_qt = QAction('About &Qt', self)
        help_menu.addAction(self.action_about_qt)

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
        """Kết nối tất cả signals"""
        # File menu
        self.action_open.triggered.connect(self._on_open_file)
        self.action_save.triggered.connect(self._on_save_file)
        self.action_save_as.triggered.connect(self._on_save_as_file)
        self.action_exit.triggered.connect(self.close)

        # Capture menu
        self.action_interfaces.triggered.connect(self.show_interface_selector)
        self.action_start_capture.triggered.connect(self._on_start_capture)
        self.action_stop_capture.triggered.connect(self._on_stop_capture)
        self.action_restart_capture.triggered.connect(self._on_restart_capture)

        # Statistics
        self.action_summary.triggered.connect(self._on_summary)
        self.action_conversations.triggered.connect(self._on_conversations)

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

    def show_interface_selector(self):
        """Hiển thị màn hình chọn interface"""
        if not self.iface_selector_view:
            self.iface_selector_view = InterfaceSelectorView()
            self.iface_selector_view.capture_started.connect(self._on_capture_started)
            self.iface_selector_view.open_file_requested.connect(self._on_open_recent_file)
            self.stacked_widget.addWidget(self.iface_selector_view)

        self.iface_selector_view.refresh_recent_files()

        self.stacked_widget.setCurrentWidget(self.iface_selector_view)
        self.setWindowTitle('Packetra - Select Interface')
        self._update_toolbar_state('selector')

    def show_capture_view(self, iface: str, iface_display_name: str, capture_filter: str = ''):
        """Hiển thị màn hình capture"""
        if not self.capture_view:
            self.capture_view = CaptureView(iface, iface_display_name, capture_filter)
            self.capture_view.status_changed.connect(self._on_capture_status_changed)
            self.capture_view.capture_state_changed.connect(lambda _running: self._sync_capture_buttons())
            self.stacked_widget.addWidget(self.capture_view)

        self.capture_view.set_interface(iface, iface_display_name, capture_filter)
        self.capture_view.set_auto_scroll_enabled(self.action_stay_last_btn.isChecked())
        self.capture_view.set_color_rules_enabled(self.action_color_btn.isChecked())
        self.stacked_widget.setCurrentWidget(self.capture_view)
        self.setWindowTitle(f'Packetra - {iface_display_name}')
        self._update_toolbar_state('capture')
        self._refresh_status_metrics()

    def _update_toolbar_state(self, mode: str):
        """Cập nhật trạng thái toolbar theo mode"""
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

    def _on_open_recent_file(self, path: str):
        if not path:
            return
        self.show_capture_view('', 'Offline', '')
        if self.capture_view:
            self.capture_view.load_file(path)
            self._sync_capture_buttons()
            self._refresh_status_metrics()

    def _on_start_capture(self):
        """Bắt đầu capture"""
        if not self.capture_view:
            return

        if self.capture_view.is_capturing():
            return

        proceed = self._prompt_save_before_destructive_action('Start capture mới sẽ thay thế dữ liệu hiện tại. Bạn có muốn lưu trước không?')
        if not proceed:
            return

        self.capture_view.start_new_capture()
        self._sync_capture_buttons()

    def _on_stop_capture(self):
        """Dừng capture"""
        if self.capture_view:
            self.capture_view.stop_capture()
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
        self._sync_capture_buttons()

    def _on_open_file(self):
        """Mở file PCAP"""
        if not self.capture_view:
            self.show_capture_view('', 'Offline', '')
        if self.capture_view:
            self.capture_view.load_file()
            self._sync_capture_buttons()
            self._refresh_status_metrics()
            if self.iface_selector_view:
                self.iface_selector_view.refresh_recent_files()

    def _on_save_file(self):
        """Lưu file PCAP"""
        if self.capture_view:
            self.capture_view.save_file()
            if self.iface_selector_view:
                self.iface_selector_view.refresh_recent_files()
        else:
            QMessageBox.information(self, 'Info', 'Không có dữ liệu để lưu.')

    def _on_save_as_file(self):
        """Lưu file PCAP với tên mới"""
        self._on_save_file()

    def _on_search(self):
        """Tìm kiếm"""
        if self.capture_view:
            self.capture_view.toggle_find_panel()

    def _on_close_capture_file(self):
        if not self.capture_view:
            return
        self.capture_view.stop_capture()
        self.show_interface_selector()
        self._refresh_status_metrics()

    def _on_reload_file(self):
        if not self.capture_view:
            return
        self.capture_view.reload_file()
        self._sync_capture_buttons()
        self._refresh_status_metrics()

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
        if self.capture_view:
            self.capture_view.set_auto_scroll_enabled(bool(enabled))

    def _on_toggle_color_rules(self, enabled: bool):
        if self.capture_view:
            self.capture_view.set_color_rules_enabled(bool(enabled))

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
        if not self.capture_view or not self.capture_view.has_packets():
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
        """Cập nhật trạng thái capture"""
        _ = status
        self._refresh_status_metrics()
        self._sync_capture_buttons()
        if self.capture_view and self.stacked_widget.currentWidget() is self.capture_view:
            self._update_toolbar_state('capture')

    def _refresh_status_metrics(self):
        packets = 0
        dropped = 0
        if self.capture_view:
            metrics = self.capture_view.get_status_metrics()
            packets = int(metrics.get('packets', 0) or 0)
            dropped = int(metrics.get('dropped', 0) or 0)
        self.packet_label.setText(f'Packet: {packets}')
        self.dropped_label.setText(f'dropped: {dropped}')

    def _on_open_expert_information(self):
        if not self.capture_view:
            QMessageBox.information(self, 'Expert Information', 'No capture is loaded.')
            return

        entries = self.capture_view.get_expert_information()
        dialog = QDialog(self)
        dialog.setWindowTitle('Expert Information')
        layout = QVBoxLayout(dialog)

        table = QTableWidget(dialog)
        table.setColumnCount(5)
        table.setHorizontalHeaderLabels(['Severity', 'Group', 'Protocol', 'Packet', 'Summary'])
        table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        table.setRowCount(len(entries))
        for row, item in enumerate(entries):
            table.setItem(row, 0, QTableWidgetItem(str(item.get('severity', ''))))
            table.setItem(row, 1, QTableWidgetItem(str(item.get('group', ''))))
            table.setItem(row, 2, QTableWidgetItem(str(item.get('protocol', ''))))
            table.setItem(row, 3, QTableWidgetItem(str(item.get('packet', ''))))
            table.setItem(row, 4, QTableWidgetItem(str(item.get('summary', ''))))
        layout.addWidget(table)

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
        edit_comment_btn = QPushButton('Edit Comments')
        close_btn = QPushButton('Close')
        help_btn = QPushButton('Help')
        button_row.addWidget(refresh_btn)
        button_row.addStretch()
        button_row.addWidget(edit_comment_btn)
        button_row.addWidget(close_btn)
        button_row.addWidget(help_btn)
        main_layout.addLayout(button_row)

        for btn in (refresh_btn, edit_comment_btn, close_btn, help_btn):
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
            # Interfaces section
            html.append('<b>Interfaces</b>')
            html.append('<table cellpadding="1" cellspacing="0" style="border-collapse: collapse; margin-bottom: 10px; margin-top: 2px;">')
            html.append('<tr>')
            html.append('<td style="' + ICOL + '"><u>Interface</u></td>')
            html.append('<td style="' + ICOL + '"><u>Interface Description</u></td>')
            html.append('<td style="' + ICOL + '"><u>Dropped packets</u></td>')
            html.append('<td style="' + ICOL + '"><u>Capture filter</u></td>')
            html.append('<td style="' + ICOL + '"><u>Link type</u></td>')
            html.append('<td style="' + ICOL + '"><u>Packet size limit</u></td>')
            html.append('</tr>')
            html.append('<tr>')
            html.append('<td style="' + ICOL + '">' + safe_text(props.get('interface_name', '-'), '-') + '</td>')
            html.append('<td style="' + ICOL + '">' + safe_text(props.get('interface_description', '-'), '-') + '</td>')
            html.append('<td style="' + ICOL + '">' + safe_text(props.get('interface_dropped', '0 (0.0%)'), '0 (0.0%)') + '</td>')
            html.append('<td style="' + ICOL + '">' + safe_text(props.get('interface_capture_filter', 'none'), 'none') + '</td>')
            html.append('<td style="' + ICOL + '">' + safe_text(props.get('interface_link_type', 'Ethernet'), 'Ethernet') + '</td>')
            html.append('<td style="' + ICOL + '">' + safe_text(props.get('interface_snaplen', '262144 bytes'), '262144 bytes') + '</td>')
            html.append('</tr>')
            html.append('</table>')
            
            SCOL = 'padding-right: 25px; padding-top: 1px; padding-bottom: 1px;'
            # Comments section
            html.append('<b>Comments</b>')
            html.append('<p style="margin: 2px 0 10px 0;">' + safe_text(props.get('comment', ''), '-') + '</p>')
            
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
                [safe_text(props.get('packet_count', 0), '0'), safe_text(props.get('stats_packets_displayed', '0 (0.0%)'), '0 (0.0%)'), safe_text(props.get('stats_packets_marked', '—'), '—')],
                [safe_text(props.get('stats_time_span', '0.000'), '0.000'), safe_text(props.get('stats_time_span', '0.000'), '0.000'), '—'],
                [safe_text(props.get('stats_average_pps', '0.0'), '0.0'), safe_text(props.get('stats_average_pps', '0.0'), '0.0'), '—'],
                [safe_text(props.get('stats_average_packet_size', '0'), '0'), safe_text(props.get('stats_average_packet_size', '0'), '0'), '—'],
                [safe_text(props.get('total_bytes', 0), '0'), safe_text(props.get('stats_bytes_displayed', '0 (0.0%)'), '0 (0.0%)'), safe_text(props.get('stats_bytes_marked', '0'), '0')],
                [safe_text(props.get('stats_average_bytes_s', '0 k'), '0 k'), safe_text(props.get('stats_average_bytes_s', '0 k'), '0 k'), '—'],
                [safe_text(props.get('stats_average_bits_s', '0 k'), '0 k'), safe_text(props.get('stats_average_bits_s', '0 k'), '0 k'), '—'],
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

        def edit_comment():
            props = self.capture_view.get_capture_properties()
            current = props.get('comment', '')
            
            text, ok = QInputDialog.getMultiLineText(dialog, 'Capture Comment', 'Comment:', current)
            if ok:
                self.capture_view.set_capture_comment(text)
                fill_values()

        def show_help():
            QMessageBox.information(
                dialog,
                'Capture File Properties Help',
                'All content is selectable. Copy any text using Ctrl+C or right-click menu. No restrictions - select and copy as much as you need.'
            )

        fill_values()
        refresh_btn.clicked.connect(fill_values)
        edit_comment_btn.clicked.connect(edit_comment)
        close_btn.clicked.connect(dialog.accept)
        help_btn.clicked.connect(show_help)

        dialog.resize(980, 760)
        self._fit_widget_90(dialog)
        dialog.exec()

    def _on_capture_options(self):
        """Mở Capture Options dialog"""
        dialog = CaptureOptionsDialog(self, self.capture_view)
        dialog.exec()

    def closeEvent(self, event):
        """Xử lý khi đóng ứng dụng"""
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

        event.accept()
