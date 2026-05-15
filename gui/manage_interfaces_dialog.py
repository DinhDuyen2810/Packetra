import os
import json
import psutil
from PySide6.QtCore import Qt, QSettings
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QTabWidget, QWidget, QPushButton, QLabel,
    QTableWidget, QTableWidgetItem, QCheckBox, QLineEdit, QTextEdit, QFileDialog,
    QSpinBox, QRadioButton, QButtonGroup, QMessageBox, QComboBox, QTreeWidget,
    QTreeWidgetItem, QHeaderView, QAbstractItemView
)
from PySide6.QtGui import QIcon


class ManageInterfacesDialog(QDialog):
    """Manage Interfaces dialog - Local Interfaces, Pipes, Remote Interfaces"""

    PIPE_HELP_TEXT = """Tham khao: Windows Named Pipe publisher cho Packetra/Wireshark

import time
import struct
import win32pipe
import win32file

from scapy.all import sniff, raw

PIPE_NAME = r'\\\\.\\pipe\\packetra'

# Create Named Pipe
pipe = win32pipe.CreateNamedPipe(
    PIPE_NAME,
    win32pipe.PIPE_ACCESS_OUTBOUND,
    win32pipe.PIPE_TYPE_BYTE | win32pipe.PIPE_WAIT,
    1,
    65536,
    65536,
    0,
    None
)

print(f"Waiting for Packetra to connect to {PIPE_NAME} ...")
win32pipe.ConnectNamedPipe(pipe, None)
print("Packetra connected!")

# Write PCAP Global Header
pcap_global_header = struct.pack(
    '<IHHIIII',
    0xa1b2c3d4,
    2,
    4,
    0,
    0,
    65535,
    1
)
win32file.WriteFile(pipe, pcap_global_header)

counter = 1

def handle_packet(pkt):
    global counter
    try:
        pkt_bytes = raw(pkt)

        ts = time.time()
        ts_sec = int(ts)
        ts_usec = int((ts - ts_sec) * 1_000_000)

        incl_len = len(pkt_bytes)
        orig_len = len(pkt_bytes)

        pkt_header = struct.pack(
            '<IIII',
            ts_sec,
            ts_usec,
            incl_len,
            orig_len
        )

        win32file.WriteFile(pipe, pkt_header)
        win32file.WriteFile(pipe, pkt_bytes)

        print(f"Forwarded packet #{counter} ({incl_len} bytes)")
        counter += 1

    except Exception as e:
        print("Pipe closed or error:", e)
        exit(0)

print("Starting live capture from Wi-Fi...")

sniff(
    iface="Wi-Fi",
    prn=handle_packet,
    store=False
)
"""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle('Manage Interfaces')
        self.resize(700, 500)
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)
        
        # Tabs
        self.tabs = QTabWidget()
        self.local_tab = QWidget()
        self.pipes_tab = QWidget()
        self.remote_tab = QWidget()
        
        self.tabs.addTab(self.local_tab, "Local Interfaces")
        self.tabs.addTab(self.pipes_tab, "Pipes")
        self.tabs.addTab(self.remote_tab, "Remote Interfaces")
        
        layout.addWidget(self.tabs)
        
        # Buttons
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()
        
        ok_btn = QPushButton('OK')
        ok_btn.clicked.connect(self.accept)
        btn_layout.addWidget(ok_btn)
        
        cancel_btn = QPushButton('Cancel')
        cancel_btn.clicked.connect(self.reject)
        btn_layout.addWidget(cancel_btn)
        
        help_btn = QPushButton('Help')
        btn_layout.addWidget(help_btn)
        
        layout.addLayout(btn_layout)
        
        # Build tabs
        self._build_local_tab()
        self._build_pipes_tab()
        self._build_remote_tab()
        
        # Load settings
        self._load_settings()
    
    def _settings(self):
        return QSettings('Packetra', 'Packetra')
    
    # ===== LOCAL INTERFACES TAB (QTreeWidget) =====
    
    def _build_local_tab(self):
        """Build Local Interfaces tab with QTreeWidget like Input tab"""
        layout = QVBoxLayout(self.local_tab)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)
        
        # Tree widget - no gridlines, no headers like Capture Options Input tab
        self.local_tree = QTreeWidget()
        self.local_tree.setColumnCount(5)
        self.local_tree.setHeaderLabels(['Show', 'Friendly Name', 'Interface Name', 'Comment', 'Show with cmt'])
        self.local_tree.setColumnWidth(0, 60)
        self.local_tree.setColumnWidth(1, 180)
        self.local_tree.setColumnWidth(2, 350)
        self.local_tree.setColumnWidth(3, 200)
        self.local_tree.setColumnWidth(4, 120)
        
        # Hide gridlines like Input tab
        self.local_tree.setStyleSheet("QTreeWidget { gridline-color: transparent; }")
        
        # Populate with interfaces
        self._populate_local_interfaces()

        self.local_tree.itemChanged.connect(self._on_local_item_changed)
        
        layout.addWidget(self.local_tree)
    
    def _populate_local_interfaces(self):
        """Populate local interfaces tree with GUID and comments"""
        from utils.network_utils import get_interfaces, get_interface_details
        
        interfaces = get_interfaces()
        iface_details = get_interface_details()
        settings_json = self._settings().value('interface_settings', '{}', str)
        saved_settings = json.loads(settings_json)
        
        for iface_name in interfaces:
            # Get details for this interface
            details = iface_details.get(iface_name, {})
            friendly_name = details.get('friendly_name', iface_name)
            description = details.get('description', '')
            guid = details.get('guid', iface_name)
            
            # Load saved settings for this interface
            iface_key = f"interface_{iface_name}"
            iface_config = saved_settings.get(iface_key, {})
            
            # Create tree item
            item = QTreeWidgetItem()
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsEditable)
            
            # Column 0: Show checkbox
            show_cb = QCheckBox()
            show_cb.setChecked(iface_config.get('show', True))
            self.local_tree.addTopLevelItem(item)
            self.local_tree.setItemWidget(item, 0, show_cb)
            show_cb.stateChanged.connect(lambda _state, _item=item: self._on_local_show_changed(_item))
            
            # Column 1: Friendly Name (editable)
            friendly = iface_config.get('friendly_name', friendly_name or iface_name)
            item.setText(1, friendly)
            item.setData(1, Qt.UserRole, friendly)
            
            # Column 2: Interface Name (GUID)
            item.setText(2, guid)
            item.setData(2, Qt.UserRole, iface_name)  # Store actual interface name for settings
            
            # Column 3: Comment (editable)
            comment = iface_config.get('comment', description or '')
            item.setText(3, comment)
            item.setData(3, Qt.UserRole, comment)

            # Column 4: Show with cmt checkbox
            show_with_cmt_cb = QCheckBox()
            show_with_cmt_cb.setChecked(iface_config.get('show_with_comment', False))
            self.local_tree.setItemWidget(item, 4, show_with_cmt_cb)
            show_with_cmt_cb.stateChanged.connect(lambda _state, _item=item: self._on_local_show_with_comment_changed(_item))

    def _collect_local_interface_settings(self):
        """Collect local interface settings from tree widget"""
        interface_settings = {}
        for i in range(self.local_tree.topLevelItemCount()):
            item = self.local_tree.topLevelItem(i)
            iface_name = item.data(2, Qt.UserRole) or item.text(2)
            show_cb = self.local_tree.itemWidget(item, 0)
            show_with_cmt_cb = self.local_tree.itemWidget(item, 4)
            iface_key = f"interface_{iface_name}"
            interface_settings[iface_key] = {
                'show': bool(show_cb and show_cb.isChecked()),
                'friendly_name': item.text(1),
                'comment': item.text(3),
                'show_with_comment': bool(show_with_cmt_cb and show_with_cmt_cb.isChecked()),
            }
        return interface_settings

    def _save_local_interface_settings(self):
        """Persist local interface settings"""
        self._settings().setValue('interface_settings', json.dumps(self._collect_local_interface_settings()))

    def _notify_preferences_changed(self):
        """Notify parent dialogs/windows that interface preferences changed"""
        parent = self.parent()
        if parent and hasattr(parent, '_on_interface_preferences_changed'):
            parent._on_interface_preferences_changed()

    def _on_local_show_changed(self, _item):
        self._save_local_interface_settings()
        self._notify_preferences_changed()

    def _on_local_show_with_comment_changed(self, _item):
        self._save_local_interface_settings()
        self._notify_preferences_changed()

    def _on_local_item_changed(self, item, column):
        if column in (1, 3):
            self._save_local_interface_settings()
            self._notify_preferences_changed()
    
    # ===== PIPES TAB =====
    
    def _build_pipes_tab(self):
        """Build Pipes tab"""
        layout = QVBoxLayout(self.pipes_tab)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)
        
        label = QLabel('Local Pipe Paths')
        layout.addWidget(label)

        self.pipes_table = QTableWidget()
        self.pipes_table.setColumnCount(1)
        self.pipes_table.setHorizontalHeaderLabels(['Pipe Path'])
        self.pipes_table.horizontalHeader().setStretchLastSection(True)
        self.pipes_table.verticalHeader().setVisible(False)
        self.pipes_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.pipes_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.pipes_table.setEditTriggers(
            QAbstractItemView.EditTrigger.DoubleClicked
            | QAbstractItemView.EditTrigger.EditKeyPressed
            | QAbstractItemView.EditTrigger.SelectedClicked
        )
        layout.addWidget(self.pipes_table)
        
        # Buttons
        btn_layout = QHBoxLayout()

        add_btn = QPushButton('+')
        add_btn.setFixedWidth(40)
        add_btn.clicked.connect(self._on_add_pipe)
        btn_layout.addWidget(add_btn)

        remove_btn = QPushButton('-')
        remove_btn.setFixedWidth(40)
        remove_btn.clicked.connect(self._on_remove_pipe)
        btn_layout.addWidget(remove_btn)

        help_btn = QPushButton('Help')
        help_btn.clicked.connect(self._show_pipe_help)
        btn_layout.addWidget(help_btn)
        
        btn_layout.addStretch()
        layout.addLayout(btn_layout)
    
    def _on_add_pipe(self):
        """Add a new pipe"""
        row = self.pipes_table.rowCount()
        self.pipes_table.insertRow(row)
        item = QTableWidgetItem('')
        item.setFlags(item.flags() | Qt.ItemFlag.ItemIsEditable)
        self.pipes_table.setItem(row, 0, item)
        self.pipes_table.setCurrentCell(row, 0)
        self.pipes_table.editItem(item)
    
    def _on_remove_pipe(self):
        """Remove selected pipe line"""
        row = self.pipes_table.currentRow()
        if row >= 0:
            self.pipes_table.removeRow(row)
    
    def _show_pipe_help(self):
        dialog = QDialog(self)
        dialog.setWindowTitle('Pipes Help')
        dialog.resize(760, 600)

        layout = QVBoxLayout(dialog)
        label = QLabel('Tham khảo: script publisher cho Windows named pipe (PCAP stream).')
        layout.addWidget(label)

        text = QTextEdit()
        text.setReadOnly(True)
        text.setPlainText(self.PIPE_HELP_TEXT)
        layout.addWidget(text)

        close_btn = QPushButton('Close')
        close_btn.clicked.connect(dialog.accept)
        button_row = QHBoxLayout()
        button_row.addStretch()
        button_row.addWidget(close_btn)
        layout.addLayout(button_row)

        dialog.exec()

    def _pipe_paths(self):
        paths = []
        seen = set()
        for row in range(self.pipes_table.rowCount()):
            item = self.pipes_table.item(row, 0)
            path = (item.text() if item else '').strip()
            if not path or path in seen:
                continue
            seen.add(path)
            paths.append(path)
        return paths

    def _set_pipe_paths(self, paths):
        self.pipes_table.setRowCount(0)
        for path in paths:
            row = self.pipes_table.rowCount()
            self.pipes_table.insertRow(row)
            item = QTableWidgetItem(path)
            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsEditable)
            self.pipes_table.setItem(row, 0, item)
    
    # ===== REMOTE INTERFACES TAB =====
    
    def _build_remote_tab(self):
        """Build Remote Interfaces tab"""
        layout = QVBoxLayout(self.remote_tab)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)
        
        # Table for remote interfaces
        self.remote_table = QTableWidget()
        self.remote_table.setColumnCount(4)
        self.remote_table.setHorizontalHeaderLabels(['Show', 'Host / Device URL', 'Port', 'Auth Type'])
        self.remote_table.horizontalHeader().setStretchLastSection(True)
        self.remote_table.setColumnWidth(0, 50)
        self.remote_table.setColumnWidth(1, 250)
        self.remote_table.setColumnWidth(2, 80)
        
        layout.addWidget(self.remote_table)
        
        # Buttons
        btn_layout = QHBoxLayout()
        
        add_btn = QPushButton('+')
        add_btn.setFixedWidth(40)
        add_btn.clicked.connect(self._on_add_remote)
        btn_layout.addWidget(add_btn)
        
        remove_btn = QPushButton('-')
        remove_btn.setFixedWidth(40)
        remove_btn.clicked.connect(self._on_remove_remote)
        btn_layout.addWidget(remove_btn)
        
        btn_layout.addStretch()
        layout.addLayout(btn_layout)
        
        # Authentication options (collapsible/detailed)
        detail_layout = QHBoxLayout()
        detail_layout.addWidget(QLabel('Authentication:'))
        
        auth_group = QButtonGroup(self)
        self.auth_null = QRadioButton('Null')
        self.auth_password = QRadioButton('Password')
        self.auth_null.setChecked(True)
        auth_group.addButton(self.auth_null)
        auth_group.addButton(self.auth_password)
        
        detail_layout.addWidget(self.auth_null)
        detail_layout.addWidget(self.auth_password)
        detail_layout.addStretch()
        
        layout.addLayout(detail_layout)
        
        # Populate remote interfaces
        self._populate_remote_interfaces()
    
    def _populate_remote_interfaces(self):
        """Populate remote interfaces table"""
        remotes_json = self._settings().value('remote_interfaces', '[]', str)
        saved_remotes = json.loads(remotes_json)
        
        self.remote_table.setRowCount(len(saved_remotes))
        
        for row, remote in enumerate(saved_remotes):
            # Show checkbox
            show_cb = QCheckBox()
            show_cb.setChecked(remote.get('show', True))
            self.remote_table.setCellWidget(row, 0, show_cb)
            
            # Host / Device URL
            host = QLineEdit()
            host.setText(remote.get('host', ''))
            self.remote_table.setCellWidget(row, 1, host)
            
            # Port
            port = QSpinBox()
            port.setMinimum(0)
            port.setMaximum(65535)
            port.setValue(remote.get('port', 2002))
            self.remote_table.setCellWidget(row, 2, port)
            
            # Auth Type
            auth_combo = QComboBox()
            auth_combo.addItems(['Null', 'Password'])
            auth_combo.setCurrentText(remote.get('auth_type', 'Null'))
            self.remote_table.setCellWidget(row, 3, auth_combo)
    
    def _on_add_remote(self):
        """Add new remote interface row"""
        row = self.remote_table.rowCount()
        self.remote_table.insertRow(row)
        
        # Show checkbox
        show_cb = QCheckBox()
        show_cb.setChecked(True)
        self.remote_table.setCellWidget(row, 0, show_cb)
        
        # Host
        host = QLineEdit()
        self.remote_table.setCellWidget(row, 1, host)
        
        # Port
        port = QSpinBox()
        port.setMinimum(0)
        port.setMaximum(65535)
        port.setValue(2002)
        self.remote_table.setCellWidget(row, 2, port)
        
        # Auth Type
        auth_combo = QComboBox()
        auth_combo.addItems(['Null', 'Password'])
        self.remote_table.setCellWidget(row, 3, auth_combo)
    
    def _on_remove_remote(self):
        """Remove selected remote interface row"""
        current_row = self.remote_table.currentRow()
        if current_row >= 0:
            self.remote_table.removeRow(current_row)
    
    # ===== SAVE/LOAD =====
    
    def _load_settings(self):
        """Load saved settings"""
        pipes = self._settings().value('pipes', '', str)
        self._set_pipe_paths([p.strip() for p in pipes.splitlines() if p.strip()])
    
    def accept(self):
        """Save settings and close"""
        # Save local interfaces from tree widget
        self._save_local_interface_settings()
        
        # Save pipes
        self._settings().setValue('pipes', '\n'.join(self._pipe_paths()))
        
        # Save remote interfaces
        remote_interfaces = []
        for row in range(self.remote_table.rowCount()):
            show_cb = self.remote_table.cellWidget(row, 0)
            host_input = self.remote_table.cellWidget(row, 1)
            port_spin = self.remote_table.cellWidget(row, 2)
            auth_combo = self.remote_table.cellWidget(row, 3)
            
            remote_interfaces.append({
                'show': show_cb.isChecked(),
                'host': host_input.text(),
                'port': port_spin.value(),
                'auth_type': auth_combo.currentText()
            })
        
        self._settings().setValue('remote_interfaces', json.dumps(remote_interfaces))

        self._notify_preferences_changed()
        
        super().accept()
