import os
import json
import base64
import zipfile
import psutil
from PySide6.QtCore import Qt, QSettings
from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QTabWidget, QWidget, QPushButton, QLabel,
    QTableWidget, QTableWidgetItem, QCheckBox, QLineEdit, QTextEdit, QFileDialog,
    QSpinBox, QMessageBox, QComboBox, QTreeWidget,
    QTreeWidgetItem, QHeaderView, QAbstractItemView, QFrame
)
from PySide6.QtGui import QIcon
from gui.table_editor_helpers import (
    LineEditDelegate,
    PasswordLineEditDelegate,
    SpinBoxDelegate,
    apply_input_like_table_style,
    show_overlay_combo_editor,
)


class ManageInterfacesDialog(QDialog):
    """Manage Interfaces dialog - Local Interfaces, Pipes, Remote Interfaces"""

    PIPE_HELP_TEXT = """Tham khao: Windows Named Pipe publisher cho Packetra

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

    REMOTE_AGENT_TEMPLATE = r'''import argparse
import logging
import re
import sys


def _ensure_scapy():
    try:
        from scapy.all import sniff, get_if_list, raw, Ether, IP, UDP, Raw
        return sniff, get_if_list, raw, Ether, IP, UDP, Raw
    except ModuleNotFoundError:
        raise RuntimeError('Scapy is not installed on remote host. Please install scapy before running the agent.')

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s %(message)s')


def list_interfaces():
    sniff, get_if_list, _raw, _Ether, _IP, _UDP, _Raw = _ensure_scapy()

    def _clean_name(value):
        text = str(value or '').strip()
        if not text:
            return ''
        # Remove common Windows filter suffix noise.
        text = re.sub(r'-(WFP|Fortinet NDIS|Npcap Packet Driver|VirtualBox NDIS|QoS Packet Scheduler|Native WiFi Filter|Virtual WiFi Filter).*$', '', text, flags=re.IGNORECASE)
        text = re.sub(r'-000\d+$', '', text, flags=re.IGNORECASE)
        return text.strip()

    def _is_noise(value):
        low = str(value or '').lower()
        blocked_keywords = (
            'lightweight filter',
            'wfp ',
            'ndis',
            'qos packet scheduler',
            'npcap packet driver',
            'virtual wifi filter',
            'native wifi filter',
            'miniport',
            'teredo',
            '6to4',
            'ip-https',
            'kernel debugger',
        )
        return any(k in low for k in blocked_keywords)

    try:
        from scapy.arch.windows import get_windows_if_list
        merged = {}
        for entry in get_windows_if_list():
            if isinstance(entry, dict):
                dev_name = entry.get('name') or ''
                win_name = entry.get('win_name') or ''
                desc = entry.get('description') or entry.get('friendly_name') or ''

                # display = Windows friendly name (short, e.g. 'Wi-Fi')
                # target  = Npcap device string used by scapy sniff()
                display = _clean_name(win_name) or _clean_name(desc)
                target = str(dev_name).strip() if dev_name else str(win_name).strip()

                if not display:
                    continue
                if _is_noise(display) and _is_noise(target):
                    continue

                key = display.lower()
                score = 0
                if not _is_noise(display):
                    score += 10
                if 'virtual' not in display.lower():
                    score += 2
                prev = merged.get(key)
                if prev is None or score > prev[0]:
                    merged[key] = (score, display, target)
                continue
            try:
                name, dev, _desc = entry
                display = _clean_name(str(name).strip())
                target = str(dev or name).strip()
                if display and not (_is_noise(display) and _is_noise(target)):
                    key = display.lower()
                    prev = merged.get(key)
                    if prev is None:
                        merged[key] = (5, display, target)
            except Exception:
                pass

        rows = sorted((v[1], v[2]) for v in merged.values())
        print('testinterface || testinterface')
        for display, target in rows:
            print(f"{display} || {target}")
        return
    except Exception:
        pass

    print('testinterface || testinterface')
    for iface in get_if_list():
        print(f"{iface} || {iface}")


def capture_to_stdout(iface, bpf_filter='', promiscuous=True):
    import os
    import struct
    import time
    # On Windows, stdout pipe opened by cmd.exe is in text mode by default.
    # Set binary mode BEFORE writing any PCAP bytes to prevent \n -> \r\n corruption.
    if sys.platform == 'win32':
        try:
            import msvcrt
            msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
        except Exception:
            pass  # If fileno() unsupported in this SSH context, continue anyway

    sniff, _get_if_list, raw, Ether, IP, UDP, Raw = _ensure_scapy()

    capture_iface = str(iface or '').strip()
    if sys.platform == 'win32':
        # Accept either friendly names (Wi-Fi/Ethernet) or raw NPF device strings.
        # Resolve to NPF when possible because WinPcap/Npcap sniffing is most reliable with it.
        try:
            from scapy.arch.windows import get_windows_if_list
            requested = capture_iface.lower()
            for entry in get_windows_if_list():
                if not isinstance(entry, dict):
                    continue
                dev_name = str(entry.get('name') or '').strip()
                win_name = str(entry.get('win_name') or '').strip()
                friendly = str(entry.get('friendly_name') or '').strip()
                desc = str(entry.get('description') or '').strip()
                candidates = [dev_name, win_name, friendly, desc]
                if any(str(c or '').strip().lower() == requested for c in candidates):
                    if dev_name:
                        capture_iface = dev_name
                    break
        except Exception:
            pass

    out = getattr(sys.stdout, 'buffer', sys.stdout)
    # PCAP global header (little-endian, LINKTYPE_ETHERNET=1).
    out.write(struct.pack('<IHHIIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    out.flush()

    def _emit(pkt_bytes, pkt_time=None):
        now = float(pkt_time) if pkt_time is not None else time.time()
        ts_sec = int(now)
        ts_usec = int((now - ts_sec) * 1_000_000)
        incl_len = len(pkt_bytes)
        out.write(struct.pack('<IIII', ts_sec, ts_usec, incl_len, incl_len))
        out.write(pkt_bytes)
        out.flush()

    if capture_iface.lower() == 'testinterface':
        seq = 1
        while True:
            pkt = Ether(dst='ff:ff:ff:ff:ff:ff', src='02:00:00:00:00:01') / IP(src='10.10.10.1', dst='10.10.10.2') / UDP(sport=50000, dport=50001) / Raw(load=f'packetra-test-{seq}'.encode('ascii'))
            _emit(raw(pkt), pkt_time=time.time())
            seq += 1
            time.sleep(0.25)

    def _write(pkt):
        _emit(raw(pkt), pkt_time=getattr(pkt, 'time', None))

    sniff(
        iface=capture_iface,
        prn=_write,
        store=False,
        filter=bpf_filter or None,
        promisc=bool(promiscuous),
    )


def main():
    parser = argparse.ArgumentParser(description='Packetra Remote Capture Agent')
    parser.add_argument('--list', action='store_true')
    parser.add_argument('--capture', action='store_true')
    parser.add_argument('--iface', default='')
    parser.add_argument('--stdout', action='store_true')
    parser.add_argument('--filter', default='')
    parser.add_argument('--promiscuous', action='store_true')
    args = parser.parse_args()

    if args.list:
        list_interfaces()
        return

    if args.capture and args.stdout and args.iface:
        try:
            capture_to_stdout(args.iface, args.filter, args.promiscuous)
        except Exception as exc:
            import traceback
            traceback.print_exc()
            sys.stderr.write(f'capture_to_stdout error: {exc}\n')
            sys.stderr.flush()
            sys.exit(1)
        return

    parser.print_help()


if __name__ == '__main__':
    main()
'''

    REMOTE_INSTALL_PS1_TEMPLATE = ""
    
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

    def _style_flat_table(self, table):
        table.setAlternatingRowColors(True)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        table.setEditTriggers(
            QAbstractItemView.EditTrigger.DoubleClicked
            | QAbstractItemView.EditTrigger.EditKeyPressed
            | QAbstractItemView.EditTrigger.SelectedClicked
        )
        table.setShowGrid(False)
        table.setFrameShape(QFrame.Shape.NoFrame)
        table.setStyleSheet('QTableWidget { border: none; gridline-color: transparent; }')
        return table

    def _style_flat_tree(self, tree):
        tree.setAlternatingRowColors(True)
        tree.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        tree.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        tree.setFrameShape(QFrame.Shape.NoFrame)
        tree.setStyleSheet('QTreeWidget { border: none; gridline-color: transparent; }')
        return tree
    
    # ===== LOCAL INTERFACES TAB (QTreeWidget) =====
    
    def _build_local_tab(self):
        """Build Local Interfaces tab with QTreeWidget like Input tab"""
        layout = QVBoxLayout(self.local_tab)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)
        
        # Tree widget - no gridlines, no headers like Capture Options Input tab
        self.local_tree = QTreeWidget()
        self._style_flat_tree(self.local_tree)
        self.local_tree.setColumnCount(5)
        self.local_tree.setHeaderLabels(['Show', 'Friendly Name', 'Interface Name', 'Comment', 'Show with cmt'])
        self.local_tree.setColumnWidth(0, 60)
        self.local_tree.setColumnWidth(1, 180)
        self.local_tree.setColumnWidth(2, 350)
        self.local_tree.setColumnWidth(3, 200)
        self.local_tree.setColumnWidth(4, 120)
        
        # Hide gridlines like Input tab
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
        self._style_flat_table(self.pipes_table)
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
        label = QLabel('Reference: Windows named pipe publisher script for Packetra.')
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
        apply_input_like_table_style(self.remote_table, editable=True)
        self.remote_table.setColumnCount(7)
        self.remote_table.setHorizontalHeaderLabels(['Show', 'Host / Device URL', 'Port', 'OS', 'Username', 'Auth Type', 'Password'])
        self.remote_table.horizontalHeader().setStretchLastSection(False)
        for column in range(7):
            self.remote_table.horizontalHeader().setSectionResizeMode(column, QHeaderView.Interactive)
        self.remote_table.setColumnWidth(0, 50)
        self.remote_table.setColumnWidth(1, 160)
        self.remote_table.setColumnWidth(2, 80)
        self.remote_table.setColumnWidth(3, 90)
        self.remote_table.setColumnWidth(4, 120)
        self.remote_table.setColumnWidth(5, 100)
        self.remote_table.setItemDelegateForColumn(1, LineEditDelegate(self.remote_table))
        self.remote_table.setItemDelegateForColumn(2, SpinBoxDelegate(1, 65535, parent=self.remote_table))
        self.remote_table.setItemDelegateForColumn(4, LineEditDelegate(self.remote_table))
        self.remote_table.setItemDelegateForColumn(6, PasswordLineEditDelegate(self.remote_table))
        
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

        load_btn = QPushButton('Connect && Load Interfaces')
        load_btn.clicked.connect(self._on_load_remote_interfaces)
        btn_layout.addWidget(load_btn)

        install_btn = QPushButton('Install Agent')
        install_btn.clicked.connect(self._on_install_agent)
        btn_layout.addWidget(install_btn)

        btn_layout.addStretch()
        layout.addLayout(btn_layout)

        self.remote_iface_tree = QTreeWidget()
        self._style_flat_tree(self.remote_iface_tree)
        self.remote_iface_tree.setColumnCount(2)
        self.remote_iface_tree.setHeaderLabels(['Remote Host / Interface', 'Show'])
        self.remote_iface_tree.header().setSectionResizeMode(0, QHeaderView.Stretch)
        self.remote_iface_tree.header().setSectionResizeMode(1, QHeaderView.Interactive)
        self.remote_iface_tree.header().setStretchLastSection(True)
        tree_header_layout = QHBoxLayout()
        tree_header_layout.addWidget(QLabel('Discovered Interfaces'))
        self.remote_select_all_btn = QPushButton('Select/Deselect All for Host')
        self.remote_select_all_btn.setEnabled(False)
        self.remote_select_all_btn.clicked.connect(self._on_remote_select_all_for_host)
        tree_header_layout.addStretch()
        tree_header_layout.addWidget(self.remote_select_all_btn)
        layout.addLayout(tree_header_layout)
        layout.addWidget(self.remote_iface_tree)
        self.remote_iface_tree.itemSelectionChanged.connect(lambda: self.remote_select_all_btn.setEnabled(len(self.remote_iface_tree.selectedItems()) > 0 and self.remote_iface_tree.selectedItems()[0].parent() is None))
        self.remote_table.itemChanged.connect(self._on_remote_table_item_changed)
        self.remote_table.cellDoubleClicked.connect(self._on_remote_table_cell_double_clicked)
        
        # Populate remote interfaces
        self._populate_remote_interfaces()
        self._refresh_remote_interface_tree()
    
    def _make_remote_check_item(self, checked: bool) -> QTableWidgetItem:
        item = QTableWidgetItem('')
        item.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable | Qt.ItemFlag.ItemIsUserCheckable)
        item.setCheckState(Qt.CheckState.Checked if checked else Qt.CheckState.Unchecked)
        return item

    def _set_remote_password_item_state(self, row: int) -> None:
        auth_item = self.remote_table.item(row, 5)
        password_item = self.remote_table.item(row, 6)
        if password_item is None:
            password_item = QTableWidgetItem('')
            self.remote_table.setItem(row, 6, password_item)
        auth_type = str(auth_item.text() if auth_item is not None else 'Null').strip() or 'Null'
        actual_password = str(password_item.data(Qt.ItemDataRole.UserRole) or '')
        if auth_type == 'Password':
            password_item.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable | Qt.ItemFlag.ItemIsEditable)
            password_item.setText('*' * len(actual_password))
        else:
            password_item.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
            password_item.setData(Qt.ItemDataRole.UserRole, '')
            password_item.setText('')

    def _set_remote_row(self, row: int, remote: dict | None = None) -> None:
        remote = remote or {}
        self.remote_table.setItem(row, 0, self._make_remote_check_item(bool(remote.get('show', False))))
        self.remote_table.setItem(row, 1, QTableWidgetItem(str(remote.get('host', '') or '')))

        port_value = int(remote.get('port', 22) or 22)
        port_item = QTableWidgetItem(str(port_value))
        port_item.setData(Qt.ItemDataRole.UserRole, port_value)
        self.remote_table.setItem(row, 2, port_item)

        os_type = str(remote.get('os_type', 'linux') or 'linux').lower()
        os_item = QTableWidgetItem(os_type)
        os_item.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
        self.remote_table.setItem(row, 3, os_item)
        self.remote_table.setItem(row, 4, QTableWidgetItem(str(remote.get('username', '') or '')))

        auth_type = str(remote.get('auth_type', 'Null') or 'Null')
        auth_item = QTableWidgetItem(auth_type)
        auth_item.setFlags(Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable)
        self.remote_table.setItem(row, 5, auth_item)

        password_value = str(remote.get('password', '') or '')
        password_item = QTableWidgetItem('*' * len(password_value) if auth_type == 'Password' else '')
        password_item.setData(Qt.ItemDataRole.UserRole, password_value if auth_type == 'Password' else '')
        self.remote_table.setItem(row, 6, password_item)
        self._set_remote_password_item_state(row)

    def _populate_remote_interfaces(self):
        """Populate remote interfaces table"""
        remotes_json = self._settings().value('remote_interfaces', '[]', str)
        saved_remotes = json.loads(remotes_json)
        was_blocked = self.remote_table.blockSignals(True)
        try:
            self.remote_table.setRowCount(len(saved_remotes))
            for row, remote in enumerate(saved_remotes):
                self._set_remote_row(row, remote)
        finally:
            self.remote_table.blockSignals(was_blocked)
    
    def _on_add_remote(self):
        """Add new remote interface row"""
        row = self.remote_table.rowCount()
        self.remote_table.insertRow(row)
        self._set_remote_row(row, {'show': True, 'port': 22, 'os_type': 'linux', 'auth_type': 'Null'})
    
    def _on_remove_remote(self):
        """Remove selected remote interface row"""
        current_row = self.remote_table.currentRow()
        if current_row >= 0:
            self.remote_table.removeRow(current_row)
            self._refresh_remote_interface_tree()

    def _remote_row_to_config(self, row):
        show_item = self.remote_table.item(row, 0)
        host_item = self.remote_table.item(row, 1)
        port_item = self.remote_table.item(row, 2)
        os_item = self.remote_table.item(row, 3)
        username_item = self.remote_table.item(row, 4)
        auth_item = self.remote_table.item(row, 5)
        password_item = self.remote_table.item(row, 6)

        auth_type = str(auth_item.text() if auth_item is not None else 'Null').strip() or 'Null'
        raw_password = str(password_item.data(Qt.ItemDataRole.UserRole) if password_item is not None else '')
        try:
            if port_item is not None and port_item.data(Qt.ItemDataRole.UserRole) is not None:
                port_value = int(port_item.data(Qt.ItemDataRole.UserRole))
            else:
                port_value = int(str(port_item.text() if port_item is not None else '22').strip() or '22')
        except Exception:
            port_value = 22
        return {
            'show': bool(show_item is not None and show_item.checkState() == Qt.CheckState.Checked),
            'host': str(host_item.text() if host_item is not None else '').strip(),
            'port': port_value,
            'os_type': str(os_item.text() if os_item is not None else 'linux').strip().lower(),
            'username': str(username_item.text() if username_item is not None else '').strip(),
            'auth_type': auth_type,
            'password': (raw_password if auth_type == 'Password' else ''),
        }

    def _on_remote_table_item_changed(self, item: QTableWidgetItem) -> None:
        if item is None:
            return
        if item.column() == 2:
            try:
                port_value = max(1, min(65535, int((item.text() or '22').strip())))
            except Exception:
                port_value = 22
            blocker = self.remote_table.blockSignals(True)
            item.setData(Qt.ItemDataRole.UserRole, port_value)
            item.setText(str(port_value))
            self.remote_table.blockSignals(blocker)
        elif item.column() == 5:
            blocker = self.remote_table.blockSignals(True)
            auth_text = str(item.text() or 'Null').strip()
            if auth_text not in {'Null', 'Password'}:
                item.setText('Null')
            self._set_remote_password_item_state(item.row())
            self.remote_table.blockSignals(blocker)

    def _on_remote_table_cell_double_clicked(self, row: int, column: int) -> None:
        if row < 0 or column not in {3, 5}:
            return
        item = self.remote_table.item(row, column)
        if item is None:
            return
        values = ['linux', 'windows'] if column == 3 else ['Null', 'Password']
        rect = self.remote_table.visualRect(self.remote_table.model().index(row, column))
        show_overlay_combo_editor(
            self.remote_table,
            rect,
            values,
            item.text(),
            lambda text, it=item, col=column: (
                it.setText(text),
                self._set_remote_password_item_state(row) if col == 5 else None,
            ),
        )

    def _remote_host_key(self, config):
        return f"{config.get('username', '').strip()}@{config.get('host', '').strip()}:{int(config.get('port', 22) or 22)}"

    def _on_load_remote_interfaces(self):
        row = self.remote_table.currentRow()
        if row < 0:
            QMessageBox.warning(self, 'ERROR', 'ERROR')
            return

        config = self._remote_row_to_config(row)
        if not config['host'] or not config['username']:
            QMessageBox.warning(self, 'ERROR', 'ERROR')
            return

        try:
            from core.remote_capture import SSHRemoteCapture
            client = SSHRemoteCapture(
                host=config['host'],
                port=config['port'],
                username=config['username'],
                password=config['password'] if config['auth_type'] == 'Password' else None,
                key_path=None,
                os_type=config['os_type'],
                auth_type=config['auth_type'],
            )
            iface_names = client.list_interfaces()
            client.close()
        except Exception as exc:
            import logging
            message = str(exc or '').strip() or 'Cannot connect to remote agent.'
            logging.getLogger(__name__).warning('Remote interface load failed: %s', message)
            QMessageBox.critical(self, 'ERROR', message)
            return

        interfaces = []
        for iface in iface_names:
            raw_value = str(iface).strip()
            if not raw_value:
                continue
            if '||' in raw_value:
                left_part, right_part = [part.strip() for part in raw_value.split('||', 1)]
                # Backward/forward compatible parsing:
                # - old agent:  "Intel... || Wi-Fi" => display Wi-Fi, target Wi-Fi
                # - new agent:  "Wi-Fi || \\Device\\NPF_{...}" => display Wi-Fi, target NPF
                if right_part.startswith('\\\\Device\\NPF'):
                    display_name = left_part or right_part
                    target_name = right_part
                else:
                    display_name = right_part or left_part
                    target_name = right_part or left_part
            else:
                display_name = raw_value
                target_name = raw_value
            interfaces.append({'name': display_name, 'target': target_name, 'show': False})

        config['interfaces'] = interfaces

        # write back this row to settings model snapshot and refresh tree
        remotes = self._collect_remote_interfaces_from_ui()
        if row < len(remotes):
            remotes[row] = config
        self._apply_remote_interfaces_to_ui(remotes)
        self._refresh_remote_interface_tree()
        QMessageBox.information(self, 'Remote Interfaces', f'Loaded {len(interfaces)} interfaces from {self._remote_host_key(config)}')

    def _refresh_remote_interface_tree(self):
        self.remote_iface_tree.clear()
        for config in self._collect_remote_interfaces_from_ui():
            host = config.get('host', '').strip()
            username = config.get('username', '').strip()
            if not host:
                continue
            host_item = QTreeWidgetItem([self._remote_host_key(config), ''])
            # host_item.setFlags(host_item.flags() & ~Qt.ItemFlag.ItemIsSelectable)
            self.remote_iface_tree.addTopLevelItem(host_item)

            for iface in config.get('interfaces', []):
                name = str(iface.get('name', '')).strip()
                if not name:
                    continue
                child = QTreeWidgetItem([name, ''])
                host_item.addChild(child)
                cb = QCheckBox()
                cb.setChecked(bool(iface.get('show', False)))
                self.remote_iface_tree.setItemWidget(child, 1, cb)
                cb.stateChanged.connect(self._on_remote_iface_show_changed)
            host_item.setExpanded(False)

    def _on_remote_select_all_for_host(self):
        selected = self.remote_iface_tree.selectedItems()
        if not selected:
            return
        item = selected[0]
        # If a child is selected, get its parent host
        host_item = item.parent() if item.parent() else item
        
        # Check if all are currently checked
        from PySide6.QtWidgets import QCheckBox
        from PySide6.QtCore import Qt
        all_checked = True
        for j in range(host_item.childCount()):
            child = host_item.child(j)
            cb = self.remote_iface_tree.itemWidget(child, 1)
            real_cb = (cb if hasattr(cb, 'isChecked') else (cb.findChild(QCheckBox) if cb else None))
            if real_cb and not real_cb.isChecked():
                all_checked = False
                break
                
        target_state = Qt.Unchecked if all_checked else Qt.Checked
        for j in range(host_item.childCount()):
            child = host_item.child(j)
            cb = self.remote_iface_tree.itemWidget(child, 1)
            real_cb = (cb if hasattr(cb, 'isChecked') else (cb.findChild(QCheckBox) if cb else None))
            if real_cb:
                real_cb.setCheckState(target_state)

    def _on_remote_iface_show_changed(self, _state):
        remotes = self._collect_remote_interfaces_from_ui()
        host_idx = 0
        for i in range(self.remote_iface_tree.topLevelItemCount()):
            host_item = self.remote_iface_tree.topLevelItem(i)
            if host_idx >= len(remotes):
                break
            iface_entries = remotes[host_idx].get('interfaces', [])
            for j in range(host_item.childCount()):
                if j >= len(iface_entries):
                    break
                child = host_item.child(j)
                cb = self.remote_iface_tree.itemWidget(child, 1)
                real_cb = (cb if hasattr(cb, "isChecked") else (cb.findChild(QCheckBox) if cb else None))
                iface_entries[j]['show'] = bool(real_cb and real_cb.isChecked())
            host_idx += 1
        self._apply_remote_interfaces_to_ui(remotes)

    def _collect_remote_interfaces_from_ui(self):
        remote_interfaces = []
        for row in range(self.remote_table.rowCount()):
            cfg = self._remote_row_to_config(row)
            if not cfg['host']:
                continue
            existing = None
            # keep previously discovered interface list if available in settings snapshot
            remotes_json = self._settings().value('remote_interfaces', '[]', str)
            try:
                saved = json.loads(remotes_json)
            except Exception:
                saved = []
            key = self._remote_host_key(cfg)
            for item in saved:
                if self._remote_host_key(item) == key:
                    existing = item
                    break
            cfg['interfaces'] = list((existing or {}).get('interfaces', []))
            remote_interfaces.append(cfg)
        return remote_interfaces

    def _apply_remote_interfaces_to_ui(self, remote_interfaces):
        self._settings().setValue('remote_interfaces', json.dumps(remote_interfaces))

    def _download_agent_package(self):
        # Packetra bundles the remote agent zip that contains PacketraAgent.msi.
        zip_src = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'packetra-remote-agent.zip')
        if not os.path.exists(zip_src):
            QMessageBox.warning(self, 'ERROR', 'ERROR')
            return None

        target_file, _ = QFileDialog.getSaveFileName(self, 'Save Remote Agent Installer Package', 'packetra-remote-agent.zip', 'ZIP Archive (*.zip)')
        if not target_file:
            return None

        import shutil
        try:
            shutil.copy2(zip_src, target_file)
        except OSError as exc:
            import logging
            logging.getLogger(__name__).exception('Cannot write agent package')
            QMessageBox.critical(self, 'ERROR', 'ERROR')
            return None

        return target_file

    def _show_agent_text_dialog(self, title, text):
        dialog = QDialog(self)
        dialog.setWindowTitle(title)
        dialog.resize(600, 350)
        layout = QVBoxLayout(dialog)
        text_box = QTextEdit()
        text_box.setReadOnly(True)
        text_box.setPlainText(text)
        layout.addWidget(text_box)
        btn_row = QHBoxLayout()
        btn_row.addStretch()
        close_btn = QPushButton('Close')
        close_btn.clicked.connect(dialog.accept)
        btn_row.addWidget(close_btn)
        layout.addLayout(btn_row)
        dialog.exec()

    def _on_install_agent(self):
        target_file = self._download_agent_package()
        if not target_file:
            return

        self._show_agent_text_dialog(
            'Install Agent',
            f'Packetra remote agent package downloaded successfully.\n\n'
            f'Package: {target_file}\n\n'
            'This button only downloads the ZIP file. It does not attach the package to any remote host.\n'
            'You can move the ZIP wherever you need afterward.'
        )
    
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
        remote_interfaces = self._collect_remote_interfaces_from_ui()

        # Overlay per-interface show values from the discovery tree.
        host_map = {self._remote_host_key(cfg): cfg for cfg in remote_interfaces}
        for i in range(self.remote_iface_tree.topLevelItemCount()):
            host_item = self.remote_iface_tree.topLevelItem(i)
            host_key = host_item.text(0).strip()
            cfg = host_map.get(host_key)
            if not cfg:
                continue
            iface_map = {str(item.get('name', '')).strip(): item for item in cfg.get('interfaces', [])}
            for j in range(host_item.childCount()):
                child = host_item.child(j)
                iface_name = child.text(0).strip()
                if not iface_name:
                    continue
                cb = self.remote_iface_tree.itemWidget(child, 1)
                iface_map.setdefault(iface_name, {'name': iface_name, 'show': True})['show'] = bool(cb and cb.isChecked())
            cfg['interfaces'] = list(iface_map.values())
        
        self._settings().setValue('remote_interfaces', json.dumps(remote_interfaces))

        self._notify_preferences_changed()
        
        super().accept()
