from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont, QAction
from PySide6.QtWidgets import QTreeWidget, QTreeWidgetItem, QMenu

from core.formatters import packet_summary_tree


class PacketDetailsTree(QTreeWidget):
    item_selected = Signal(int, int)  # offset, length
    item_bytes_selected = Signal(int, int, str)  # offset, length, byte_source
    detail_field_selected = Signal(str, int)  # field name, byte count
    BYTE_SOURCE_ROLE = int(Qt.ItemDataRole.UserRole) + 1
    BYTE_SELECTABLE_ROLE = int(Qt.ItemDataRole.UserRole) + 2

    def __init__(self):
        super().__init__()
        # Hide header entirely to avoid empty top row.
        self.setHeaderHidden(True)
        self.setUniformRowHeights(True)
        self.setIndentation(18)
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self._show_context_menu)
        self.itemSelectionChanged.connect(self._on_selection_changed)
        # Persistent expand state by top-level section type.
        self._expand_state = {}

    def _on_selection_changed(self):
        selected_items = self.selectedItems()
        if not selected_items:
            self.item_selected.emit(-1, 0)
            self.item_bytes_selected.emit(-1, 0, 'packet')
            self.detail_field_selected.emit('', 0)
            return

        item = selected_items[0]
        title = item.text(0)
        offset, length = item.data(0, Qt.ItemDataRole.UserRole)
        byte_source = str(item.data(0, self.BYTE_SOURCE_ROLE) or 'packet')
        selectable = bool(item.data(0, self.BYTE_SELECTABLE_ROLE))
        is_top_level_frame_section = item.parent() is None and title.lower().startswith('frame')

        detail_name = self._detail_field_name(title)
        detail_length = int(length) if length > 0 and not is_top_level_frame_section else 0
        self.detail_field_selected.emit(detail_name if detail_length > 0 else '', detail_length)

        if selectable and offset >= 0 and length > 0 and not is_top_level_frame_section:
            self.item_selected.emit(offset, length)
            self.item_bytes_selected.emit(offset, length, byte_source)
            return

        self.item_selected.emit(-1, 0)
        self.item_bytes_selected.emit(-1, 0, byte_source)

    def _detail_field_name(self, title: str) -> str:
        text = str(title or '').strip()
        if not text:
            return ''
        if ' = ' in text:
            text = text.split(' = ', 1)[1].strip()
        if ':' in text:
            text = text.split(':', 1)[0].strip()
        return text

    def _show_context_menu(self, position):
        menu = QMenu(self)
        copy_action = QAction('Copy', self)
        copy_action.triggered.connect(self._copy_details)
        menu.addAction(copy_action)
        menu.exec(self.mapToGlobal(position))

    def _copy_details(self):
        # Copy all details to clipboard
        details = []
        def collect_items(item, level=0):
            indent = '  ' * level
            details.append(f'{indent}{item.text(0)}')
            for i in range(item.childCount()):
                collect_items(item.child(i), level + 1)
        root = self.invisibleRootItem()
        for i in range(root.childCount()):
            collect_items(root.child(i))
        from PySide6.QtWidgets import QApplication
        clipboard = QApplication.clipboard()
        clipboard.setText('\n'.join(details))

    def select_offset(self, offset: int, byte_source: str = 'packet'):
        best_item = None
        best_depth = -1

        def visit(item, depth=0, in_frame_section=False):
            nonlocal best_item, best_depth

            if in_frame_section:
                for i in range(item.childCount()):
                    visit(item.child(i), depth + 1, True)
                return

            data = item.data(0, Qt.ItemDataRole.UserRole)
            item_source = str(item.data(0, self.BYTE_SOURCE_ROLE) or 'packet')
            selectable = bool(item.data(0, self.BYTE_SELECTABLE_ROLE))
            if isinstance(data, tuple):
                start, length = data
                if (
                    selectable
                    and start >= 0
                    and length > 0
                    and item_source == byte_source
                    and start <= offset < start + length
                ):
                    if depth > best_depth:
                        best_item = item
                        best_depth = depth
            for i in range(item.childCount()):
                visit(item.child(i), depth + 1, in_frame_section)

        root = self.invisibleRootItem()
        for i in range(root.childCount()):
            child = root.child(i)
            top_title = child.text(0).strip().lower()
            visit(child, 0, top_title.startswith('frame'))
        if best_item:
            self.setCurrentItem(best_item)

    def show_packet(self, record):
        # Save current UI state before clearing/rebuilding.
        self._save_expand_state()
        v_scroll = self.verticalScrollBar().value()
        h_scroll = self.horizontalScrollBar().value()

        self.clear()
        if not record:
            self.item_selected.emit(-1, 0)
            self.item_bytes_selected.emit(-1, 0, 'packet')
            self.detail_field_selected.emit('', 0)
            return

        for node in packet_summary_tree(record.raw, record):
            self._add_node(self.invisibleRootItem(), node)

        self._restore_expand_state()
        self.verticalScrollBar().setValue(v_scroll)
        self.horizontalScrollBar().setValue(h_scroll)

    def _add_node(self, parent, data):
        item = QTreeWidgetItem([data['title']])
        parent_offset, parent_length = parent.data(0, Qt.ItemDataRole.UserRole) if parent is not self.invisibleRootItem() else (-1, 0)
        parent_source = parent.data(0, self.BYTE_SOURCE_ROLE) if parent is not self.invisibleRootItem() else 'packet'
        offset = int(data['offset']) if 'offset' in data else parent_offset
        length = int(data['length']) if 'length' in data else parent_length
        byte_source = str(data.get('byte_source', parent_source) or parent_source or 'packet')
        selectable = bool(data.get('selectable_bytes', False))
        if 'offset' in data and 'length' in data and offset >= 0 and length > 0:
            selectable = True
        item.setData(0, Qt.ItemDataRole.UserRole, (offset, length))
        item.setData(0, self.BYTE_SOURCE_ROLE, byte_source)
        item.setData(0, self.BYTE_SELECTABLE_ROLE, selectable)
        parent.addChild(item)

        # Default: all top-level sections collapsed unless saved state says otherwise.
        if parent is self.invisibleRootItem():
            item.setExpanded(False)

        for child in data.get('children', []):
            self._add_node(item, child)

    def _top_level_state_key(self, title: str) -> str:
        low = title.lower().strip()
        if low.startswith('frame'):
            return 'frame'
        if ',' in low:
            return low.split(',', 1)[0].strip()
        return low

    def _save_expand_state(self):
        # Save expand/collapse state by section type (top-level only).
        self._expand_state.clear()
        root = self.invisibleRootItem()
        for i in range(root.childCount()):
            item = root.child(i)
            key = self._top_level_state_key(item.text(0))
            self._expand_state[key] = item.isExpanded()

    def _restore_expand_state(self):
        # Restore expand/collapse state by section type (top-level only).
        root = self.invisibleRootItem()
        for i in range(root.childCount()):
            item = root.child(i)
            key = self._top_level_state_key(item.text(0))
            if key in self._expand_state:
                item.setExpanded(self._expand_state[key])
