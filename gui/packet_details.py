from PySide6.QtCore import Qt, Signal, QSignalBlocker
from PySide6.QtGui import QFont
from PySide6.QtWidgets import QApplication, QTreeWidget, QTreeWidgetItem

from core.formatters import packet_summary_tree


class PacketDetailsTree(QTreeWidget):
    item_selected = Signal(int, int)  # offset, length
    item_bytes_selected = Signal(int, int, str)  # offset, length, byte_source
    detail_field_selected = Signal(str, int)  # field name, byte count
    context_menu_requested = Signal(object, object)
    BYTE_SOURCE_ROLE = int(Qt.ItemDataRole.UserRole) + 1
    BYTE_SELECTABLE_ROLE = int(Qt.ItemDataRole.UserRole) + 2

    def __init__(self):
        super().__init__()
        # Hide header entirely to avoid empty top row.
        self.setHeaderHidden(True)
        self.setUniformRowHeights(True)
        self.setIndentation(18)
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self._on_custom_context_menu)
        self.itemSelectionChanged.connect(self._on_selection_changed)
        # Persistent expand state by normalized tree path.
        self._expand_state = {}
        self._show_item_tooltips = False

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
        if ',' in text:
            text = text.split(',', 1)[0].strip()
        if ': ' in text:
            text = text.split(': ', 1)[0].strip()
        elif text.endswith(':'):
            text = text[:-1].strip()
        text = ' '.join(text.split())
        if len(text) > 140:
            text = text[:137].rstrip() + '...'
        return text

    def _on_custom_context_menu(self, position):
        item = self.itemAt(position)
        if item is None:
            return
        self.context_menu_requested.emit(item, self.viewport().mapToGlobal(position))

    def _collect_text_lines(self, root_item, visible_only: bool, include_root: bool = True, level: int = 0):
        lines = []
        if include_root:
            lines.append(('  ' * level) + root_item.text(0))
        if visible_only and not root_item.isExpanded():
            return lines
        next_level = level + (1 if include_root else 0)
        for i in range(root_item.childCount()):
            child = root_item.child(i)
            lines.extend(self._collect_text_lines(child, visible_only, True, next_level))
        return lines

    def copy_all_items(self) -> bool:
        lines = []
        root = self.invisibleRootItem()
        for i in range(root.childCount()):
            lines.extend(self._collect_text_lines(root.child(i), visible_only=False, include_root=True, level=0))
        if not lines:
            return False
        QApplication.clipboard().setText('\n'.join(lines))
        return True

    def copy_visible_items(self) -> bool:
        lines = []
        root = self.invisibleRootItem()
        for i in range(root.childCount()):
            lines.extend(self._collect_text_lines(root.child(i), visible_only=True, include_root=True, level=0))
        if not lines:
            return False
        QApplication.clipboard().setText('\n'.join(lines))
        return True

    def copy_visible_selected_subtree(self, item: QTreeWidgetItem | None = None) -> bool:
        target = item
        if target is None:
            selected = self.selectedItems()
            target = selected[0] if selected else None
        if target is None:
            return False
        lines = self._collect_text_lines(target, visible_only=True, include_root=True, level=0)
        if not lines:
            return False
        QApplication.clipboard().setText('\n'.join(lines))
        return True

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
        self.setUpdatesEnabled(False)
        try:
            with QSignalBlocker(self):
                self.clear()
                if not record:
                    self.item_selected.emit(-1, 0)
                    self.item_bytes_selected.emit(-1, 0, 'packet')
                    self.detail_field_selected.emit('', 0)
                    return

                metadata = getattr(record, 'metadata', {}) if record else {}
                cached_tree = metadata.get('_detail_tree_cache', None) if isinstance(metadata, dict) else None
                if not isinstance(cached_tree, list):
                    cached_tree = packet_summary_tree(record.raw, record)
                    if isinstance(metadata, dict):
                        metadata['_detail_tree_cache'] = cached_tree

                packet_comment = str(getattr(record, 'packet_comment', '') or '').strip()
                if packet_comment:
                    comment_lines = packet_comment.replace('\r\n', '\n').replace('\r', '\n').split('\n')
                    if not comment_lines:
                        comment_lines = [packet_comment]
                    comment_children = []
                    for line in comment_lines:
                        comment_children.append({'title': line})
                    comment_node = {
                        'title': 'Packet Comment',
                        'children': comment_children,
                    }
                    self._add_node(self.invisibleRootItem(), comment_node)

                for node in cached_tree:
                    self._add_node(self.invisibleRootItem(), node)

                self._restore_expand_state()
                self.verticalScrollBar().setValue(v_scroll)
                self.horizontalScrollBar().setValue(h_scroll)
        finally:
            self.setUpdatesEnabled(True)

    def _add_node(self, parent, data):
        title = str(data.get('title', '') or '')
        item = QTreeWidgetItem([title])
        if self._show_item_tooltips:
            item.setToolTip(0, title)
        parent_source = parent.data(0, self.BYTE_SOURCE_ROLE) if parent is not self.invisibleRootItem() else 'packet'
        offset = int(data['offset']) if 'offset' in data else -1
        length = int(data['length']) if 'length' in data else 0
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

    def _normalize_state_title(self, title: str) -> str:
        text = str(title or '').strip().lower()
        if not text:
            return ''
        if text.startswith('frame'):
            return 'frame'
        if ' = ' in text:
            text = text.split(' = ', 1)[1].strip()
        if ':' in text:
            text = text.split(':', 1)[0].strip()
        if ',' in text:
            text = text.split(',', 1)[0].strip()
        return text

    def _item_state_key(self, item: QTreeWidgetItem) -> str:
        parts = []
        node = item
        while node is not None and node is not self.invisibleRootItem():
            parts.append(self._normalize_state_title(node.text(0)))
            node = node.parent()
        parts.reverse()
        return '/'.join(part for part in parts if part)

    def _save_expand_state(self):
        # Save expand/collapse state recursively by normalized path.
        state: dict[str, bool] = {}

        def walk(item: QTreeWidgetItem):
            key = self._item_state_key(item)
            if key and not key.startswith('packet comment'):
                state[key] = bool(item.isExpanded())
            for idx in range(item.childCount()):
                walk(item.child(idx))

        root = self.invisibleRootItem()
        for i in range(root.childCount()):
            walk(root.child(i))
        self._expand_state = state

    def _restore_expand_state(self):
        # Restore expand/collapse state recursively by normalized path.
        def walk(item: QTreeWidgetItem):
            key = self._item_state_key(item)
            if key.startswith('packet comment'):
                item.setExpanded(False)
            elif key in self._expand_state:
                item.setExpanded(bool(self._expand_state.get(key)))
            for idx in range(item.childCount()):
                walk(item.child(idx))

        root = self.invisibleRootItem()
        for i in range(root.childCount()):
            walk(root.child(i))
