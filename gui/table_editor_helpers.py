from __future__ import annotations

from collections.abc import Callable, Iterable

from PySide6.QtCore import QSize, Qt, QTimer
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QFrame,
    QHeaderView,
    QLineEdit,
    QSpinBox,
    QStyledItemDelegate,
    QTableWidget,
    QWidget,
)


DEFAULT_ROW_HEIGHT = 24
DEFAULT_EDITOR_MARGIN = 1
COMPACT_EDITOR_STYLE = (
    'padding: 0px 2px; margin: 0px; border-radius: 0px;'
)
def _overlay_combo_style(target_height: int) -> str:
    content_height = max(16, int(target_height) - 2)
    return (
        'QComboBox {'
        ' margin: 0px;'
        ' padding: 0px 2px;'
        ' border-radius: 0px;'
        f' min-height: {content_height}px;'
        f' max-height: {content_height}px;'
        '}'
        'QComboBox::drop-down {'
        ' border: 0px;'
        ' width: 18px;'
        '}'
        'QComboBox::down-arrow {'
        ' subcontrol-origin: padding;'
        '}'
    )
COMPACT_TABLE_STYLE = (
    'QTableWidget { border: none; gridline-color: transparent; } '
    'QTableWidget::item { height: 24px; }'
)


class _CompactEditorMixin:
    def _compact_height(self) -> int:
        try:
            return max(18, int(self.property('_compact_height') or DEFAULT_ROW_HEIGHT))
        except Exception:
            return DEFAULT_ROW_HEIGHT

    def minimumSizeHint(self):
        hint = super().minimumSizeHint()
        hint.setHeight(self._compact_height())
        return hint

    def sizeHint(self):
        hint = super().sizeHint()
        hint.setHeight(self._compact_height())
        return hint


class CompactLineEdit(_CompactEditorMixin, QLineEdit):
    pass


class AutoPopupComboBox(QComboBox):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._did_auto_popup = False

    def focusInEvent(self, event) -> None:
        super().focusInEvent(event)
        if not self._did_auto_popup:
            self._did_auto_popup = True
            QTimer.singleShot(0, self.showPopup)


class CompactSpinBox(_CompactEditorMixin, QSpinBox):
    pass


def _editor_height_for_rect(rect_height: int) -> int:
    return max(18, int(rect_height or DEFAULT_ROW_HEIGHT))


def _style_editor_widget(editor: QWidget, rect_height: int) -> QWidget:
    editor.setAutoFillBackground(True)
    editor.setContentsMargins(0, 0, 0, 0)
    target_height = _editor_height_for_rect(rect_height)
    editor.setMinimumHeight(target_height)
    editor.setMaximumHeight(target_height)
    editor.resize(editor.width(), target_height)
    if isinstance(editor, (CompactLineEdit, CompactSpinBox)):
        editor.setProperty('_compact_height', target_height)
        editor.setStyleSheet(COMPACT_EDITOR_STYLE)
    if isinstance(editor, QComboBox):
        editor.setMaxVisibleItems(12)
    elif hasattr(editor, 'setFrame'):
        try:
            editor.setFrame(False)
        except Exception:
            pass
    return editor


def apply_input_like_table_style(
    table: QTableWidget,
    *,
    stretch_column: int | None = None,
    resize_mode=QHeaderView.ResizeMode.ResizeToContents,
    editable: bool = True,
    row_height: int = DEFAULT_ROW_HEIGHT,
) -> QTableWidget:
    table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    table.setEditTriggers(
        QAbstractItemView.EditTrigger.DoubleClicked
        | QAbstractItemView.EditTrigger.EditKeyPressed
        | QAbstractItemView.EditTrigger.SelectedClicked
        if editable
        else QAbstractItemView.EditTrigger.NoEditTriggers
    )
    table.setAlternatingRowColors(True)
    table.setWordWrap(False)
    table.setShowGrid(False)
    table.setFrameShape(QFrame.Shape.NoFrame)
    table.setStyleSheet(COMPACT_TABLE_STYLE)
    vertical = table.verticalHeader()
    vertical.setVisible(False)
    vertical.setDefaultSectionSize(int(row_height))
    vertical.setMinimumSectionSize(int(row_height))
    header = table.horizontalHeader()
    for column in range(int(table.columnCount() or 0)):
        mode = QHeaderView.ResizeMode.Stretch if stretch_column == column else resize_mode
        header.setSectionResizeMode(column, mode)
    return table


class FixedHeightDelegate(QStyledItemDelegate):
    def sizeHint(self, option, index):
        hint = super().sizeHint(option, index)
        hint.setHeight(max(DEFAULT_ROW_HEIGHT, hint.height()))
        return hint

    def updateEditorGeometry(self, editor: QWidget, option, index) -> None:
        rect = option.rect.adjusted(DEFAULT_EDITOR_MARGIN, 0, -DEFAULT_EDITOR_MARGIN, 0)
        _style_editor_widget(editor, rect.height())
        editor.setGeometry(rect.x(), rect.y(), rect.width(), rect.height())


class LineEditDelegate(FixedHeightDelegate):
    def createEditor(self, parent, option, index):
        editor = CompactLineEdit(parent)
        return _style_editor_widget(editor, option.rect.height())

    def setEditorData(self, editor, index) -> None:
        editor.setText(str(index.data(Qt.ItemDataRole.DisplayRole) or ''))
        editor.selectAll()

    def setModelData(self, editor, model, index) -> None:
        value = editor.text()
        model.setData(index, value, Qt.ItemDataRole.DisplayRole)
        model.setData(index, value, Qt.ItemDataRole.UserRole)


class PasswordLineEditDelegate(LineEditDelegate):
    def createEditor(self, parent, option, index):
        editor = super().createEditor(parent, option, index)
        editor.setEchoMode(QLineEdit.EchoMode.Password)
        return editor

    def setEditorData(self, editor, index) -> None:
        value = str(index.data(Qt.ItemDataRole.UserRole) or '')
        editor.setText(value)
        editor.selectAll()

    def setModelData(self, editor, model, index) -> None:
        password = editor.text()
        model.setData(index, password, Qt.ItemDataRole.UserRole)
        model.setData(index, '*' * len(password), Qt.ItemDataRole.DisplayRole)


class ComboBoxDelegate(FixedHeightDelegate):
    def __init__(self, values: Iterable[str] | Callable[[object], Iterable[str]], parent=None):
        super().__init__(parent)
        self._values = values

    def _resolved_values(self, index) -> list[str]:
        values = self._values(index) if callable(self._values) else self._values
        return [str(value) for value in values]

    def createEditor(self, parent, option, index):
        editor = AutoPopupComboBox(parent)
        editor.addItems(self._resolved_values(index))
        return _style_editor_widget(editor, option.rect.height())

    def setEditorData(self, editor, index) -> None:
        current = str(index.data(Qt.ItemDataRole.DisplayRole) or '')
        current = current.strip()
        if current:
            combo_index = editor.findText(current, Qt.MatchFlag.MatchFixedString)
            if combo_index >= 0:
                editor.setCurrentIndex(combo_index)

    def setModelData(self, editor, model, index) -> None:
        value = editor.currentText()
        model.setData(index, value, Qt.ItemDataRole.DisplayRole)
        model.setData(index, value, Qt.ItemDataRole.UserRole)


class SpinBoxDelegate(FixedHeightDelegate):
    def __init__(self, minimum: int, maximum: int, *, special_text: str | None = None, parent=None):
        super().__init__(parent)
        self._minimum = int(minimum)
        self._maximum = int(maximum)
        self._special_text = str(special_text) if special_text is not None else None

    def createEditor(self, parent, option, index):
        editor = CompactSpinBox(parent)
        editor.setRange(self._minimum, self._maximum)
        if self._special_text:
            editor.setSpecialValueText(self._special_text)
        return _style_editor_widget(editor, option.rect.height())

    def setEditorData(self, editor, index) -> None:
        raw_value = index.data(Qt.ItemDataRole.UserRole)
        if raw_value is None:
            display = str(index.data(Qt.ItemDataRole.DisplayRole) or '').strip().lower()
            if self._special_text and display == self._special_text.strip().lower():
                raw_value = self._maximum
            else:
                try:
                    raw_value = int(display or self._minimum)
                except Exception:
                    raw_value = self._minimum
        editor.setValue(int(raw_value))
        editor.selectAll()

    def setModelData(self, editor, model, index) -> None:
        value = int(editor.value())
        model.setData(index, value, Qt.ItemDataRole.UserRole)
        if self._special_text and value == self._maximum:
            model.setData(index, self._special_text, Qt.ItemDataRole.DisplayRole)
        else:
            model.setData(index, str(value), Qt.ItemDataRole.DisplayRole)


def show_overlay_combo_editor(
    host_view: QWidget,
    cell_rect,
    values: Iterable[str],
    current_text: str,
    on_commit: Callable[[str], None],
) -> QComboBox:
    viewport = host_view.viewport() if hasattr(host_view, 'viewport') else host_view
    existing = viewport.property('_overlay_combo_editor')
    if isinstance(existing, QComboBox):
        try:
            existing.hide()
            existing.deleteLater()
        except RuntimeError:
            pass

    target_rect = cell_rect.adjusted(0, 0, -1, -1)
    if target_rect.width() <= 0 or target_rect.height() <= 0:
        target_rect = cell_rect

    combo = QComboBox(viewport)
    combo.addItems([str(value) for value in values])
    combo.setMaxVisibleItems(12)
    combo.setGeometry(target_rect)
    combo.setFixedSize(target_rect.size())
    combo.setStyleSheet(_overlay_combo_style(target_rect.height()))
    combo.setCurrentText(str(current_text or ''))
    popup_view = combo.view()
    popup_view.setMinimumWidth(max(combo.width(), int(target_rect.width())))
    row_hint = max(22, popup_view.sizeHintForRow(0) if combo.count() > 0 else 22)
    popup_view.setMinimumHeight(min(max(120, row_hint * min(combo.count(), 6)), 260))
    viewport.setProperty('_overlay_combo_editor', combo)

    def _finish(*_args):
        text = combo.currentText()
        try:
            on_commit(text)
        finally:
            if viewport.property('_overlay_combo_editor') is combo:
                viewport.setProperty('_overlay_combo_editor', None)
            combo.hide()
            combo.deleteLater()

    combo.activated.connect(lambda _index: _finish())
    combo.textActivated.connect(_finish)
    combo.show()
    combo.setFocus(Qt.FocusReason.MouseFocusReason)
    QTimer.singleShot(120, combo.showPopup)
    return combo
