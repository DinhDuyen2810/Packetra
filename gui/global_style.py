"""Shared application stylesheet to align the main GUI with the dashboard visual language."""

from __future__ import annotations

from PySide6.QtCore import QEvent, QObject, Qt
from PySide6.QtWidgets import QApplication, QMenu, QWidget

from gui.dashboard.ui.theme import DashboardTheme


class _RoundedPopupFilter(QObject):
    def eventFilter(self, obj, event):
        if event is None:
            return super().eventFilter(obj, event)
        ev_type = event.type()
        if isinstance(obj, QMenu) and ev_type in {
            QEvent.Type.Polish,
            QEvent.Type.Show,
            QEvent.Type.Resize,
        }:
            _prepare_rounded_popup(obj)
        elif ev_type == QEvent.Type.Polish and isinstance(obj, QWidget):
            try:
                class_name = obj.metaObject().className()
                if class_name == 'QTipLabel':
                    _apply_tooltip_mask(obj)
                elif class_name == 'QComboBoxPrivateContainer' or obj.inherits('QComboBoxPrivateContainer'):
                    # ComboBox drop-down popup needs the same translucency fix to avoid black corners
                    _apply_tooltip_mask(obj)
            except Exception:
                pass
        return super().eventFilter(obj, event)


_rounded_popup_filter: _RoundedPopupFilter | None = None


def _apply_tooltip_mask(widget: QWidget) -> None:
    """Apply rounded-corner styling to QTipLabel (Qt's internal tooltip widget).
    Using WA_NoSystemBackground=True prevents Windows from painting an opaque
    background before QSS, which was causing the black-corner artifact.
    """
    widget.setWindowFlag(Qt.WindowType.FramelessWindowHint, True)
    widget.setWindowFlag(Qt.WindowType.NoDropShadowWindowHint, True)
    widget.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)
    widget.setAttribute(Qt.WidgetAttribute.WA_NoSystemBackground, True)
    widget.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)


def _prepare_rounded_popup(widget: QWidget) -> None:
    if widget is None:
        return
    widget.setWindowFlag(Qt.WindowType.NoDropShadowWindowHint, True)
    widget.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)
    widget.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
    widget.setAttribute(Qt.WidgetAttribute.WA_NoSystemBackground, False)
    widget.clearMask()


def application_stylesheet() -> str:
    t = DashboardTheme
    return f"""
QWidget {{
    color: {t.TEXT};
}}

QLabel#PageTitle,
QLabel#HeroTitle {{
    font-size: 20px;
    font-weight: 700;
    color: {t.TEXT};
}}

QLabel#SectionTitle,
QLabel#SectionHeading {{
    font-size: 13px;
    font-weight: 700;
    color: {t.TEXT};
}}

QLabel#PageSubtitle,
QLabel#MutedText,
QLabel#MutedHint {{
    font-size: 11px;
    color: {t.TEXT_MUTED};
}}

QMainWindow,
QDialog {{
    background: {t.BG};
}}

QMenuBar,
QToolBar,
QStatusBar {{
    background: {t.SURFACE};
}}

QMenuBar {{
    border-bottom: 1px solid {t.BORDER};
}}

QMenuBar::item {{
    padding: 4px 8px;
    margin: 2px 2px;
    border-radius: {t.RADIUS_SM}px;
    background: transparent;
}}

QMenuBar::item:selected,
QMenuBar::item:pressed {{
    background: {t.PRIMARY_SOFT};
}}

QMenu {{
    background: {t.SURFACE};
    border: 1px solid {t.BORDER};
    border-radius: {t.RADIUS_MD}px;
    padding: 4px;
    margin: 0px;
}}

QMenu::item {{
    padding: 6px 12px;
    border-radius: {t.RADIUS_SM}px;
}}

QMenu::item:selected {{
    background: {t.PRIMARY_SOFT};
    color: {t.TEXT};
}}

QComboBox QAbstractItemView {{
    background: {t.SURFACE};
    border: 1px solid {t.BORDER};
    border-radius: {t.RADIUS_MD}px;
    outline: 0;
    padding: 4px;
    selection-background-color: {t.PRIMARY_SOFT};
    selection-color: {t.TEXT};
}}

QToolBar {{
    border: none;
    border-bottom: 1px solid {t.BORDER};
    spacing: 0px;
    padding: 2px 4px;
}}

QStatusBar {{
    border-top: 1px solid {t.BORDER};
}}

QStatusBar::item {{
    border: none;
}}

QPushButton,
QToolButton {{
    background: {t.SURFACE};
    color: {t.TEXT};
    border: 1px solid {t.BORDER_STRONG};
    border-radius: {t.RADIUS_SM}px;
    padding: 4px 10px;
}}

QPushButton:hover,
QToolButton:hover {{
    background: #F3F4F6;
    border-color: {t.BORDER_STRONG};
}}

QPushButton:pressed,
QToolButton:pressed {{
    background: #E5EEFf;
}}

QToolBar QToolButton {{
    background: transparent;
    border: 1px solid transparent;
    padding: 2px;
    margin: 0px;
    min-width: 26px;
    min-height: 26px;
    border-radius: {t.RADIUS_SM}px;
}}

QStatusBar QToolButton {{
    border: 1px solid transparent;
    background: transparent;
    padding: 1px;
    margin: 0px 1px;
    min-width: 0px;
    min-height: 0px;
    border-radius: {t.RADIUS_SM}px;
}}

QToolBar QToolButton:hover,
QStatusBar QToolButton:hover {{
    background: #F3F4F6;
    border: 1px solid {t.BORDER_STRONG};
}}

QToolBar QToolButton:pressed,
QStatusBar QToolButton:pressed {{
    background: #E5EEFf;
    border: 1px solid {t.BORDER_STRONG};
}}

QToolBar QToolButton:checked,
QStatusBar QToolButton:checked {{
    background: #E5E7EB;
    border: 1px solid {t.BORDER_STRONG};
}}

QToolBar QToolButton:checked:hover,
QStatusBar QToolButton:checked:hover {{
    background: #D1D5DB;
    border: 1px solid {t.BORDER_STRONG};
}}

QToolBar::separator {{
    width: 1px;
    margin: 3px 8px;
    border-left: 1px solid {t.BORDER_STRONG};
    background: transparent;
}}

QLineEdit#FilterBarInput {{
    min-height: 22px;
    padding: 1px 7px;
    border-radius: {t.RADIUS_SM}px;
}}

QToolButton#FilterApplyButton,
QPushButton#FilterApplyButton,
QToolButton#FilterClearButton,
QPushButton#FilterClearButton {{
    padding: 0px;
    min-width: 40px;
    max-width: 40px;
    min-height: 26px;
    max-height: 26px;
    border-radius: {t.RADIUS_SM}px;
    font-weight: 700;
}}

QToolButton#FilterApplyButton,
QPushButton#FilterApplyButton {{
    font-size: 17px;
}}

QToolButton#FilterClearButton,
QPushButton#FilterClearButton {{
    font-size: 15px;
    padding-top: 0px;
    padding-bottom: 1px;
}}

QTabBar#PacketBytesTabBar {{
    background: transparent;
}}

QTabBar#PacketBytesTabBar::tab {{
    padding: 3px 10px;
    min-height: 18px;
    background: {t.SURFACE};
    border: 1px solid {t.BORDER};
    border-radius: {t.RADIUS_SM}px;
    margin-right: 4px;
    color: {t.TEXT_MUTED};
}}

QTabBar#PacketBytesTabBar::tab:selected {{
    color: {t.PRIMARY};
    font-weight: bold;
    background: {t.PRIMARY_SOFT};
    border-color: {t.PRIMARY};
}}

QLineEdit,
QTextEdit,
QPlainTextEdit,
QSpinBox,
QAbstractSpinBox,
QComboBox,
QListWidget,
QTreeWidget,
QTableWidget,
QTextBrowser,
QTabWidget::pane {{
    background: {t.SURFACE};
    color: {t.TEXT};
    border: 1px solid {t.BORDER};
    border-radius: {t.RADIUS_MD}px;
}}

QGroupBox {{
    background: {t.SURFACE};
    color: {t.TEXT};
    border: 1px solid {t.BORDER};
    border-radius: {t.RADIUS_MD}px;
    margin-top: 12px;
    padding: 10px 12px 12px 12px;
}}

QGroupBox::title {{
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: 12px;
    top: -1px;
    padding: 0px 6px;
    background: {t.SURFACE};
    color: {t.TEXT};
}}

QLineEdit,
QTextEdit,
QPlainTextEdit,
QSpinBox,
QAbstractSpinBox,
QComboBox {{
    padding: 3px 8px;
}}

QComboBox,
QSpinBox,
QAbstractSpinBox {{
    min-height: 24px;
}}

QComboBox {{
    padding-right: 22px;
}}

QComboBox::drop-down {{
    subcontrol-origin: padding;
    subcontrol-position: top right;
    width: 18px;
    border: none;
    background: transparent;
}}

QComboBox::down-arrow {{
    width: 9px;
    height: 9px;
    border: none;
    background: transparent;
}}

QSpinBox,
QAbstractSpinBox {{
    padding-right: 20px;
}}

QSpinBox::up-button,
QSpinBox::down-button,
QAbstractSpinBox::up-button,
QAbstractSpinBox::down-button {{
    subcontrol-origin: border;
    width: 16px;
    border: none;
    background: transparent;
}}

QSpinBox::up-button {{
    subcontrol-position: top right;
}}

QSpinBox::down-button {{
    subcontrol-position: bottom right;
}}

QAbstractSpinBox::up-button {{
    subcontrol-position: top right;
}}

QAbstractSpinBox::down-button {{
    subcontrol-position: bottom right;
}}

QSpinBox::up-arrow,
QSpinBox::down-arrow,
QAbstractSpinBox::up-arrow,
QAbstractSpinBox::down-arrow {{
    width: 8px;
    height: 8px;
    border: none;
    background: transparent;
}}

QComboBox:disabled,
QSpinBox:disabled,
QAbstractSpinBox:disabled,
QLineEdit:disabled {{
    background: #F5F7FA;
    color: {t.TEXT_MUTED};
    border-color: #D7DDE6;
}}

QLineEdit:focus,
QTextEdit:focus,
QPlainTextEdit:focus,
QSpinBox:focus,
QAbstractSpinBox:focus,
QComboBox:focus,
QListWidget:focus,
QTreeWidget:focus,
QTableWidget:focus,
QTextBrowser:focus {{
    border: 1px solid {t.PRIMARY};
}}

QHeaderView::section {{
    background: {t.SURFACE_ALT};
    color: {t.TEXT};
    border: none;
    border-bottom: 1px solid {t.BORDER};
    padding: 6px 8px;
    font-weight: 600;
}}

QTabBar::tab {{
    background: {t.SURFACE};
    border: 1px solid {t.BORDER};
    border-bottom-color: {t.BORDER};
    border-top-left-radius: {t.RADIUS_SM}px;
    border-top-right-radius: {t.RADIUS_SM}px;
    padding: 6px 12px;
    margin-right: 2px;
}}

QTabBar::tab:selected {{
    background: {t.SURFACE_ALT};
    border-color: {t.BORDER_STRONG};
}}

QTabBar::tab:!selected {{
    margin-top: 2px;
}}

QScrollArea {{
    border: none;
    background: transparent;
}}

QTreeView,
QTableView {{
    alternate-background-color: {t.SURFACE_ALT};
    selection-background-color: {t.PRIMARY_SOFT};
    selection-color: {t.TEXT};
}}

QSplitter::handle {{
    background: {t.BORDER};
}}

QToolTip {{
    background: {t.SURFACE};
    color: {t.TEXT};
    border: 1px solid {t.BORDER};
    border-radius: {t.RADIUS_SM}px;
    padding: 4px 8px;
    font-size: 12px;
}}
"""


def apply_application_theme(widget) -> None:
    if widget is None:
        return
    global _rounded_popup_filter
    widget.setStyleSheet(application_stylesheet())
    app = QApplication.instance()
    if app is not None and _rounded_popup_filter is None:
        _rounded_popup_filter = _RoundedPopupFilter(app)
        app.installEventFilter(_rounded_popup_filter)
    if isinstance(widget, QWidget):
        for menu in widget.findChildren(QMenu):
            _prepare_rounded_popup(menu)
