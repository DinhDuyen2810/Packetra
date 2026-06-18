"""Central stylesheet for dashboard dialogs and widgets."""

from __future__ import annotations

from .theme import DashboardTheme


def dashboard_stylesheet() -> str:
    t = DashboardTheme
    return f"""
QWidget {{
    font-family: "Segoe UI", "Arial";
    font-size: 13px;
    color: {t.TEXT};
}}

QDialog {{
    background: {t.BG};
}}

QFrame#GalleryCard,
QFrame#WidgetCard,
QFrame#DashboardSurface,
QFrame#DashboardTopBar,
QFrame#PreviewSurface {{
    background: {t.SURFACE};
    border: 1px solid {t.BORDER};
    border-radius: {t.RADIUS_MD}px;
}}

QFrame#GalleryCard:hover,
QFrame#WidgetCard:hover {{
    border: 1px solid {t.BORDER_STRONG};
}}

QFrame#PreviewSurface {{
    background: {t.SURFACE_ALT};
}}

QLabel#PageTitle {{
    font-size: 18px;
    font-weight: 700;
    color: {t.TEXT};
}}

QLabel#PageSubtitle,
QLabel#MutedText {{
    font-size: 11px;
    color: {t.TEXT_MUTED};
}}

QLabel#SectionTitle {{
    font-size: 13px;
    font-weight: 700;
    color: {t.TEXT};
}}

QPushButton {{
    background: {t.SURFACE};
    color: {t.TEXT};
    border: 1px solid {t.BORDER_STRONG};
    border-radius: {t.RADIUS_SM}px;
    padding: 4px 10px;
    min-height: 22px;
}}

QPushButton:hover {{
    background: #F3F4F6;
}}

QPushButton#PrimaryButton {{
    background: {t.PRIMARY};
    color: white;
    border: none;
    font-weight: 600;
}}

QPushButton#PrimaryButton:hover {{
    background: {t.PRIMARY_HOVER};
}}

QPushButton#CardMoreButton {{
    padding: 0px;
    min-height: 0px;
    min-width: 0px;
    font-size: 14px;
    font-weight: 700;
    border: none;
    background: transparent;
    border-radius: 0px;
    color: {t.TEXT_MUTED};
}}

QPushButton#CardMoreButton:hover {{
    border: none;
    background: transparent;
    color: {t.TEXT};
}}

QPushButton#CardMoreButton:pressed {{
    border: none;
    background: transparent;
}}

QPushButton#DangerButton {{
    color: {t.DANGER};
    border: 1px solid #FCA5A5;
    background: {t.SURFACE};
}}

QPushButton#DangerButton:hover {{
    background: #FEF2F2;
}}

QLineEdit,
QComboBox,
QTextEdit,
QSpinBox,
QListWidget,
QTableWidget,
QTabWidget::pane {{
    background: {t.SURFACE};
    color: {t.TEXT};
    border: 1px solid {t.BORDER_STRONG};
    border-radius: {t.RADIUS_SM}px;
}}

QLineEdit,
QComboBox,
QSpinBox {{
    padding: 3px 8px;
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
}}

QLineEdit:focus,
QComboBox:focus,
QTextEdit:focus,
QSpinBox:focus {{
    border: 1px solid {t.PRIMARY};
}}

QScrollArea {{
    border: none;
    background: transparent;
}}

QHeaderView::section {{
    background: {t.SURFACE_ALT};
    color: #374151;
    border: none;
    border-bottom: 1px solid {t.BORDER};
    padding: 6px 8px;
    font-weight: 600;
}}

QTableWidget {{
    gridline-color: {t.BORDER};
    selection-background-color: {t.PRIMARY_SOFT};
    selection-color: {t.TEXT};
}}
"""


def apply_dashboard_theme(widget) -> None:
    if widget is None:
        return
    widget.setStyleSheet(dashboard_stylesheet())
