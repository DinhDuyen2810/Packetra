"""
Dashboard Editor UI.

Allows editing dashboard layout, widgets, queries, and visualizations.
"""

from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QWidget, QScrollArea, QGridLayout,
    QPushButton, QLabel, QMessageBox, QToolBar, QComboBox, QLineEdit,
    QMenu, QFrame, QSplitter, QApplication, QSizePolicy, QCheckBox,
    QDialogButtonBox, QFormLayout, QSpinBox
)
from PySide6.QtCore import Qt, Signal, QSize, QPoint, QRect, QTimer, QMimeData
from PySide6.QtGui import QIcon, QFont, QCursor, QPixmap, QPainter, QColor
from typing import Optional, List, Dict, Callable
from uuid import uuid4
from datetime import datetime

from .models import (
    Dashboard, DashboardWidget, WidgetQuery, VisualizationConfig,
    WidgetLayout, DashboardLayout, QueryMetric, QuerySort
)
from .repository import DashboardRepository


def _apply_fixed_screen_size(dialog: QDialog):
    screen = QApplication.primaryScreen()
    if screen is None:
        return
    available = screen.availableGeometry()
    width = int(available.width() * 0.9)
    height = int(available.height() * 0.9)
    dialog.setFixedSize(width, height)
    dialog.move(
        available.x() + ((available.width() - width) // 2),
        available.y() + ((available.height() - height) // 2),
    )


class TemplatePreviewCard(QFrame):
    """Selectable card used in the Add Widget chart picker."""

    selected = Signal(str)

    def __init__(self, dashboard: Dashboard, preview_widget: Optional[QWidget] = None, parent=None):
        super().__init__(parent)
        self.dashboard = dashboard
        self.preview_widget = preview_widget
        self.setup_ui()

    def setup_ui(self):
        self.setFrameShape(QFrame.Box)
        self.setFrameShadow(QFrame.Raised)
        self.setStyleSheet(
            "TemplatePreviewCard {"
            "background-color: #f8f8f8;"
            "border: 1px solid #d9d9d9;"
            "border-radius: 6px;"
            "padding: 8px;"
            "}"
            "TemplatePreviewCard:hover {"
            "border: 1px solid #0066cc;"
            "background-color: #fbfdff;"
            "}"
        )

        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(6)

        title_label = QLabel(self.dashboard.name)
        title_font = QFont()
        title_font.setBold(True)
        title_font.setPointSize(11)
        title_label.setFont(title_font)
        layout.addWidget(title_label)

        description_label = QLabel(self.dashboard.description or "")
        description_label.setWordWrap(True)
        description_label.setStyleSheet("color: #666; font-size: 9pt;")
        layout.addWidget(description_label)

        preview_frame = QFrame()
        preview_frame.setStyleSheet("background-color: #ffffff; border: 1px solid #ddd; border-radius: 4px;")
        preview_layout = QVBoxLayout(preview_frame)
        preview_layout.setContentsMargins(6, 6, 6, 6)
        if self.preview_widget is not None:
            self.preview_widget.setParent(preview_frame)
            preview_layout.addWidget(self.preview_widget)
        else:
            placeholder = QLabel("Preview unavailable")
            placeholder.setAlignment(Qt.AlignCenter)
            placeholder.setStyleSheet("color: #999; font-size: 10pt;")
            preview_layout.addWidget(placeholder)
        layout.addWidget(preview_frame)

        type_label = QLabel(f"Type: {self.dashboard.widgets[0].visualization.type if self.dashboard.widgets else 'unknown'}")
        type_label.setStyleSheet("color: #888; font-size: 9pt;")
        layout.addWidget(type_label)

    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.selected.emit(self.dashboard.dashboard_id)
        super().mousePressEvent(event)


class ChartTemplatePickerDialog(QDialog):
    """Dialog that lets users choose a chart template using live previews."""

    def __init__(self, chart_templates: List[Dashboard], query_engine=None, viz_registry=None, parent=None):
        super().__init__(parent)
        self.chart_templates = chart_templates
        self.query_engine = query_engine
        self.viz_registry = viz_registry
        self.selected_template_id: Optional[str] = None
        self.blank_requested = False
        self.setWindowTitle("Add Chart Widget")
        self.setup_ui()
        _apply_fixed_screen_size(self)

    def _preview_config(self, widget_model) -> Dict[str, object]:
        visualization = widget_model.visualization
        return {
            "type": visualization.type,
            "xField": visualization.x_field,
            "yField": visualization.y_field,
            "categoryField": visualization.category_field,
            "valueField": visualization.value_field,
            "seriesField": visualization.series_field,
            "showLegend": False,
            "showLabels": False,
            "compactMode": True,
        }

    def _make_preview_pass_through(self, widget: QWidget):
        widget.setAttribute(Qt.WA_TransparentForMouseEvents, True)
        for child in widget.findChildren(QWidget):
            child.setAttribute(Qt.WA_TransparentForMouseEvents, True)

    def _create_preview_widget(self, dashboard: Dashboard) -> Optional[QWidget]:
        if not dashboard.widgets or not self.query_engine or not self.viz_registry:
            return None

        widget_model = dashboard.widgets[0]
        try:
            data = self.query_engine.execute(
                data_source=widget_model.data_source,
                query=widget_model.query,
                global_filter=None,
            )
            renderer = self.viz_registry.get_renderer(widget_model.visualization.type)
            if renderer is None:
                return None
            preview = renderer(data, self._preview_config(widget_model), None)
            preview.setMinimumHeight(180)
            preview.setMaximumHeight(180)
            preview.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
            self._make_preview_pass_through(preview)
            return preview
        except Exception:
            return None

    def setup_ui(self):
        main_layout = QVBoxLayout(self)

        header_layout = QHBoxLayout()
        title_label = QLabel("Choose a chart to add")
        title_font = QFont()
        title_font.setPointSize(13)
        title_font.setBold(True)
        title_label.setFont(title_font)
        header_layout.addWidget(title_label)
        header_layout.addStretch()

        blank_button = QPushButton("Blank Widget")
        blank_button.clicked.connect(self.on_blank_requested)
        header_layout.addWidget(blank_button)

        cancel_button = QPushButton("Cancel")
        cancel_button.clicked.connect(self.reject)
        header_layout.addWidget(cancel_button)

        main_layout.addLayout(header_layout)

        info_label = QLabel("Click a chart to add it immediately to the dashboard.")
        info_label.setStyleSheet("color: #666; font-size: 10pt;")
        main_layout.addWidget(info_label)

        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)

        content_widget = QWidget()
        content_layout = QGridLayout(content_widget)
        content_layout.setSpacing(12)

        if not self.chart_templates:
            empty_label = QLabel("No chart templates available")
            empty_label.setStyleSheet("color: #999;")
            content_layout.addWidget(empty_label, 0, 0)
        else:
            for index, dashboard in enumerate(self.chart_templates):
                card = TemplatePreviewCard(
                    dashboard,
                    preview_widget=self._create_preview_widget(dashboard),
                    parent=content_widget,
                )
                card.selected.connect(self.on_template_selected)
                row = index // 3
                col = index % 3
                content_layout.addWidget(card, row, col)

            for column in range(3):
                content_layout.setColumnStretch(column, 1)

        scroll_area.setWidget(content_widget)
        main_layout.addWidget(scroll_area)

    def on_blank_requested(self):
        self.blank_requested = True
        self.accept()

    def on_template_selected(self, template_id: str):
        self.selected_template_id = template_id
        self.accept()


class WidgetEditorDialog(QDialog):
    """Small, usable widget editor for dashboard widgets."""

    def __init__(self, widget_model: DashboardWidget, available_sources: List[str], available_visualizations: List[str], parent=None):
        super().__init__(parent)
        self.widget_model = widget_model
        self.available_sources = available_sources
        self.available_visualizations = available_visualizations
        self.delete_requested = False
        self.setWindowTitle("Edit Widget")
        self._build_ui()

    def _build_ui(self):
        layout = QVBoxLayout(self)

        heading = QLabel(f"Editing: {self.widget_model.title}")
        heading_font = QFont()
        heading_font.setBold(True)
        heading_font.setPointSize(12)
        heading.setFont(heading_font)
        layout.addWidget(heading)

        form = QFormLayout()

        self.title_input = QLineEdit(self.widget_model.title)
        form.addRow("Title", self.title_input)

        self.description_input = QLineEdit(self.widget_model.description or "")
        form.addRow("Description", self.description_input)

        self.data_source_combo = QComboBox()
        self.data_source_combo.addItems(self.available_sources or [self.widget_model.data_source])
        current_source_index = self.data_source_combo.findText(self.widget_model.data_source)
        if current_source_index >= 0:
            self.data_source_combo.setCurrentIndex(current_source_index)
        form.addRow("Data Source", self.data_source_combo)

        self.visualization_combo = QComboBox()
        self.visualization_combo.addItems(self.available_visualizations or [self.widget_model.visualization.type])
        current_viz_index = self.visualization_combo.findText(self.widget_model.visualization.type)
        if current_viz_index >= 0:
            self.visualization_combo.setCurrentIndex(current_viz_index)
        form.addRow("Chart Type", self.visualization_combo)

        self.x_field_input = QLineEdit(self.widget_model.visualization.x_field or "")
        form.addRow("X Field", self.x_field_input)

        self.y_field_input = QLineEdit(self.widget_model.visualization.y_field or "")
        form.addRow("Y Field", self.y_field_input)

        self.category_field_input = QLineEdit(self.widget_model.visualization.category_field or "")
        form.addRow("Category Field", self.category_field_input)

        self.value_field_input = QLineEdit(self.widget_model.visualization.value_field or "")
        form.addRow("Value Field", self.value_field_input)

        self.series_field_input = QLineEdit(self.widget_model.visualization.series_field or "")
        form.addRow("Series Field", self.series_field_input)

        self.width_spin = QSpinBox()
        self.width_spin.setRange(1, 12)
        self.width_spin.setValue(self.widget_model.layout.w)
        form.addRow("Grid Width", self.width_spin)

        self.height_spin = QSpinBox()
        self.height_spin.setRange(1, 12)
        self.height_spin.setValue(self.widget_model.layout.h)
        form.addRow("Grid Height", self.height_spin)

        self.legend_check = QCheckBox("Show legend")
        self.legend_check.setChecked(bool(self.widget_model.visualization.show_legend))
        form.addRow("Legend", self.legend_check)

        self.labels_check = QCheckBox("Show labels")
        self.labels_check.setChecked(bool(self.widget_model.visualization.show_labels))
        form.addRow("Labels", self.labels_check)

        layout.addLayout(form)

        delete_button = QPushButton("Delete Widget")
        delete_button.setStyleSheet(
            "QPushButton { background-color: #a61e1e; color: white; padding: 6px 12px; border-radius: 4px; }"
            "QPushButton:hover { background-color: #861818; }"
        )
        delete_button.clicked.connect(self.on_delete_requested)
        layout.addWidget(delete_button, 0, Qt.AlignLeft)

        buttons = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def on_delete_requested(self):
        self.delete_requested = True
        self.accept()

    def apply_changes(self):
        visualization = self.widget_model.visualization
        self.widget_model.title = self.title_input.text().strip() or self.widget_model.title
        self.widget_model.description = self.description_input.text().strip() or None
        self.widget_model.data_source = self.data_source_combo.currentText().strip() or self.widget_model.data_source
        visualization.type = self.visualization_combo.currentText().strip() or visualization.type
        visualization.x_field = self.x_field_input.text().strip() or None
        visualization.y_field = self.y_field_input.text().strip() or None
        visualization.category_field = self.category_field_input.text().strip() or None
        visualization.value_field = self.value_field_input.text().strip() or None
        visualization.series_field = self.series_field_input.text().strip() or None
        visualization.show_legend = self.legend_check.isChecked()
        visualization.show_labels = self.labels_check.isChecked()
        self.widget_model.layout.w = self.width_spin.value()
        self.widget_model.layout.h = self.height_spin.value()


class DashboardGridSurface(QWidget):
    """Drop target surface for draggable dashboard widgets."""

    widget_dropped = Signal(str, QPoint, QPoint)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)

    @staticmethod
    def _extract_widget_id(mime_data: QMimeData) -> Optional[str]:
        if mime_data is None or not mime_data.hasFormat("application/x-dashboard-widget-id"):
            return None
        try:
            return bytes(mime_data.data("application/x-dashboard-widget-id")).decode("utf-8")
        except Exception:
            return None

    @staticmethod
    def _extract_hotspot(mime_data: QMimeData) -> QPoint:
        if mime_data is None or not mime_data.hasFormat("application/x-dashboard-widget-hotspot"):
            return QPoint(0, 0)
        try:
            raw = bytes(mime_data.data("application/x-dashboard-widget-hotspot")).decode("utf-8")
            x_str, y_str = raw.split(",", 1)
            return QPoint(int(x_str), int(y_str))
        except Exception:
            return QPoint(0, 0)

    def dragEnterEvent(self, event):
        widget_id = self._extract_widget_id(event.mimeData())
        if widget_id:
            event.acceptProposedAction()
            return
        event.ignore()

    def dragMoveEvent(self, event):
        widget_id = self._extract_widget_id(event.mimeData())
        if widget_id:
            event.acceptProposedAction()
            return
        event.ignore()

    def dropEvent(self, event):
        widget_id = self._extract_widget_id(event.mimeData())
        if not widget_id:
            event.ignore()
            return
        hotspot = self._extract_hotspot(event.mimeData())
        self.widget_dropped.emit(widget_id, event.position().toPoint(), hotspot)
        event.acceptProposedAction()


class GridWidget(QFrame):
    """Represents a widget cell in the dashboard grid"""
    
    clicked = Signal(str)  # widget ID
    edit_requested = Signal(str)
    drag_started = Signal(str, QPoint, QPoint, object)
    drag_moved = Signal(QPoint)
    drag_finished = Signal(QPoint)
    
    def __init__(self, widget, editable: bool = True, query_engine=None, viz_registry=None, display_mode: Optional[str] = None):
        super().__init__()
        self.widget = widget
        self.editable = editable
        self.query_engine = query_engine
        self.viz_registry = viz_registry
        self.display_mode = display_mode
        self._drag_start_pos: Optional[QPoint] = None
        self._drag_in_progress = False
        self.setup_ui()

    def _visualization_config(self) -> Dict[str, object]:
        visualization = self.widget.visualization
        config = {
            "type": visualization.type,
            "xField": visualization.x_field,
            "yField": visualization.y_field,
            "categoryField": visualization.category_field,
            "valueField": visualization.value_field,
            "seriesField": visualization.series_field,
            "showLegend": visualization.show_legend,
            "showLabels": visualization.show_labels,
        }
        if self.display_mode == "table":
            config["type"] = "table"
            config["showLegend"] = False
        return config

    def _render_visualization_type(self) -> str:
        if self.display_mode == "table":
            return "table"
        return self.widget.visualization.type

    def _make_visualization_pass_through(self, widget: QWidget):
        widget.setAttribute(Qt.WA_TransparentForMouseEvents, True)
        for child in widget.findChildren(QWidget):
            child.setAttribute(Qt.WA_TransparentForMouseEvents, True)

    def _create_drag_pixmap(self) -> QPixmap:
        """Build a crisp logical-size drag preview without the faded overlay."""
        source = self.grab()
        logical_size = self.size()
        preview = QPixmap(logical_size)
        preview.fill(Qt.transparent)

        painter = QPainter(preview)
        painter.drawPixmap(preview.rect(), source)
        painter.end()

        preview.setDevicePixelRatio(1.0)
        return preview
    
    def setup_ui(self):
        """Build widget UI"""
        self.setFrameShape(QFrame.Box)
        self.setFrameShadow(QFrame.Raised)
        self.setLineWidth(1)
        self.setCursor(QCursor(Qt.OpenHandCursor) if self.editable else Qt.ArrowCursor)
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        
        # Header
        header_layout = QHBoxLayout()
        title = QLabel(self.widget.title)
        title_font = QFont()
        title_font.setBold(True)
        title.setFont(title_font)
        header_layout.addWidget(title)
        header_layout.addStretch()
        
        if self.editable:
            edit_btn = QPushButton("✎")
            edit_btn.setMaximumWidth(24)
            edit_btn.clicked.connect(lambda: self.edit_requested.emit(self.widget.id))
            header_layout.addWidget(edit_btn)
        
        layout.addLayout(header_layout)
        
        # Content area - execute query and render visualization
        content = QFrame()
        content.setStyleSheet("background-color: #f9f9f9; border: 1px solid #e0e0e0; border-radius: 2px;")
        content_layout = QVBoxLayout(content)
        content_layout.setContentsMargins(8, 8, 8, 8)
        
        # Try to render widget data if we have query engine
        if self.query_engine and self.viz_registry and self.widget.query:
            try:
                data = self.query_engine.execute(
                    data_source=self.widget.data_source,
                    query=self.widget.query,
                    global_filter=None
                )

                viz_type = self._render_visualization_type()
                renderer = self.viz_registry.get_renderer(viz_type)
                if renderer:
                    viz_widget = renderer(data, self._visualization_config(), content)
                    if self.editable:
                        self._make_visualization_pass_through(viz_widget)
                    content_layout.addWidget(viz_widget)
                else:
                    error_label = QLabel(f"Renderer '{viz_type}' not found")
                    error_label.setStyleSheet("color: #c00;")
                    content_layout.addWidget(error_label)
            except Exception as e:
                error_label = QLabel(f"Error: {str(e)[:50]}...")
                error_label.setStyleSheet("color: #c00;")
                content_layout.addWidget(error_label)
        else:
            # Show placeholder
            if not self.query_engine:
                msg = "Query engine not available"
            elif not self.viz_registry:
                msg = "Visualization registry not available"
            else:
                msg = "No query configured"
            placeholder = QLabel(msg)
            placeholder.setStyleSheet("color: #999; font-size: 9pt;")
            content_layout.addWidget(placeholder)
        
        layout.addWidget(content, 1)
        
        # Footer
        footer_label = QLabel(f"Data: {self.widget.data_source} | View: {self._render_visualization_type()}")
        footer_label.setStyleSheet("font-size: 8pt; color: #666;")
        layout.addWidget(footer_label)
    
    def mousePressEvent(self, event):
        if self.editable and event.button() == Qt.LeftButton:
            self._drag_start_pos = event.pos()
            self._drag_in_progress = False
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event):
        if not self.editable or self._drag_start_pos is None:
            return super().mouseMoveEvent(event)
        if not (event.buttons() & Qt.LeftButton):
            return super().mouseMoveEvent(event)
        if (event.pos() - self._drag_start_pos).manhattanLength() < QApplication.startDragDistance():
            return super().mouseMoveEvent(event)

        if not self._drag_in_progress:
            self._drag_in_progress = True
            self.setCursor(Qt.ClosedHandCursor)
            self.drag_started.emit(
                self.widget.id,
                self.mapToGlobal(event.pos()),
                QPoint(event.pos()),
                self._create_drag_pixmap(),
            )
        else:
            self.drag_moved.emit(self.mapToGlobal(event.pos()))
        event.accept()

    def mouseReleaseEvent(self, event):
        if self.editable and event.button() == Qt.LeftButton:
            if self._drag_in_progress:
                self.drag_finished.emit(self.mapToGlobal(event.pos()))
            elif self._drag_start_pos is not None:
                self.clicked.emit(self.widget.id)
            self._drag_start_pos = None
            self._drag_in_progress = False
            self.setCursor(Qt.OpenHandCursor)
        super().mouseReleaseEvent(event)
    
    def mouseDoubleClickEvent(self, event):
        if self.editable:
            self._drag_start_pos = None
            self._drag_in_progress = False
            self.edit_requested.emit(self.widget.id)
        super().mouseDoubleClickEvent(event)


class DashboardEditor(QDialog):
    """Dashboard editor with grid layout, widget management, and editing"""

    GRID_COLUMNS = 12
    GRID_ROW_HEIGHT = 80
    GRID_SPACING = 8
    
    dashboard_saved = Signal(Dashboard)
    
    def __init__(self, dashboard: Dashboard, dashboard_repo: DashboardRepository, 
                 query_engine: Optional['QueryEngine'] = None,
                 viz_registry: Optional['VisualizationRegistry'] = None,
                 template_repo=None,
                 back_callback: Optional[Callable[[], None]] = None,
                 parent=None):
        super().__init__(parent)
        self.dashboard = dashboard
        self.dashboard_repo = dashboard_repo
        self.query_engine = query_engine
        self.viz_registry = viz_registry
        self.template_repo = template_repo
        self.back_callback = back_callback
        self.edit_mode = not dashboard.is_template  # Templates cannot be edited
        self.selected_widget_id: Optional[str] = None
        self.single_widget_view_mode = "chart"
        self.view_mode_combo: Optional[QComboBox] = None
        self.title_label: Optional[QLabel] = None
        self.scroll_area: Optional[QScrollArea] = None
        self._dragging_widget_id: Optional[str] = None
        self._drag_hotspot = QPoint(0, 0)
        self._drag_preview: Optional[QLabel] = None
        self._drag_indicator: Optional[QFrame] = None
        self._drag_candidate_layout: Optional[WidgetLayout] = None
        self._drag_source_view: Optional[GridWidget] = None
        
        self.setWindowTitle(f"Dashboard Editor - {dashboard.name}")
        
        self.setup_ui()
        _apply_fixed_screen_size(self)
        self._normalize_widget_layouts()
        self.render_grid()
    
    def setup_ui(self):
        """Build main UI"""
        main_layout = QVBoxLayout(self)
        
        # Toolbar
        toolbar_layout = QHBoxLayout()

        back_btn = QPushButton("Back")
        back_btn.clicked.connect(self.on_back)
        toolbar_layout.addWidget(back_btn)

        toolbar_layout.addSpacing(12)
        
        title_label = QLabel(self.dashboard.name)
        title_font = QFont()
        title_font.setPointSize(12)
        title_font.setBold(True)
        title_label.setFont(title_font)
        self.title_label = title_label
        toolbar_layout.addWidget(title_label)
        
        toolbar_layout.addSpacing(20)
        
        if self.edit_mode:
            mode_label = QLabel("Edit Mode")
            mode_label.setStyleSheet("color: #0066cc; font-weight: bold;")
            toolbar_layout.addWidget(mode_label)
            
            toolbar_layout.addSpacing(20)
            
            add_widget_btn = QPushButton("Add Widget")
            add_widget_btn.clicked.connect(self.on_add_widget)
            toolbar_layout.addWidget(add_widget_btn)

            rename_btn = QPushButton("Rename")
            rename_btn.clicked.connect(self.on_rename_dashboard)
            toolbar_layout.addWidget(rename_btn)
            
            toolbar_layout.addSpacing(10)
        else:
            mode_label = QLabel("View Mode (Template)")
            mode_label.setStyleSheet("color: #999;")
            toolbar_layout.addWidget(mode_label)

        if len(self.dashboard.widgets) == 1:
            toolbar_layout.addSpacing(20)
            view_label = QLabel("View:")
            toolbar_layout.addWidget(view_label)
            self.view_mode_combo = QComboBox()
            self.view_mode_combo.addItems(["Chart", "Table"])
            if str(self.dashboard.widgets[0].visualization.type or '') == 'table':
                self.view_mode_combo.setCurrentText("Table")
                self.single_widget_view_mode = "table"
            self.view_mode_combo.currentTextChanged.connect(self.on_view_mode_changed)
            toolbar_layout.addWidget(self.view_mode_combo)
        
        toolbar_layout.addStretch()
        
        if self.edit_mode:
            save_btn = QPushButton("Save")
            save_btn.setStyleSheet("""
                QPushButton {
                    background-color: #0066cc;
                    color: white;
                    padding: 5px 15px;
                    border-radius: 3px;
                    font-weight: bold;
                }
                QPushButton:hover {
                    background-color: #0052a3;
                }
            """)
            save_btn.clicked.connect(self.on_save)
            toolbar_layout.addWidget(save_btn)
        
        main_layout.addLayout(toolbar_layout)
        
        # Grid area
        scroll_area = QScrollArea()
        self.scroll_area = scroll_area
        scroll_area.setWidgetResizable(True)
        scroll_area.setStyleSheet("QScrollArea { background-color: #fafafa; }")
        
        self.grid_container = DashboardGridSurface()
        self.grid_container.widget_dropped.connect(self.on_widget_drop_requested)
        self.grid_layout = QGridLayout(self.grid_container)
        self.grid_layout.setSpacing(self.GRID_SPACING)
        
        # Grid styling
        for row in range(200):
            self.grid_layout.setRowMinimumHeight(row, self.GRID_ROW_HEIGHT)
        
        for col in range(12):
            self.grid_layout.setColumnMinimumWidth(col, 100)
            self.grid_layout.setColumnStretch(col, 1)
        
        # Set bottom-right area to stretch
        self.grid_layout.setRowStretch(199, 1)
        self.grid_layout.setColumnStretch(11, 1)

        self._drag_indicator = QFrame(self.grid_container)
        self._drag_indicator.hide()
        self._drag_indicator.setAttribute(Qt.WA_TransparentForMouseEvents, True)
        self._drag_indicator.setStyleSheet(
            "QFrame {"
            "background-color: rgba(0, 102, 204, 0.12);"
            "border: 2px dashed rgba(0, 102, 204, 0.85);"
            "border-radius: 6px;"
            "}"
        )
        
        scroll_area.setWidget(self.grid_container)
        main_layout.addWidget(scroll_area)
        
        # Status bar
        status_layout = QHBoxLayout()
        status_layout.addStretch()
        self.status_label = QLabel(f"Widgets: {len(self.dashboard.widgets)}")
        status_layout.addWidget(self.status_label)
        main_layout.addLayout(status_layout)
    
    def render_grid(self):
        """Render all widgets in grid"""
        # Clear existing
        while self.grid_layout.count() > 0:
            item = self.grid_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        if not self.dashboard.widgets:
            empty_label = QLabel("This dashboard has no widgets yet.")
            empty_label.setAlignment(Qt.AlignCenter)
            empty_label.setStyleSheet("color: #999; font-size: 11pt; padding: 24px;")
            self.grid_layout.addWidget(empty_label, 0, 0, 1, 12)
            self.update_status()
            return
        
        # Render widgets
        for widget_model in self.dashboard.widgets:
            grid_widget = GridWidget(
                widget_model, 
                editable=self.edit_mode,
                query_engine=self.query_engine,
                viz_registry=self.viz_registry,
                display_mode=self.single_widget_view_mode if len(self.dashboard.widgets) == 1 else None,
            )
            grid_widget.clicked.connect(self.on_grid_widget_clicked)
            grid_widget.edit_requested.connect(self.on_widget_edit_requested)
            grid_widget.drag_started.connect(self.on_widget_drag_started)
            grid_widget.drag_moved.connect(self.on_widget_drag_moved)
            grid_widget.drag_finished.connect(self.on_widget_drag_finished)
            
            layout = widget_model.layout
            self.grid_layout.addWidget(grid_widget, layout.y, layout.x, layout.h, layout.w)
        
        self.update_status()
    
    def on_grid_widget_clicked(self, widget_id: str):
        """Handle widget click"""
        self.selected_widget_id = widget_id
        if self.edit_mode:
            self.on_widget_edit_requested(widget_id)
    
    def on_widget_edit_requested(self, widget_id: str):
        """Open widget editor"""
        widget = self.find_widget(widget_id)
        if not widget:
            return

        available_sources = []
        if self.query_engine and getattr(self.query_engine, 'registry', None):
            try:
                available_sources = list(self.query_engine.registry.list_sources())
            except Exception:
                available_sources = []

        available_visualizations = []
        if self.viz_registry:
            try:
                available_visualizations = [viz_type for viz_type in self.viz_registry.list_types() if viz_type != 'topology']
            except Exception:
                available_visualizations = []

        editor = WidgetEditorDialog(widget, available_sources, available_visualizations, self)
        if editor.exec() != QDialog.Accepted:
            return

        if editor.delete_requested:
            self.dashboard.widgets = [existing for existing in self.dashboard.widgets if existing.id != widget_id]
            self._normalize_widget_layouts()
            self.render_grid()
            return

        editor.apply_changes()
        self._normalize_widget_layouts()
        self.render_grid()

    def on_widget_drop_requested(self, widget_id: str, drop_position: QPoint, hotspot: QPoint):
        """Reposition a widget by dragging it to a new spot in the grid."""
        widget = self.find_widget(widget_id)
        if not widget:
            return

        width = max(1, min(self.GRID_COLUMNS, int(widget.layout.w or 1)))
        origin_point = drop_position - hotspot
        candidate_x = self._grid_column_for_position(origin_point.x(), width)
        candidate_y = self._grid_row_for_position(origin_point.y())

        preferred_layout = WidgetLayout(x=candidate_x, y=candidate_y, w=width, h=max(1, int(widget.layout.h or 1)))
        self._place_widget_at_drop(widget_id, preferred_layout)
        self.render_grid()

    def on_widget_drag_started(self, widget_id: str, global_position: QPoint, hotspot: QPoint, preview_pixmap):
        if not self.edit_mode:
            return

        self._cancel_drag_preview()
        self._dragging_widget_id = widget_id
        self._drag_hotspot = QPoint(hotspot)
        self._drag_source_view = self._find_grid_widget_view(widget_id)
        if self._drag_source_view is not None:
            self._drag_source_view.setVisible(False)

        self._drag_preview = QLabel(self.grid_container)
        self._drag_preview.setAttribute(Qt.WA_TransparentForMouseEvents, True)
        self._drag_preview.setPixmap(preview_pixmap)
        self._drag_preview.resize(preview_pixmap.size())
        self._drag_preview.show()
        self._drag_preview.raise_()
        if self._drag_indicator is not None:
            self._drag_indicator.raise_()
        self.on_widget_drag_moved(global_position)

    def on_widget_drag_moved(self, global_position: QPoint):
        if not self._dragging_widget_id or self._drag_preview is None:
            return

        local_position = self.grid_container.mapFromGlobal(global_position)
        origin_point = local_position - self._drag_hotspot
        self._drag_preview.move(origin_point)

        widget = self.find_widget(self._dragging_widget_id)
        if not widget:
            return

        width = max(1, min(self.GRID_COLUMNS, int(widget.layout.w or 1)))
        height = max(1, int(widget.layout.h or 1))
        candidate_x = self._grid_column_for_position(origin_point.x(), width)
        candidate_y = self._grid_row_for_position(origin_point.y())
        self._drag_candidate_layout = WidgetLayout(x=candidate_x, y=candidate_y, w=width, h=height)
        self._update_drag_indicator(self._drag_candidate_layout)
        self._maybe_autoscroll(local_position)

    def on_widget_drag_finished(self, global_position: QPoint):
        if not self._dragging_widget_id:
            return

        self.on_widget_drag_moved(global_position)
        widget_id = self._dragging_widget_id
        preferred_layout = self._drag_candidate_layout
        self._cancel_drag_preview()
        if preferred_layout is None:
            return
        self._place_widget_at_drop(widget_id, preferred_layout)
        self.render_grid()
    
    def on_add_widget(self):
        """Add new widget to dashboard"""
        if not self.edit_mode:
            QMessageBox.warning(self, "Error", "Cannot edit templates")
            return
        
        new_x, new_y = 0, 0
        
        chart_templates = self.template_repo.list_chart_template_dashboards() if self.template_repo else []
        picker = ChartTemplatePickerDialog(
            chart_templates,
            query_engine=self.query_engine,
            viz_registry=self.viz_registry,
            parent=self,
        )
        if picker.exec() != QDialog.Accepted:
            return

        if not picker.blank_requested:
            new_widget = self.template_repo.create_widget_from_chart_template(picker.selected_template_id)
            if not new_widget:
                QMessageBox.warning(self, "Error", "Failed to load chart template")
                return
            if new_widget.visualization.type == 'metric':
                width, height = 3, 2
            else:
                width, height = 6, 4
        else:
            width, height = 3, 2
            new_widget = DashboardWidget(
                id=str(uuid4()),
                title="New Widget",
                data_source="packets",
                query=WidgetQuery(
                    metrics=[QueryMetric(type="count", field="*", as_="count")]
                ),
                visualization=VisualizationConfig(type="metric", value_field="count", show_legend=False),
                layout=WidgetLayout(x=0, y=0, w=width, h=height),
                description="New widget",
            )

        new_x, new_y = self._find_first_fit_position(width, height)
        new_widget.layout = WidgetLayout(x=new_x, y=new_y, w=width, h=height)
        
        self.dashboard.widgets.append(new_widget)
        self._normalize_widget_layouts()
        self.render_grid()
        QMessageBox.information(self, "Success", "Widget added. Edit to customize.")

    def on_back(self):
        self._cancel_drag_preview()
        callback = self.back_callback
        self.close()
        if callback is not None:
            QTimer.singleShot(0, callback)

    def on_rename_dashboard(self):
        """Rename the current dashboard inside the editor."""
        if not self.edit_mode:
            return
        from PySide6.QtWidgets import QInputDialog

        new_name, ok = QInputDialog.getText(
            self,
            "Rename Dashboard",
            "Dashboard name:",
            text=self.dashboard.name,
        )
        if not ok:
            return

        cleaned_name = (new_name or "").strip()
        if not cleaned_name:
            return

        self.dashboard.name = cleaned_name
        self.setWindowTitle(f"Dashboard Editor - {cleaned_name}")
        if self.title_label is not None:
            self.title_label.setText(cleaned_name)

    def on_view_mode_changed(self, text: str):
        """Switch a single-visualization view between chart and table."""
        self.single_widget_view_mode = "table" if text == "Table" else "chart"
        self.render_grid()
    
    def on_save(self):
        """Save dashboard"""
        self._cancel_drag_preview()
        self.dashboard.updated_at = datetime.now().isoformat()
        self.dashboard_repo.save(self.dashboard)
        QMessageBox.information(self, "Success", "Dashboard saved")
        self.dashboard_saved.emit(self.dashboard)
    
    def find_widget(self, widget_id: str) -> Optional[DashboardWidget]:
        """Find widget by ID"""
        for w in self.dashboard.widgets:
            if w.id == widget_id:
                return w
        return None

    def _find_grid_widget_view(self, widget_id: str) -> Optional[GridWidget]:
        for child in self.grid_container.findChildren(GridWidget):
            if child.widget.id == widget_id:
                return child
        return None

    def _layout_cells(self, layout: WidgetLayout):
        for x in range(layout.x, layout.x + layout.w):
            for y in range(layout.y, layout.y + layout.h):
                yield (x, y)

    def _sanitize_layout(self, layout: WidgetLayout) -> WidgetLayout:
        width = max(1, min(self.GRID_COLUMNS, int(layout.w or 1)))
        height = max(1, int(layout.h or 1))
        max_x = max(0, self.GRID_COLUMNS - width)
        x = min(max(int(layout.x or 0), 0), max_x)
        y = max(int(layout.y or 0), 0)
        return WidgetLayout(x=x, y=y, w=width, h=height)

    def _occupied_cells(self, *, exclude_widget_id: Optional[str] = None):
        occupied = set()
        for widget in self.dashboard.widgets:
            if widget.id == exclude_widget_id:
                continue
            layout = self._sanitize_layout(widget.layout)
            occupied.update(self._layout_cells(layout))
        return occupied

    def _can_place_layout(self, layout: WidgetLayout, *, exclude_widget_id: Optional[str] = None) -> bool:
        normalized = self._sanitize_layout(layout)
        if normalized.x + normalized.w > self.GRID_COLUMNS:
            return False
        occupied = self._occupied_cells(exclude_widget_id=exclude_widget_id)
        return all(cell not in occupied for cell in self._layout_cells(normalized))

    def _find_first_fit_position(self, width: int, height: int, *, exclude_widget_id: Optional[str] = None) -> tuple[int, int]:
        search_width = max(1, min(self.GRID_COLUMNS, int(width or 1)))
        search_height = max(1, int(height or 1))
        max_x = max(0, self.GRID_COLUMNS - search_width)
        for y in range(0, 200):
            for x in range(0, max_x + 1):
                candidate = WidgetLayout(x=x, y=y, w=search_width, h=search_height)
                if self._can_place_layout(candidate, exclude_widget_id=exclude_widget_id):
                    return x, y
        return 0, 0

    def _grid_cell_rect(self, row: int, column: int) -> QRect:
        rect = self.grid_layout.cellRect(max(0, row), max(0, column))
        if rect.isValid():
            return rect

        margins = self.grid_layout.contentsMargins()
        spacing = max(0, self.grid_layout.spacing())
        x = margins.left()
        for current_column in range(max(0, column)):
            x += max(1, self.grid_layout.columnMinimumWidth(current_column)) + spacing

        y = margins.top() + (max(0, row) * (self.GRID_ROW_HEIGHT + spacing))
        width = max(1, self.grid_layout.columnMinimumWidth(max(0, column)))
        height = self.GRID_ROW_HEIGHT
        return QRect(x, y, width, height)

    def _layout_rect(self, layout: WidgetLayout) -> QRect:
        normalized = self._sanitize_layout(layout)
        top_left = self._grid_cell_rect(normalized.y, normalized.x)
        bottom_right = self._grid_cell_rect(normalized.y + normalized.h - 1, normalized.x + normalized.w - 1)
        return QRect(
            top_left.left(),
            top_left.top(),
            max(1, bottom_right.right() - top_left.left() + 1),
            max(1, bottom_right.bottom() - top_left.top() + 1),
        )

    def _update_drag_indicator(self, layout: WidgetLayout):
        if self._drag_indicator is None:
            return
        rect = self._layout_rect(layout)
        self._drag_indicator.setGeometry(rect)
        self._drag_indicator.show()
        self._drag_indicator.raise_()

    def _maybe_autoscroll(self, local_position: QPoint):
        if self.scroll_area is None:
            return

        scrollbar = self.scroll_area.verticalScrollBar()
        viewport_height = self.scroll_area.viewport().height()
        margin = 72
        step = 28
        if local_position.y() < scrollbar.value() + margin:
            scrollbar.setValue(max(scrollbar.minimum(), scrollbar.value() - step))
        elif local_position.y() > scrollbar.value() + viewport_height - margin:
            scrollbar.setValue(min(scrollbar.maximum(), scrollbar.value() + step))

    def _cancel_drag_preview(self):
        if self._drag_source_view is not None:
            self._drag_source_view.setVisible(True)
            self._drag_source_view = None
        if self._drag_preview is not None:
            self._drag_preview.hide()
            self._drag_preview.deleteLater()
            self._drag_preview = None
        if self._drag_indicator is not None:
            self._drag_indicator.hide()
        self._dragging_widget_id = None
        self._drag_candidate_layout = None
        self._drag_hotspot = QPoint(0, 0)

    def _grid_column_for_position(self, x_pos: int, widget_width: int) -> int:
        max_x = max(0, self.GRID_COLUMNS - max(1, min(self.GRID_COLUMNS, int(widget_width or 1))))
        x_value = int(x_pos)
        for column in range(0, max_x + 1):
            rect = self.grid_layout.cellRect(0, column)
            if rect.isValid():
                origin_x = rect.x()
            else:
                margins = self.grid_layout.contentsMargins()
                origin_x = margins.left() + (column * max(1, self.grid_layout.columnMinimumWidth(column)))

            next_rect = self.grid_layout.cellRect(0, column + 1) if column < max_x else QRect()
            if next_rect.isValid():
                next_x = next_rect.x()
            else:
                next_x = origin_x + max(1, self.grid_layout.columnMinimumWidth(column))

            if x_value < origin_x:
                return column
            if origin_x <= x_value < next_x:
                return column
        return max_x

    def _grid_row_for_position(self, y_pos: int) -> int:
        y_value = int(y_pos)
        for row in range(0, 200):
            rect = self.grid_layout.cellRect(row, 0)
            if rect.isValid():
                origin_y = rect.y()
            else:
                origin_y = self.grid_layout.contentsMargins().top() + (row * self.GRID_ROW_HEIGHT)
            next_rect = self.grid_layout.cellRect(row + 1, 0)
            if next_rect.isValid():
                next_y = next_rect.y()
            else:
                next_y = origin_y + self.GRID_ROW_HEIGHT

            if y_value < origin_y:
                return row
            if origin_y <= y_value < next_y:
                return row
        return max(0, int(y_value / max(1, self.GRID_ROW_HEIGHT)))

    def _find_fit_position_from(self, start_x: int, start_y: int, width: int, height: int, *, exclude_widget_id: Optional[str] = None) -> tuple[int, int]:
        search_width = max(1, min(self.GRID_COLUMNS, int(width or 1)))
        search_height = max(1, int(height or 1))
        max_x = max(0, self.GRID_COLUMNS - search_width)
        origin_x = min(max(int(start_x or 0), 0), max_x)
        origin_y = max(int(start_y or 0), 0)

        for y in range(origin_y, 200):
            x_start = origin_x if y == origin_y else 0
            for x in range(x_start, max_x + 1):
                candidate = WidgetLayout(x=x, y=y, w=search_width, h=search_height)
                if self._can_place_layout(candidate, exclude_widget_id=exclude_widget_id):
                    return x, y
        return self._find_first_fit_position(search_width, search_height, exclude_widget_id=exclude_widget_id)

    def _place_widget_at_drop(self, widget_id: str, preferred_layout: WidgetLayout):
        """Pin the dragged widget to the drop slot and reflow only the surrounding widgets."""
        target_widget = self.find_widget(widget_id)
        if not target_widget:
            return

        pinned_layout = self._sanitize_layout(preferred_layout)
        target_widget.layout = pinned_layout

        pinned_cells = set(self._layout_cells(pinned_layout))
        other_widgets = [widget for widget in self.dashboard.widgets if widget.id != widget_id]
        ordered_widgets = sorted(
            other_widgets,
            key=lambda widget: (
                int(getattr(widget.layout, 'y', 0) or 0),
                int(getattr(widget.layout, 'x', 0) or 0),
                widget.id,
            ),
        )

        arranged_widgets: List[DashboardWidget] = [target_widget]
        self.dashboard.widgets = [target_widget]
        for widget in ordered_widgets:
            candidate_layout = self._sanitize_layout(widget.layout)
            overlaps_pinned = any(cell in pinned_cells for cell in self._layout_cells(candidate_layout))
            if overlaps_pinned or not self._can_place_layout(candidate_layout, exclude_widget_id=widget.id):
                new_x, new_y = self._find_fit_position_from(
                    candidate_layout.x,
                    candidate_layout.y,
                    candidate_layout.w,
                    candidate_layout.h,
                    exclude_widget_id=widget.id,
                )
                candidate_layout = WidgetLayout(x=new_x, y=new_y, w=candidate_layout.w, h=candidate_layout.h)
            widget.layout = candidate_layout
            arranged_widgets.append(widget)
            self.dashboard.widgets.append(widget)

        self.dashboard.widgets = arranged_widgets

    def _normalize_widget_layouts(self, preferred_widget_id: Optional[str] = None, preferred_layout: Optional[WidgetLayout] = None):
        arranged_widgets: List[DashboardWidget] = []
        ordered_widgets = sorted(
            self.dashboard.widgets,
            key=lambda widget: (
                0 if preferred_widget_id and widget.id == preferred_widget_id else 1,
                int(getattr(widget.layout, 'y', 0) or 0),
                int(getattr(widget.layout, 'x', 0) or 0),
                widget.id,
            ),
        )

        self.dashboard.widgets = []
        for widget in ordered_widgets:
            if preferred_widget_id and widget.id == preferred_widget_id and preferred_layout is not None:
                candidate_layout = self._sanitize_layout(preferred_layout)
            else:
                candidate_layout = self._sanitize_layout(widget.layout)

            if not self._can_place_layout(candidate_layout, exclude_widget_id=widget.id):
                new_x, new_y = self._find_fit_position_from(
                    candidate_layout.x,
                    candidate_layout.y,
                    candidate_layout.w,
                    candidate_layout.h,
                    exclude_widget_id=widget.id,
                )
                candidate_layout = WidgetLayout(x=new_x, y=new_y, w=candidate_layout.w, h=candidate_layout.h)

            widget.layout = candidate_layout
            arranged_widgets.append(widget)
            self.dashboard.widgets.append(widget)

        self.dashboard.widgets = arranged_widgets
    
    def update_status(self):
        """Update status bar"""
        self.status_label.setText(f"Widgets: {len(self.dashboard.widgets)}")
