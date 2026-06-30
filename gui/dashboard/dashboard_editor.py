"""
Dashboard Editor UI.

Allows editing dashboard layout, widgets, queries, and visualizations.
"""

from PySide6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QWidget, QScrollArea, QGridLayout,
    QPushButton, QLabel, QMessageBox, QToolBar, QComboBox, QLineEdit,
    QMenu, QFrame, QSplitter, QApplication, QSizePolicy, QCheckBox,
    QDialogButtonBox, QFormLayout, QSpinBox, QTabWidget, QTextEdit,
    QColorDialog,
    QListWidget, QListWidgetItem, QTableWidget, QTableWidgetItem
)
from PySide6.QtCore import Qt, Signal, QSize, QPoint, QRect, QTimer, QMimeData, QEvent
from PySide6.QtGui import QIcon, QFont, QCursor, QPixmap, QPainter, QColor
from typing import Optional, List, Dict, Callable, Any
from uuid import uuid4
from datetime import datetime
from copy import deepcopy
from contextlib import contextmanager

from .models import (
    Dashboard, DashboardWidget, WidgetQuery, VisualizationConfig,
    WidgetLayout, DashboardLayout, QueryMetric, QuerySort
)
from .repository import DashboardRepository
from .ui import apply_dashboard_theme


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


def _fetch_rows_for_source(query_engine, source_name: str, *, limit: int = 500) -> List[Dict[str, Any]]:
    if not query_engine or not getattr(query_engine, "registry", None):
        return []
    cleaned_source = str(source_name or "").strip()
    if not cleaned_source:
        return []
    try:
        fetcher = query_engine.registry.get_fetcher(cleaned_source)
    except Exception:
        fetcher = None
    if fetcher is None:
        return []
    try:
        rows = fetcher(limit=limit) or []
    except TypeError:
        try:
            rows = fetcher() or []
        except Exception:
            return []
    except Exception:
        return []
    return list(rows)[:max(1, int(limit or 500))]


def _build_dual_source_xy_rows(
    query_engine,
    x_source: str,
    y_source: str,
    x_field: str,
    y_field: str,
    *,
    series_field: Optional[str] = None,
    limit: int = 500,
) -> List[Dict[str, Any]]:
    rows_x = _fetch_rows_for_source(query_engine, x_source, limit=limit)
    rows_y = _fetch_rows_for_source(query_engine, y_source, limit=limit)
    if not rows_x or not rows_y:
        return []

    merged: List[Dict[str, Any]] = []
    sample_count = min(len(rows_x), len(rows_y), max(1, int(limit or 500)))
    for idx in range(sample_count):
        left = rows_x[idx]
        right = rows_y[idx]
        row: Dict[str, Any] = {}
        row[x_field] = left.get(x_field, left.get("time", idx))
        row[y_field] = right.get(y_field, right.get("packets", right.get("bytes", 0)))
        if series_field:
            row[series_field] = right.get(series_field, left.get(series_field, str(y_source)))
        merged.append(row)
    return merged


class _NoWheelComboBox(QComboBox):
    def wheelEvent(self, event):
        if self.hasFocus():
            super().wheelEvent(event)
            return
        event.ignore()


class _NoWheelSpinBox(QSpinBox):
    def wheelEvent(self, event):
        if self.hasFocus():
            super().wheelEvent(event)
            return
        event.ignore()


class WidgetEditorDialog(QDialog):
    """Field-based chart builder used to edit dashboard widgets."""

    SIZE_PRESETS = {
        "Custom": None,
        "Small (3 x 2)": (3, 2),
        "Medium (6 x 4)": (6, 4),
        "Large (8 x 5)": (8, 5),
        "Full Width (12 x 4)": (12, 4),
    }
    METRIC_TYPES = ["none", "count", "distinct_count", "sum", "avg", "min", "max", "first", "last"]
    TIME_BUCKETS = ["", "1s", "5s", "10s", "30s", "1m", "5m", "10m", "1h"]
    FILTER_OPERATORS = ["==", "!=", ">", ">=", "<", "<="]
    FILTER_JOINERS = ["AND", "OR"]
    FIELD_ROLE_OPTIONS = ["All Roles", "time", "metric", "dimension", "flag"]
    CORE_SHARED_FIELDS = ["time", "protocol", "bytes", "packets", "packet"]
    SINGLE_SOURCE_CHARTS = {"metric", "histogram", "pie", "donut", "radar", "treemap", "sunburst"}
    PROPORTION_SOURCE_CHARTS = {"pie", "donut", "radar", "treemap", "sunburst"}
    HIERARCHY_PROTOCOL_CHARTS = {"treemap", "sunburst"}
    DOUBLE_SOURCE_CHARTS = {"bar", "horizontal_bar", "line", "area", "scatter", "heatmap", "table"}
    ASSIGNMENT_LABELS = {
        "x_field": "X Axis",
        "y_field": "Y Axis",
        "category_field": "Category",
        "value_field": "Value",
        "series_field": "Series / Color",
        "metric_field": "Metric Field",
        "group_by": "Group By",
        "sort_field": "Sort",
        "columns": "Columns",
        "filter_field": "Filter Builder",
    }
    DEFAULT_CHART_CAPABILITY = {
        "mapping_controls": {"x_field", "y_field", "category_field", "value_field", "series_field", "group_by", "columns"},
        "query_controls": {"metric_type", "metric_field", "metric_alias", "filter", "filter_builder", "sort_field", "sort_direction", "limit", "time_bucket"},
        "style_controls": {"legend", "labels", "x_axis_label", "y_axis_label", "unit", "primary_color", "color_palette"},
        "assignment_targets": ["x_field", "y_field", "category_field", "value_field", "series_field", "group_by", "sort_field", "columns", "filter_field"],
        "summary": "Unlock all chart-builder controls.",
    }
    CHART_CAPABILITIES = {
        "metric": {
            "mapping_controls": {"value_field"},
            "query_controls": {"metric_type", "metric_field", "metric_alias", "filter", "filter_builder", "limit"},
            "style_controls": {"unit"},
            "assignment_targets": ["value_field", "metric_field", "filter_field"],
            "summary": "Metric cards focus on one output value and a compact filter/metric setup.",
        },
        "table": {
            "mapping_controls": {"group_by", "columns"},
            "query_controls": {"metric_type", "metric_field", "metric_alias", "filter", "filter_builder", "sort_field", "sort_direction", "limit", "time_bucket"},
            "style_controls": set(),
            "assignment_targets": ["group_by", "metric_field", "sort_field", "columns", "filter_field"],
            "summary": "Table widgets mainly need columns, optional aggregation, filter and sort.",
        },
        "bar": {
            "mapping_controls": {"category_field", "value_field", "series_field", "group_by"},
            "query_controls": {"metric_type", "metric_field", "metric_alias", "filter", "filter_builder", "sort_field", "sort_direction", "limit"},
            "style_controls": {"legend", "labels", "x_axis_label", "y_axis_label", "unit", "primary_color"},
            "assignment_targets": ["category_field", "value_field", "series_field", "group_by", "metric_field", "sort_field", "filter_field"],
            "summary": "Bar charts compare categories against one plotted value, with optional series grouping.",
        },
        "horizontal_bar": {
            "mapping_controls": {"category_field", "value_field", "series_field", "group_by"},
            "query_controls": {"metric_type", "metric_field", "metric_alias", "filter", "filter_builder", "sort_field", "sort_direction", "limit"},
            "style_controls": {"legend", "labels", "x_axis_label", "y_axis_label", "unit", "primary_color"},
            "assignment_targets": ["category_field", "value_field", "series_field", "group_by", "metric_field", "sort_field", "filter_field"],
            "summary": "Horizontal bar charts use the same category/value model as bar charts.",
        },
        "line": {
            "mapping_controls": {"x_field", "y_field", "value_field", "series_field", "group_by"},
            "query_controls": {"metric_type", "metric_field", "metric_alias", "filter", "filter_builder", "sort_field", "sort_direction", "limit", "time_bucket"},
            "style_controls": {"legend", "labels", "x_axis_label", "y_axis_label", "unit", "primary_color"},
            "assignment_targets": ["x_field", "y_field", "value_field", "series_field", "group_by", "metric_field", "sort_field", "filter_field"],
            "summary": "Line charts need an X axis plus one numeric value series, with optional time bucketing.",
        },
        "area": {
            "mapping_controls": {"x_field", "y_field", "value_field", "series_field", "group_by"},
            "query_controls": {"metric_type", "metric_field", "metric_alias", "filter", "filter_builder", "sort_field", "sort_direction", "limit", "time_bucket"},
            "style_controls": {"legend", "labels", "x_axis_label", "y_axis_label", "unit", "primary_color"},
            "assignment_targets": ["x_field", "y_field", "value_field", "series_field", "group_by", "metric_field", "sort_field", "filter_field"],
            "summary": "Area charts share the line-chart mapping model and optionally use time buckets.",
        },
        "scatter": {
            "mapping_controls": {"x_field", "y_field", "series_field"},
            "query_controls": {"filter", "filter_builder", "sort_field", "sort_direction", "limit"},
            "style_controls": {"legend", "labels", "x_axis_label", "y_axis_label", "primary_color"},
            "assignment_targets": ["x_field", "y_field", "series_field", "sort_field", "filter_field"],
            "summary": "Scatter plots compare two numeric axes directly and do not need aggregate metrics by default.",
        },
        "radar": {
            "mapping_controls": {"category_field", "value_field", "series_field", "group_by"},
            "query_controls": {"metric_type", "metric_field", "metric_alias", "filter", "filter_builder", "sort_field", "sort_direction", "limit"},
            "style_controls": {"legend", "labels", "unit", "primary_color"},
            "assignment_targets": ["category_field", "value_field", "series_field", "group_by", "metric_field", "sort_field", "filter_field"],
            "summary": "Radar charts compare a value across a small set of categories.",
        },
        "treemap": {
            "mapping_controls": {"category_field", "value_field", "series_field", "group_by"},
            "query_controls": {"metric_type", "metric_field", "metric_alias", "filter", "filter_builder", "sort_field", "sort_direction", "limit"},
            "style_controls": {"legend", "labels", "unit", "primary_color", "color_palette"},
            "assignment_targets": ["category_field", "value_field", "series_field", "group_by", "metric_field", "sort_field", "filter_field"],
            "summary": "Treemap charts need categories, values and optionally one grouping field.",
        },
        "sunburst": {
            "mapping_controls": {"category_field", "value_field", "series_field", "group_by"},
            "query_controls": {"metric_type", "metric_field", "metric_alias", "filter", "filter_builder", "sort_field", "sort_direction", "limit"},
            "style_controls": {"legend", "labels", "unit", "primary_color", "color_palette"},
            "assignment_targets": ["category_field", "value_field", "series_field", "group_by", "metric_field", "sort_field", "filter_field"],
            "summary": "Sunburst charts use category/value mappings and an optional series field for grouping depth.",
        },
        "pie": {
            "mapping_controls": {"category_field", "value_field", "group_by"},
            "query_controls": {"metric_type", "metric_field", "metric_alias", "filter", "filter_builder", "sort_field", "sort_direction", "limit"},
            "style_controls": {"legend", "labels", "unit", "primary_color", "color_palette"},
            "assignment_targets": ["category_field", "value_field", "group_by", "metric_field", "sort_field", "filter_field"],
            "summary": "Pie charts only need category/value mappings and optional aggregation.",
        },
        "donut": {
            "mapping_controls": {"category_field", "value_field", "group_by"},
            "query_controls": {"metric_type", "metric_field", "metric_alias", "filter", "filter_builder", "sort_field", "sort_direction", "limit"},
            "style_controls": {"legend", "labels", "unit", "primary_color", "color_palette"},
            "assignment_targets": ["category_field", "value_field", "group_by", "metric_field", "sort_field", "filter_field"],
            "summary": "Donut charts use the same focused setup as pie charts.",
        },
        "histogram": {
            "mapping_controls": {"value_field"},
            "query_controls": {"filter", "filter_builder", "sort_field", "sort_direction", "limit"},
            "style_controls": {"labels", "x_axis_label", "y_axis_label", "unit", "primary_color"},
            "assignment_targets": ["value_field", "sort_field", "filter_field"],
            "summary": "Histograms only need one numeric value field and optional filter/sort controls.",
        },
        "heatmap": {
            "mapping_controls": {"category_field", "value_field", "group_by"},
            "query_controls": {"metric_type", "metric_field", "metric_alias", "filter", "filter_builder", "sort_field", "sort_direction", "limit"},
            "style_controls": {"primary_color"},
            "assignment_targets": ["category_field", "value_field", "group_by", "metric_field", "sort_field", "filter_field"],
            "summary": "Heatmaps focus on row labels and numeric values; axis styling is intentionally hidden.",
        },
    }

    SOURCE_PRIORITY = [
        "packets",
        "endpoints",
        "conversations",
        "protocol_stats",
        "dns_queries",
        "http_requests",
    ]

    @classmethod
    def _ordered_sources(cls, sources: List[str]) -> List[str]:
        seen = set()
        cleaned_sources: List[str] = []
        for source_name in sources or []:
            cleaned = str(source_name or "").strip()
            if not cleaned or cleaned in seen:
                continue
            seen.add(cleaned)
            cleaned_sources.append(cleaned)
        priority = {name: idx for idx, name in enumerate(cls.SOURCE_PRIORITY)}
        return sorted(cleaned_sources, key=lambda name: (priority.get(name, 999), name))

    def __init__(
        self,
        widget_model: DashboardWidget,
        available_sources: List[str],
        available_visualizations: List[str],
        query_engine=None,
        viz_registry=None,
        parent=None,
    ):
        super().__init__(parent)
        self.widget_model = widget_model
        self.available_sources = self._ordered_sources(available_sources or [widget_model.data_source])
        self.available_visualizations = available_visualizations
        self.query_engine = query_engine
        self.viz_registry = viz_registry
        self.delete_requested = False
        self._working_copy = deepcopy(widget_model)
        self._source_rows: List[Dict[str, Any]] = []
        self._source_rows_by_name: Dict[str, List[Dict[str, Any]]] = {}
        self._field_catalog: List[Dict[str, Any]] = []
        self._mapping_controls: Dict[str, Any] = {}
        self._query_controls: Dict[str, Any] = {}
        self._style_controls: Dict[str, Any] = {}
        self._preview_click_targets: List[QWidget] = []
        self._color_editor_active = False
        self._applying_size_preset = False
        self._preview_refresh_suspend_count = 0
        self._preview_refresh_pending = False
        self._preview_timer = QTimer(self)
        self._preview_timer.setSingleShot(True)
        # Slightly longer debounce keeps the editor responsive while typing/filtering.
        self._preview_timer.setInterval(420)
        self._preview_timer.timeout.connect(self._refresh_preview)
        self.setWindowTitle(f"Edit Chart - {widget_model.title}")
        self._build_ui()
        apply_dashboard_theme(self)
        self._set_combo_to_text(self.x_data_source_combo, self._working_copy.data_source)
        self._set_combo_to_text(self.y_data_source_combo, self._working_copy.data_source)
        self._load_source(self._working_copy.data_source)
        self._populate_controls()
        self._connect_live_preview_signals()
        self._schedule_preview_refresh()
        _apply_fixed_screen_size(self)

    def _build_ui(self):
        root_layout = QVBoxLayout(self)

        heading = QLabel(f"Edit Chart: {self.widget_model.title}")
        heading_font = QFont()
        heading_font.setBold(True)
        heading_font.setPointSize(13)
        heading.setFont(heading_font)
        root_layout.addWidget(heading)

        subheading = QLabel("General -> Data Source -> Style. The next tab reuses the choices made in the previous tab.")
        subheading.setStyleSheet("color: #666; font-size: 9pt;")
        root_layout.addWidget(subheading)

        splitter = QSplitter(Qt.Horizontal, self)
        splitter.setChildrenCollapsible(False)
        root_layout.addWidget(splitter, 1)

        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_layout.setContentsMargins(0, 0, 0, 0)
        self.tabs = QTabWidget()
        left_layout.addWidget(self.tabs)
        splitter.addWidget(left_panel)

        preview_panel = QWidget()
        preview_layout = QVBoxLayout(preview_panel)
        preview_layout.setContentsMargins(0, 0, 0, 0)
        splitter.addWidget(preview_panel)
        splitter.setSizes([650, 540])

        self._build_general_tab()
        self._build_source_tab()
        self._build_mapping_tab()
        self._build_query_tab()
        self._build_style_tab()
        self._finalize_simplified_editor()

        preview_heading = QLabel("Preview")
        preview_heading_font = QFont()
        preview_heading_font.setBold(True)
        preview_heading_font.setPointSize(11)
        preview_heading.setFont(preview_heading_font)
        preview_layout.addWidget(preview_heading)

        self.preview_status_label = QLabel("Preview not loaded yet.")
        self.preview_status_label.setStyleSheet("color: #666; font-size: 9pt;")
        preview_layout.addWidget(self.preview_status_label)

        self.preview_chart_frame = QFrame()
        self.preview_chart_frame.setFrameShape(QFrame.Box)
        self.preview_chart_frame.setStyleSheet("QFrame { background-color: white; border: 1px solid #d9d9d9; border-radius: 4px; }")
        self.preview_chart_layout = QVBoxLayout(self.preview_chart_frame)
        self.preview_chart_layout.setContentsMargins(8, 8, 8, 8)
        self.preview_chart_layout.setSpacing(4)
        preview_layout.addWidget(self.preview_chart_frame, 3)

        sheet_action_row = QHBoxLayout()
        sheet_action_row.addWidget(QLabel("Sheet Preview"))
        sheet_action_row.addStretch()

        copy_table_btn = QPushButton("Copy Table")
        copy_table_btn.clicked.connect(lambda: self._copy_table_to_clipboard(self.preview_sheet_table))
        sheet_action_row.addWidget(copy_table_btn)
        preview_layout.addLayout(sheet_action_row)

        self.preview_sheet_table = QTableWidget()
        preview_layout.addWidget(self.preview_sheet_table, 2)

        button_row = QHBoxLayout()
        delete_button = QPushButton("Delete Widget")
        delete_button.setStyleSheet(
            "QPushButton { background-color: #a61e1e; color: white; padding: 6px 12px; border-radius: 4px; }"
            "QPushButton:hover { background-color: #861818; }"
        )
        delete_button.clicked.connect(self.on_delete_requested)
        button_row.addWidget(delete_button)
        button_row.addStretch()

        buttons = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self._validate_and_accept)
        buttons.rejected.connect(self.reject)
        button_row.addWidget(buttons)
        root_layout.addLayout(button_row)

    def _build_general_tab(self):
        tab = QWidget()
        self.general_tab = tab
        container_layout = QVBoxLayout(tab)
        container_layout.setContentsMargins(0, 0, 0, 0)
        container_layout.setSpacing(8)

        form_widget = QWidget()
        layout = QFormLayout(form_widget)
        layout.setContentsMargins(0, 0, 0, 0)

        self.title_input = QLineEdit()
        layout.addRow("Name Chart", self.title_input)

        self.description_input = QTextEdit()
        self.description_input.setMaximumHeight(90)
        layout.addRow("Description", self.description_input)

        self.visualization_combo = _NoWheelComboBox()
        self.visualization_combo.addItems(self.available_visualizations or [self.widget_model.visualization.type])
        self.visualization_combo.currentTextChanged.connect(self._on_chart_type_changed)
        layout.addRow("Chart Type", self.visualization_combo)

        self.size_preset_combo = _NoWheelComboBox()
        self.size_preset_combo.addItems(list(self.SIZE_PRESETS.keys()))
        self.size_preset_combo.currentTextChanged.connect(self._on_size_preset_changed)
        self.size_preset_combo.setMaximumWidth(120)

        size_row = QHBoxLayout()
        size_row.setContentsMargins(0, 0, 0, 0)
        size_row.setSpacing(6)
        size_row.addWidget(QLabel("Preset"))
        size_row.addWidget(self.size_preset_combo)
        size_row.addSpacing(10)
        self.width_spin = _NoWheelSpinBox()
        self.width_spin.setRange(1, 12)
        self.width_spin.setFixedWidth(64)
        self.width_spin.valueChanged.connect(self._on_size_dimension_changed)
        self.height_spin = _NoWheelSpinBox()
        self.height_spin.setRange(1, 12)
        self.height_spin.setFixedWidth(64)
        self.height_spin.valueChanged.connect(self._on_size_dimension_changed)
        size_row.addWidget(QLabel("W"))
        size_row.addWidget(self.width_spin)
        size_row.addSpacing(4)
        size_row.addWidget(QLabel("H"))
        size_row.addWidget(self.height_spin)
        size_row.addStretch()
        size_widget = QWidget()
        size_widget.setLayout(size_row)
        size_widget.setSizePolicy(QSizePolicy.Maximum, QSizePolicy.Fixed)
        size_widget.setMaximumWidth(320)
        layout.addRow("Size", size_widget)

        self.display_mode_combo = _NoWheelComboBox()
        self.display_mode_combo.addItems(["Chart", "Table"])
        layout.addRow("Display Mode", self.display_mode_combo)

        container_layout.addWidget(form_widget)
        container_layout.addStretch()

        self.tabs.addTab(tab, "General")

    def _build_source_tab(self):
        tab = QWidget()
        self.source_tab = tab
        layout = QVBoxLayout(tab)

        source_form = QFormLayout()
        self.data_source_combo = _NoWheelComboBox()
        self.data_source_combo.addItems(self.available_sources or [self.widget_model.data_source])
        self.data_source_combo.currentTextChanged.connect(self._on_source_changed)
        self.data_source_label = QLabel("Data Source")
        source_form.addRow(self.data_source_label, self.data_source_combo)

        self.x_data_source_combo = _NoWheelComboBox()
        self.x_data_source_combo.addItems(self.available_sources or [self.widget_model.data_source])
        self.x_data_source_combo.currentTextChanged.connect(self._on_dual_source_changed)

        self.y_data_source_combo = _NoWheelComboBox()
        self.y_data_source_combo.addItems(self.available_sources or [self.widget_model.data_source])
        self.y_data_source_combo.currentTextChanged.connect(self._on_dual_source_changed)

        self.source_primary_axis_label = QLabel("X Name")
        self.source_secondary_axis_label = QLabel("Y Name")

        self.x_data_source_label = QLabel("X Source")
        self.y_data_source_label = QLabel("Y Source")

        layout.addLayout(source_form)

        self.simple_source_form = QFormLayout()
        self.single_source_field_label = QLabel("Source Field")
        self.single_source_field_combo = self._create_field_combo()
        self.single_source_field_combo.currentTextChanged.connect(self._on_simple_source_changed)
        self.simple_source_form.addRow(self.single_source_field_label, self.single_source_field_combo)

        self.simple_source_form.addRow(self.x_data_source_label, self.x_data_source_combo)

        self.primary_source_field_label = QLabel("X Field")
        self.primary_source_field_combo = self._create_field_combo()
        self.primary_source_field_combo.currentTextChanged.connect(self._on_simple_source_changed)
        self.simple_source_form.addRow(self.primary_source_field_label, self.primary_source_field_combo)

        self.simple_source_form.addRow(self.y_data_source_label, self.y_data_source_combo)

        self.secondary_source_field_label = QLabel("Y Field")
        self.secondary_source_field_combo = self._create_field_combo()
        self.secondary_source_field_combo.currentTextChanged.connect(self._on_simple_source_changed)
        self.simple_source_form.addRow(self.secondary_source_field_label, self.secondary_source_field_combo)

        self.swap_axes_button = QPushButton("Swap Axes")
        self.swap_axes_button.clicked.connect(self._swap_simple_source_fields)
        swap_widget = QWidget()
        swap_layout = QHBoxLayout(swap_widget)
        swap_layout.setContentsMargins(0, 0, 0, 0)
        swap_layout.addWidget(self.swap_axes_button)
        swap_layout.addStretch()
        self.swap_axes_label = QLabel("")
        self.simple_source_form.addRow(self.swap_axes_label, swap_widget)

        self.source_tab_hint_label = QLabel("Choose chart type first, then pick the fields from the current data source that should be plotted.")
        self.source_tab_hint_label.setWordWrap(True)
        self.source_tab_hint_label.setStyleSheet("color: #666; font-size: 9pt;")
        layout.addLayout(self.simple_source_form)
        layout.addWidget(self.source_tab_hint_label)

        browser_frame = QFrame()
        browser_layout = QVBoxLayout(browser_frame)
        browser_layout.setContentsMargins(0, 0, 0, 0)
        browser_layout.setSpacing(6)
        filter_row = QHBoxLayout()
        self.field_search_input = QLineEdit()
        self.field_search_input.setPlaceholderText("Search field by id, sample value, group or role")
        self.field_search_input.textChanged.connect(self._refresh_field_list)
        filter_row.addWidget(self.field_search_input, 2)

        self.field_group_filter_combo = _NoWheelComboBox()
        self.field_group_filter_combo.currentTextChanged.connect(self._refresh_field_list)
        filter_row.addWidget(self.field_group_filter_combo, 1)

        self.field_role_filter_combo = _NoWheelComboBox()
        self.field_role_filter_combo.addItems(self.FIELD_ROLE_OPTIONS)
        self.field_role_filter_combo.currentTextChanged.connect(self._refresh_field_list)
        filter_row.addWidget(self.field_role_filter_combo, 1)
        browser_layout.addLayout(filter_row)

        self.field_list = QListWidget()
        self.field_list.currentItemChanged.connect(self._on_field_selected)
        self.field_list.itemDoubleClicked.connect(lambda _item: self._assign_selected_field_to_current_target())
        browser_layout.addWidget(self.field_list, 1)

        self.field_details_label = QLabel("Select a field to inspect metadata, group, role, and sample values.")
        self.field_details_label.setWordWrap(True)
        self.field_details_label.setStyleSheet("color: #555; background-color: #f8f8f8; border: 1px solid #e5e5e5; border-radius: 4px; padding: 8px;")
        browser_layout.addWidget(self.field_details_label)

        self.field_assignment_hint_label = QLabel("The selected chart type decides where this field can be assigned.")
        self.field_assignment_hint_label.setWordWrap(True)
        self.field_assignment_hint_label.setStyleSheet("color: #666; font-size: 9pt;")
        browser_layout.addWidget(self.field_assignment_hint_label)

        assign_frame = QFrame()
        assign_frame.setStyleSheet("QFrame { background-color: #fbfbfb; border: 1px solid #e4e4e4; border-radius: 4px; }")
        assign_layout = QHBoxLayout(assign_frame)
        assign_layout.setContentsMargins(8, 8, 8, 8)
        assign_layout.setSpacing(8)
        assign_layout.addWidget(QLabel("Assign selected field to"))

        self.assignment_target_combo = _NoWheelComboBox()
        self.assignment_target_combo.currentTextChanged.connect(self._update_assignment_ui)
        assign_layout.addWidget(self.assignment_target_combo, 1)

        self.assign_selected_field_button = QPushButton("Assign Field")
        self.assign_selected_field_button.clicked.connect(self._assign_selected_field_to_current_target)
        assign_layout.addWidget(self.assign_selected_field_button)

        browser_layout.addWidget(assign_frame)
        browser_frame.setVisible(False)
        layout.addWidget(browser_frame, 1)
        self.field_browser_frame = browser_frame

        self.tabs.addTab(tab, "Data Source")

    def _build_mapping_tab(self):
        tab = QWidget()
        self.mapping_tab = tab
        layout = QFormLayout(tab)

        self.x_field_combo = self._create_field_combo()
        layout.addRow("X Axis Field", self.x_field_combo)

        self.y_field_combo = self._create_field_combo()
        layout.addRow("Y Axis Field", self.y_field_combo)

        self.category_field_combo = self._create_field_combo()
        layout.addRow("Category Field", self.category_field_combo)

        self.value_field_combo = self._create_field_combo()
        layout.addRow("Value Field", self.value_field_combo)

        self.series_field_combo = self._create_field_combo()
        layout.addRow("Series / Color Field", self.series_field_combo)

        self.group_by_input = QLineEdit()
        self.group_by_input.setPlaceholderText("Comma-separated fields")
        layout.addRow("Group By", self.group_by_input)

        self.columns_input = QLineEdit()
        self.columns_input.setPlaceholderText("Comma-separated columns for table/raw preview")
        layout.addRow("Columns", self.columns_input)

        self._mapping_controls = {
            "x_field": (layout.labelForField(self.x_field_combo), self.x_field_combo),
            "y_field": (layout.labelForField(self.y_field_combo), self.y_field_combo),
            "category_field": (layout.labelForField(self.category_field_combo), self.category_field_combo),
            "value_field": (layout.labelForField(self.value_field_combo), self.value_field_combo),
            "series_field": (layout.labelForField(self.series_field_combo), self.series_field_combo),
            "group_by": (layout.labelForField(self.group_by_input), self.group_by_input),
            "columns": (layout.labelForField(self.columns_input), self.columns_input),
        }

        self.tabs.addTab(tab, "Fields & Axes")

    def _build_query_tab(self):
        tab = QWidget()
        self.query_tab = tab
        tab_layout = QVBoxLayout(tab)
        layout = QFormLayout()
        tab_layout.addLayout(layout)

        self.metric_type_combo = _NoWheelComboBox()
        self.metric_type_combo.addItems(self.METRIC_TYPES)
        layout.addRow("Metric Type", self.metric_type_combo)

        self.metric_field_combo = self._create_field_combo(include_star=True)
        layout.addRow("Metric Field", self.metric_field_combo)

        self.metric_alias_input = QLineEdit()
        self.metric_alias_input.setPlaceholderText("Alias for aggregated output")
        layout.addRow("Metric Alias", self.metric_alias_input)

        self.filter_input = QTextEdit()
        self.filter_input.setMaximumHeight(85)
        self.filter_input.setPlaceholderText("Advanced mode: tcp AND tcp.window_size_value > 10000")
        layout.addRow("Local Filter", self.filter_input)

        builder_frame = QFrame()
        builder_frame.setStyleSheet("QFrame { background-color: #fbfbfb; border: 1px solid #e4e4e4; border-radius: 4px; }")
        builder_layout = QVBoxLayout(builder_frame)
        builder_layout.setContentsMargins(8, 8, 8, 8)
        builder_layout.setSpacing(6)

        builder_title = QLabel("Simple Filter Builder")
        builder_title_font = QFont()
        builder_title_font.setBold(True)
        builder_title.setFont(builder_title_font)
        builder_layout.addWidget(builder_title)

        builder_help = QLabel("Build one clause from the Field Catalog, then append it into the advanced filter text using AND/OR.")
        builder_help.setWordWrap(True)
        builder_help.setStyleSheet("color: #666; font-size: 9pt;")
        builder_layout.addWidget(builder_help)

        builder_grid = QGridLayout()
        self.filter_join_combo = _NoWheelComboBox()
        self.filter_join_combo.addItems(self.FILTER_JOINERS)
        builder_grid.addWidget(QLabel("Join"), 0, 0)
        builder_grid.addWidget(self.filter_join_combo, 0, 1)

        self.filter_field_combo = self._create_field_combo()
        builder_grid.addWidget(QLabel("Field"), 1, 0)
        builder_grid.addWidget(self.filter_field_combo, 1, 1)

        self.filter_operator_combo = _NoWheelComboBox()
        self.filter_operator_combo.addItems(self.FILTER_OPERATORS)
        builder_grid.addWidget(QLabel("Operator"), 1, 2)
        builder_grid.addWidget(self.filter_operator_combo, 1, 3)

        self.filter_value_input = QLineEdit()
        self.filter_value_input.setPlaceholderText("Examples: TCP, 10000, 64")
        builder_grid.addWidget(QLabel("Value"), 2, 0)
        builder_grid.addWidget(self.filter_value_input, 2, 1, 1, 3)
        builder_layout.addLayout(builder_grid)

        builder_button_row = QHBoxLayout()
        append_filter_btn = QPushButton("Append Clause")
        append_filter_btn.clicked.connect(self._append_filter_clause)
        builder_button_row.addWidget(append_filter_btn)

        replace_filter_btn = QPushButton("Replace Filter")
        replace_filter_btn.clicked.connect(self._replace_filter_with_clause)
        builder_button_row.addWidget(replace_filter_btn)

        clear_filter_btn = QPushButton("Clear Filter")
        clear_filter_btn.clicked.connect(self._clear_filter)
        builder_button_row.addWidget(clear_filter_btn)
        builder_button_row.addStretch()
        builder_layout.addLayout(builder_button_row)

        self.filter_builder_status_label = QLabel("Builder is ready. Use advanced text directly for complex expressions.")
        self.filter_builder_status_label.setWordWrap(True)
        self.filter_builder_status_label.setStyleSheet("color: #666; font-size: 9pt;")
        builder_layout.addWidget(self.filter_builder_status_label)

        tab_layout.addWidget(builder_frame)

        tail_form = QFormLayout()
        self.sort_field_combo = self._create_field_combo(include_star=False)
        tail_form.addRow("Sort Field", self.sort_field_combo)

        self.sort_direction_combo = _NoWheelComboBox()
        self.sort_direction_combo.addItems(["asc", "desc"])
        tail_form.addRow("Sort Direction", self.sort_direction_combo)

        self.limit_spin = _NoWheelSpinBox()
        self.limit_spin.setRange(0, 5000)
        self.limit_spin.setSpecialValueText("No limit")
        tail_form.addRow("Limit", self.limit_spin)

        self.time_bucket_combo = _NoWheelComboBox()
        self.time_bucket_combo.addItems([bucket or "None" for bucket in self.TIME_BUCKETS])
        tail_form.addRow("Time Bucket", self.time_bucket_combo)

        self._query_controls = {
            "metric_type": (layout.labelForField(self.metric_type_combo), self.metric_type_combo),
            "metric_field": (layout.labelForField(self.metric_field_combo), self.metric_field_combo),
            "metric_alias": (layout.labelForField(self.metric_alias_input), self.metric_alias_input),
            "filter": (layout.labelForField(self.filter_input), self.filter_input),
            "filter_builder": (None, builder_frame),
            "sort_field": (tail_form.labelForField(self.sort_field_combo), self.sort_field_combo),
            "sort_direction": (tail_form.labelForField(self.sort_direction_combo), self.sort_direction_combo),
            "limit": (tail_form.labelForField(self.limit_spin), self.limit_spin),
            "time_bucket": (tail_form.labelForField(self.time_bucket_combo), self.time_bucket_combo),
        }
        tab_layout.addLayout(tail_form)
        tab_layout.addStretch()

        self.tabs.addTab(tab, "Aggregation")

    def _build_style_tab(self):
        tab = QWidget()
        self.style_tab = tab
        layout = QFormLayout(tab)

        self.style_status_label = QLabel("Click a colored part in Preview to unlock color editing.")
        self.style_status_label.setWordWrap(True)
        self.style_status_label.setStyleSheet("color: #666; font-size: 9pt;")
        layout.addRow(self.style_status_label)

        layout.addRow("Metric", self.metric_type_combo)

        self.legend_check = QCheckBox("Show legend")
        layout.addRow("Legend", self.legend_check)

        self.labels_check = QCheckBox("Show data labels")
        layout.addRow("Labels", self.labels_check)

        self.legend_check.setToolTip("Show legend displays the mapping between colors/series and their names.")
        self.labels_check.setToolTip("Show data labels writes the value directly on the bar, slice, point, or segment when the renderer supports it.")
        self.style_options_hint_label = QLabel("Legend shows which color belongs to which category or series. Labels show the value directly on the chart when supported.")
        self.style_options_hint_label.setWordWrap(True)
        self.style_options_hint_label.setStyleSheet("color: #666; font-size: 9pt;")
        layout.addRow(self.style_options_hint_label)

        self.axis_x_label_input = QLineEdit()
        layout.addRow("X Axis Label", self.axis_x_label_input)

        self.axis_y_label_input = QLineEdit()
        layout.addRow("Y Axis Label", self.axis_y_label_input)

        self.unit_input = QLineEdit()
        layout.addRow("Unit", self.unit_input)

        primary_color_row = QHBoxLayout()
        self.primary_color_input = QLineEdit()
        self.primary_color_input.setPlaceholderText("#4e79a7 or red")
        primary_color_row.addWidget(self.primary_color_input, 1)
        self.pick_primary_color_button = QPushButton("Pick Color")
        self.pick_primary_color_button.clicked.connect(self._pick_primary_color)
        primary_color_row.addWidget(self.pick_primary_color_button)
        primary_color_widget = QWidget()
        primary_color_widget.setLayout(primary_color_row)
        layout.addRow("Primary Color", primary_color_widget)

        self.color_palette_input = QLineEdit()
        self.color_palette_input.setPlaceholderText("#4e79a7, #f28e2b, #e15759")
        layout.addRow("Color Palette", self.color_palette_input)

        self._style_controls = {
            "legend": (layout.labelForField(self.legend_check), self.legend_check),
            "labels": (layout.labelForField(self.labels_check), self.labels_check),
            "x_axis_label": (layout.labelForField(self.axis_x_label_input), self.axis_x_label_input),
            "y_axis_label": (layout.labelForField(self.axis_y_label_input), self.axis_y_label_input),
            "unit": (layout.labelForField(self.unit_input), self.unit_input),
            "primary_color": (layout.labelForField(primary_color_widget), primary_color_widget),
            "color_palette": (layout.labelForField(self.color_palette_input), self.color_palette_input),
        }

        self.tabs.addTab(tab, "Style")

    def _create_field_combo(self, include_star: bool = False) -> QComboBox:
        combo = _NoWheelComboBox()
        combo.setEditable(False)
        if include_star:
            combo.addItem("*")
        return combo

    @contextmanager
    def _preview_refresh_batch(self):
        self._preview_refresh_suspend_count += 1
        try:
            yield
        finally:
            self._preview_refresh_suspend_count = max(0, self._preview_refresh_suspend_count - 1)
            if self._preview_refresh_suspend_count == 0 and self._preview_refresh_pending:
                self._preview_refresh_pending = False
                self._preview_timer.start()

    def _pick_primary_color(self):
        initial = QColor(self.primary_color_input.text().strip() or "#4e79a7")
        if not initial.isValid():
            initial = QColor("#4e79a7")
        color = QColorDialog.getColor(initial, self, "Pick Chart Color")
        if color.isValid():
            self.primary_color_input.setText(color.name())

    def _finalize_simplified_editor(self):
        self.simple_source_form.insertRow(3, self.source_primary_axis_label, self.axis_x_label_input)
        self.simple_source_form.insertRow(6, self.source_secondary_axis_label, self.axis_y_label_input)

        for tab_widget in (getattr(self, "mapping_tab", None), getattr(self, "query_tab", None)):
            if tab_widget is None:
                continue
            tab_index = self.tabs.indexOf(tab_widget)
            if tab_index >= 0:
                self.tabs.removeTab(tab_index)

        self._set_control_enabled(*self._style_controls["legend"], False)
        self._set_control_enabled(*self._style_controls["labels"], False)
        self._set_control_enabled(*self._style_controls["x_axis_label"], False)
        self._set_control_enabled(*self._style_controls["y_axis_label"], False)
        self._set_color_editor_active(False)

    def _on_size_preset_changed(self, preset_name: str):
        with self._preview_refresh_batch():
            self._applying_size_preset = True
            try:
                self._apply_size_preset(preset_name)
            finally:
                self._applying_size_preset = False
            self._sync_size_preset(prefer_custom=False)
            self._sync_size_preset_editability()
        self._schedule_preview_refresh()

    def _on_size_dimension_changed(self, _value: int):
        if self._applying_size_preset:
            return
        self._sync_size_preset(prefer_custom=self.size_preset_combo.currentText().strip() == "Custom")
        self._sync_size_preset_editability()

    def _sync_size_preset_editability(self):
        # Presets act as quick-fill shortcuts; keep dimensions editable for fine tuning.
        self.width_spin.setEnabled(True)
        self.height_spin.setEnabled(True)

    def _source_behavior(self, chart_type: str) -> Dict[str, Any]:
        normalized = (chart_type or "").strip().lower()
        if normalized in self.PROPORTION_SOURCE_CHARTS:
            return {
                "mode": "single",
                "single_label": "Category Field",
                "hint": "Pick one category field from the current source. Value can come from metric or built-in numeric fields.",
                "primary_axis_label": "Category Name",
                "secondary_axis_label": "Value Name",
                "swap": False,
                "metric_locked": None,
            }
        if normalized == "metric":
            return {
                "mode": "single",
                "single_label": "Metric Source Field",
                "hint": "Choose one field, then Style decides whether to count, sum, average, get min/max, first or last.",
                "primary_axis_label": "Label",
                "secondary_axis_label": "Value Name",
                "swap": False,
                "metric_locked": None,
            }
        if normalized == "histogram":
            return {
                "mode": "single",
                "single_label": "Numeric Source Field",
                "hint": "Histogram uses one numeric field and automatically builds value buckets.",
                "primary_axis_label": "Bucket Label",
                "secondary_axis_label": "Count Label",
                "swap": False,
                "metric_locked": "none",
            }
        if normalized in {"bar", "horizontal_bar", "heatmap", "table"}:
            return {
                "mode": "double",
                "primary_label": "X Field",
                "secondary_label": "Y Field",
                "hint": "Choose X and Y fields from the selected sources.",
                "primary_axis_label": "X Name",
                "secondary_axis_label": "Y Name",
                "swap": True,
                "metric_locked": None,
            }
        if normalized in {"line", "area", "scatter"}:
            return {
                "mode": "double",
                "primary_label": "X Field",
                "secondary_label": "Y Field",
                "hint": "For 2-axis charts, use time on X when available and choose a numeric Y field.",
                "primary_axis_label": "X Name",
                "secondary_axis_label": "Y Name",
                "swap": True,
                "metric_locked": None,
            }
        return {
            "mode": "double",
            "primary_label": "X Axis Field",
            "secondary_label": "Y Axis Field",
            "hint": "The first field drives the X axis. The second field drives the Y axis. You can rename or swap them here.",
            "primary_axis_label": "X Name",
            "secondary_axis_label": "Y Name",
            "swap": True,
            "metric_locked": None,
        }

    def _set_form_row_visible(self, label: QWidget, field: QWidget, visible: bool):
        label.setVisible(visible)
        field.setVisible(visible)

    def _on_simple_source_changed(self, _value: str):
        with self._preview_refresh_batch():
            self._sync_hidden_controls_from_simple_editor()
            self._refresh_secondary_field_compatibility()
        self._schedule_preview_refresh()

    def _swap_simple_source_fields(self):
        primary = self.primary_source_field_combo.currentText().strip()
        secondary = self.secondary_source_field_combo.currentText().strip()
        with self._preview_refresh_batch():
            self.primary_source_field_combo.blockSignals(True)
            self.secondary_source_field_combo.blockSignals(True)
            self._set_combo_to_text(self.primary_source_field_combo, secondary)
            self._set_combo_to_text(self.secondary_source_field_combo, primary)
            self.primary_source_field_combo.blockSignals(False)
            self.secondary_source_field_combo.blockSignals(False)

            primary_axis_name = self.axis_x_label_input.text()
            secondary_axis_name = self.axis_y_label_input.text()
            self.axis_x_label_input.setText(secondary_axis_name)
            self.axis_y_label_input.setText(primary_axis_name)

            if self._should_group_after_swap(self.primary_source_field_combo.currentText().strip() or None):
                replacement_metric = self._recommended_metric_for_grouping(self.secondary_source_field_combo.currentText().strip() or None)
                self.metric_type_combo.setCurrentText(replacement_metric)
            self._sync_hidden_controls_from_simple_editor()
        self._schedule_preview_refresh()

    def _field_catalog_entry(self, field_id: Optional[str]) -> Optional[Dict[str, Any]]:
        cleaned = str(field_id or "").strip()
        if not cleaned:
            return None
        for entry in self._field_catalog:
            if entry.get("id") == cleaned:
                return entry
        return None

    def _is_numeric_field(self, field_id: Optional[str]) -> bool:
        entry = self._field_catalog_entry(field_id)
        if entry is None:
            return False
        field_type = str(entry.get("type") or "").strip().lower()
        if field_type in {"int", "float"}:
            return True
        return str(entry.get("role") or "").strip().lower() == "metric"

    def _preferred_time_field(self) -> Optional[str]:
        for entry in self._field_catalog:
            if str(entry.get("role") or "").strip().lower() == "time":
                field_id = str(entry.get("id") or "").strip()
                if field_id:
                    return field_id
        for fallback in ["time", "frame.time", "frame.time_epoch", "timestamp"]:
            if self._field_catalog_entry(fallback) is not None:
                return fallback
        return None

    def _preferred_protocol_field(self) -> Optional[str]:
        for candidate in ["protocol", "frame.protocol"]:
            if self._field_catalog_entry(candidate) is not None:
                return candidate
        for entry in self._field_catalog:
            if str(entry.get("role") or "").strip().lower() == "dimension":
                field_id = str(entry.get("id") or "").strip().lower()
                if field_id.endswith("protocol"):
                    return str(entry.get("id") or "").strip()
        return None

    def _is_secondary_field_compatible(self, field_id: Optional[str], chart_type: str) -> bool:
        cleaned = str(field_id or "").strip()
        normalized_chart = str(chart_type or "").strip().lower()
        if not cleaned:
            return True
        if normalized_chart in {"line", "area", "scatter"}:
            primary_field = self.primary_source_field_combo.currentText().strip() if hasattr(self, "primary_source_field_combo") else ""
            if primary_field and cleaned == primary_field:
                return False
            return self._is_numeric_field(cleaned)
        return True

    def _refresh_secondary_field_compatibility(self):
        if not hasattr(self, "secondary_source_field_combo"):
            return

        chart_type = self.visualization_combo.currentText().strip().lower() if hasattr(self, "visualization_combo") else ""
        model = self.secondary_source_field_combo.model()
        current_value = self.secondary_source_field_combo.currentText().strip()
        compatible_values: List[str] = []

        for row in range(self.secondary_source_field_combo.count()):
            field_id = self.secondary_source_field_combo.itemText(row).strip()
            compatible = self._is_secondary_field_compatible(field_id, chart_type)
            if compatible:
                compatible_values.append(field_id)
            if hasattr(model, "item"):
                item = model.item(row)
                if item is not None:
                    item.setEnabled(compatible)

        behavior = self._source_behavior(chart_type)
        enforce_compatibility = behavior.get("mode") == "double" and chart_type in {"line", "area", "scatter"}

        self.secondary_source_field_combo.blockSignals(True)
        if enforce_compatibility and current_value and current_value not in compatible_values:
            if compatible_values:
                self._set_combo_to_text(self.secondary_source_field_combo, compatible_values[0])
            else:
                self.secondary_source_field_combo.setCurrentIndex(-1)

        no_compatible = enforce_compatibility and not compatible_values
        self.secondary_source_field_combo.setEnabled(not no_compatible)
        if no_compatible:
            self.secondary_source_field_label.setEnabled(False)
            self.secondary_source_field_combo.setToolTip("No compatible numeric field for Field 2 with the current chart type.")
        else:
            self.secondary_source_field_label.setEnabled(True)
            self.secondary_source_field_combo.setToolTip("")
        self.secondary_source_field_combo.blockSignals(False)

    def _source_field_catalog_for(self, source_name: str) -> List[Dict[str, Any]]:
        cleaned = str(source_name or "").strip()
        if not cleaned:
            return []
        rows = self._source_rows_by_name.get(cleaned)
        if rows is None:
            rows = self._fetch_source_rows(cleaned)
            self._source_rows_by_name[cleaned] = rows
        return self._build_field_catalog(rows)

    def _source_has_compatible_secondary_fields(self, source_name: str, chart_type: str, primary_field: Optional[str]) -> bool:
        normalized_chart = str(chart_type or "").strip().lower()
        catalog = self._source_field_catalog_for(source_name)
        primary_cleaned = str(primary_field or "").strip()
        if normalized_chart not in {"line", "area", "scatter"}:
            for entry in catalog:
                field_id = str(entry.get("id") or "").strip()
                if field_id and (not primary_cleaned or field_id != primary_cleaned):
                    return True
            return False
        for entry in catalog:
            field_id = str(entry.get("id") or "").strip()
            if not field_id or (primary_cleaned and field_id == primary_cleaned):
                continue
            field_type = str(entry.get("type") or "").strip().lower()
            field_role = str(entry.get("role") or "").strip().lower()
            if field_type in {"int", "float"} or field_role == "metric":
                return True
        return False

    def _refresh_dual_source_compatibility(self):
        if not hasattr(self, "y_data_source_combo"):
            return

        chart_type = self.visualization_combo.currentText().strip().lower() if hasattr(self, "visualization_combo") else ""
        behavior = self._source_behavior(chart_type)
        if behavior.get("mode") != "double":
            self.y_data_source_combo.setEnabled(True)
            self.y_data_source_label.setEnabled(True)
            return

        primary_field = self.primary_source_field_combo.currentText().strip() if hasattr(self, "primary_source_field_combo") else ""
        model = self.y_data_source_combo.model()
        current_source = self.y_data_source_combo.currentText().strip()
        compatible_sources: List[str] = []

        self.y_data_source_combo.blockSignals(True)
        for row in range(self.y_data_source_combo.count()):
            source_name = self.y_data_source_combo.itemText(row).strip()
            compatible = self._source_has_compatible_secondary_fields(source_name, chart_type, primary_field)
            if compatible:
                compatible_sources.append(source_name)
            if hasattr(model, "item"):
                item = model.item(row)
                if item is not None:
                    item.setEnabled(compatible)

        if current_source and current_source not in compatible_sources:
            if compatible_sources:
                self._set_combo_to_text(self.y_data_source_combo, compatible_sources[0])
            else:
                self.y_data_source_combo.setCurrentIndex(-1)

        has_compatible_source = bool(compatible_sources)
        self.y_data_source_combo.setEnabled(has_compatible_source)
        self.y_data_source_label.setEnabled(has_compatible_source)
        self.y_data_source_combo.setToolTip("" if has_compatible_source else "No compatible Y source for current chart and Field 1.")
        self.y_data_source_combo.blockSignals(False)

        dual_sources_visible = behavior.get("mode") == "double"
        self._set_form_row_visible(self.y_data_source_label, self.y_data_source_combo, dual_sources_visible and has_compatible_source)

    def _should_group_after_swap(self, primary_field: Optional[str]) -> bool:
        cleaned = str(primary_field or "").strip()
        if not cleaned:
            return False
        chart_type = self.visualization_combo.currentText().strip().lower()
        if chart_type not in (self.DOUBLE_SOURCE_CHARTS - {"scatter"}):
            return False
        metric_type = self.metric_type_combo.currentText().strip() or "none"
        if metric_type != "none":
            return False
        seen_values = set()
        for row in self._source_rows:
            value = row.get(cleaned)
            if value in seen_values:
                return True
            seen_values.add(value)
        return False

    def _recommended_metric_for_grouping(self, value_field: Optional[str]) -> str:
        entry = self._field_catalog_entry(value_field)
        if entry and entry.get("role") == "metric":
            return "sum"
        return "count"

    def _default_metric_alias(self, metric_type: str, fallback_field: Optional[str]) -> str:
        if metric_type == "count":
            return "count"
        cleaned = str(fallback_field or "value").strip()
        return cleaned.replace(".", "_") or "value"

    def _clear_combo_text(self, combo: QComboBox):
        combo.blockSignals(True)
        combo.setCurrentIndex(-1)
        combo.blockSignals(False)

    def _preferred_single_source_total_field(self, detail_field: Optional[str], current_value_field: Optional[str]) -> Optional[str]:
        field_ids = {entry["id"] for entry in self._field_catalog}
        current_value = str(current_value_field or "").strip()
        detail = str(detail_field or "").strip()

        if current_value and current_value in field_ids and current_value != detail:
            return current_value

        preferred_names = ["packets", "count", "bytes", "length", "frame.len"]
        for name in preferred_names:
            if name in field_ids and name != detail:
                return name
        return None

    def _sheet_preview_header_map(self, rows: List[Dict[str, Any]]) -> Dict[str, str]:
        if not rows:
            return {}
        chart_type = self.visualization_combo.currentText().strip().lower()
        style = dict(self._working_copy.style or {})
        visualization = self._working_copy.visualization
        headers: Dict[str, str] = {}

        x_label = style.get("x_axis_label") or ""
        y_label = style.get("y_axis_label") or ""

        if chart_type in self.PROPORTION_SOURCE_CHARTS:
            category_key = visualization.category_field or self.primary_source_field_combo.currentText().strip() or "source"
            headers[category_key] = x_label or category_key
            headers["total"] = y_label or visualization.value_field or "total"
            headers["%"] = "%"
            return headers

        key_pairs = [
            (visualization.category_field, x_label),
            (visualization.x_field, x_label),
            (visualization.value_field, y_label),
            (visualization.y_field, y_label),
        ]
        for key, label in key_pairs:
            cleaned_key = str(key or "").strip()
            cleaned_label = str(label or "").strip()
            if cleaned_key and cleaned_label:
                headers[cleaned_key] = cleaned_label
        return headers

    def _apply_sheet_preview_headers(self, rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        header_map = self._sheet_preview_header_map(rows)
        if not rows or not header_map:
            return rows

        renamed_rows: List[Dict[str, Any]] = []
        for row in rows:
            renamed_row: Dict[str, Any] = {}
            for key, value in row.items():
                display_key = header_map.get(key, key)
                suffix = 2
                original_display_key = display_key
                while display_key in renamed_row:
                    display_key = f"{original_display_key} {suffix}"
                    suffix += 1
                renamed_row[display_key] = value
            renamed_rows.append(renamed_row)
        return renamed_rows

    def _sync_hidden_controls_from_simple_editor(self):
        chart_type = self.visualization_combo.currentText().strip().lower()
        behavior = self._source_behavior(chart_type)
        metric_type = self.metric_type_combo.currentText().strip() or "none"
        single_field = self.single_source_field_combo.currentText().strip() or None
        primary_field = self.primary_source_field_combo.currentText().strip() or None
        secondary_field = self.secondary_source_field_combo.currentText().strip() or None
        preferred_time_field = self._preferred_time_field()
        protocol_series_field = self._preferred_protocol_field() if chart_type in {"line", "area"} else None
        selected_source = self.data_source_combo.currentText().strip() or None
        working_copy_source = getattr(self._working_copy, "data_source", None)
        fallback_value_field = self._working_copy.visualization.value_field if selected_source and working_copy_source == selected_source else None
        current_value_field = self.value_field_combo.currentText().strip() or fallback_value_field or None

        locked_metric = behavior.get("metric_locked")
        if locked_metric is not None and metric_type != locked_metric:
            self.metric_type_combo.blockSignals(True)
            self.metric_type_combo.setCurrentText(locked_metric)
            self.metric_type_combo.blockSignals(False)
            metric_type = locked_metric

        metric_alias = self._default_metric_alias(metric_type, secondary_field or single_field)
        self.metric_alias_input.setText(metric_alias)
        self.columns_input.setText("")
        self.group_by_input.setText("")
        self._clear_combo_text(self.x_field_combo)
        self._clear_combo_text(self.y_field_combo)
        self._clear_combo_text(self.category_field_combo)
        self._clear_combo_text(self.value_field_combo)
        self._clear_combo_text(self.series_field_combo)
        self._clear_combo_text(self.metric_field_combo)

        if chart_type in self.PROPORTION_SOURCE_CHARTS:
            if chart_type in self.HIERARCHY_PROTOCOL_CHARTS:
                category_field = single_field or primary_field or "conversation"
                protocol_field = self._preferred_protocol_field()
                direct_total_field = self._preferred_single_source_total_field(category_field, current_value_field)
                self._set_combo_to_text(self.category_field_combo, category_field or "")
                self._set_combo_to_text(self.series_field_combo, protocol_field or "protocol")
                self.metric_type_combo.blockSignals(True)
                self.metric_type_combo.setCurrentText("none")
                self.metric_type_combo.blockSignals(False)
                self._set_combo_to_text(self.value_field_combo, direct_total_field or current_value_field or "packets")
                self.group_by_input.setText("")
                selected_columns = [field for field in [category_field, protocol_field, direct_total_field or current_value_field or "packets"] if field]
                self.columns_input.setText(", ".join(dict.fromkeys(selected_columns)))
                return
            category_field = single_field or primary_field
            direct_total_field = self._preferred_single_source_total_field(category_field, current_value_field)
            self._set_combo_to_text(self.category_field_combo, category_field or "")
            if metric_type == "none" and direct_total_field:
                self.metric_type_combo.blockSignals(True)
                self.metric_type_combo.setCurrentText("none")
                self.metric_type_combo.blockSignals(False)
                self._set_combo_to_text(self.value_field_combo, direct_total_field)
                self.columns_input.setText(", ".join([field for field in [category_field, direct_total_field] if field]))
            else:
                metric_field = "*" if metric_type == "count" else (current_value_field or "*")
                self._set_combo_to_text(self.metric_field_combo, metric_field)
                self._set_combo_to_text(self.value_field_combo, metric_alias)
                self.group_by_input.setText(category_field or "")
                self.columns_input.setText(", ".join([field for field in [category_field, metric_alias] if field]))
            return

        if chart_type == "histogram":
            self.metric_type_combo.setCurrentText("none")
            self._set_combo_to_text(self.value_field_combo, single_field or "")
            self.columns_input.setText(single_field or "")
            return

        if chart_type == "metric":
            metric_field = "*" if metric_type == "count" else (single_field or "*")
            self._set_combo_to_text(self.metric_field_combo, metric_field)
            self._set_combo_to_text(self.value_field_combo, metric_alias)
            self.columns_input.setText(metric_alias)
            return

        if chart_type in {"bar", "horizontal_bar", "heatmap", "table"}:
            self._set_combo_to_text(self.category_field_combo, primary_field or "")
            if metric_type == "none":
                self._set_combo_to_text(self.value_field_combo, secondary_field or "")
                plotted_value = secondary_field
            else:
                self._set_combo_to_text(self.metric_field_combo, "*" if metric_type == "count" else (secondary_field or "*"))
                self._set_combo_to_text(self.value_field_combo, metric_alias)
                self.group_by_input.setText(primary_field or "")
                plotted_value = metric_alias
            selected_columns = [field for field in [primary_field, plotted_value] if field]
            self.columns_input.setText(", ".join(selected_columns))
            return

        effective_primary_field = primary_field or (preferred_time_field if chart_type in {"line", "area", "scatter"} else None)
        secondary_is_numeric = self._is_numeric_field(secondary_field)
        self._set_combo_to_text(self.x_field_combo, effective_primary_field or "")
        if chart_type in {"line", "area"}:
            self._set_combo_to_text(self.series_field_combo, protocol_series_field or "")
        if chart_type in {"line", "area"} and secondary_field and not secondary_is_numeric:
            self.metric_type_combo.blockSignals(True)
            self.metric_type_combo.setCurrentText("count")
            self.metric_type_combo.blockSignals(False)
            self.metric_alias_input.setText("count")
            self._set_combo_to_text(self.metric_field_combo, "*")
            self._set_combo_to_text(self.y_field_combo, "count")
            self._set_combo_to_text(self.value_field_combo, "count")
            grouped_fields = [field for field in [effective_primary_field, protocol_series_field] if field]
            self.group_by_input.setText(", ".join(grouped_fields))
            selected_columns = [field for field in [effective_primary_field, protocol_series_field, "count"] if field]
            if preferred_time_field and preferred_time_field not in selected_columns:
                selected_columns.insert(0, preferred_time_field)
            self.columns_input.setText(", ".join(selected_columns))
            return

        if metric_type == "none" or chart_type == "scatter":
            self._set_combo_to_text(self.y_field_combo, secondary_field or "")
            self._set_combo_to_text(self.value_field_combo, secondary_field or "")
            plotted_value = secondary_field
        else:
            self._set_combo_to_text(self.metric_field_combo, "*" if metric_type == "count" else (secondary_field or "*"))
            self._set_combo_to_text(self.y_field_combo, metric_alias)
            self._set_combo_to_text(self.value_field_combo, metric_alias)
            grouped_fields = [field for field in [effective_primary_field, protocol_series_field] if field] if chart_type in {"line", "area"} else [effective_primary_field]
            self.group_by_input.setText(", ".join([field for field in grouped_fields if field]))
            plotted_value = metric_alias
        selected_columns = [field for field in [effective_primary_field, plotted_value] if field]
        if chart_type in {"line", "area"} and protocol_series_field and protocol_series_field not in selected_columns:
            selected_columns.append(protocol_series_field)
        if chart_type in {"line", "area", "scatter"} and preferred_time_field and preferred_time_field not in selected_columns:
            selected_columns.insert(0, preferred_time_field)
        self.columns_input.setText(", ".join(selected_columns))

    def _sync_simple_controls_from_working_copy(self):
        chart_type = (self.visualization_combo.currentText() or self.widget_model.visualization.type or "").strip().lower()
        query = self._working_copy.query
        visualization = self._working_copy.visualization
        metric = query.metrics[0] if query.metrics else None

        if chart_type in self.HIERARCHY_PROTOCOL_CHARTS:
            source_field = visualization.category_field or ((query.columns or [""])[0] if query.columns else "")
            self._set_combo_to_text(self.single_source_field_combo, source_field)
            return
        if chart_type in self.PROPORTION_SOURCE_CHARTS:
            source_field = visualization.category_field or ((query.group_by or [""])[0])
            self._set_combo_to_text(self.single_source_field_combo, source_field)
        elif chart_type == "histogram":
            self._set_combo_to_text(self.single_source_field_combo, visualization.value_field or "")
        elif chart_type == "metric":
            metric_field = "" if metric is None or metric.field == "*" else metric.field
            self._set_combo_to_text(self.single_source_field_combo, metric_field)
        elif chart_type in {"bar", "horizontal_bar", "heatmap", "table"}:
            self._set_combo_to_text(self.primary_source_field_combo, visualization.category_field or ((query.group_by or [""])[0]))
            secondary_value = metric.field if metric is not None and metric.field != "*" else (visualization.value_field or "")
            self._set_combo_to_text(self.secondary_source_field_combo, secondary_value)
        else:
            self._set_combo_to_text(self.primary_source_field_combo, visualization.x_field or self._preferred_time_field() or "")
            secondary_value = metric.field if metric is not None and metric.field != "*" else (visualization.y_field or visualization.value_field or "")
            self._set_combo_to_text(self.secondary_source_field_combo, secondary_value)

    def _chart_supports_color(self, chart_type: str) -> bool:
        return chart_type in {"bar", "horizontal_bar", "line", "area", "scatter", "radar", "treemap", "sunburst", "pie", "donut", "histogram", "heatmap"}

    def _chart_supports_palette(self, chart_type: str) -> bool:
        return chart_type in {"pie", "donut", "treemap", "sunburst"}

    def _chart_supports_metric(self, chart_type: str) -> bool:
        return chart_type not in {"histogram", "scatter"} and chart_type != ""

    def _set_color_editor_active(self, active: bool):
        chart_type = self.visualization_combo.currentText().strip().lower()
        supports_color = self._chart_supports_color(chart_type)
        supports_palette = self._chart_supports_palette(chart_type)
        self._color_editor_active = bool(active and supports_color)
        self.primary_color_input.setEnabled(self._color_editor_active)
        self.pick_primary_color_button.setEnabled(self._color_editor_active)
        self.color_palette_input.setEnabled(self._color_editor_active and supports_palette)
        if not supports_color:
            self.style_status_label.setText("This chart does not expose color editing.")
        elif self._color_editor_active:
            self.style_status_label.setText("Color editing unlocked from Preview. Change Primary Color or Color Palette here.")
        else:
            self.style_status_label.setText("Click a colored part in Preview to unlock color editing.")

    def _install_preview_activation_handlers(self, widget: QWidget):
        for target in self._preview_click_targets:
            try:
                target.removeEventFilter(self)
            except Exception:
                pass
        self._preview_click_targets = []
        if widget is None:
            return
        for target in [widget] + widget.findChildren(QWidget):
            target.installEventFilter(self)
            self._preview_click_targets.append(target)

    def eventFilter(self, watched, event):
        if watched in self._preview_click_targets and event.type() == QEvent.MouseButtonPress:
            self._set_color_editor_active(True)
        return super().eventFilter(watched, event)

    def _chart_capability(self, chart_type: str) -> Dict[str, Any]:
        capability = dict(self.DEFAULT_CHART_CAPABILITY)
        specific = self.CHART_CAPABILITIES.get((chart_type or "").strip().lower(), {})
        for key, value in specific.items():
            if isinstance(value, set):
                capability[key] = set(value)
            elif isinstance(value, list):
                capability[key] = list(value)
            else:
                capability[key] = value
        return capability

    def _set_control_enabled(self, label: Optional[QWidget], widget: QWidget, enabled: bool):
        if label is not None:
            label.setEnabled(enabled)
        widget.setEnabled(enabled)

    def _enabled_chart_assignment_targets(self, capability: Dict[str, Any]) -> List[str]:
        return [
            target
            for target in capability.get("assignment_targets", [])
            if target in self.ASSIGNMENT_LABELS
        ]

    def _refresh_assignment_targets(self, capability: Dict[str, Any]):
        available_targets = self._enabled_chart_assignment_targets(capability)
        current_target = self.assignment_target_combo.currentData() if hasattr(self, "assignment_target_combo") else None
        self.assignment_target_combo.blockSignals(True)
        self.assignment_target_combo.clear()
        for target in available_targets:
            self.assignment_target_combo.addItem(self.ASSIGNMENT_LABELS[target], target)
        self.assignment_target_combo.blockSignals(False)

        if current_target in available_targets:
            self.assignment_target_combo.setCurrentIndex(available_targets.index(current_target))
        elif available_targets:
            self.assignment_target_combo.setCurrentIndex(0)

        self._update_assignment_ui()

    def _update_assignment_ui(self):
        if not hasattr(self, "assignment_target_combo"):
            return
        target = self.assignment_target_combo.currentData()
        selected_field = self._selected_field_id()
        target_label = self.assignment_target_combo.currentText().strip() or "Current Target"
        self.assign_selected_field_button.setEnabled(bool(target and selected_field))
        self.assign_selected_field_button.setText(f"Assign to {target_label}" if target else "Assign Field")

    def _apply_chart_type_capabilities(self):
        chart_type = self.visualization_combo.currentText().strip().lower() or self.widget_model.visualization.type
        capability = self._chart_capability(chart_type)
        behavior = self._source_behavior(chart_type)
        preserve_color_state = self._color_editor_active and self._chart_supports_color(chart_type)

        mapping_controls = capability.get("mapping_controls", set())
        query_controls = capability.get("query_controls", set())
        style_controls = capability.get("style_controls", set())

        for control_name, (label, widget) in self._mapping_controls.items():
            self._set_control_enabled(label, widget, control_name in mapping_controls)
        for control_name, (label, widget) in self._query_controls.items():
            self._set_control_enabled(label, widget, control_name in query_controls)
        for control_name, (label, widget) in self._style_controls.items():
            self._set_control_enabled(label, widget, control_name in style_controls)

        self._set_form_row_visible(self.single_source_field_label, self.single_source_field_combo, behavior["mode"] == "single")
        self._set_form_row_visible(self.primary_source_field_label, self.primary_source_field_combo, behavior["mode"] == "double")
        self._set_form_row_visible(self.secondary_source_field_label, self.secondary_source_field_combo, behavior["mode"] == "double")
        dual_sources_visible = behavior["mode"] == "double"
        self._set_form_row_visible(self.data_source_label, self.data_source_combo, behavior["mode"] == "single")
        self._set_form_row_visible(self.x_data_source_label, self.x_data_source_combo, dual_sources_visible)
        self._set_form_row_visible(self.y_data_source_label, self.y_data_source_combo, dual_sources_visible)
        self._set_form_row_visible(self.source_primary_axis_label, self.axis_x_label_input, dual_sources_visible)
        self._set_form_row_visible(self.source_secondary_axis_label, self.axis_y_label_input, dual_sources_visible)
        self._set_form_row_visible(self.swap_axes_label, self.swap_axes_button.parentWidget(), behavior.get("swap", False) and behavior["mode"] == "double")
        self.swap_axes_button.setEnabled(bool(behavior.get("swap", False)))
        self.single_source_field_label.setText(behavior.get("single_label", "Source Field"))
        self.primary_source_field_label.setText(behavior.get("primary_label", "Primary Field"))
        self.secondary_source_field_label.setText(behavior.get("secondary_label", "Secondary Field"))
        self.source_primary_axis_label.setText(behavior.get("primary_axis_label", "Primary Axis Name"))
        self.source_secondary_axis_label.setText(behavior.get("secondary_axis_label", "Secondary Axis Name"))
        self.source_tab_hint_label.setText(behavior.get("hint") or "Choose the fields that should be drawn.")

        self.metric_type_combo.setEnabled(self._chart_supports_metric(chart_type) and behavior.get("metric_locked") is None)
        self.unit_input.setEnabled("unit" in style_controls)

        is_table_chart = chart_type == "table"
        self.display_mode_combo.blockSignals(True)
        if is_table_chart:
            self.display_mode_combo.setCurrentText("Table")
        else:
            self.display_mode_combo.setCurrentText("Chart")
        self.display_mode_combo.setEnabled(not is_table_chart)
        self.display_mode_combo.blockSignals(False)

        self.field_assignment_hint_label.setText(capability.get("summary") or "The selected chart type decides where this field can be assigned.")
        self._refresh_assignment_targets(capability)
        self._sync_size_preset_editability()
        self._set_color_editor_active(preserve_color_state)
        with self._preview_refresh_batch():
            self._sync_hidden_controls_from_simple_editor()
            self._refresh_secondary_field_compatibility()
            self._refresh_dual_source_compatibility()

    def _on_chart_type_changed(self, _chart_type: str):
        with self._preview_refresh_batch():
            self._apply_chart_type_capabilities()
        self._schedule_preview_refresh()

    def _connect_live_preview_signals(self):
        watched_widgets = [
            self.title_input,
            self.description_input,
            self.visualization_combo,
            self.width_spin,
            self.height_spin,
            self.size_preset_combo,
            self.display_mode_combo,
            self.data_source_combo,
            self.x_data_source_combo,
            self.y_data_source_combo,
            self.single_source_field_combo,
            self.primary_source_field_combo,
            self.secondary_source_field_combo,
            self.x_field_combo,
            self.y_field_combo,
            self.category_field_combo,
            self.value_field_combo,
            self.series_field_combo,
            self.group_by_input,
            self.columns_input,
            self.metric_type_combo,
            self.metric_field_combo,
            self.metric_alias_input,
            self.filter_input,
            self.sort_field_combo,
            self.sort_direction_combo,
            self.limit_spin,
            self.time_bucket_combo,
            self.legend_check,
            self.labels_check,
            self.axis_x_label_input,
            self.axis_y_label_input,
            self.unit_input,
            self.primary_color_input,
            self.color_palette_input,
        ]
        for widget in watched_widgets:
            if isinstance(widget, (QLineEdit, QTextEdit)):
                widget.textChanged.connect(self._schedule_preview_refresh)
            elif isinstance(widget, QComboBox):
                widget.currentTextChanged.connect(self._schedule_preview_refresh)
            elif isinstance(widget, QSpinBox):
                widget.valueChanged.connect(self._schedule_preview_refresh)
            elif isinstance(widget, QCheckBox):
                widget.toggled.connect(self._schedule_preview_refresh)

    def _populate_controls(self):
        with self._preview_refresh_batch():
            working = self._working_copy
            visualization = working.visualization
            query = working.query
            style = dict(working.style or {})

            self.title_input.setText(working.title or "")
            self.description_input.setPlainText(working.description or "")
            self._set_combo_to_text(self.visualization_combo, visualization.type or "")
            self.width_spin.setValue(max(1, int(working.layout.w or 1)))
            self.height_spin.setValue(max(1, int(working.layout.h or 1)))
            self._sync_size_preset()
            self._sync_size_preset_editability()
            self.display_mode_combo.setCurrentText("Table" if style.get("display_mode") == "table" else "Chart")

            self._set_combo_to_text(self.data_source_combo, working.data_source or "")
            self._set_combo_to_text(self.x_data_source_combo, str(style.get("x_data_source") or working.data_source or ""))
            self._set_combo_to_text(self.y_data_source_combo, str(style.get("y_data_source") or working.data_source or ""))
            self._set_combo_to_text(self.x_field_combo, visualization.x_field or "")
            self._set_combo_to_text(self.y_field_combo, visualization.y_field or "")
            self._set_combo_to_text(self.category_field_combo, visualization.category_field or "")
            self._set_combo_to_text(self.value_field_combo, visualization.value_field or "")
            self._set_combo_to_text(self.series_field_combo, visualization.series_field or "")

            self.group_by_input.setText(", ".join(query.group_by or []))
            self.columns_input.setText(", ".join(query.columns or []))

            metric = query.metrics[0] if query.metrics else None
            if metric is not None:
                self._set_combo_to_text(self.metric_type_combo, metric.type)
                self._set_combo_to_text(self.metric_field_combo, metric.field)
                self.metric_alias_input.setText(metric.as_ or "")
            else:
                self.metric_type_combo.setCurrentText("none")
                self.metric_alias_input.setText(visualization.value_field or "value")

            self.filter_input.setPlainText(query.filter or "")
            self._sync_simple_filter_builder_from_text(query.filter or "")
            sort = query.sort[0] if query.sort else None
            if sort is not None:
                self._set_combo_to_text(self.sort_field_combo, sort.field)
                self._set_combo_to_text(self.sort_direction_combo, sort.direction)
            self.limit_spin.setValue(int(query.limit or 0))
            self._set_combo_to_text(self.time_bucket_combo, query.time_bucket or "None")

            self.legend_check.setChecked(bool(visualization.show_legend))
            self.labels_check.setChecked(bool(visualization.show_labels))
            self.axis_x_label_input.setText(str(style.get("x_axis_label") or ""))
            self.axis_y_label_input.setText(str(style.get("y_axis_label") or ""))
            self.unit_input.setText(str(style.get("unit") or ""))
            self.primary_color_input.setText(str(style.get("primary_color") or ""))
            self.color_palette_input.setText(str(style.get("color_palette") or ""))
            self._load_source(working.data_source)
            self._sync_simple_controls_from_working_copy()
            self._apply_chart_type_capabilities()

    def _set_combo_to_text(self, combo: QComboBox, text: str):
        cleaned = str(text or "").strip()
        if not cleaned:
            combo.setCurrentIndex(-1)
            return
        index = combo.findText(cleaned)
        if index < 0:
            combo.addItem(cleaned)
            index = combo.findText(cleaned)
        combo.setCurrentIndex(index)

    def _apply_size_preset(self, preset_name: str):
        preset = self.SIZE_PRESETS.get(preset_name)
        if preset is None:
            return
        width, height = preset
        self.width_spin.setValue(width)
        self.height_spin.setValue(height)

    def _sync_size_preset(self, *, prefer_custom: bool = False):
        current = (self.width_spin.value(), self.height_spin.value())
        target_label = "Custom"
        if not prefer_custom:
            for label, preset in self.SIZE_PRESETS.items():
                if preset == current:
                    target_label = label
                    break
        self.size_preset_combo.blockSignals(True)
        self.size_preset_combo.setCurrentText(target_label)
        self.size_preset_combo.blockSignals(False)

    def _on_source_changed(self, source_name: str):
        self.x_data_source_combo.blockSignals(True)
        self.y_data_source_combo.blockSignals(True)
        self._set_combo_to_text(self.x_data_source_combo, source_name)
        self._set_combo_to_text(self.y_data_source_combo, source_name)
        self.x_data_source_combo.blockSignals(False)
        self.y_data_source_combo.blockSignals(False)
        with self._preview_refresh_batch():
            self._load_source(source_name)
            self._sync_hidden_controls_from_simple_editor()
            self._refresh_dual_source_compatibility()
        self._schedule_preview_refresh()

    def _on_dual_source_changed(self, _source_name: str):
        with self._preview_refresh_batch():
            self._load_source(self.data_source_combo.currentText().strip())
            self._sync_hidden_controls_from_simple_editor()
            self._refresh_dual_source_compatibility()
        self._schedule_preview_refresh()

    def _active_field_sources(self, default_source: Optional[str] = None) -> List[str]:
        chart_type = self.visualization_combo.currentText().strip().lower() if hasattr(self, "visualization_combo") else ""
        behavior = self._source_behavior(chart_type)
        if behavior.get("mode") == "double":
            x_source = self.x_data_source_combo.currentText().strip() if hasattr(self, "x_data_source_combo") else ""
            y_source = self.y_data_source_combo.currentText().strip() if hasattr(self, "y_data_source_combo") else ""
            ordered = [x_source, y_source, default_source or self.data_source_combo.currentText().strip()]
        else:
            ordered = [default_source or self.data_source_combo.currentText().strip()]

        resolved: List[str] = []
        seen = set()
        for source_name in ordered:
            cleaned = str(source_name or "").strip()
            if not cleaned or cleaned in seen:
                continue
            seen.add(cleaned)
            resolved.append(cleaned)
        return resolved

    def _load_source(self, source_name: str):
        active_sources = self._active_field_sources(source_name)
        self._source_rows_by_name = {}
        merged_rows: List[Dict[str, Any]] = []
        for active_source in active_sources:
            rows = self._fetch_source_rows(active_source)
            self._source_rows_by_name[active_source] = rows
            merged_rows.extend(rows)
        self._source_rows = merged_rows
        self._field_catalog = self._build_field_catalog(self._source_rows)
        self._refresh_field_filter_options()
        self._refresh_field_combo_items()
        self._refresh_field_list()

    def _fetch_source_rows(self, source_name: str) -> List[Dict[str, Any]]:
        if not self.query_engine or not getattr(self.query_engine, "registry", None):
            return []
        try:
            fetcher = self.query_engine.registry.get_fetcher(source_name)
        except Exception:
            fetcher = None
        if fetcher is None:
            return []
        try:
            rows = fetcher(limit=500) or []
        except TypeError:
            try:
                rows = fetcher() or []
            except Exception:
                return []
        except Exception:
            return []
        return list(rows)[:500]

    def _field_group(self, field_id: str) -> str:
        cleaned = str(field_id or "")
        if "." in cleaned:
            return cleaned.split(".", 1)[0]
        known_prefixes = {"frame", "eth", "arp", "ip", "ipv6", "tcp", "udp", "icmp", "dns", "http", "tls"}
        prefix = cleaned.split("_", 1)[0]
        if prefix in known_prefixes:
            return prefix
        return "packet"

    def _field_role(self, field_id: str, field_type: str) -> str:
        lowered = str(field_id or "").lower()
        if field_type == "bool" or "flag" in lowered:
            return "flag"
        if "time" in lowered or lowered.startswith("frame.time") or lowered.endswith("_time"):
            return "time"
        dimension_markers = (
            "stream",
            "port",
            "frame.number",
            "number",
            "index",
            ".id",
            "_id",
            "ttl",
            "hlim",
            "hop_limit",
        )
        if any(marker in lowered for marker in dimension_markers):
            return "dimension"
        metric_markers = (
            "latency",
            "delta",
            "bytes",
            "length",
            "size",
            "window",
            "count",
            "rate",
        )
        if any(marker in lowered for marker in metric_markers):
            return "metric"
        if field_type in {"int", "float"}:
            return "metric"
        return "dimension"

    def _build_field_catalog(self, rows: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        summary: Dict[str, Dict[str, Any]] = {}
        total_rows = len(rows)

        for shared_field in self.CORE_SHARED_FIELDS:
            summary[shared_field] = {
                "id": shared_field,
                "name": shared_field.replace("_", " ").replace(".", " ").title(),
                "present_count": 0,
                "samples": [],
                "types": {"float" if shared_field == "time" else ("int" if shared_field in {"bytes", "packets", "packet"} else "string")},
            }

        for row in rows:
            for key, value in row.items():
                entry = summary.setdefault(
                    key,
                    {
                        "id": key,
                        "name": key.replace("_", " ").replace(".", " ").title(),
                        "present_count": 0,
                        "samples": [],
                        "types": set(),
                    },
                )
                entry["present_count"] += 1
                if value is not None and len(entry["samples"]) < 4:
                    rendered = str(value)
                    if rendered not in entry["samples"]:
                        entry["samples"].append(rendered)
                if isinstance(value, bool):
                    entry["types"].add("bool")
                elif isinstance(value, int):
                    entry["types"].add("int")
                elif isinstance(value, float):
                    entry["types"].add("float")
                elif value is None:
                    entry["types"].add("null")
                else:
                    entry["types"].add("string")

        catalog = []
        for entry in summary.values():
            field_type = "string"
            types = entry["types"]
            if "float" in types:
                field_type = "float"
            elif "int" in types:
                field_type = "int"
            elif "bool" in types:
                field_type = "bool"
            entry["type"] = field_type
            entry["group"] = self._field_group(entry["id"])
            entry["role"] = self._field_role(entry["id"], field_type)
            entry["present_ratio"] = f"{entry['present_count']}/{max(1, total_rows)}"
            catalog.append(entry)

        shared_rank = {field: idx for idx, field in enumerate(self.CORE_SHARED_FIELDS)}
        return sorted(
            catalog,
            key=lambda item: (
                0 if item["id"] in shared_rank else 1,
                shared_rank.get(item["id"], 999),
                item["group"],
                item["role"],
                item["id"],
            ),
        )

    def _refresh_field_filter_options(self):
        current_group = self.field_group_filter_combo.currentText().strip() if hasattr(self, "field_group_filter_combo") else ""
        groups = ["All Groups"] + sorted({entry["group"] for entry in self._field_catalog})
        self.field_group_filter_combo.blockSignals(True)
        self.field_group_filter_combo.clear()
        self.field_group_filter_combo.addItems(groups)
        self.field_group_filter_combo.blockSignals(False)
        if current_group and current_group in groups:
            self.field_group_filter_combo.setCurrentText(current_group)
        else:
            self.field_group_filter_combo.setCurrentText("All Groups")

    def _refresh_field_combo_items(self):
        field_ids = [entry["id"] for entry in self._field_catalog]
        combos = [
            self.single_source_field_combo,
            self.primary_source_field_combo,
            self.secondary_source_field_combo,
            self.x_field_combo,
            self.y_field_combo,
            self.category_field_combo,
            self.value_field_combo,
            self.series_field_combo,
            self.metric_field_combo,
            self.sort_field_combo,
            self.filter_field_combo,
        ]
        for combo in combos:
            current_text = combo.currentText().strip()
            combo.blockSignals(True)
            combo.clear()
            if combo is self.metric_field_combo:
                combo.addItem("*")
            combo.addItems(field_ids)
            keep_current = current_text and (current_text in field_ids or (combo is self.metric_field_combo and current_text == "*"))
            if keep_current:
                self._set_combo_to_text(combo, current_text)
            else:
                combo.setCurrentIndex(-1)
            combo.blockSignals(False)
        self._refresh_secondary_field_compatibility()
        self._refresh_dual_source_compatibility()

    def _refresh_field_list(self):
        term = (self.field_search_input.text() or "").strip().lower()
        selected_group = self.field_group_filter_combo.currentText().strip()
        selected_role = self.field_role_filter_combo.currentText().strip().lower()
        self.field_list.clear()
        for entry in self._field_catalog:
            haystack = " ".join([
                entry["id"],
                entry["name"],
                entry["group"],
                entry["role"],
                " ".join(entry["samples"]),
            ]).lower()
            if term and term not in haystack:
                continue
            if selected_group and selected_group != "All Groups" and entry["group"] != selected_group:
                continue
            if selected_role and selected_role != "all roles" and entry["role"] != selected_role:
                continue
            item = QListWidgetItem(f"[{entry['group']}] {entry['id']}   [{entry['role']}/{entry['type']}]")
            item.setData(Qt.UserRole, entry)
            self.field_list.addItem(item)
        if self.field_list.count() > 0:
            self.field_list.setCurrentRow(0)
        else:
            self.field_details_label.setText("No fields matched the current search/filter.")

    def _on_field_selected(self, current: Optional[QListWidgetItem], _previous: Optional[QListWidgetItem] = None):
        if current is None:
            self.field_details_label.setText("Select a field to inspect metadata, group, role, and sample values.")
            self._update_assignment_ui()
            return
        entry = current.data(Qt.UserRole) or {}
        details = [
            f"Field ID: {entry.get('id', '-')}",
            f"Group: {entry.get('group', '-')}",
            f"Role: {entry.get('role', '-')}",
            f"Type: {entry.get('type', '-')}",
            f"Present in: {entry.get('present_ratio', '-')}",
            f"Sample values: {', '.join(entry.get('samples', [])) or '-'}",
        ]
        self.field_details_label.setText("\n".join(details))
        self._update_assignment_ui()

    def _selected_field_id(self) -> Optional[str]:
        item = self.field_list.currentItem()
        if item is None:
            return None
        entry = item.data(Qt.UserRole) or {}
        return str(entry.get("id") or "").strip() or None

    def _assign_selected_field(self, combo: QComboBox):
        selected_field = self._selected_field_id()
        if not selected_field:
            return
        self._set_combo_to_text(combo, selected_field)
        self._schedule_preview_refresh()

    def _assign_selected_field_to_current_target(self):
        target = self.assignment_target_combo.currentData() if hasattr(self, "assignment_target_combo") else None
        if not target:
            return
        if target == "x_field":
            self._assign_selected_field(self.x_field_combo)
        elif target == "y_field":
            self._assign_selected_field(self.y_field_combo)
        elif target == "category_field":
            self._assign_selected_field(self.category_field_combo)
        elif target == "value_field":
            self._assign_selected_field(self.value_field_combo)
        elif target == "series_field":
            self._assign_selected_field(self.series_field_combo)
        elif target == "metric_field":
            self._assign_selected_field(self.metric_field_combo)
        elif target == "group_by":
            self._assign_group_by()
            self._schedule_preview_refresh()
        elif target == "sort_field":
            self._assign_selected_field(self.sort_field_combo)
        elif target == "columns":
            self._append_selected_column()
            self._schedule_preview_refresh()
        elif target == "filter_field":
            self._set_filter_field_from_selected()

    def _assign_group_by(self):
        selected_field = self._selected_field_id()
        if not selected_field:
            return
        current_fields = [field.strip() for field in self.group_by_input.text().split(",") if field.strip()]
        if selected_field not in current_fields:
            current_fields.append(selected_field)
        self.group_by_input.setText(", ".join(current_fields))

    def _append_selected_column(self):
        selected_field = self._selected_field_id()
        if not selected_field:
            return
        current_fields = [field.strip() for field in self.columns_input.text().split(",") if field.strip()]
        if selected_field not in current_fields:
            current_fields.append(selected_field)
        self.columns_input.setText(", ".join(current_fields))

    def _set_filter_field_from_selected(self):
        selected_field = self._selected_field_id()
        if not selected_field:
            return
        self._set_combo_to_text(self.filter_field_combo, selected_field)
        self.filter_builder_status_label.setText(f"Builder field set to '{selected_field}'.")

    def _format_filter_clause(self) -> Optional[str]:
        field_name = self.filter_field_combo.currentText().strip()
        operator = self.filter_operator_combo.currentText().strip()
        value = self.filter_value_input.text().strip()
        if not field_name or not operator or not value:
            return None
        return f"({field_name} {operator} {value})"

    def _append_filter_clause(self):
        clause = self._format_filter_clause()
        if clause is None:
            self.filter_builder_status_label.setText("Choose field, operator, and value before appending.")
            return
        existing = self.filter_input.toPlainText().strip()
        if existing:
            joined = f"{existing} {self.filter_join_combo.currentText().strip()} {clause}"
        else:
            joined = clause
        self.filter_input.setPlainText(joined)
        self.filter_builder_status_label.setText(f"Appended clause: {clause}")

    def _replace_filter_with_clause(self):
        clause = self._format_filter_clause()
        if clause is None:
            self.filter_builder_status_label.setText("Choose field, operator, and value before replacing.")
            return
        self.filter_input.setPlainText(clause)
        self.filter_builder_status_label.setText(f"Filter replaced with: {clause}")

    def _clear_filter(self):
        self.filter_input.clear()
        self.filter_builder_status_label.setText("Local filter cleared.")

    def _sync_simple_filter_builder_from_text(self, filter_text: str):
        text = str(filter_text or "").strip()
        if not text:
            self.filter_builder_status_label.setText("Builder is ready. Use advanced text directly for complex expressions.")
            return
        if " AND " in text or " OR " in text:
            self.filter_builder_status_label.setText("Advanced filter detected. Builder keeps the last manual selection.")
            return
        cleaned = text.strip()
        if cleaned.startswith("(") and cleaned.endswith(")"):
            cleaned = cleaned[1:-1].strip()
        import re
        match = re.match(r"^([A-Za-z0-9_.]+)\s*(==|!=|>=|<=|>|<)\s*(.+)$", cleaned)
        if not match:
            self.filter_builder_status_label.setText("Filter text does not match a single simple clause.")
            return
        field_name, operator, value = match.groups()
        self._set_combo_to_text(self.filter_field_combo, field_name)
        self._set_combo_to_text(self.filter_operator_combo, operator)
        self.filter_value_input.setText(value.strip())
        self.filter_builder_status_label.setText("Builder synced from the current single-clause filter.")

    def _schedule_preview_refresh(self):
        if self._preview_refresh_suspend_count > 0:
            self._preview_refresh_pending = True
            return
        self._preview_timer.start()

    def _collect_working_copy(self):
        with self._preview_refresh_batch():
            self._sync_hidden_controls_from_simple_editor()
        working = deepcopy(self.widget_model)
        visualization = working.visualization
        query = deepcopy(working.query)
        style = dict(working.style or {})

        working.title = self.title_input.text().strip() or self._auto_title()
        working.description = self.description_input.toPlainText().strip() or None
        base_source = self.data_source_combo.currentText().strip() or working.data_source
        x_source = self.x_data_source_combo.currentText().strip() or base_source
        y_source = self.y_data_source_combo.currentText().strip() or base_source
        behavior = self._source_behavior(self.visualization_combo.currentText().strip().lower())
        if behavior.get("mode") == "double":
            working.data_source = y_source or base_source
            style["x_data_source"] = x_source
            style["y_data_source"] = y_source
        else:
            working.data_source = base_source
            style.pop("x_data_source", None)
            style.pop("y_data_source", None)
        visualization.type = self.visualization_combo.currentText().strip() or visualization.type
        visualization.x_field = self.x_field_combo.currentText().strip() or None
        visualization.y_field = self.y_field_combo.currentText().strip() or None
        visualization.category_field = self.category_field_combo.currentText().strip() or None
        visualization.value_field = self.value_field_combo.currentText().strip() or None
        visualization.series_field = self.series_field_combo.currentText().strip() or None
        visualization.show_legend = self.legend_check.isChecked()
        visualization.show_labels = self.labels_check.isChecked()

        working.layout.w = self.width_spin.value()
        working.layout.h = self.height_spin.value()

        query.group_by = [field.strip() for field in self.group_by_input.text().split(",") if field.strip()] or None

        metric_type = self.metric_type_combo.currentText().strip() or "none"
        metric_field = self.metric_field_combo.currentText().strip() or "*"
        metric_alias = self.metric_alias_input.text().strip() or visualization.value_field or metric_type
        if metric_type == "none":
            query.metrics = None
        else:
            query.metrics = [QueryMetric(type=metric_type, field=metric_field, as_=metric_alias)]

        query.filter = self.filter_input.toPlainText().strip() or None

        sort_field = self.sort_field_combo.currentText().strip()
        if sort_field:
            query.sort = [QuerySort(field=sort_field, direction=self.sort_direction_combo.currentText().strip() or "asc")]
        else:
            query.sort = None

        query.limit = self.limit_spin.value() or None
        bucket_text = self.time_bucket_combo.currentText().strip()
        query.time_bucket = None if bucket_text in {"", "None"} else bucket_text
        query.columns = [field.strip() for field in self.columns_input.text().split(",") if field.strip()] or None

        style["x_axis_label"] = self.axis_x_label_input.text().strip() or None
        style["y_axis_label"] = self.axis_y_label_input.text().strip() or None
        style["unit"] = self.unit_input.text().strip() or None
        style["primary_color"] = self.primary_color_input.text().strip() or None
        style["color_palette"] = self.color_palette_input.text().strip() or None
        style["display_mode"] = self.display_mode_combo.currentText().strip().lower()
        working.query = query
        working.style = {key: value for key, value in style.items() if value not in (None, "")}
        return working

    def _copy_table_to_clipboard(self, table: QTableWidget):
        if table.rowCount() == 0 or table.columnCount() == 0:
            return
        headers = [table.horizontalHeaderItem(col).text() if table.horizontalHeaderItem(col) else "" for col in range(table.columnCount())]
        rows = ["\t".join(headers)]
        for row in range(table.rowCount()):
            values = []
            for col in range(table.columnCount()):
                item = table.item(row, col)
                values.append(item.text() if item is not None else "")
            rows.append("\t".join(values))
        QApplication.clipboard().setText("\n".join(rows))

    def _auto_title(self) -> str:
        value_field = self.value_field_combo.currentText().strip()
        x_field = self.x_field_combo.currentText().strip() or self.category_field_combo.currentText().strip()
        metric_type = self.metric_type_combo.currentText().strip() or "count"
        if value_field and x_field:
            return f"{metric_type.title()} {value_field} by {x_field}"
        if value_field:
            return f"{metric_type.title()} of {value_field}"
        return self.widget_model.title or "Chart"

    def _refresh_preview(self):
        self._working_copy = self._collect_working_copy()
        preview_rows = self._execute_plot_preview_rows()
        self._refresh_chart_preview(preview_rows)
        self._refresh_sheet_preview(preview_rows)

    def _chart_config(self) -> Dict[str, Any]:
        visualization = self._working_copy.visualization
        style = dict(self._working_copy.style or {})
        config = {
            "type": "table" if style.get("display_mode") == "table" else visualization.type,
            "xField": visualization.x_field,
            "yField": visualization.y_field,
            "categoryField": visualization.category_field,
            "valueField": visualization.value_field,
            "seriesField": visualization.series_field,
            "showLegend": visualization.show_legend,
            "showLabels": visualization.show_labels,
            "enableInspector": False,
        }
        if style.get("x_axis_label"):
            config["xAxisLabel"] = style["x_axis_label"]
        if style.get("y_axis_label"):
            config["yAxisLabel"] = style["y_axis_label"]
        if style.get("unit"):
            config["unit"] = style["unit"]
        if style.get("primary_color"):
            config["primaryColor"] = style["primary_color"]
        if style.get("color_palette"):
            config["colorPalette"] = style["color_palette"]
        if style.get("x_data_source"):
            config["xDataSource"] = style["x_data_source"]
        if style.get("y_data_source"):
            config["yDataSource"] = style["y_data_source"]
        return config

    def _selected_xy_sources(self) -> tuple[str, str]:
        style = dict(self._working_copy.style or {})
        base_source = str(self._working_copy.data_source or self.data_source_combo.currentText() or "").strip()
        x_source = str(style.get("x_data_source") or self.x_data_source_combo.currentText() or base_source).strip()
        y_source = str(style.get("y_data_source") or self.y_data_source_combo.currentText() or base_source).strip()
        return x_source, y_source

    def _uses_dual_source_execution(self) -> bool:
        chart_type = self.visualization_combo.currentText().strip().lower()
        if chart_type not in {"line", "area", "scatter"}:
            return False
        x_source, y_source = self._selected_xy_sources()
        return bool(x_source and y_source and x_source != y_source)

    def _execute_dual_source_preview_rows(self) -> List[Dict[str, Any]]:
        x_source, y_source = self._selected_xy_sources()
        x_field = str(self._working_copy.visualization.x_field or "time").strip() or "time"
        y_field = str(self._working_copy.visualization.y_field or self._working_copy.visualization.value_field or "packets").strip() or "packets"
        series_field = str(self._working_copy.visualization.series_field or "").strip() or None
        return _build_dual_source_xy_rows(
            self.query_engine,
            x_source,
            y_source,
            x_field,
            y_field,
            series_field=series_field,
            limit=max(50, int(self._working_copy.query.limit or 500)),
        )

    def _execute_plot_preview_rows(self) -> List[Dict[str, Any]]:
        if not self.query_engine:
            return []
        try:
            if self._uses_dual_source_execution():
                return self._execute_dual_source_preview_rows()
            return self.query_engine.execute(self._working_copy.data_source, self._working_copy.query, None)
        except Exception:
            return []

    def _build_sheet_preview_rows(self, rows: Optional[List[Dict[str, Any]]] = None) -> List[Dict[str, Any]]:
        if rows is None:
            rows = self._execute_plot_preview_rows()
        chart_type = self.visualization_combo.currentText().strip().lower()
        if chart_type not in self.PROPORTION_SOURCE_CHARTS or not rows:
            return self._apply_sheet_preview_headers(rows)

        category_field = self._working_copy.visualization.category_field or self.primary_source_field_combo.currentText().strip() or "source"
        value_field = self._working_copy.visualization.value_field or "count"
        total = 0.0
        for row in rows:
            try:
                total += float(row.get(value_field, 0) or 0)
            except Exception:
                continue

        preview_rows = []
        for row in rows:
            value = row.get(value_field, 0)
            try:
                numeric_value = float(value or 0)
            except Exception:
                numeric_value = 0.0
            percent_value = (numeric_value / total * 100.0) if total else 0.0
            preview_rows.append({
                category_field: row.get(category_field),
                "total": value,
                "%": f"{percent_value:.2f}",
            })
        return self._apply_sheet_preview_headers(preview_rows)

    def _refresh_chart_preview(self, preview_data: Optional[List[Dict[str, Any]]] = None):
        while self.preview_chart_layout.count() > 0:
            item = self.preview_chart_layout.takeAt(0)
            if item.widget() is not None:
                item.widget().deleteLater()

        preserve_color_state = self._color_editor_active and self._chart_supports_color(self.visualization_combo.currentText().strip().lower())
        self._install_preview_activation_handlers(None)
        self._set_color_editor_active(preserve_color_state)

        if not self.query_engine or not self.viz_registry:
            self.preview_chart_layout.addWidget(QLabel("Preview unavailable: query engine or visualization registry missing."))
            return

        try:
            if preview_data is None:
                preview_data = self.query_engine.execute(self._working_copy.data_source, self._working_copy.query, None)
            renderer = self.viz_registry.get_renderer(self._working_copy.visualization.type)
            if renderer is None:
                raise ValueError(f"Renderer '{self._working_copy.visualization.type}' not found")
            preview_widget = renderer(preview_data, self._chart_config(), self.preview_chart_frame)
            self._preview_widget = preview_widget
            self._install_preview_activation_handlers(preview_widget)
            self._set_color_editor_active(preserve_color_state)
            self.preview_chart_layout.addWidget(preview_widget)
            self.preview_status_label.setText(
                f"Preview rows: {len(preview_data)} | Field sample rows: {len(self._source_rows)}"
            )
        except Exception as exc:
            error_label = QLabel(f"Preview error: {exc}")
            error_label.setWordWrap(True)
            error_label.setStyleSheet("color: #a61e1e;")
            self.preview_chart_layout.addWidget(error_label)
            self.preview_status_label.setText("Preview failed. Check field mappings, filter expression, or source sample.")

    def _refresh_sheet_preview(self, preview_rows: Optional[List[Dict[str, Any]]] = None):
        self._populate_table(self.preview_sheet_table, self._build_sheet_preview_rows(preview_rows))

    def _execute_aggregated_preview(self) -> List[Dict[str, Any]]:
        if not self.query_engine:
            return []
        try:
            return self.query_engine.execute(self._working_copy.data_source, self._working_copy.query, None)
        except Exception:
            return []

    def _execute_raw_preview(self) -> List[Dict[str, Any]]:
        if not self.query_engine:
            return []
        if self._uses_dual_source_execution():
            return self._execute_dual_source_preview_rows()
        raw_query = deepcopy(self._working_copy.query)
        raw_query.group_by = None
        raw_query.metrics = None
        raw_query.time_bucket = None
        raw_query.sort = None
        raw_query.limit = raw_query.limit or 50
        selected_columns = [field for field in [
            self.x_field_combo.currentText().strip(),
            self.y_field_combo.currentText().strip(),
            self.category_field_combo.currentText().strip(),
            self.value_field_combo.currentText().strip(),
            self.series_field_combo.currentText().strip(),
        ] if field]
        column_override = [field.strip() for field in self.columns_input.text().split(",") if field.strip()]
        raw_query.columns = column_override or list(dict.fromkeys(selected_columns)) or None
        try:
            return self.query_engine.execute(self._working_copy.data_source, raw_query, None)
        except Exception:
            return []

    @staticmethod
    def _populate_table(table: QTableWidget, rows: List[Dict[str, Any]]):
        table.clear()
        if not rows:
            table.setRowCount(0)
            table.setColumnCount(0)
            return
        columns = list(rows[0].keys())
        table.setColumnCount(len(columns))
        table.setHorizontalHeaderLabels(columns)
        table.setRowCount(len(rows))
        for row_index, row in enumerate(rows):
            for column_index, column_name in enumerate(columns):
                table.setItem(row_index, column_index, QTableWidgetItem(str(row.get(column_name, ""))))
        table.resizeColumnsToContents()

    def _validate_and_accept(self):
        title = self.title_input.text().strip() or self._auto_title().strip()
        if not title:
            QMessageBox.warning(self, "Error", "The operation failed. Please check the input data, connection state, or source file.")
            self.tabs.setCurrentIndex(0)
            return
        self._working_copy = self._collect_working_copy()
        self.accept()

    def on_delete_requested(self):
        self.delete_requested = True
        self.accept()

    def apply_changes(self):
        self._working_copy = self._collect_working_copy()
        self.widget_model.title = self._working_copy.title
        self.widget_model.description = self._working_copy.description
        self.widget_model.data_source = self._working_copy.data_source
        self.widget_model.query = self._working_copy.query
        self.widget_model.visualization = self._working_copy.visualization
        self.widget_model.layout = self._working_copy.layout
        self.widget_model.style = self._working_copy.style


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
    view_mode_changed = Signal(str, str)
    drag_started = Signal(str, QPoint, QPoint, object)
    drag_moved = Signal(QPoint)
    drag_finished = Signal(QPoint)
    
    def __init__(self, widget, editable: bool = True, query_engine=None, viz_registry=None, display_mode: Optional[str] = None, preview_font_scale: float = 1.0):
        super().__init__()
        self.widget = widget
        self.editable = editable
        self.query_engine = query_engine
        self.viz_registry = viz_registry
        self.display_mode = display_mode
        self.preview_font_scale = float(preview_font_scale or 1.0)
        self._drag_start_pos: Optional[QPoint] = None
        self._drag_in_progress = False
        self.setup_ui()

    def _visualization_config(self) -> Dict[str, object]:
        visualization = self.widget.visualization
        style = dict(self.widget.style or {})
        compact_mode = int(getattr(self.widget.layout, "h", 1) or 1) <= 2 or int(getattr(self.widget.layout, "w", 1) or 1) <= 3
        config = {
            "type": visualization.type,
            "xField": visualization.x_field,
            "yField": visualization.y_field,
            "categoryField": visualization.category_field,
            "valueField": visualization.value_field,
            "seriesField": visualization.series_field,
            "showLegend": visualization.show_legend,
            "showLabels": visualization.show_labels,
            "compactMode": compact_mode,
            "showChartAnnotations": True,
            "showChartContext": False,
            "previewFontScale": self.preview_font_scale,
        }
        if style.get("x_axis_label"):
            config["xAxisLabel"] = style["x_axis_label"]
        if style.get("y_axis_label"):
            config["yAxisLabel"] = style["y_axis_label"]
        if style.get("unit"):
            config["unit"] = style["unit"]
        if style.get("primary_color"):
            config["primaryColor"] = style["primary_color"]
        if style.get("color_palette"):
            config["colorPalette"] = style["color_palette"]
        if self._effective_display_mode() == "table":
            config["type"] = "table"
            config["showLegend"] = False
        return config

    def _render_visualization_type(self) -> str:
        if self._effective_display_mode() == "table":
            return "table"
        return self.widget.visualization.type

    def _effective_display_mode(self) -> str:
        if self.display_mode in {"chart", "table"}:
            return self.display_mode
        stored_mode = str((self.widget.style or {}).get("display_mode") or "").strip().lower()
        if stored_mode == "table" and self.widget.visualization.type != "table":
            return "table"
        return "table" if self.widget.visualization.type == "table" else "chart"

    def _uses_dual_source_mapping(self) -> bool:
        style = dict(self.widget.style or {})
        x_source = str(style.get("x_data_source") or "").strip()
        y_source = str(style.get("y_data_source") or "").strip()
        return self.widget.visualization.type in {"line", "area", "scatter"} and bool(x_source and y_source and x_source != y_source)

    def _load_widget_rows(self) -> List[Dict[str, Any]]:
        if self._uses_dual_source_mapping():
            style = dict(self.widget.style or {})
            x_source = str(style.get("x_data_source") or self.widget.data_source or "").strip()
            y_source = str(style.get("y_data_source") or self.widget.data_source or "").strip()
            x_field = str(self.widget.visualization.x_field or "time").strip() or "time"
            y_field = str(self.widget.visualization.y_field or self.widget.visualization.value_field or "packets").strip() or "packets"
            series_field = str(self.widget.visualization.series_field or "").strip() or None
            return _build_dual_source_xy_rows(
                self.query_engine,
                x_source,
                y_source,
                x_field,
                y_field,
                series_field=series_field,
                limit=max(50, int(getattr(self.widget.query, "limit", 0) or 500)),
            )

        return self.query_engine.execute(
            data_source=self.widget.data_source,
            query=self.widget.query,
            global_filter=None,
        )

    def _toggle_view_mode(self):
        next_mode = "chart" if self._effective_display_mode() == "table" else "table"
        self.view_mode_changed.emit(self.widget.id, next_mode)

    def _make_visualization_pass_through(self, widget: QWidget):
        widget.setAttribute(Qt.WA_TransparentForMouseEvents, True)
        for child in widget.findChildren(QWidget):
            child.setAttribute(Qt.WA_TransparentForMouseEvents, True)

    def _make_visualization_flexible(self, widget: QWidget):
        if widget is None:
            return
        widget.setMinimumSize(0, 0)
        if hasattr(widget, "setMaximumHeight"):
            widget.setMaximumHeight(16777215)
        if hasattr(widget, "setMaximumWidth"):
            widget.setMaximumWidth(16777215)
        policy = widget.sizePolicy()
        policy.setHorizontalPolicy(QSizePolicy.Expanding)
        policy.setVerticalPolicy(QSizePolicy.Expanding)
        widget.setSizePolicy(policy)
        for child in widget.findChildren(QWidget):
            child.setMinimumSize(0, 0)
            if hasattr(child, "setMaximumHeight"):
                child.setMaximumHeight(16777215)
            if hasattr(child, "setMaximumWidth"):
                child.setMaximumWidth(16777215)
            child_policy = child.sizePolicy()
            child_policy.setHorizontalPolicy(QSizePolicy.Expanding)
            child_policy.setVerticalPolicy(QSizePolicy.Expanding)
            child.setSizePolicy(child_policy)

    def _create_drag_pixmap(self) -> QPixmap:
        """Build an opaque drag preview so the moving widget does not look washed out."""
        logical_size = self.size()
        preview = QPixmap(logical_size)
        preview.fill(QColor("#ffffff"))

        painter = QPainter(preview)
        self.render(painter, QPoint(0, 0))
        painter.end()

        preview.setDevicePixelRatio(1.0)
        return preview
    
    def setup_ui(self):
        """Build widget UI"""
        self.setObjectName("WidgetCard")
        self.setFrameShape(QFrame.NoFrame)
        self.setAttribute(Qt.WA_StyledBackground, True)
        self.setCursor(QCursor(Qt.ArrowCursor))
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(4)
        
        # Header
        header_frame = QFrame(self)
        self.header_frame = header_frame
        if self.editable:
            header_frame.setCursor(QCursor(Qt.OpenHandCursor))
        header_layout = QHBoxLayout(header_frame)
        header_layout.setContentsMargins(0, 0, 0, 0)
        header_layout.setSpacing(6)
        title = QLabel(self.widget.title)
        self.title_label = title
        title.setObjectName("SectionTitle")
        title.setWordWrap(False)
        title.setToolTip(self.widget.title)
        title.setMinimumHeight(18)
        title.setMaximumHeight(18)
        title_font = QFont()
        title_font.setBold(True)
        title_font.setPointSize(11)
        title.setFont(title_font)
        if self.editable:
            title.setCursor(QCursor(Qt.OpenHandCursor))
        header_layout.addWidget(title)
        header_layout.addStretch()

        actions_btn = QPushButton("...")
        actions_btn.setFixedSize(18, 18)
        actions_btn.setObjectName("CardMoreButton")
        actions_btn.setFlat(True)
        actions_btn.setFocusPolicy(Qt.NoFocus)
        actions_btn.setToolTip("More actions")
        actions_btn.setCursor(QCursor(Qt.ArrowCursor))
        actions_menu = QMenu(actions_btn)
        if self.widget.visualization.type != "table":
            switch_label = "View as Table" if self._effective_display_mode() != "table" else "View as Chart"
            actions_menu.addAction(switch_label, self._toggle_view_mode)
        
        if self.editable:
            actions_menu.addAction("Configure Widget", lambda: self.edit_requested.emit(self.widget.id))
        actions_btn.clicked.connect(lambda: actions_menu.popup(actions_btn.mapToGlobal(actions_btn.rect().bottomLeft())))
        header_layout.addWidget(actions_btn)
        
        self._header_drag_targets = [header_frame, title]
        if self.editable:
            for target in self._header_drag_targets:
                target.installEventFilter(self)

        layout.addWidget(header_frame)
        
        # Content area - execute query and render visualization
        content = QFrame()
        content.setObjectName("PreviewSurface")
        self.content_frame = content
        content.setCursor(QCursor(Qt.ArrowCursor))
        content_layout = QVBoxLayout(content)
        content_layout.setSpacing(0)
        compact_body = int(getattr(self.widget.layout, "h", 1) or 1) <= 2
        if compact_body:
            content_layout.setContentsMargins(4, 4, 4, 4)
        else:
            content_layout.setContentsMargins(6, 6, 6, 6)
        
        # Try to render widget data if we have query engine
        if self.query_engine and self.viz_registry and self.widget.query:
            try:
                data = self._load_widget_rows()

                viz_type = self._render_visualization_type()
                renderer = self.viz_registry.get_renderer(viz_type)
                if renderer:
                    viz_widget = renderer(data, self._visualization_config(), content)
                    self._make_visualization_flexible(viz_widget)
                    content_layout.addWidget(viz_widget, 1)
                else:
                    error_label = QLabel(f"No renderer was found for chart type '{viz_type}'")
                    error_label.setStyleSheet("color: #c00;")
                    content_layout.addWidget(error_label, 1)
            except Exception as e:
                error_label = QLabel(f"Error: {str(e)[:50]}...")
                error_label.setStyleSheet("color: #c00;")
                content_layout.addWidget(error_label, 1)
        else:
            # Show placeholder
            if not self.query_engine:
                msg = "Query engine not available"
            elif not self.viz_registry:
                msg = "Visualization registry not available"
            else:
                msg = "No query configured"
            placeholder = QLabel(msg)
            placeholder.setObjectName("MutedText")
            placeholder.setAlignment(Qt.AlignCenter)
            content_layout.addWidget(placeholder, 1)
        
        layout.addWidget(content, 1)
        
        # Footer
        footer_text = str(self.widget.description or "").strip()
        if footer_text:
            footer_label = QLabel(footer_text)
            footer_label.setWordWrap(True)
            footer_label.setObjectName("MutedText")
            layout.addWidget(footer_label)

    def _event_point_in_self(self, watched, event) -> QPoint:
        local_pos = event.position().toPoint() if hasattr(event, "position") else event.pos()
        if watched is self:
            return local_pos
        return watched.mapTo(self, local_pos)

    def _begin_header_interaction(self, pos: QPoint):
        self._drag_start_pos = pos
        self._drag_in_progress = False

    def _handle_header_drag(self, pos: QPoint):
        if not self.editable or self._drag_start_pos is None:
            return False
        if (pos - self._drag_start_pos).manhattanLength() < QApplication.startDragDistance():
            return False
        if not self._drag_in_progress:
            self._drag_in_progress = True
            self.header_frame.setCursor(Qt.ClosedHandCursor)
            self.title_label.setCursor(Qt.ClosedHandCursor)
            self.drag_started.emit(
                self.widget.id,
                self.mapToGlobal(pos),
                QPoint(pos),
                self._create_drag_pixmap(),
            )
        else:
            self.drag_moved.emit(self.mapToGlobal(pos))
        return True

    def _finish_header_interaction(self, pos: QPoint):
        if not self.editable or self._drag_start_pos is None:
            return False
        if self._drag_in_progress:
            self.drag_finished.emit(self.mapToGlobal(pos))
        else:
            self.clicked.emit(self.widget.id)
        self._drag_start_pos = None
        self._drag_in_progress = False
        self.header_frame.setCursor(Qt.OpenHandCursor)
        self.title_label.setCursor(Qt.OpenHandCursor)
        return True

    def eventFilter(self, watched, event):
        if self.editable and watched in getattr(self, "_header_drag_targets", []):
            if event.type() == QEvent.MouseButtonPress and event.button() == Qt.LeftButton:
                self._begin_header_interaction(self._event_point_in_self(watched, event))
                return True
            if event.type() == QEvent.MouseMove and (event.buttons() & Qt.LeftButton):
                if self._handle_header_drag(self._event_point_in_self(watched, event)):
                    return True
            if event.type() == QEvent.MouseButtonRelease and event.button() == Qt.LeftButton:
                if self._finish_header_interaction(self._event_point_in_self(watched, event)):
                    return True
        return super().eventFilter(watched, event)
    
    def mousePressEvent(self, event):
        super().mousePressEvent(event)

    def mouseMoveEvent(self, event):
        super().mouseMoveEvent(event)

    def mouseReleaseEvent(self, event):
        super().mouseReleaseEvent(event)
    
    def mouseDoubleClickEvent(self, event):
        if self.editable:
            self._drag_start_pos = None
            self._drag_in_progress = False
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
        if len(self.dashboard.widgets) == 1:
            stored_mode = str((self.dashboard.widgets[0].style or {}).get("display_mode") or "").strip().lower()
            if stored_mode == "table" or str(self.dashboard.widgets[0].visualization.type or "") == "table":
                self.single_widget_view_mode = "table"
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
        apply_dashboard_theme(self)
        _apply_fixed_screen_size(self)
        self._normalize_widget_layouts()
        self.render_grid()
    
    def setup_ui(self):
        """Build main UI"""
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(16)
        
        # Toolbar
        toolbar_frame = QFrame()
        toolbar_frame.setObjectName("DashboardTopBar")
        toolbar_layout = QHBoxLayout(toolbar_frame)
        toolbar_layout.setContentsMargins(16, 14, 16, 14)
        toolbar_layout.setSpacing(12)

        back_btn = QPushButton("Back")
        back_btn.clicked.connect(self.on_back)
        toolbar_layout.addWidget(back_btn)

        toolbar_layout.addSpacing(12)
        
        title_label = QLabel(self.dashboard.name)
        title_label.setObjectName("PageTitle")
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
            add_widget_btn.setObjectName("PrimaryButton")
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
            if self.single_widget_view_mode == "table":
                self.view_mode_combo.setCurrentText("Table")
            self.view_mode_combo.currentTextChanged.connect(self.on_view_mode_changed)
            toolbar_layout.addWidget(self.view_mode_combo)
        
        toolbar_layout.addStretch()
        
        if self.edit_mode:
            save_btn = QPushButton("Save")
            save_btn.setObjectName("PrimaryButton")
            save_btn.clicked.connect(self.on_save)
            toolbar_layout.addWidget(save_btn)
        
        main_layout.addWidget(toolbar_frame)
        
        # Grid area
        scroll_area = QScrollArea()
        self.scroll_area = scroll_area
        scroll_area.setWidgetResizable(True)
        
        self.grid_container = DashboardGridSurface()
        self.grid_container.setObjectName("DashboardSurface")
        self.grid_container.widget_dropped.connect(self.on_widget_drop_requested)
        self.grid_layout = QGridLayout(self.grid_container)
        self.grid_layout.setSpacing(self.GRID_SPACING)
        self.grid_layout.setContentsMargins(12, 12, 12, 12)
        
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
            "background-color: rgba(0, 102, 204, 0.02);"
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
            empty_frame = QFrame()
            empty_frame.setObjectName("PreviewSurface")
            empty_layout = QVBoxLayout(empty_frame)
            empty_layout.setContentsMargins(24, 28, 24, 28)
            empty_layout.setSpacing(10)
            empty_title = QLabel("This dashboard has no widgets yet.")
            empty_title.setObjectName("SectionTitle")
            empty_title.setAlignment(Qt.AlignCenter)
            empty_layout.addWidget(empty_title)
            empty_body = QLabel("Add widgets to analyze packets, endpoints, protocols, DNS, HTTP, and conversations.")
            empty_body.setObjectName("MutedText")
            empty_body.setWordWrap(True)
            empty_body.setAlignment(Qt.AlignCenter)
            empty_layout.addWidget(empty_body)
            self.grid_layout.addWidget(empty_frame, 0, 0, 1, 12)
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
            grid_widget.view_mode_changed.connect(self.on_widget_view_mode_changed)
            grid_widget.drag_started.connect(self.on_widget_drag_started)
            grid_widget.drag_moved.connect(self.on_widget_drag_moved)
            grid_widget.drag_finished.connect(self.on_widget_drag_finished)
            
            layout = widget_model.layout
            slot_height = (max(1, int(layout.h or 1)) * self.GRID_ROW_HEIGHT) + (max(0, int(layout.h or 1) - 1) * self.GRID_SPACING)
            grid_widget.setMinimumHeight(slot_height)
            grid_widget.setMaximumHeight(slot_height)
            grid_policy = grid_widget.sizePolicy()
            grid_policy.setHorizontalPolicy(QSizePolicy.Expanding)
            grid_policy.setVerticalPolicy(QSizePolicy.Fixed)
            grid_widget.setSizePolicy(grid_policy)
            self.grid_layout.addWidget(grid_widget, layout.y, layout.x, layout.h, layout.w)
        
        self.update_status()
    
    def on_grid_widget_clicked(self, widget_id: str):
        """Handle widget click"""
        self.selected_widget_id = widget_id
    
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

        editor = WidgetEditorDialog(
            widget,
            available_sources,
            available_visualizations,
            query_engine=self.query_engine,
            viz_registry=self.viz_registry,
            parent=self,
        )
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
            QMessageBox.warning(self, "Error", "The operation failed. Please check the input data, connection state, or source file.")
            return
        
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

        editor = WidgetEditorDialog(
            new_widget,
            available_sources or [new_widget.data_source],
            available_visualizations or [new_widget.visualization.type],
            query_engine=self.query_engine,
            viz_registry=self.viz_registry,
            parent=self,
        )
        if editor.exec() != QDialog.Accepted or editor.delete_requested:
            return

        editor.apply_changes()
        final_layout = self._sanitize_layout(new_widget.layout)
        new_x, new_y = self._find_first_fit_position(final_layout.w, final_layout.h)
        new_widget.layout = WidgetLayout(x=new_x, y=new_y, w=final_layout.w, h=final_layout.h)
        self.dashboard.widgets.append(new_widget)
        self.render_grid()

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

    def on_widget_view_mode_changed(self, widget_id: str, mode: str):
        widget = self.find_widget(widget_id)
        if not widget:
            return

        style = dict(widget.style or {})
        if mode == "table":
            style["display_mode"] = "table"
        else:
            style.pop("display_mode", None)
        widget.style = style or None

        if len(self.dashboard.widgets) == 1:
            self.single_widget_view_mode = mode
            if hasattr(self, "view_mode_combo") and self.view_mode_combo is not None:
                self.view_mode_combo.blockSignals(True)
                self.view_mode_combo.setCurrentText("Table" if mode == "table" else "Chart")
                self.view_mode_combo.blockSignals(False)
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
        margins = self.grid_layout.contentsMargins()
        spacing = max(0, self.grid_layout.spacing())
        column_index = max(0, min(self.GRID_COLUMNS - 1, int(column or 0)))
        container_width = self.grid_container.contentsRect().width()
        if self.scroll_area is not None:
            container_width = max(container_width, self.scroll_area.viewport().width())
        available_width = max(1, container_width - margins.left() - margins.right() - (spacing * (self.GRID_COLUMNS - 1)))
        start_x = margins.left() + int(round((column_index * available_width) / self.GRID_COLUMNS)) + (column_index * spacing)
        end_x = margins.left() + int(round(((column_index + 1) * available_width) / self.GRID_COLUMNS)) + (column_index * spacing)
        y = margins.top() + (max(0, row) * (self.GRID_ROW_HEIGHT + spacing))
        width = max(1, end_x - start_x)
        height = self.GRID_ROW_HEIGHT
        return QRect(start_x, y, width, height)

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
            rect = self._grid_cell_rect(0, column)
            origin_x = rect.x()
            next_x = self._grid_cell_rect(0, column + 1).x() if column < max_x else rect.right() + 1

            if x_value < origin_x:
                return column
            if origin_x <= x_value < next_x:
                return column
        return max_x

    def _grid_row_for_position(self, y_pos: int) -> int:
        y_value = int(y_pos)
        spacing = max(0, self.grid_layout.spacing())
        margins = self.grid_layout.contentsMargins()
        for row in range(0, 200):
            origin_y = margins.top() + (row * (self.GRID_ROW_HEIGHT + spacing))
            next_y = origin_y + self.GRID_ROW_HEIGHT + spacing

            if y_value < origin_y:
                return row
            if origin_y <= y_value < next_y:
                return row
        return max(0, int((y_value - margins.top()) / max(1, self.GRID_ROW_HEIGHT + spacing)))

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
