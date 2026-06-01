"""
Visualization Registry and Renderers.

Handles rendering different visualization types (bar, line, pie, table, metric, etc.)
"""

from __future__ import annotations

import math
from typing import List, Dict, Any, Optional, Callable
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableWidget, QTableWidgetItem, QLabel,
    QAbstractItemView
)
from PySide6.QtCore import Qt, QDateTime, QMargins, QPoint, QPointF, QRectF, QObject, QEvent
from PySide6.QtGui import QBrush, QColor, QCursor, QFont, QPainter, QPainterPath, QPen, QPolygonF
from PySide6.QtCharts import (
    QBarCategoryAxis, QBarSeries, QBarSet, QChart, QChartView,
    QDateTimeAxis, QHorizontalBarSeries, QLineSeries, QPieSeries, QScatterSeries, QValueAxis
)


def _empty_widget(message: str, parent: QWidget = None) -> QWidget:
    widget = QWidget(parent)
    layout = QVBoxLayout(widget)
    layout.setContentsMargins(20, 20, 20, 20)
    label = QLabel(message)
    label.setAlignment(Qt.AlignCenter)
    label.setStyleSheet("color: #999; font-size: 11pt;")
    layout.addWidget(label)
    return widget


def _coerce_number(value: Any) -> Optional[float]:
    if isinstance(value, bool):
        return float(int(value))
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return float(str(value))
    except Exception:
        return None


def _infer_value_field(data: List[Dict[str, Any]], config: Dict[str, Any]) -> Optional[str]:
    candidates = [
        config.get("valueField"),
        config.get("yField"),
        config.get("xField") if config.get("type") == "metric" else None,
    ]
    for candidate in candidates:
        if candidate and any(candidate in row for row in data):
            return candidate

    if not data:
        return None

    for key in data[0].keys():
        if any(_coerce_number(row.get(key)) is not None for row in data):
            return key
    return next(iter(data[0].keys()), None)


def _infer_category_field(data: List[Dict[str, Any]], config: Dict[str, Any], value_field: Optional[str]) -> Optional[str]:
    candidates = [config.get("categoryField"), config.get("xField")]
    for candidate in candidates:
        if candidate and any(candidate in row for row in data):
            return candidate

    if not data:
        return None

    for key in data[0].keys():
        if key == value_field:
            continue
        if any(_coerce_number(row.get(key)) is None for row in data):
            return key

    for key in data[0].keys():
        if key != value_field:
            return key
    return None


def _build_chart_view(chart: QChart, parent: QWidget = None) -> QChartView:
    view = QChartView(chart, parent)
    view.setRenderHint(QPainter.Antialiasing)
    view.setStyleSheet("background: transparent;")
    return view


def _format_inspector_text(*lines: Optional[str]) -> Optional[str]:
    normalized = [str(line) for line in lines if line not in (None, "")]
    return "\n".join(normalized) if normalized else None


def _mouse_event_pos(event) -> QPoint:
    if hasattr(event, "position"):
        return event.position().toPoint()
    return event.pos()


def _mouse_event_global_pos(event) -> QPoint:
    if hasattr(event, "globalPosition"):
        return event.globalPosition().toPoint()
    return event.globalPos()


class _InspectorBubble(QLabel):
    def __init__(self, parent: QWidget = None):
        super().__init__(parent)
        self.setWordWrap(True)
        self.setAttribute(Qt.WA_TransparentForMouseEvents, True)
        self.setStyleSheet(
            "background-color: rgba(17, 24, 39, 225); color: white; "
            "border: 1px solid rgba(255, 255, 255, 40); border-radius: 8px; "
            "padding: 6px 8px; font-size: 9pt;"
        )
        self.hide()


class _PointerInspectorController(QObject):
    def __init__(self, interactive_widget: QWidget, provider: Optional[Callable[[QPoint], Optional[str]]] = None):
        super().__init__(interactive_widget)
        self.interactive_widget = interactive_widget
        self.provider = provider
        self.active_text: Optional[str] = None
        bubble_parent = interactive_widget.window() if interactive_widget.window() else interactive_widget
        self.bubble = _InspectorBubble(bubble_parent)
        self.interactive_widget.installEventFilter(self)
        self.interactive_widget.setMouseTracking(True)

    def start(self, text: Optional[str], global_pos: Optional[QPoint] = None):
        if not text:
            return
        self.active_text = str(text)
        self._show(global_pos or QCursor.pos())

    def stop(self):
        self.active_text = None
        self.bubble.hide()

    def _show(self, global_pos: QPoint):
        if not self.active_text:
            return
        self.bubble.setText(self.active_text)
        self.bubble.adjustSize()
        anchor = self.bubble.parentWidget() or self.interactive_widget
        local_pos = anchor.mapFromGlobal(global_pos + QPoint(18, 18))
        max_x = max(8, anchor.width() - self.bubble.width() - 8)
        max_y = max(8, anchor.height() - self.bubble.height() - 8)
        x_pos = min(max(8, local_pos.x()), max_x)
        y_pos = min(max(8, local_pos.y()), max_y)
        self.bubble.move(x_pos, y_pos)
        self.bubble.raise_()
        self.bubble.show()

    def eventFilter(self, watched, event):
        event_type = event.type()
        if self.provider is not None and event_type == QEvent.MouseButtonPress and getattr(event, "button", lambda: None)() == Qt.LeftButton:
            text = self.provider(_mouse_event_pos(event))
            if text:
                self.start(text, _mouse_event_global_pos(event))
            else:
                self.stop()
        elif self.active_text and event_type == QEvent.MouseMove:
            if self.provider is not None:
                next_text = self.provider(_mouse_event_pos(event))
                if next_text:
                    self.active_text = next_text
            self._show(_mouse_event_global_pos(event))
        elif event_type in {QEvent.Leave, QEvent.Hide, QEvent.WindowDeactivate}:
            self.stop()
        return False


def _ensure_pointer_inspector(widget: QWidget, provider: Optional[Callable[[QPoint], Optional[str]]] = None) -> _PointerInspectorController:
    controller = getattr(widget, "_pointer_inspector_controller", None)
    if controller is None or (provider is not None and controller.provider is not provider):
        controller = _PointerInspectorController(widget, provider=provider)
        setattr(widget, "_pointer_inspector_controller", controller)
    return controller


class _InteractiveChartCanvas(QWidget):
    def __init__(self, parent: QWidget = None):
        super().__init__(parent)
        self._inspector_regions: List[tuple[Any, str]] = []
        self._inspector_controller = _ensure_pointer_inspector(self, self._inspector_text_at)

    def _inspector_text_at(self, pos: QPoint) -> Optional[str]:
        point = QPointF(pos)
        for shape, text in reversed(self._inspector_regions):
            if isinstance(shape, QPainterPath) and shape.contains(point):
                return text
            if isinstance(shape, QRectF) and shape.contains(point):
                return text
        return None

    def _set_inspector_regions(self, regions: List[tuple[Any, str]]):
        self._inspector_regions = regions


def _format_info_bubble(title: Optional[str], fields: List[tuple[str, Optional[str]]]) -> Optional[str]:
    lines = [str(title).strip()] if title else []
    for label, value in fields:
        if value in (None, ""):
            continue
        lines.append(f"{label}: {value}")
    return "\n".join(line for line in lines if line)


def _attach_static_inspector(widget: QWidget, title: Optional[str], fields: List[tuple[str, Optional[str]]]) -> None:
    text = _format_info_bubble(title, fields)
    _ensure_pointer_inspector(widget, lambda _pos, text=text: text)


def _attach_table_inspector(table: QTableWidget) -> None:
    def provider(pos: QPoint) -> Optional[str]:
        item = table.itemAt(pos)
        if item is None:
            return None
        row_header = table.verticalHeaderItem(item.row())
        col_header = table.horizontalHeaderItem(item.column())
        return _format_info_bubble(
            "Cell Details",
            [
                ("Row", row_header.text() if row_header else str(item.row() + 1)),
                ("Column", col_header.text() if col_header else str(item.column() + 1)),
                ("Value", item.text()),
            ],
        )

    _ensure_pointer_inspector(table.viewport(), provider)


def _semantic_annotations_enabled(config: Dict[str, Any]) -> bool:
    return not bool((config or {}).get("compactMode", False))


def _wrap_with_chart_context(content: QWidget, lines: List[str], parent: QWidget = None) -> QWidget:
    context_lines = [line for line in lines if line]
    if not context_lines:
        return content

    container = QWidget(parent)
    layout = QVBoxLayout(container)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(4)
    layout.addWidget(content, 1)

    for line in context_lines:
        label = QLabel(line, container)
        label.setWordWrap(True)
        label.setStyleSheet("color: #666; font-size: 9pt;")
        layout.addWidget(label)

    return container


def _build_chart_overlay(lines: List[str], parent: QWidget = None) -> Optional[QWidget]:
    overlay_lines = [line for line in lines if line]
    if not overlay_lines:
        return None

    overlay = QWidget(parent)
    overlay.setAttribute(Qt.WA_TransparentForMouseEvents, True)
    overlay_layout = QVBoxLayout(overlay)
    overlay_layout.setContentsMargins(10, 10, 10, 10)
    overlay_layout.setSpacing(6)

    for index, line in enumerate(overlay_lines):
        label = QLabel(line, overlay)
        label.setWordWrap(True)
        if index == 0:
            label.setStyleSheet(
                "color: #111827; font-size: 9pt; font-weight: 700; "
                "background-color: rgba(255, 255, 255, 205); border-radius: 6px; padding: 4px 6px;"
            )
        else:
            label.setStyleSheet(
                "color: #374151; font-size: 9pt; "
                "background-color: rgba(255, 255, 255, 190); border-radius: 6px; padding: 4px 6px;"
            )
        overlay_layout.addWidget(label)

    overlay_layout.addStretch(1)
    return overlay


def _humanize_field_name(field_name: Optional[str], *, fallback: str = "Value") -> str:
    if not field_name:
        return fallback

    normalized = str(field_name).strip().lower()
    aliases = {
        "time": "Time (s)",
        "relative_time": "Relative Time (s)",
        "epoch_time": "Timestamp",
        "packets": "Packets (count)",
        "count": "Count",
        "hits": "Hits (count)",
        "responses": "Responses (count)",
        "queries": "Queries (count)",
        "bytes": "Bytes",
        "length": "Length (bytes)",
        "protocol": "Protocol",
        "address": "Address",
        "conversation": "Conversation",
    }
    if normalized in aliases:
        return aliases[normalized]

    if normalized.endswith("_ms"):
        return f"{normalized[:-3].replace('_', ' ').title()} (ms)"
    if normalized.endswith("_bytes"):
        return f"{normalized[:-6].replace('_', ' ').title()} (bytes)"
    if normalized.endswith("_packets") or normalized.endswith("_count"):
        return f"{normalized.rsplit('_', 1)[0].replace('_', ' ').title()} (count)"

    return normalized.replace('_', ' ').title()


def _axis_titles_visible(config: Dict[str, Any]) -> bool:
    return not bool((config or {}).get("compactMode", False))


def _set_axis_title(axis, field_name: Optional[str], config: Dict[str, Any], *, fallback: str):
    title = _humanize_field_name(field_name, fallback=fallback)
    axis.setTitleText(title)
    axis.setTitleVisible(_axis_titles_visible(config))


def _format_number(value: float) -> str:
    if float(value).is_integer():
        return str(int(value))
    return f"{value:.2f}"


def _extract_xy_points(data: List[Dict[str, Any]], config: Dict[str, Any]):
    config = config or {}
    x_field = config.get("xField") or "time"
    y_field = _infer_value_field(data, config)
    if not y_field:
        return x_field, None, [], []

    numeric_points = []
    datetime_points = []

    for index, row in enumerate(data):
        y_value = _coerce_number(row.get(y_field))
        if y_value is None:
            continue

        x_value = row.get(x_field, index)
        if isinstance(x_value, (int, float)):
            numeric_points.append((float(x_value), y_value))
            continue

        if isinstance(x_value, str):
            dt_value = QDateTime.fromString(x_value, Qt.ISODate)
            if dt_value.isValid():
                datetime_points.append((dt_value.toMSecsSinceEpoch(), y_value))
                continue

        numeric_points.append((float(index), y_value))

    if datetime_points:
        datetime_points.sort(key=lambda point: point[0])
    if numeric_points:
        numeric_points.sort(key=lambda point: point[0])

    return x_field, y_field, numeric_points, datetime_points


def _configure_xy_axes(
    chart: QChart,
    series,
    numeric_points: List[tuple[float, float]],
    datetime_points: List[tuple[float, float]],
    x_field: Optional[str],
    y_field: Optional[str],
    config: Dict[str, Any],
):
    if datetime_points:
        x_axis = QDateTimeAxis()
        x_axis.setFormat("hh:mm:ss")
        x_values = [point[0] for point in datetime_points]
        x_axis.setMin(QDateTime.fromMSecsSinceEpoch(int(min(x_values))))
        x_axis.setMax(QDateTime.fromMSecsSinceEpoch(int(max(x_values))))
    else:
        x_axis = QValueAxis()
        x_values = [point[0] for point in numeric_points]
        x_axis.setLabelFormat("%.0f")
        min_x = min(x_values)
        max_x = max(x_values)
        if min_x == max_x:
            max_x += 1.0
        x_axis.setRange(min_x, max_x)

    y_axis = QValueAxis()
    y_axis.setLabelFormat("%.0f")
    y_values = [point[1] for point in (datetime_points or numeric_points)]
    max_y = max(y_values) if y_values else 1.0
    y_axis.setRange(0, max_y * 1.15 if max_y > 0 else 1.0)

    _set_axis_title(x_axis, x_field, config, fallback="X Axis")
    _set_axis_title(y_axis, y_field, config, fallback="Value")

    chart.addAxis(x_axis, Qt.AlignBottom)
    chart.addAxis(y_axis, Qt.AlignLeft)
    series.attachAxis(x_axis)
    series.attachAxis(y_axis)


def _palette(index: int) -> QColor:
    palette = [
        QColor("#4e79a7"),
        QColor("#f28e2b"),
        QColor("#e15759"),
        QColor("#76b7b2"),
        QColor("#59a14f"),
        QColor("#edc948"),
        QColor("#b07aa1"),
        QColor("#ff9da7"),
        QColor("#9c755f"),
        QColor("#bab0ab"),
    ]
    return palette[index % len(palette)]


def _scale_points(points: List[tuple[float, float]], rect, *, include_zero: bool = True) -> List[QPointF]:
    if not points:
        return []

    x_values = [point[0] for point in points]
    y_values = [point[1] for point in points]
    min_x = min(x_values)
    max_x = max(x_values)
    min_y = 0.0 if include_zero else min(y_values)
    max_y = max(y_values)

    if min_x == max_x:
        max_x += 1.0
    if min_y == max_y:
        max_y += 1.0

    scaled = []
    for x_value, y_value in points:
        x_ratio = (x_value - min_x) / (max_x - min_x)
        y_ratio = (y_value - min_y) / (max_y - min_y)
        scaled.append(
            QPointF(
                rect.left() + (x_ratio * rect.width()),
                rect.bottom() - (y_ratio * rect.height()),
            )
        )
    return scaled


class _RadarCanvas(_InteractiveChartCanvas):
    """Custom radar/spider chart renderer."""

    def __init__(self, labels: List[str], values: List[float], *, compact_mode: bool, parent: QWidget = None):
        super().__init__(parent)
        self.labels = labels
        self.values = values
        self.compact_mode = compact_mode
        self.setMinimumHeight(120 if compact_mode else 280)
        if not compact_mode:
            label_font = self.font()
            label_font.setPointSize(max(label_font.pointSize(), 9))
            label_font.setBold(True)
            self.setFont(label_font)

    def paintEvent(self, event):
        if not self.labels or not self.values:
            return

        info_regions: List[tuple[Any, str]] = []

        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        label_font = painter.font()
        if not self.compact_mode:
            label_font.setPointSize(max(label_font.pointSize(), 9))
            label_font.setBold(True)
            painter.setFont(label_font)

        margin = 18 if self.compact_mode else 44
        center = self.rect().center()
        radius = min(self.width(), self.height()) / 2 - margin
        if radius <= 0:
            return

        max_value = max(self.values) if self.values else 1.0
        if max_value <= 0:
            max_value = 1.0

        step_count = 4
        painter.setPen(QPen(QColor("#d6dde6"), 1))
        for step in range(1, step_count + 1):
            level_radius = radius * (step / step_count)
            ring_points = []
            for index in range(len(self.labels)):
                angle = ((2 * math.pi) * index / len(self.labels)) - (math.pi / 2)
                ring_points.append(
                    QPointF(
                        center.x() + (math.cos(angle) * level_radius),
                        center.y() + (math.sin(angle) * level_radius),
                    )
                )
            painter.drawPolygon(QPolygonF(ring_points))

        painter.setPen(QPen(QColor("#c3cad4"), 1))
        polygon_points = []
        for index, label in enumerate(self.labels):
            angle = ((2 * math.pi) * index / len(self.labels)) - (math.pi / 2)
            axis_end = QPointF(
                center.x() + (math.cos(angle) * radius),
                center.y() + (math.sin(angle) * radius),
            )
            painter.drawLine(center, axis_end)

            value_radius = radius * (self.values[index] / max_value)
            value_point = QPointF(
                center.x() + (math.cos(angle) * value_radius),
                center.y() + (math.sin(angle) * value_radius),
            )
            polygon_points.append(value_point)

            point_path = QPainterPath()
            point_path.addEllipse(value_point, 12.0, 12.0)
            info_regions.append(
                (
                    point_path,
                    _format_info_bubble(
                        label,
                        [
                            ("Value", _format_number(self.values[index])),
                            ("Share of Max", f"{(self.values[index] / max_value) * 100.0:.1f}%"),
                        ],
                    ),
                )
            )

            if not self.compact_mode:
                painter.setPen(QPen(QColor("#1f2937"), 1))
                text_rect = QRectF(axis_end.x() - 40, axis_end.y() - 10, 80, 20)
                painter.drawText(text_rect, Qt.AlignCenter, label)
                text_path = QPainterPath()
                text_path.addRect(text_rect)
                info_regions.append((text_path, _format_info_bubble(label, [("Value", _format_number(self.values[index]))])))

        painter.setPen(QPen(QColor("#0066cc"), 2))
        painter.setBrush(QBrush(QColor(0, 102, 204, 80)))
        painter.drawPolygon(QPolygonF(polygon_points))
        self._set_inspector_regions(info_regions)


class _TreemapCanvas(_InteractiveChartCanvas):
    """Custom slice-and-dice treemap renderer."""

    def __init__(self, groups: List[dict], *, compact_mode: bool, parent: QWidget = None):
        super().__init__(parent)
        self.groups = groups
        self.compact_mode = compact_mode
        self.setMinimumHeight(140 if compact_mode else 260)

    def paintEvent(self, event):
        if not self.groups:
            return

        info_regions: List[tuple[Any, str]] = []

        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        outer_rect = self.rect().adjusted(6, 6, -6, -6)
        total_value = sum(group['value'] for group in self.groups) or 1.0
        current_x = outer_rect.left()

        for group_index, group in enumerate(self.groups):
            group_width = outer_rect.width() * (group['value'] / total_value)
            group_rect = QRectF(current_x, outer_rect.top(), group_width, outer_rect.height())
            current_x += group_width

            painter.setPen(QPen(QColor("white"), 1))
            painter.setBrush(QBrush(_palette(group_index).lighter(125)))
            painter.drawRect(group_rect)
            group_path = QPainterPath()
            group_path.addRect(group_rect)
            info_regions.append((group_path, _format_info_bubble(group['label'], [("Group Total", _format_number(group['value']))])))

            if not self.compact_mode:
                painter.setPen(QColor("#223"))
                painter.drawText(group_rect.adjusted(4, 4, -4, -4), Qt.AlignTop | Qt.AlignLeft, group['label'])

            children_total = sum(item['value'] for item in group['children']) or 1.0
            child_y = group_rect.top()
            child_top = group_rect.top() + (18 if not self.compact_mode else 0)
            usable_height = max(1.0, group_rect.bottom() - child_top)
            child_y = child_top
            for child_index, child in enumerate(group['children']):
                child_height = usable_height * (child['value'] / children_total)
                child_rect = QRectF(group_rect.left(), child_y, group_rect.width(), child_height)
                child_y += child_height
                painter.setBrush(QBrush(_palette(group_index + child_index).darker(100 + (child_index * 7))))
                painter.drawRect(child_rect)
                child_path = QPainterPath()
                child_path.addRect(child_rect)
                info_regions.append(
                    (
                        child_path,
                        _format_info_bubble(
                            child['label'],
                            [("Group", group['label']), ("Value", _format_number(child['value']))],
                        ),
                    )
                )
                if child_rect.width() > 50 and child_rect.height() > 24:
                    painter.setPen(QColor("white"))
                    painter.drawText(child_rect.adjusted(4, 4, -4, -4), Qt.AlignLeft | Qt.AlignTop | Qt.TextWordWrap, child['label'])
        self._set_inspector_regions(info_regions)


class _SunburstCanvas(_InteractiveChartCanvas):
    """Custom sunburst renderer with inner groups and outer leaves."""

    def __init__(self, groups: List[dict], *, compact_mode: bool, center_label: str = "Total", parent: QWidget = None):
        super().__init__(parent)
        self.groups = groups
        self.compact_mode = compact_mode
        self.center_label = center_label
        self.setMinimumHeight(140 if compact_mode else 280)

    def paintEvent(self, event):
        if not self.groups:
            return

        info_regions: List[tuple[Any, str]] = []

        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        outer_rect = self.rect().adjusted(12, 12, -12, -12)
        size = min(outer_rect.width(), outer_rect.height())
        center = outer_rect.center()
        outer_radius = size / 2.0
        split_radius = outer_radius * 0.58
        hole_radius = outer_radius * 0.28
        total_value = sum(group['value'] for group in self.groups) or 1.0
        start_angle = 90.0 * 16

        def rect_for_radius(radius: float) -> QRectF:
            return QRectF(center.x() - radius, center.y() - radius, radius * 2.0, radius * 2.0)

        def point_at_angle(radius: float, angle_degrees: float) -> QPointF:
            radians = math.radians(-angle_degrees)
            return QPointF(
                center.x() + (math.cos(radians) * radius),
                center.y() + (math.sin(radians) * radius),
            )

        def ring_segment_path(outer_segment_radius: float, inner_segment_radius: float, start: float, span: float) -> QPainterPath:
            start_degrees = start / 16.0
            span_degrees = span / 16.0
            end_degrees = start_degrees + span_degrees
            outer_segment_rect = rect_for_radius(outer_segment_radius)
            inner_segment_rect = rect_for_radius(inner_segment_radius)

            path = QPainterPath()
            path.arcMoveTo(outer_segment_rect, start_degrees)
            path.arcTo(outer_segment_rect, start_degrees, span_degrees)
            path.lineTo(point_at_angle(inner_segment_radius, end_degrees))
            path.arcTo(inner_segment_rect, end_degrees, -span_degrees)
            path.closeSubpath()
            return path

        def draw_arc_label(primary_text: str, secondary_text: str, start: float, span: float, *, outer_segment_radius: float, inner_segment_radius: float, fill_color: QColor, min_span_degrees: float, font_scale: int = 0):
            if self.compact_mode or (not primary_text and not secondary_text):
                return
            span_degrees = abs(span) / 16.0
            value_only_min_span = max(4.5, min_span_degrees * 0.35)
            if span_degrees < value_only_min_span:
                return

            font = painter.font()
            font.setPointSize(max(font.pointSize() + font_scale, 8))
            font.setBold(True)

            label_radius = (outer_segment_radius + inner_segment_radius) / 2.0
            available_width = max(36.0, min(math.radians(span_degrees) * label_radius * 0.9, 150.0))
            available_height = max(20.0, min((outer_segment_radius - inner_segment_radius) * 0.9, 56.0))

            compact_secondary_text = str(secondary_text or "")
            if compact_secondary_text and '(' in compact_secondary_text and available_width < 76.0:
                compact_secondary_text = compact_secondary_text.split(' ', 1)[0]

            show_name = bool(primary_text) and span_degrees >= min_span_degrees and available_width >= 62.0 and available_height >= 28.0
            use_value_only = not show_name and bool(compact_secondary_text)
            if use_value_only:
                font.setPointSize(max(font.pointSize() - 1, 7))

            painter.setFont(font)
            metrics = painter.fontMetrics()

            raw_lines = []
            if compact_secondary_text:
                raw_lines.append(compact_secondary_text)
            if show_name:
                raw_lines.insert(0, primary_text)
            elif not raw_lines and primary_text:
                raw_lines = [primary_text]

            if not raw_lines:
                return

            fitted_lines = [
                metrics.elidedText(line, Qt.ElideRight, max(24, int(available_width)))
                for line in raw_lines
            ]
            if not any(line.strip() for line in fitted_lines):
                return

            total_text_height = max(metrics.height() * len(fitted_lines) + 4, 18)
            text_width = max(metrics.horizontalAdvance(line) for line in fitted_lines) + 8
            text_rect = QRectF(0, 0, min(max(text_width, 40.0), available_width), min(total_text_height, available_height))

            mid_degrees = (start + (span / 2.0)) / 16.0
            label_center = point_at_angle(label_radius, mid_degrees)
            text_rect.moveCenter(label_center)

            outer_bounds = rect_for_radius(outer_segment_radius - 4.0)
            if text_rect.left() < outer_bounds.left():
                text_rect.moveLeft(outer_bounds.left())
            if text_rect.right() > outer_bounds.right():
                text_rect.moveRight(outer_bounds.right())
            if text_rect.top() < outer_bounds.top():
                text_rect.moveTop(outer_bounds.top())
            if text_rect.bottom() > outer_bounds.bottom():
                text_rect.moveBottom(outer_bounds.bottom())

            painter.setPen(QColor("#ffffff") if fill_color.lightness() < 150 else QColor("#111827"))
            painter.drawText(text_rect, Qt.AlignCenter | Qt.TextWordWrap, "\n".join(fitted_lines))

        outer_pen = QPen(QColor("white"), 1)
        for group_index, group in enumerate(self.groups):
            span_angle = -360.0 * 16 * (group['value'] / total_value)
            painter.setPen(outer_pen)
            group_color = _palette(group_index).lighter(110)
            painter.setBrush(QBrush(group_color))
            group_path = ring_segment_path(split_radius, hole_radius, start_angle, span_angle)
            painter.drawPath(group_path)

            group_percent = (group['value'] / total_value) * 100.0
            info_regions.append(
                (
                    group_path,
                    _format_info_bubble(
                        str(group['label']),
                        [("Value", _format_number(group['value'])), ("Share", f"{group_percent:.1f}%")],
                    ),
                )
            )
            draw_arc_label(
                str(group['label']),
                f"{_format_number(group['value'])} ({group_percent:.0f}%)",
                start_angle,
                span_angle,
                outer_segment_radius=split_radius,
                inner_segment_radius=hole_radius,
                fill_color=group_color,
                min_span_degrees=28.0,
            )

            child_start = start_angle
            child_total = sum(item['value'] for item in group['children']) or 1.0
            for child_index, child in enumerate(group['children']):
                child_span = span_angle * (child['value'] / child_total)
                child_color = _palette(group_index + child_index + 1).darker(105 + (child_index * 8))
                painter.setBrush(QBrush(child_color))
                child_path = ring_segment_path(outer_radius, split_radius, child_start, child_span)
                painter.drawPath(child_path)

                child_percent = (child['value'] / total_value) * 100.0
                info_regions.append(
                    (
                        child_path,
                        _format_info_bubble(
                            str(child['label']),
                            [
                                ("Group", str(group['label'])),
                                ("Value", _format_number(child['value'])),
                                ("Share", f"{child_percent:.1f}%"),
                            ],
                        ),
                    )
                )

                draw_arc_label(
                    str(child['label']),
                    _format_number(child['value']),
                    child_start,
                    child_span,
                    outer_segment_radius=outer_radius,
                    inner_segment_radius=split_radius,
                    fill_color=child_color,
                    min_span_degrees=18.0,
                    font_scale=-1,
                )
                child_start += child_span

            start_angle += span_angle

        hole_rect = rect_for_radius(hole_radius - 2.0)
        painter.setPen(Qt.NoPen)
        painter.setBrush(QColor("white"))
        painter.drawEllipse(hole_rect)

        if not self.compact_mode:
            total_value = sum(group['value'] for group in self.groups)
            label_font = painter.font()
            label_font.setPointSize(max(label_font.pointSize() - 1, 8))
            label_font.setBold(True)
            painter.setFont(label_font)
            painter.setPen(QColor("#1f2937"))
            painter.drawText(hole_rect, Qt.AlignCenter, f"{self.center_label}\n{_format_number(total_value)}")
        self._set_inspector_regions(info_regions)


def _build_grouped_items(data: List[Dict[str, Any]], config: Dict[str, Any], *, fallback_group: str = "Group") -> List[dict]:
    config = config or {}
    value_field = _infer_value_field(data, config)
    label_field = _infer_category_field(data, config, value_field)
    group_field = config.get("seriesField")
    if not value_field or not label_field:
        return []

    grouped = {}
    for row in data:
        value = _coerce_number(row.get(value_field))
        label = str(row.get(label_field, '') or '')
        if value is None or value <= 0 or not label:
            continue
        group_name = str(row.get(group_field, fallback_group) or fallback_group) if group_field else fallback_group
        entry = grouped.setdefault(group_name, {"label": group_name, "value": 0.0, "children": []})
        entry["value"] += value
        entry["children"].append({"label": label, "value": value})

    return list(grouped.values())


def _format_x_value(value: float, *, is_datetime: bool) -> str:
    if is_datetime:
        return QDateTime.fromMSecsSinceEpoch(int(value)).toString("hh:mm:ss")
    return _format_number(value)


class _AreaCanvas(_InteractiveChartCanvas):
    """Custom-painted area chart to avoid QAreaSeries crashes on Windows."""

    def __init__(self, points: List[tuple[float, float]], *, is_datetime: bool, compact_mode: bool, parent: QWidget = None):
        super().__init__(parent)
        self.points = points
        self.is_datetime = is_datetime
        self.compact_mode = compact_mode
        self.setMinimumHeight(120 if compact_mode else 260)

    def paintEvent(self, event):
        if not self.points:
            return

        info_regions: List[tuple[Any, str]] = []

        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)

        left_margin = 10 if self.compact_mode else 46
        top_margin = 10
        right_margin = 10
        bottom_margin = 12 if self.compact_mode else 34
        plot_rect = self.rect().adjusted(left_margin, top_margin, -right_margin, -bottom_margin)
        if plot_rect.width() <= 0 or plot_rect.height() <= 0:
            return

        x_values = [point[0] for point in self.points]
        y_values = [point[1] for point in self.points]
        min_x = min(x_values)
        max_x = max(x_values)
        if min_x == max_x:
            max_x += 1.0
        max_y = max(y_values) if y_values else 1.0
        if max_y <= 0:
            max_y = 1.0

        def map_point(x_value: float, y_value: float) -> QPointF:
            x_ratio = (x_value - min_x) / (max_x - min_x)
            y_ratio = y_value / max_y
            x_pos = plot_rect.left() + (x_ratio * plot_rect.width())
            y_pos = plot_rect.bottom() - (y_ratio * plot_rect.height())
            return QPointF(x_pos, y_pos)

        mapped_points = [map_point(x_value, y_value) for x_value, y_value in self.points]
        for (x_value, y_value), mapped_point in zip(self.points, mapped_points):
            point_path = QPainterPath()
            point_path.addEllipse(mapped_point, 10.0, 10.0)
            info_regions.append(
                (
                    point_path,
                    _format_info_bubble(
                        "Area Point",
                        [
                            ("X", _format_x_value(x_value, is_datetime=self.is_datetime)),
                            ("Y", _format_number(y_value)),
                        ],
                    ),
                )
            )
        polygon = QPolygonF()
        polygon.append(QPointF(mapped_points[0].x(), plot_rect.bottom()))
        for point in mapped_points:
            polygon.append(point)
        polygon.append(QPointF(mapped_points[-1].x(), plot_rect.bottom()))

        axis_pen = QPen(QColor("#c3cad4"), 1)
        painter.setPen(axis_pen)
        painter.drawLine(plot_rect.bottomLeft(), plot_rect.topLeft())
        painter.drawLine(plot_rect.bottomLeft(), plot_rect.bottomRight())

        painter.setPen(Qt.NoPen)
        painter.setBrush(QBrush(QColor(0, 102, 204, 90)))
        painter.drawPolygon(polygon)

        painter.setPen(QPen(QColor("#0066cc"), 2))
        painter.setBrush(Qt.NoBrush)
        painter.drawPolyline(QPolygonF(mapped_points))

        if self.compact_mode:
            return

        label_pen = QPen(QColor("#666"))
        painter.setPen(label_pen)
        painter.drawText(
            int(plot_rect.left() - 40),
            int(plot_rect.top()),
            34,
            18,
            Qt.AlignRight | Qt.AlignTop,
            _format_number(max_y),
        )
        painter.drawText(
            int(plot_rect.left() - 40),
            int(plot_rect.bottom() - 10),
            34,
            18,
            Qt.AlignRight | Qt.AlignVCenter,
            "0",
        )
        painter.drawText(
            int(plot_rect.left()),
            int(plot_rect.bottom() + 6),
            90,
            18,
            Qt.AlignLeft | Qt.AlignTop,
            _format_x_value(min_x, is_datetime=self.is_datetime),
        )
        painter.drawText(
            int(plot_rect.right() - 90),
            int(plot_rect.bottom() + 6),
            90,
            18,
            Qt.AlignRight | Qt.AlignTop,
            _format_x_value(max_x, is_datetime=self.is_datetime),
        )
        self._set_inspector_regions(info_regions)


class VisualizationRegistry:
    """Registry for visualization types and renderers"""
    
    def __init__(self):
        self.renderers: Dict[str, Callable] = {}
    
    def register(self, viz_type: str, renderer: Callable):
        """Register a renderer for a visualization type"""
        self.renderers[viz_type] = renderer
    
    def get_renderer(self, viz_type: str) -> Optional[Callable]:
        """Get renderer for a visualization type"""
        return self.renderers.get(viz_type)
    
    def list_types(self) -> List[str]:
        """List all registered visualization types"""
        return list(self.renderers.keys())
    
    def is_compatible(self, viz_type: str, dataset_schema: Dict[str, Any]) -> bool:
        """Check if a visualization type is compatible with a dataset schema"""
        # Simplified compatibility check
        # In production, each renderer would define its schema requirements
        fields = dataset_schema.get("fields", [])
        
        if viz_type == "metric":
            return len(fields) >= 1
        
        elif viz_type == "table":
            return True  # Tables work with any schema
        
        elif viz_type in {"bar", "horizontal_bar", "pie", "donut", "radar", "treemap", "sunburst"}:
            return len(fields) >= 2  # Need at least category and value
        
        elif viz_type in {"line", "area", "scatter"}:
            has_time = any(f.get("name") == "time" for f in fields)
            return has_time and len(fields) >= 2  # Need time and value field
        
        elif viz_type == "histogram":
            has_numeric = any(f.get("type") in ["int", "float"] for f in fields)
            return has_numeric
        
        elif viz_type == "topology":
            return len(fields) >= 2  # Need node and edge data
        
        return True


class MetricRenderer:
    """Renders single metric display (KPI card)"""
    
    @staticmethod
    def render(data: List[Dict], config: Dict[str, Any], parent: QWidget = None) -> QWidget:
        """
        Render metric card showing a single aggregated value.
        
        Expected data: List with 1 row containing the metric value
        """
        widget = QWidget(parent)
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(20, 20, 20, 20)
        
        if not data:
            label = QLabel("No data")
            label.setStyleSheet("color: #999; font-size: 14pt;")
            layout.addWidget(label)
            return widget

        row = data[0]
        value_field = _infer_value_field(data, config or {})
        value = row.get(value_field, next(iter(row.values()), "N/A"))
        
        # Format number if applicable
        if isinstance(value, (int, float)):
            if isinstance(value, float):
                value = f"{value:.2f}"
        
        value_label = QLabel(str(value))
        value_font = QFont()
        value_font.setPointSize(32)
        value_font.setBold(True)
        value_label.setFont(value_font)
        value_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(value_label)

        if _semantic_annotations_enabled(config or {}):
            caption = QLabel(_humanize_field_name(value_field, fallback="Metric"))
            caption.setAlignment(Qt.AlignCenter)
            caption.setWordWrap(True)
            caption.setStyleSheet("color: #666; font-size: 10pt;")
            layout.addWidget(caption)

        _attach_static_inspector(
            widget,
            _humanize_field_name(value_field, fallback="Metric"),
            [("Value", str(value))],
        )
        
        layout.addStretch()
        return widget


class TableRenderer:
    """Renders data as a table"""
    
    @staticmethod
    def render(data: List[Dict], config: Dict[str, Any], parent: QWidget = None) -> QWidget:
        """Render data as a table widget"""
        widget = QWidget(parent)
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        if not data:
            label = QLabel("No data")
            layout.addWidget(label)
            return widget
        
        table = QTableWidget()
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.setSelectionMode(QAbstractItemView.SingleSelection)
        
        # Get column names from first row
        columns = list(data[0].keys())
        table.setColumnCount(len(columns))
        table.setHorizontalHeaderLabels([_humanize_field_name(column) for column in columns])
        
        # Populate rows
        table.setRowCount(len(data))
        for row_idx, row in enumerate(data):
            for col_idx, col in enumerate(columns):
                value = row.get(col, "")
                item = QTableWidgetItem(str(value))
                table.setItem(row_idx, col_idx, item)
        
        # Auto-resize columns
        table.resizeColumnsToContents()
        layout.addWidget(table)
        _attach_table_inspector(table)
        
        return widget


class BarChartRenderer:
    """Renders bar chart."""
    
    @staticmethod
    def render(data: List[Dict], config: Dict[str, Any], parent: QWidget = None) -> QWidget:
        if not data:
            return _empty_widget("No data", parent)

        value_field = _infer_value_field(data, config or {})
        category_field = _infer_category_field(data, config or {}, value_field)
        if not value_field or not category_field:
            return _empty_widget("Chart fields are not configured", parent)

        categories = []
        values = []
        for row in data:
            value = _coerce_number(row.get(value_field))
            category = str(row.get(category_field, '') or '')
            if value is None or not category:
                continue
            categories.append(category)
            values.append(value)

        if not values:
            return _empty_widget("No plottable data", parent)

        bar_set = QBarSet(value_field)
        for value in values:
            bar_set.append(value)

        series = QBarSeries()
        series.append(bar_set)
        if hasattr(series, "setLabelsVisible"):
            series.setLabelsVisible(_semantic_annotations_enabled(config or {}))

        chart = QChart()
        chart.addSeries(series)
        chart.legend().setVisible(bool((config or {}).get("showLegend", True)))
        chart.setBackgroundVisible(False)
        chart.setMargins(QMargins(0, 0, 0, 0))

        axis_x = QBarCategoryAxis()
        axis_x.append(categories)
        _set_axis_title(axis_x, category_field, config, fallback="Category")
        chart.addAxis(axis_x, Qt.AlignBottom)
        series.attachAxis(axis_x)

        axis_y = QValueAxis()
        axis_y.setLabelFormat("%.0f")
        axis_y.setMin(0)
        axis_y.setMax(max(values) * 1.15 if max(values) > 0 else 1)
        _set_axis_title(axis_y, value_field, config, fallback="Value")
        chart.addAxis(axis_y, Qt.AlignLeft)
        series.attachAxis(axis_y)

        view = _build_chart_view(chart, parent)
        tracker = _ensure_pointer_inspector(view)
        signal = getattr(series, "pressed", None) or getattr(series, "clicked", None)
        if signal is not None:
            signal.connect(
                lambda index, _bar_set=None, tracker=tracker, categories=categories, values=values, category_field=category_field, value_field=value_field:
                tracker.start(
                    _format_info_bubble(
                        str(categories[index]),
                        [(_humanize_field_name(value_field, fallback="Value"), _format_number(values[index]))],
                    )
                )
            )
        if not _semantic_annotations_enabled(config or {}):
            return view
        return _wrap_with_chart_context(
            view,
            [
                f"X Axis: {_humanize_field_name(category_field, fallback='Category')} | Y Axis: {_humanize_field_name(value_field, fallback='Value')}",
                f"Bars show {_humanize_field_name(value_field, fallback='Value')} for each {_humanize_field_name(category_field, fallback='Category')}",
            ],
            parent,
        )


class HorizontalBarChartRenderer:
    """Renders horizontal clustered bar chart."""

    @staticmethod
    def render(data: List[Dict], config: Dict[str, Any], parent: QWidget = None) -> QWidget:
        if not data:
            return _empty_widget("No data", parent)

        value_field = _infer_value_field(data, config or {})
        category_field = _infer_category_field(data, config or {}, value_field)
        if not value_field or not category_field:
            return _empty_widget("Chart fields are not configured", parent)

        categories = []
        values = []
        for row in data:
            value = _coerce_number(row.get(value_field))
            category = str(row.get(category_field, '') or '')
            if value is None or not category:
                continue
            categories.append(category)
            values.append(value)

        if not values:
            return _empty_widget("No plottable data", parent)

        bar_set = QBarSet(value_field)
        for value in values:
            bar_set.append(value)

        series = QHorizontalBarSeries()
        series.append(bar_set)
        if hasattr(series, "setLabelsVisible"):
            series.setLabelsVisible(_semantic_annotations_enabled(config or {}))

        chart = QChart()
        chart.addSeries(series)
        chart.legend().setVisible(bool((config or {}).get("showLegend", True)))
        chart.setBackgroundVisible(False)
        chart.setMargins(QMargins(0, 0, 0, 0))

        axis_y = QBarCategoryAxis()
        axis_y.append(categories)
        _set_axis_title(axis_y, category_field, config, fallback="Category")
        chart.addAxis(axis_y, Qt.AlignLeft)
        series.attachAxis(axis_y)

        axis_x = QValueAxis()
        axis_x.setLabelFormat("%.0f")
        axis_x.setMin(0)
        axis_x.setMax(max(values) * 1.15 if max(values) > 0 else 1)
        _set_axis_title(axis_x, value_field, config, fallback="Value")
        chart.addAxis(axis_x, Qt.AlignBottom)
        series.attachAxis(axis_x)

        view = _build_chart_view(chart, parent)
        tracker = _ensure_pointer_inspector(view)
        signal = getattr(series, "pressed", None) or getattr(series, "clicked", None)
        if signal is not None:
            signal.connect(
                lambda index, _bar_set=None, tracker=tracker, categories=categories, values=values, category_field=category_field, value_field=value_field:
                tracker.start(
                    _format_info_bubble(
                        str(categories[index]),
                        [(_humanize_field_name(value_field, fallback="Value"), _format_number(values[index]))],
                    )
                )
            )
        if not _semantic_annotations_enabled(config or {}):
            return view
        return _wrap_with_chart_context(
            view,
            [
                f"X Axis: {_humanize_field_name(value_field, fallback='Value')} | Y Axis: {_humanize_field_name(category_field, fallback='Category')}",
                f"Bars compare {_humanize_field_name(value_field, fallback='Value')} across {_humanize_field_name(category_field, fallback='Category')}",
            ],
            parent,
        )


class LineChartRenderer:
    """Renders line chart."""
    
    @staticmethod
    def render(data: List[Dict], config: Dict[str, Any], parent: QWidget = None) -> QWidget:
        if not data:
            return _empty_widget("No data", parent)

        config = config or {}
        x_field, y_field, numeric_points, datetime_points = _extract_xy_points(data, config)
        if not y_field:
            return _empty_widget("Line chart is missing a numeric field", parent)

        series = QLineSeries()

        if datetime_points:
            for x_value, y_value in datetime_points:
                series.append(x_value, y_value)
        elif numeric_points:
            for x_value, y_value in numeric_points:
                series.append(x_value, y_value)
        else:
            return _empty_widget("No plottable data", parent)

        chart = QChart()
        chart.addSeries(series)
        chart.legend().setVisible(bool(config.get("showLegend", False)))
        chart.setBackgroundVisible(False)
        chart.setMargins(QMargins(0, 0, 0, 0))

        if hasattr(series, "setName"):
            series.setName(_humanize_field_name(y_field, fallback="Value"))
        if hasattr(series, "setPointsVisible"):
            series.setPointsVisible(_semantic_annotations_enabled(config))
        if hasattr(series, "setPointLabelsVisible"):
            series.setPointLabelsVisible(_semantic_annotations_enabled(config))
        if hasattr(series, "setPointLabelsFormat"):
            series.setPointLabelsFormat("@yPoint")

        _configure_xy_axes(chart, series, numeric_points, datetime_points, x_field, y_field, config)

        view = _build_chart_view(chart, parent)
        tracker = _ensure_pointer_inspector(view)
        signal = getattr(series, "pressed", None) or getattr(series, "clicked", None)
        if signal is not None:
            signal.connect(
                lambda point, tracker=tracker, x_field=x_field, y_field=y_field, is_datetime=bool(datetime_points):
                tracker.start(
                    _format_info_bubble(
                        "Line Point",
                        [
                            (_humanize_field_name(x_field, fallback="X Axis"), _format_x_value(point.x(), is_datetime=is_datetime)),
                            (_humanize_field_name(y_field, fallback="Value"), _format_number(point.y())),
                        ],
                    )
                )
            )
        if not _semantic_annotations_enabled(config):
            return view
        return _wrap_with_chart_context(
            view,
            [
                f"X Axis: {_humanize_field_name(x_field, fallback='X Axis')} | Y Axis: {_humanize_field_name(y_field, fallback='Value')}",
                f"Line tracks {_humanize_field_name(y_field, fallback='Value')} over {_humanize_field_name(x_field, fallback='X Axis')}",
            ],
            parent,
        )


class AreaChartRenderer:
    """Renders area chart with a custom-painted fill to avoid Qt native crashes."""

    @staticmethod
    def render(data: List[Dict], config: Dict[str, Any], parent: QWidget = None) -> QWidget:
        if not data:
            return _empty_widget("No data", parent)

        config = config or {}
        x_field, y_field, numeric_points, datetime_points = _extract_xy_points(data, config)
        if not y_field:
            return _empty_widget("Area chart is missing a numeric field", parent)

        points = datetime_points or numeric_points
        if not points:
            return _empty_widget("No plottable data", parent)

        compact_mode = bool(config.get("compactMode", False))
        container = QWidget(parent)
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)

        if not compact_mode:
            y_axis_label = QLabel(f"Y Axis: {_humanize_field_name(y_field, fallback='Value')}")
            y_axis_label.setStyleSheet("color: #666; font-size: 9pt;")
            layout.addWidget(y_axis_label)

        canvas = _AreaCanvas(
            points,
            is_datetime=bool(datetime_points),
            compact_mode=compact_mode,
            parent=container,
        )
        layout.addWidget(canvas, 1)

        if not compact_mode:
            x_axis_label = QLabel(f"X Axis: {_humanize_field_name(x_field, fallback='X Axis')}")
            x_axis_label.setAlignment(Qt.AlignRight)
            x_axis_label.setStyleSheet("color: #666; font-size: 9pt;")
            layout.addWidget(x_axis_label)

        return container


class ScatterChartRenderer:
    """Renders scatter chart."""

    @staticmethod
    def render(data: List[Dict], config: Dict[str, Any], parent: QWidget = None) -> QWidget:
        if not data:
            return _empty_widget("No data", parent)

        config = config or {}
        x_field, y_field, numeric_points, datetime_points = _extract_xy_points(data, config)
        if not y_field:
            return _empty_widget("Scatter chart is missing numeric fields", parent)

        points = datetime_points or numeric_points
        if not points:
            return _empty_widget("No plottable data", parent)

        series = QScatterSeries()
        series.setMarkerSize(10.0 if not config.get("compactMode") else 7.0)
        series.setColor(QColor("#0066cc"))
        for x_value, y_value in points:
            series.append(x_value, y_value)

        chart = QChart()
        chart.addSeries(series)
        chart.legend().setVisible(False)
        chart.setBackgroundVisible(False)
        chart.setMargins(QMargins(0, 0, 0, 0))

        if hasattr(series, "setName"):
            series.setName(_humanize_field_name(y_field, fallback="Value"))
        if hasattr(series, "setPointLabelsVisible"):
            series.setPointLabelsVisible(_semantic_annotations_enabled(config))
        if hasattr(series, "setPointLabelsFormat"):
            series.setPointLabelsFormat("(@xPoint, @yPoint)")

        _configure_xy_axes(chart, series, numeric_points, datetime_points, x_field, y_field, config)
        view = _build_chart_view(chart, parent)
        tracker = _ensure_pointer_inspector(view)
        signal = getattr(series, "pressed", None) or getattr(series, "clicked", None)
        if signal is not None:
            signal.connect(
                lambda point, tracker=tracker, x_field=x_field, y_field=y_field, is_datetime=bool(datetime_points):
                tracker.start(
                    _format_info_bubble(
                        "Scatter Point",
                        [
                            (_humanize_field_name(x_field, fallback="X Axis"), _format_x_value(point.x(), is_datetime=is_datetime)),
                            (_humanize_field_name(y_field, fallback="Value"), _format_number(point.y())),
                        ],
                    )
                )
            )
        if not _semantic_annotations_enabled(config):
            return view
        return _wrap_with_chart_context(
            view,
            [
                f"X Axis: {_humanize_field_name(x_field, fallback='X Axis')} | Y Axis: {_humanize_field_name(y_field, fallback='Value')}",
                f"Points plot {_humanize_field_name(y_field, fallback='Value')} against {_humanize_field_name(x_field, fallback='X Axis')}",
            ],
            parent,
        )


class RadarChartRenderer:
    """Renders radar chart using a custom painter canvas."""

    @staticmethod
    def render(data: List[Dict], config: Dict[str, Any], parent: QWidget = None) -> QWidget:
        if not data:
            return _empty_widget("No data", parent)

        value_field = _infer_value_field(data, config or {})
        category_field = _infer_category_field(data, config or {}, value_field)
        if not value_field or not category_field:
            return _empty_widget("Radar chart fields are not configured", parent)

        labels = []
        values = []
        for row in data[:8]:
            value = _coerce_number(row.get(value_field))
            category = str(row.get(category_field, '') or '')
            if value is None or not category:
                continue
            labels.append(category)
            values.append(value)

        if not values:
            return _empty_widget("No plottable data", parent)

        widget = QWidget(parent)
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)
        layout.addWidget(_RadarCanvas(labels, values, compact_mode=bool((config or {}).get("compactMode", False)), parent=widget), 1)

        if not bool((config or {}).get("compactMode", False)):
            axis_label = QLabel(f"Axes: {_humanize_field_name(category_field, fallback='Category')} | Value: {_humanize_field_name(value_field, fallback='Value')}")
            axis_label.setStyleSheet("color: #666; font-size: 9pt;")
            layout.addWidget(axis_label)

        return widget


class TreemapRenderer:
    """Renders treemap chart using grouped rectangles."""

    @staticmethod
    def render(data: List[Dict], config: Dict[str, Any], parent: QWidget = None) -> QWidget:
        groups = _build_grouped_items(data, config, fallback_group="Items")
        if not groups:
            return _empty_widget("Treemap needs categories and values", parent)

        widget = QWidget(parent)
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)
        layout.addWidget(_TreemapCanvas(groups, compact_mode=bool((config or {}).get("compactMode", False)), parent=widget), 1)
        if not bool((config or {}).get("compactMode", False)):
            group_field = (config or {}).get("seriesField")
            label_text = f"Group: {_humanize_field_name(group_field, fallback='Items')} | Size: {_humanize_field_name(_infer_value_field(data, config or {}), fallback='Value')}"
            meta = QLabel(label_text)
            meta.setStyleSheet("color: #666; font-size: 9pt;")
            layout.addWidget(meta)
        return widget


class SunburstRenderer:
    """Renders sunburst chart using concentric arcs."""

    @staticmethod
    def render(data: List[Dict], config: Dict[str, Any], parent: QWidget = None) -> QWidget:
        groups = _build_grouped_items(data, config, fallback_group="Items")
        if not groups:
            return _empty_widget("Sunburst needs grouped values", parent)

        config = config or {}
        return _SunburstCanvas(
            groups,
            compact_mode=bool(config.get("compactMode", False)),
            center_label=_humanize_field_name(_infer_value_field(data, config), fallback="Value"),
            parent=parent,
        )


class PieChartRenderer:
    """Renders pie chart (placeholder)"""
    
    @staticmethod
    def render(data: List[Dict], config: Dict[str, Any], parent: QWidget = None) -> QWidget:
        return PieChartRenderer._render_pie(data, config, parent, donut=False)

    @staticmethod
    def _render_pie(data: List[Dict], config: Dict[str, Any], parent: QWidget = None, donut: bool = False) -> QWidget:
        if not data:
            return _empty_widget("No data", parent)

        config = config or {}
        value_field = _infer_value_field(data, config or {})
        category_field = _infer_category_field(data, config or {}, value_field)
        if not value_field or not category_field:
            return _empty_widget("Chart fields are not configured", parent)

        slices = []
        total = 0.0
        for row in data:
            value = _coerce_number(row.get(value_field))
            category = str(row.get(category_field, '') or '')
            if value is None or value <= 0 or not category:
                continue
            slices.append((category, value))
            total += value

        series = QPieSeries()
        for index, (category, value) in enumerate(slices):
            pie_slice = series.append(category, value)
            pie_slice.setColor(_palette(index))
            percent = 0.0 if total <= 0 else (value / total) * 100.0
            pie_slice.setLabel(f"{category}: {_format_number(value)} ({percent:.1f}%)")
            if hasattr(pie_slice, "setLabelVisible"):
                pie_slice.setLabelVisible(_semantic_annotations_enabled(config))

        if not series.slices():
            return _empty_widget("No plottable data", parent)

        if donut:
            series.setHoleSize(0.45)

        chart = QChart()
        chart.addSeries(series)
        chart.legend().setVisible(bool(config.get("showLegend", True)) or _semantic_annotations_enabled(config))
        chart.setBackgroundVisible(False)
        chart.setMargins(QMargins(0, 0, 0, 0))

        view = _build_chart_view(chart, parent)
        tracker = _ensure_pointer_inspector(view)
        for slice_index, pie_slice in enumerate(series.slices()):
            category, value = slices[slice_index]
            percent = 0.0 if total <= 0 else (value / total) * 100.0
            signal = getattr(pie_slice, "pressed", None) or getattr(pie_slice, "clicked", None)
            if signal is not None:
                signal.connect(
                    lambda tracker=tracker, category=category, value=value, percent=percent, value_field=value_field:
                    tracker.start(
                        _format_info_bubble(
                            str(category),
                            [
                                (_humanize_field_name(value_field, fallback="Value"), _format_number(value)),
                                ("Share", f"{percent:.1f}%"),
                            ],
                        )
                    )
                )
        if not _semantic_annotations_enabled(config):
            return view

        chart_kind = "Donut" if donut else "Pie"
        context_lines = [
            f"Slices: {_humanize_field_name(category_field, fallback='Category')} | Size: {_humanize_field_name(value_field, fallback='Value')}",
            f"{chart_kind} segments show {_humanize_field_name(value_field, fallback='Value')} for each {_humanize_field_name(category_field, fallback='Category')}",
        ]

        if donut:
            top_slices = sorted(slices, key=lambda item: item[1], reverse=True)[:3]
            summary_parts = [
                f"Total {_humanize_field_name(value_field, fallback='Value')}: {_format_number(total)}"
            ]
            for category, value in top_slices:
                percent = 0.0 if total <= 0 else (value / total) * 100.0
                summary_parts.append(f"{category}: {_format_number(value)} ({percent:.1f}%)")
            context_lines.append(" | ".join(summary_parts))

        return _wrap_with_chart_context(view, context_lines, parent)


class DonutChartRenderer:
    """Renders donut chart (placeholder)"""
    
    @staticmethod
    def render(data: List[Dict], config: Dict[str, Any], parent: QWidget = None) -> QWidget:
        return PieChartRenderer._render_pie(data, config, parent, donut=True)


class HistogramRenderer:
    """Renders histogram using numeric bins."""
    
    @staticmethod
    def render(data: List[Dict], config: Dict[str, Any], parent: QWidget = None) -> QWidget:
        if not data:
            return _empty_widget("No data", parent)

        config = config or {}
        numeric_field = config.get("valueField") or config.get("yField")
        if not numeric_field or not any(numeric_field in row for row in data):
            numeric_field = _infer_value_field(data, config)
        if not numeric_field:
            return _empty_widget("Histogram is missing a numeric field", parent)

        values = [
            numeric_value
            for row in data
            for numeric_value in [_coerce_number(row.get(numeric_field))]
            if numeric_value is not None
        ]
        if not values:
            return _empty_widget("No plottable data", parent)

        min_value = min(values)
        max_value = max(values)
        if min_value == max_value:
            labels = [_format_number(min_value)]
            counts = [len(values)]
        else:
            bin_count = min(8, max(4, int(math.sqrt(len(values)))))
            bin_width = (max_value - min_value) / bin_count or 1.0
            counts = [0] * bin_count
            for value in values:
                index = min(bin_count - 1, int((value - min_value) / bin_width))
                counts[index] += 1
            labels = []
            for index in range(bin_count):
                low = min_value + (index * bin_width)
                high = min_value + ((index + 1) * bin_width)
                labels.append(f"{_format_number(low)}-{_format_number(high)}")

        bar_set = QBarSet("Frequency")
        for count in counts:
            bar_set.append(count)

        series = QBarSeries()
        series.append(bar_set)
        series.setBarWidth(1.0)
        if hasattr(series, "setLabelsVisible"):
            series.setLabelsVisible(_semantic_annotations_enabled(config))

        chart = QChart()
        chart.addSeries(series)
        chart.legend().setVisible(False)
        chart.setBackgroundVisible(False)
        chart.setMargins(QMargins(0, 0, 0, 0))

        axis_x = QBarCategoryAxis()
        axis_x.append(labels)
        _set_axis_title(axis_x, numeric_field, config, fallback="Bins")
        chart.addAxis(axis_x, Qt.AlignBottom)
        series.attachAxis(axis_x)

        axis_y = QValueAxis()
        axis_y.setLabelFormat("%.0f")
        axis_y.setRange(0, max(counts) * 1.15 if counts and max(counts) > 0 else 1)
        _set_axis_title(axis_y, "count", config, fallback="Frequency")
        chart.addAxis(axis_y, Qt.AlignLeft)
        series.attachAxis(axis_y)

        view = _build_chart_view(chart, parent)
        tracker = _ensure_pointer_inspector(view)
        signal = getattr(series, "pressed", None) or getattr(series, "clicked", None)
        if signal is not None:
            signal.connect(
                lambda index, _bar_set=None, tracker=tracker, labels=labels, counts=counts:
                tracker.start(
                    _format_info_bubble(
                        str(labels[index]),
                        [("Count", _format_number(counts[index]))],
                    )
                )
            )
        if not _semantic_annotations_enabled(config):
            return view
        return _wrap_with_chart_context(
            view,
            [
                f"X Axis: {_humanize_field_name(numeric_field, fallback='Bins')} bins | Y Axis: Count",
                f"Histogram counts how many records fall into each {_humanize_field_name(numeric_field, fallback='Value')} range",
            ],
            parent,
        )


class HeatmapRenderer:
    """Renders a heatmap-style matrix using colored table cells."""

    @staticmethod
    def render(data: List[Dict], config: Dict[str, Any], parent: QWidget = None) -> QWidget:
        if not data:
            return _empty_widget("No data", parent)

        config = config or {}
        value_field = config.get("valueField")
        label_field = config.get("categoryField")
        first_row = data[0]

        if not label_field or label_field not in first_row:
            label_field = next(
                (
                    key for key in first_row.keys()
                    if any(_coerce_number(row.get(key)) is None for row in data)
                ),
                None,
            )

        numeric_fields = [
            key for key in first_row.keys()
            if any(_coerce_number(row.get(key)) is not None for row in data)
        ]
        if value_field in numeric_fields:
            numeric_fields.remove(value_field)
            numeric_fields.insert(0, value_field)
        numeric_fields = numeric_fields[:4]

        if not label_field or not numeric_fields:
            return _empty_widget("Heatmap needs categories and numeric values", parent)

        widget = QWidget(parent)
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)

        table = QTableWidget()
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.setSelectionMode(QAbstractItemView.NoSelection)
        table.setSelectionBehavior(QAbstractItemView.SelectItems)
        table.setRowCount(len(data))
        table.setColumnCount(len(numeric_fields))
        table.setHorizontalHeaderLabels([_humanize_field_name(field) for field in numeric_fields])
        table.setVerticalHeaderLabels([
            str(row.get(label_field, index + 1))
            for index, row in enumerate(data)
        ])

        values = [
            numeric_value
            for row in data
            for field in numeric_fields
            for numeric_value in [_coerce_number(row.get(field))]
            if numeric_value is not None
        ]
        min_value = min(values) if values else 0.0
        max_value = max(values) if values else 1.0

        for row_index, row in enumerate(data):
            for col_index, field in enumerate(numeric_fields):
                numeric_value = _coerce_number(row.get(field))
                item = QTableWidgetItem("" if numeric_value is None else _format_number(numeric_value))
                item.setTextAlignment(Qt.AlignCenter)
                if numeric_value is not None:
                    ratio = 0.0 if max_value == min_value else (numeric_value - min_value) / (max_value - min_value)
                    color = QColor(
                        int(245 - (ratio * 120)),
                        int(248 - (ratio * 140)),
                        int(255 - (ratio * 20)),
                    )
                    item.setBackground(color)
                    if ratio > 0.6:
                        item.setForeground(QColor("white"))
                table.setItem(row_index, col_index, item)

        table.resizeColumnsToContents()
        layout.addWidget(table)
        _attach_table_inspector(table)
        if not _semantic_annotations_enabled(config):
            return widget
        return _wrap_with_chart_context(
            widget,
            [
                f"Rows: {_humanize_field_name(label_field, fallback='Category')} | Columns: {', '.join(_humanize_field_name(field) for field in numeric_fields)}",
            ],
            parent,
        )


class TopologyRenderer:
    """Renders network topology graph (placeholder)"""
    
    @staticmethod
    def render(data: List[Dict], config: Dict[str, Any], parent: QWidget = None) -> QWidget:
        return TableRenderer.render(data, config, parent)


def create_default_visualization_registry() -> VisualizationRegistry:
    """Create registry with default renderers"""
    registry = VisualizationRegistry()
    
    registry.register("metric", MetricRenderer.render)
    registry.register("table", TableRenderer.render)
    registry.register("bar", BarChartRenderer.render)
    registry.register("horizontal_bar", HorizontalBarChartRenderer.render)
    registry.register("line", LineChartRenderer.render)
    registry.register("pie", PieChartRenderer.render)
    registry.register("donut", DonutChartRenderer.render)
    registry.register("area", AreaChartRenderer.render)
    registry.register("scatter", ScatterChartRenderer.render)
    registry.register("radar", RadarChartRenderer.render)
    registry.register("treemap", TreemapRenderer.render)
    registry.register("sunburst", SunburstRenderer.render)
    registry.register("histogram", HistogramRenderer.render)
    registry.register("heatmap", HeatmapRenderer.render)
    registry.register("topology", TopologyRenderer.render)
    
    return registry
