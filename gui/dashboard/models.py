"""
Dashboard data models.

Defines all data structures for dashboards, widgets, queries, and visualizations.
Schema compatible with JSON serialization.
"""

import re
from dataclasses import dataclass, field, asdict, MISSING, fields as dataclass_fields
from typing import Optional, List, Dict, Any, get_args, get_origin, Union
from datetime import datetime
from enum import Enum


# Enum for visualization types
class VisualizationType(str, Enum):
    METRIC = "metric"
    TABLE = "table"
    BAR = "bar"
    HORIZONTAL_BAR = "horizontal_bar"
    LINE = "line"
    AREA = "area"
    SCATTER = "scatter"
    RADAR = "radar"
    TREEMAP = "treemap"
    SUNBURST = "sunburst"
    PIE = "pie"
    DONUT = "donut"
    HISTOGRAM = "histogram"
    HEATMAP = "heatmap"
    TOPOLOGY = "topology"


# Enum for time range modes
class TimeRangeMode(str, Enum):
    FULL_CAPTURE = "full_capture"
    LAST_10S = "last_10s"
    CUSTOM = "custom"
    SELECTED_PACKET_RANGE = "selected_packet_range"


# Enum for data scope
class DataScope(str, Enum):
    ALL_PACKETS = "all_packets"
    DISPLAYED_PACKETS = "displayed_packets"


# Query layer models
@dataclass
class QueryMetric:
    """Metric in a query (count, sum, avg, min, max, etc.)"""
    type: str  # count, sum, avg, min, max, distinct_count
    field: str  # field to apply metric on, "*" for count
    as_: str = field(metadata={"key": "as"})  # alias for result


@dataclass
class QuerySort:
    """Sort order in a query"""
    field: str
    direction: str = "asc"  # asc, desc


@dataclass
class WidgetQuery:
    """Query configuration for a widget"""
    filter: Optional[str] = None
    group_by: Optional[List[str]] = None
    metrics: Optional[List[QueryMetric]] = None
    sort: Optional[List[QuerySort]] = None
    limit: Optional[int] = None
    time_bucket: Optional[str] = None  # 1s, 1m, 1h, etc.
    columns: Optional[List[str]] = None  # for table query


# Visualization models
@dataclass
class VisualizationConfig:
    """Visualization configuration for a widget"""
    type: str  # bar, line, pie, etc.
    x_field: Optional[str] = None
    y_field: Optional[str] = None
    category_field: Optional[str] = None
    value_field: Optional[str] = None
    series_field: Optional[str] = None
    show_legend: bool = True
    show_labels: bool = False


# Layout models
@dataclass
class WidgetLayout:
    """Layout of a widget in the grid"""
    x: int
    y: int
    w: int  # width in columns (1-12)
    h: int  # height in rows (1+)


@dataclass
class DashboardLayout:
    """Dashboard grid layout configuration"""
    columns: int = 12
    row_height: int = 80


# Widget model
@dataclass
class DashboardWidget:
    """A widget in a dashboard"""
    id: str
    title: str
    data_source: str
    query: WidgetQuery
    visualization: VisualizationConfig
    layout: WidgetLayout
    description: Optional[str] = None
    style: Optional[Dict[str, Any]] = None


# Time range model
@dataclass
class TimeRange:
    """Time range configuration"""
    mode: str  # full_capture, last_10s, custom, selected_packet_range
    from_time: Optional[str] = None  # ISO 8601 format
    to_time: Optional[str] = None  # ISO 8601 format


# Dashboard thumbnail model
@dataclass
class DashboardThumbnail:
    """Dashboard thumbnail metadata"""
    mode: str  # static, skeleton, live
    image_url: Optional[str] = None
    generated_at: Optional[str] = None


# Full dashboard model
@dataclass
class Dashboard:
    """Complete dashboard configuration"""
    schema_version: int
    dashboard_id: str
    name: str
    description: Optional[str]
    is_template: bool
    created_at: str  # ISO 8601
    updated_at: str  # ISO 8601
    layout: DashboardLayout
    widgets: List[DashboardWidget]
    source_template_id: Optional[str] = None
    global_filter: Optional[str] = None
    time_range: Optional[TimeRange] = None
    data_scope: str = DataScope.DISPLAYED_PACKETS.value
    tags: List[str] = field(default_factory=list)
    thumbnail: Optional[DashboardThumbnail] = None


# Dashboard summary model (lightweight for overview)
@dataclass
class DashboardSummary:
    """Lightweight dashboard metadata for overview/gallery"""
    id: str
    name: str
    description: Optional[str]
    is_template: bool
    source_template_id: Optional[str]
    widget_count: int
    visualization_types: List[str]
    tags: List[str]
    thumbnail_type: str  # static, skeleton, live
    thumbnail_url: Optional[str]
    updated_at: str  # ISO 8601
    created_at: str  # ISO 8601
    last_opened_at: Optional[str] = None
    favorite: bool = False


# Helper function to convert Dashboard to DashboardSummary
def dashboard_to_summary(dashboard: Dashboard) -> DashboardSummary:
    """Convert a full Dashboard to a DashboardSummary"""
    viz_types = list(set(w.visualization.type for w in dashboard.widgets))
    
    return DashboardSummary(
        id=dashboard.dashboard_id,
        name=dashboard.name,
        description=dashboard.description,
        is_template=dashboard.is_template,
        source_template_id=dashboard.source_template_id,
        widget_count=len(dashboard.widgets),
        visualization_types=viz_types,
        tags=dashboard.tags,
        thumbnail_type=dashboard.thumbnail.mode if dashboard.thumbnail else "skeleton",
        thumbnail_url=dashboard.thumbnail.image_url if dashboard.thumbnail else None,
        updated_at=dashboard.updated_at,
        created_at=dashboard.created_at,
    )


# Serialization helpers
def to_dict(obj: Any) -> Dict[str, Any]:
    """Convert dataclass to dict, handling nested dataclasses and enums"""
    if isinstance(obj, (list, tuple)):
        return [to_dict(item) for item in obj]
    elif isinstance(obj, dict):
        return {k: to_dict(v) for k, v in obj.items()}
    elif isinstance(obj, Enum):
        return obj.value
    elif hasattr(obj, "__dataclass_fields__"):
        result = {}
        for k, v in asdict(obj).items():
            # Handle the special "as_" field -> "as" in JSON
            key = "as" if k == "as_" else k
            result[key] = to_dict(v)
        return result
    else:
        return obj


def from_dict(data: Dict[str, Any], model_class: type) -> Any:
    """Convert dict to dataclass, handling nested dataclasses and camelCase<->snake_case conversion"""
    if not isinstance(data, dict):
        return data
    
    # Convert camelCase keys to snake_case
    data_normalized = {}
    for key, value in data.items():
        # Convert camelCase to snake_case
        snake_key = _camel_to_snake(key)
        data_normalized[snake_key] = value
    
    # Handle the special "as" field -> "as_" in Python
    if "as" in data_normalized and model_class == QueryMetric:
        data_normalized["as_"] = data_normalized.pop("as")
    
    kwargs = {}
    
    # Get all field definitions
    for fld in dataclass_fields(model_class):
        field_name = fld.name
        field_type = fld.type
        
        if field_name not in data_normalized:
            # Field not in data - skip if it has a default
            if fld.default is not MISSING or fld.default_factory is not MISSING:
                continue
            # Otherwise let dataclass init handle the error
            continue
        
        value = data_normalized[field_name]
        
        # Handle None values
        if value is None:
            kwargs[field_name] = None
            continue
        
        value = _convert_typed_value(value, field_type)
        
        kwargs[field_name] = value
    
    return model_class(**kwargs)


def _camel_to_snake(name: str) -> str:
    """Convert camelCase to snake_case"""
    import re
    # Insert an underscore before any uppercase letter that follows a lowercase letter
    s1 = re.sub('(.)([A-Z][a-z]+)', r'\1_\2', name)
    # Insert an underscore before any uppercase letter that follows a lowercase or digit
    return re.sub('([a-z0-9])([A-Z])', r'\1_\2', s1).lower()


def _convert_typed_value(value: Any, field_type: Any) -> Any:
    """Convert nested typed values into dataclass instances when needed."""
    if value is None:
        return None

    origin = get_origin(field_type)
    args = get_args(field_type)

    if origin in (list, List):
        item_type = args[0] if args else Any
        return [_convert_typed_value(item, item_type) for item in (value or [])]

    if origin in (dict, Dict):
        value_type = args[1] if len(args) > 1 else Any
        return {
            key: _convert_typed_value(item, value_type)
            for key, item in (value or {}).items()
        }

    if origin is Union:
        non_none_types = [arg for arg in args if arg is not type(None)]
        if len(non_none_types) == 1:
            return _convert_typed_value(value, non_none_types[0])
        for candidate in non_none_types:
            try:
                return _convert_typed_value(value, candidate)
            except Exception:
                continue
        return value

    if hasattr(field_type, "__dataclass_fields__") and isinstance(value, dict):
        return from_dict(value, field_type)

    return value
