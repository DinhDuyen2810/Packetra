"""
Dashboard repository - handles persistence and retrieval of dashboards and templates.
"""

import json
import os
from pathlib import Path
from typing import List, Optional, Dict, Any
from datetime import datetime
from uuid import uuid4

from .models import (
    Dashboard, DashboardSummary, DashboardWidget, WidgetQuery, VisualizationConfig,
    WidgetLayout, DashboardLayout, TimeRange, DashboardThumbnail,
    dashboard_to_summary, to_dict, from_dict, QueryMetric, QuerySort
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DASHBOARD_DATA_ROOT = PROJECT_ROOT / "data"


def get_dashboard_templates_path() -> Path:
    """Return the runtime path for dashboard templates."""
    return DASHBOARD_DATA_ROOT / "dashboard_templates"


def get_user_dashboards_path() -> Path:
    """Return the runtime path for user dashboards."""
    return DASHBOARD_DATA_ROOT / "dashboards"


class DashboardRepository:
    """Manages user-created dashboards (save, load, delete, list, etc.)"""
    
    def __init__(self, storage_path: str):
        """
        Initialize repository with storage path.
        
        Args:
            storage_path: Directory to store dashboard JSON files
        """
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)
        self.dashboards_file = self.storage_path / "user_dashboards.json"
        self._cache: Dict[str, Dashboard] = {}
        self._load_cache()
    
    def _load_cache(self):
        """Load all dashboards from file into memory cache"""
        if self.dashboards_file.exists():
            try:
                with open(self.dashboards_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    for dash_dict in data.get("dashboards", []):
                        dashboard = from_dict(dash_dict, Dashboard)
                        self._cache[dashboard.dashboard_id] = dashboard
            except Exception as e:
                print(f"Error loading dashboards: {e}")
    
    def _save_cache(self):
        """Save all dashboards from cache to file"""
        data = {
            "dashboards": [to_dict(d) for d in self._cache.values()]
        }
        try:
            with open(self.dashboards_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"Error saving dashboards: {e}")
    
    def save(self, dashboard: Dashboard):
        """Save or update a dashboard"""
        dashboard.updated_at = datetime.now().isoformat()
        self._cache[dashboard.dashboard_id] = dashboard
        self._save_cache()
    
    def load(self, dashboard_id: str) -> Optional[Dashboard]:
        """Load a dashboard by ID"""
        return self._cache.get(dashboard_id)
    
    def delete(self, dashboard_id: str) -> bool:
        """Delete a dashboard (user dashboards only)"""
        if dashboard_id in self._cache:
            dashboard = self._cache[dashboard_id]
            if not dashboard.is_template:
                del self._cache[dashboard_id]
                self._save_cache()
                return True
        return False
    
    def list_user_dashboards(self) -> List[Dashboard]:
        """List all non-template dashboards"""
        return [d for d in self._cache.values() if not d.is_template]
    
    def list_all_dashboards(self) -> List[Dashboard]:
        """List all dashboards including templates"""
        return list(self._cache.values())
    
    def get_summaries(self) -> List[DashboardSummary]:
        """Get lightweight summaries for all user dashboards (for gallery/overview)"""
        return [dashboard_to_summary(d) for d in self.list_user_dashboards()]
    
    def duplicate(self, dashboard_id: str, new_name: str) -> Optional[Dashboard]:
        """Create a copy of a dashboard with a new ID and name"""
        original = self.load(dashboard_id)
        if not original:
            return None
        
        # Deep copy via dict
        dashboard_dict = to_dict(original)
        dashboard_dict['dashboard_id'] = str(uuid4())
        dashboard_dict['name'] = new_name
        dashboard_dict['created_at'] = datetime.now().isoformat()
        dashboard_dict['updated_at'] = datetime.now().isoformat()
        
        # Create new widget IDs
        for widget_dict in dashboard_dict.get('widgets', []):
            widget_dict['id'] = str(uuid4())
        
        new_dashboard = from_dict(dashboard_dict, Dashboard)
        self.save(new_dashboard)
        return new_dashboard
    
    def rename(self, dashboard_id: str, new_name: str) -> Optional[Dashboard]:
        """Rename a dashboard"""
        dashboard = self.load(dashboard_id)
        if dashboard:
            dashboard.name = new_name
            self.save(dashboard)
            return dashboard
        return None
    
    def export_json(self, dashboard_id: str) -> Optional[str]:
        """Export a dashboard as JSON string"""
        dashboard = self.load(dashboard_id)
        if dashboard:
            return json.dumps(to_dict(dashboard), indent=2, ensure_ascii=False)
        return None
    
    def import_json(self, json_str: str) -> Optional[Dashboard]:
        """Import a dashboard from JSON string"""
        try:
            data = json.loads(json_str)
            # Generate new ID if already exists
            if data['dashboard_id'] in self._cache:
                data['dashboard_id'] = str(uuid4())
            
            dashboard = from_dict(data, Dashboard)
            dashboard.is_template = False  # Ensure imported as user dashboard
            self.save(dashboard)
            return dashboard
        except Exception as e:
            print(f"Error importing dashboard: {e}")
            return None


class DashboardTemplateRepository:
    """Manages dashboard templates"""

    MAX_CHART_TEMPLATE_TYPES = 10
    CHART_TEMPLATE_SPECS = [
        {
            "id": "chart_template_metric",
            "template_id": "template_network_overview",
            "widget_id": "network_total_packets",
            "chart_type": "metric",
            "name": "Count",
            "description": "Sample count metric for the current capture.",
        },
        {
            "id": "chart_template_bar",
            "template_id": "template_protocol_analysis",
            "widget_id": "protocol_top_protocols",
            "chart_type": "bar",
            "name": "Clustered Column",
            "description": "Sample clustered column chart showing grouped protocol counts.",
        },
        {
            "id": "chart_template_pie",
            "template_id": "template_network_overview",
            "widget_id": "network_protocol_distribution",
            "chart_type": "pie",
            "name": "Pie",
            "description": "Sample pie chart for category shares.",
        },
        {
            "id": "chart_template_line",
            "template_id": "template_network_overview",
            "widget_id": "network_packets_over_time",
            "chart_type": "line",
            "name": "Line",
            "description": "Sample timeline chart across the capture.",
        },
        {
            "id": "chart_template_horizontal_bar",
            "template_id": "template_endpoint_activity",
            "widget_id": "endpoint_top_bytes",
            "chart_type": "horizontal_bar",
            "name": "Clustered Bar",
            "description": "Sample clustered horizontal bar chart for endpoint bytes.",
        },
        {
            "id": "chart_template_area",
            "template_id": "template_network_overview",
            "widget_id": "network_packets_over_time",
            "chart_type": "area",
            "name": "Area",
            "description": "Sample filled trend chart across time buckets.",
        },
        {
            "id": "chart_template_scatter",
            "template_id": "template_network_overview",
            "widget_id": "network_packets_over_time",
            "chart_type": "scatter",
            "name": "Scatter",
            "description": "Sample scatter chart showing packet counts across time buckets.",
        },
        {
            "id": "chart_template_radar",
            "template_id": "template_protocol_analysis",
            "widget_id": "protocol_top_protocols",
            "chart_type": "radar",
            "name": "Radar",
            "description": "Sample radar chart comparing top protocols.",
        },
        {
            "id": "chart_template_treemap",
            "template_id": "template_timeline_analysis",
            "widget_id": "timeline_top_conversations",
            "chart_type": "treemap",
            "name": "Treemap",
            "description": "Sample treemap chart grouping top conversations by protocol.",
            "visualization": {
                "series_field": "protocol"
            },
        },
        {
            "id": "chart_template_sunburst",
            "template_id": "template_timeline_analysis",
            "widget_id": "timeline_top_conversations",
            "chart_type": "sunburst",
            "name": "Sunburst",
            "description": "Sample sunburst chart grouping top conversations by protocol.",
            "visualization": {
                "series_field": "protocol"
            },
        },
    ]
    
    def __init__(self, templates_path: str):
        """
        Initialize template repository with path to templates.
        
        Args:
            templates_path: Directory containing template JSON files
        """
        self.templates_path = Path(templates_path)
        self.templates_path.mkdir(parents=True, exist_ok=True)
        self._cache: Dict[str, Dashboard] = {}
        self._load_templates()
        self._sync_default_templates()
    
    def _load_templates(self):
        """Load all template files from disk"""
        for template_file in self.templates_path.glob("*.json"):
            try:
                with open(template_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    template = from_dict(data, Dashboard)
                    self._cache[template.dashboard_id] = template
            except Exception as e:
                print(f"Error loading template {template_file}: {e}")

    def _sync_default_templates(self):
        """Ensure built-in templates are present and up to date on disk."""
        for template in create_default_templates():
            existing = self._cache.get(template.dashboard_id)
            if existing is not None and to_dict(existing) == to_dict(template):
                continue
            self.save_template(template)
    
    def get(self, template_id: str) -> Optional[Dashboard]:
        """Get a template by ID"""
        return self._cache.get(template_id)
    
    def list_templates(self) -> List[Dashboard]:
        """List all templates"""
        return list(self._cache.values())

    @staticmethod
    def _compose_chart_template_id(template_id: str, widget_id: str) -> str:
        return f"{template_id}::{widget_id}"

    @staticmethod
    def _split_chart_template_id(chart_template_id: str) -> tuple[Optional[str], Optional[str]]:
        parts = str(chart_template_id or '').split('::', 1)
        if len(parts) != 2:
            return None, None
        return parts[0], parts[1]

    def _build_chart_template_dashboard(
        self,
        template: Dashboard,
        widget: DashboardWidget,
        *,
        chart_template_id: Optional[str] = None,
        chart_type: Optional[str] = None,
        name: Optional[str] = None,
        description: Optional[str] = None,
        extra_tags: Optional[List[str]] = None,
        visualization_overrides: Optional[Dict[str, Any]] = None,
    ) -> Dashboard:
        """Project one widget from a template as a standalone chart template."""
        chart_dashboard = from_dict(to_dict(template), Dashboard)
        chart_widget = from_dict(to_dict(widget), DashboardWidget)
        if chart_type:
            chart_widget.visualization.type = chart_type
        for field_name, field_value in (visualization_overrides or {}).items():
            if hasattr(chart_widget.visualization, field_name):
                setattr(chart_widget.visualization, field_name, field_value)
        chart_widget.layout = WidgetLayout(
            x=0,
            y=0,
            w=12,
            h=6 if chart_widget.visualization.type != 'metric' else 3,
        )

        chart_dashboard.dashboard_id = chart_template_id or self._compose_chart_template_id(template.dashboard_id, widget.id)
        chart_dashboard.name = name or widget.title
        chart_dashboard.description = description or widget.description or f"From {template.name}"
        chart_dashboard.is_template = True
        chart_dashboard.layout = DashboardLayout(columns=12, row_height=80)
        chart_dashboard.widgets = [chart_widget]
        chart_dashboard.source_template_id = template.dashboard_id
        chart_dashboard.tags = list(dict.fromkeys([*template.tags, chart_widget.visualization.type, *(extra_tags or [])]))
        return chart_dashboard

    def _find_template_widget(self, template_id: str, widget_id: str) -> tuple[Optional[Dashboard], Optional[DashboardWidget]]:
        template = self.get(template_id)
        if not template:
            return None, None
        widget = next((item for item in template.widgets if item.id == widget_id), None)
        return template, widget

    def _build_curated_chart_template_dashboards(self) -> List[Dashboard]:
        chart_templates: List[Dashboard] = []
        for spec in self.CHART_TEMPLATE_SPECS[:self.MAX_CHART_TEMPLATE_TYPES]:
            template, widget = self._find_template_widget(spec["template_id"], spec["widget_id"])
            if not template or not widget:
                continue
            chart_templates.append(
                self._build_chart_template_dashboard(
                    template,
                    widget,
                    chart_template_id=spec["id"],
                    chart_type=spec["chart_type"],
                    name=spec["name"],
                    description=spec["description"],
                    extra_tags=["sample", "chart-template"],
                    visualization_overrides=spec.get("visualization"),
                )
            )
        return chart_templates

    def list_chart_template_dashboards(self) -> List[Dashboard]:
        """List curated chart templates with up to eight distinct visualization types."""
        chart_templates = self._build_curated_chart_template_dashboards()
        if chart_templates:
            return chart_templates

        # Fallback to discovered charts if curated sources are unavailable.
        discovered_templates: List[Dashboard] = []
        seen_types: set[str] = set()
        for template in self.list_templates():
            for widget in template.widgets:
                chart_type = str(widget.visualization.type or '').strip().lower()
                if not chart_type or chart_type == 'table' or chart_type in seen_types:
                    continue
                seen_types.add(chart_type)
                discovered_templates.append(self._build_chart_template_dashboard(template, widget))
                if len(discovered_templates) >= self.MAX_CHART_TEMPLATE_TYPES:
                    return discovered_templates
        return discovered_templates

    def get_chart_template_dashboard(self, chart_template_id: str) -> Optional[Dashboard]:
        """Get a single-chart template dashboard by composite ID."""
        curated_match = next(
            (item for item in self.list_chart_template_dashboards() if item.dashboard_id == chart_template_id),
            None,
        )
        if curated_match:
            return from_dict(to_dict(curated_match), Dashboard)

        template_id, widget_id = self._split_chart_template_id(chart_template_id)
        if not template_id or not widget_id:
            return None

        template = self.get(template_id)
        if not template:
            return None

        widget = next((item for item in template.widgets if item.id == widget_id), None)
        if not widget:
            return None

        return self._build_chart_template_dashboard(template, widget)

    def create_dashboard_from_chart_template(self, chart_template_id: str, new_name: Optional[str] = None) -> Optional[Dashboard]:
        """Create a user dashboard from a single chart template item."""
        chart_dashboard = self.get_chart_template_dashboard(chart_template_id)
        if not chart_dashboard:
            return None

        chart_dashboard.dashboard_id = str(uuid4())
        chart_dashboard.name = (new_name or chart_dashboard.name or '').strip() or chart_dashboard.name
        chart_dashboard.is_template = False
        chart_dashboard.created_at = datetime.now().isoformat()
        chart_dashboard.updated_at = datetime.now().isoformat()
        for widget in chart_dashboard.widgets:
            widget.id = str(uuid4())
        return chart_dashboard

    def create_widget_from_chart_template(self, chart_template_id: str) -> Optional[DashboardWidget]:
        """Create a reusable widget copy from a single chart template item."""
        chart_dashboard = self.get_chart_template_dashboard(chart_template_id)
        if not chart_dashboard or not chart_dashboard.widgets:
            return None

        widget = from_dict(to_dict(chart_dashboard.widgets[0]), DashboardWidget)
        widget.id = str(uuid4())
        if widget.visualization.type == 'metric':
            widget.layout = WidgetLayout(x=0, y=0, w=3, h=2)
        else:
            widget.layout = WidgetLayout(x=0, y=0, w=6, h=4)
        return widget
    
    def get_summaries(self) -> List[DashboardSummary]:
        """Get lightweight summaries of all templates (for gallery/overview)"""
        return [dashboard_to_summary(t) for t in self.list_templates()]
    
    def create_from_template(self, template_id: str, new_name: str) -> Optional[Dashboard]:
        """
        Create a new user dashboard from a template.
        Template itself is not modified.
        """
        template = self.get(template_id)
        if not template:
            return None
        
        # Deep copy via dict
        dashboard_dict = to_dict(template)
        dashboard_dict['dashboard_id'] = str(uuid4())
        dashboard_dict['name'] = new_name or template.name
        dashboard_dict['is_template'] = False
        dashboard_dict['source_template_id'] = template_id
        dashboard_dict['created_at'] = datetime.now().isoformat()
        dashboard_dict['updated_at'] = datetime.now().isoformat()
        
        # Generate new widget IDs
        for widget_dict in dashboard_dict.get('widgets', []):
            widget_dict['id'] = str(uuid4())
        
        dashboard = from_dict(dashboard_dict, Dashboard)
        return dashboard
    
    def save_template(self, template: Dashboard):
        """Save a template to disk"""
        if not template.is_template:
            template.is_template = True
        
        template_file = self.templates_path / f"{template.dashboard_id}.json"
        try:
            with open(template_file, 'w', encoding='utf-8') as f:
                json.dump(to_dict(template), f, indent=2, ensure_ascii=False)
            self._cache[template.dashboard_id] = template
        except Exception as e:
            print(f"Error saving template: {e}")


# Factory function to create default templates
def create_default_templates() -> List[Dashboard]:
    """Create 8 default template dashboards"""
    seeded_at = "2026-06-01T00:00:00"

    def widget(
        widget_id: str,
        title: str,
        data_source: str,
        viz_type: str,
        *,
        x: int,
        y: int,
        w: int,
        h: int,
        description: Optional[str] = None,
        filter_expr: Optional[str] = None,
        group_by: Optional[List[str]] = None,
        metrics: Optional[List[QueryMetric]] = None,
        sort: Optional[List[QuerySort]] = None,
        limit: Optional[int] = None,
        time_bucket: Optional[str] = None,
        columns: Optional[List[str]] = None,
        x_field: Optional[str] = None,
        y_field: Optional[str] = None,
        category_field: Optional[str] = None,
        value_field: Optional[str] = None,
        show_legend: bool = True,
        show_labels: bool = False,
    ) -> DashboardWidget:
        return DashboardWidget(
            id=widget_id,
            title=title,
            data_source=data_source,
            query=WidgetQuery(
                filter=filter_expr,
                group_by=group_by,
                metrics=metrics,
                sort=sort,
                limit=limit,
                time_bucket=time_bucket,
                columns=columns,
            ),
            visualization=VisualizationConfig(
                type=viz_type,
                x_field=x_field,
                y_field=y_field,
                category_field=category_field,
                value_field=value_field,
                show_legend=show_legend,
                show_labels=show_labels,
            ),
            layout=WidgetLayout(x=x, y=y, w=w, h=h),
            description=description,
        )

    templates = [
        Dashboard(
            schema_version=1,
            dashboard_id="template_network_overview",
            name="Network Overview",
            description="Overview of packets, protocols, endpoints and conversations",
            is_template=True,
            created_at=seeded_at,
            updated_at=seeded_at,
            layout=DashboardLayout(columns=12, row_height=80),
            widgets=[
                widget(
                    "network_total_packets",
                    "Total Packets",
                    "packets",
                    "metric",
                    x=0,
                    y=0,
                    w=3,
                    h=2,
                    description="Total number of packets in the current capture",
                    metrics=[QueryMetric(type="count", field="*", as_="packets")],
                    value_field="packets",
                    show_legend=False,
                ),
                widget(
                    "network_total_bytes",
                    "Total Bytes",
                    "packets",
                    "metric",
                    x=3,
                    y=0,
                    w=3,
                    h=2,
                    description="Total bytes transferred in the current capture",
                    metrics=[QueryMetric(type="sum", field="length", as_="bytes")],
                    value_field="bytes",
                    show_legend=False,
                ),
                widget(
                    "network_protocol_distribution",
                    "Protocol Distribution",
                    "protocol_stats",
                    "donut",
                    x=6,
                    y=0,
                    w=6,
                    h=4,
                    description="Protocol mix across the displayed packets",
                    sort=[QuerySort(field="packets", direction="desc")],
                    limit=10,
                    category_field="protocol",
                    value_field="packets",
                ),
                widget(
                    "network_packets_over_time",
                    "Packets Over Time",
                    "packets",
                    "line",
                    x=0,
                    y=2,
                    w=6,
                    h=4,
                    description="Packet rate across the capture timeline",
                    metrics=[QueryMetric(type="count", field="*", as_="packets")],
                    time_bucket="1s",
                    x_field="time",
                    y_field="packets",
                    show_legend=False,
                ),
                widget(
                    "network_top_endpoints",
                    "Top Endpoints",
                    "endpoints",
                    "table",
                    x=0,
                    y=6,
                    w=12,
                    h=4,
                    description="Top endpoints by packet count",
                    sort=[QuerySort(field="packets", direction="desc")],
                    limit=10,
                    columns=["address", "packets", "bytes", "protocols"],
                    show_legend=False,
                ),
            ],
            tags=["overview", "packets", "protocols"],
        ),
        Dashboard(
            schema_version=1,
            dashboard_id="template_protocol_analysis",
            name="Protocol Analysis",
            description="Analyze DNS, HTTP, TLS and other protocols",
            is_template=True,
            created_at=seeded_at,
            updated_at=seeded_at,
            layout=DashboardLayout(columns=12, row_height=80),
            widgets=[
                widget(
                    "protocol_top_protocols",
                    "Top Protocols",
                    "protocol_stats",
                    "bar",
                    x=0,
                    y=0,
                    w=6,
                    h=4,
                    sort=[QuerySort(field="packets", direction="desc")],
                    limit=10,
                    category_field="protocol",
                    value_field="packets",
                ),
                widget(
                    "protocol_bytes_distribution",
                    "Protocol Bytes",
                    "protocol_stats",
                    "donut",
                    x=6,
                    y=0,
                    w=6,
                    h=4,
                    sort=[QuerySort(field="bytes", direction="desc")],
                    limit=8,
                    category_field="protocol",
                    value_field="bytes",
                ),
                widget(
                    "protocol_dns_queries",
                    "Top DNS Queries",
                    "dns_queries",
                    "table",
                    x=0,
                    y=4,
                    w=6,
                    h=4,
                    sort=[QuerySort(field="count", direction="desc")],
                    limit=10,
                    columns=["query", "count", "responses", "avg_time_ms"],
                    show_legend=False,
                ),
                widget(
                    "protocol_http_messages",
                    "HTTP Messages",
                    "http_requests",
                    "table",
                    x=6,
                    y=4,
                    w=6,
                    h=4,
                    sort=[QuerySort(field="bytes", direction="desc")],
                    limit=10,
                    columns=["kind", "uri", "status", "latency_ms", "bytes"],
                    show_legend=False,
                ),
            ],
            tags=["protocol", "dns", "http", "tls"],
        ),
        Dashboard(
            schema_version=1,
            dashboard_id="template_security_investigation",
            name="Security Investigation",
            description="Investigate suspicious activity, expert warnings",
            is_template=True,
            created_at=seeded_at,
            updated_at=seeded_at,
            layout=DashboardLayout(columns=12, row_height=80),
            widgets=[
                widget(
                    "security_top_dst_ports",
                    "Top Destination Ports",
                    "packets",
                    "bar",
                    x=0,
                    y=0,
                    w=6,
                    h=4,
                    filter_expr="dst_port > 0",
                    group_by=["dst_port"],
                    metrics=[
                        QueryMetric(type="count", field="*", as_="hits"),
                        QueryMetric(type="sum", field="length", as_="bytes"),
                    ],
                    sort=[QuerySort(field="hits", direction="desc")],
                    limit=10,
                    category_field="dst_port",
                    value_field="hits",
                ),
                widget(
                    "security_slow_dns",
                    "Slow DNS Responses",
                    "dns_queries",
                    "table",
                    x=6,
                    y=0,
                    w=6,
                    h=4,
                    sort=[QuerySort(field="avg_time_ms", direction="desc")],
                    limit=10,
                    columns=["query", "responses", "avg_time_ms", "count"],
                    show_legend=False,
                ),
                widget(
                    "security_largest_conversations",
                    "Largest Conversations",
                    "conversations",
                    "table",
                    x=0,
                    y=4,
                    w=12,
                    h=4,
                    sort=[QuerySort(field="bytes", direction="desc")],
                    limit=12,
                    columns=["conversation", "protocol", "packets", "bytes"],
                    show_legend=False,
                ),
            ],
            tags=["security", "expert", "warnings"],
        ),
        Dashboard(
            schema_version=1,
            dashboard_id="template_endpoint_activity",
            name="Endpoint Activity",
            description="Track endpoint behavior, traffic patterns",
            is_template=True,
            created_at=seeded_at,
            updated_at=seeded_at,
            layout=DashboardLayout(columns=12, row_height=80),
            widgets=[
                widget(
                    "endpoint_top_bytes",
                    "Top Talkers by Bytes",
                    "endpoints",
                    "bar",
                    x=0,
                    y=0,
                    w=6,
                    h=4,
                    sort=[QuerySort(field="bytes", direction="desc")],
                    limit=10,
                    category_field="address",
                    value_field="bytes",
                ),
                widget(
                    "endpoint_top_packets",
                    "Top Talkers by Packets",
                    "endpoints",
                    "bar",
                    x=6,
                    y=0,
                    w=6,
                    h=4,
                    sort=[QuerySort(field="packets", direction="desc")],
                    limit=10,
                    category_field="address",
                    value_field="packets",
                ),
                widget(
                    "endpoint_table",
                    "Endpoint Table",
                    "endpoints",
                    "table",
                    x=0,
                    y=4,
                    w=12,
                    h=4,
                    sort=[QuerySort(field="packets", direction="desc")],
                    limit=15,
                    columns=["address", "packets", "bytes", "tx_packets", "rx_packets", "protocols"],
                    show_legend=False,
                ),
            ],
            tags=["endpoints", "activity", "traffic"],
        ),
        Dashboard(
            schema_version=1,
            dashboard_id="template_timeline_analysis",
            name="Timeline Analysis",
            description="View packet and event timeline",
            is_template=True,
            created_at=seeded_at,
            updated_at=seeded_at,
            layout=DashboardLayout(columns=12, row_height=80),
            widgets=[
                widget(
                    "timeline_packets",
                    "Packets Over Time",
                    "packets",
                    "line",
                    x=0,
                    y=0,
                    w=6,
                    h=4,
                    metrics=[QueryMetric(type="count", field="*", as_="packets")],
                    time_bucket="1s",
                    x_field="time",
                    y_field="packets",
                    show_legend=False,
                ),
                widget(
                    "timeline_bytes",
                    "Bytes Over Time",
                    "packets",
                    "line",
                    x=6,
                    y=0,
                    w=6,
                    h=4,
                    metrics=[QueryMetric(type="sum", field="length", as_="bytes")],
                    time_bucket="1s",
                    x_field="time",
                    y_field="bytes",
                    show_legend=False,
                ),
                widget(
                    "timeline_top_conversations",
                    "Top Conversations",
                    "conversations",
                    "bar",
                    x=0,
                    y=4,
                    w=6,
                    h=4,
                    sort=[QuerySort(field="packets", direction="desc")],
                    limit=10,
                    category_field="conversation",
                    value_field="packets",
                ),
                widget(
                    "timeline_protocol_mix",
                    "Protocol Mix",
                    "protocol_stats",
                    "donut",
                    x=6,
                    y=4,
                    w=6,
                    h=4,
                    sort=[QuerySort(field="packets", direction="desc")],
                    limit=8,
                    category_field="protocol",
                    value_field="packets",
                ),
            ],
            tags=["timeline", "events"],
        ),
        Dashboard(
            schema_version=1,
            dashboard_id="template_topology_view",
            name="Topology View",
            description="Visualize network topology and connections",
            is_template=True,
            created_at=seeded_at,
            updated_at=seeded_at,
            layout=DashboardLayout(columns=12, row_height=80),
            widgets=[
                widget(
                    "topology_conversation_bytes",
                    "Conversation Bytes",
                    "conversations",
                    "bar",
                    x=0,
                    y=0,
                    w=6,
                    h=4,
                    sort=[QuerySort(field="bytes", direction="desc")],
                    limit=10,
                    category_field="conversation",
                    value_field="bytes",
                ),
                widget(
                    "topology_protocol_mix",
                    "Protocol Distribution",
                    "protocol_stats",
                    "donut",
                    x=6,
                    y=0,
                    w=6,
                    h=4,
                    sort=[QuerySort(field="packets", direction="desc")],
                    limit=8,
                    category_field="protocol",
                    value_field="packets",
                ),
                widget(
                    "topology_conversation_table",
                    "Top Conversations",
                    "conversations",
                    "table",
                    x=0,
                    y=4,
                    w=12,
                    h=4,
                    sort=[QuerySort(field="bytes", direction="desc")],
                    limit=12,
                    columns=["conversation", "protocol", "packets", "bytes"],
                    show_legend=False,
                ),
            ],
            tags=["topology", "network", "graph"],
        ),
        Dashboard(
            schema_version=1,
            dashboard_id="template_dns_analysis",
            name="DNS Analysis",
            description="Deep dive into DNS queries and responses",
            is_template=True,
            created_at=seeded_at,
            updated_at=seeded_at,
            layout=DashboardLayout(columns=12, row_height=80),
            widgets=[
                widget(
                    "dns_distinct_queries",
                    "Distinct Queries",
                    "dns_queries",
                    "metric",
                    x=0,
                    y=0,
                    w=3,
                    h=2,
                    metrics=[QueryMetric(type="distinct_count", field="query", as_="queries")],
                    value_field="queries",
                    show_legend=False,
                ),
                widget(
                    "dns_top_queries",
                    "Top DNS Queries",
                    "dns_queries",
                    "bar",
                    x=3,
                    y=0,
                    w=9,
                    h=4,
                    sort=[QuerySort(field="count", direction="desc")],
                    limit=10,
                    category_field="query",
                    value_field="count",
                ),
                widget(
                    "dns_query_table",
                    "DNS Query Table",
                    "dns_queries",
                    "table",
                    x=0,
                    y=4,
                    w=6,
                    h=4,
                    sort=[QuerySort(field="count", direction="desc")],
                    limit=15,
                    columns=["query", "count", "responses", "avg_time_ms"],
                    show_legend=False,
                ),
                widget(
                    "dns_latency_table",
                    "DNS Response Time",
                    "dns_queries",
                    "table",
                    x=6,
                    y=4,
                    w=6,
                    h=4,
                    sort=[QuerySort(field="avg_time_ms", direction="desc")],
                    limit=15,
                    columns=["query", "avg_time_ms", "responses"],
                    show_legend=False,
                ),
            ],
            tags=["dns", "queries"],
        ),
        Dashboard(
            schema_version=1,
            dashboard_id="template_http_tls_analysis",
            name="HTTP/TLS Analysis",
            description="Analyze HTTP requests, TLS sessions",
            is_template=True,
            created_at=seeded_at,
            updated_at=seeded_at,
            layout=DashboardLayout(columns=12, row_height=80),
            widgets=[
                widget(
                    "http_message_count",
                    "HTTP Messages",
                    "http_requests",
                    "metric",
                    x=0,
                    y=0,
                    w=3,
                    h=2,
                    metrics=[QueryMetric(type="count", field="*", as_="messages")],
                    value_field="messages",
                    show_legend=False,
                ),
                widget(
                    "http_tls_mix",
                    "HTTP vs SSL",
                    "packets",
                    "donut",
                    x=3,
                    y=0,
                    w=9,
                    h=4,
                    filter_expr="(protocol == HTTP) OR (protocol == SSL)",
                    group_by=["protocol"],
                    metrics=[QueryMetric(type="count", field="*", as_="packets")],
                    sort=[QuerySort(field="packets", direction="desc")],
                    limit=10,
                    category_field="protocol",
                    value_field="packets",
                ),
                widget(
                    "http_request_table",
                    "HTTP Request Table",
                    "http_requests",
                    "table",
                    x=0,
                    y=4,
                    w=7,
                    h=4,
                    sort=[QuerySort(field="bytes", direction="desc")],
                    limit=15,
                    columns=["kind", "uri", "status", "latency_ms", "bytes"],
                    show_legend=False,
                ),
                widget(
                    "http_tls_packets",
                    "Largest SSL Packets",
                    "packets",
                    "table",
                    x=7,
                    y=4,
                    w=5,
                    h=4,
                    filter_expr="protocol == SSL",
                    sort=[QuerySort(field="length", direction="desc")],
                    limit=10,
                    columns=["src_ip", "dst_ip", "length", "info"],
                    show_legend=False,
                ),
            ],
            tags=["http", "tls", "https"],
        ),
    ]

    return templates
