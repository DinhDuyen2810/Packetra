"""
Dashboard Services Layer.

High-level services for dashboard operations (overview, editor, rendering, etc.)
"""

from typing import Optional, List, Dict, Any
from datetime import datetime
from uuid import uuid4

from .models import Dashboard, DashboardWidget, WidgetQuery, VisualizationConfig, WidgetLayout, DashboardLayout
from .repository import DashboardRepository, DashboardTemplateRepository
from .query_engine import QueryEngine, DataSourceRegistry
from .visualization import VisualizationRegistry


class DashboardService:
    """High-level dashboard service orchestrating all operations"""
    
    def __init__(
        self,
        dashboard_repo: DashboardRepository,
        template_repo: DashboardTemplateRepository,
        data_source_registry: DataSourceRegistry,
        visualization_registry: VisualizationRegistry
    ):
        self.dashboard_repo = dashboard_repo
        self.template_repo = template_repo
        self.data_source_registry = data_source_registry
        self.visualization_registry = visualization_registry
        self.query_engine = QueryEngine(data_source_registry)
    
    # ===== Dashboard Management =====
    
    def get_dashboard(self, dashboard_id: str) -> Optional[Dashboard]:
        """Get a dashboard by ID"""
        return self.dashboard_repo.load(dashboard_id)
    
    def list_user_dashboards(self) -> List[Dashboard]:
        """List all user dashboards"""
        return self.dashboard_repo.list_user_dashboards()
    
    def get_dashboard_summaries(self) -> Dict[str, List]:
        """Get summaries for gallery view"""
        return {
            "templates": self.template_repo.get_summaries(),
            "user_dashboards": self.dashboard_repo.get_summaries(),
        }
    
    def create_blank_dashboard(self, name: str = "Untitled Dashboard") -> Dashboard:
        """Create a blank dashboard"""
        dashboard = Dashboard(
            schema_version=1,
            dashboard_id=str(uuid4()),
            name=name,
            description=None,
            is_template=False,
            created_at=datetime.now().isoformat(),
            updated_at=datetime.now().isoformat(),
            layout=DashboardLayout(columns=12, row_height=80),
            widgets=[],
        )
        self.dashboard_repo.save(dashboard)
        return dashboard
    
    def create_from_template(self, template_id: str, dashboard_name: Optional[str] = None) -> Optional[Dashboard]:
        """Create a dashboard from a template"""
        new_dashboard = self.template_repo.create_from_template(
            template_id,
            dashboard_name or "Untitled Dashboard"
        )
        if new_dashboard:
            self.dashboard_repo.save(new_dashboard)
        return new_dashboard
    
    def save_dashboard(self, dashboard: Dashboard) -> bool:
        """Save a dashboard"""
        try:
            dashboard.updated_at = datetime.now().isoformat()
            self.dashboard_repo.save(dashboard)
            return True
        except Exception as e:
            print(f"Error saving dashboard: {e}")
            return False
    
    def delete_dashboard(self, dashboard_id: str) -> bool:
        """Delete a dashboard"""
        return self.dashboard_repo.delete(dashboard_id)
    
    def rename_dashboard(self, dashboard_id: str, new_name: str) -> Optional[Dashboard]:
        """Rename a dashboard"""
        return self.dashboard_repo.rename(dashboard_id, new_name)
    
    def duplicate_dashboard(self, dashboard_id: str, new_name: Optional[str] = None) -> Optional[Dashboard]:
        """Duplicate a dashboard"""
        dashboard = self.dashboard_repo.load(dashboard_id)
        if not dashboard:
            return None
        
        if not new_name:
            new_name = f"{dashboard.name} (Copy)"
        
        return self.dashboard_repo.duplicate(dashboard_id, new_name)
    
    def export_dashboard(self, dashboard_id: str) -> Optional[str]:
        """Export dashboard as JSON"""
        return self.dashboard_repo.export_json(dashboard_id)
    
    def import_dashboard(self, json_str: str) -> Optional[Dashboard]:
        """Import dashboard from JSON"""
        return self.dashboard_repo.import_json(json_str)
    
    # ===== Widget Management =====
    
    def add_widget(self, dashboard_id: str, widget: DashboardWidget) -> bool:
        """Add a widget to a dashboard"""
        dashboard = self.dashboard_repo.load(dashboard_id)
        if not dashboard:
            return False
        
        widget.id = str(uuid4())
        dashboard.widgets.append(widget)
        self.dashboard_repo.save(dashboard)
        return True
    
    def remove_widget(self, dashboard_id: str, widget_id: str) -> bool:
        """Remove a widget from a dashboard"""
        dashboard = self.dashboard_repo.load(dashboard_id)
        if not dashboard:
            return False
        
        dashboard.widgets = [w for w in dashboard.widgets if w.id != widget_id]
        self.dashboard_repo.save(dashboard)
        return True
    
    def update_widget(self, dashboard_id: str, widget_id: str, widget_update: Dict[str, Any]) -> bool:
        """Update widget properties"""
        dashboard = self.dashboard_repo.load(dashboard_id)
        if not dashboard:
            return False
        
        for widget in dashboard.widgets:
            if widget.id == widget_id:
                # Update widget fields
                if "title" in widget_update:
                    widget.title = widget_update["title"]
                if "query" in widget_update:
                    widget.query = widget_update["query"]
                if "visualization" in widget_update:
                    widget.visualization = widget_update["visualization"]
                if "layout" in widget_update:
                    widget.layout = widget_update["layout"]
                
                self.dashboard_repo.save(dashboard)
                return True
        
        return False
    
    def duplicate_widget(self, dashboard_id: str, widget_id: str) -> bool:
        """Duplicate a widget"""
        dashboard = self.dashboard_repo.load(dashboard_id)
        if not dashboard:
            return False
        
        for widget in dashboard.widgets:
            if widget.id == widget_id:
                # Create copy
                from copy import deepcopy
                new_widget = deepcopy(widget)
                new_widget.id = str(uuid4())
                new_widget.title = f"{widget.title} (Copy)"
                # Shift position
                new_widget.layout.x = min(new_widget.layout.x + 1, 9)
                new_widget.layout.y = new_widget.layout.y + new_widget.layout.h
                
                dashboard.widgets.append(new_widget)
                self.dashboard_repo.save(dashboard)
                return True
        
        return False
    
    # ===== Query & Rendering =====
    
    def execute_widget_query(
        self,
        widget: DashboardWidget,
        global_filter: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Execute a widget's query"""
        try:
            from .dashboard_editor import build_widget_dataset
            return build_widget_dataset(self.query_engine, widget)
        except Exception as e:
            print(f"Error executing query: {e}")
            return []
    
    def render_widget(
        self,
        widget: DashboardWidget,
        data: List[Dict[str, Any]],
        parent=None
    ) -> Optional[Any]:
        """Render a widget with its visualization"""
        renderer = self.visualization_registry.get_renderer(widget.visualization.type)
        if not renderer:
            return None
        
        try:
            from .visualization import MetricRenderer
            # Convert visualization config to dict
            config = {
                "type": widget.visualization.type,
                "xField": widget.visualization.x_field,
                "yField": widget.visualization.y_field,
                "categoryField": widget.visualization.category_field,
                "valueField": widget.visualization.value_field,
                "seriesField": widget.visualization.series_field,
                "showLegend": widget.visualization.show_legend,
                "showLabels": widget.visualization.show_labels,
            }
            return renderer(data, config, parent)
        except Exception as e:
            print(f"Error rendering widget: {e}")
            return None
    
    # ===== Data Source & Compatibility =====
    
    def register_data_source(self, source_name: str, fetcher):
        """Register a data source"""
        self.data_source_registry.register(source_name, fetcher)
    
    def list_data_sources(self) -> List[str]:
        """List available data sources"""
        return self.data_source_registry.list_sources()
    
    def is_visualization_compatible(
        self,
        viz_type: str,
        dataset_schema: Dict[str, Any]
    ) -> bool:
        """Check if a visualization type is compatible with a dataset"""
        return self.visualization_registry.is_compatible(viz_type, dataset_schema)
    
    # ===== Utilities =====
    
    def get_dataset_schema(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Infer schema from dataset"""
        if not data:
            return {"fields": []}
        
        first_row = data[0]
        fields = []
        
        for key, value in first_row.items():
            field_type = "string"
            if isinstance(value, int):
                field_type = "int"
            elif isinstance(value, float):
                field_type = "float"
            elif isinstance(value, bool):
                field_type = "bool"
            
            fields.append({
                "name": key,
                "type": field_type,
            })
        
        return {"fields": fields}
