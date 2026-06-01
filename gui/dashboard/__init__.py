"""
Dashboard module - Custom dashboard builder.
"""

from .models import (
    Dashboard, DashboardSummary, DashboardWidget, WidgetQuery, VisualizationConfig,
    WidgetLayout, DashboardLayout, TimeRange, DashboardThumbnail, QueryMetric, QuerySort,
    VisualizationType, TimeRangeMode, DataScope,
    dashboard_to_summary, to_dict, from_dict
)
from .repository import (
    DashboardRepository, DashboardTemplateRepository,
    create_default_templates, get_dashboard_templates_path,
    get_user_dashboards_path,
)
from .dashboard_overview import DashboardOverviewDialog, DashboardCard
from .dashboard_editor import DashboardEditor, GridWidget
from .query_engine import QueryEngine, DataSourceRegistry
from .visualization import (
    VisualizationRegistry, MetricRenderer, TableRenderer,
    BarChartRenderer, LineChartRenderer, PieChartRenderer, DonutChartRenderer,
    HistogramRenderer, TopologyRenderer, create_default_visualization_registry
)
from .advanced_queries import (
    FilterParser, DrilldownEngine, AdvancedAggregation, TopNAnalysis, ComparisonAnalysis
)
from .services import DashboardService
from .capture_integration import CaptureDataSourceBuilder
from .thumbnail_generator import ThumbnailGenerator, DashboardThumbnailCache

__all__ = [
    # Models
    'Dashboard', 'DashboardSummary', 'DashboardWidget', 'WidgetQuery',
    'VisualizationConfig', 'WidgetLayout', 'DashboardLayout', 'TimeRange',
    'DashboardThumbnail', 'QueryMetric', 'QuerySort',
    'VisualizationType', 'TimeRangeMode', 'DataScope',
    'dashboard_to_summary', 'to_dict', 'from_dict',
    
    # Repository
    'DashboardRepository', 'DashboardTemplateRepository',
    'create_default_templates', 'get_dashboard_templates_path',
    'get_user_dashboards_path',
    
    # UI
    'DashboardOverviewDialog', 'DashboardCard',
    'DashboardEditor', 'GridWidget',
    
    # Query Engine
    'QueryEngine', 'DataSourceRegistry',
    
    # Visualization
    'VisualizationRegistry', 'MetricRenderer', 'TableRenderer',
    'BarChartRenderer', 'LineChartRenderer', 'PieChartRenderer', 'DonutChartRenderer',
    'HistogramRenderer', 'TopologyRenderer', 'create_default_visualization_registry',
    
    # Advanced Queries
    'FilterParser', 'DrilldownEngine', 'AdvancedAggregation', 'TopNAnalysis', 'ComparisonAnalysis',
    
    # Services
    'DashboardService',
    
    # Capture Integration
    'CaptureDataSourceBuilder',
    
    # Thumbnail Generation
    'ThumbnailGenerator', 'DashboardThumbnailCache',
]
