"""
Query Engine for Dashboard.

Executes queries on data sources and returns datasets for visualization.
"""

from typing import List, Dict, Any, Optional, Callable
from datetime import datetime
from collections import defaultdict
import statistics

from .models import WidgetQuery, DashboardWidget
from .advanced_queries import FilterParser


class DataSourceRegistry:
    """Registry for available data sources"""
    
    def __init__(self):
        self.sources: Dict[str, Callable] = {}
    
    def register(self, source_name: str, fetcher: Callable):
        """Register a data source fetcher"""
        self.sources[source_name] = fetcher
    
    def get_fetcher(self, source_name: str) -> Optional[Callable]:
        """Get fetcher for a data source"""
        return self.sources.get(source_name)
    
    def list_sources(self) -> List[str]:
        """List all available sources"""
        return list(self.sources.keys())


class QueryEngine:
    """Executes widget queries on data sources"""
    
    def __init__(self, data_source_registry: DataSourceRegistry):
        self.registry = data_source_registry
    
    def execute(
        self,
        data_source: str,
        query: WidgetQuery,
        global_filter: Optional[str] = None,
        prefetched_data: Optional[List[Dict[str, Any]]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Execute a query on a data source.
        
        Args:
            data_source: Name of the data source (packets, endpoints, etc.)
            query: Query configuration
            global_filter: Optional global filter to apply
        
        Returns:
            List of result rows (dicts)
        """
        if prefetched_data is None:
            fetcher = self.registry.get_fetcher(data_source)
            if not fetcher:
                raise ValueError(f"Unknown data source: {data_source}")
            data = fetcher()
        else:
            data = list(prefetched_data)

        if not data:
            return []
        
        # Apply filters
        final_filter = self._combine_filters(global_filter, query.filter)
        if final_filter:
            data = self._apply_filter(data, final_filter)
        
        # Apply group by
        if query.group_by:
            data = self._apply_group_by(data, query.group_by, query.metrics or [])
        
        # Apply time bucketing
        elif query.time_bucket:
            data = self._apply_time_bucket(data, query.time_bucket, query.metrics or [])

        # Apply aggregate metrics without grouping
        elif query.metrics:
            data = [self._apply_metrics(data, query.metrics)]
        
        # Apply sorting
        if query.sort:
            data = self._apply_sort(data, query.sort)
        
        # Apply limit
        if query.limit:
            data = data[:query.limit]
        
        # Select columns if specified
        if query.columns:
            data = self._select_columns(data, query.columns)
        
        return data

    def _apply_metrics(self, data: List[Dict], metrics: List) -> Dict[str, Any]:
        """Aggregate metrics over the full dataset into a single result row."""
        result = {}
        for metric in metrics:
            result[metric.as_] = self._compute_metric(data, metric)
        return result
    
    def _combine_filters(self, global_filter: Optional[str], widget_filter: Optional[str]) -> Optional[str]:
        """Combine global and widget filters"""
        if global_filter and widget_filter:
            return f"({global_filter}) AND ({widget_filter})"
        return global_filter or widget_filter
    
    def _apply_filter(self, data: List[Dict], filter_expr: str) -> List[Dict]:
        """
        Apply filter expression to data.
        Uses FilterParser for sophisticated filter evaluation.
        """
        try:
            filtered = []
            for row in data:
                if FilterParser.parse_and_evaluate(row, filter_expr):
                    filtered.append(row)
            return filtered
        except Exception as e:
            # If filter fails, return all data
            print(f"Filter error: {e}")
            return data
    
    def _apply_group_by(self, data: List[Dict], group_by_fields: List[str], metrics: List) -> List[Dict]:
        """Apply group by aggregation"""
        groups: Dict[tuple, List[Dict]] = defaultdict(list)
        
        # Group rows
        for row in data:
            key = tuple(row.get(field) for field in group_by_fields)
            if key not in groups:
                groups[key] = []
            groups[key].append(row)
        
        # Aggregate
        result = []
        for key_tuple, rows in groups.items():
            agg_row = {field: value for field, value in zip(group_by_fields, key_tuple)}
            
            # Apply metrics
            for metric in metrics:
                agg_value = self._compute_metric(rows, metric)
                agg_row[metric.as_] = agg_value
            
            result.append(agg_row)
        
        return result
    
    def _apply_time_bucket(self, data: List[Dict], time_bucket: str, metrics: List) -> List[Dict]:
        """Apply time bucketing for time series"""
        # Parse time bucket (1s, 1m, 1h, etc.)
        bucket_seconds = self._parse_time_bucket(time_bucket)
        
        buckets: Dict[int, List[Dict]] = defaultdict(list)
        
        # Group by time bucket
        for row in data:
            time_val = row.get('time')
            if time_val:
                if isinstance(time_val, (int, float)):
                    numeric_time = float(time_val)
                elif isinstance(time_val, str):
                    try:
                        numeric_time = datetime.fromisoformat(time_val).timestamp()
                    except Exception:
                        continue
                else:
                    try:
                        numeric_time = float(time_val.timestamp())
                    except Exception:
                        continue

                bucket_key = int(numeric_time) // bucket_seconds
                buckets[bucket_key].append(row)
        
        # Aggregate per bucket
        result = []
        for bucket_key in sorted(buckets.keys()):
            rows = buckets[bucket_key]
            bucket_time = bucket_key * bucket_seconds
            
            bucket_row = {
                'time': bucket_time,
                'bucket_key': bucket_key,
            }
            
            # Apply metrics
            for metric in metrics:
                agg_value = self._compute_metric(rows, metric)
                bucket_row[metric.as_] = agg_value
            
            result.append(bucket_row)
        
        return result
    
    def _parse_time_bucket(self, bucket_str: str) -> int:
        """Parse time bucket string to seconds"""
        import re
        match = re.match(r'(\d+)([smh])', bucket_str)
        if not match:
            return 1
        
        value, unit = match.groups()
        value = int(value)
        
        if unit == 's':
            return value
        elif unit == 'm':
            return value * 60
        elif unit == 'h':
            return value * 3600
        
        return 1
    
    def _compute_metric(self, rows: List[Dict], metric) -> Any:
        """Compute a metric on a list of rows"""
        if not rows:
            return None
        
        field = metric.field
        metric_type = metric.type
        
        if metric_type == "count":
            return len(rows)
        
        elif metric_type == "distinct_count":
            return len(set(row.get(field) for row in rows if field in row))
        
        elif metric_type == "sum":
            values = [row.get(field, 0) for row in rows if isinstance(row.get(field), (int, float))]
            return sum(values) if values else 0
        
        elif metric_type == "avg":
            values = [row.get(field, 0) for row in rows if isinstance(row.get(field), (int, float))]
            return statistics.mean(values) if values else 0
        
        elif metric_type == "min":
            values = [row.get(field) for row in rows if isinstance(row.get(field), (int, float))]
            return min(values) if values else None
        
        elif metric_type == "max":
            values = [row.get(field) for row in rows if isinstance(row.get(field), (int, float))]
            return max(values) if values else None
        
        elif metric_type == "first":
            return rows[0].get(field) if rows else None
        
        elif metric_type == "last":
            return rows[-1].get(field) if rows else None
        
        return None
    
    def _apply_sort(self, data: List[Dict], sorts: List) -> List[Dict]:
        """Apply sorting"""
        result = list(data)
        
        for sort in reversed(sorts):  # Reverse to apply in order
            field = sort.field
            reverse = sort.direction == "desc"
            
            try:
                result = sorted(result, key=lambda row: row.get(field, 0), reverse=reverse)
            except:
                pass
        
        return result
    
    def _select_columns(self, data: List[Dict], columns: List[str]) -> List[Dict]:
        """Select specific columns"""
        result = []
        for row in data:
            new_row = {col: row.get(col) for col in columns}
            result.append(new_row)
        return result
