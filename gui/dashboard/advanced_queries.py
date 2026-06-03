"""
Advanced Query Layer.

Supports filter expression parsing, more sophisticated aggregations, and drilldown.
"""

import re
from typing import List, Dict, Any, Optional, Callable
from operator import eq, ne, lt, le, gt, ge


class FilterParser:
    """Parse and execute filter expressions"""
    
    OPERATORS = {
        '==': eq,
        '!=': ne,
        '<': lt,
        '<=': le,
        '>': gt,
        '>=': ge,
    }
    
    @staticmethod
    def parse_and_evaluate(row: Dict[str, Any], filter_expr: str) -> bool:
        """
        Parse and evaluate a filter expression on a row.
        
        Supports simple expressions like:
            protocol == TCP
            packet_count > 100
            ip.addr == 192.168.1.1
            (protocol == TCP) OR (port == 443)
        """
        if not filter_expr or not filter_expr.strip():
            return True
        
        try:
            return FilterParser._evaluate(row, filter_expr.strip())
        except:
            # If parsing fails, include the row
            return True
    
    @staticmethod
    def _evaluate(row: Dict[str, Any], expr: str) -> bool:
        """Internal evaluation - handles AND, OR, parentheses"""
        expr = expr.strip()
        
        # Handle parentheses
        while '(' in expr:
            # Find innermost parentheses
            start = expr.rfind('(')
            end = expr.find(')', start)
            if end == -1:
                break
            
            inner = expr[start + 1:end]
            inner_result = FilterParser._evaluate(row, inner)
            expr = expr[:start] + ('1' if inner_result else '0') + expr[end + 1:]
        
        # Split by OR (lower precedence)
        or_parts = re.split(r'\s+OR\s+', expr, flags=re.IGNORECASE)
        if len(or_parts) > 1:
            return any(FilterParser._evaluate(row, part) for part in or_parts)
        
        # Split by AND (higher precedence)
        and_parts = re.split(r'\s+AND\s+', expr, flags=re.IGNORECASE)
        if len(and_parts) > 1:
            return all(FilterParser._evaluate(row, part) for part in and_parts)
        
        # Handle atomic comparison: field op value
        return FilterParser._evaluate_comparison(row, expr)
    
    @staticmethod
    def _evaluate_comparison(row: Dict[str, Any], expr: str) -> bool:
        """Evaluate a single comparison like 'protocol == TCP'"""
        expr = expr.strip()
        
        # Handle string boolean values from parentheses
        if expr in ('0', '1'):
            return expr == '1'
        
        # Find operator
        for op_str, op_func in FilterParser.OPERATORS.items():
            if f' {op_str} ' in expr:
                parts = expr.split(f' {op_str} ', 1)
                if len(parts) == 2:
                    field, value = parts[0].strip(), parts[1].strip()
                    if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
                        value = value[1:-1]
                    
                    # Get field value from row
                    field_value = row.get(field)
                    
                    # Type conversions
                    try:
                        if isinstance(field_value, (int, float)):
                            value = float(value)
                        elif field_value is None:
                            return False
                    except:
                        pass
                    
                    return op_func(field_value, value)

        # Bare token fallback: perform case-insensitive substring search across row values.
        return FilterParser._row_contains_token(row, expr)

    @staticmethod
    def _row_contains_token(row: Dict[str, Any], token: str) -> bool:
        needle = str(token or '').strip()
        if not needle:
            return True
        if len(needle) >= 2 and needle[0] == needle[-1] and needle[0] in {'"', "'"}:
            needle = needle[1:-1]
        lowered = needle.lower()
        if not lowered:
            return True

        for value in row.values():
            if value in (None, ''):
                continue
            try:
                hay = str(value).lower()
            except Exception:
                continue
            if lowered in hay:
                return True
        return False


class DrilldownEngine:
    """Handle drilldown operations (click chart -> apply filter)"""
    
    @staticmethod
    def create_filter_from_row(row: Dict[str, Any], dimensions: List[str]) -> str:
        """
        Create a filter expression from a row based on dimensions.
        
        Args:
            row: A row from query result
            dimensions: List of dimension field names to filter on
        
        Returns:
            Filter expression string
        """
        conditions = []
        for field in dimensions:
            value = row.get(field)
            if value is None:
                continue
            
            # Quote string values
            if isinstance(value, str) and not value.isdigit():
                value = f'"{value}"'
            
            conditions.append(f'{field} == {value}')
        
        return ' AND '.join(conditions) if conditions else ''
    
    @staticmethod
    def create_time_range_filter(start_time: str, end_time: str, time_field: str = 'time') -> str:
        """Create a time range filter"""
        return f'({time_field} >= "{start_time}") AND ({time_field} <= "{end_time}")'


class AdvancedAggregation:
    """Advanced aggregation operations"""
    
    @staticmethod
    def pivot_table(data: List[Dict], rows: List[str], columns: List[str], values: str, agg_func: str = 'sum') -> List[Dict]:
        """
        Create a pivot table from data.
        
        Args:
            data: Input data
            rows: Fields to pivot on rows
            columns: Fields to pivot on columns
            values: Field to aggregate
            agg_func: Aggregation function (sum, count, avg, etc.)
        """
        from collections import defaultdict
        
        pivot = defaultdict(dict)
        
        for row in data:
            row_key = tuple(row.get(f) for f in rows)
            col_key = tuple(row.get(f) for f in columns)
            value = row.get(values, 0)
            
            if col_key not in pivot[row_key]:
                pivot[row_key][col_key] = []
            pivot[row_key][col_key].append(value)
        
        # Aggregate values
        result = []
        for row_key, col_dict in pivot.items():
            result_row = {rows[i]: row_key[i] for i in range(len(rows))}
            
            for col_key, values_list in col_dict.items():
                col_header = '_'.join(str(v) for v in col_key)
                result_row[col_header] = AdvancedAggregation._aggregate(values_list, agg_func)
            
            result.append(result_row)
        
        return result
    
    @staticmethod
    def _aggregate(values: List[Any], agg_func: str) -> Any:
        """Apply aggregation function"""
        if not values:
            return None
        
        if agg_func == 'sum':
            return sum(v for v in values if isinstance(v, (int, float)))
        elif agg_func == 'count':
            return len(values)
        elif agg_func == 'avg':
            nums = [v for v in values if isinstance(v, (int, float))]
            return sum(nums) / len(nums) if nums else None
        elif agg_func == 'max':
            nums = [v for v in values if isinstance(v, (int, float))]
            return max(nums) if nums else None
        elif agg_func == 'min':
            nums = [v for v in values if isinstance(v, (int, float))]
            return min(nums) if nums else None
        
        return None
    
    @staticmethod
    def percentile(data: List[Dict], field: str, percentile: float) -> Optional[float]:
        """Calculate percentile of a field"""
        values = sorted([d.get(field) for d in data if isinstance(d.get(field), (int, float))])
        if not values:
            return None
        
        idx = int(len(values) * percentile / 100)
        return values[min(idx, len(values) - 1)]


class TopNAnalysis:
    """Top N and Bottom N analysis"""
    
    @staticmethod
    def get_top_n(data: List[Dict], metric_field: str, n: int = 10, include_bottom: bool = False) -> Dict[str, List[Dict]]:
        """
        Get top N (and optionally bottom N) by metric.
        
        Returns:
            {'top': [...], 'bottom': [...]}
        """
        sorted_data = sorted(data, key=lambda x: x.get(metric_field, 0), reverse=True)
        
        result = {
            'top': sorted_data[:n],
        }
        
        if include_bottom:
            result['bottom'] = sorted_data[-n:] if len(sorted_data) >= n else sorted_data
        
        return result
    
    @staticmethod
    def get_outliers(data: List[Dict], field: str, std_dev_threshold: float = 2.0) -> Dict[str, List[Dict]]:
        """
        Identify statistical outliers.
        
        Args:
            data: Input data
            field: Field to analyze
            std_dev_threshold: Number of standard deviations to consider outlier
        """
        import statistics
        
        values = [d.get(field) for d in data if isinstance(d.get(field), (int, float))]
        if len(values) < 2:
            return {'outliers': []}
        
        mean = statistics.mean(values)
        stdev = statistics.stdev(values)
        
        if stdev == 0:
            return {'outliers': []}
        
        threshold = std_dev_threshold * stdev
        
        outliers = [
            d for d in data
            if isinstance(d.get(field), (int, float)) and abs(d.get(field) - mean) > threshold
        ]
        
        return {'outliers': outliers, 'mean': mean, 'stdev': stdev}


class ComparisonAnalysis:
    """Compare periods or segments"""
    
    @staticmethod
    def period_comparison(
        data: List[Dict],
        time_field: str,
        metric_field: str,
        period_size_seconds: int
    ) -> List[Dict]:
        """
        Compare metrics across time periods.
        
        Args:
            data: Input data with time field
            time_field: Name of time field
            metric_field: Name of metric field to compare
            period_size_seconds: Size of each period in seconds
        """
        from datetime import datetime
        from collections import defaultdict
        
        periods = defaultdict(list)
        
        for row in data:
            time_str = row.get(time_field)
            metric = row.get(metric_field)
            
            if not time_str or metric is None:
                continue
            
            try:
                time_obj = datetime.fromisoformat(time_str)
                period_key = int(time_obj.timestamp()) // period_size_seconds
                periods[period_key].append(metric)
            except:
                continue
        
        result = []
        for period_key in sorted(periods.keys()):
            values = periods[period_key]
            result.append({
                'period': period_key,
                'start_time': datetime.fromtimestamp(period_key * period_size_seconds).isoformat(),
                'count': len(values),
                'sum': sum(v for v in values if isinstance(v, (int, float))),
                'avg': sum(v for v in values if isinstance(v, (int, float))) / len([v for v in values if isinstance(v, (int, float))]) if values else 0,
                'min': min((v for v in values if isinstance(v, (int, float))), default=None),
                'max': max((v for v in values if isinstance(v, (int, float))), default=None),
            })
        
        return result
