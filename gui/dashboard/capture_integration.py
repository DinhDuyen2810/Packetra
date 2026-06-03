"""
Phase 7: Integration with capture_view Data Sources

Connects the dashboard system to real packet capture data from the GUI.
"""

from __future__ import annotations

import re
from typing import List, Dict, Any, Callable

from .query_engine import DataSourceRegistry


class CaptureDataSourceBuilder:
    """
    Factory for creating data source fetchers from capture_view components.
    
    These fetchers provide real packet data to dashboard queries.
    """

    @staticmethod
    def _iter_records(capture_view_ref: Any) -> List[Any]:
        """Return the effective records backing the current capture view."""
        if capture_view_ref is None:
            return []

        get_effective_records = getattr(capture_view_ref, 'get_effective_records', None)
        if callable(get_effective_records):
            try:
                return list(get_effective_records(include_ignored=False))
            except TypeError:
                try:
                    return list(get_effective_records())
                except Exception:
                    pass

        records = getattr(capture_view_ref, 'records', None)
        if records is not None:
            try:
                return list(records)
            except Exception:
                return []

        packet_table = getattr(capture_view_ref, 'packet_table', None)
        packets = getattr(packet_table, 'packets', None) if packet_table is not None else None
        if packets is not None:
            try:
                return list(packets)
            except Exception:
                return []

        return []

    @staticmethod
    def _records_signature(records: List[Any]) -> tuple[int, Any, Any]:
        if not records:
            return (0, None, None)
        return (
            len(records),
            getattr(records[0], 'number', None),
            getattr(records[-1], 'number', None),
        )

    @staticmethod
    def _metadata(record: Any) -> Dict[str, Any]:
        metadata = getattr(record, 'metadata', None)
        return metadata if isinstance(metadata, dict) else {}

    @staticmethod
    def _flatten_dashboard_value(value: Any) -> Any:
        if value is None:
            return None
        if isinstance(value, (bool, int, float, str)):
            return value
        if isinstance(value, bytes):
            return value.decode('utf-8', errors='ignore')
        if isinstance(value, (list, tuple, set)):
            parts = []
            for item in value:
                normalized = CaptureDataSourceBuilder._flatten_dashboard_value(item)
                if normalized not in (None, ''):
                    parts.append(str(normalized))
            return ', '.join(parts) if parts else None
        return str(value)

    @staticmethod
    def _flatten_dashboard_mapping(prefix: str, value: Any, target: Dict[str, Any]):
        if isinstance(value, dict):
            for child_key, child_value in value.items():
                child_prefix = f"{prefix}.{child_key}" if prefix else str(child_key)
                CaptureDataSourceBuilder._flatten_dashboard_mapping(child_prefix, child_value, target)
            return

        normalized = CaptureDataSourceBuilder._flatten_dashboard_value(value)
        if normalized is None or not prefix:
            return
        target[prefix] = normalized

    @staticmethod
    def _metadata_dashboard_fields(metadata: Dict[str, Any]) -> Dict[str, Any]:
        fields: Dict[str, Any] = {}
        for key, value in metadata.items():
            if isinstance(value, dict):
                CaptureDataSourceBuilder._flatten_dashboard_mapping(str(key), value, fields)
                continue

            normalized = CaptureDataSourceBuilder._flatten_dashboard_value(value)
            if normalized is not None:
                fields[str(key)] = normalized
        return fields

    @staticmethod
    def _to_int(value: Any) -> int:
        try:
            return int(value or 0)
        except Exception:
            return 0

    @staticmethod
    def _to_float(value: Any) -> float:
        try:
            return float(value or 0.0)
        except Exception:
            return 0.0

    @staticmethod
    def _protocol(record: Any) -> str:
        return str(getattr(record, 'protocol', '') or '').upper()

    @staticmethod
    def _extract_dns_query(record: Any) -> str:
        raw_packet = getattr(record, 'raw', None)
        try:
            if raw_packet is not None and raw_packet.haslayer('DNS'):
                dns_layer = raw_packet['DNS']
                question = getattr(dns_layer, 'qd', None)
                qname = getattr(question, 'qname', b'') if question is not None else b''
                if isinstance(qname, bytes):
                    qname = qname.decode('utf-8', errors='ignore')
                qname = str(qname or '').rstrip('.')
                if qname:
                    return qname
        except Exception:
            pass

        info = str(getattr(record, 'info', '') or '').strip()
        match = re.search(r'([A-Za-z0-9._-]+\.[A-Za-z]{2,})', info)
        if match:
            return match.group(1)
        return info or '(unknown)'

    @staticmethod
    def _extract_http_status(text: str) -> int:
        match = re.search(r'\b(\d{3})\b', str(text or ''))
        if not match:
            return 0
        try:
            return int(match.group(1))
        except Exception:
            return 0

    @staticmethod
    def _extract_http_method(record: Any, metadata: Dict[str, Any]) -> str:
        for key in ('http_request_method', 'http.method', 'http.request.method', 'method'):
            value = str(metadata.get(key, '') or '').strip().upper()
            if value:
                return value

        info = str(getattr(record, 'info', '') or '').strip()
        if info:
            token = info.split(' ', 1)[0].strip().upper()
            if token in {'GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'TRACE', 'CONNECT'}:
                return token

        return ''

    @staticmethod
    def _with_shared_fields(row: Dict[str, Any], *, default_protocol: str = "", default_time: float = 0.0) -> Dict[str, Any]:
        normalized = dict(row or {})
        protocol_value = str(
            normalized.get('protocol')
            or normalized.get('frame.protocol')
            or default_protocol
            or 'UNKNOWN'
        )
        bytes_value = CaptureDataSourceBuilder._to_int(
            normalized.get('bytes', normalized.get('length', normalized.get('frame.len', 0)))
        )
        packets_value = CaptureDataSourceBuilder._to_int(
            normalized.get('packets', normalized.get('count', 1))
        )
        normalized['protocol'] = protocol_value
        normalized['bytes'] = bytes_value
        normalized['packets'] = packets_value
        normalized['packet'] = packets_value
        normalized['time'] = CaptureDataSourceBuilder._to_float(normalized.get('time', default_time))
        return normalized
    
    @staticmethod
    def create_packets_fetcher(capture_view_ref: Any) -> Callable:
        """Create fetcher for packet data"""
        cache_signature = None
        cache_rows: List[Dict[str, Any]] = []

        def fetch_packets(limit: int | None = None) -> List[Dict[str, Any]]:
            """Fetch all packets from capture view"""
            nonlocal cache_signature, cache_rows
            try:
                records = CaptureDataSourceBuilder._iter_records(capture_view_ref)
                signature = CaptureDataSourceBuilder._records_signature(records)
                if cache_signature != signature:
                    result = []
                    for packet in records:
                        metadata = CaptureDataSourceBuilder._metadata(packet)
                        http_method = CaptureDataSourceBuilder._extract_http_method(packet, metadata)
                        packet_dict = {
                            'number': CaptureDataSourceBuilder._to_int(getattr(packet, 'number', 0)),
                            'time': CaptureDataSourceBuilder._to_float(getattr(packet, 'relative_time', 0.0)),
                            'epoch_time': CaptureDataSourceBuilder._to_float(getattr(packet, 'epoch_time', 0.0)),
                            'src_ip': str(getattr(packet, 'src', '') or ''),
                            'dst_ip': str(getattr(packet, 'dst', '') or ''),
                            'protocol': str(getattr(packet, 'protocol', '') or ''),
                            'length': CaptureDataSourceBuilder._to_int(getattr(packet, 'length', 0)),
                            'src_port': CaptureDataSourceBuilder._to_int(getattr(packet, 'sport', 0)),
                            'dst_port': CaptureDataSourceBuilder._to_int(getattr(packet, 'dport', 0)),
                            'info': str(getattr(packet, 'info', '') or ''),
                            'http_kind': str(metadata.get('http_kind', '') or ''),
                            'http_method': http_method,
                            'http_request_uri': str(metadata.get('http_request_uri', '') or metadata.get('http_full_request_uri', '') or ''),
                            'http_latency_ms': CaptureDataSourceBuilder._to_float(metadata.get('http_time_since_request_ms', 0.0)),
                            'dns_time_ms': CaptureDataSourceBuilder._to_float(metadata.get('dns_time_ms', 0.0)),
                            'frame.number': CaptureDataSourceBuilder._to_int(getattr(packet, 'number', 0)),
                            'frame.time_relative': CaptureDataSourceBuilder._to_float(getattr(packet, 'relative_time', 0.0)),
                            'frame.time_epoch': CaptureDataSourceBuilder._to_float(getattr(packet, 'epoch_time', 0.0)),
                            'frame.len': CaptureDataSourceBuilder._to_int(getattr(packet, 'length', 0)),
                            'frame.protocol': str(getattr(packet, 'protocol', '') or ''),
                            'frame.info': str(getattr(packet, 'info', '') or ''),
                            'ip.src': str(getattr(packet, 'src', '') or ''),
                            'ip.dst': str(getattr(packet, 'dst', '') or ''),
                            'tcp.srcport': CaptureDataSourceBuilder._to_int(getattr(packet, 'sport', 0)),
                            'tcp.dstport': CaptureDataSourceBuilder._to_int(getattr(packet, 'dport', 0)),
                            'udp.srcport': CaptureDataSourceBuilder._to_int(getattr(packet, 'sport', 0)),
                            'udp.dstport': CaptureDataSourceBuilder._to_int(getattr(packet, 'dport', 0)),
                            'http.kind': str(metadata.get('http_kind', '') or ''),
                            'http.method': http_method,
                            'http.request.method': http_method,
                            'http.request_uri': str(metadata.get('http_request_uri', '') or metadata.get('http_full_request_uri', '') or ''),
                            'http.time_since_request_ms': CaptureDataSourceBuilder._to_float(metadata.get('http_time_since_request_ms', 0.0)),
                            'dns.time_ms': CaptureDataSourceBuilder._to_float(metadata.get('dns_time_ms', 0.0)),
                        }
                        packet_dict.update(CaptureDataSourceBuilder._metadata_dashboard_fields(metadata))
                        result.append(CaptureDataSourceBuilder._with_shared_fields(packet_dict, default_protocol=str(getattr(packet, 'protocol', '') or ''), default_time=CaptureDataSourceBuilder._to_float(getattr(packet, 'relative_time', 0.0))))
                    cache_rows = result
                    cache_signature = signature

                if limit is not None:
                    return list(cache_rows[:max(1, int(limit))])
                return list(cache_rows)
            except Exception as e:
                print(f"Error fetching packets: {e}")
                return []
        
        return fetch_packets
    
    @staticmethod
    def create_endpoints_fetcher(capture_view_ref: Any) -> Callable:
        """Create fetcher for endpoint statistics"""
        cache_signature = None
        cache_rows: List[Dict[str, Any]] = []

        def fetch_endpoints(limit: int | None = None) -> List[Dict[str, Any]]:
            """Fetch endpoint statistics"""
            nonlocal cache_signature, cache_rows
            try:
                records = CaptureDataSourceBuilder._iter_records(capture_view_ref)
                signature = CaptureDataSourceBuilder._records_signature(records)
                if cache_signature != signature:
                    endpoints = {}
                    for packet in records:
                        src_ip = str(getattr(packet, 'src', '') or '')
                        dst_ip = str(getattr(packet, 'dst', '') or '')
                        protocol = str(getattr(packet, 'protocol', '') or '')
                        length = CaptureDataSourceBuilder._to_int(getattr(packet, 'length', 0))

                        if src_ip:
                            entry = endpoints.setdefault(src_ip, {
                                'address': src_ip,
                                'ip': src_ip,
                                'packets': 0,
                                'bytes': 0,
                                'tx_packets': 0,
                                'rx_packets': 0,
                                'protocols': set(),
                            })
                            entry['packets'] += 1
                            entry['bytes'] += length
                            entry['tx_packets'] += 1
                            if protocol:
                                entry['protocols'].add(protocol)

                        if dst_ip:
                            entry = endpoints.setdefault(dst_ip, {
                                'address': dst_ip,
                                'ip': dst_ip,
                                'packets': 0,
                                'bytes': 0,
                                'tx_packets': 0,
                                'rx_packets': 0,
                                'protocols': set(),
                            })
                            entry['packets'] += 1
                            entry['bytes'] += length
                            entry['rx_packets'] += 1
                            if protocol:
                                entry['protocols'].add(protocol)

                    result = []
                    for endpoint in endpoints.values():
                        endpoint['protocols'] = ', '.join(sorted(endpoint['protocols']))
                        result.append(CaptureDataSourceBuilder._with_shared_fields(endpoint, default_protocol='ENDPOINT', default_time=0.0))
                    cache_rows = result
                    cache_signature = signature

                if limit is not None:
                    return list(cache_rows[:max(1, int(limit))])
                return list(cache_rows)
            except Exception as e:
                print(f"Error fetching endpoints: {e}")
                return []
        
        return fetch_endpoints
    
    @staticmethod
    def create_conversations_fetcher(capture_view_ref: Any) -> Callable:
        """Create fetcher for conversation data"""
        cache_signature = None
        cache_rows: List[Dict[str, Any]] = []

        def fetch_conversations(limit: int | None = None) -> List[Dict[str, Any]]:
            """Fetch conversation statistics"""
            nonlocal cache_signature, cache_rows
            try:
                records = CaptureDataSourceBuilder._iter_records(capture_view_ref)
                signature = CaptureDataSourceBuilder._records_signature(records)
                if cache_signature != signature:
                    conversations = {}
                    for packet in records:
                        src_ip = str(getattr(packet, 'src', '') or '')
                        dst_ip = str(getattr(packet, 'dst', '') or '')
                        protocol = str(getattr(packet, 'protocol', '') or '')
                        length = CaptureDataSourceBuilder._to_int(getattr(packet, 'length', 0))

                        ips = sorted([src_ip, dst_ip])
                        if ips[0] and ips[1]:
                            key = f"{ips[0]}<->{ips[1]}:{protocol}"

                            if key not in conversations:
                                conversations[key] = {
                                    'conversation': f"{ips[0]} <-> {ips[1]} ({protocol or 'UNKNOWN'})",
                                    'src_ip': ips[0],
                                    'dst_ip': ips[1],
                                    'protocol': protocol,
                                    'packets': 0,
                                    'bytes': 0,
                                }

                            conversations[key]['packets'] += 1
                            conversations[key]['bytes'] += length

                    cache_rows = [
                        CaptureDataSourceBuilder._with_shared_fields(item, default_protocol=str(item.get('protocol', '') or 'UNKNOWN'), default_time=0.0)
                        for item in conversations.values()
                    ]
                    cache_signature = signature

                if limit is not None:
                    return list(cache_rows[:max(1, int(limit))])
                return list(cache_rows)
            except Exception as e:
                print(f"Error fetching conversations: {e}")
                return []
        
        return fetch_conversations
    
    @staticmethod
    def create_protocol_stats_fetcher(capture_view_ref: Any) -> Callable:
        """Create fetcher for protocol statistics"""
        cache_signature = None
        cache_rows: List[Dict[str, Any]] = []

        def fetch_protocol_stats(limit: int | None = None) -> List[Dict[str, Any]]:
            """Fetch protocol distribution"""
            nonlocal cache_signature, cache_rows
            try:
                records = CaptureDataSourceBuilder._iter_records(capture_view_ref)
                signature = CaptureDataSourceBuilder._records_signature(records)
                if cache_signature != signature:
                    protocols = {}
                    for packet in records:
                        protocol = str(getattr(packet, 'protocol', 'Unknown') or 'Unknown')
                        length = CaptureDataSourceBuilder._to_int(getattr(packet, 'length', 0))

                        if protocol not in protocols:
                            protocols[protocol] = {
                                'protocol': protocol,
                                'packets': 0,
                                'bytes': 0,
                            }

                        protocols[protocol]['packets'] += 1
                        protocols[protocol]['bytes'] += length

                    cache_rows = [
                        CaptureDataSourceBuilder._with_shared_fields(item, default_protocol=str(item.get('protocol', '') or 'UNKNOWN'), default_time=0.0)
                        for item in protocols.values()
                    ]
                    cache_signature = signature

                if limit is not None:
                    return list(cache_rows[:max(1, int(limit))])
                return list(cache_rows)
            except Exception as e:
                print(f"Error fetching protocol stats: {e}")
                return []
        
        return fetch_protocol_stats
    
    @staticmethod
    def create_dns_queries_fetcher(capture_view_ref: Any) -> Callable:
        """Create fetcher for DNS queries"""
        def fetch_dns_queries() -> List[Dict[str, Any]]:
            """Fetch DNS query statistics"""
            try:
                dns_queries = {}

                for packet in CaptureDataSourceBuilder._iter_records(capture_view_ref):
                    protocol = CaptureDataSourceBuilder._protocol(packet)
                    if protocol not in {'DNS', 'MDNS'}:
                        continue

                    metadata = CaptureDataSourceBuilder._metadata(packet)
                    query = CaptureDataSourceBuilder._extract_dns_query(packet)
                    is_response = bool(CaptureDataSourceBuilder._to_int(metadata.get('dns_qr', 0)))
                    entry = dns_queries.setdefault(query, {
                        'query': query,
                        'count': 0,
                        'responses': 0,
                        'avg_time_ms': 0.0,
                        '_total_time_ms': 0.0,
                    })

                    if is_response:
                        entry['responses'] += 1
                        entry['_total_time_ms'] += CaptureDataSourceBuilder._to_float(metadata.get('dns_time_ms', 0.0))
                    else:
                        entry['count'] += 1

                result = []
                for entry in dns_queries.values():
                    responses = max(1, entry['responses']) if entry['responses'] else 0
                    total_time_ms = entry.pop('_total_time_ms', 0.0)
                    entry['avg_time_ms'] = round(total_time_ms / responses, 2) if responses else 0.0
                    result.append(CaptureDataSourceBuilder._with_shared_fields(entry, default_protocol='DNS', default_time=0.0))
                return result
            except Exception as e:
                print(f"Error fetching DNS queries: {e}")
                return []
        
        return fetch_dns_queries
    
    @staticmethod
    def create_http_requests_fetcher(capture_view_ref: Any) -> Callable:
        """Create fetcher for HTTP requests"""
        def fetch_http_requests() -> List[Dict[str, Any]]:
            """Fetch HTTP request statistics"""
            try:
                http_requests = []

                for packet in CaptureDataSourceBuilder._iter_records(capture_view_ref):
                    protocol = CaptureDataSourceBuilder._protocol(packet)
                    metadata = CaptureDataSourceBuilder._metadata(packet)
                    kind = str(metadata.get('http_kind', '') or '')
                    uri = str(metadata.get('http_request_uri', '') or metadata.get('http_full_request_uri', '') or '')
                    method = CaptureDataSourceBuilder._extract_http_method(packet, metadata)

                    if protocol not in {'HTTP', 'HTTP/XML'} and not (kind or uri):
                        continue

                    http_request = {
                        'src_ip': str(getattr(packet, 'src', '') or ''),
                        'dst_ip': str(getattr(packet, 'dst', '') or ''),
                        'kind': kind or 'message',
                        'method': method,
                        'uri': uri or str(getattr(packet, 'info', '') or ''),
                        'status': CaptureDataSourceBuilder._extract_http_status(str(getattr(packet, 'info', '') or '')),
                        'latency_ms': round(CaptureDataSourceBuilder._to_float(metadata.get('http_time_since_request_ms', 0.0)), 2),
                        'bytes': CaptureDataSourceBuilder._to_int(getattr(packet, 'length', 0)),
                    }
                    http_requests.append(CaptureDataSourceBuilder._with_shared_fields(http_request, default_protocol='HTTP', default_time=0.0))

                return http_requests
            except Exception as e:
                print(f"Error fetching HTTP requests: {e}")
                return []
        
        return fetch_http_requests
    
    @staticmethod
    def register_all_sources(data_source_registry: DataSourceRegistry, capture_view_ref: Any):
        """
        Register all capture data sources with the registry.
        
        Args:
            data_source_registry: DataSourceRegistry instance
            capture_view_ref: Reference to CaptureView GUI component (or None for demo)
        """
        data_source_registry.register(
            'packets',
            CaptureDataSourceBuilder.create_packets_fetcher(capture_view_ref)
        )
        
        data_source_registry.register(
            'endpoints',
            CaptureDataSourceBuilder.create_endpoints_fetcher(capture_view_ref)
        )
        
        data_source_registry.register(
            'conversations',
            CaptureDataSourceBuilder.create_conversations_fetcher(capture_view_ref)
        )
        
        data_source_registry.register(
            'protocol_stats',
            CaptureDataSourceBuilder.create_protocol_stats_fetcher(capture_view_ref)
        )
        
        data_source_registry.register(
            'dns_queries',
            CaptureDataSourceBuilder.create_dns_queries_fetcher(capture_view_ref)
        )
        
        data_source_registry.register(
            'http_requests',
            CaptureDataSourceBuilder.create_http_requests_fetcher(capture_view_ref)
        )
