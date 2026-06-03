import re

from scapy.all import ARP, BOOTP, DHCP, DNS, Dot1Q, Ether, ICMP, IP, IPv6, TCP, UDP

from core.models import PacketRecord


TOKEN_RE = re.compile(
    r'"[^"\\]*(?:\\.[^"\\]*)*"|\'[^\'\\]*(?:\\.[^\'\\]*)*\'|==|!=|<=|>=|\|\||&&|[()<>!]|\bcontains\b|\band\b|\bor\b|\bnot\b|[^\s()<>!=&|]+'
    ,
    re.IGNORECASE,
)


class DisplayFilter:
    PROTOCOL_ALIASES = {
        'tcp', 'udp', 'dns', 'mdns', 'arp', 'icmp', 'icmpv6', 'igmp', 'tls', 'quic', 'http', 'smtp', 'imf',
        'dhcp', 'bootp', 'ripng', 'ripv2', 'stp', 'syslog', 'ntp', 'lacp', 'vtp', 'dtp', 'lldp', 'udld',
        'loop', 'hsrp', 'hsrpv2', 'ip', 'ipv6', 'eth', 'tftp', 'ssdp', 'esp', 'ssh', 'sshv2', 'isakmp', 'ike',
        'ftp', 'pop', 'imap', 'smb', 'smb2', 'llmnr', 'nbns', 'snmp', 'ah', 'ospf', 'eigrp', 'bgp', 'gre', 'vlan', 'ssl',
        'ipv4', 'icmpv4'
    }
    HTTP_REQUEST_METHODS = {
        'GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH', 'TRACE', 'CONNECT', 'PRI'
    }

    def matches(self, record: PacketRecord, expression: str) -> bool:
        text = self._normalize_expression(expression)
        if not text:
            return True

        # Fast-path for protocol-only filters (e.g. tcp, arp, ip, ipv6, icmp, vlan).
        proto_token = self._protocol_only_candidate(text)
        if proto_token in self.PROTOCOL_ALIASES:
            return self._protocol_present(record, proto_token)

        try:
            self.tokens = TOKEN_RE.findall(text)
            self.pos = 0
            result = self._parse_or(record)
            return bool(result) and self.pos == len(self.tokens)
        except Exception:
            return self._match_legacy_atom(record, text)

    def _parse_or(self, record: PacketRecord) -> bool:
        result = self._parse_and(record)
        while self._peek_lower() in {'or', '||'}:
            self.pos += 1
            rhs = self._parse_and(record)
            result = bool(result or rhs)
        return bool(result)

    def _parse_and(self, record: PacketRecord) -> bool:
        result = self._parse_not(record)
        while self._peek_lower() in {'and', '&&'}:
            self.pos += 1
            rhs = self._parse_not(record)
            result = bool(result and rhs)
        return bool(result)

    def _parse_not(self, record: PacketRecord) -> bool:
        if self._peek_lower() in {'not', '!'}:
            self.pos += 1
            return not self._parse_not(record)
        return self._parse_primary(record)

    def _parse_primary(self, record: PacketRecord) -> bool:
        token = self._peek()
        if token == '(':
            self.pos += 1
            value = self._parse_or(record)
            if self._peek() == ')':
                self.pos += 1
            return bool(value)

        field = self._consume()
        if field is None:
            return False
        field = self._normalize_token(field)

        next_token = self._peek_lower()
        if next_token in {'==', '!=', '<', '>', '<=', '>=', 'contains'}:
            op = self._consume().lower()
            rhs_token = self._consume()
            rhs_value = self._parse_literal(rhs_token)
            return self._compare_field(record, field, op, rhs_value)

        return self._evaluate_boolean_field(record, field)

    def _peek(self):
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _peek_lower(self):
        token = self._peek()
        return token.lower() if token is not None else None

    def _consume(self):
        token = self._peek()
        if token is not None:
            self.pos += 1
        return token

    def _parse_literal(self, token):
        if token is None:
            return ''
        token = self._normalize_token(token)
        if len(token) >= 2 and token[0] == token[-1] and token[0] in {'"', "'"}:
            return token[1:-1]
        if re.fullmatch(r'0x[0-9a-fA-F]+', token):
            return int(token, 16)
        if re.fullmatch(r'-?\d+', token):
            return int(token)
        if re.fullmatch(r'-?\d+\.\d+', token):
            return float(token)
        return token

    def _compare_field(self, record: PacketRecord, field: str, op: str, rhs_value) -> bool:
        values = self._resolve_field_values(record, field)
        if not values:
            return False
        for value in values:
            if self._compare_value(value, op, rhs_value):
                return True
        return False

    def _compare_value(self, value, op: str, rhs_value) -> bool:
        if op == 'contains':
            return str(rhs_value).lower() in str(value).lower()

        left_num = self._as_number(value)
        right_num = self._as_number(rhs_value)
        if left_num is not None and right_num is not None:
            if op == '==':
                return left_num == right_num
            if op == '!=':
                return left_num != right_num
            if op == '<':
                return left_num < right_num
            if op == '>':
                return left_num > right_num
            if op == '<=':
                return left_num <= right_num
            if op == '>=':
                return left_num >= right_num

        left_text = str(value).lower()
        right_text = str(rhs_value).lower()
        if op == '==':
            return left_text == right_text
        if op == '!=':
            return left_text != right_text
        if op == '<':
            return left_text < right_text
        if op == '>':
            return left_text > right_text
        if op == '<=':
            return left_text <= right_text
        if op == '>=':
            return left_text >= right_text
        return False

    def _evaluate_boolean_field(self, record: PacketRecord, field: str) -> bool:
        values = self._resolve_field_values(record, field)
        if not values:
            return False
        if all(isinstance(value, bool) for value in values):
            return any(values)
        return True

    def _resolve_field_values(self, record: PacketRecord, field: str) -> list:
        key = str(field or '').strip()
        low = key.lower()
        raw = getattr(record, 'raw', None)
        metadata = getattr(record, 'metadata', {}) or {}

        if not key:
            return []

        if low in self.PROTOCOL_ALIASES:
            return [self._protocol_present(record, low)]

        if low == 'frame.number':
            return [int(record.number)]
        if low == 'frame.len':
            return [int(record.length)]
        if low == 'frame.time_delta':
            return [float(metadata.get('frame_time_delta', 0.0) or 0.0)]

        if low == 'eth.addr':
            layer = self._get_layer(raw, Ether)
            return [str(getattr(layer, 'src', '') or ''), str(getattr(layer, 'dst', '') or '')] if layer is not None else []
        if low == 'eth.src':
            return self._field_from_layer(raw, Ether, 'src')
        if low == 'eth.dst':
            return self._field_from_layer(raw, Ether, 'dst')
        if low == 'eth.type':
            return self._field_from_layer(raw, Ether, 'type')

        if low == 'vlan.id':
            return self._field_from_layer(raw, Dot1Q, 'vlan')

        if low == 'arp.opcode':
            return self._field_from_layer(raw, ARP, 'op')
        if low == 'arp.src.proto_ipv4':
            return self._field_from_layer(raw, ARP, 'psrc')
        if low == 'arp.dst.proto_ipv4':
            return self._field_from_layer(raw, ARP, 'pdst')

        if low in {'ip.addr', 'ip.host'}:
            return self._ip_addrs(raw)
        if low == 'ip.src':
            return self._field_from_layer(raw, IP, 'src')
        if low == 'ip.dst':
            return self._field_from_layer(raw, IP, 'dst')
        if low == 'ip.proto':
            return self._field_from_layer(raw, IP, 'proto')
        if low == 'ip.ttl':
            return self._field_from_layer(raw, IP, 'ttl')

        if low in {'ipv6.addr', 'ipv6.host'}:
            layer = self._get_layer(raw, IPv6)
            return [str(getattr(layer, 'src', '') or ''), str(getattr(layer, 'dst', '') or '')] if layer is not None else []
        if low == 'ipv6.src':
            return self._field_from_layer(raw, IPv6, 'src')
        if low == 'ipv6.dst':
            return self._field_from_layer(raw, IPv6, 'dst')

        if low == 'icmp.type':
            return self._field_from_layer(raw, ICMP, 'type')

        if low == 'tcp.port':
            return self._ports(record, TCP)
        if low == 'tcp.srcport':
            return self._field_from_layer(raw, TCP, 'sport')
        if low == 'tcp.dstport':
            return self._field_from_layer(raw, TCP, 'dport')
        if low == 'tcp.stream':
            stream_index = metadata.get('tcp_stream_index', None)
            return [int(stream_index)] if stream_index is not None else []
        if low.startswith('tcp.flags.'):
            flag_name = low.rsplit('.', 1)[-1]
            return [self._tcp_flag(raw, flag_name)]

        if low == 'udp.port':
            return self._ports(record, UDP)
        if low == 'udp.srcport':
            return self._field_from_layer(raw, UDP, 'sport')
        if low == 'udp.dstport':
            return self._field_from_layer(raw, UDP, 'dport')
        if low == 'udp.stream':
            stream_index = metadata.get('udp_stream_index', None)
            return [int(stream_index)] if stream_index is not None else []

        if low == 'dns.flags.response':
            return [int(getattr(raw[DNS], 'qr', 0) or 0)] if raw.haslayer(DNS) else []
        if low == 'dns.qry.name':
            return self._dns_query_names(raw)
        if low == 'dns.qry.type':
            return self._dns_query_types(raw)
        if low == 'dns.flags.rcode':
            return [int(getattr(raw[DNS], 'rcode', 0) or 0)] if raw.haslayer(DNS) else []

        if low == 'bootp.option.dhcp':
            dhcp_type = self._dhcp_message_type(raw)
            return [dhcp_type] if dhcp_type is not None else []

        if low == 'http.request':
            return [self._http_payload_kind(record) == 'request']
        if low == 'http.response':
            return [self._http_payload_kind(record) == 'response']
        if low == 'http.request.method':
            method = self._http_request_method(record)
            return [method] if method else []
        if low == 'http.host':
            host = self._http_host(record)
            return [host] if host else []
        if low == 'http.request.uri':
            uri = str(metadata.get('http_request_uri', '') or '').strip()
            return [uri] if uri else []

        if low == 'tls.handshake':
            return [bool(self._tls_records(record, raw)) and any(int(item.get('content_type', 0) or 0) == 22 for item in self._tls_records(record, raw))]
        if low == 'tls.handshake.type':
            return self._tls_handshake_types(record, raw)
        if low == 'tls.handshake.extensions_server_name':
            sni = self._tls_sni(record, raw)
            return [sni] if sni else []
        if low == 'tls.record.content_type':
            return [int(item.get('content_type', 0) or 0) for item in self._tls_records(record, raw)]

        if low == 'ftp.request.command':
            cmd = self._ftp_command(record)
            return [cmd] if cmd else []
        if low == 'smtp.req.command':
            cmd = self._smtp_command(record)
            return [cmd] if cmd else []
        if low == 'smb2.cmd':
            cmd = self._smb2_command(raw, record)
            return [cmd] if cmd is not None else []
        if low == 'smb2.filename':
            names = self._smb2_filenames(record)
            return names

        if low == 'port':
            return self._ports(record, None)

        if low == 'detail':
            return self._detail_terms(record)
        if low == 'detail.title':
            return [str(item.get('title', '') or '') for item in self._detail_nodes(record)]
        if low == 'detail.key':
            return [str(item.get('key', '') or '') for item in self._detail_nodes(record)]
        if low == 'detail.value':
            return [str(item.get('value', '') or '') for item in self._detail_nodes(record)]
        if low == 'detail.pair':
            return [str(item.get('pair', '') or '') for item in self._detail_nodes(record)]
        if low == 'detail.path':
            return [str(item.get('path', '') or '') for item in self._detail_nodes(record)]

        return []

    def _detail_nodes(self, record: PacketRecord) -> list:
        metadata = getattr(record, 'metadata', {}) or {}
        cached = metadata.get('_detail_filter_nodes') if isinstance(metadata, dict) else None
        if isinstance(cached, list):
            return cached

        nodes = []
        raw = getattr(record, 'raw', None)
        if raw is None:
            return nodes

        try:
            from core.formatters import packet_summary_tree

            tree = packet_summary_tree(raw, record)
        except Exception:
            tree = []

        def _strip_bracket_suffix(text: str) -> str:
            value = str(text or '').strip()
            if not value:
                return ''
            return re.split(r'\s+\[[^\]]*\]', value, 1)[0].strip()

        def _normalize_path_part(text: str) -> str:
            value = str(text or '').strip().casefold()
            if not value:
                return ''
            if ': ' in value:
                value = value.split(': ', 1)[0].strip()
            elif ' = ' in value:
                value = value.split(' = ', 1)[0].strip()
            if ',' in value:
                value = value.split(',', 1)[0].strip()
            value = re.sub(r'\s+', ' ', value)
            return value

        def _walk(items, path_parts):
            for item in items or []:
                if not isinstance(item, dict):
                    continue
                title = str(item.get('title', '') or '').strip()
                node_path = list(path_parts)
                if title:
                    key = title
                    value = ''
                    if ': ' in title:
                        key, value = title.split(': ', 1)
                    elif ' = ' in title:
                        key, value = title.split(' = ', 1)
                    key = str(key or '').strip()
                    value = _strip_bracket_suffix(value)
                    pair = f'{key}: {value}' if key and value else key
                    key_part = _normalize_path_part(key)
                    if key_part:
                        node_path.append(key_part)
                    nodes.append({
                        'title': title,
                        'key': key,
                        'value': value,
                        'pair': pair,
                        'path': ' / '.join(node_path),
                    })
                _walk(item.get('children', []), node_path)

        _walk(tree, [])
        if isinstance(metadata, dict):
            metadata['_detail_filter_nodes'] = nodes
        return nodes

    def _detail_terms(self, record: PacketRecord) -> list:
        metadata = getattr(record, 'metadata', {}) or {}
        cached = metadata.get('_detail_filter_terms') if isinstance(metadata, dict) else None
        if isinstance(cached, list):
            return cached

        terms = []
        for item in self._detail_nodes(record):
            title = str(item.get('title', '') or '').strip()
            key = str(item.get('key', '') or '').strip()
            value = str(item.get('value', '') or '').strip()
            pair = str(item.get('pair', '') or '').strip()
            path = str(item.get('path', '') or '').strip()
            if title:
                terms.append(title)
            if key:
                terms.append(key)
            if value:
                terms.append(value)
            if pair:
                terms.append(pair)
            if path:
                terms.append(path)
        if isinstance(metadata, dict):
            metadata['_detail_filter_terms'] = terms
        return terms

    def _protocol_present(self, record: PacketRecord, name: str) -> bool:
        raw = getattr(record, 'raw', None)
        proto_low = str(record.protocol or '').strip().lower()
        layer_lows = self._layer_lows(record)

        if name == 'bootp':
            return name in layer_lows or proto_low == 'dhcp' or (raw is not None and (raw.haslayer(BOOTP) or raw.haslayer(DHCP)))
        if name == 'dhcp':
            return proto_low in {'dhcp', 'bootp'} or name in layer_lows or (raw is not None and raw.haslayer(DHCP))
        if name == 'tls':
            return proto_low.startswith('tls') or proto_low == 'ssl' or 'tls' in layer_lows or 'ssl' in layer_lows or bool(self._tls_records(record, raw))
        if name == 'ssl':
            return proto_low == 'ssl' or proto_low.startswith('tls') or 'ssl' in layer_lows or 'tls' in layer_lows
        if name == 'http':
            if proto_low in {'http', 'http/xml'} or 'http' in layer_lows:
                return True
            # Only use payload heuristics for TCP traffic to avoid matching
            # HTTP-like text protocols over UDP (e.g. SSDP responses).
            if raw is not None and raw.haslayer(TCP):
                return bool(self._http_payload_kind(record))
            return False
        if name in {'smtp', 'imf'}:
            return proto_low in {'smtp', 'smtp/imf'} or name in layer_lows
        if name in {'ssh', 'sshv2'}:
            return proto_low in {'ssh', 'sshv2'} or name in layer_lows
        if name in {'smb', 'smb2'}:
            return proto_low == name or name in layer_lows
        if name == 'pop':
            return proto_low in {'pop', 'pop/imf'} or name in layer_lows
        if name == 'mdns':
            return proto_low == 'mdns' or name in layer_lows
        if name == 'icmpv6':
            return proto_low == 'icmpv6' or name in layer_lows
        if name == 'vlan':
            return name in layer_lows or (raw is not None and raw.haslayer(Dot1Q))
        if name == 'eth':
            return name in layer_lows or (raw is not None and raw.haslayer(Ether))
        if name == 'ip':
            return proto_low in {'ip', 'ipv4'} or name in layer_lows or (raw is not None and raw.haslayer(IP))
        if name == 'ipv4':
            return proto_low in {'ip', 'ipv4'} or 'ip' in layer_lows or 'ipv4' in layer_lows or (raw is not None and raw.haslayer(IP))
        if name == 'ipv6':
            return proto_low == 'ipv6' or name in layer_lows or (raw is not None and raw.haslayer(IPv6))
        if name == 'arp':
            return proto_low.startswith('arp') or name in layer_lows or (raw is not None and raw.haslayer(ARP))
        if name == 'icmp':
            return proto_low in {'icmp', 'icmpv4'} or name in layer_lows or (raw is not None and raw.haslayer(ICMP))
        if name == 'icmpv4':
            return proto_low in {'icmp', 'icmpv4'} or 'icmp' in layer_lows or 'icmpv4' in layer_lows or (raw is not None and raw.haslayer(ICMP))
        if name == 'tcp':
            return proto_low == 'tcp' or name in layer_lows or (raw is not None and raw.haslayer(TCP))
        if name == 'udp':
            return proto_low == 'udp' or name in layer_lows or (raw is not None and raw.haslayer(UDP))
        if name == 'dns':
            return (
                proto_low == 'dns'
                or 'dns' in layer_lows
                or (raw is not None and raw.haslayer(DNS) and proto_low not in {'mdns', 'llmnr', 'nbns'})
            )
        if name == 'gre':
            return proto_low == 'gre' or 'gre' in layer_lows
        if name == 'ike':
            return proto_low == 'isakmp' or 'isakmp' in layer_lows
        return proto_low == name or name in layer_lows

    def _get_layer(self, raw, layer_type):
        try:
            return raw[layer_type] if raw is not None and raw.haslayer(layer_type) else None
        except Exception:
            return None

    def _field_from_layer(self, raw, layer_type, attr_name: str) -> list:
        layer = self._get_layer(raw, layer_type)
        if layer is None:
            return []
        try:
            value = getattr(layer, attr_name, None)
        except Exception:
            return []
        return [] if value is None else [value]

    def _ip_addrs(self, raw) -> list:
        layer = self._get_layer(raw, IP)
        if layer is None:
            return []
        return [str(getattr(layer, 'src', '') or ''), str(getattr(layer, 'dst', '') or '')]

    def _ports(self, record: PacketRecord, layer_type) -> list:
        raw = getattr(record, 'raw', None)
        if layer_type is not None and raw is not None and not raw.haslayer(layer_type):
            return []
        if layer_type is TCP and raw is None:
            proto_low = str(record.protocol or '').lower()
            layer_lows = self._layer_lows(record)
            if proto_low != 'tcp' and 'tcp' not in layer_lows and not any(name in layer_lows for name in {'http', 'tls', 'ssl', 'ftp', 'smtp', 'pop', 'imap', 'ssh', 'smb', 'smb2', 'bgp'}):
                return []
        if layer_type is UDP and raw is None:
            proto_low = str(record.protocol or '').lower()
            layer_lows = self._layer_lows(record)
            if proto_low != 'udp' and 'udp' not in layer_lows and not any(name in layer_lows for name in {'dns', 'dhcp', 'bootp', 'ntp', 'snmp', 'llmnr', 'nbns', 'mdns', 'isakmp'}):
                return []
        values = []
        if getattr(record, 'sport', None) is not None:
            values.append(int(record.sport))
        if getattr(record, 'dport', None) is not None:
            values.append(int(record.dport))
        return values

    def _tcp_flag(self, raw, flag_name: str) -> bool:
        layer = self._get_layer(raw, TCP)
        if layer is None:
            return False
        try:
            flags = int(getattr(layer, 'flags', 0) or 0)
        except Exception:
            return False
        mapping = {
            'syn': 0x02,
            'ack': 0x10,
            'fin': 0x01,
            'reset': 0x04,
            'rst': 0x04,
        }
        bit = mapping.get(flag_name, 0)
        return bool(flags & bit)

    def _dns_query_names(self, raw) -> list:
        layer = self._get_layer(raw, DNS)
        if layer is None:
            return []
        try:
            qd = getattr(layer, 'qd', None)
            qname = getattr(qd, 'qname', b'') if qd is not None else b''
            if isinstance(qname, (bytes, bytearray)):
                return [qname.decode(errors='ignore').rstrip('.')]
            return [str(qname).rstrip('.')]
        except Exception:
            return []

    def _dns_query_types(self, raw) -> list:
        layer = self._get_layer(raw, DNS)
        if layer is None:
            return []
        try:
            qd = getattr(layer, 'qd', None)
            qtype = getattr(qd, 'qtype', None) if qd is not None else None
            return [] if qtype is None else [int(qtype)]
        except Exception:
            return []

    def _dhcp_message_type(self, raw):
        try:
            if raw is None or not raw.haslayer(DHCP):
                return None
            for option in getattr(raw[DHCP], 'options', []):
                if isinstance(option, tuple) and option and option[0] == 'message-type':
                    return int(option[1])
        except Exception:
            return None
        return None

    def _raw_payload_bytes(self, raw) -> bytes:
        if raw is None:
            return b''
        try:
            if raw.haslayer(TCP):
                return bytes(getattr(raw[TCP], 'payload', b''))
            if raw.haslayer(UDP):
                return bytes(getattr(raw[UDP], 'payload', b''))
            if raw.haslayer(IP):
                return bytes(getattr(raw[IP], 'payload', b''))
            if raw.haslayer(IPv6):
                return bytes(getattr(raw[IPv6], 'payload', b''))
        except Exception:
            return b''
        return b''

    def _http_first_line(self, record: PacketRecord) -> str:
        raw = getattr(record, 'raw', None)
        payload = self._raw_payload_bytes(raw)
        if not payload:
            return ''
        return payload.split(b'\r\n', 1)[0].decode(errors='ignore').strip()

    def _http_payload_kind(self, record: PacketRecord) -> str:
        metadata = getattr(record, 'metadata', {}) or {}
        kind = str(metadata.get('http_kind', '') or '').strip().lower()
        if kind in {'request', 'response'}:
            return kind
        line = self._http_first_line(record)
        if not line:
            return ''
        if line.startswith('HTTP/'):
            return 'response'
        parts = line.split(' ', 2)
        if len(parts) < 2:
            return ''
        method = str(parts[0] or '').upper()
        target = str(parts[1] or '').strip()
        version = str(parts[2] or '').upper() if len(parts) >= 3 else ''
        if method in self.HTTP_REQUEST_METHODS and target and version.startswith('HTTP/'):
            return 'request'
        return ''

    def _http_request_method(self, record: PacketRecord) -> str:
        line = self._http_first_line(record)
        if not line:
            return ''
        parts = line.split(' ', 2)
        if len(parts) < 2:
            return ''
        method = str(parts[0] or '').upper()
        target = str(parts[1] or '').strip()
        version = str(parts[2] or '').upper() if len(parts) >= 3 else ''
        if method in self.HTTP_REQUEST_METHODS and target and version.startswith('HTTP/'):
            return method
        return ''

    def _http_host(self, record: PacketRecord) -> str:
        raw = getattr(record, 'raw', None)
        payload = self._raw_payload_bytes(raw)
        try:
            header_blob = payload.split(b'\r\n\r\n', 1)[0].decode(errors='ignore')
        except Exception:
            return ''
        for line in header_blob.splitlines()[1:]:
            if ':' not in line:
                continue
            name, value = line.split(':', 1)
            if name.strip().lower() == 'host':
                return value.strip()
        return ''

    def _tls_records(self, record: PacketRecord, raw) -> list:
        metadata = getattr(record, 'metadata', {}) or {}
        cached = metadata.get('tls_summary', None)
        if isinstance(cached, list) and cached:
            return cached

        payload = self._raw_payload_bytes(raw)
        if len(payload) < 5:
            return []

        summaries = []
        cursor = 0
        while cursor + 5 <= len(payload):
            content_type = int(payload[cursor])
            version = int.from_bytes(payload[cursor + 1:cursor + 3], 'big')
            record_len = int.from_bytes(payload[cursor + 3:cursor + 5], 'big')
            if content_type not in {20, 21, 22, 23} or version not in {0x0301, 0x0302, 0x0303, 0x0304}:
                cursor += 1
                continue
            body_start = cursor + 5
            body_end = min(len(payload), body_start + record_len)
            body = payload[body_start:body_end]
            summary = {'content_type': content_type, 'handshake_types': []}
            if content_type == 22:
                hs_pos = 0
                while hs_pos + 4 <= len(body):
                    handshake_type = int(body[hs_pos])
                    handshake_len = int.from_bytes(body[hs_pos + 1:hs_pos + 4], 'big')
                    total = 4 + handshake_len
                    if hs_pos + total > len(body):
                        break
                    summary['handshake_types'].append(handshake_type)
                    hs_pos += total
            summaries.append(summary)
            cursor = body_end if body_end > cursor else cursor + 1
        return summaries

    def _tls_handshake_types(self, record: PacketRecord, raw) -> list:
        values = []
        for item in self._tls_records(record, raw):
            for hs_type in item.get('handshake_types', []):
                values.append(int(hs_type))
        return values

    def _tls_sni(self, record: PacketRecord, raw) -> str:
        info = str(getattr(record, 'info', '') or '')
        match = re.search(r'SNI=([^\)]+)', info)
        if match:
            return match.group(1).strip()

        payload = self._raw_payload_bytes(raw)
        if len(payload) < 5:
            return ''
        cursor = 0
        while cursor + 5 <= len(payload):
            content_type = int(payload[cursor])
            version = int.from_bytes(payload[cursor + 1:cursor + 3], 'big')
            record_len = int.from_bytes(payload[cursor + 3:cursor + 5], 'big')
            if content_type not in {20, 21, 22, 23} or version not in {0x0301, 0x0302, 0x0303, 0x0304}:
                cursor += 1
                continue
            body_start = cursor + 5
            body_end = min(len(payload), body_start + record_len)
            if content_type != 22 or body_end - body_start < 4:
                cursor = body_end
                continue
            hs_pos = body_start
            while hs_pos + 4 <= body_end:
                hs_type = int(payload[hs_pos])
                hs_len = int.from_bytes(payload[hs_pos + 1:hs_pos + 4], 'big')
                body = payload[hs_pos + 4:hs_pos + 4 + hs_len]
                if hs_type != 1 or len(body) < 34:
                    break
                pos = 34
                if pos >= len(body):
                    break
                sid_len = int(body[pos]); pos += 1 + sid_len
                if pos + 2 > len(body):
                    break
                cs_len = int.from_bytes(body[pos:pos + 2], 'big'); pos += 2 + cs_len
                if pos >= len(body):
                    break
                comp_len = int(body[pos]); pos += 1 + comp_len
                if pos + 2 > len(body):
                    break
                ext_len = int.from_bytes(body[pos:pos + 2], 'big'); pos += 2
                ext_end = min(len(body), pos + ext_len)
                while pos + 4 <= ext_end:
                    ext_type = int.from_bytes(body[pos:pos + 2], 'big')
                    ext_size = int.from_bytes(body[pos + 2:pos + 4], 'big')
                    data = body[pos + 4:pos + 4 + ext_size]
                    if ext_type == 0 and len(data) >= 5:
                        list_len = int.from_bytes(data[0:2], 'big')
                        entry_pos = 2
                        list_end = min(len(data), 2 + list_len)
                        while entry_pos + 3 <= list_end:
                            name_type = int(data[entry_pos])
                            name_len = int.from_bytes(data[entry_pos + 1:entry_pos + 3], 'big')
                            name_start = entry_pos + 3
                            name_end = min(list_end, name_start + name_len)
                            if name_type == 0 and name_end > name_start:
                                return data[name_start:name_end].decode(errors='ignore')
                            entry_pos = name_end
                    pos += 4 + ext_size
                break
            cursor = body_end
        return ''

    def _ftp_command(self, record: PacketRecord) -> str:
        metadata = getattr(record, 'metadata', {}) or {}
        ftp = metadata.get('ftp', None)
        if isinstance(ftp, dict) and str(ftp.get('kind', '') or '') == 'request':
            return str(ftp.get('command', '') or '').upper()
        line = self._raw_payload_bytes(getattr(record, 'raw', None)).split(b'\r\n', 1)[0].decode(errors='ignore').strip()
        return line.split(' ', 1)[0].upper() if line else ''

    def _smtp_command(self, record: PacketRecord) -> str:
        metadata = getattr(record, 'metadata', {}) or {}
        if str(metadata.get('smtp_kind', '') or '') != 'command':
            return ''
        line = self._raw_payload_bytes(getattr(record, 'raw', None)).split(b'\r\n', 1)[0].decode(errors='ignore').strip()
        return line.split(' ', 1)[0].upper() if line else ''

    def _smb2_command(self, raw, record: PacketRecord):
        try:
            if raw is not None and raw.haslayer('SMB2_Header'):
                header = raw['SMB2_Header']
                value = getattr(header, 'Command', None)
                if value is not None:
                    return int(value)
        except Exception:
            pass

        info = str(getattr(record, 'info', '') or '')
        names = {
            'NEGOTIATE': 0,
            'SESSION_SETUP': 1,
            'LOGOFF': 2,
            'TREE_CONNECT': 3,
            'TREE_DISCONNECT': 4,
            'CREATE': 5,
            'CLOSE': 6,
            'FLUSH': 7,
            'READ': 8,
            'WRITE': 9,
            'LOCK': 10,
            'IOCTL': 11,
            'CANCEL': 12,
            'ECHO': 13,
            'QUERY_DIRECTORY': 14,
            'CHANGE_NOTIFY': 15,
            'QUERY_INFO': 16,
            'SET_INFO': 17,
            'OPLOCK_BREAK': 18,
        }
        upper = info.upper().replace(' ', '_')
        for name, value in names.items():
            if name in upper:
                return value
        return None

    def _smb2_filenames(self, record: PacketRecord) -> list:
        info = str(getattr(record, 'info', '') or '')
        matches = re.findall(r'([A-Za-z]:\\[^,]+|\\\\[^,]+|/[^,\s]+|[A-Za-z0-9_.-]+\.[A-Za-z0-9]{1,8})', info)
        values = []
        for match in matches:
            cleaned = match.strip(' ,:;()[]{}"\'')
            if cleaned and cleaned not in values:
                values.append(cleaned)
        return values

    def _as_number(self, value):
        if isinstance(value, bool):
            return int(value)
        if isinstance(value, (int, float)):
            return value
        text = str(value).strip()
        if not text:
            return None
        try:
            if re.fullmatch(r'0x[0-9a-fA-F]+', text):
                return int(text, 16)
            if re.fullmatch(r'-?\d+', text):
                return int(text)
            if re.fullmatch(r'-?\d+\.\d+', text):
                return float(text)
        except Exception:
            return None
        return None

    def _layer_lows(self, record: PacketRecord) -> set:
        layers_raw = getattr(record, 'layers', [])
        tokens = set()

        if isinstance(layers_raw, str):
            chunks = [layers_raw]
        elif isinstance(layers_raw, (list, tuple, set)):
            chunks = [str(item) for item in layers_raw if item is not None]
        else:
            chunks = [str(layers_raw)] if layers_raw is not None else []

        for chunk in chunks:
            text = str(chunk).strip().lower()
            if not text:
                continue
            tokens.add(text)
            for part in re.split(r'[:;,\s]+', text):
                part = part.strip()
                if part:
                    tokens.add(part)

        # Alias common layer spellings into filter-friendly names.
        if 'dot1q' in tokens or '802.1q' in tokens:
            tokens.add('vlan')
        if 'ether' in tokens or 'ethernet' in tokens:
            tokens.add('eth')
        if any(tok.startswith('icmpv6') for tok in list(tokens)):
            tokens.add('icmpv6')
            tokens.add('ipv6')
        if any(tok.startswith('icmp') and not tok.startswith('icmpv6') for tok in list(tokens)):
            tokens.add('icmp')
        if 'ip' in tokens or 'ipv4' in tokens:
            tokens.add('ip')
            tokens.add('ipv4')
        if 'ipv6exthdrhopbyhop' in tokens or 'ipv6exthdrfragment' in tokens:
            tokens.add('ipv6')

        return tokens

    def _normalize_token(self, token: str) -> str:
        text = str(token or '').strip()
        if len(text) >= 2 and text[0] == text[-1] == '`':
            text = text[1:-1].strip()
        if len(text) >= 2 and text[0] == text[-1] and text[0] in {'"', "'"}:
            text = text[1:-1].strip()
        return text

    def _normalize_expression(self, expression: str) -> str:
        text = str(expression or '')
        # Remove common invisible characters when users copy/paste from docs/web.
        text = re.sub(r'[\u200b\u200c\u200d\ufeff\u200e\u200f]', '', text)
        text = text.strip()
        if len(text) >= 2 and text[0] == text[-1] == '`':
            text = text[1:-1].strip()
        return text

    def _protocol_only_candidate(self, text: str) -> str:
        if not text:
            return ''
        # Not protocol-only if expression contains operators, spaces, or parentheses.
        if re.search(r'\s|[()<>!=&|]', text):
            return ''
        token = self._normalize_token(text)
        token = token.strip(',:;')
        return token.lower()

    def _match_legacy_atom(self, record: PacketRecord, atom: str) -> bool:
        atom = atom.strip()
        low = atom.lower()
        if not atom:
            return True

        checks = {
            'ip.addr==': lambda v: v in {record.src, record.dst},
            'ip.src==': lambda v: record.src == v,
            'ip.dst==': lambda v: record.dst == v,
            'tcp.port==': lambda v: self._port_match(record, v, TCP),
            'udp.port==': lambda v: self._port_match(record, v, UDP),
            'frame.number==': lambda v: str(record.number) == v,
            'frame.len==': lambda v: str(record.length) == v,
            'contains==': lambda v: self._contains(record, v),
        }
        for prefix, func in checks.items():
            if low.startswith(prefix):
                return func(atom.split('==', 1)[1].strip().strip('"\''))

        if low.startswith('port=='):
            return self._port_match(record, atom.split('==', 1)[1].strip(), None)

        if atom.startswith('"') and atom.endswith('"'):
            atom = atom[1:-1]
            low = atom.lower()

        if low in self.PROTOCOL_ALIASES:
            return self._protocol_present(record, low)
        return self._contains(record, low)

    def _port_match(self, record: PacketRecord, value, layer_type) -> bool:
        try:
            port = int(value)
        except Exception:
            return False
        values = self._ports(record, layer_type)
        return any(int(v) == port for v in values)

    def _contains(self, record: PacketRecord, value: str) -> bool:
        haystack = ' '.join([
            str(record.number),
            f'{record.relative_time:.6f}',
            str(record.src or ''),
            str(record.dst or ''),
            str(record.protocol or ''),
            str(record.length),
            str(record.info or ''),
            ' '.join(str(layer) for layer in (record.layers or [])),
            str(record.stream_hint or ''),
        ]).lower()
        return str(value).lower() in haystack
