import re
from core.models import PacketRecord


TOKEN_RE = re.compile(r'\(|\)|\band\b|\bor\b|\bnot\b|[^()\s]+', re.IGNORECASE)


class DisplayFilter:
    def matches(self, record: PacketRecord, expression: str) -> bool:
        text = (expression or '').strip()
        if not text:
            return True
        try:
            self.tokens = TOKEN_RE.findall(text)
            self.pos = 0
            result = self._parse_or(record)
            return result and self.pos == len(self.tokens)
        except Exception:
            return self._match_atom(record, text)

    def _parse_or(self, record):
        result = self._parse_and(record)
        while self._peek_lower() == 'or':
            self.pos += 1
            result = result or self._parse_and(record)
        return result

    def _parse_and(self, record):
        result = self._parse_not(record)
        while self._peek_lower() == 'and':
            self.pos += 1
            result = result and self._parse_not(record)
        return result

    def _parse_not(self, record):
        if self._peek_lower() == 'not':
            self.pos += 1
            return not self._parse_not(record)
        return self._parse_primary(record)

    def _parse_primary(self, record):
        token = self._peek()
        if token == '(':
            self.pos += 1
            value = self._parse_or(record)
            if self._peek() == ')':
                self.pos += 1
            return value
        self.pos += 1
        return self._match_atom(record, token)

    def _peek(self):
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def _peek_lower(self):
        token = self._peek()
        return token.lower() if token else None

    def _match_atom(self, record: PacketRecord, atom: str) -> bool:
        atom = atom.strip()
        low = atom.lower()
        if not atom:
            return True

        aliases = {
            'tcp', 'udp', 'dns', 'mdns', 'arp', 'icmp', 'icmpv6', 'igmp', 'tls', 'quic', 'http', 'dhcp', 'ip', 'ipv6', 'eth'
        }
        if low in aliases:
            proto_low = str(record.protocol or '').lower()
            layer_lows = {layer.lower() for layer in record.layers}
            if low == 'tls':
                return proto_low.startswith('tls') or 'tls' in layer_lows
            if low == 'igmp':
                return proto_low.startswith('igmp') or 'igmp' in layer_lows
            return proto_low == low or low in layer_lows

        checks = {
            'ip.addr==': lambda v: v in {record.src, record.dst},
            'ip.src==': lambda v: record.src == v,
            'ip.dst==': lambda v: record.dst == v,
            'tcp.port==': lambda v: 'tcp' in {layer.lower() for layer in record.layers} and self._port_match(record, v),
            'udp.port==': lambda v: 'udp' in {layer.lower() for layer in record.layers} and self._port_match(record, v),
            'frame.number==': lambda v: str(record.number) == v,
            'frame.len==': lambda v: str(record.length) == v,
            'contains==': lambda v: self._contains(record, v),
        }
        for prefix, func in checks.items():
            if low.startswith(prefix):
                return func(atom.split('==', 1)[1].strip().strip('"\''))

        if low.startswith('port=='):
            return self._port_match(record, atom.split('==', 1)[1].strip())

        if atom.startswith('"') and atom.endswith('"'):
            atom = atom[1:-1]
            low = atom.lower()

        return self._contains(record, low)

    def _port_match(self, record, value):
        try:
            port = int(value)
        except Exception:
            return False
        return record.sport == port or record.dport == port

    def _contains(self, record, value):
        haystack = ' '.join([
            str(record.number),
            f'{record.relative_time:.6f}',
            record.src,
            record.dst,
            record.protocol,
            str(record.length),
            record.info,
            ' '.join(record.layers),
            record.stream_hint,
        ]).lower()
        return value.lower() in haystack
