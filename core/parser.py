from __future__ import annotations
from collections import Counter
from scapy.all import ARP, DNS, Ether, ICMP, IP, IPv6, TCP, UDP
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.inet6 import ICMPv6EchoRequest, ICMPv6EchoReply, ICMPv6ND_NS, ICMPv6ND_NA
from scapy.layers.tls.all import TLS, TLSClientHello  # type: ignore
from scapy.layers.quic import QUIC  # type: ignore

from core.models import PacketRecord


class PacketParser:
    MAX_CONTIGUOUS_RANGES = 101

    def __init__(self):
        self.first_epoch = None
        self.last_epoch_captured = None
        self.last_epoch_displayed = None
        self.conversations = Counter()
        self.transport_stream_state = {}
        self.layer_stream_maps = {
            'ethernet': {},
            'ipv4': {},
            'ipv6': {},
            'tcp': {},
            'udp': {},
        }
        self.layer_stream_next = {
            'ethernet': 0,
            'ipv4': 0,
            'ipv6': 0,
            'tcp': 0,
            'udp': 0,
        }

    def parse(self, packet, number: int, iface: str = '') -> PacketRecord:
        epoch_time = float(getattr(packet, 'time', 0.0))
        if self.first_epoch is None:
            self.first_epoch = epoch_time
        relative_time = max(0.0, epoch_time - self.first_epoch)

        if self.last_epoch_captured is None:
            frame_delta = 0.0
        else:
            frame_delta = max(0.0, epoch_time - self.last_epoch_captured)

        if self.last_epoch_displayed is None:
            frame_delta_displayed = 0.0
        else:
            frame_delta_displayed = max(0.0, epoch_time - self.last_epoch_displayed)

        self.last_epoch_captured = epoch_time
        self.last_epoch_displayed = epoch_time

        src, dst = self._extract_endpoints(packet)
        sport, dport = self._extract_ports(packet)
        protocol = self._guess_protocol(packet)
        layers = [layer.__name__.upper() for layer in packet.layers()]
        info = self._build_info(packet, protocol)
        length = len(packet)

        stream_hint = ''
        if sport is not None or dport is not None:
            stream_hint = f'{src}:{sport or "-"} -> {dst}:{dport or "-"}'
            self.conversations[(src, sport, dst, dport, protocol)] += 1

        metadata = {
            'is_ipv6': packet.haslayer(IPv6),
            'has_ip': packet.haslayer(IP) or packet.haslayer(IPv6),
            'eth_type': self._safe_attr(packet[Ether], 'type') if packet.haslayer(Ether) else None,
            'frame_number': int(number),
            'frame_time_delta': frame_delta,
            'frame_time_delta_displayed': frame_delta_displayed,
        }
        if packet.haslayer(IP):
            metadata['ttl'] = self._safe_attr(packet[IP], 'ttl')
        if packet.haslayer(IPv6):
            metadata['hlim'] = self._safe_attr(packet[IPv6], 'hlim')
        if packet.haslayer(TCP):
            metadata['tcp_flags'] = str(packet[TCP].flags)
        if packet.haslayer(DNS):
            metadata['dns_qr'] = self._safe_attr(packet[DNS], 'qr')

        self._populate_stream_indices(packet, metadata)

        self._update_transport_stream_metadata(packet, metadata, epoch_time)

        return PacketRecord(
            number=number,
            epoch_time=epoch_time,
            relative_time=relative_time,
            length=length,
            src=src,
            dst=dst,
            protocol=protocol,
            info=info,
            layers=layers,
            sport=sport,
            dport=dport,
            stream_hint=stream_hint,
            metadata=metadata,
            raw=packet,
            iface=iface,
        )

    def _canonical_transport_key(self, src: str, sport: int, dst: str, dport: int, proto: str):
        left = (str(src), int(sport))
        right = (str(dst), int(dport))
        if left <= right:
            return (proto, left, right)
        return (proto, right, left)

    def _tcp_seq_cmp(self, a: int, b: int) -> int:
        """Compare 32-bit TCP sequence values with wrap-around awareness."""
        return ((int(a) - int(b) + 0x80000000) & 0xFFFFFFFF) - 0x80000000

    def _tcp_seq_leq(self, a: int, b: int) -> bool:
        return self._tcp_seq_cmp(a, b) <= 0

    def _tcp_seq_geq(self, a: int, b: int) -> bool:
        return self._tcp_seq_cmp(a, b) >= 0

    def _tcp_seq_gt(self, a: int, b: int) -> bool:
        return self._tcp_seq_cmp(a, b) > 0

    def _track_tcp_contiguity(self, seq: int, nextseq: int, contig_state: dict):
        """Track contiguous TCP data ranges similar to Wireshark logic."""
        if self._tcp_seq_cmp(nextseq, seq) <= 0:
            return

        ranges = contig_state['ranges']
        crlen = len(ranges)
        array_growth = 0
        dstindex = 0
        extension_mode = False

        while (
            dstindex < crlen
            and not extension_mode
            and self._tcp_seq_geq(seq, ranges[dstindex][0])
        ):
            if self._tcp_seq_leq(seq, ranges[dstindex][1]):
                if self._tcp_seq_gt(nextseq, ranges[dstindex][1]):
                    ranges[dstindex][1] = nextseq
                    extension_mode = True
                    break
                # Fully contained retransmission/overlap.
                return
            dstindex += 1

        if not extension_mode:
            if crlen >= self.MAX_CONTIGUOUS_RANGES:
                return
            array_growth = 1
            ranges.insert(dstindex, [seq, nextseq])

        to_shrink = 0
        next_crlen = crlen if extension_mode else (crlen + 1)
        j = dstindex + 1

        while j < next_crlen and self._tcp_seq_geq(nextseq, ranges[j][0]):
            if self._tcp_seq_gt(ranges[j][1], nextseq):
                ranges[dstindex][1] = ranges[j][1]
            to_shrink += 1
            j += 1

        array_growth -= to_shrink

        if to_shrink > 0:
            del ranges[dstindex + 1:dstindex + 1 + to_shrink]

        # Keep list length aligned with the modeled growth.
        expected_len = crlen + array_growth
        if expected_len < len(ranges):
            del ranges[expected_len:]

    def _get_or_create_bidirectional_index(self, layer_name: str, forward_key: tuple, reverse_key: tuple) -> int:
        stream_map = self.layer_stream_maps[layer_name]
        if forward_key in stream_map:
            return stream_map[forward_key]
        if reverse_key in stream_map:
            return stream_map[reverse_key]

        idx = self.layer_stream_next[layer_name]
        self.layer_stream_next[layer_name] += 1
        stream_map[forward_key] = idx
        return idx

    def _populate_stream_indices(self, packet, metadata: dict):
        metadata['ether_stream_index'] = -1
        metadata['ip_stream_index'] = -1
        metadata['ipv6_stream_index'] = -1
        metadata['tcp_stream_index'] = -1
        metadata['udp_stream_index'] = -1

        if packet.haslayer(Ether):
            src = str(packet[Ether].src).lower()
            dst = str(packet[Ether].dst).lower()
            metadata['ether_stream_index'] = self._get_or_create_bidirectional_index(
                'ethernet',
                (src, dst),
                (dst, src),
            )

        if packet.haslayer(IP):
            src = str(packet[IP].src)
            dst = str(packet[IP].dst)
            metadata['ip_stream_index'] = self._get_or_create_bidirectional_index(
                'ipv4',
                (src, dst),
                (dst, src),
            )

        if packet.haslayer(IPv6):
            src = str(packet[IPv6].src)
            dst = str(packet[IPv6].dst)
            metadata['ipv6_stream_index'] = self._get_or_create_bidirectional_index(
                'ipv6',
                (src, dst),
                (dst, src),
            )

        if packet.haslayer(TCP):
            if packet.haslayer(IP):
                src = str(packet[IP].src)
                dst = str(packet[IP].dst)
            elif packet.haslayer(IPv6):
                src = str(packet[IPv6].src)
                dst = str(packet[IPv6].dst)
            else:
                src = dst = ''

            if src and dst:
                sport = int(packet[TCP].sport)
                dport = int(packet[TCP].dport)
                metadata['tcp_stream_index'] = self._get_or_create_bidirectional_index(
                    'tcp',
                    (src, sport, dst, dport),
                    (dst, dport, src, sport),
                )

        if packet.haslayer(UDP):
            if packet.haslayer(IP):
                src = str(packet[IP].src)
                dst = str(packet[IP].dst)
            elif packet.haslayer(IPv6):
                src = str(packet[IPv6].src)
                dst = str(packet[IPv6].dst)
            else:
                src = dst = ''

            if src and dst:
                sport = int(packet[UDP].sport)
                dport = int(packet[UDP].dport)
                metadata['udp_stream_index'] = self._get_or_create_bidirectional_index(
                    'udp',
                    (src, sport, dst, dport),
                    (dst, dport, src, sport),
                )

    def _update_transport_stream_metadata(self, packet, metadata: dict, epoch_time: float):
        if packet.haslayer(TCP):
            proto = 'TCP'
            layer = packet[TCP]
        elif packet.haslayer(UDP):
            proto = 'UDP'
            layer = packet[UDP]
        else:
            return

        if packet.haslayer(IP):
            src = str(packet[IP].src)
            dst = str(packet[IP].dst)
        elif packet.haslayer(IPv6):
            src = str(packet[IPv6].src)
            dst = str(packet[IPv6].dst)
        else:
            return

        sport = int(getattr(layer, 'sport', 0) or 0)
        dport = int(getattr(layer, 'dport', 0) or 0)
        stream_key = self._canonical_transport_key(src, sport, dst, dport, proto)

        state = self.transport_stream_state.get(stream_key)
        if state is None:
            if sport <= 1024 < dport:
                client_endpoint = (dst, dport)
            elif dport <= 1024 < sport:
                client_endpoint = (src, sport)
            else:
                client_endpoint = (src, sport)

            state = {
                'count': 0,
                'first_epoch': epoch_time,
                'last_epoch': None,
                'dir_base_seq': {},
                'completeness_flags': 0,
                'client_packets': 0,
                'server_packets': 0,
                'client_endpoint': client_endpoint,
                'packets_by_dir': {},
                'contig': {
                    'client': {'ranges': []},
                    'server': {'ranges': []},
                },
            }
            self.transport_stream_state[stream_key] = state

        state['count'] += 1
        stream_packet_number = int(state['count'])
        metadata[f'{proto.lower()}_stream_packet_number'] = state['count']
        metadata[f'{proto.lower()}_time_since_first'] = max(0.0, epoch_time - state['first_epoch'])

        if state['last_epoch'] is None:
            metadata[f'{proto.lower()}_time_since_prev'] = 0.0
        else:
            metadata[f'{proto.lower()}_time_since_prev'] = max(0.0, epoch_time - state['last_epoch'])
        state['last_epoch'] = epoch_time


        # --- Wireshark-style contiguous streams logic ---
        if proto == 'TCP':
            seq = int(getattr(layer, 'seq', 0) or 0)
            payload_len = len(bytes(getattr(layer, 'payload', b'')))
            seg_len = payload_len
            nextseq = (seq + seg_len) & 0xFFFFFFFF
            src_is_client = (src, sport) == state.get('client_endpoint')
            active_contig = state['contig']['client' if src_is_client else 'server']

            if seg_len > 0:
                self._track_tcp_contiguity(seq, nextseq, active_contig)

            client_ranges = state['contig']['client']['ranges']
            server_ranges = state['contig']['server']['ranges']
            metadata['tcp_client_contiguous_streams'] = int(len(client_ranges))
            metadata['tcp_server_contiguous_streams'] = int(len(server_ranges))
        else:
            # For UDP, fallback to old logic
            src_is_client = (src, sport) == state.get('client_endpoint')
            if src_is_client:
                state['client_packets'] += 1
            else:
                state['server_packets'] += 1
            metadata[f'{proto.lower()}_client_contiguous_streams'] = int(state['client_packets'])
            metadata[f'{proto.lower()}_server_contiguous_streams'] = int(state['server_packets'])

        if proto != 'TCP':
            return

        seq = int(getattr(layer, 'seq', 0) or 0)
        ack = int(getattr(layer, 'ack', 0) or 0)

        dir_key = (src, sport, dst, dport)
        rev_key = (dst, dport, src, sport)

        if dir_key not in state['dir_base_seq']:
            state['dir_base_seq'][dir_key] = seq
        relative_seq = ((seq - state['dir_base_seq'][dir_key]) & 0xFFFFFFFF) + 1

        if ack > 0:
            ack_base = state['dir_base_seq'].get(rev_key)
            if ack_base is None:
                # First packet might only carry ACK for reverse direction before reverse data is seen.
                state['dir_base_seq'][rev_key] = ack
                ack_base = ack
            relative_ack = ((ack - ack_base) & 0xFFFFFFFF) + 1
        else:
            relative_ack = 0

        payload_len = len(bytes(getattr(layer, 'payload', b'')))
        syn_len = 1 if (int(getattr(layer, 'flags', 0) or 0) & 0x02) else 0
        fin_len = 1 if (int(getattr(layer, 'flags', 0) or 0) & 0x01) else 0
        seq_advance = payload_len + syn_len + fin_len
        end_seq_raw = (seq + seq_advance) & 0xFFFFFFFF

        completeness_flags = int(state.get('completeness_flags', 0) or 0)
        if int(getattr(layer, 'flags', 0) or 0) & 0x04:  # RST
            completeness_flags |= 32
        if int(getattr(layer, 'flags', 0) or 0) & 0x01:  # FIN
            completeness_flags |= 16
        if payload_len > 0:
            completeness_flags |= 8
        if int(getattr(layer, 'flags', 0) or 0) & 0x10:  # ACK
            completeness_flags |= 4
        if (int(getattr(layer, 'flags', 0) or 0) & 0x12) == 0x12:  # SYN-ACK
            completeness_flags |= 2
        if (int(getattr(layer, 'flags', 0) or 0) & 0x12) == 0x02:  # SYN without ACK
            completeness_flags |= 1
        state['completeness_flags'] = completeness_flags

        metadata['tcp_relative_seq'] = relative_seq
        metadata['tcp_relative_ack'] = relative_ack
        metadata['tcp_next_seq'] = relative_seq + payload_len
        metadata['tcp_completeness_flags'] = completeness_flags

        # ---- SEQ/ACK analysis (Wireshark-like conditions) ----
        dir_packets = state['packets_by_dir'].setdefault(dir_key, [])
        rev_packets = state['packets_by_dir'].setdefault(rev_key, [])

        ack_frame_number = None
        ack_rtt_ms = None
        bytes_in_flight = None
        bytes_since_last_psh = None
        tcp_flags = int(getattr(layer, 'flags', 0) or 0)
        has_ack_flag = bool(tcp_flags & 0x10)

        # Group 1: ACK analysis (ACK->segment mapping + RTT).
        if has_ack_flag and ack > 0 and rev_packets:
            newly_acked = []
            for seg in rev_packets:
                if seg['payload_len'] <= 0 or seg['acked']:
                    continue
                if self._tcp_seq_leq(seg['end_seq_raw'], ack):
                    newly_acked.append(seg)

            if newly_acked:
                candidate = None
                for seg in reversed(newly_acked):
                    if seg['end_seq_raw'] == ack:
                        candidate = seg
                        break

                if candidate is not None:
                    ack_frame_number = int(candidate['frame_number'])
                    ack_rtt_ms = max(0.0, (epoch_time - float(candidate['epoch_time'])) * 1000.0)

                for seg in newly_acked:
                    seg['acked'] = True

        # Group 2: Data-flight analysis (for packets carrying payload).
        if payload_len > 0 and stream_packet_number > 1:
            outstanding_same_dir = [
                seg for seg in dir_packets
                if seg['payload_len'] > 0 and not seg['acked']
            ]
            bytes_in_flight = int(sum(int(seg['payload_len']) for seg in outstanding_same_dir) + payload_len)

            sent_bytes = int(payload_len)
            for seg in reversed(dir_packets):
                if seg['payload_len'] > 0:
                    sent_bytes += int(seg['payload_len'])
                if seg['psh']:
                    break
            bytes_since_last_psh = int(sent_bytes)

        if ack_frame_number is not None:
            metadata['tcp_ack_frame_number'] = int(ack_frame_number)
        if ack_rtt_ms is not None:
            metadata['tcp_ack_rtt_ms'] = float(ack_rtt_ms)
        if bytes_in_flight is not None:
            metadata['tcp_bytes_in_flight'] = int(bytes_in_flight)
        if bytes_since_last_psh is not None:
            metadata['tcp_bytes_since_last_psh'] = int(bytes_since_last_psh)

        dir_packets.append({
            'frame_number': int(metadata.get('frame_number', 0) or 0),
            'epoch_time': float(epoch_time),
            'seq_raw': int(seq),
            'end_seq_raw': int(end_seq_raw),
            'payload_len': int(payload_len),
            'psh': bool(int(getattr(layer, 'flags', 0) or 0) & 0x08),
            'acked': False,
        })

    def _safe_attr(self, obj, name, default=None):
        try:
            return getattr(obj, name, default)
        except Exception:
            return default

    def _extract_endpoints(self, packet):
        if packet.haslayer(ARP):
            return packet[ARP].psrc, packet[ARP].pdst
        if packet.haslayer(IP):
            return str(packet[IP].src), str(packet[IP].dst)
        if packet.haslayer(IPv6):
            return str(packet[IPv6].src), str(packet[IPv6].dst)
        if packet.haslayer(Ether):
            return str(packet[Ether].src), str(packet[Ether].dst)
        return 'N/A', 'N/A'

    def _extract_ports(self, packet):
        if packet.haslayer(TCP):
            return int(packet[TCP].sport), int(packet[TCP].dport)
        if packet.haslayer(UDP):
            return int(packet[UDP].sport), int(packet[UDP].dport)
        return None, None

    def _guess_protocol(self, packet):
        if packet.haslayer(ARP):
            return 'ARP'
        if packet.haslayer(DHCP) or packet.haslayer(BOOTP):
            return 'DHCP'
        if packet.haslayer(DNS):
            qname = self._dns_qname(packet)
            if qname.endswith('.local'):
                return 'MDNS'
            return 'DNS'
        if packet.haslayer(HTTPResponse) or packet.haslayer(HTTPRequest):
            return 'HTTP'
        if packet.haslayer(TLSClientHello) or packet.haslayer(TLS):
            return 'TLS'
        if packet.haslayer(QUIC):
            return 'QUIC'
        if packet.haslayer(ICMPv6EchoRequest) or packet.haslayer(ICMPv6EchoReply) or packet.haslayer(ICMPv6ND_NS) or packet.haslayer(ICMPv6ND_NA):
            return 'ICMPV6'
        if packet.haslayer(ICMP):
            return 'ICMP'
        if packet.haslayer(TCP):
            return 'TCP'
        if packet.haslayer(UDP):
            return 'UDP'
        if packet.haslayer(IPv6):
            return 'IPV6'
        if packet.haslayer(IP):
            return 'IP'
        if packet.haslayer(Ether):
            return 'ETH'
        return 'OTHER'

    def _dns_qname(self, packet) -> str:
        try:
            qname = packet[DNS].qd.qname
            if isinstance(qname, bytes):
                return qname.decode(errors='ignore').rstrip('.')
            return str(qname).rstrip('.')
        except Exception:
            return ''

    def _build_info(self, packet, protocol: str) -> str:
        try:
            if protocol == 'ARP':
                arp = packet[ARP]
                if arp.op == 1:
                    return f'Who has {arp.pdst}? Tell {arp.psrc}'
                elif arp.op == 2:
                    return f'{arp.psrc} is at {arp.hwsrc}'
                return f'ARP {arp.op}'
            if protocol in {'DNS', 'MDNS'}:
                dns = packet[DNS]
                qname = self._dns_qname(packet)
                if getattr(dns, 'qr', 0) == 0:
                    return f'Standard query 0x{getattr(dns, "id", 0):04x} {qname or "(unknown)"}'
                return f'Standard query response 0x{getattr(dns, "id", 0):04x} {qname or "(unknown)"}'
            if protocol == 'DHCP':
                return 'DHCP Request'  # Simplified
            if protocol == 'HTTP':
                if packet.haslayer(HTTPRequest):
                    req = packet[HTTPRequest]
                    method = self._to_text(getattr(req, 'Method', b''))
                    path = self._to_text(getattr(req, 'Path', b''))
                    return f'{method} {path}'
                if packet.haslayer(HTTPResponse):
                    resp = packet[HTTPResponse]
                    code = self._to_text(getattr(resp, 'Status_Code', b''))
                    return f'HTTP/{code}'
            if protocol == 'TLS':
                return 'Application Data'
            if protocol == 'QUIC':
                return 'QUIC'
            if protocol == 'TCP':
                tcp = packet[TCP]
                flags_str = self._tcp_flags_to_string(tcp.flags)
                seq = tcp.seq
                ack = tcp.ack
                win = tcp.window
                payload_len = len(bytes(getattr(tcp, "payload", b"")))
                return f'{tcp.sport} -> {tcp.dport} [{flags_str}] Seq={seq} Ack={ack} Win={win} Len={payload_len}'
            if protocol == 'UDP':
                udp = packet[UDP]
                payload_len = max(0, udp.len - 8)
                return f'{udp.sport} -> {udp.dport} Len={payload_len}'
            if protocol in {'ICMP', 'ICMPV6'}:
                return packet.summary()
            return packet.summary()
        except Exception:
            return packet.summary()

    def _to_text(self, value):
        if isinstance(value, bytes):
            return value.decode(errors='ignore')
        return str(value)

    def _tcp_flags_to_string(self, flags):
        flag_map = {
            'F': 'FIN',
            'S': 'SYN',
            'R': 'RST',
            'P': 'PSH',
            'A': 'ACK',
            'U': 'URG',
            'E': 'ECE',
            'C': 'CWR'
        }
        flags_str = str(flags).replace(' ', '')
        expanded = [flag_map.get(f, f) for f in flags_str if f in flag_map]
        return '/'.join(expanded) if expanded else 'None'
