from __future__ import annotations
from collections import Counter
from decimal import Decimal
from scapy.all import ARP, DNS, Ether, ICMP, IP, IPv6, TCP, UDP, bind_layers
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.inet6 import ICMPv6EchoRequest, ICMPv6EchoReply, ICMPv6ND_NS, ICMPv6ND_NA
from scapy.layers.l2 import Dot3, LLC, SNAP
from scapy.layers.tls.all import TLS, TLSClientHello  # type: ignore
from scapy.layers.quic import QUIC  # type: ignore

from core.models import PacketRecord
from core.formatters import get_mac_vendor


bind_layers(Ether, ARP, type=0x8035)


class PacketParser:
    MAX_CONTIGUOUS_RANGES = 101

    def __init__(self):
        self.first_epoch = None
        self.last_epoch_captured = None
        self.last_epoch_displayed = None
        self.conversations = Counter()
        self.transport_stream_state = {}
        self.icmp_echo_pending = {}
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

        effective_ip = self._effective_ip_layer(packet)
        effective_tcp = self._effective_tcp_layer(packet, effective_ip)
        effective_udp = self._effective_udp_layer(packet, effective_ip)

        src, dst = self._extract_endpoints(packet)
        sport, dport = self._extract_ports(packet, effective_tcp, effective_udp)
        layers = [layer.__name__.upper() for layer in packet.layers()]
        length = len(packet)

        stream_hint = ''
        if sport is not None or dport is not None:
            stream_hint = f'{src}:{sport or "-"} -> {dst}:{dport or "-"}'

        metadata = {
            'is_ipv6': packet.haslayer(IPv6),
            'has_ip': effective_ip is not None or packet.haslayer(IPv6),
            'eth_type': self._safe_attr(packet[Ether], 'type') if packet.haslayer(Ether) else None,
            'frame_number': int(number),
            'frame_time_delta': frame_delta,
            'frame_time_delta_displayed': frame_delta_displayed,
        }
        if effective_ip is not None:
            metadata['ttl'] = self._safe_attr(effective_ip, 'ttl')
        if packet.haslayer(IPv6):
            metadata['hlim'] = self._safe_attr(packet[IPv6], 'hlim')
        if effective_tcp is not None:
            metadata['tcp_flags'] = str(effective_tcp.flags)
        if packet.haslayer(DNS):
            metadata['dns_qr'] = self._safe_attr(packet[DNS], 'qr')

        self._populate_stream_indices(packet, metadata)

        self._update_transport_stream_metadata(packet, metadata, epoch_time)

        protocol = self._guess_protocol(packet, metadata)
        info = self._build_info(packet, protocol, metadata)

        if sport is not None or dport is not None:
            self.conversations[(src, sport, dst, dport, protocol)] += 1

        record = PacketRecord(
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

        self._update_icmp_echo_metadata(packet, record)

        return record

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

        effective_ip = self._effective_ip_layer(packet)
        effective_tcp = self._effective_tcp_layer(packet, effective_ip)
        effective_udp = self._effective_udp_layer(packet, effective_ip)

        if packet.haslayer(Ether):
            src = str(packet[Ether].src).lower()
            dst = str(packet[Ether].dst).lower()
            metadata['ether_stream_index'] = self._get_or_create_bidirectional_index(
                'ethernet',
                (src, dst),
                (dst, src),
            )
        elif packet.haslayer(Dot3):
            src = str(packet[Dot3].src).lower()
            dst = str(packet[Dot3].dst).lower()
            metadata['ether_stream_index'] = self._get_or_create_bidirectional_index(
                'ethernet',
                (src, dst),
                (dst, src),
            )

        if effective_ip is not None:
            src = str(effective_ip.src)
            dst = str(effective_ip.dst)
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

        if effective_tcp is not None:
            if effective_ip is not None:
                src = str(effective_ip.src)
                dst = str(effective_ip.dst)
            elif packet.haslayer(IPv6):
                src = str(packet[IPv6].src)
                dst = str(packet[IPv6].dst)
            else:
                src = dst = ''

            if src and dst:
                sport = int(effective_tcp.sport)
                dport = int(effective_tcp.dport)
                metadata['tcp_stream_index'] = self._get_or_create_bidirectional_index(
                    'tcp',
                    (src, sport, dst, dport),
                    (dst, dport, src, sport),
                )

        if effective_udp is not None:
            if effective_ip is not None:
                src = str(effective_ip.src)
                dst = str(effective_ip.dst)
            elif packet.haslayer(IPv6):
                src = str(packet[IPv6].src)
                dst = str(packet[IPv6].dst)
            else:
                src = dst = ''

            if src and dst:
                sport = int(effective_udp.sport)
                dport = int(effective_udp.dport)
                metadata['udp_stream_index'] = self._get_or_create_bidirectional_index(
                    'udp',
                    (src, sport, dst, dport),
                    (dst, dport, src, sport),
                )

    def _update_transport_stream_metadata(self, packet, metadata: dict, epoch_time: float):
        effective_ip = self._effective_ip_layer(packet)
        tcp_layer = self._effective_tcp_layer(packet, effective_ip)
        udp_layer = self._effective_udp_layer(packet, effective_ip)

        if tcp_layer is not None:
            proto = 'TCP'
            layer = tcp_layer
        elif udp_layer is not None:
            proto = 'UDP'
            layer = udp_layer
        else:
            return

        if effective_ip is not None:
            src = str(effective_ip.src)
            dst = str(effective_ip.dst)
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
            payload_len = self._tcp_payload_length(packet, layer, effective_ip)
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

        payload_len = self._tcp_payload_length(packet, layer, effective_ip)
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
        ack_ambiguous = False
        bytes_in_flight = None
        bytes_since_last_psh = None
        tcp_flags = int(getattr(layer, 'flags', 0) or 0)
        has_ack_flag = bool(tcp_flags & 0x10)
        ack_only = bool(has_ack_flag and payload_len == 0 and (tcp_flags & 0x07) == 0)
        is_retransmission = False
        is_duplicate_ack = False
        is_window_update = False
        previous_segment_not_captured = False
        duplicate_ack_count = None
        duplicate_ack_frame_number = None

        if end_seq_raw != seq:
            for seg in reversed(dir_packets):
                if int(seg.get('end_seq_raw', 0) or 0) == int(seg.get('seq_raw', 0) or 0):
                    continue
                if (
                    seg['seq_raw'] == int(seq)
                    and seg['end_seq_raw'] == int(end_seq_raw)
                    and int(seg.get('payload_len', -1) if seg.get('payload_len', None) is not None else -1) == int(payload_len)
                    and (int(seg.get('tcp_flags', 0) or 0) & 0x03) == (tcp_flags & 0x03)
                ):
                    is_retransmission = True
                    break

        if is_retransmission:
            metadata['tcp_is_retransmission'] = True

        if dir_packets:
            highest_dir_end = None
            for seg in dir_packets:
                seg_end = int(seg.get('end_seq_raw', seg.get('seq_raw', 0)) or 0)
                if highest_dir_end is None or self._tcp_seq_gt(seg_end, highest_dir_end):
                    highest_dir_end = seg_end
            if highest_dir_end is not None and self._tcp_seq_gt(seq, highest_dir_end):
                previous_segment_not_captured = True

        if ack_only and dir_packets:
            same_ack_run = []
            for seg in reversed(dir_packets):
                seg_flags = int(seg.get('tcp_flags', 0) or 0)
                if int(seg.get('payload_len', 0) or 0) != 0 or not bool(seg_flags & 0x10) or (seg_flags & 0x07) != 0:
                    break
                if int(seg.get('ack_raw', -1) or -1) != ack or int(seg.get('seq_raw', -1) or -1) != seq:
                    break
                same_ack_run.append(seg)

            if same_ack_run:
                current_window = int(getattr(layer, 'window', 0) or 0)
                last_same_dir = same_ack_run[0]
                if int(last_same_dir.get('window', -1) or -1) != current_window:
                    is_window_update = True
                else:
                    oldest_same = same_ack_run[-1]
                    duplicate_ack_frame_number = int(
                        oldest_same.get('duplicate_ack_frame_number', 0)
                        or oldest_same.get('frame_number', 0)
                        or 0
                    )
                    duplicate_ack_count = max(
                        int(seg.get('duplicate_ack_count', 0) or 0)
                        for seg in same_ack_run
                    ) + 1
                    is_duplicate_ack = True

        # Group 1: ACK analysis (ACK->segment mapping + RTT).
        if has_ack_flag and ack > 0 and rev_packets and not is_duplicate_ack:
            newly_acked = []
            for seg in rev_packets:
                if seg['payload_len'] <= 0 or seg['acked']:
                    continue
                if self._tcp_seq_leq(seg['end_seq_raw'], ack):
                    newly_acked.append(seg)

            if newly_acked:
                candidate = None
                exact_matches = [seg for seg in newly_acked if seg['end_seq_raw'] == ack]
                if exact_matches:
                    candidate = exact_matches[-1]
                    ack_ambiguous = len(exact_matches) > 1

                if candidate is not None:
                    ack_frame_number = int(candidate['frame_number'])
                    ack_delta = (Decimal(str(epoch_time)) - Decimal(str(candidate['epoch_time']))) * Decimal('1000')
                    ack_rtt_ms = max(0.0, float(ack_delta))

                for seg in newly_acked:
                    seg['acked'] = True

        # Group 2: Data-flight analysis (for packets carrying payload).
        if payload_len > 0 and stream_packet_number > 1 and not is_retransmission:
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
        if ack_ambiguous:
            metadata['tcp_ack_ambiguous'] = True
        if is_window_update:
            metadata['tcp_is_window_update'] = True
        if previous_segment_not_captured:
            metadata['tcp_previous_segment_not_captured'] = True
        if is_duplicate_ack:
            metadata['tcp_is_duplicate_ack'] = True
        if duplicate_ack_count is not None:
            metadata['tcp_duplicate_ack_count'] = int(duplicate_ack_count)
        if duplicate_ack_frame_number is not None:
            metadata['tcp_duplicate_ack_frame_number'] = int(duplicate_ack_frame_number)
        if bytes_in_flight is not None:
            metadata['tcp_bytes_in_flight'] = int(bytes_in_flight)
        if bytes_since_last_psh is not None:
            metadata['tcp_bytes_since_last_psh'] = int(bytes_since_last_psh)

        dir_packets.append({
            'frame_number': int(metadata.get('frame_number', 0) or 0),
            'epoch_time': float(epoch_time),
            'seq_raw': int(seq),
            'ack_raw': int(ack),
            'end_seq_raw': int(end_seq_raw),
            'payload_len': int(payload_len),
            'window': int(getattr(layer, 'window', 0) or 0),
            'tcp_flags': int(tcp_flags),
            'duplicate_ack_count': int(duplicate_ack_count or 0),
            'duplicate_ack_frame_number': int(duplicate_ack_frame_number or 0),
            'is_window_update': bool(is_window_update),
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
            if packet.haslayer(Ether):
                src = str(getattr(packet[Ether], 'src', '') or '')
                dst = str(getattr(packet[Ether], 'dst', '') or '')
            else:
                src = str(getattr(packet[ARP], 'hwsrc', '') or '')
                dst = str(getattr(packet[ARP], 'hwdst', '') or '')
            if not src or src == '00:00:00:00:00:00':
                src = str(getattr(packet[ARP], 'psrc', '') or 'N/A')
            if not dst or dst == '00:00:00:00:00:00':
                dst = str(getattr(packet[ARP], 'pdst', '') or 'N/A')
            return self._normalize_endpoint_text(src), self._normalize_endpoint_text(dst)
        if packet.haslayer(IP):
            return self._normalize_endpoint_text(str(packet[IP].src)), self._normalize_endpoint_text(str(packet[IP].dst))
        inner_ip = self._mpls_inner_ip(packet)
        if inner_ip is not None:
            return self._normalize_endpoint_text(str(inner_ip.src)), self._normalize_endpoint_text(str(inner_ip.dst))
        if packet.haslayer(IPv6):
            return self._normalize_endpoint_text(str(packet[IPv6].src)), self._normalize_endpoint_text(str(packet[IPv6].dst))
        if packet.haslayer(Dot3):
            return self._normalize_endpoint_text(str(packet[Dot3].src)), self._normalize_endpoint_text(str(packet[Dot3].dst))
        if packet.haslayer(Ether):
            return self._normalize_endpoint_text(str(packet[Ether].src)), self._normalize_endpoint_text(str(packet[Ether].dst))
        return 'N/A', 'N/A'

    def _normalize_endpoint_text(self, endpoint: str) -> str:
        text = (endpoint or '').strip()
        if text.lower() == 'ff:ff:ff:ff:ff:ff':
            return 'Broadcast'
        if text.lower() == '01:00:0c:cc:cc:cc':
            return 'CDP/VTP/DTP/PAgP/UDLD'
        parts = text.split(':')
        if len(parts) == 6 and all(len(part) == 2 for part in parts):
            vendor = get_mac_vendor(text)
            if vendor:
                suffix = ':'.join(parts[-3:])
                return f'{vendor}_{suffix}'
        return text or 'N/A'

    def _snap_oui_code(self, packet):
        try:
            if packet.haslayer(SNAP):
                oui = int(getattr(packet[SNAP], 'OUI', 0) or 0)
                code = int(getattr(packet[SNAP], 'code', 0) or 0)
                return oui, code
        except Exception:
            pass
        return None, None

    def _is_cdp_packet(self, packet) -> bool:
        oui, code = self._snap_oui_code(packet)
        if oui == 0x00000C and code == 0x2000:
            return True
        try:
            if packet.haslayer(Dot3):
                return str(getattr(packet[Dot3], 'dst', '') or '').lower() == '01:00:0c:cc:cc:cc'
        except Exception:
            pass
        return False

    def _cdp_payload(self, packet) -> bytes:
        try:
            if packet.haslayer(SNAP):
                return bytes(packet[SNAP].payload)
        except Exception:
            pass
        return b''

    def _cdp_device_and_port(self, payload: bytes):
        device_id = ''
        port_id = ''
        pos = 4
        while pos + 4 <= len(payload):
            tlv_type = int.from_bytes(payload[pos:pos + 2], 'big')
            tlv_len = int.from_bytes(payload[pos + 2:pos + 4], 'big')
            if tlv_len < 4 or pos + tlv_len > len(payload):
                break
            tlv_value = payload[pos + 4:pos + tlv_len]
            if tlv_type == 0x0001:
                device_id = tlv_value.decode(errors='ignore').rstrip('\x00')
            elif tlv_type == 0x0003:
                port_id = tlv_value.decode(errors='ignore').rstrip('\x00')
            pos += tlv_len
        return device_id, port_id

    def _extract_ports(self, packet, effective_tcp=None, effective_udp=None):
        tcp_layer = effective_tcp if effective_tcp is not None else self._effective_tcp_layer(packet)
        if tcp_layer is not None:
            return int(tcp_layer.sport), int(tcp_layer.dport)
        udp_layer = effective_udp if effective_udp is not None else self._effective_udp_layer(packet)
        if udp_layer is not None:
            return int(udp_layer.sport), int(udp_layer.dport)
        return None, None

    def _effective_ip_layer(self, packet):
        if packet.haslayer(IP):
            return packet[IP]
        return self._mpls_inner_ip(packet)

    def _effective_tcp_layer(self, packet, ip_layer=None):
        if packet.haslayer(TCP):
            return packet[TCP]
        effective_ip = ip_layer if ip_layer is not None else self._effective_ip_layer(packet)
        if effective_ip is not None and effective_ip.haslayer(TCP):
            return effective_ip[TCP]
        return None

    def _effective_udp_layer(self, packet, ip_layer=None):
        if packet.haslayer(UDP):
            return packet[UDP]
        effective_ip = ip_layer if ip_layer is not None else self._effective_ip_layer(packet)
        if effective_ip is not None and effective_ip.haslayer(UDP):
            return effective_ip[UDP]
        return None

    def _ipv4_payload_length(self, ip_layer) -> int | None:
        try:
            total_len = int(getattr(ip_layer, 'len', 0) or 0)
            header_len = int(getattr(ip_layer, 'ihl', 5) or 5) * 4
            if total_len >= header_len:
                return total_len - header_len
        except Exception:
            pass
        return None

    def _tcp_payload_length(self, packet, tcp_layer=None, ip_layer=None) -> int:
        tcp = tcp_layer if tcp_layer is not None else self._effective_tcp_layer(packet, ip_layer)
        if tcp is None:
            return 0

        raw_payload_len = len(bytes(getattr(tcp, 'payload', b'')))
        effective_ip = ip_layer if ip_layer is not None else self._effective_ip_layer(packet)
        if effective_ip is not None:
            ip_payload_len = self._ipv4_payload_length(effective_ip)
            if ip_payload_len is not None:
                tcp_header_len = int(getattr(tcp, 'dataofs', 5) or 5) * 4
                return max(0, min(raw_payload_len, ip_payload_len - tcp_header_len))

        if packet.haslayer(IPv6):
            try:
                ipv6_payload_len = int(getattr(packet[IPv6], 'plen', 0) or 0)
                tcp_header_len = int(getattr(tcp, 'dataofs', 5) or 5) * 4
                return max(0, min(raw_payload_len, ipv6_payload_len - tcp_header_len))
            except Exception:
                pass

        return raw_payload_len

    def _tcp_payload_bytes(self, packet, tcp_layer=None, ip_layer=None) -> bytes:
        tcp = tcp_layer if tcp_layer is not None else self._effective_tcp_layer(packet, ip_layer)
        if tcp is None:
            return b''
        raw_payload = bytes(getattr(tcp, 'payload', b''))
        return raw_payload[:self._tcp_payload_length(packet, tcp, ip_layer)]

    def _ip_payload_bytes(self, packet, ip_layer=None) -> bytes:
        effective_ip = ip_layer if ip_layer is not None else self._effective_ip_layer(packet)
        if effective_ip is not None:
            raw_payload = bytes(getattr(effective_ip, 'payload', b''))
            ip_payload_len = self._ipv4_payload_length(effective_ip)
            if ip_payload_len is not None:
                return raw_payload[:ip_payload_len]
            return raw_payload

        if packet.haslayer(IPv6):
            try:
                raw_payload = bytes(packet[IPv6].payload)
                payload_len = int(getattr(packet[IPv6], 'plen', 0) or 0)
                return raw_payload[:payload_len]
            except Exception:
                pass

        return b''

    def _mpls_inner_ip(self, packet):
        try:
            if self._ether_type(packet) != 0x8847 or not packet.haslayer(Ether):
                return None
            raw_bytes = bytes(packet)
            offset = 14
            while offset + 4 <= len(raw_bytes):
                label_word = int.from_bytes(raw_bytes[offset:offset + 4], 'big')
                offset += 4
                if label_word & 0x100:
                    break
            if offset >= len(raw_bytes):
                return None
            if raw_bytes[offset] >> 4 != 4:
                return None
            return IP(raw_bytes[offset:])
        except Exception:
            return None

    def _ether_type(self, packet) -> int | None:
        try:
            if packet.haslayer(Ether):
                return int(getattr(packet[Ether], 'type', 0) or 0)
        except Exception:
            pass
        return None

    def _payload_bytes(self, packet) -> bytes:
        try:
            tcp_layer = self._effective_tcp_layer(packet)
            if tcp_layer is not None:
                return self._tcp_payload_bytes(packet, tcp_layer)
            udp_layer = self._effective_udp_layer(packet)
            if udp_layer is not None:
                return bytes(udp_layer.payload)
            ip_layer = self._effective_ip_layer(packet)
            if ip_layer is not None:
                return self._ip_payload_bytes(packet, ip_layer)
            if packet.haslayer(IPv6):
                return bytes(packet[IPv6].payload)
            if packet.haslayer('Raw'):
                return bytes(packet['Raw'].load)
        except Exception:
            pass
        return b''

    def _ldp_message_name(self, msg_type: int) -> str:
        return {
            0x0100: 'Hello Message',
            0x0200: 'Initialization Message',
            0x0201: 'Keep Alive Message',
            0x0300: 'Address Message',
            0x0301: 'Address Withdrawal Message',
            0x0400: 'Label Mapping Message',
            0x0401: 'Label Request Message',
            0x0402: 'Label Withdraw Message',
            0x0403: 'Label Release Message',
            0x0404: 'Label Abort Request Message',
            0x0001: 'Notification Message',
        }.get(msg_type, f'LDP Message (0x{msg_type:04x})')

    def _iter_ldp_messages(self, payload: bytes) -> list[dict]:
        if len(payload) < 10:
            return []

        pdu_len = int.from_bytes(payload[2:4], 'big')
        pdu_end = min(len(payload), 4 + pdu_len)
        pos = 10
        messages = []

        while pos + 8 <= pdu_end:
            header = int.from_bytes(payload[pos:pos + 2], 'big')
            msg_type = header & 0x7FFF
            msg_len = int.from_bytes(payload[pos + 2:pos + 4], 'big')
            total_len = 4 + msg_len
            if msg_len < 4 or pos + total_len > pdu_end:
                break

            messages.append({
                'offset': pos,
                'type': msg_type,
                'length': msg_len,
                'total_length': total_len,
            })
            pos += total_len

        return messages

    def _ldp_message_type_name(self, payload: bytes) -> str:
        """Extract all LDP message names from a PDU for packet-list text."""
        messages = self._iter_ldp_messages(payload)
        if not messages:
            return 'LDP Message (incomplete)'
        return ''.join(f"{self._ldp_message_name(int(message['type']))} " for message in messages)

    def _is_ldp_payload(self, payload: bytes) -> bool:
        if len(payload) < 10:
            return False
        version = int.from_bytes(payload[0:2], 'big')
        if version != 1:
            return False
        pdu_len = int.from_bytes(payload[2:4], 'big')
        return 4 <= pdu_len <= max(4, len(payload) - 4)

    def _bgp_message_type_name(self, payload: bytes) -> str:
        if len(payload) < 19:
            return 'BGP Message'
        msg_type = int(payload[18])
        names = {
            1: 'OPEN Message',
            2: 'UPDATE Message',
            3: 'NOTIFICATION Message',
            4: 'KEEPALIVE Message',
            5: 'ROUTE-REFRESH Message',
        }
        return names.get(msg_type, f'BGP Message ({msg_type})')

    def _is_bgp_payload(self, payload: bytes) -> bool:
        if len(payload) < 19:
            return False
        if payload[:16] != (b'\xff' * 16):
            return False
        length = int.from_bytes(payload[16:18], 'big')
        if length < 19 or length > len(payload):
            return False
        msg_type = int(payload[18])
        return 1 <= msg_type <= 5

    def _loop_function_name(self, payload: bytes) -> str:
        if len(payload) < 4:
            return 'Unknown'
        fn = int.from_bytes(payload[2:4], 'little')
        name = {
            1: 'Reply',
            2: 'Forward Data',
        }.get(fn)
        if name is not None:
            return name
        return f'Function {fn}'

    def _l2tpv3_control_message_name(self, payload: bytes) -> str | None:
        if len(payload) < 16:
            return None
        flags = int.from_bytes(payload[4:6], 'big')
        is_control = bool(flags & 0x8000)
        version = flags & 0x000F
        if not is_control or version != 3:
            return None
        if len(payload) < 24:
            return 'ZLB'
        avp_type = int.from_bytes(payload[20:22], 'big')
        if avp_type != 0:
            return 'Control Message'
        message_type = int.from_bytes(payload[22:24], 'big')
        names = {
            0: 'Control Message',
            1: 'SCCRQ',
            2: 'SCCRP',
            3: 'SCCCN',
            4: 'StopCCN',
            6: 'Hello',
        }
        return names.get(message_type, f'Control Message ({message_type})')

    def _l2tpv3_info_text(self, payload: bytes, metadata: dict) -> str:
        if len(payload) < 4:
            return 'Layer 2 Tunneling Protocol version 3'

        session_id = int.from_bytes(payload[:4], 'big')
        if session_id != 0:
            metadata['l2tpv3_is_control'] = False
            return f'D[S:0x{session_id:08X}]'

        metadata['l2tpv3_is_control'] = True
        ccid = int.from_bytes(payload[8:12], 'big') if len(payload) >= 12 else 0
        message_name = self._l2tpv3_control_message_name(payload) or 'Control Message'
        return f'Control Message - {message_name} (ccid=0x{ccid:08X})'

    def _guess_protocol(self, packet, metadata: dict | None = None):
        metadata = metadata or {}
        eth_type = self._ether_type(packet)
        effective_ip = self._effective_ip_layer(packet)
        effective_tcp = self._effective_tcp_layer(packet, effective_ip)
        effective_udp = self._effective_udp_layer(packet, effective_ip)
        if eth_type == 0x8035 and packet.haslayer(ARP):
            return 'RARP'
        if eth_type == 0x9000:
            return 'LOOP'
        if self._is_cdp_packet(packet):
            return 'CDP'
        if effective_ip is not None:
            ip_proto = int(getattr(effective_ip, 'proto', 0) or 0)
            if ip_proto == 115:
                return 'L2TPv3'
            if ip_proto == 89:
                return 'OSPF'
        if effective_udp is not None:
            sport = int(getattr(effective_udp, 'sport', 0) or 0)
            dport = int(getattr(effective_udp, 'dport', 0) or 0)
            if (sport == 646 or dport == 646) and self._is_ldp_payload(self._payload_bytes(packet)):
                return 'LDP'
        if effective_tcp is not None:
            sport = int(getattr(effective_tcp, 'sport', 0) or 0)
            dport = int(getattr(effective_tcp, 'dport', 0) or 0)
            if (
                not bool(metadata.get('tcp_is_retransmission', False))
                and (sport == 646 or dport == 646)
                and self._is_ldp_payload(self._payload_bytes(packet))
            ):
                return 'LDP'
            if not bool(metadata.get('tcp_is_retransmission', False)) and (sport == 179 or dport == 179):
                if self._is_bgp_payload(self._payload_bytes(packet)):
                    return 'BGP'
        if packet.haslayer(ARP) and eth_type != 0x8035:
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
        if effective_tcp is not None:
            return 'TCP'
        if effective_udp is not None:
            return 'UDP'
        if packet.haslayer(IPv6):
            return 'IPV6'
        if effective_ip is not None:
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

    def _build_info(self, packet, protocol: str, metadata: dict | None = None) -> str:
        metadata = metadata or {}
        try:
            if protocol == 'ARP':
                arp = packet[ARP]
                is_gratuitous = str(getattr(arp, 'psrc', '') or '') == str(getattr(arp, 'pdst', '') or '')
                if is_gratuitous and arp.op in {1, 2}:
                    label = 'Request' if int(getattr(arp, 'op', 0) or 0) == 1 else 'Reply'
                    return f'Gratuitous ARP for {arp.psrc} ({label})'
                if arp.op == 1:
                    return f'Who has {arp.pdst}? Tell {arp.psrc}'
                elif arp.op == 2:
                    return f'{arp.psrc} is at {arp.hwsrc}'
                return f'Opcode {arp.op}'
            if protocol == 'RARP':
                arp = packet[ARP]
                return f'Who is {arp.hwdst}? Tell {arp.hwsrc}'
            if protocol == 'LDP':
                return self._ldp_message_type_name(self._payload_bytes(packet))
            if protocol == 'BGP':
                return self._bgp_message_type_name(self._payload_bytes(packet))
            if protocol == 'L2TPv3':
                try:
                    ip_layer = self._effective_ip_layer(packet)
                    if ip_layer is not None:
                        ip_payload = self._ip_payload_bytes(packet, ip_layer)
                        if len(ip_payload) >= 4:
                            return self._l2tpv3_info_text(ip_payload, metadata)
                except Exception:
                    pass
                return 'Layer 2 Tunneling Protocol version 3'
            if protocol == 'LOOP':
                return self._loop_function_name(self._payload_bytes(packet))
            if protocol == 'CDP':
                device_id, port_id = self._cdp_device_and_port(self._cdp_payload(packet))
                if device_id or port_id:
                    return f'Device ID: {device_id}  Port ID: {port_id}  '
                return 'Cisco Discovery Protocol'
            if protocol == 'OSPF':
                payload = self._payload_bytes(packet)
                msg_type = int(payload[1]) if len(payload) >= 2 else -1
                msg_name = {
                    1: 'Hello Packet',
                    2: 'DB Description',
                    3: 'LS Request',
                    4: 'LS Update',
                    5: 'LS Acknowledge',
                }.get(msg_type, f'OSPF Message ({msg_type})' if msg_type >= 0 else 'OSPF')
                return msg_name
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
                tcp = self._effective_tcp_layer(packet)
                if tcp is None:
                    return packet.summary()
                flags_str = self._tcp_flags_to_string(tcp.flags)
                seq = int(metadata.get('tcp_relative_seq', tcp.seq) or 0)
                ack = int(metadata.get('tcp_relative_ack', tcp.ack) or 0)
                win = tcp.window
                payload_len = self._tcp_payload_length(packet, tcp)
                prefix = ''
                if bool(metadata.get('tcp_is_duplicate_ack', False)):
                    dup_frame = int(metadata.get('tcp_duplicate_ack_frame_number', 0) or 0)
                    dup_count = int(metadata.get('tcp_duplicate_ack_count', 1) or 1)
                    prefix = f'[TCP Dup ACK {dup_frame}#{dup_count}] '
                elif bool(metadata.get('tcp_is_window_update', False)):
                    prefix = '[TCP Window Update] '
                elif bool(metadata.get('tcp_is_retransmission', False)):
                    prefix = '[TCP Retransmission] '
                elif bool(metadata.get('tcp_previous_segment_not_captured', False)):
                    prefix = '[TCP Previous segment not captured] '
                return f'{prefix}{tcp.sport} → {tcp.dport} [{flags_str}] Seq={seq} Ack={ack} Win={win} Len={payload_len}'
            if protocol == 'UDP':
                udp = self._effective_udp_layer(packet)
                if udp is None:
                    return packet.summary()
                payload_len = max(0, udp.len - 8)
                return f'{udp.sport} -> {udp.dport} Len={payload_len}'
            if protocol in {'ICMP', 'ICMPV6'}:
                return packet.summary()
            return packet.summary()
        except Exception:
            return packet.summary()

    def _icmp_echo_info_text(self, packet, request_frame: int | None = None, response_frame: int | None = None, no_response: bool = False) -> str:
        if not packet.haslayer(ICMP):
            return packet.summary()
        raw = bytes(packet[ICMP])
        if len(raw) < 8:
            return packet.summary()

        icmp_type = int(raw[0])
        if icmp_type not in {0, 8}:
            return packet.summary()

        label = 'Echo (ping) request' if icmp_type == 8 else 'Echo (ping) reply'
        identifier = int.from_bytes(raw[4:6], 'big')
        sequence = int.from_bytes(raw[6:8], 'big')
        ttl = 0
        if packet.haslayer(IP):
            ttl = int(getattr(packet[IP], 'ttl', 0) or 0)

        info = f'{label.ljust(21)}id=0x{identifier:04x}, seq={sequence}/{sequence}, ttl={ttl}'
        if icmp_type == 8 and response_frame is not None:
            return f'{info} (reply in {response_frame})'
        if icmp_type == 8 and no_response:
            return f'{info} (no response found!)'
        if icmp_type == 0 and request_frame is not None:
            return f'{info} (request in {request_frame})'
        return info

    def _update_icmp_echo_metadata(self, packet, record: PacketRecord) -> None:
        if not packet.haslayer(ICMP) or not packet.haslayer(IP):
            return

        raw = bytes(packet[ICMP])
        if len(raw) < 8:
            return

        icmp_type = int(raw[0])
        if icmp_type not in {0, 8}:
            return

        src = str(packet[IP].src)
        dst = str(packet[IP].dst)
        identifier = int.from_bytes(raw[4:6], 'big')
        sequence = int.from_bytes(raw[6:8], 'big')
        payload = raw[8:]
        key = (src, dst, identifier, sequence, payload)

        if icmp_type == 8:
            record.metadata['icmp_no_response_seen'] = True
            self.icmp_echo_pending[key] = record
            record.info = self._icmp_echo_info_text(packet, no_response=True)
            return

        reverse_key = (dst, src, identifier, sequence, payload)
        pending = self.icmp_echo_pending.get(reverse_key)
        if pending is not None:
            request_record = pending
            self.icmp_echo_pending.pop(reverse_key, None)

            rtt_ms = max(0.0, (float(record.epoch_time) - float(request_record.epoch_time)) * 1000.0)
            request_record.metadata['icmp_response_frame'] = int(record.number)
            request_record.metadata['icmp_no_response_seen'] = False
            request_record.info = self._icmp_echo_info_text(request_record.raw, response_frame=int(record.number))

            record.metadata['icmp_request_frame'] = int(request_record.number)
            record.metadata['icmp_response_time_ms'] = float(rtt_ms)
            record.info = self._icmp_echo_info_text(packet, request_frame=int(request_record.number))
            return

        record.info = self._icmp_echo_info_text(packet)

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
        return ', '.join(expanded) if expanded else 'None'
