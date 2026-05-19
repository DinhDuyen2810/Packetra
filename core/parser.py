from __future__ import annotations
from collections import Counter
from decimal import Decimal
import ipaddress
from scapy.all import ARP, DNS, Ether, ICMP, IP, IPv6, TCP, UDP, bind_layers
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.inet6 import ICMPv6EchoRequest, ICMPv6EchoReply, ICMPv6ND_NS, ICMPv6ND_NA, IPv6ExtHdrHopByHop
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
        self.http_request_pending = {}
        self.dns_request_pending = {}
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
        self._update_http_stream_metadata(packet, metadata, epoch_time)
        self._update_capwap_metadata(packet, metadata)

        protocol = self._guess_protocol(packet, metadata)
        if protocol not in {'CAPWAP-Control', 'CAPWAP-Data', '802.11'}:
            if str(metadata.get('capwap_transport', '') or '') == 'control':
                protocol = 'CAPWAP-Control'
            elif str(metadata.get('capwap_transport', '') or '') == 'data':
                protocol = 'CAPWAP-Data'
            elif effective_udp is not None:
                sport = int(getattr(effective_udp, 'sport', 0) or 0)
                dport = int(getattr(effective_udp, 'dport', 0) or 0)
                if sport in {5246, 5247} or dport in {5246, 5247}:
                    self._update_capwap_metadata(packet, metadata)
                    if str(metadata.get('capwap_transport', '') or '') == 'control':
                        protocol = 'CAPWAP-Control'
                    elif str(metadata.get('capwap_transport', '') or '') == 'data':
                        protocol = 'CAPWAP-Data'

        if protocol == '802.11':
            wlan = metadata.get('wlan', {}) or {}
            src = str(wlan.get('source', '') or src)
            dst = str(wlan.get('destination', '') or dst)
            sport = None
            dport = None
            stream_hint = f'{src} -> {dst}' if src or dst else ''
            if 'WLAN' not in layers:
                layers.append('WLAN')
        elif protocol == 'DHCPv6':
            if not any(str(layer).upper().startswith('DHCP6') or str(layer).upper() == 'DHCPV6' for layer in layers):
                layers.append('DHCPV6')
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

        self._track_transport_record(record)
        self._update_http_metadata(record)
        self._update_icmp_echo_metadata(packet, record)
        self._update_dns_metadata(packet, record)

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
                'dir_relative_origin': {},
                'dir_window_shift': {},
                'completeness_flags': 0,
                'client_packets': 0,
                'server_packets': 0,
                'client_endpoint': client_endpoint,
                'packets_by_dir': {},
                'records': [],
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
        tcp_flags = int(getattr(layer, 'flags', 0) or 0)

        dir_key = (src, sport, dst, dport)
        rev_key = (dst, dport, src, sport)

        if dir_key not in state['dir_base_seq']:
            state['dir_base_seq'][dir_key] = seq
            state['dir_relative_origin'][dir_key] = seq if (tcp_flags & 0x02) else ((seq - 1) & 0xFFFFFFFF)
        relative_seq = (seq - int(state['dir_relative_origin'][dir_key])) & 0xFFFFFFFF

        if ack > 0:
            ack_base = state['dir_relative_origin'].get(rev_key)
            if ack_base is None:
                # First packet might only carry ACK for reverse direction before reverse data is seen.
                state['dir_base_seq'][rev_key] = ack
                state['dir_relative_origin'][rev_key] = ((ack - 1) & 0xFFFFFFFF)
                ack_base = state['dir_relative_origin'][rev_key]
            relative_ack = (ack - int(ack_base)) & 0xFFFFFFFF
        else:
            relative_ack = 0

        payload_len = self._tcp_payload_length(packet, layer, effective_ip)
        syn_len = 1 if (tcp_flags & 0x02) else 0
        fin_len = 1 if (tcp_flags & 0x01) else 0
        seq_advance = payload_len + syn_len + fin_len
        end_seq_raw = (seq + seq_advance) & 0xFFFFFFFF

        completeness_flags = int(state.get('completeness_flags', 0) or 0)
        if tcp_flags & 0x04:  # RST
            completeness_flags |= 32
        if tcp_flags & 0x01:  # FIN
            completeness_flags |= 16
        if payload_len > 0:
            completeness_flags |= 8
        if tcp_flags & 0x10:  # ACK
            completeness_flags |= 4
        if (tcp_flags & 0x12) == 0x12:  # SYN-ACK
            completeness_flags |= 2
        if (tcp_flags & 0x12) == 0x02:  # SYN without ACK
            completeness_flags |= 1
        state['completeness_flags'] = completeness_flags
        for stream_record in state.get('records', []):
            stream_record.metadata['tcp_completeness_flags'] = completeness_flags

        metadata['tcp_relative_seq'] = relative_seq
        metadata['tcp_relative_ack'] = relative_ack
        metadata['tcp_next_seq'] = relative_seq + seq_advance
        metadata['tcp_completeness_flags'] = completeness_flags

        if tcp_flags & 0x02:
            window_scale_shift = self._tcp_window_scale_shift(layer)
            state['dir_window_shift'][dir_key] = int(window_scale_shift) if window_scale_shift is not None else -1
        current_window_shift = state['dir_window_shift'].get(dir_key)
        if current_window_shift is not None:
            if int(current_window_shift) >= 0:
                metadata['tcp_window_scale_shift'] = int(current_window_shift)
            else:
                metadata['tcp_window_scaling_disabled'] = True

        # ---- SEQ/ACK analysis (Wireshark-like conditions) ----
        dir_packets = state['packets_by_dir'].setdefault(dir_key, [])
        rev_packets = state['packets_by_dir'].setdefault(rev_key, [])

        ack_frame_number = None
        ack_rtt_ms = None
        ack_ambiguous = False
        bytes_in_flight = None
        bytes_since_last_psh = None
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

    def _track_transport_record(self, record: PacketRecord) -> None:
        packet = getattr(record, 'raw', None)
        if packet is None:
            return

        effective_ip = self._effective_ip_layer(packet)
        tcp_layer = self._effective_tcp_layer(packet, effective_ip)
        udp_layer = self._effective_udp_layer(packet, effective_ip)
        if tcp_layer is not None:
            layer = tcp_layer
            proto = 'TCP'
        elif udp_layer is not None:
            layer = udp_layer
            proto = 'UDP'
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
            return

        state.setdefault('records', []).append(record)
        record.metadata[f'{proto.lower()}_completeness_flags'] = int(state.get('completeness_flags', 0) or 0)

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

    def _capwap_enterprise_name(self, enterprise_number: int) -> str:
        names = {
            0: 'Reserved',
            13277: 'IEEE 802.11',
        }
        return names.get(int(enterprise_number), 'Unknown')

    def _capwap_message_type_name(
        self,
        message_type: int,
        enterprise_number: int = 0,
        specific_message_type: int | None = None,
    ) -> str:
        enterprise_number = int(enterprise_number or 0)
        message_type = int(message_type or 0)
        if enterprise_number == 13277:
            specific = int(specific_message_type if specific_message_type is not None else (message_type & 0xFF))
            names = {
                1: 'IEEE 802.11 WLAN Configuration Request',
                2: 'IEEE 802.11 WLAN Configuration Response',
            }
            return names.get(specific, f'Enterprise Message ({message_type})')

        names = {
            1: 'Discovery Request',
            2: 'Discovery Response',
            3: 'Join Request',
            4: 'Join Response',
            5: 'Configuration Status Request',
            6: 'Configuration Status Response',
            7: 'Configuration Update Request',
            8: 'Configuration Update Response',
            9: 'WTP Event Request',
            10: 'WTP Event Response',
            11: 'Change State Request',
            12: 'Change State Response',
            13: 'Echo Request',
            14: 'Echo Response',
            15: 'Image Data Request',
            16: 'Image Data Response',
            17: 'Reset Request',
            18: 'Reset Response',
            19: 'Primary Discovery Request',
            20: 'Primary Discovery Response',
        }
        return names.get(int(message_type), f'Control Message ({int(message_type)})')

    def _capwap_element_name(self, element_type: int) -> str:
        names = {
            1: 'AC Descriptor',
            2: 'AC IPv4 List',
            4: 'AC Name',
            10: 'CAPWAP Control IPv4 Address',
            12: 'CAPWAP Timers',
            16: 'Decryption Error Report Period',
            23: 'Idle Timeout',
            28: 'Location Data',
            30: 'CAPWAP Local IPv4 Address',
            31: 'Radio Administrative State',
            32: 'Radio Operational State',
            33: 'Result Code',
            35: 'Session ID',
            36: 'Statistics Timer',
            38: 'WTP Board Data',
            39: 'WTP Descriptor',
            40: 'WTP Fallback',
            41: 'WTP Frame Tunnel Mode',
            44: 'WTP MAC Type',
            45: 'WTP Name',
            48: 'WTP Reboot Statistics',
            51: 'CAPWAP Transport Protocol',
            53: 'ECN Support',
            1024: 'IEEE 802.11 Add WLAN',
            1025: 'IEEE 802.11 Antenna',
            1026: 'IEEE 802.11 Assigned WTP BSSID',
            1028: 'IEEE 802.11 Direct Sequence Control',
            1030: 'IEEE 802.11 MAC Operation',
            1032: 'IEEE 802.11 Multi-Domain Capability',
            1040: 'IEEE 802.11 Supported Rates',
            1041: 'IEEE 802.11 Tx Power',
            1042: 'IEEE 802.11 Tx Power Level',
            1046: 'IEEE 802.11 WTP Radio Configuration',
            1048: 'IEEE 802.11 WTP Radio Information',
        }
        return names.get(int(element_type), f'Element {int(element_type)}')

    def _capwap_vendor_name(self, vendor_id: int) -> str:
        names = {
            12345: 'VWB Group',
            23456: 'NetCarrier Inc',
            33457: 'DANET.CZ s.r.o.',
            43458: 'Nvizible Ltd',
            53459: 'CHALLENGE NETWORKS PTY LTD',
        }
        return names.get(int(vendor_id), 'Unknown')

    def _capwap_wbid_name(self, wbid: int) -> str:
        names = {
            0: 'Reserved',
            1: 'IEEE 802.11',
            2: 'Reserved',
            3: 'EPCGlobal',
        }
        return names.get(int(wbid), f'Unknown ({int(wbid)})')

    def _capwap_board_data_type_name(self, board_type: int) -> str:
        names = {
            0: 'WTP Model Number',
            1: 'WTP Serial Number',
            2: 'Board ID',
            3: 'Board Revision',
            4: 'Base MAC Address',
        }
        return names.get(int(board_type), f'Board Data Type {int(board_type)}')

    def _capwap_board_data_display_name(self, board_type: int) -> str:
        names = {
            0: 'WTP Model Number',
            1: 'WTP Serial Number',
            2: 'WTP Board ID',
            3: 'WTP Board Revision',
            4: 'Base Mac Address',
        }
        return names.get(int(board_type), self._capwap_board_data_type_name(board_type))

    def _capwap_descriptor_type_name(self, descriptor_type: int) -> str:
        names = {
            0: 'WTP Hardware Version',
            1: 'WTP Active Software Version',
            2: 'WTP Boot Version',
            3: 'WTP Other Software Version',
        }
        return names.get(int(descriptor_type), f'Descriptor Type {int(descriptor_type)}')

    def _capwap_decode_text(self, data: bytes) -> str:
        try:
            return data.decode('utf-8', errors='ignore')
        except Exception:
            return ''

    def _capwap_format_mac(self, data: bytes) -> str:
        if len(data) != 6:
            return data.hex()
        mac = ':'.join(f'{byte:02x}' for byte in data)
        vendor = get_mac_vendor(mac)
        if vendor:
            suffix = ':'.join(mac.split(':')[-3:])
            return f'{vendor}_{suffix} ({mac})'
        return mac

    def _wlan_frame_type_name(self, frame_type: int) -> str:
        return {
            0: 'Management frame',
            1: 'Control frame',
            2: 'Data frame',
            3: 'Extension frame',
        }.get(int(frame_type), f'Frame Type {int(frame_type)}')

    def _wlan_management_subtype_name(self, subtype: int) -> str:
        return {
            0: 'Association Request',
            1: 'Association Response',
            2: 'Reassociation Request',
            3: 'Reassociation Response',
            4: 'Probe Request',
            5: 'Probe Response',
            8: 'Beacon',
            10: 'Disassociation',
            11: 'Authentication',
            12: 'Deauthentication',
        }.get(int(subtype), f'Management Subtype {int(subtype)}')

    def _wlan_flags_display(self, flags: int) -> str:
        mapping = (
            (0x80, 'o'),
            (0x40, 'p'),
            (0x20, 'm'),
            (0x10, 'P'),
            (0x08, 'r'),
            (0x04, 'M'),
            (0x02, 'f'),
            (0x01, 't'),
        )
        return ''.join(letter if int(flags) & mask else '.' for mask, letter in mapping)

    def _wlan_rate_text(self, rate_byte: int) -> tuple[str, str]:
        rate_value = int(rate_byte) & 0x7F
        basic = bool(int(rate_byte) & 0x80)
        known = {
            2: '1',
            4: '2',
            11: '5.5',
            22: '11',
            12: '6',
            18: '9',
            24: '12',
            36: '18',
            48: '24',
            72: '36',
            96: '48',
            108: '54',
        }.get(rate_value)
        if known is None:
            return 'Unknown Rate', 'Unknown'
        title_text = f'{known}(B)' if basic else known
        return title_text, title_text

    def _parse_wlan_tagged_parameters(self, data: bytes, value_offset: int) -> dict:
        tags = []
        cursor = 0
        malformed = None

        while cursor + 2 <= len(data):
            tag_number = int(data[cursor])
            declared_length = int(data[cursor + 1])
            value_start = cursor + 2
            available_length = max(0, len(data) - value_start)
            actual_length = min(declared_length, available_length)
            malformed_length = declared_length > available_length
            value = data[value_start:value_start + actual_length]

            tag_name = {
                0: 'SSID parameter set',
                1: 'Supported Rates',
                50: 'Extended Supported Rates',
            }.get(tag_number, f'Tag {tag_number}')

            tag = {
                'number': tag_number,
                'name': tag_name,
                'declared_length': declared_length,
                'length': actual_length,
                'offset': value_offset + cursor,
                'value_offset': value_offset + value_start,
                'value_hex': value.hex(),
                'malformed_length': malformed_length,
            }

            if tag_number == 0:
                ssid = self._capwap_decode_text(value)
                tag['ssid'] = ssid
                tag['title'] = f'Tag: SSID parameter set: "{ssid}"'
            elif tag_number in {1, 50}:
                rate_titles = []
                rate_entries = []
                for rate_byte in value:
                    title_text, child_text = self._wlan_rate_text(int(rate_byte))
                    rate_titles.append(title_text)
                    rate_entries.append({
                        'value': int(rate_byte),
                        'title_text': title_text,
                        'child_text': child_text,
                    })
                tag['rates'] = rate_entries
                joined = ', '.join(rate_titles)
                if malformed_length:
                    tag['title'] = f'Tag: {tag_name} {joined},'
                else:
                    tag['title'] = f'Tag: {tag_name} {joined}, [Mbit/sec]'
            else:
                tag['title'] = f'Tag: {tag_name}'

            tags.append(tag)
            cursor = value_start + actual_length

            if malformed_length:
                malformed = {
                    'summary': '[Malformed Packet: IEEE 802.11: length of contained item exceeds length of containing item]',
                    'info_suffix': '[Malformed Packet: length of contained item exceeds length of containing item]',
                    'reason': 'Exception occurred',
                    'tag_reason': 'Tag Length is longer than remaining payload',
                }
                break

        return {
            'tags': tags,
            'malformed': malformed,
        }

    def _parse_wlan_ht_control(self, value: int) -> dict:
        lac = (int(value) >> 1) & 0x7FFF
        return {
            'value': int(value),
            'vht': bool(int(value) & 0x00000001),
            'link_adaptation_control': lac,
            'training_request': (lac >> 11) & 0x1,
            'mcs_request': (lac >> 10) & 0x1,
            'lac_reserved': (lac >> 7) & 0x7,
            'mfsi': (lac >> 4) & 0x7,
            'mfb': lac & 0xF,
            'calibration_position': (int(value) >> 16) & 0x3,
            'calibration_sequence': (int(value) >> 18) & 0x3,
            'reserved_mid': (int(value) >> 20) & 0x3,
            'csi_steering': (int(value) >> 22) & 0x3,
            'ndp_announcement': bool(int(value) & 0x01000000),
            'reserved_upper': (int(value) >> 25) & 0x1F,
            'ac_constraint': bool(int(value) & 0x40000000),
            'rdg_more_ppdu': bool(int(value) & 0x80000000),
        }

    def _parse_wlan_association_request(self, data: bytes, frame_offset: int) -> dict | None:
        if len(data) < 24:
            return None

        def _candidate(frame_control_low: int, flags: int, frame_control_display: int, frame_control_low_offset: int, flags_offset: int) -> dict | None:
            version = int(frame_control_low) & 0x03
            frame_type = (int(frame_control_low) >> 2) & 0x03
            subtype = (int(frame_control_low) >> 4) & 0x0F
            if version != 0 or frame_type != 0 or subtype != 0:
                return None

            duration = int.from_bytes(data[2:4], 'little')
            receiver = self._capwap_format_mac(data[4:10])
            transmitter = self._capwap_format_mac(data[10:16])
            bssid = self._capwap_format_mac(data[16:22])
            sequence_control = int.from_bytes(data[22:24], 'little')
            fragment_number = sequence_control & 0x0F
            sequence_number = sequence_control >> 4
            cursor = 24
            ht_control = None

            if int(flags) & 0x80:
                if len(data) < cursor + 4:
                    return None
                ht_control = self._parse_wlan_ht_control(int.from_bytes(data[cursor:cursor + 4], 'little'))
                cursor += 4

            fixed_data = data[cursor:cursor + 4]
            capabilities = int.from_bytes(fixed_data[:2], 'little') if len(fixed_data) >= 2 else 0
            listen_interval = int.from_bytes(fixed_data[2:4], 'little') if len(fixed_data) >= 4 else None
            tags_result = self._parse_wlan_tagged_parameters(data[cursor + 4:], frame_offset + cursor + 4) if len(data) > cursor + 4 else {
                'tags': [],
                'malformed': None,
            }

            malformed = tags_result.get('malformed')
            if malformed is None and len(fixed_data) < 4:
                malformed = {
                    'summary': '[Malformed Packet: IEEE 802.11]',
                    'info_suffix': '[Malformed Packet]',
                    'reason': 'Exception occurred',
                }

            capability_bits = {
                'ess': bool(capabilities & 0x0001),
                'ibss': bool(capabilities & 0x0002),
                'privacy': bool(capabilities & 0x0010),
                'short_preamble': bool(capabilities & 0x0020),
                'critical_update': bool(capabilities & 0x0040),
                'nontransmitted_bssid_update': bool(capabilities & 0x0080),
                'spectrum_management': bool(capabilities & 0x0100),
                'qos': bool(capabilities & 0x0200),
                'short_slot_time': bool(capabilities & 0x0400),
                'apsd': bool(capabilities & 0x0800),
                'radio_measurement': bool(capabilities & 0x1000),
                'epd': bool(capabilities & 0x2000),
            }

            ssid = ''
            for tag in tags_result.get('tags', []):
                if int(tag.get('number', -1)) == 0:
                    ssid = str(tag.get('ssid', '') or '')
                    break

            info = f'Association Request, SN={sequence_number}, FN={fragment_number}, Flags={self._wlan_flags_display(flags)}'
            if ssid and malformed is None:
                info += f', SSID="{ssid}"'
            if malformed is not None:
                info += str(malformed.get('info_suffix', '') or '')

            return {
                'offset': frame_offset,
                'length': len(data),
                'type': frame_type,
                'type_name': self._wlan_frame_type_name(frame_type),
                'subtype': subtype,
                'subtype_name': self._wlan_management_subtype_name(subtype),
                'frame_control': int(frame_control_display),
                'frame_control_low_offset': int(frame_control_low_offset),
                'flags_offset': int(flags_offset),
                'flags': int(flags),
                'flags_display': self._wlan_flags_display(flags),
                'duration': duration,
                'receiver': receiver,
                'destination': receiver,
                'transmitter': transmitter,
                'source': transmitter,
                'bssid': bssid,
                'fragment_number': fragment_number,
                'sequence_number': sequence_number,
                'ht_control': ht_control,
                'management': {
                    'fixed_offset': frame_offset + cursor,
                    'fixed_length': len(fixed_data),
                    'capabilities': capabilities,
                    'capability_bits': capability_bits,
                    'listen_interval': listen_interval,
                    'tags_offset': frame_offset + cursor + 4,
                    'tags_length': max(0, len(data) - (cursor + 4)),
                    'tags': tags_result.get('tags', []),
                },
                'malformed': malformed,
                'info': info,
            }

        candidates = []
        if data[0] == data[1]:
            candidates.append(
                _candidate(
                    int(data[0]),
                    int(data[1]),
                    int.from_bytes(data[:2], 'little'),
                    frame_offset + 1,
                    frame_offset,
                )
            )

        candidates.append(
            _candidate(
                int(data[0]),
                int(data[1]),
                int.from_bytes(data[:2], 'little'),
                frame_offset,
                frame_offset + 1,
            )
        )
        if data[0] != data[1]:
            candidates.append(
                _candidate(
                    int(data[1]),
                    int(data[0]),
                    int.from_bytes(data[:2], 'big'),
                    frame_offset + 1,
                    frame_offset,
                )
            )

        for candidate in candidates:
            if candidate is not None:
                return candidate
        return None

    def _parse_capwap_board_data(self, value: bytes, value_offset: int) -> dict:
        vendor_id = int.from_bytes(value[:4], 'big') if len(value) >= 4 else 0
        subelements = []
        cursor = 4
        while cursor + 4 <= len(value):
            sub_type = int.from_bytes(value[cursor:cursor + 2], 'big')
            sub_length = int.from_bytes(value[cursor + 2:cursor + 4], 'big')
            sub_value_start = cursor + 4
            sub_end = sub_value_start + sub_length
            if sub_end > len(value):
                break
            sub_value = value[sub_value_start:sub_end]
            subelement = {
                'type': sub_type,
                'name': self._capwap_board_data_type_name(sub_type),
                'display_name': self._capwap_board_data_display_name(sub_type),
                'length': sub_length,
                'value_hex': sub_value.hex(),
                'offset': value_offset + cursor,
                'value_offset': value_offset + sub_value_start,
            }
            if sub_type in {0, 1, 2, 3}:
                subelement['display_value'] = self._capwap_decode_text(sub_value)
            elif sub_type == 4:
                subelement['display_value'] = self._capwap_format_mac(sub_value)
            subelements.append(subelement)
            cursor = sub_end
        return {
            'vendor_id': vendor_id,
            'vendor_name': self._capwap_vendor_name(vendor_id),
            'subelements': subelements,
        }

    def _parse_capwap_descriptor(self, value: bytes, value_offset: int) -> dict:
        max_radios = int(value[0]) if len(value) >= 1 else 0
        radios_in_use = int(value[1]) if len(value) >= 2 else 0
        num_encrypt = int(value[2]) if len(value) >= 3 else 0
        encryptions = []
        cursor = 3
        for _ in range(num_encrypt):
            if cursor + 3 > len(value):
                break
            encryption_word = int.from_bytes(value[cursor:cursor + 3], 'big')
            encryptions.append({
                'reserved': (encryption_word >> 21) & 0x7,
                'wbid': (encryption_word >> 16) & 0x1F,
                'wbid_name': self._capwap_wbid_name((encryption_word >> 16) & 0x1F),
                'capabilities': encryption_word & 0xFFFF,
                'offset': value_offset + cursor,
            })
            cursor += 3

        descriptors = []
        while cursor + 8 <= len(value):
            vendor_id = int.from_bytes(value[cursor:cursor + 4], 'big')
            descriptor_type = int.from_bytes(value[cursor + 4:cursor + 6], 'big')
            descriptor_length = int.from_bytes(value[cursor + 6:cursor + 8], 'big')
            descriptor_value_start = cursor + 8
            descriptor_end = descriptor_value_start + descriptor_length
            if descriptor_end > len(value):
                break
            descriptor_value = value[descriptor_value_start:descriptor_end]
            descriptors.append({
                'vendor_id': vendor_id,
                'vendor_name': self._capwap_vendor_name(vendor_id),
                'type': descriptor_type,
                'name': self._capwap_descriptor_type_name(descriptor_type),
                'length': descriptor_length,
                'value_hex': descriptor_value.hex(),
                'text': self._capwap_decode_text(descriptor_value),
                'offset': value_offset + cursor,
                'value_offset': value_offset + descriptor_value_start,
            })
            cursor = descriptor_end

        return {
            'max_radios': max_radios,
            'radios_in_use': radios_in_use,
            'num_encrypt': num_encrypt,
            'encryptions': encryptions,
            'descriptors': descriptors,
        }

    def _parse_capwap_reboot_statistics(self, value: bytes) -> dict:
        counts = [
            int.from_bytes(value[index:index + 2], 'big')
            for index in range(0, min(len(value), 14), 2)
        ]
        while len(counts) < 7:
            counts.append(0)
        last_failure_type = int(value[14]) if len(value) >= 15 else 0
        failure_names = {
            0: 'Not Supported',
            1: 'Software Failure',
            2: 'Hardware Failure',
            3: 'Other Failure',
            255: 'Unknown',
        }
        return {
            'reboot_count': counts[0],
            'ac_initiated_count': counts[1],
            'link_failure_count': counts[2],
            'sw_failure_count': counts[3],
            'hw_failure_count': counts[4],
            'other_failure_count': counts[5],
            'unknown_failure_count': counts[6],
            'last_failure_type': last_failure_type,
            'last_failure_name': failure_names.get(last_failure_type, f'Unknown ({last_failure_type})'),
        }

    def _capwap_ac_information_type_name(self, info_type: int) -> str:
        names = {
            4: 'AC Hardware Version',
            5: 'AC Software Version',
        }
        return names.get(int(info_type), f'AC Information Type ({int(info_type)})')

    def _parse_capwap_ac_descriptor(self, value: bytes, value_offset: int) -> dict:
        stations = int.from_bytes(value[0:2], 'big') if len(value) >= 2 else 0
        limit_stations = int.from_bytes(value[2:4], 'big') if len(value) >= 4 else 0
        active_wtps = int.from_bytes(value[4:6], 'big') if len(value) >= 6 else 0
        max_wtps = int.from_bytes(value[6:8], 'big') if len(value) >= 8 else 0
        security_flags = int(value[8]) if len(value) >= 9 else 0
        r_mac_field = int(value[9]) if len(value) >= 10 else 0
        reserved = int(value[10]) if len(value) >= 11 else 0
        dtls_policy_flags = int(value[11]) if len(value) >= 12 else 0

        ac_information = []
        cursor = 12
        while cursor + 8 <= len(value):
            vendor_id = int.from_bytes(value[cursor:cursor + 4], 'big')
            info_type = int.from_bytes(value[cursor + 4:cursor + 6], 'big')
            info_length = int.from_bytes(value[cursor + 6:cursor + 8], 'big')
            info_value_start = cursor + 8
            info_end = info_value_start + info_length
            if info_end > len(value):
                break
            info_value = value[info_value_start:info_end]
            ac_information.append({
                'vendor_id': vendor_id,
                'vendor_name': self._capwap_vendor_name(vendor_id),
                'type': info_type,
                'name': self._capwap_ac_information_type_name(info_type),
                'length': info_length,
                'value_hex': info_value.hex(),
                'text': self._capwap_decode_text(info_value),
                'offset': value_offset + cursor,
                'value_offset': value_offset + info_value_start,
            })
            cursor = info_end

        return {
            'stations': stations,
            'limit_stations': limit_stations,
            'active_wtps': active_wtps,
            'max_wtps': max_wtps,
            'security_flags': security_flags,
            'security_reserved': (security_flags >> 3) & 0x1F,
            'security_pre_shared': bool(security_flags & 0x04),
            'security_x509': bool(security_flags & 0x02),
            'r_mac_field': r_mac_field,
            'r_mac_field_name': {
                0: 'Supported',
                1: 'Reserved',
                2: 'Not Supported',
            }.get(r_mac_field, f'Unknown ({r_mac_field})'),
            'reserved': reserved,
            'dtls_policy_flags': dtls_policy_flags,
            'dtls_reserved': (dtls_policy_flags >> 3) & 0x1F,
            'dtls_data_channel_supported': bool(dtls_policy_flags & 0x04),
            'dtls_clear_text_supported': bool(dtls_policy_flags & 0x02),
            'ac_information': ac_information,
        }

    def _parse_capwap_message_element(self, element_type: int, value: bytes, element_offset: int) -> dict:
        parsed = None
        if element_type == 1:
            parsed = self._parse_capwap_ac_descriptor(value, element_offset + 4)
        elif element_type == 2 and len(value) >= 4:
            parsed = {'address': '.'.join(str(byte) for byte in value[:4])}
        elif element_type == 4:
            parsed = {'name': self._capwap_decode_text(value)}
        elif element_type == 10 and len(value) >= 6:
            parsed = {
                'address': '.'.join(str(byte) for byte in value[:4]),
                'wtp_count': int.from_bytes(value[4:6], 'big'),
            }
        elif element_type == 12 and len(value) >= 2:
            parsed = {
                'discovery_seconds': int(value[0]),
                'echo_request_seconds': int(value[1]),
            }
        elif element_type == 16 and len(value) >= 3:
            parsed = {
                'radio_id': int(value[0]),
                'interval_seconds': int.from_bytes(value[1:3], 'big'),
            }
        elif element_type == 23 and len(value) >= 4:
            parsed = {'timeout_seconds': int.from_bytes(value[:4], 'big')}
        elif element_type == 28:
            parsed = {'text': self._capwap_decode_text(value)}
        elif element_type == 30 and len(value) >= 4:
            parsed = {'address': '.'.join(str(byte) for byte in value[:4])}
        elif element_type == 31 and len(value) >= 2:
            state = int(value[1])
            parsed = {
                'radio_id': int(value[0]),
                'state': state,
                'state_name': {
                    0: 'Disabled',
                    1: 'Enabled',
                }.get(state, f'Unknown ({state})'),
            }
        elif element_type == 32 and len(value) >= 3:
            state = int(value[1])
            cause = int(value[2])
            parsed = {
                'radio_id': int(value[0]),
                'state': state,
                'state_name': {
                    0: 'Disabled',
                    1: 'Enabled',
                }.get(state, f'Unknown ({state})'),
                'cause': cause,
                'cause_name': {
                    0: 'Normal',
                }.get(cause, f'Unknown ({cause})'),
            }
        elif element_type == 33 and len(value) >= 4:
            result_code = int.from_bytes(value[:4], 'big')
            parsed = {
                'value': result_code,
                'name': {
                    0: 'Success',
                }.get(result_code, f'Unknown ({result_code})'),
            }
        elif element_type == 35:
            parsed = {'session_id': value.hex()}
        elif element_type == 36 and len(value) >= 2:
            parsed = {'seconds': int.from_bytes(value[:2], 'big')}
        elif element_type == 38:
            parsed = self._parse_capwap_board_data(value, element_offset + 4)
        elif element_type == 39:
            parsed = self._parse_capwap_descriptor(value, element_offset + 4)
        elif element_type == 40 and value:
            fallback = int(value[0])
            parsed = {
                'value': fallback,
                'name': {
                    0: 'Disabled',
                    1: 'Enabled',
                }.get(fallback, f'Unknown ({fallback})'),
            }
        elif element_type == 41 and value:
            mode = int(value[0])
            parsed = {
                'value': mode,
                'native_frame_tunnel_mode': bool(mode & 0x08),
                'dot3_frame_tunnel_mode': bool(mode & 0x04),
                'local_bridging': bool(mode & 0x02),
                'reserved': mode & 0x01,
            }
        elif element_type == 44 and value:
            mac_type = int(value[0])
            parsed = {
                'value': mac_type,
                'name': {
                    0: 'Local MAC',
                    1: 'Split MAC',
                    2: 'Both',
                }.get(mac_type, f'Unknown ({mac_type})'),
            }
        elif element_type == 45:
            parsed = {'name': self._capwap_decode_text(value)}
        elif element_type == 48:
            parsed = self._parse_capwap_reboot_statistics(value)
        elif element_type == 51 and value:
            transport = int(value[0])
            parsed = {
                'value': transport,
                'name': {
                    1: 'UDP-Lite',
                    2: 'UDP',
                }.get(transport, f'Unknown ({transport})'),
            }
        elif element_type == 53 and value:
            support = int(value[0])
            parsed = {
                'value': support,
                'name': {
                    0: 'Limited ECN Support',
                    1: 'Full and Limited ECN Support',
                }.get(support, f'Unknown ({support})'),
            }
        elif element_type == 1024 and len(value) >= 19:
            capability = int.from_bytes(value[2:4], 'big') if len(value) >= 4 else 0
            key_status = int(value[5]) if len(value) >= 6 else 0
            key_length = int.from_bytes(value[6:8], 'big') if len(value) >= 8 else 0
            key_offset = 8
            key_end = min(len(value), key_offset + key_length)
            group_tsc_offset = key_end
            group_tsc_end = min(len(value), group_tsc_offset + 6)
            qos_offset = group_tsc_end
            qos = int(value[qos_offset]) if qos_offset < len(value) else 0
            auth_offset = qos_offset + 1
            auth_type = int(value[auth_offset]) if auth_offset < len(value) else 0
            mac_mode_offset = auth_offset + 1
            mac_mode = int(value[mac_mode_offset]) if mac_mode_offset < len(value) else 0
            tunnel_mode_offset = mac_mode_offset + 1
            tunnel_mode = int(value[tunnel_mode_offset]) if tunnel_mode_offset < len(value) else 0
            suppress_offset = tunnel_mode_offset + 1
            suppress_value = int(value[suppress_offset]) if suppress_offset < len(value) else 0
            ssid_offset = suppress_offset + 1
            parsed = {
                'radio_id': int(value[0]),
                'wlan_id': int(value[1]),
                'capability': capability,
                'key_index': int(value[4]) if len(value) >= 5 else 0,
                'key_status': key_status,
                'key_status_name': 'SN Information Element means that the WLAN uses per-station encryption keys'
                if key_status == 0 else f'Unknown ({key_status})',
                'key_length': key_length,
                'key_value_hex': value[key_offset:key_end].hex(),
                'group_tsc': int.from_bytes(value[group_tsc_offset:group_tsc_end], 'big') if group_tsc_end > group_tsc_offset else 0,
                'group_tsc_length': max(0, group_tsc_end - group_tsc_offset),
                'qos': qos,
                'qos_name': {0: 'Best Effort'}.get(qos, f'Unknown ({qos})'),
                'auth_type': auth_type,
                'auth_type_name': {0: 'Open System'}.get(auth_type, f'Unknown ({auth_type})'),
                'mac_mode': mac_mode,
                'mac_mode_name': {0: 'Local MAC'}.get(mac_mode, f'Unknown ({mac_mode})'),
                'tunnel_mode': tunnel_mode,
                'tunnel_mode_name': {0: 'Local Bridging'}.get(tunnel_mode, f'Unknown ({tunnel_mode})'),
                'suppress_ssid': bool(suppress_value & 0x01),
                'suppress_ssid_raw': suppress_value,
                'ssid': self._capwap_decode_text(value[ssid_offset:]),
                'key_offset': key_offset,
                'key_end': key_end,
                'group_tsc_offset': group_tsc_offset,
                'qos_offset': qos_offset,
                'auth_offset': auth_offset,
                'mac_mode_offset': mac_mode_offset,
                'tunnel_mode_offset': tunnel_mode_offset,
                'suppress_offset': suppress_offset,
                'ssid_offset': ssid_offset,
                'capability_bits': {
                    'ess': bool(capability & 0x8000),
                    'ibss': bool(capability & 0x4000),
                    'cf_pollable': bool(capability & 0x2000),
                    'cf_poll_request': bool(capability & 0x1000),
                    'privacy': bool(capability & 0x0800),
                    'short_preamble': bool(capability & 0x0400),
                    'pbcc': bool(capability & 0x0200),
                    'channel_agility': bool(capability & 0x0100),
                    'spectrum_management': bool(capability & 0x0080),
                    'qos': bool(capability & 0x0040),
                    'short_slot_time': bool(capability & 0x0020),
                    'apsd': bool(capability & 0x0010),
                    'reserved': bool(capability & 0x0008),
                    'dsss_ofdm': bool(capability & 0x0004),
                    'delayed_block_ack': bool(capability & 0x0002),
                    'immediate_block_ack': bool(capability & 0x0001),
                },
            }
        elif element_type == 1025 and len(value) >= 5:
            diversity = int(value[1])
            combiner = int(value[2])
            selection = int(value[4])
            parsed = {
                'radio_id': int(value[0]),
                'diversity': diversity,
                'diversity_name': {0: 'Disabled'}.get(diversity, f'Unknown ({diversity})'),
                'combiner': combiner,
                'combiner_name': {3: 'Omni'}.get(combiner, f'Unknown ({combiner})'),
                'antenna_count': int(value[3]),
                'selection': selection,
                'selection_name': {1: 'Internal Antenna'}.get(selection, f'Unknown ({selection})'),
            }
        elif element_type == 1026 and len(value) >= 8:
            parsed = {
                'radio_id': int(value[0]),
                'wlan_id': int(value[1]),
                'bssid': self._capwap_format_mac(value[2:8]),
            }
        elif element_type == 1028 and len(value) >= 8:
            parsed = {
                'radio_id': int(value[0]),
                'reserved': int(value[1]),
                'current_channel': int(value[2]),
                'current_cca': int(value[3]),
                'energy_detect_threshold': int.from_bytes(value[4:8], 'big'),
            }
        elif element_type == 1030 and len(value) >= 16:
            parsed = {
                'radio_id': int(value[0]),
                'reserved': int(value[1]),
                'rts_threshold': int.from_bytes(value[2:4], 'big'),
                'short_retry': int(value[4]),
                'long_retry': int(value[5]),
                'fragmentation_threshold': int.from_bytes(value[6:8], 'big'),
                'tx_msdu_lifetime': int.from_bytes(value[8:12], 'big'),
                'rx_msdu_lifetime': int.from_bytes(value[12:16], 'big'),
            }
        elif element_type == 1032 and len(value) >= 8:
            parsed = {
                'radio_id': int(value[0]),
                'reserved': int(value[1]),
                'first_channel': int.from_bytes(value[2:4], 'big'),
                'number_of_channels': int.from_bytes(value[4:6], 'big'),
                'max_tx_power_level': int.from_bytes(value[6:8], 'big'),
            }
        elif element_type == 1040 and value:
            parsed = {
                'radio_id': int(value[0]),
                'rates': [int(rate_byte / 2) for rate_byte in value[1:]],
                'rate_values': list(value[1:]),
            }
        elif element_type == 1041 and len(value) >= 4:
            parsed = {
                'radio_id': int(value[0]),
                'reserved': int(value[1]),
                'current_tx_power': int.from_bytes(value[2:4], 'big'),
            }
        elif element_type == 1042 and len(value) >= 4:
            parsed = {
                'radio_id': int(value[0]),
                'num_levels': int(value[1]),
                'power_level': int.from_bytes(value[2:4], 'big'),
            }
        elif element_type == 1046 and len(value) >= 16:
            parsed = {
                'radio_id': int(value[0]),
                'short_preamble': int(value[1]),
                'num_bssids': int(value[2]),
                'dtim_period': int(value[3]),
                'bssid': self._capwap_format_mac(value[4:10]),
                'beacon_period': int.from_bytes(value[10:12], 'big'),
                'country_string': self._capwap_decode_text(value[12:16]).rstrip('\x00'),
            }
        elif element_type == 1048 and len(value) >= 5:
            radio_flags = int.from_bytes(value[1:5], 'big')
            parsed = {
                'radio_id': int(value[0]),
                'reserved_bits': format((radio_flags >> 4) & 0x3F, '06b'),
                'radio_type_80211n': bool(radio_flags & 0x08),
                'radio_type_80211g': bool(radio_flags & 0x04),
                'radio_type_80211a': bool(radio_flags & 0x02),
                'radio_type_80211b': bool(radio_flags & 0x01),
            }

        return {
            'type': element_type,
            'name': self._capwap_element_name(element_type),
            'length': len(value),
            'value_hex': value.hex(),
            'offset': element_offset,
            'value_offset': element_offset + 4,
            'parsed': parsed,
        }

    def _parse_capwap_message_elements(self, data: bytes, base_offset: int) -> dict | None:
        elements = []
        cursor = 0
        while cursor < len(data):
            remaining = data[cursor:]
            if remaining and all(byte == 0 for byte in remaining):
                return {
                    'elements': elements,
                    'padding': len(remaining),
                }
            if len(remaining) < 4:
                return None
            element_type = int.from_bytes(data[cursor:cursor + 2], 'big')
            element_length = int.from_bytes(data[cursor + 2:cursor + 4], 'big')
            value_start = cursor + 4
            value_end = value_start + element_length
            if value_end > len(data):
                return None
            elements.append(
                self._parse_capwap_message_element(
                    element_type,
                    data[value_start:value_end],
                    base_offset + cursor,
                )
            )
            cursor = value_end

        return {
            'elements': elements,
            'padding': 0,
        }

    def _parse_capwap_payload(self, payload: bytes) -> dict | None:
        if len(payload) < 8:
            return None

        header_word = int.from_bytes(payload[:4], 'big')
        version = (header_word >> 28) & 0x0F
        preamble_type = (header_word >> 24) & 0x0F
        if version != 0 or preamble_type != 0:
            return None

        header_length = (header_word >> 19) & 0x1F
        header_length_bytes = header_length * 4
        if header_length < 2 or len(payload) < header_length_bytes:
            return None

        radio_id = (header_word >> 14) & 0x1F
        wbid = (header_word >> 9) & 0x1F
        payload_type_native = bool((header_word >> 8) & 0x1)
        fragment = bool((header_word >> 7) & 0x1)
        last_fragment = bool((header_word >> 6) & 0x1)
        wireless_header = bool((header_word >> 5) & 0x1)
        radio_mac_header = bool((header_word >> 4) & 0x1)
        keep_alive = bool((header_word >> 3) & 0x1)
        reserved_flags = header_word & 0x7

        fragment_word = int.from_bytes(payload[4:8], 'big')
        fragment_id = (fragment_word >> 16) & 0xFFFF
        fragment_offset = (fragment_word >> 3) & 0x1FFF
        fragment_reserved = fragment_word & 0x7

        def _control_candidate(
            control_header_length: int,
            message_type: int,
            enterprise_number: int,
            sequence_number: int,
            message_element_length: int,
            flags: int,
            control_offset: int | None = None,
        ):
            control_offset = header_length_bytes if control_offset is None else int(control_offset)
            message_offset = control_offset + control_header_length
            actual_message_element_length = int(message_element_length)
            if actual_message_element_length < 0:
                return None

            implicit_padding = 0
            available_message_bytes = len(payload) - message_offset
            if actual_message_element_length > available_message_bytes:
                implicit_padding = actual_message_element_length - available_message_bytes
                if implicit_padding > 3:
                    return None
                actual_message_element_length = available_message_bytes

            parsed_elements = self._parse_capwap_message_elements(
                payload[message_offset:message_offset + actual_message_element_length],
                message_offset,
            )
            if parsed_elements is None:
                return None
            padding_only = int(parsed_elements.get('padding', 0) or 0) == actual_message_element_length
            if not parsed_elements.get('elements') and not padding_only:
                return None

            trailing = payload[message_offset + actual_message_element_length:]
            if trailing and any(byte != 0 for byte in trailing):
                return None

            message_type_value = ((int(enterprise_number) << 8) | int(message_type)) if int(enterprise_number) else int(message_type)
            message_name = self._capwap_message_type_name(message_type_value, enterprise_number, message_type)
            score = len(parsed_elements['elements'])
            if enterprise_number == 0:
                score += 1
            if not message_name.startswith('Control Message'):
                score += 2
            if len(trailing) <= 3:
                score += 1
            if int(parsed_elements.get('padding', 0) or 0) <= 3:
                score += 1
            if implicit_padding == 0:
                score += 1

            return {
                'score': score,
                'control_header_length': control_header_length,
                'transport': 'control',
                'control_header': {
                    'offset': control_offset,
                    'length': control_header_length,
                    'message_type': message_type_value,
                    'message_type_specific': int(message_type),
                    'message_type_enterprise': enterprise_number,
                    'message_type_enterprise_name': self._capwap_enterprise_name(enterprise_number),
                    'message_name': message_name,
                    'sequence_number': sequence_number,
                    'message_element_length': message_element_length,
                    'message_element_actual_length': actual_message_element_length,
                    'flags': flags,
                    'message_element_missing_padding': implicit_padding,
                },
                'message_elements': parsed_elements['elements'],
                'message_element_padding': int(parsed_elements.get('padding', 0) or 0) + max(0, implicit_padding),
            }

        def _data_keepalive_candidate():
            if not keep_alive or len(payload) < header_length_bytes + 2:
                return None
            keepalive_offset = header_length_bytes
            declared_length = int.from_bytes(payload[keepalive_offset:keepalive_offset + 2], 'big')
            if declared_length < 2:
                return None
            message_offset = keepalive_offset + 2
            actual_message_element_length = declared_length - 2
            if actual_message_element_length < 0 or message_offset + actual_message_element_length > len(payload):
                return None
            parsed_elements = self._parse_capwap_message_elements(
                payload[message_offset:message_offset + actual_message_element_length],
                message_offset,
            )
            if parsed_elements is None or not parsed_elements.get('elements'):
                return None
            trailing = payload[message_offset + actual_message_element_length:]
            if trailing and any(byte != 0 for byte in trailing):
                return None
            return {
                'transport': 'data',
                'data_header': {
                    'offset': keepalive_offset,
                    'length': len(payload) - keepalive_offset,
                    'kind': 'keep_alive',
                    'message_element_length': declared_length,
                    'message_element_actual_length': actual_message_element_length,
                },
                'message_elements': parsed_elements['elements'],
                'message_element_padding': int(parsed_elements.get('padding', 0) or 0),
            }

        def _data_wlan_candidate():
            if keep_alive or not payload_type_native or wbid != 1:
                return None
            payload_offset = header_length_bytes
            wlan = self._parse_wlan_association_request(payload[payload_offset:], payload_offset)
            if wlan is None:
                return None
            return {
                'transport': 'data',
                'data_header': {
                    'offset': payload_offset,
                    'length': len(payload) - payload_offset,
                    'kind': 'native_80211',
                },
                'wlan': wlan,
            }

        candidates = []
        if len(payload) >= header_length_bytes + 8:
            message_type_raw = int.from_bytes(payload[header_length_bytes:header_length_bytes + 4], 'big')
            candidates.append(
                _control_candidate(
                    8,
                    message_type_raw & 0xFF,
                    message_type_raw >> 8,
                    int(payload[header_length_bytes + 4]),
                    int.from_bytes(payload[header_length_bytes + 5:header_length_bytes + 7], 'big'),
                    int(payload[header_length_bytes + 7]),
                )
            )
        if len(payload) >= header_length_bytes + 5:
            candidates.append(
                _control_candidate(
                    5,
                    int(payload[header_length_bytes]),
                    0,
                    int(payload[header_length_bytes + 1]),
                    int.from_bytes(payload[header_length_bytes + 2:header_length_bytes + 4], 'big'),
                    int(payload[header_length_bytes + 4]),
                )
            )

        data_keepalive = _data_keepalive_candidate()
        data_wlan = _data_wlan_candidate()
        candidates = [candidate for candidate in candidates if candidate is not None]
        if data_keepalive is not None:
            return {
                'payload_length': len(payload),
                'transport': 'data',
                'preamble': {
                    'version': version,
                    'type': preamble_type,
                },
                'header': {
                    'header_length': header_length,
                    'header_length_bytes': header_length_bytes,
                    'radio_id': radio_id,
                    'wireless_binding_id': wbid,
                    'wireless_binding_name': self._capwap_wbid_name(wbid),
                    'payload_type_native': payload_type_native,
                    'fragment': fragment,
                    'last_fragment': last_fragment,
                    'wireless_header': wireless_header,
                    'radio_mac_header': radio_mac_header,
                    'keep_alive': keep_alive,
                    'reserved_flags': reserved_flags,
                    'header_flags_value': (
                        (int(payload_type_native) << 8)
                        | (int(fragment) << 7)
                        | (int(last_fragment) << 6)
                        | (int(wireless_header) << 5)
                        | (int(radio_mac_header) << 4)
                        | (int(keep_alive) << 3)
                        | reserved_flags
                    ),
                    'fragment_id': fragment_id,
                    'fragment_offset': fragment_offset,
                    'fragment_reserved': fragment_reserved,
                },
                'data_header': data_keepalive['data_header'],
                'message_elements': data_keepalive['message_elements'],
                'message_element_padding': data_keepalive['message_element_padding'],
            }
        if data_wlan is not None:
            return {
                'payload_length': len(payload),
                'transport': 'data',
                'preamble': {
                    'version': version,
                    'type': preamble_type,
                },
                'header': {
                    'header_length': header_length,
                    'header_length_bytes': header_length_bytes,
                    'radio_id': radio_id,
                    'wireless_binding_id': wbid,
                    'wireless_binding_name': self._capwap_wbid_name(wbid),
                    'payload_type_native': payload_type_native,
                    'fragment': fragment,
                    'last_fragment': last_fragment,
                    'wireless_header': wireless_header,
                    'radio_mac_header': radio_mac_header,
                    'keep_alive': keep_alive,
                    'reserved_flags': reserved_flags,
                    'header_flags_value': (
                        (int(payload_type_native) << 8)
                        | (int(fragment) << 7)
                        | (int(last_fragment) << 6)
                        | (int(wireless_header) << 5)
                        | (int(radio_mac_header) << 4)
                        | (int(keep_alive) << 3)
                        | reserved_flags
                    ),
                    'fragment_id': fragment_id,
                    'fragment_offset': fragment_offset,
                    'fragment_reserved': fragment_reserved,
                },
                'data_header': data_wlan['data_header'],
                'wlan': data_wlan['wlan'],
            }
        if not candidates:
            return None

        control = max(candidates, key=lambda candidate: int(candidate.get('score', 0) or 0))
        return {
            'payload_length': len(payload),
            'transport': control['transport'],
            'preamble': {
                'version': version,
                'type': preamble_type,
            },
            'header': {
                'header_length': header_length,
                'header_length_bytes': header_length_bytes,
                'radio_id': radio_id,
                'wireless_binding_id': wbid,
                'wireless_binding_name': self._capwap_wbid_name(wbid),
                'payload_type_native': payload_type_native,
                'fragment': fragment,
                'last_fragment': last_fragment,
                'wireless_header': wireless_header,
                'radio_mac_header': radio_mac_header,
                'keep_alive': keep_alive,
                'reserved_flags': reserved_flags,
                'header_flags_value': (
                    (int(payload_type_native) << 8)
                    | (int(fragment) << 7)
                    | (int(last_fragment) << 6)
                    | (int(wireless_header) << 5)
                    | (int(radio_mac_header) << 4)
                    | (int(keep_alive) << 3)
                    | reserved_flags
                ),
                'fragment_id': fragment_id,
                'fragment_offset': fragment_offset,
                'fragment_reserved': fragment_reserved,
            },
            'control_header': control['control_header'],
            'message_elements': control['message_elements'],
            'message_element_padding': control['message_element_padding'],
        }

    def _update_capwap_metadata(self, packet, metadata: dict):
        effective_udp = self._effective_udp_layer(packet)
        if effective_udp is None:
            return
        sport = int(getattr(effective_udp, 'sport', 0) or 0)
        dport = int(getattr(effective_udp, 'dport', 0) or 0)
        if sport not in {5246, 5247} and dport not in {5246, 5247}:
            return

        capwap = self._parse_capwap_payload(self._payload_bytes(packet))
        if capwap is None:
            return

        metadata['capwap'] = capwap
        metadata['capwap_transport'] = str(capwap.get('transport', '') or '')
        control_header = capwap.get('control_header', {}) or {}
        metadata['capwap_message_type'] = int(control_header.get('message_type', 0) or 0)
        metadata['capwap_message_name'] = str(control_header.get('message_name', '') or '')
        metadata['capwap_message_type_enterprise'] = int(control_header.get('message_type_enterprise', 0) or 0)
        metadata['capwap_message_type_enterprise_name'] = str(control_header.get('message_type_enterprise_name', '') or '')
        data_header = capwap.get('data_header', {}) or {}
        metadata['capwap_data_kind'] = str(data_header.get('kind', '') or '')
        wlan = capwap.get('wlan', {}) or {}
        if wlan:
            metadata['wlan'] = wlan
            metadata['wlan_src'] = str(wlan.get('source', '') or '')
            metadata['wlan_dst'] = str(wlan.get('destination', '') or '')
            metadata['wlan_info'] = str(wlan.get('info', '') or '')

    def _icmpv6_payload_bytes(self, packet) -> bytes:
        if not packet.haslayer(IPv6):
            return b''
        try:
            if packet.haslayer(IPv6ExtHdrHopByHop):
                return bytes(getattr(packet[IPv6ExtHdrHopByHop], 'payload', b''))
            if int(getattr(packet[IPv6], 'nh', -1) or -1) == 58:
                return bytes(getattr(packet[IPv6], 'payload', b''))
        except Exception:
            return b''
        return b''

    def _is_icmpv6_packet(self, packet) -> bool:
        if not packet.haslayer(IPv6):
            return False
        try:
            if packet.haslayer(IPv6ExtHdrHopByHop):
                return int(getattr(packet[IPv6ExtHdrHopByHop], 'nh', -1) or -1) == 58 and len(self._icmpv6_payload_bytes(packet)) >= 4
            return int(getattr(packet[IPv6], 'nh', -1) or -1) == 58 and len(self._icmpv6_payload_bytes(packet)) >= 4
        except Exception:
            return False

    def _icmpv6_info_text(self, packet) -> str | None:
        payload = self._icmpv6_payload_bytes(packet)
        if len(payload) < 4:
            return None

        def _link_layer_address(options: bytes, expected_type: int) -> str | None:
            cursor = 0
            while cursor + 2 <= len(options):
                option_type = int(options[cursor])
                option_units = int(options[cursor + 1])
                if option_units <= 0:
                    break
                option_length = option_units * 8
                actual_length = min(option_length, len(options) - cursor)
                if option_type == expected_type and actual_length >= 8:
                    return ':'.join(f'{byte:02x}' for byte in options[cursor + 2:cursor + 8])
                cursor += option_length
            return None

        icmpv6_type = int(payload[0])
        if icmpv6_type == 143:
            return 'Multicast Listener Report Message v2'
        if icmpv6_type == 133:
            source_mac = _link_layer_address(payload[8:], 1) if len(payload) > 8 else None
            return f'Router Solicitation from {source_mac}' if source_mac else 'Router Solicitation'
        if icmpv6_type == 134:
            return 'Router Advertisement'
        if icmpv6_type == 135:
            if len(payload) >= 24:
                target = str(ipaddress.IPv6Address(payload[8:24]))
                source_mac = _link_layer_address(payload[24:], 1) if len(payload) > 24 else None
                return f'Neighbor Solicitation for {target} from {source_mac}' if source_mac else f'Neighbor Solicitation for {target}'
            return 'Neighbor Solicitation'
        if icmpv6_type == 136:
            if len(payload) >= 24:
                target = str(ipaddress.IPv6Address(payload[8:24]))
                flags = int.from_bytes(payload[4:8], 'big')
                flag_labels = []
                if flags & 0x80000000:
                    flag_labels.append('rtr')
                if flags & 0x40000000:
                    flag_labels.append('sol')
                if flags & 0x20000000:
                    flag_labels.append('ovr')
                target_mac = _link_layer_address(payload[24:], 2) if len(payload) > 24 else None
                info = f'Neighbor Advertisement {target}'
                if flag_labels:
                    info += f' ({", ".join(flag_labels)})'
                if target_mac:
                    info += f' is at {target_mac}'
                return info
            return 'Neighbor Advertisement'
        return {
            128: 'Echo (ping) request',
            129: 'Echo (ping) reply',
            130: 'Multicast Listener Query',
            131: 'Multicast Listener Report',
            132: 'Multicast Listener Done',
        }.get(icmpv6_type, f'ICMPv6 Type {icmpv6_type}')

    def _dhcpv6_message_name(self, msg_type: int) -> str:
        return {
            1: 'Solicit',
            2: 'Advertise',
            3: 'Request',
            4: 'Confirm',
            5: 'Renew',
            6: 'Rebind',
            7: 'Reply',
            8: 'Release',
            9: 'Decline',
            10: 'Reconfigure',
            11: 'Information-request',
            12: 'Relay-forward',
            13: 'Relay-reply',
        }.get(int(msg_type), f'DHCPv6 Type {int(msg_type)}')

    def _dhcpv6_payload_bytes(self, packet) -> bytes:
        udp_layer = self._effective_udp_layer(packet)
        if udp_layer is None or not packet.haslayer(IPv6):
            return b''
        return bytes(udp_layer.payload)

    def _is_dhcpv6_packet(self, packet) -> bool:
        udp_layer = self._effective_udp_layer(packet)
        if udp_layer is None or not packet.haslayer(IPv6):
            return False
        try:
            sport = int(getattr(udp_layer, 'sport', 0) or 0)
            dport = int(getattr(udp_layer, 'dport', 0) or 0)
        except Exception:
            return False
        if sport not in {546, 547} and dport not in {546, 547}:
            return False
        payload = bytes(udp_layer.payload)
        return len(payload) >= 4 and int(payload[0]) in {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}

    def _dhcpv6_client_id(self, payload: bytes) -> str:
        cursor = 4
        while cursor + 4 <= len(payload):
            option_code = int.from_bytes(payload[cursor:cursor + 2], 'big')
            option_length = int.from_bytes(payload[cursor + 2:cursor + 4], 'big')
            value_start = cursor + 4
            value_end = value_start + option_length
            if value_end > len(payload):
                break
            if option_code == 1:
                return payload[value_start:value_end].hex()
            cursor = value_end
        return ''

    def _dhcpv6_info_text(self, packet) -> str | None:
        payload = self._dhcpv6_payload_bytes(packet)
        if len(payload) < 4:
            return None
        msg_type = int(payload[0])
        xid = int.from_bytes(payload[1:4], 'big')
        info = f'{self._dhcpv6_message_name(msg_type)} XID: 0x{xid:06x}'
        client_id = self._dhcpv6_client_id(payload)
        if client_id:
            info += f' CID: {client_id} '
        return info

    def _guess_protocol(self, packet, metadata: dict | None = None):
        metadata = metadata or {}
        eth_type = self._ether_type(packet)
        effective_ip = self._effective_ip_layer(packet)
        effective_tcp = self._effective_tcp_layer(packet, effective_ip)
        effective_udp = self._effective_udp_layer(packet, effective_ip)

        def _ensure_capwap_metadata() -> dict | None:
            capwap = metadata.get('capwap', None)
            if isinstance(capwap, dict) and capwap:
                return capwap
            parsed = self._parse_capwap_payload(self._payload_bytes(packet))
            if parsed is None:
                return None
            metadata['capwap'] = parsed
            metadata['capwap_transport'] = str(parsed.get('transport', '') or '')
            control_header = parsed.get('control_header', {}) or {}
            metadata['capwap_message_type'] = int(control_header.get('message_type', 0) or 0)
            metadata['capwap_message_name'] = str(control_header.get('message_name', '') or '')
            metadata['capwap_message_type_enterprise'] = int(control_header.get('message_type_enterprise', 0) or 0)
            metadata['capwap_message_type_enterprise_name'] = str(control_header.get('message_type_enterprise_name', '') or '')
            data_header = parsed.get('data_header', {}) or {}
            metadata['capwap_data_kind'] = str(data_header.get('kind', '') or '')
            wlan = parsed.get('wlan', {}) or {}
            if wlan:
                metadata['wlan'] = wlan
                metadata['wlan_src'] = str(wlan.get('source', '') or '')
                metadata['wlan_dst'] = str(wlan.get('destination', '') or '')
                metadata['wlan_info'] = str(wlan.get('info', '') or '')
            return parsed

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
        if isinstance(metadata.get('wlan', None), dict) and metadata.get('wlan'):
            return '802.11'
        if str(metadata.get('capwap_transport', '') or '') == 'control':
            return 'CAPWAP-Control'
        if str(metadata.get('capwap_transport', '') or '') == 'data':
            if isinstance(metadata.get('wlan', None), dict) and metadata.get('wlan'):
                return '802.11'
            return 'CAPWAP-Data'
        if effective_udp is not None:
            sport = int(getattr(effective_udp, 'sport', 0) or 0)
            dport = int(getattr(effective_udp, 'dport', 0) or 0)
            if (sport in {5246, 5247} or dport in {5246, 5247}) and _ensure_capwap_metadata() is not None:
                if str(metadata.get('capwap_transport', '') or '') == 'control':
                    return 'CAPWAP-Control'
                if str(metadata.get('capwap_transport', '') or '') == 'data':
                    if isinstance(metadata.get('wlan', None), dict) and metadata.get('wlan'):
                        return '802.11'
                    return 'CAPWAP-Data'
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
            if not bool(metadata.get('http_incomplete', False)) and str(metadata.get('http_kind', '') or ''):
                return 'HTTP'
        if packet.haslayer(ARP) and eth_type != 0x8035:
            return 'ARP'
        if self._is_dhcpv6_packet(packet):
            return 'DHCPv6'
        if packet.haslayer(DHCP) or packet.haslayer(BOOTP):
            return 'DHCP'
        if packet.haslayer(DNS):
            qname = self._dns_qname(packet)
            if qname.endswith('.local'):
                return 'MDNS'
            return 'DNS'
        igmp_summary = self._igmp_summary(packet)
        if igmp_summary is not None:
            return str(igmp_summary.get('version', 'IGMP'))
        if effective_tcp is not None:
            sport = int(getattr(effective_tcp, 'sport', 0) or 0)
            dport = int(getattr(effective_tcp, 'dport', 0) or 0)
            payload = self._payload_bytes(packet)
            if (
                not bool(metadata.get('http_incomplete', False))
                and (sport in {80, 3128, 8080} or dport in {80, 3128, 8080})
                and self._http_payload_kind(payload) is not None
            ):
                return 'HTTP'
        if (
            not bool(metadata.get('http_incomplete', False))
            and (packet.haslayer(HTTPResponse) or packet.haslayer(HTTPRequest))
        ):
            return 'HTTP'
        if packet.haslayer(TLSClientHello) or packet.haslayer(TLS):
            tls_summary = self._tls_record_summary(packet)
            if tls_summary is not None:
                return str(tls_summary.get('version_name', 'TLS'))
            return 'TLS'
        if packet.haslayer(QUIC):
            return 'QUIC'
        if self._is_icmpv6_packet(packet):
            return 'ICMPv6'
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

    def _tls_version_name(self, version: int) -> str:
        return {
            0x0301: 'TLSv1.0',
            0x0302: 'TLSv1.1',
            0x0303: 'TLSv1.2',
            0x0304: 'TLSv1.3',
        }.get(int(version or 0), 'TLS')

    def _tls_handshake_type_name(self, handshake_type: int) -> str:
        return {
            1: 'Client Hello',
            2: 'Server Hello',
            4: 'New Session Ticket',
            8: 'Encrypted Extensions',
            11: 'Certificate',
            12: 'Server Key Exchange',
            13: 'Certificate Request',
            14: 'Server Hello Done',
            15: 'Certificate Verify',
            16: 'Client Key Exchange',
            20: 'Finished',
        }.get(int(handshake_type or -1), f'Handshake ({int(handshake_type or 0)})')

    def _tls_record_summary(self, packet) -> dict | None:
        payload = self._payload_bytes(packet)
        if len(payload) < 5:
            return None

        content_type = int(payload[0])
        version = int.from_bytes(payload[1:3], 'big')
        record_len = int.from_bytes(payload[3:5], 'big')
        summary = {
            'content_type': content_type,
            'version': version,
            'version_name': self._tls_version_name(version),
            'record_len': record_len,
        }

        if content_type == 22 and len(payload) >= 9:
            handshake_type = int(payload[5])
            summary['handshake_type'] = handshake_type
            summary['handshake_name'] = self._tls_handshake_type_name(handshake_type)
            summary['handshake_len'] = int.from_bytes(payload[6:9], 'big')
            if handshake_type == 1 and len(payload) >= 11:
                hello_version = int.from_bytes(payload[9:11], 'big')
                summary['handshake_version'] = hello_version
                summary['version_name'] = self._tls_version_name(hello_version)

        return summary

    def _igmp_summary(self, packet) -> dict | None:
        effective_ip = self._effective_ip_layer(packet)
        if effective_ip is None:
            return None
        try:
            if int(getattr(effective_ip, 'proto', 0) or 0) != 2:
                return None
        except Exception:
            return None

        payload = self._ip_payload_bytes(packet, effective_ip)
        if len(payload) < 8:
            return None

        igmp_type = int(payload[0])
        group_address = '.'.join(str(int(b)) for b in payload[4:8])
        summary = {
            'type': igmp_type,
            'group_address': group_address,
            'version': 'IGMP',
            'info': 'Internet Group Management Protocol',
        }

        if igmp_type == 0x11 and len(payload) >= 12:
            summary['version'] = 'IGMPv3'
            summary['qrv'] = int(payload[8] & 0x07)
            summary['qqic'] = int(payload[9])
            summary['num_src'] = int.from_bytes(payload[10:12], 'big')
            if group_address == '0.0.0.0':
                summary['info'] = 'Membership Query, general'
            else:
                summary['info'] = f'Membership Query, specific for {group_address}'
            return summary

        summary['info'] = {
            0x11: 'Membership Query',
            0x12: 'Version 1 Membership Report',
            0x16: 'Version 2 Membership Report',
            0x17: 'Leave Group',
            0x22: 'Version 3 Membership Report',
        }.get(igmp_type, f'IGMP Type 0x{igmp_type:02x}')
        return summary

    def _tcp_window_scale_shift(self, tcp_layer) -> int | None:
        for option in getattr(tcp_layer, 'options', []) or []:
            if not isinstance(option, tuple) or not option:
                continue
            name = str(option[0])
            value = option[1] if len(option) > 1 else None
            if name == 'WScale':
                try:
                    return int(value)
                except Exception:
                    return None
        return None

    def _tcp_info_options(self, tcp_layer) -> list[str]:
        tokens = []
        for option in getattr(tcp_layer, 'options', []) or []:
            if not isinstance(option, tuple) or not option:
                continue
            name = str(option[0])
            value = option[1] if len(option) > 1 else None
            if name == 'MSS':
                tokens.append(f'MSS={int(value)}')
            elif name == 'WScale':
                shift = int(value)
                tokens.append(f'WS={1 << shift}')
            elif name == 'SAckOK':
                tokens.append('SACK_PERM')
        return tokens

    def _http_payload_kind(self, payload: bytes) -> str | None:
        if not payload:
            return None
        request_prefixes = (
            b'GET ', b'POST ', b'HEAD ', b'PUT ', b'DELETE ',
            b'OPTIONS ', b'PATCH ', b'TRACE ', b'CONNECT '
        )
        if any(payload.startswith(prefix) for prefix in request_prefixes):
            return 'request'
        if payload.startswith(b'HTTP/1.') or payload.startswith(b'HTTP/2'):
            return 'response'
        return None

    def _http_request_parts(self, payload: bytes) -> tuple[str, str, str]:
        try:
            line = payload.split(b'\r\n', 1)[0].decode(errors='ignore').strip()
            parts = line.split(' ', 2)
            if len(parts) == 3:
                return parts[0], parts[1], parts[2]
        except Exception:
            pass
        return '', '', ''

    def _http_response_parts(self, payload: bytes) -> tuple[str, str, str]:
        try:
            line = payload.split(b'\r\n', 1)[0].decode(errors='ignore').strip()
            parts = line.split(' ', 2)
            if len(parts) >= 2:
                return parts[0], parts[1], parts[2] if len(parts) > 2 else ''
        except Exception:
            pass
        return '', '', ''

    def _http_headers(self, payload: bytes) -> dict[str, str]:
        headers = {}
        try:
            header_blob = payload.split(b'\r\n\r\n', 1)[0]
            for raw_line in header_blob.split(b'\r\n')[1:]:
                if b':' not in raw_line:
                    continue
                name, value = raw_line.split(b':', 1)
                headers[name.decode(errors='ignore').strip().lower()] = value.decode(errors='ignore').strip()
        except Exception:
            pass
        return headers

    def _http_content_length(self, headers: dict[str, str]) -> int:
        try:
            return max(0, int(str(headers.get('content-length', '0') or '0').strip()))
        except Exception:
            return 0

    def _http_message_length(self, payload: bytes) -> tuple[str, int | None, int | None, dict[str, str]] | None:
        kind = self._http_payload_kind(payload)
        if kind is None:
            return None

        header_end = payload.find(b'\r\n\r\n')
        if header_end == -1:
            return kind, None, None, {}

        header_len = header_end + 4
        headers = self._http_headers(payload[:header_len])
        total_len = header_len + self._http_content_length(headers)
        return kind, header_len, total_len, headers

    def _find_stream_record(self, state: dict, frame_number: int) -> PacketRecord | None:
        for stream_record in reversed(state.get('records', [])):
            if int(getattr(stream_record, 'number', 0) or 0) == int(frame_number):
                return stream_record
        return None

    def _update_http_stream_metadata(self, packet, metadata: dict, epoch_time: float) -> None:
        effective_ip = self._effective_ip_layer(packet)
        tcp_layer = self._effective_tcp_layer(packet, effective_ip)
        if effective_ip is None or tcp_layer is None:
            return

        payload = self._payload_bytes(packet)
        if not payload:
            return

        src = str(effective_ip.src)
        dst = str(effective_ip.dst)
        sport = int(getattr(tcp_layer, 'sport', 0) or 0)
        dport = int(getattr(tcp_layer, 'dport', 0) or 0)
        stream_key = self._canonical_transport_key(src, sport, dst, dport, 'TCP')
        state = self.transport_stream_state.get(stream_key)
        if state is None:
            return

        dir_key = (src, sport, dst, dport)
        frame_number = int(metadata.get('frame_number', 0) or 0)
        http_state = state.setdefault('http', {})
        pending_by_dir = http_state.setdefault('pending_by_dir', {})
        pending = pending_by_dir.get(dir_key)

        candidate = bytes(payload)
        if pending is not None:
            candidate = bytes(pending.get('payload', b'')) + candidate

        length_info = self._http_message_length(candidate)
        if length_info is None:
            return

        kind, header_len, total_len, headers = length_info
        segment_start = len(bytes(pending.get('payload', b''))) if pending is not None else 0
        current_segment = {
            'frame_number': frame_number,
            'payload_start': int(segment_start),
            'payload_length': int(len(payload)),
        }

        if header_len is None or total_len is None:
            segments = list(pending.get('segments', [])) if pending is not None else []
            segments.append(current_segment)
            pending_by_dir[dir_key] = {
                'payload': candidate,
                'kind': kind,
                'segments': segments,
                'start_epoch': float(pending.get('start_epoch', epoch_time) if pending is not None else epoch_time),
            }
            metadata['http_incomplete'] = True
            metadata['http_kind'] = kind
            return

        current_segment['payload_length'] = int(max(0, min(len(payload), total_len - segment_start)))
        if current_segment['payload_length'] <= 0:
            current_segment['payload_length'] = int(len(payload))

        segments = list(pending.get('segments', [])) if pending is not None else []
        segments.append(current_segment)

        if len(candidate) < total_len:
            pending_by_dir[dir_key] = {
                'payload': candidate,
                'kind': kind,
                'segments': segments,
                'header_len': int(header_len),
                'expected_total_len': int(total_len),
                'headers': headers,
                'start_epoch': float(pending.get('start_epoch', epoch_time) if pending is not None else epoch_time),
            }
            metadata['http_incomplete'] = True
            metadata['http_kind'] = kind
            return

        if pending is not None:
            pending_by_dir.pop(dir_key, None)

        full_payload = candidate[:total_len]
        content_length = self._http_content_length(headers)
        content_type = str(headers.get('content-type', '') or '').split(';', 1)[0].strip()
        body = full_payload[header_len:]

        metadata['http_kind'] = kind
        metadata['http_header_len'] = int(header_len)
        metadata['http_content_length'] = int(content_length)
        metadata['http_reassembled_payload'] = full_payload
        metadata['http_reassembled_length'] = int(total_len)
        metadata['http_reassembled_segments'] = segments
        metadata['http_reassembled_segment_count'] = int(len(segments))
        metadata['http_body'] = body
        if content_type:
            metadata['http_content_type'] = content_type
        if content_type.startswith('text/') and body:
            metadata['http_has_line_based_text'] = True
        if len(segments) > 1:
            metadata['http_is_reassembled'] = True

            for segment in segments[:-1]:
                segment_record = self._find_stream_record(state, int(segment.get('frame_number', 0) or 0))
                if segment_record is None:
                    continue
                segment_record.metadata['tcp_reassembled_pdu_in_frame'] = frame_number
                segment_record.protocol = 'TCP'
                segment_record.info = self._build_info(segment_record.raw, 'TCP', segment_record.metadata)

            metadata['tcp_reassembled_segments'] = segments
            metadata['tcp_reassembled_length'] = int(total_len)
            metadata['tcp_reassembled_data_hex'] = full_payload.hex()

    def _update_http_metadata(self, record: PacketRecord) -> None:
        if str(getattr(record, 'protocol', '') or '').upper() != 'HTTP':
            return

        packet = getattr(record, 'raw', None)
        if packet is None:
            return

        payload = record.metadata.get('http_reassembled_payload', None)
        if payload is None:
            payload = self._payload_bytes(packet)
        kind = str(record.metadata.get('http_kind', '') or '') or self._http_payload_kind(payload)
        if kind is None:
            return

        effective_ip = self._effective_ip_layer(packet)
        tcp_layer = self._effective_tcp_layer(packet, effective_ip)
        if effective_ip is None or tcp_layer is None:
            return

        stream_key = self._canonical_transport_key(
            str(effective_ip.src),
            int(getattr(tcp_layer, 'sport', 0) or 0),
            str(effective_ip.dst),
            int(getattr(tcp_layer, 'dport', 0) or 0),
            'TCP',
        )

        if kind == 'request':
            _, path, _ = self._http_request_parts(payload)
            headers = self._http_headers(payload)
            record.metadata['http_request_uri'] = path
            host = headers.get('host', '')
            if path.startswith('http://') or path.startswith('https://'):
                record.metadata['http_full_request_uri'] = path
            elif host:
                record.metadata['http_full_request_uri'] = f'http://{host}{path or "/"}'
            self.http_request_pending.setdefault(stream_key, []).append(record)
            return

        pending = self.http_request_pending.get(stream_key)
        if not pending:
            return

        request_record = pending.pop(0)
        request_record.metadata['http_response_frame'] = int(record.number)
        record.metadata['http_request_frame'] = int(request_record.number)
        request_uri = str(request_record.metadata.get('http_request_uri', '') or '')
        if request_uri:
            record.metadata['http_request_uri'] = request_uri
        full_request_uri = str(request_record.metadata.get('http_full_request_uri', '') or '')
        if full_request_uri:
            record.metadata['http_full_request_uri'] = full_request_uri
        response_delta = (Decimal(str(record.epoch_time)) - Decimal(str(request_record.epoch_time))) * Decimal('1000')
        response_ms = max(0.0, float(response_delta))
        record.metadata['http_time_since_request_ms'] = float(response_ms)
        if not pending:
            self.http_request_pending.pop(stream_key, None)

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
            if protocol == 'CAPWAP-Control':
                message_name = str(metadata.get('capwap_message_name', '') or '').strip()
                if message_name:
                    return f'CAPWAP-Control - {message_name}'
                return 'CAPWAP-Control'
            if protocol == 'CAPWAP-Data':
                if str(metadata.get('capwap_data_kind', '') or '') == 'keep_alive':
                    return 'CAPWAP-Data Keep-Alive'
                return 'CAPWAP-Data'
            if protocol == '802.11':
                wlan_info = str(metadata.get('wlan_info', '') or '').strip()
                if wlan_info:
                    return wlan_info
                return 'IEEE 802.11'
            if protocol in {'DNS', 'MDNS'}:
                dns = packet[DNS]
                qname = self._dns_qname(packet)
                qtype_name = ''
                try:
                    qtype_value = int(getattr(getattr(dns, 'qd', None), 'qtype', 0) or 0)
                    qtype_name = {
                        1: 'A',
                        2: 'NS',
                        5: 'CNAME',
                        12: 'PTR',
                        15: 'MX',
                        16: 'TXT',
                        28: 'AAAA',
                    }.get(qtype_value, str(qtype_value))
                except Exception:
                    qtype_name = ''
                if getattr(dns, 'qr', 0) == 0:
                    qtype_prefix = f'{qtype_name} ' if qtype_name else ''
                    return f'Standard query 0x{getattr(dns, "id", 0):04x} {qtype_prefix}{qname or "(unknown)"}'
                answer_suffix = ''
                try:
                    first_answer = getattr(dns, 'an', None)
                    answer_type = int(getattr(first_answer, 'type', 0) or 0) if first_answer is not None else 0
                    answer_data = getattr(first_answer, 'rdata', '') if first_answer is not None else ''
                    answer_type_name = {
                        1: 'A',
                        2: 'NS',
                        5: 'CNAME',
                        12: 'PTR',
                        15: 'MX',
                        16: 'TXT',
                        28: 'AAAA',
                    }.get(answer_type, str(answer_type)) if answer_type else ''
                    if answer_type_name and answer_data:
                        answer_suffix = f' {answer_type_name} {answer_data}'
                except Exception:
                    answer_suffix = ''
                qtype_prefix = f'{qtype_name} ' if qtype_name else ''
                return f'Standard query response 0x{getattr(dns, "id", 0):04x} {qtype_prefix}{qname or "(unknown)"}{answer_suffix}'
            if protocol == 'DHCPv6':
                return self._dhcpv6_info_text(packet) or 'DHCPv6'
            if protocol == 'DHCP':
                bootp_layer = packet[BOOTP] if packet.haslayer(BOOTP) else None
                dhcp_layer = packet[DHCP] if packet.haslayer(DHCP) else None
                xid = int(getattr(bootp_layer, 'xid', 0) or 0) if bootp_layer is not None else 0
                message_type = None
                if dhcp_layer is not None:
                    for option in getattr(dhcp_layer, 'options', []):
                        if isinstance(option, tuple) and option and option[0] == 'message-type':
                            message_type = int(option[1])
                            break
                message_name = {
                    1: 'Discover',
                    2: 'Offer',
                    3: 'Request',
                    4: 'Decline',
                    5: 'ACK',
                    6: 'NAK',
                    7: 'Release',
                    8: 'Inform',
                }.get(message_type, 'Request')
                return f'DHCP {message_name:<8} - Transaction ID 0x{xid:08x}'
            if protocol == 'HTTP':
                payload = metadata.get('http_reassembled_payload', self._payload_bytes(packet))
                kind = str(metadata.get('http_kind', '') or '') or self._http_payload_kind(payload)
                if kind == 'request':
                    method, path, version = self._http_request_parts(payload)
                    if method or path or version:
                        return f'{method} {path} {version} '
                if kind == 'response':
                    version, code, reason = self._http_response_parts(payload)
                    response_text = ' '.join(part for part in (version, code, reason) if part)
                    if response_text:
                        content_type = str(metadata.get('http_content_type', '') or '').strip()
                        if content_type:
                            return f'{response_text}  ({content_type})'
                        return f'{response_text} '
                return 'HTTP'
            if protocol.startswith('TLS'):
                tls_summary = self._tls_record_summary(packet)
                if tls_summary is None:
                    return 'Transport Layer Security'
                content_type = int(tls_summary.get('content_type', 0) or 0)
                if content_type == 22 and tls_summary.get('handshake_name'):
                    return str(tls_summary.get('handshake_name'))
                return {
                    20: 'Change Cipher Spec',
                    21: 'Alert',
                    22: 'Handshake',
                    23: 'Application Data',
                }.get(content_type, 'Transport Layer Security')
            if protocol in {'IGMP', 'IGMPv3'}:
                igmp_summary = self._igmp_summary(packet)
                if igmp_summary is not None:
                    return str(igmp_summary.get('info', 'Internet Group Management Protocol'))
                return 'Internet Group Management Protocol'
            if protocol == 'QUIC':
                return 'QUIC'
            if protocol == 'TCP':
                tcp = self._effective_tcp_layer(packet)
                if tcp is None:
                    return packet.summary()
                flags_str = self._tcp_flags_to_string(tcp.flags)
                seq = int(metadata.get('tcp_relative_seq', tcp.seq) or 0)
                ack = int(metadata.get('tcp_relative_ack', tcp.ack) or 0)
                win = int(getattr(tcp, 'window', 0) or 0)
                display_window = int(win)
                tcp_flags = int(getattr(tcp, 'flags', 0) or 0)
                if not bool(tcp_flags & 0x02):
                    try:
                        shift = metadata.get('tcp_window_scale_shift', None)
                        if shift is not None:
                            display_window = int(win) * (1 << int(shift))
                    except Exception:
                        display_window = int(win)
                payload_len = self._tcp_payload_length(packet, tcp)
                has_ack_flag = bool(int(getattr(tcp, 'flags', 0) or 0) & 0x10)
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
                parts = [f'{prefix}{tcp.sport} → {tcp.dport} [{flags_str}] Seq={seq}']
                if has_ack_flag:
                    parts.append(f'Ack={ack}')
                parts.append(f'Win={display_window}')
                parts.append(f'Len={payload_len}')
                reassembled_pdu_frame = metadata.get('tcp_reassembled_pdu_in_frame', None)
                if reassembled_pdu_frame is not None:
                    parts.append(f'[TCP PDU reassembled in {int(reassembled_pdu_frame)}]')
                parts.extend(self._tcp_info_options(tcp))
                return ' '.join(parts)
            if protocol == 'UDP':
                udp = self._effective_udp_layer(packet)
                if udp is None:
                    return packet.summary()
                payload_len = max(0, udp.len - 8)
                return f'{udp.sport} -> {udp.dport} Len={payload_len}'
            if protocol == 'ICMPv6':
                return self._icmpv6_info_text(packet) or packet.summary()
            if protocol == 'ICMP':
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

    def _update_dns_metadata(self, packet, record: PacketRecord) -> None:
        if not packet.haslayer(DNS):
            return

        dns = packet[DNS]
        qname = self._dns_qname(packet)
        try:
            qtype = int(getattr(getattr(dns, 'qd', None), 'qtype', 0) or 0)
        except Exception:
            qtype = 0

        dns_id = int(getattr(dns, 'id', 0) or 0)
        src = str(getattr(record, 'src', '') or '')
        dst = str(getattr(record, 'dst', '') or '')
        sport = int(getattr(record, 'sport', 0) or 0)
        dport = int(getattr(record, 'dport', 0) or 0)
        is_response = bool(int(getattr(dns, 'qr', 0) or 0))

        if not is_response:
            key = (dns_id, qname, qtype, src, dst, sport, dport)
            self.dns_request_pending[key] = record
            return

        reverse_key = (dns_id, qname, qtype, dst, src, dport, sport)
        request_record = self.dns_request_pending.pop(reverse_key, None)
        if request_record is None:
            return

        request_record.metadata['dns_response_frame'] = int(record.number)
        record.metadata['dns_request_frame'] = int(request_record.number)
        response_ms = max(0.0, (float(record.epoch_time) - float(request_record.epoch_time)) * 1000.0)
        record.metadata['dns_time_ms'] = float(response_ms)

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
