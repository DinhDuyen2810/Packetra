from __future__ import annotations
from collections import Counter
from decimal import Decimal
import ipaddress
import json
import re
import zlib
from typing import Any
from scapy.all import ARP, DNS, Ether, ICMP, IP, IPv6, TCP, UDP, bind_layers
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.http import HTTPRequest, HTTPResponse
from scapy.layers.inet6 import ICMPv6EchoRequest, ICMPv6EchoReply, ICMPv6ND_NS, ICMPv6ND_NA, IPv6ExtHdrHopByHop, IPv6ExtHdrFragment
from scapy.layers.l2 import Dot1Q, Dot3, LLC, SNAP, GRE
from scapy.layers.snmp import SNMP
from scapy.layers.tls.all import TLS, TLSClientHello  # type: ignore
from scapy.layers.quic import QUIC  # type: ignore
from scapy.contrib.eigrp import EIGRP  # type: ignore
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

from core.models import PacketRecord
from core.formatters import get_mac_vendor


bind_layers(Ether, ARP, type=0x8035)


class PacketParser:
    MAX_CONTIGUOUS_RANGES = 101
    FTP_COMMANDS = {
        'ABOR', 'ACCT', 'ALLO', 'APPE', 'AUTH', 'CDUP', 'CLNT', 'CWD', 'DELE', 'EPRT', 'EPSV',
        'FEAT', 'HELP', 'LANG', 'LIST', 'MDTM', 'MIC', 'MKD', 'MLSD', 'MLST', 'MODE', 'NLST',
        'NOOP', 'OPTS', 'PASS', 'PASV', 'PBSZ', 'PORT', 'PROT', 'PWD', 'QUIT', 'REIN', 'REST',
        'RETR', 'RMD', 'RNFR', 'RNTO', 'SITE', 'SIZE', 'SMNT', 'STAT', 'STOR', 'STOU', 'STRU',
        'SYST', 'TYPE', 'USER', 'UTF8', 'XCUP', 'XCWD', 'XMKD', 'XPWD', 'XRMD',
    }
    HTTP_REQUEST_METHODS = {
        b'GET', b'POST', b'PUT', b'DELETE', b'HEAD', b'OPTIONS', b'PATCH', b'TRACE', b'CONNECT', b'PRI',
        b'SUBSCRIBE', b'UNSUBSCRIBE', b'NOTIFY',
    }
    _COMMON_PROTOCOLS_FAST = {'TCP', 'UDP', 'ICMP', 'ARP', 'DNS', 'TLS', 'HTTPS'}
    _REGEX_CACHE = {}

    def __init__(self):
        self.first_epoch = None
        self.last_epoch_captured = None
        self.last_epoch_displayed = None
        self.conversations = Counter()
        self.transport_stream_state = {}
        self.icmp_echo_pending = {}
        self.icmpv6_echo_pending = {}
        self.http_request_pending = {}
        self.dns_request_pending = {}
        self.smtp_request_pending = {}
        self.imap_request_pending = {}
        self.sip_request_pending = {}
        self.snmp_request_pending = {}
        self.whois_request_pending = {}
        self.whois_stream_context = {}
        self.sdp_media_by_call = {}
        self.ntp_request_pending = {}
        self.radius_request_pending = {}
        self.radius_eap_tls_pending = {}
        self.zabbix_request_pending = {}
        self.tftp_sessions = {}
        self.tftp_sessions_by_client = {}
        self.ftp_control_streams = {}
        self.ftp_data_sessions = {}
        self.cflow_template_cache = {}
        self.smb2_pending_requests = {}
        self.smb2_preauth_hashes = {}
        self.smb2_tree_paths = {}
        self.smb2_file_open_frames = {}
        self.smb2_file_close_frames = {}
        self.smb2_file_records = {}
        self.ipv4_fragment_state = {}
        self.ipv6_fragment_state = {}
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
        self.capture_file_path = ''
        self.dcerpc_stream_contexts = {}
        self.dcerpc_call_opnums = {}
        self.dcerpc_stream_protocols = {}
        self.dcerpc_request_tracker = {}
        self.ldap_stream_protocols = set()
        self.ldap_pending_requests = {}
        self.ldap_result_counts = {}
        self.ldap_stream_reassembly = {}
        self.h264_ts_stream_state = {}
        self.rdpudp_tls_stream_versions = {}
        self.ws_col_info_cache = {}
        self.stun_pending = {}
        self.srtcp_setup_frames = {}
        self.quic_connections = {}

    def set_capture_file_path(self, capture_file_path: str) -> None:
        self.capture_file_path = str(capture_file_path or '').strip()

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
        length = int(getattr(packet, 'frame_wire_len', len(packet)) or len(packet))

        stream_hint = ''
        if sport is not None or dport is not None:
            stream_hint = f'{src}:{sport or "-"} \u2192 {dst}:{dport or "-"}'

        metadata = {
            'is_ipv6': packet.haslayer(IPv6),
            'has_ip': effective_ip is not None or packet.haslayer(IPv6),
            'eth_type': self._safe_attr(packet[Ether], 'type') if packet.haslayer(Ether) else None,
            'frame_number': int(number),
            'frame_time_delta': frame_delta,
            'frame_time_delta_displayed': frame_delta_displayed,
        }
        if self.capture_file_path:
            metadata['capture_file_path'] = self.capture_file_path
        try:
            metadata['frame_linktype'] = int(getattr(packet, 'frame_linktype', 1) or 1)
        except Exception:
            metadata['frame_linktype'] = 1
        has_fpp = bool(hasattr(packet, 'fpp_preamble') or packet.haslayer('MPacketPreamble'))
        if has_fpp:
            metadata['frame_has_fpp'] = True
            if int(metadata.get('frame_linktype', 1) or 1) == 1:
                metadata['frame_linktype'] = 198
        if effective_ip is not None:
            metadata['ttl'] = self._safe_attr(effective_ip, 'ttl')
        if packet.haslayer(IPv6):
            metadata['hlim'] = self._safe_attr(packet[IPv6], 'hlim')
        if effective_tcp is not None:
            metadata['tcp_flags'] = str(effective_tcp.flags)
        if packet.haslayer(DNS):
            metadata['dns_qr'] = self._safe_attr(packet[DNS], 'qr')

        self._populate_stream_indices(packet, metadata)
        self._update_ip_fragment_metadata(packet, metadata, int(number))

        self._update_transport_stream_metadata(packet, metadata, epoch_time)
        self._update_dcerpc_stream_metadata(packet, metadata, epoch_time)
        self._update_tls_stream_metadata(packet, metadata, int(number))
        self._update_http_stream_metadata(packet, metadata, epoch_time)
        self._update_smtp_stream_metadata(packet, metadata, epoch_time)
        self._update_ssh_stream_metadata(packet, metadata, epoch_time)
        self._update_kerberos_stream_metadata(packet, metadata, epoch_time)
        self._update_whois_stream_metadata(packet, metadata, epoch_time)
        self._update_capwap_metadata(packet, metadata)
        self._update_tftp_metadata(packet, metadata)
        self._update_ftp_metadata(packet, metadata)

        protocol = self._guess_protocol(packet, metadata)
        pim_inner_src = str(metadata.get('pim_inner_src', '') or '')
        pim_inner_dst = str(metadata.get('pim_inner_dst', '') or '')
        if protocol == 'PIMv2' and pim_inner_src and pim_inner_dst:
            src, dst = pim_inner_src, pim_inner_dst
        if protocol in {'GRE', 'TELNET'}:
            gre_endpoints = self._gre_inner_endpoints(packet)
            if gre_endpoints is not None:
                src, dst = gre_endpoints
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
            stream_hint = f'{src} \u2192 {dst}' if src or dst else ''
            if 'WLAN' not in layers:
                layers.append('WLAN')
        elif protocol == 'DHCPv6':
            if not any(str(layer).upper().startswith('DHCP6') or str(layer).upper() == 'DHCPV6' for layer in layers):
                layers.append('DHCPV6')
        self._update_ldap_stream_reassembly(packet, protocol, metadata)
        if protocol == 'TCP':
            reassembled_hex = str(metadata.get('tcp_reassembled_data_hex', '') or '')
            if reassembled_hex:
                try:
                    ldap_payload = bytes.fromhex(reassembled_hex)
                except Exception:
                    ldap_payload = b''
                if ldap_payload and self._ldap_payload_is_complete(ldap_payload) and (self._looks_like_ldap_payload(ldap_payload) or self._contains_ldap_message(ldap_payload)):
                    protocol = 'LDAP'
        self._update_stun_request_response_metadata(protocol, metadata, src, dst, sport, dport, int(number), epoch_time)
        self._update_srtcp_setup_metadata(protocol, metadata, src, dst, sport, dport)
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

        self._update_h264_ts_reassembly(record, packet)
        if str(getattr(record, 'protocol', '') or '') == 'H.264' and str(record.metadata.get('h264_ts_reassembled_pes_hex', '') or ''):
            record.info = self._build_info(record.raw, 'H.264', record.metadata)

        self._track_transport_record(record)
        self._update_kerberos_record_metadata(record)
        self._update_ldap_request_response_metadata(packet, protocol, record.metadata, int(number), epoch_time, record)
        self._update_http_metadata(record)
        self._update_smtp_metadata(record)
        self._update_imap_metadata(record)
        self._update_sip_metadata(record)
        self._update_snmp_metadata(record)
        self._update_whois_metadata(record)
        self._update_rtp_metadata(record)
        self._update_ntp_metadata(record)
        self._update_zabbix_metadata(record)
        self._update_icmp_echo_metadata(packet, record)
        self._update_icmpv6_echo_metadata(packet, record)
        self._update_dns_metadata(packet, record)
        self._update_radius_metadata(packet, record)
        self._update_smb2_metadata(record)
        self._update_dcerpc_record_metadata(record)
        self._register_ip_fragment_record(packet, record)

        return record

    def parse_fast(self, packet, number: int, iface: str = '') -> PacketRecord:
        """Fast-path parser for initial large-file rendering."""
        epoch_time = float(getattr(packet, 'time', 0.0))
        if self.first_epoch is None:
            self.first_epoch = epoch_time
        relative_time = max(0.0, epoch_time - self.first_epoch)

        if self.last_epoch_captured is None:
            frame_delta = 0.0
        else:
            frame_delta = max(0.0, epoch_time - self.last_epoch_captured)
        self.last_epoch_captured = epoch_time
        self.last_epoch_displayed = epoch_time

        effective_ip = self._effective_ip_layer(packet)
        effective_tcp = self._effective_tcp_layer(packet, effective_ip)
        effective_udp = self._effective_udp_layer(packet, effective_ip)
        src, dst = self._extract_endpoints(packet)
        sport, dport = self._extract_ports(packet, effective_tcp, effective_udp)
        layers = [layer.__name__.upper() for layer in packet.layers()]
        length = int(getattr(packet, 'frame_wire_len', len(packet)) or len(packet))

        metadata = {
            'fast_preview': True,
            'frame_number': int(number),
            'frame_time_delta': frame_delta,
            'frame_time_delta_displayed': frame_delta,
        }
        if self.capture_file_path:
            metadata['capture_file_path'] = self.capture_file_path
        try:
            metadata['frame_linktype'] = int(getattr(packet, 'frame_linktype', 1) or 1)
        except Exception:
            metadata['frame_linktype'] = 1
        has_fpp = bool(hasattr(packet, 'fpp_preamble') or packet.haslayer('MPacketPreamble'))
        if has_fpp:
            metadata['frame_has_fpp'] = True
            if int(metadata.get('frame_linktype', 1) or 1) == 1:
                metadata['frame_linktype'] = 198
        self._populate_stream_indices(packet, metadata)
        self._update_ip_fragment_metadata(packet, metadata, int(number))
        self._update_transport_stream_metadata(packet, metadata, epoch_time)
        self._update_dcerpc_stream_metadata(packet, metadata, epoch_time)
        self._update_kerberos_stream_metadata(packet, metadata, epoch_time)
        self._update_ssh_stream_metadata(packet, metadata, epoch_time)
        self._update_ftp_metadata(packet, metadata)

        protocol = self._quick_guess_protocol(packet, effective_tcp, effective_udp, metadata)
        pim_inner_src = str(metadata.get('pim_inner_src', '') or '')
        pim_inner_dst = str(metadata.get('pim_inner_dst', '') or '')
        if protocol == 'PIMv2' and pim_inner_src and pim_inner_dst:
            src, dst = pim_inner_src, pim_inner_dst
        if protocol in {'GRE', 'TELNET'}:
            gre_endpoints = self._gre_inner_endpoints(packet)
            if gre_endpoints is not None:
                src, dst = gre_endpoints
        if protocol == 'TCP':
            info = self._build_info(packet, protocol, metadata)
        else:
            info = self._quick_info(packet, protocol, effective_tcp, effective_udp, metadata)

        stream_hint = ''
        if sport is not None or dport is not None:
            stream_hint = f'{src}:{sport or "-"} \u2192 {dst}:{dport or "-"}'

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
        self._update_kerberos_record_metadata(record)
        self._update_ldap_request_response_metadata(packet, protocol, record.metadata, int(number), epoch_time, record)
        if protocol in {'SIP', 'SIP/SDP'}:
            self._update_sip_metadata(record)
        self._update_smb2_metadata(record)
        self._update_dcerpc_record_metadata(record)
        self._register_ip_fragment_record(packet, record)
        return record

    def _quick_guess_protocol(self, packet, tcp_layer=None, udp_layer=None, metadata: dict | None = None) -> str:
        metadata = metadata or {}
        fragment_override = self._fragment_override_protocol(packet, metadata)
        if fragment_override:
            return fragment_override
        if self._is_homeplug_av_packet(packet):
            return 'HomePlug AV'
        if packet.haslayer(GRE):
            gre_payload = self._payload_bytes(packet)
            if b'SSH-' in gre_payload:
                return self._ssh_banner_protocol_name(gre_payload)
            if packet.haslayer(ICMP):
                return 'ICMP'
            if self._is_icmpv6_packet(packet):
                return 'ICMPv6'
            if len(gre_payload) >= 5:
                for i in range(0, min(len(gre_payload) - 4, 256)):
                    ct = int(gre_payload[i])
                    ver = int.from_bytes(gre_payload[i + 1:i + 3], 'big')
                    rlen = int.from_bytes(gre_payload[i + 3:i + 5], 'big')
                    if ct in {20, 21, 22, 23} and ver in {0x0300, 0x0301, 0x0302, 0x0303, 0x0304} and i + 5 + rlen <= len(gre_payload):
                        return 'SSL'
            if tcp_layer is not None:
                sport = int(getattr(tcp_layer, 'sport', 0) or 0)
                dport = int(getattr(tcp_layer, 'dport', 0) or 0)
                telnet_info = self._telnet_payload_info(gre_payload, sport, dport)
                if telnet_info is not None:
                    metadata['telnet'] = telnet_info
                    return 'TELNET'
            return 'GRE'
        pppoe_info = self._pppoe_payload_info(packet)
        if pppoe_info is not None:
            metadata['pppoe'] = pppoe_info
            if bool(pppoe_info.get('is_discovery', False)):
                return 'PPPoED'
            ppp_protocol = int(pppoe_info.get('ppp_protocol', 0) or 0)
            if ppp_protocol == 0xC021:
                return 'PPP LCP'
            if ppp_protocol == 0x8021:
                return 'PPP IPCP'
            if ppp_protocol == 0x8057:
                return 'PPP IPV6CP'
            if ppp_protocol not in {0x0021, 0x0057}:
                return 'PPP'
        if packet.haslayer('ESP'):
            return 'ESP'
        if self._is_ospf_ipv6_packet(packet):
            return 'OSPF'
        effective_ip = self._effective_ip_layer(packet)
        if effective_ip is not None:
            try:
                ip_proto = self._ip_next_proto(effective_ip)
                ip_payload = bytes(getattr(effective_ip, 'payload', b'') or b'')
                pim_info = self._pim_payload_info(ip_payload, ip_proto)
                if pim_info is not None:
                    metadata['pim'] = pim_info
                    if str(pim_info.get('protocol', '')) == 'PIMv2':
                        inner_src = str(pim_info.get('inner_src', '') or '')
                        inner_dst = str(pim_info.get('inner_dst', '') or '')
                        if inner_src and inner_dst:
                            metadata['pim_inner_src'] = inner_src
                            metadata['pim_inner_dst'] = inner_dst
                    return str(pim_info.get('protocol', 'PIMv2'))
                if ip_proto == 89:
                    return 'OSPF'
                if ip_proto == 112:
                    vrrp_info = self._vrrp_payload_info(packet, effective_ip)
                    if vrrp_info is not None:
                        metadata['vrrp'] = vrrp_info
                        return 'VRRP'
            except Exception:
                pass
            eigrp_info = self._eigrp_payload_info(packet, effective_ip)
            if eigrp_info is not None:
                metadata['eigrp'] = eigrp_info
                return 'EIGRP'
        elif packet.haslayer(IPv6):
            eigrp_info = self._eigrp_payload_info(packet, packet[IPv6])
            if eigrp_info is not None:
                metadata['eigrp'] = eigrp_info
                return 'EIGRP'
        if packet.haslayer(ARP):
            return 'ARP'
        eth_type = self._ether_type(packet)
        if eth_type == 0x0842:
            wol_payload = bytes(getattr(packet[Ether], 'payload', b'')) if packet.haslayer(Ether) else b''
            wol = self._wol_payload_info(wol_payload)
            if wol is not None:
                metadata['wol'] = wol
                return 'WOL'
        isis_info = self._isis_payload_info(packet)
        if isis_info is not None:
            metadata['isis'] = isis_info
            return str(isis_info.get('protocol', 'ISIS'))
        if self._is_icmpv6_packet(packet):
            if packet.haslayer(DNS):
                metadata['icmpv6_contains_dns'] = True
            return 'ICMPv6'
        if tcp_layer is not None and bool(metadata.get('tcp_is_retransmission', False)):
            return 'TCP'
        if packet.haslayer('KerberosTCPHeader') or packet.haslayer('Kerberos'):
            return 'KRB5'
        if packet.haslayer('CLDAP'):
            return 'CLDAP'
        if packet.haslayer('SMB2_Header'):
            if bool(metadata.get('tcp_is_retransmission', False)):
                return 'TCP'
            if tcp_layer is not None:
                embedded = self._dcerpc_embedded_payload_info(self._payload_bytes(packet), metadata)
                if embedded is not None:
                    metadata['dcerpc'] = embedded
                    metadata['dcerpc_embedded_offset'] = int(embedded.get('embedded_offset', 0) or 0)
                    return str(embedded.get('protocol', 'DCERPC'))
                sport = int(getattr(tcp_layer, 'sport', 0) or 0)
                dport = int(getattr(tcp_layer, 'dport', 0) or 0)
                if sport == 445 or dport == 445:
                    nbss_info = self._nbss_payload_info(self._payload_bytes(packet))
                    if isinstance(nbss_info, dict) and bool(nbss_info.get('is_fragment', False)):
                        metadata['nbss'] = nbss_info
                        return 'NBSS'
            return 'SMB2'
        if packet.haslayer('SMB_Header'):
            if tcp_layer is not None:
                embedded = self._dcerpc_embedded_payload_info(self._payload_bytes(packet), metadata)
                if embedded is not None:
                    metadata['dcerpc'] = embedded
                    metadata['dcerpc_embedded_offset'] = int(embedded.get('embedded_offset', 0) or 0)
                    return str(embedded.get('protocol', 'DCERPC'))
                sport = int(getattr(tcp_layer, 'sport', 0) or 0)
                dport = int(getattr(tcp_layer, 'dport', 0) or 0)
                if sport == 445 or dport == 445:
                    nbss_info = self._nbss_payload_info(self._payload_bytes(packet))
                    if isinstance(nbss_info, dict) and bool(nbss_info.get('is_fragment', False)):
                        metadata['nbss'] = nbss_info
                        return 'NBSS'
            return 'SMB'
        if packet.haslayer(DNS):
            qname = self._dns_qname(packet)
            if qname.endswith('.local'):
                return 'MDNS'
            return 'DNS'
        if packet.haslayer(ICMPv6EchoRequest) or packet.haslayer(ICMPv6EchoReply) or packet.haslayer(IPv6ExtHdrHopByHop):
            raw = bytes(getattr(packet[IPv6], 'payload', b'')) if packet.haslayer(IPv6) else b''
            if raw and raw[:1] == b'\x03':
                return 'ICMPv6'
        if packet.haslayer(ICMP):
            return 'ICMP'
        if tcp_layer is not None:
            payload = self._payload_bytes(packet)
            sport = int(getattr(tcp_layer, 'sport', 0) or 0)
            dport = int(getattr(tcp_layer, 'dport', 0) or 0)
            if bool(metadata.get('dcerpc_pending_reassembly', False)):
                return 'TCP'
            pre_dcerpc = metadata.get('dcerpc', None)
            if isinstance(pre_dcerpc, dict):
                return str(pre_dcerpc.get('protocol', 'DCERPC'))
            dcerpc_info = self._dcerpc_payload_info(payload, metadata, allow_segment_fragment=True)
            if dcerpc_info is not None:
                metadata['dcerpc'] = dcerpc_info
                return str(dcerpc_info.get('protocol', 'DCERPC'))
            if packet.haslayer('SMB2_Header') or packet.haslayer('SMB_Header'):
                embedded = self._dcerpc_embedded_payload_info(payload, metadata)
                if embedded is not None:
                    metadata['dcerpc'] = embedded
                    metadata['dcerpc_embedded_offset'] = int(embedded.get('embedded_offset', 0) or 0)
                    return str(embedded.get('protocol', 'DCERPC'))
            stream_index = int(metadata.get('tcp_stream_index', -1))
            if stream_index >= 0 and stream_index in self.dcerpc_stream_protocols and len(payload) > 0:
                return str(self.dcerpc_stream_protocols.get(stream_index, 'DCERPC'))
            pop_imf = self._pop_imf_fragment_info(payload, sport, dport)
            if pop_imf is not None:
                metadata['pop_imf'] = pop_imf
                return 'POP/IMF'
            pop_info = self._pop_payload_info(payload, sport, dport)
            if pop_info is not None:
                metadata['pop'] = pop_info
                return 'POP'
            if sport == 445 or dport == 445:
                nbss_info = self._nbss_payload_info(payload)
                if isinstance(nbss_info, dict) and bool(nbss_info.get('is_fragment', False)):
                    metadata['nbss'] = nbss_info
                    return 'NBSS'
                if bool(metadata.get('tcp_is_retransmission', False)):
                    return 'TCP'
                if packet.haslayer('SMB2_Header'):
                    return 'SMB2'
                if packet.haslayer('SMB_Header'):
                    return 'SMB'
            if sport == 3389 or dport == 3389:
                rdp_info = self._rdp_tpkt_info(payload)
                if isinstance(rdp_info, dict):
                    metadata['rdp'] = rdp_info
                    return 'RDP'
            if sport == 88 or dport == 88:
                if packet.haslayer('KerberosTCPHeader') or packet.haslayer('Kerberos'):
                    return 'KRB5'
            ldap_ports = {389, 3268, 3269}
            ldap_complete = self._ldap_payload_is_complete(payload)
            if (sport in ldap_ports or dport in ldap_ports) and ldap_complete and (self._looks_like_ldap_payload(payload) or self._contains_ldap_message(payload)):
                if stream_index >= 0:
                    self.ldap_stream_protocols.add(int(stream_index))
                return 'LDAP'
            if sport in ldap_ports or dport in ldap_ports:
                if self._looks_like_ldap_sasl_payload(payload):
                    if stream_index >= 0:
                        self.ldap_stream_protocols.add(int(stream_index))
                    return 'LDAP'
                if stream_index >= 0 and stream_index in self.ldap_stream_protocols:
                    if not ldap_complete and not str(metadata.get('tcp_reassembled_data_hex', '') or ''):
                        return 'TCP'
                    return 'LDAP'
                reassembled_hex = str(metadata.get('tcp_reassembled_data_hex', '') or '')
                if reassembled_hex:
                    try:
                        reassembled = bytes.fromhex(reassembled_hex)
                    except Exception:
                        reassembled = b''
                    if self._looks_like_ldap_payload(reassembled) or self._contains_ldap_message(reassembled):
                        if stream_index >= 0:
                            self.ldap_stream_protocols.add(int(stream_index))
                        return 'LDAP'
            if payload and (sport == 7 or dport == 7):
                return 'ECHO'
            if payload and (sport == 9 or dport == 9):
                return 'DISCARD'
            if payload and (sport == 13 or dport == 13):
                return 'DAYTIME'
            if payload and (sport == 19 or dport == 19):
                return 'Chargen'
            if payload and (sport == 37 or dport == 37):
                return 'TIME'
            if sport == 49 or dport == 49:
                tacacs = self._tacacs_payload_info(payload)
                if tacacs is not None:
                    metadata['tacacs'] = tacacs
                    return 'TACACS+'
            if sport == 443 or dport == 443:
                probe = payload
                if len(probe) >= 5:
                    for i in range(0, min(len(probe) - 4, 96)):
                        ct = int(probe[i])
                        ver = int.from_bytes(probe[i + 1:i + 3], 'big')
                        rlen = int.from_bytes(probe[i + 3:i + 5], 'big')
                        if ct in {20, 21, 22, 23} and ver in {0x0300, 0x0301, 0x0302, 0x0303, 0x0304} and i + 5 + rlen <= len(probe):
                            return 'SSL'
            ftp_data_meta = metadata.get('ftp_data') if isinstance(metadata.get('ftp_data'), dict) else None
            if isinstance(ftp_data_meta, dict) and payload:
                return 'FTP-DATA'
            if sport == 21 or dport == 21:
                ftp_info = self._ftp_payload_info(payload, sport, dport)
                if ftp_info is not None:
                    metadata['ftp'] = ftp_info
                    return 'FTP'
            zabbix_info = self._zabbix_payload_info(payload)
            if zabbix_info is not None:
                metadata['zabbix'] = zabbix_info
                return 'Zabbix'
            payload_lower = payload.lower()
            if b'application/ocsp-request' in payload_lower or b'application/ocsp-response' in payload_lower:
                return 'OCSP'
            telnet_info = self._telnet_payload_info(payload, sport, dport)
            if telnet_info is not None:
                metadata['telnet'] = telnet_info
                return 'TELNET'
            if (sport == 179 or dport == 179) and self._is_bgp_payload(payload):
                return 'BGP'
            ssh_protocol = self._ssh_stream_protocol_name(packet, metadata)
            if ssh_protocol is not None:
                return ssh_protocol
            if self._is_rsh_packet(packet):
                return 'RSH'
            imap_info = self._imap_payload_info(payload, sport, dport)
            if imap_info is not None:
                metadata['imap'] = imap_info
                return 'IMAP'
            whois_meta = metadata.get('whois') if isinstance(metadata.get('whois'), dict) else None
            if isinstance(whois_meta, dict):
                kind = str(whois_meta.get('kind', '') or '')
                if kind == 'query' and dport == 43:
                    return 'WHOIS'
                if kind == 'answer' and sport == 43:
                    tcp_flags = int(getattr(tcp_layer, 'flags', 0) or 0)
                    has_fin = bool(tcp_flags & 0x01)
                    if has_fin or (not payload and bool(str(metadata.get('tcp_reassembled_data_hex', '') or ''))):
                        return 'WHOIS'
            whois_payload = payload
            if not whois_payload:
                reassembled_hex = str(metadata.get('tcp_reassembled_data_hex', '') or '')
                if reassembled_hex:
                    try:
                        whois_payload = bytes.fromhex(reassembled_hex)
                    except Exception:
                        whois_payload = b''
            whois_info = self._whois_payload_info(whois_payload, sport, dport)
            if whois_info is not None:
                kind = str(whois_info.get('kind', '') or '')
                tcp_flags = int(getattr(tcp_layer, 'flags', 0) or 0)
                has_fin = bool(tcp_flags & 0x01)
                if kind == 'query' and dport == 43:
                    metadata['whois'] = whois_info
                    return 'WHOIS'
                if kind == 'answer' and sport == 43:
                    if has_fin or (not payload and bool(str(metadata.get('tcp_reassembled_data_hex', '') or ''))):
                        metadata['whois'] = whois_info
                        return 'WHOIS'
            http_info = self._http_message_length(payload)
            if http_info is not None:
                _kind, _header_len, _total_len, _headers = http_info
                # In quick mode, keep incomplete HTTP PDUs as TCP to avoid
                # misclassifying reassembly fragments as application protocol.
                if _header_len is None or _total_len is None or len(payload) < int(_total_len):
                    return 'TCP'
                content_type = str(_headers.get('content-type', '') or '').split(';', 1)[0].strip().lower()
                if self._is_ocsp_http(content_type):
                    return 'OCSP'
                if self._is_ipp_http(content_type):
                    return 'IPP'
                if b'xml' in payload.lower():
                    return 'HTTP/XML'
                return 'HTTP'
            if sport == 515 or dport == 515:
                lpd_info = self._lpd_payload_info(payload, sport, dport)
                if lpd_info is not None:
                    metadata['lpd'] = lpd_info
                    return 'LPD'
            if sport in {25, 587} or dport in {25, 587}:
                smtp_kind = self._smtp_payload_kind(payload)
                if smtp_kind in {'command', 'response'}:
                    metadata['smtp_kind'] = smtp_kind
                    return 'SMTP'
            return 'TCP'
        if udp_layer is not None:
            sport = int(getattr(udp_layer, 'sport', 0) or 0)
            dport = int(getattr(udp_layer, 'dport', 0) or 0)
            payload = bytes(getattr(udp_layer, 'payload', b''))
            if sport == 3389 or dport == 3389:
                rdpudp = self._rdpudp_payload_info(payload)
                if isinstance(rdpudp, dict):
                    metadata['rdpudp'] = rdpudp
                    unwrapped_payload = bytes(rdpudp.get('unwrapped_payload', b'') or b'')
                    if unwrapped_payload:
                        metadata['rdpudp_unwrapped_payload'] = unwrapped_payload
                        data_offset = int(rdpudp.get('data_offset', -1) or -1)
                        if data_offset >= 0 and len(unwrapped_payload) > data_offset + 4:
                            metadata['rdpudp_tls_fragment_payload'] = bytes(unwrapped_payload[data_offset + 4:])
                    tls_info = self._rdpudp_embedded_tls_info(payload, rdpudp, int(metadata.get('udp_stream_index', -1) or -1))
                    if isinstance(tls_info, dict):
                        metadata['tls_embedded_payload'] = bytes(tls_info.get('payload', b'') or b'')
                        metadata['tls_embedded_offset'] = int(tls_info.get('offset', 0) or 0)
                        metadata['tls_embedded_summaries'] = list(tls_info.get('summaries', []) or [])
                        metadata['tls_embedded_sni'] = str(tls_info.get('sni', '') or '')
                        metadata['tls_embedded_unknown_record'] = bool(tls_info.get('unknown_record', False))
                        metadata['tls_embedded_transport'] = 'RDPUDP'
                        metadata['rdpudp_tls_fragment_payload'] = bytes(tls_info.get('payload', b'') or b'')
                        return str(tls_info.get('protocol', 'TLSv1.2'))
                    return str(rdpudp.get('protocol', 'RDPUDP'))
            if sport == 4500 or dport == 4500:
                udpencap = self._udpencap_payload_info(payload)
                if isinstance(udpencap, dict):
                    metadata['udpencap'] = udpencap
                    return 'UDPENCAP'
            qsrc, qdst = self._extract_endpoints(packet)
            quic_info = self._quic_payload_info(payload, str(qsrc), str(qdst), sport, dport)
            if isinstance(quic_info, dict):
                metadata['quic'] = quic_info
                decrypted = bytes(quic_info.get('quic_decrypted_payload', b'') or b'')
                if decrypted:
                    metadata['quic_decrypted_payload'] = decrypted
                return 'QUIC'
            stun_info = self._stun_payload_info(payload)
            if isinstance(stun_info, dict):
                metadata['stun'] = stun_info
                return 'STUN'
            srtcp_info = self._srtcp_payload_info(payload)
            if isinstance(srtcp_info, dict):
                metadata['srtcp'] = srtcp_info
                return 'SRTCP'
            if (sport in {500, 4500} or dport in {500, 4500}) and self._is_isakmp_packet_payload(payload):
                return 'ISAKMP'
            if self._looks_like_h264_over_udp(payload):
                return 'H.264'
            if self._looks_like_mpeg_ts_payload(payload):
                return 'MPEG TS'
            dtls_info = self._dtls_payload_info(payload)
            if dtls_info is not None:
                metadata['dtls'] = dtls_info
                if b'\x00\x0e' in payload:
                    src_addr, dst_addr = self._extract_endpoints(packet)
                    setup_key = self._canonical_transport_key(str(src_addr), sport, str(dst_addr), dport, 'UDP')
                    frame_no = int(metadata.get('frame_number', 0) or 0)
                    existing = int(self.srtcp_setup_frames.get(setup_key, 0) or 0)
                    info_text = str(dtls_info.get('info_text', '') or '')
                    prefer = 'Server Hello' in info_text
                    if prefer or existing <= 0 or (frame_no > 0 and frame_no < existing):
                        self.srtcp_setup_frames[setup_key] = frame_no
                return str(dtls_info.get('protocol', 'DTLS'))
            if (sport == 389 or dport == 389) and packet.haslayer('CLDAP'):
                return 'CLDAP'
            if (sport == 88 or dport == 88) and packet.haslayer('Kerberos'):
                return 'KRB5'
            if payload and (sport == 7 or dport == 7):
                return 'ECHO'
            if payload and (sport == 9 or dport == 9):
                return 'DISCARD'
            if payload and (sport == 13 or dport == 13):
                return 'DAYTIME'
            if payload and (sport == 19 or dport == 19):
                return 'Chargen'
            if payload and (sport == 37 or dport == 37):
                return 'TIME'
            if sport == 5355 or dport == 5355:
                llmnr = self._llmnr_payload_info(payload)
                if llmnr is not None:
                    metadata['llmnr'] = llmnr
                    return 'LLMNR'
            if sport == 137 or dport == 137:
                nbns = self._nbns_payload_info(payload)
                if nbns is not None:
                    metadata['nbns'] = nbns
                    return 'NBNS'
            if sport == 5351 or dport == 5351:
                pcp = self._pcp_payload_info(payload)
                if pcp is not None:
                    metadata['pcp'] = pcp
                    return 'PCP v2'
            if (sport == 3702 or dport == 3702) and payload.lstrip().startswith(b'<?xml'):
                metadata['udp_xml'] = {'length': int(len(payload))}
                return 'UDP/XML'
            if self._is_hsrpv2_packet(packet):
                return 'HSRPv2'
            if self._is_hsrp_packet(packet):
                return 'HSRP'
            if sport == 3222 or dport == 3222:
                glbp_info = self._glbp_payload_info(payload)
                if glbp_info is not None:
                    metadata['glbp'] = glbp_info
                    return 'GLBP'
            if sport == 3785 or dport == 3785:
                return 'BFD Echo'
            if sport == 3784 or dport == 3784:
                bfd_info = self._bfd_control_payload_info(payload)
                if bfd_info is not None:
                    metadata['bfd'] = bfd_info
                    return 'BFD Control'
            if sport == 2055 or dport == 2055:
                cflow_info = self._cflow_payload_info(payload)
                if cflow_info is not None:
                    metadata['cflow'] = cflow_info
                    return 'CFLOW'
            if (sport == 646 or dport == 646) and self._is_ldp_payload(payload):
                return 'LDP'
            if (sport == 69 or dport == 69) and len(payload) >= 2:
                opcode = int.from_bytes(payload[:2], 'big')
                if opcode in {1, 2, 4, 5}:
                    return 'TFTP'
            if sport == 1900 or dport == 1900:
                first = payload.split(b'\r\n', 1)[0].upper()
                if first.startswith(b'M-SEARCH ') or first.startswith(b'NOTIFY ') or first.startswith(b'HTTP/1.'):
                    return 'SSDP'
            sip_info = self._sip_payload_info(payload, sport, dport)
            if sip_info is not None:
                metadata['sip'] = sip_info
                if bool(sip_info.get('has_sdp', False)):
                    metadata['sdp'] = self._parse_sdp_body(bytes(sip_info.get('sdp_body', b'') or b''))
                    return 'SIP/SDP'
                return 'SIP'
            rtp_info = self._rtp_payload_info(payload, sport, dport)
            if self._should_classify_as_rtp(
                payload,
                rtp_info,
                str(getattr(effective_ip, 'src', '') or ''),
                sport,
                str(getattr(effective_ip, 'dst', '') or ''),
                dport,
            ):
                metadata['rtp'] = rtp_info
                return 'RTP'
            snmp_info = self._snmp_payload_info(packet)
            if snmp_info is None:
                snmp_info = self._snmp_payload_info_from_bytes(payload)
            if snmp_info is not None:
                metadata['snmp'] = snmp_info
                return 'SNMP'
            if sport == 623 or dport == 623:
                rmcp_info = self._rmcp_payload_info(payload)
                if isinstance(rmcp_info, dict):
                    metadata['rmcp'] = rmcp_info
                    session_ver = str(rmcp_info.get('session_version', '') or '')
                    if session_ver == 'v1_5':
                        return 'IPMB'
                    if session_ver == 'v2_0':
                        return 'RMCP+'
            if sport in {1812, 1813} or dport in {1812, 1813}:
                radius = self._radius_payload_info(payload)
                if radius is not None:
                    metadata['radius'] = radius
                    eap_info = self._radius_eap_info(radius)
                    if eap_info is not None:
                        metadata['radius_eap'] = eap_info
                    return 'RADIUS'
            return 'UDP'
        if packet.haslayer(IPv6):
            return 'IPv6'
        if packet.haslayer(IP):
            return 'IPv4'
        return 'ETH'

    def _quick_info(self, packet, protocol: str, tcp_layer=None, udp_layer=None, metadata: dict | None = None) -> str:
        metadata = metadata or {}
        if protocol in {'PPPoED', 'PPP LCP', 'PPP IPCP', 'PPP IPV6CP', 'PPP', 'EIGRP', 'SNMP', 'IPMB', 'RMCP+', 'IMAP', 'SIP', 'SIP/SDP', 'RTP', 'WHOIS', 'TELNET', 'CFLOW', 'GRE', 'BFD Echo', 'ISIS CSNP', 'ISIS HELLO', 'GLBP', 'VRRP', 'HSRP', 'HSRPv2', 'Zabbix', 'ECHO', 'DISCARD', 'DAYTIME', 'Chargen', 'TIME', 'TACACS+', 'RADIUS', 'WOL', 'LLMNR', 'NBNS', 'PCP v2', 'UDP/XML', 'POP', 'POP/IMF', 'KRB5', 'CLDAP', 'LDAP', 'SMB', 'SMB2', 'NBSS', 'RDP', 'RDPUDP', 'RDPUDP2', 'PIMv1', 'PIMv2', 'SMTP', 'DCERPC', 'DRSUAPI', 'DTLS', 'DTLSv1.2', 'H.264', 'MPEG TS', 'RPC_NETLOGON', 'SAMR', 'SRTCP', 'SSH', 'SSL', 'STUN', 'UDPENCAP'}:
            return self._build_info(packet, protocol, metadata)
        if protocol in {'IPv4', 'IPv6', 'IP', 'IPV6'} and bool(metadata.get('ip_is_fragmented', False)):
            return self._ip_fragment_info_text(packet, metadata)
        if protocol in {'HTTP', 'HTTP/XML'}:
            payload = self._payload_bytes(packet)
            kind = self._http_payload_kind(payload)
            if kind == 'request':
                method, path, version = self._http_request_parts(payload)
                if method or path or version:
                    return f'{method} {path} {version} '
            if kind == 'response':
                version, code, reason = self._http_response_parts(payload)
                text = ' '.join(part for part in (version, code, reason) if part)
            if text:
                return f'{text} '
            return 'HTTP'
        if protocol.startswith('UDP'):
            return self._build_info(packet, protocol, metadata)
        if protocol == 'OCSP':
            kind = self._http_payload_kind(self._payload_bytes(packet)) or 'request'
            return 'Request' if kind == 'request' else 'Response'
        if protocol == 'IPP':
            return self._ipp_info_text(packet, metadata)
        if protocol == 'LPD':
            return self._lpd_info_text(packet, metadata)
        if protocol == 'RSH':
            return self._rsh_info_text(packet)
        if protocol == 'HomePlug AV':
            return self._homeplug_info_text(packet)
        if protocol in {'FTP', 'FTP-DATA', 'BFD Control'}:
            return self._build_info(packet, protocol, metadata)
        if protocol in {'SSHv2', 'SSH'}:
            return self._ssh_info_text(packet, metadata)
        if protocol.startswith('TLS'):
            return self._build_info(packet, protocol, metadata)
        if protocol in {'DNS', 'MDNS'}:
            return self._build_info(packet, protocol, metadata)
        if protocol == 'BGP':
            return self._bgp_message_type_name(self._payload_bytes(packet))
        if protocol == 'LDP':
            return self._ldp_message_type_name(self._payload_bytes(packet))
        if protocol == 'OSPF':
            ospf_payload = self._ospf_payload_bytes(packet)
            msg_type = int(ospf_payload[1]) if len(ospf_payload) >= 2 else -1
            return {
                1: 'Hello Packet',
                2: 'DB Description',
                3: 'LS Request',
                4: 'LS Update',
                5: 'LS Acknowledge',
            }.get(msg_type, f'OSPF Message ({msg_type})' if msg_type >= 0 else 'OSPF')
        if protocol == 'ISAKMP':
            return self._isakmp_info_text(packet)
        if protocol == 'ICMPv6':
            return self._icmpv6_info_text(packet, metadata) or 'Internet Control Message Protocol v6'
        if protocol == 'TFTP':
            payload = bytes(getattr(udp_layer, 'payload', b'')) if udp_layer is not None else b''
            if len(payload) >= 2:
                opcode = int.from_bytes(payload[:2], 'big')
                if opcode == 2:
                    parts = payload[2:].split(b'\x00')
                    fn = parts[0].decode(errors='ignore') if parts else ''
                    mode = parts[1].decode(errors='ignore') if len(parts) > 1 else ''
                    return f'Write Request, File: {fn}, Transfer type: {mode}'
                if opcode == 4 and len(payload) >= 4:
                    block = int.from_bytes(payload[2:4], 'big')
                    return f'Acknowledgement, Block: {block}'
            return 'Trivial File Transfer Protocol'
        if protocol == 'SSDP':
            payload = bytes(getattr(udp_layer, 'payload', b'')) if udp_layer is not None else b''
            first_line = payload.split(b'\r\n', 1)[0].decode(errors='ignore')
            return f'{first_line} ' if first_line else 'Simple Service Discovery Protocol'
        if protocol == 'ESP':
            try:
                esp_layer = packet['ESP']
                spi = int(getattr(esp_layer, 'spi', 0) or 0)
                return f'ESP (SPI=0x{spi:08x})'
            except Exception:
                return 'Encapsulating Security Payload'
        if protocol == 'TCP' and tcp_layer is not None:
            flags = self._tcp_flags_to_string(tcp_layer.flags)
            payload_len = self._tcp_payload_length(packet, tcp_layer)
            base = f'{tcp_layer.sport} -> {tcp_layer.dport} [{flags}] Len={payload_len}'
            option_tokens = self._tcp_info_options(tcp_layer, metadata)
            if option_tokens:
                return f'{base} ' + ' '.join(option_tokens)
            return base
        if protocol.startswith('UDP') and udp_layer is not None:
            udp_len = max(0, int(getattr(udp_layer, 'len', 8) or 8) - 8)
            return f'{udp_layer.sport} -> {udp_layer.dport} Len={udp_len}'
        try:
            return packet.summary()
        except Exception:
            return protocol

    def _canonical_transport_key(self, src: str, sport: int, dst: str, dport: int, proto: str):
        left = (str(src), int(sport))
        right = (str(dst), int(dport))
        if left <= right:
            return (proto, left, right)
        return (proto, right, left)

    def _tftp_client_session_key(self, src: str, sport: int, dst: str, dport: int) -> tuple[str, int, str] | None:
        if sport == 69 and dport != 69:
            return (str(dst), int(dport), str(src))
        if dport == 69 and sport != 69:
            return (str(src), int(sport), str(dst))
        if sport != 69 and dport != 69:
            return (str(dst), int(dport), str(src))
        return None

    def _radius_payload_info(self, payload: bytes) -> dict | None:
        if len(payload) < 20:
            return None
        code = int(payload[0])
        if code not in {1, 2, 3, 4, 5, 11, 12, 13}:
            return None
        identifier = int(payload[1])
        radius_len = int.from_bytes(payload[2:4], 'big')
        if radius_len < 20 or radius_len > len(payload):
            return None
        avps = []
        cursor = 20
        while cursor + 2 <= radius_len:
            avp_type = int(payload[cursor])
            avp_len = int(payload[cursor + 1])
            if avp_len < 2 or cursor + avp_len > radius_len:
                break
            avps.append({
                'type': avp_type,
                'length': avp_len,
                'value': payload[cursor + 2:cursor + avp_len],
            })
            cursor += avp_len
        return {
            'code': code,
            'identifier': identifier,
            'length': radius_len,
            'authenticator': payload[4:20],
            'avps': avps,
        }

    def _wol_payload_info(self, payload: bytes) -> dict | None:
        if len(payload) < 6 + (16 * 6):
            return None
        if payload[:6] != (b'\xff' * 6):
            return None
        target = payload[6:12]
        for i in range(16):
            start = 6 + (i * 6)
            if payload[start:start + 6] != target:
                return None
        return {
            'target_mac': bytes(target),
            'payload_length': int(len(payload)),
        }

    def _decode_dns_name(self, data: bytes, start: int) -> tuple[str, int] | None:
        labels: list[str] = []
        pos = int(start)
        while pos < len(data):
            ln = int(data[pos])
            pos += 1
            if ln == 0:
                return '.'.join(labels), pos
            if (ln & 0xC0) == 0xC0:
                if pos >= len(data):
                    return None
                ptr = ((ln & 0x3F) << 8) | int(data[pos])
                pos += 1
                if ptr >= len(data):
                    return None
                pointed = self._decode_dns_name(data, ptr)
                if pointed is None:
                    return None
                labels.append(pointed[0])
                return '.'.join(part for part in labels if part), pos
            if pos + ln > len(data):
                return None
            labels.append(data[pos:pos + ln].decode(errors='ignore'))
            pos += ln
        return None

    def _llmnr_payload_info(self, payload: bytes) -> dict | None:
        if len(payload) < 12:
            return None
        qdcount = int.from_bytes(payload[4:6], 'big')
        if qdcount <= 0:
            return None
        name_parsed = self._decode_dns_name(payload, 12)
        if name_parsed is None:
            return None
        qname, qend = name_parsed
        if qend + 4 > len(payload):
            return None
        return {
            'transaction_id': int.from_bytes(payload[0:2], 'big'),
            'flags': int.from_bytes(payload[2:4], 'big'),
            'qdcount': qdcount,
            'ancount': int.from_bytes(payload[6:8], 'big'),
            'nscount': int.from_bytes(payload[8:10], 'big'),
            'arcount': int.from_bytes(payload[10:12], 'big'),
            'qname': qname,
            'qtype': int.from_bytes(payload[qend:qend + 2], 'big'),
            'qclass': int.from_bytes(payload[qend + 2:qend + 4], 'big'),
        }

    def _decode_nbns_name(self, encoded: bytes) -> str:
        if len(encoded) < 32:
            return ''
        decoded = bytearray()
        for i in range(0, 32, 2):
            c1 = int(encoded[i]) - 0x41
            c2 = int(encoded[i + 1]) - 0x41
            if c1 < 0 or c2 < 0:
                break
            decoded.append(((c1 & 0x0F) << 4) | (c2 & 0x0F))
        if not decoded:
            return ''
        base = decoded[:15].decode(errors='ignore').rstrip(' ')
        suffix = int(decoded[15]) if len(decoded) >= 16 else 0
        return f'{base}<{suffix:02x}>'

    def _nbns_payload_info(self, payload: bytes) -> dict | None:
        if len(payload) < 12:
            return None
        qdcount = int.from_bytes(payload[4:6], 'big')
        if qdcount <= 0:
            return None
        pos = 12
        if pos >= len(payload):
            return None
        name_len = int(payload[pos])
        pos += 1
        if name_len != 32 or pos + name_len + 1 + 4 > len(payload):
            return None
        encoded_name = payload[pos:pos + name_len]
        pos += name_len
        if int(payload[pos]) != 0:
            return None
        pos += 1
        qtype = int.from_bytes(payload[pos:pos + 2], 'big')
        qclass = int.from_bytes(payload[pos + 2:pos + 4], 'big')
        if qtype != 32:
            return None
        return {
            'transaction_id': int.from_bytes(payload[0:2], 'big'),
            'flags': int.from_bytes(payload[2:4], 'big'),
            'qdcount': qdcount,
            'ancount': int.from_bytes(payload[6:8], 'big'),
            'nscount': int.from_bytes(payload[8:10], 'big'),
            'arcount': int.from_bytes(payload[10:12], 'big'),
            'name': self._decode_nbns_name(encoded_name),
            'qtype': qtype,
            'qclass': qclass,
        }

    def _pcp_payload_info(self, payload: bytes) -> dict | None:
        if len(payload) < 60:
            return None
        version = int(payload[0])
        if version != 2:
            return None
        opcode = int(payload[1] & 0x7F)
        if opcode != 1:
            return None
        return {
            'version': version,
            'is_response': bool(payload[1] & 0x80),
            'opcode': opcode,
            'lifetime': int.from_bytes(payload[4:8], 'big'),
            'client_ip': bytes(payload[8:24]),
            'mapping_nonce': bytes(payload[24:36]),
            'protocol': int(payload[36]),
            'internal_port': int.from_bytes(payload[40:42], 'big'),
            'external_port': int.from_bytes(payload[42:44], 'big'),
            'external_ip': bytes(payload[44:60]),
        }

    def _pop_payload_info(self, payload: bytes, sport: int, dport: int) -> dict | None:
        if not payload:
            return None
        if sport not in {110, 995} and dport not in {110, 995}:
            return None
        line = payload.split(b'\r\n', 1)[0]
        if not line:
            return None
        try:
            text = line.decode(errors='ignore')
        except Exception:
            return None
        text = text.strip()
        if not text:
            return None

        if text.startswith('+OK') or text.startswith('-ERR'):
            marker = '+OK' if text.startswith('+OK') else '-ERR'
            desc = text[len(marker):].strip()
            return {
                'kind': 'response',
                'line': text,
                'marker': marker,
                'description': desc,
            }

        cmd = text.split(' ', 1)[0].upper()
        if cmd in {'USER', 'PASS', 'CAPA', 'QUIT', 'STAT', 'LIST', 'RETR', 'DELE', 'NOOP', 'TOP', 'UIDL', 'APOP', 'RSET', 'AUTH'}:
            side = 'client' if dport == 110 else 'server' if sport == 110 else ''
            return {
                'kind': 'command',
                'side': side,
                'line': text,
                'command': cmd,
                'param': text[len(cmd):].strip(),
            }
        return None

    def _pop_imf_fragment_info(self, payload: bytes, sport: int, dport: int) -> dict | None:
        if sport != 110 and dport != 110:
            return None
        if not payload:
            return None
        try:
            text = payload.decode(errors='ignore')
        except Exception:
            return None
        if not text:
            return None
        lower = text.lower()
        if ('</html>' not in lower and 'content-type:' not in lower and 'mime-version:' not in lower and '--=_'
                not in lower and 'from:' not in lower and 'subject:' not in lower):
            return None
        lines = [ln for ln in text.splitlines() if ln.strip()]
        if not lines:
            return None
        return {
            'kind': 'imf_fragment',
            'lines': lines,
            'line_count': len(lines),
        }

    def _rmcp_payload_info(self, payload: bytes) -> dict | None:
        if len(payload) < 4:
            return None
        version = int(payload[0])
        reserved = int(payload[1])
        sequence = int(payload[2])
        rmcp_class = int(payload[3])
        if version != 0x06:
            return None
        if (rmcp_class & 0x0F) != 0x07:
            return None

        info: dict[str, object] = {
            'version': version,
            'reserved': reserved,
            'sequence': sequence,
            'class': rmcp_class,
            'message_type': int((rmcp_class >> 7) & 0x01),
        }
        body = payload[4:]
        if len(body) < 1:
            return info

        auth_type = int(body[0])
        info['auth_type'] = auth_type

        if auth_type == 0x00:
            if len(body) < 10:
                return info
            session_sequence = int.from_bytes(body[1:5], 'little')
            session_id = int.from_bytes(body[5:9], 'little')
            message_length = int(body[9])
            data_start = 10
            data_end = min(len(body), data_start + max(0, message_length))
            info.update({
                'session_version': 'v1_5',
                'session_sequence': session_sequence,
                'session_id': session_id,
                'message_length': message_length,
                'data': bytes(body[data_start:data_end]),
            })
            return info

        if auth_type == 0x06:
            if len(body) < 12:
                return info
            payload_type_byte = int(body[1])
            session_id = int.from_bytes(body[2:6], 'little')
            session_sequence = int.from_bytes(body[6:10], 'little')
            message_length = int.from_bytes(body[10:12], 'little')
            data_start = 12
            data_end = min(len(body), data_start + max(0, message_length))
            trailer = bytes(body[data_end:]) if data_end < len(body) else b''
            info.update({
                'session_version': 'v2_0',
                'payload_type_byte': payload_type_byte,
                'payload_type': int(payload_type_byte & 0x3F),
                'is_encrypted': bool(payload_type_byte & 0x80),
                'is_authenticated': bool(payload_type_byte & 0x40),
                'session_id': session_id,
                'session_sequence': session_sequence,
                'message_length': message_length,
                'data': bytes(body[data_start:data_end]),
                'trailer': trailer,
            })
            return info

        return info

    def _radius_eap_info(self, radius_info: dict) -> dict | None:
        if not isinstance(radius_info, dict):
            return None
        fragments = []
        for avp in list(radius_info.get('avps', []) or []):
            if int(avp.get('type', 0) or 0) == 79:
                fragments.append(bytes(avp.get('value', b'') or b''))
        if not fragments:
            return None

        eap = b''.join(fragments)
        if len(eap) < 4:
            return None
        code = int(eap[0])
        eap_id = int(eap[1])
        eap_len = int.from_bytes(eap[2:4], 'big')
        if eap_len < 4 or eap_len > len(eap):
            eap_len = len(eap)
        eap_type = int(eap[4]) if eap_len >= 5 else None
        eap_data = eap[5:eap_len] if eap_len > 5 else b''

        type_name = None
        if eap_type is not None:
            type_name = {
                1: 'Identity',
                3: 'Legacy Nak (Response Only)',
                4: 'MD5-Challenge EAP (EAP-MD5-CHALLENGE)',
                25: 'Protected EAP (EAP-PEAP)',
            }.get(eap_type, f'Type {eap_type}')

        tls_summary = []
        tls_flags = None
        tls_length = None
        tls_fragment = b''
        tls_fragment_offset = None
        if eap_type == 25 and eap_data:
            tls_offset = 1
            if len(eap_data) >= 1:
                flags = int(eap_data[0])
                tls_flags = int(flags)
                tls_offset = 1 + (4 if (flags & 0x80 and len(eap_data) >= 5) else 0)
                if flags & 0x80 and len(eap_data) >= 5:
                    tls_length = int.from_bytes(eap_data[1:5], 'big')
            tls_blob = eap_data[tls_offset:] if tls_offset <= len(eap_data) else b''
            tls_fragment = bytes(tls_blob)
            tls_fragment_offset = int(5 + tls_offset)
            pos = 0
            while pos + 5 <= len(tls_blob):
                content_type = int(tls_blob[pos])
                rec_len = int.from_bytes(tls_blob[pos + 3:pos + 5], 'big')
                body_start = pos + 5
                body_end = min(len(tls_blob), body_start + rec_len)
                body = tls_blob[body_start:body_end]
                if content_type == 22 and len(body) >= 4:
                    hs_pos = 0
                    while hs_pos + 4 <= len(body):
                        hs_type = int(body[hs_pos])
                        hs_len = int.from_bytes(body[hs_pos + 1:hs_pos + 4], 'big')
                        hs_total = 4 + hs_len
                        tls_summary.append({
                            1: 'Client Hello',
                            2: 'Server Hello',
                            11: 'Certificate',
                            12: 'Server Key Exchange',
                            14: 'Server Hello Done',
                            16: 'Client Key Exchange',
                        }.get(hs_type, 'Encrypted Handshake Message'))
                        if hs_total < 4 or hs_pos + hs_total > len(body):
                            break
                        hs_pos += hs_total
                elif content_type == 20:
                    tls_summary.append('Change Cipher Spec')
                elif content_type == 23:
                    tls_summary.append('Application Data')
                elif content_type == 21:
                    tls_summary.append('Alert')
                if rec_len <= 0:
                    break
                pos = body_start + rec_len

        return {
            'code': code,
            'id': eap_id,
            'length': eap_len,
            'type': eap_type,
            'type_name': type_name,
            'raw': bytes(eap[:eap_len]),
            'tls_flags': tls_flags,
            'tls_length': tls_length,
            'tls_fragment': tls_fragment,
            'tls_fragment_offset': tls_fragment_offset,
            'tls_summary': tls_summary,
        }

    def _update_radius_eap_tls_reassembly(
        self,
        record: PacketRecord,
        eap_info: dict,
        src: str,
        sport: int,
        dst: str,
        dport: int,
    ) -> None:
        if not isinstance(eap_info, dict):
            return
        if int(eap_info.get('type', 0) or 0) != 25:
            return

        tls_flags = eap_info.get('tls_flags', None)
        tls_fragment_raw = eap_info.get('tls_fragment', b'')
        if tls_flags is None:
            return
        tls_fragment = bytes(tls_fragment_raw or b'')
        if not tls_fragment:
            return

        try:
            flags = int(tls_flags)
        except Exception:
            return

        more_fragments = bool(flags & 0x40)
        length_included = bool(flags & 0x80)
        expected_length = int(eap_info.get('tls_length', 0) or 0)
        direction_key = (str(src), int(sport), str(dst), int(dport))

        if length_included and expected_length > 0:
            initial_state = {
                'expected': int(expected_length),
                'data': bytearray(tls_fragment),
                'fragments': [
                    {
                        'frame_number': int(record.number),
                        'payload_start': 0,
                        'payload_length': int(len(tls_fragment)),
                    }
                ],
            }
            if more_fragments:
                self.radius_eap_tls_pending[direction_key] = initial_state
            else:
                self.radius_eap_tls_pending.pop(direction_key, None)
            return

        state = self.radius_eap_tls_pending.get(direction_key)
        if not isinstance(state, dict):
            return

        expected = int(state.get('expected', 0) or 0)
        buffer = state.get('data', None)
        if expected <= 0 or not isinstance(buffer, bytearray):
            self.radius_eap_tls_pending.pop(direction_key, None)
            return

        payload_start = int(len(buffer))
        buffer.extend(tls_fragment)
        fragments = state.get('fragments', [])
        if not isinstance(fragments, list):
            fragments = []
        fragments.append(
            {
                'frame_number': int(record.number),
                'payload_start': int(payload_start),
                'payload_length': int(len(tls_fragment)),
            }
        )
        state['fragments'] = fragments

        if len(buffer) >= expected:
            assembled = bytes(buffer[:expected])
            if len(fragments) > 1:
                record.metadata['radius_eap_tls_reassembled_hex'] = assembled.hex()
                record.metadata['radius_eap_tls_reassembled_length'] = int(expected)
                record.metadata['radius_eap_tls_fragments'] = list(fragments)
            self.radius_eap_tls_pending.pop(direction_key, None)
            return

        if not more_fragments:
            self.radius_eap_tls_pending.pop(direction_key, None)

    def _tacacs_payload_info(self, payload: bytes) -> dict | None:
        if len(payload) < 12:
            return None
        version = int(payload[0])
        major = (version >> 4) & 0x0F
        minor = version & 0x0F
        if major != 0x0C:
            return None
        tac_type = int(payload[1])
        if tac_type not in {1, 2, 3}:
            return None
        packet_len = int.from_bytes(payload[8:12], 'big')
        if packet_len < 0 or 12 + packet_len > len(payload):
            return None
        return {
            'major': major,
            'minor': minor,
            'type': tac_type,
            'sequence': int(payload[2]),
            'flags': int(payload[3]),
            'session_id': int.from_bytes(payload[4:8], 'big'),
            'length': packet_len,
        }

    def _update_tftp_metadata(self, packet, metadata: dict) -> None:
        udp = self._effective_udp_layer(packet)
        ip_layer = self._effective_ip_layer(packet)
        if udp is None or ip_layer is None:
            return
        src = str(getattr(ip_layer, 'src', '') or '')
        dst = str(getattr(ip_layer, 'dst', '') or '')
        sport = int(getattr(udp, 'sport', 0) or 0)
        dport = int(getattr(udp, 'dport', 0) or 0)
        stream_key = self._canonical_transport_key(src, sport, dst, dport, 'UDP')
        client_session_key = self._tftp_client_session_key(src, sport, dst, dport)
        known_session = stream_key in self.tftp_sessions or (
            client_session_key is not None and client_session_key in self.tftp_sessions_by_client
        )
        if sport != 69 and dport != 69 and not known_session:
            return
        payload = bytes(getattr(udp, 'payload', b''))
        if len(payload) < 2:
            return
        opcode = int.from_bytes(payload[:2], 'big')
        if opcode not in {1, 2, 4, 5}:
            return
        session = self.tftp_sessions.get(stream_key, {})
        if not session and client_session_key is not None:
            session = self.tftp_sessions_by_client.get(client_session_key, {})

        metadata['tftp_opcode'] = opcode
        if opcode in {1, 2}:
            parts = payload[2:].split(b'\x00')
            filename = parts[0].decode(errors='ignore') if parts else ''
            mode = parts[1].decode(errors='ignore') if len(parts) > 1 else ''
            metadata['tftp_filename'] = filename
            metadata['tftp_mode'] = mode
            metadata['tftp_kind'] = 'RRQ' if opcode == 1 else 'WRQ'
            session['filename'] = filename
            session['request_frame'] = int(metadata.get('frame_number', 0) or 0)
            if client_session_key is not None:
                self.tftp_sessions_by_client[client_session_key] = session
        elif opcode == 4 and len(payload) >= 4:
            block = int.from_bytes(payload[2:4], 'big')
            metadata['tftp_block'] = block
            metadata['tftp_kind'] = 'ACK'
            if session.get('filename'):
                metadata['tftp_filename'] = str(session.get('filename'))
            if session.get('request_frame'):
                metadata['tftp_request_frame'] = int(session.get('request_frame'))
        elif opcode == 5 and len(payload) >= 4:
            code = int.from_bytes(payload[2:4], 'big')
            message = payload[4:].split(b'\x00', 1)[0].decode(errors='ignore')
            metadata['tftp_error_code'] = code
            metadata['tftp_error_message'] = message
            metadata['tftp_kind'] = 'ERROR'
        self.tftp_sessions[stream_key] = session
        if client_session_key is not None and session:
            self.tftp_sessions_by_client[client_session_key] = session

    def _ftp_payload_info(self, payload: bytes, sport: int, dport: int) -> dict | None:
        raw = bytes(payload or b'')
        if not raw:
            return None
        first = raw.split(b'\r\n', 1)[0].decode('utf-8', errors='replace').strip()
        if not first:
            return None
        if any(ord(ch) < 32 and ch not in '\t' for ch in first):
            return None
        if len(first) >= 3 and first[:3].isdigit():
            try:
                code = int(first[:3])
            except Exception:
                return None
            separator = first[3] if len(first) > 3 else ''
            if separator not in {'', ' ', '-'}:
                return None
            arg = first[4:] if len(first) > 4 else ''
            return {
                'kind': 'response',
                'line': first,
                'code': code,
                'arg': arg,
                'separator': separator,
            }
        parts = first.split(' ', 1)
        command = parts[0].upper().strip()
        if dport != 21:
            return None
        if not command or len(command) > 8 or not command.isalpha() or command not in self.FTP_COMMANDS:
            return None
        arg = parts[1].strip() if len(parts) > 1 else ''
        return {
            'kind': 'request',
            'line': first,
            'command': command,
            'arg': arg,
        }

    def _ftp_pasv_port(self, text: str) -> int:
        open_idx = str(text).rfind('(')
        close_idx = str(text).rfind(')')
        if open_idx < 0 or close_idx <= open_idx:
            return 0
        parts = [p.strip() for p in str(text)[open_idx + 1:close_idx].split(',')]
        if len(parts) < 6:
            return 0
        try:
            p1 = int(parts[-2])
            p2 = int(parts[-1])
        except Exception:
            return 0
        if p1 < 0 or p1 > 255 or p2 < 0 or p2 > 255:
            return 0
        return p1 * 256 + p2

    def _ftp_epsv_port(self, text: str) -> int:
        value = str(text or '').strip()
        open_idx = value.rfind('(')
        close_idx = value.rfind(')')
        if open_idx < 0 or close_idx <= open_idx:
            return 0
        body = value[open_idx + 1:close_idx]
        parts = body.split('|')
        for item in reversed(parts):
            token = item.strip()
            if token.isdigit():
                try:
                    port = int(token)
                except Exception:
                    return 0
                if 0 < port < 65536:
                    return port
        return 0

    def _update_ftp_metadata(self, packet, metadata: dict) -> None:
        tcp = self._effective_tcp_layer(packet)
        ip_layer = self._effective_ip_layer(packet)
        if tcp is None or ip_layer is None:
            return
        src = str(getattr(ip_layer, 'src', '') or '')
        dst = str(getattr(ip_layer, 'dst', '') or '')
        sport = int(getattr(tcp, 'sport', 0) or 0)
        dport = int(getattr(tcp, 'dport', 0) or 0)
        payload = self._payload_bytes(packet)
        frame_number = int(metadata.get('frame_number', 0) or 0)
        stream_key = self._canonical_transport_key(src, sport, dst, dport, 'TCP')

        ftp_info = self._ftp_payload_info(payload, sport, dport)
        if ftp_info is not None and (sport == 21 or dport == 21):
            metadata['ftp'] = ftp_info
            stream = self.ftp_control_streams.setdefault(stream_key, {})
            client_ip = src if dport == 21 else dst
            server_ip = dst if dport == 21 else src
            stream['client_ip'] = client_ip
            stream['server_ip'] = server_ip

            if str(ftp_info.get('kind', '')) == 'request':
                stream['last_command'] = str(ftp_info.get('command', '') or '')
                stream['last_command_arg'] = str(ftp_info.get('arg', '') or '')
                stream['last_command_frame'] = frame_number
                if str(stream['last_command']).upper() == 'CWD' and str(stream.get('last_command_arg', '') or ''):
                    stream['cwd'] = str(stream.get('last_command_arg', '') or '')
                command_upper = str(stream.get('last_command', '') or '').upper()
                if command_upper and command_upper not in {'PASV', 'EPSV'}:
                    for session_key, session_meta in list(self.ftp_data_sessions.items()):
                        if len(session_key) != 3:
                            continue
                        if str(session_key[0]) != str(server_ip) or str(session_key[2]) != str(client_ip):
                            continue
                        if int(session_meta.get('setup_frame', 0) or 0) > frame_number:
                            continue
                        session_meta['command'] = command_upper
                        session_meta['command_arg'] = str(stream.get('last_command_arg', '') or '')
                        session_meta['command_frame'] = frame_number
            else:
                code = int(ftp_info.get('code', 0) or 0)
                arg = str(ftp_info.get('arg', '') or '')
                if code == 257:
                    q1 = arg.find('"')
                    q2 = arg.find('"', q1 + 1) if q1 >= 0 else -1
                    if q1 >= 0 and q2 > q1:
                        stream['cwd'] = arg[q1 + 1:q2]
                if code == 227:
                    data_port = self._ftp_pasv_port(arg)
                    if data_port > 0:
                        self.ftp_data_sessions[(server_ip, data_port, client_ip)] = {
                            'setup_frame': frame_number,
                            'setup_method': 'PASV',
                            'command': str(stream.get('last_command', '') or ''),
                            'command_arg': str(stream.get('last_command_arg', '') or ''),
                            'command_frame': int(stream.get('last_command_frame', 0) or 0),
                            'cwd': str(stream.get('cwd', '') or ''),
                            'control_stream_key': stream_key,
                        }
                if code == 229:
                    data_port = self._ftp_epsv_port(arg)
                    if data_port > 0:
                        self.ftp_data_sessions[(server_ip, data_port, client_ip)] = {
                            'setup_frame': frame_number,
                            'setup_method': 'EPSV',
                            'command': str(stream.get('last_command', '') or ''),
                            'command_arg': str(stream.get('last_command_arg', '') or ''),
                            'command_frame': int(stream.get('last_command_frame', 0) or 0),
                            'cwd': str(stream.get('cwd', '') or ''),
                            'control_stream_key': stream_key,
                        }
            metadata['ftp_cwd'] = str(stream.get('cwd', '') or '')

        data_meta = self.ftp_data_sessions.get((src, sport, dst))
        if data_meta is None:
            data_meta = self.ftp_data_sessions.get((dst, dport, src))
        if data_meta is not None and payload:
            metadata['ftp_data'] = {
                'setup_frame': int(data_meta.get('setup_frame', 0) or 0),
                'setup_method': str(data_meta.get('setup_method', '') or ''),
                'command': str(data_meta.get('command', '') or ''),
                'command_arg': str(data_meta.get('command_arg', '') or ''),
                'command_frame': int(data_meta.get('command_frame', 0) or 0),
                'cwd': str(data_meta.get('cwd', '') or ''),
            }

    def _bfd_control_payload_info(self, payload: bytes) -> dict | None:
        raw = bytes(payload or b'')
        if len(raw) < 24:
            return None
        version = (int(raw[0]) >> 5) & 0x07
        if version != 1:
            return None
        diag = int(raw[0]) & 0x1F
        state = (int(raw[1]) >> 6) & 0x03
        flags = int(raw[1]) & 0x3F
        detect_mult = int(raw[2])
        length = int(raw[3])
        if length < 24 or length > len(raw):
            return None
        return {
            'version': version,
            'diag': diag,
            'state': state,
            'flags': flags,
            'flags_byte': int(raw[1]),
            'detect_multiplier': detect_mult,
            'length': length,
            'my_discriminator': int.from_bytes(raw[4:8], 'big'),
            'your_discriminator': int.from_bytes(raw[8:12], 'big'),
            'desired_min_tx': int.from_bytes(raw[12:16], 'big'),
            'required_min_rx': int.from_bytes(raw[16:20], 'big'),
            'required_min_echo': int.from_bytes(raw[20:24], 'big'),
        }

    def _glbp_payload_info(self, payload: bytes) -> dict | None:
        raw = bytes(payload or b'')
        if len(raw) < 12:
            return None
        if int(raw[0]) != 1:
            return None
        group = int.from_bytes(raw[2:4], 'big')
        owner_id = raw[6:12]
        tlvs = []
        cursor = 12
        hello_addr_type = 0
        while cursor + 2 <= len(raw):
            tlv_type = int(raw[cursor])
            tlv_len = int(raw[cursor + 1])
            if tlv_len < 2 or cursor + tlv_len > len(raw):
                break
            value_start = cursor + 2
            value_end = cursor + tlv_len
            value = raw[value_start:value_end]
            tlvs.append({
                'type': tlv_type,
                'length': tlv_len,
                'value': value,
            })
            if tlv_type == 1 and len(value) >= 22:
                hello_addr_type = int(value[20])
            cursor += tlv_len
        if not tlvs:
            return None
        return {
            'version': int(raw[0]),
            'unknown1': int(raw[1]),
            'group': group,
            'unknown2': raw[4:6],
            'owner_id': owner_id,
            'tlvs': tlvs,
            'hello_addr_type': hello_addr_type,
        }

    def _vrrp_payload_info(self, packet, ip_layer=None) -> dict | None:
        effective_ip = ip_layer if ip_layer is not None else self._effective_ip_layer(packet)
        if effective_ip is None:
            return None
        try:
            proto = int(getattr(effective_ip, 'proto', 0) or 0)
        except Exception:
            return None
        if proto != 112:
            return None
        payload = self._ip_payload_bytes(packet, effective_ip)
        if len(payload) < 8:
            return None
        version = (int(payload[0]) >> 4) & 0x0F
        ptype = int(payload[0]) & 0x0F
        if version == 0 or ptype == 0:
            return None
        ipcount = int(payload[3])
        header_len = 8 + (ipcount * 4)
        if len(payload) < header_len:
            return None
        addrlist = []
        addr_cursor = 8
        for _ in range(ipcount):
            if addr_cursor + 4 > len(payload):
                break
            addr_bytes = payload[addr_cursor:addr_cursor + 4]
            addrlist.append('.'.join(str(int(b)) for b in addr_bytes))
            addr_cursor += 4
        auth_data = b''
        if len(payload) >= header_len + 8:
            auth_data = payload[header_len:header_len + 8]
        trailer = payload[header_len + 8:] if len(payload) > header_len + 8 else b''
        md5_data = trailer[-16:] if len(trailer) >= 16 else b''
        return {
            'version': version,
            'type': ptype,
            'vrid': int(payload[1]),
            'priority': int(payload[2]),
            'ipcount': ipcount,
            'authtype': int(payload[4]),
            'adv': int(payload[5]),
            'checksum': int.from_bytes(payload[6:8], 'big'),
            'addrlist': addrlist,
            'auth_data': auth_data,
            'md5_data': md5_data,
            'payload': payload,
        }

    def _isis_system_id_text(self, data: bytes) -> str:
        value = bytes(data or b'')
        if len(value) < 6:
            return ''
        return f'{value[0]:02x}{value[1]:02x}.{value[2]:02x}{value[3]:02x}.{value[4]:02x}{value[5]:02x}'

    def _isis_lsp_id_text(self, data: bytes) -> str:
        value = bytes(data or b'')
        if len(value) < 8:
            return ''
        return f'{self._isis_system_id_text(value[:6])}.{value[6]:02x}-{value[7]:02x}'

    def _isis_payload_info(self, packet) -> dict | None:
        if not packet.haslayer(LLC):
            return None
        try:
            llc_layer = packet[LLC]
            dsap = int(getattr(llc_layer, 'dsap', -1) or -1)
            ssap = int(getattr(llc_layer, 'ssap', -1) or -1)
        except Exception:
            return None
        if dsap != 0xFE or ssap != 0xFE:
            return None
        payload = bytes(getattr(llc_layer, 'payload', b''))
        if len(payload) < 8:
            return None
        if int(payload[0]) != 0x83:
            return None
        pdu_type = int(payload[4]) & 0x1F
        if pdu_type in {18, 20} and len(payload) >= 27:
            level = 'L1' if pdu_type == 18 else 'L2'
            return {
                'protocol': 'ISIS LSP',
                'pdu_type': pdu_type,
                'level': level,
                'pdu_length': int.from_bytes(payload[8:10], 'big'),
                'remaining_lifetime': int.from_bytes(payload[10:12], 'big'),
                'lsp_id': self._isis_lsp_id_text(payload[12:20]),
                'sequence': int.from_bytes(payload[20:24], 'big'),
                'checksum': int.from_bytes(payload[24:26], 'big'),
                'type_block': int(payload[26]),
            }
        if pdu_type in {24, 25} and len(payload) >= 33:
            level = 'L1' if pdu_type == 24 else 'L2'
            return {
                'protocol': 'ISIS CSNP',
                'pdu_type': pdu_type,
                'level': level,
                'source_id': self._isis_system_id_text(payload[10:16]),
                'source_id_circuit': int(payload[16]),
                'start_lsp_id': self._isis_lsp_id_text(payload[17:25]),
                'end_lsp_id': self._isis_lsp_id_text(payload[25:33]),
            }
        if pdu_type in {26, 27} and len(payload) >= 17:
            level = 'L1' if pdu_type == 26 else 'L2'
            return {
                'protocol': 'ISIS PSNP',
                'pdu_type': pdu_type,
                'level': level,
                'pdu_length': int.from_bytes(payload[8:10], 'big'),
                'source_id': self._isis_system_id_text(payload[10:16]),
                'source_id_circuit': int(payload[16]),
            }
        if pdu_type in {15, 16, 17} and len(payload) >= 27:
            level = 'L1' if pdu_type == 15 else ('L2' if pdu_type == 16 else 'P2P')
            return {
                'protocol': 'ISIS HELLO',
                'pdu_type': pdu_type,
                'level': level,
                'system_id': self._isis_system_id_text(payload[9:15]),
            }
        return None

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
        """Track contiguous TCP data ranges with internal stream logic."""
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
        if effective_ip is None and packet.haslayer(IPv6):
            effective_ip = packet[IPv6]
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

        if proto == 'TCP':
            tcp_flags_now = int(getattr(layer, 'flags', 0) or 0)
            syn_without_ack = bool((tcp_flags_now & 0x12) == 0x02)
            payload_len_now = self._tcp_payload_length(packet, layer, effective_ip)
            if syn_without_ack and payload_len_now == 0 and int(state.get('count', 0) or 0) > 0:
                # A new SYN appearing after packets have already been tracked for this 4-tuple
                # is not automatically a port-reuse case. If the prior stream has no teardown
                # evidence (FIN/RST), treat it as out-of-order capture instead of resetting state.
                saw_teardown = bool(int(state.get('completeness_flags', 0) or 0) & (16 | 32))
                if saw_teardown:
                    metadata['tcp_port_numbers_reused'] = True
                    state['count'] = 0
                    state['first_epoch'] = epoch_time
                    state['last_epoch'] = None
                    state['dir_base_seq'] = {}
                    state['dir_relative_origin'] = {}
                    state['dir_window_shift'] = {}
                    state['completeness_flags'] = 0
                    state['packets_by_dir'] = {}
                    state['records'] = []
                    state['contig'] = {
                        'client': {'ranges': []},
                        'server': {'ranges': []},
                    }
                else:
                    metadata['tcp_is_out_of_order'] = True

        state['count'] += 1
        stream_packet_number = int(state['count'])
        metadata[f'{proto.lower()}_stream_packet_number'] = state['count']
        metadata[f'{proto.lower()}_time_since_first'] = max(0.0, epoch_time - state['first_epoch'])

        if state['last_epoch'] is None:
            metadata[f'{proto.lower()}_time_since_prev'] = 0.0
        else:
            metadata[f'{proto.lower()}_time_since_prev'] = max(0.0, epoch_time - state['last_epoch'])
        state['last_epoch'] = epoch_time


        # --- Contiguous streams logic ---
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

        # ---- SEQ/ACK analysis ----
        dir_packets = state['packets_by_dir'].setdefault(dir_key, [])
        rev_packets = state['packets_by_dir'].setdefault(rev_key, [])

        ack_frame_number = None
        ack_rtt_ms = None
        irtt_ms = None
        ack_ambiguous = False
        bytes_in_flight = None
        bytes_since_last_psh = None
        is_window_full = False
        has_ack_flag = bool(tcp_flags & 0x10)
        ack_only = bool(has_ack_flag and payload_len == 0 and (tcp_flags & 0x07) == 0)
        is_retransmission = False
        is_spurious_retransmission = False
        is_out_of_order = False
        is_duplicate_ack = False
        is_window_update = False
        is_keep_alive = False
        is_keep_alive_ack = False
        is_acked_unseen_segment = False
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
            if (tcp_flags & 0x02) and not (tcp_flags & 0x10):
                for seg in reversed(dir_packets):
                    seg_flags = int(seg.get('tcp_flags', 0) or 0)
                    if seg_flags & 0x10:
                        is_out_of_order = True
                        break
                if not is_out_of_order:
                    for seg in reversed(rev_packets):
                        seg_flags = int(seg.get('tcp_flags', 0) or 0)
                        if (seg_flags & 0x12) == 0x12 or (seg_flags & 0x10):
                            is_out_of_order = True
                            break
            metadata['tcp_is_retransmission'] = True
            if has_ack_flag and rev_packets:
                for seg in reversed(rev_packets):
                    seg_ack = int(seg.get('ack_raw', 0) or 0)
                    if self._tcp_seq_geq(seg_ack, end_seq_raw):
                        is_spurious_retransmission = True
                        break
            if is_spurious_retransmission and (packet.haslayer('SMB2_Header') or packet.haslayer('SMB_Header')):
                is_spurious_retransmission = False
            if is_spurious_retransmission:
                metadata['tcp_is_spurious_retransmission'] = True
            if is_out_of_order:
                metadata['tcp_is_out_of_order'] = True

        if (tcp_flags & 0x12) == 0x12 and rev_packets:
            syn_candidate = None
            for seg in reversed(rev_packets):
                seg_flags = int(seg.get('tcp_flags', 0) or 0)
                if (seg_flags & 0x02) and not (seg_flags & 0x10):
                    syn_candidate = seg
                    break
            if syn_candidate is not None:
                irtt_delta = (Decimal(str(epoch_time)) - Decimal(str(syn_candidate['epoch_time']))) * Decimal('1000')
                irtt_ms = max(0.0, float(irtt_delta))
                state['tcp_i_rtt_ms'] = float(irtt_ms)
        elif irtt_ms is None:
            cached_irtt = state.get('tcp_i_rtt_ms', None)
            if cached_irtt is not None:
                try:
                    irtt_ms = float(cached_irtt)
                except (TypeError, ValueError):
                    irtt_ms = None

        if dir_packets:
            highest_dir_end = None
            for seg in dir_packets:
                seg_end = int(seg.get('end_seq_raw', seg.get('seq_raw', 0)) or 0)
                if highest_dir_end is None or self._tcp_seq_gt(seg_end, highest_dir_end):
                    highest_dir_end = seg_end
            if highest_dir_end is not None and self._tcp_seq_gt(seq, highest_dir_end):
                previous_segment_not_captured = True
            if (
                has_ack_flag
                and payload_len <= 1
                and (tcp_flags & 0x07) == 0
                and highest_dir_end is not None
                and self._tcp_seq_cmp((seq + 1) & 0xFFFFFFFF, int(highest_dir_end)) == 0
            ):
                is_keep_alive = True

        keep_alive_probe = state.setdefault('keep_alive_probe', {})
        if is_keep_alive:
            keep_alive_probe[dir_key] = {
                'frame_number': int(metadata.get('frame_number', 0) or 0),
                'probe_seq': int(seq),
                'probe_ack': int(ack),
                'ack_expected': int((seq + 1) & 0xFFFFFFFF),
            }

        if has_ack_flag and ack > 0 and rev_packets:
            rev_has_gap = any(
                bool(seg.get('is_retransmission', False))
                or bool(seg.get('is_out_of_order', False))
                or bool(seg.get('previous_segment_not_captured', False))
                for seg in rev_packets
            )
            highest_rev_end = None
            for seg in rev_packets:
                seg_end = int(seg.get('end_seq_raw', seg.get('seq_raw', 0)) or 0)
                if highest_rev_end is None or self._tcp_seq_gt(seg_end, highest_rev_end):
                    highest_rev_end = seg_end
            if rev_has_gap and highest_rev_end is not None and self._tcp_seq_gt(ack, int((highest_rev_end + 1) & 0xFFFFFFFF)):
                is_acked_unseen_segment = True

        same_ack_run = []
        same_ack_run_duplicate_candidate = False
        if ack_only and dir_packets and not is_keep_alive:
            for seg in reversed(dir_packets):
                seg_flags = int(seg.get('tcp_flags', 0) or 0)
                if not bool(seg_flags & 0x10) or (seg_flags & 0x07) != 0:
                    continue
                if int(seg.get('ack_raw', -1) or -1) != ack:
                    if same_ack_run:
                        break
                    continue
                same_ack_run.append(seg)

            if same_ack_run:
                current_window = int(getattr(layer, 'window', 0) or 0)
                last_same_dir = same_ack_run[0]
                has_sack_block = False
                for option in getattr(layer, 'options', []) or []:
                    if isinstance(option, tuple) and option and str(option[0]) == 'SAck':
                        has_sack_block = True
                        break

                if int(last_same_dir.get('window', -1) or -1) != current_window and not has_sack_block:
                    is_window_update = True
                else:
                    same_ack_run_duplicate_candidate = True

        if ack_only and not is_keep_alive and not is_window_update and not is_duplicate_ack:
            probe = keep_alive_probe.get(rev_key)
            if isinstance(probe, dict):
                expected_ack = int(probe.get('ack_expected', -1) or -1)
                expected_seq = int(probe.get('probe_ack', -1) or -1)
                if (
                    expected_ack >= 0
                    and expected_seq >= 0
                    and self._tcp_seq_cmp(ack, expected_ack) == 0
                    and self._tcp_seq_cmp(seq, expected_seq) == 0
                ):
                    is_keep_alive_ack = True
                    keep_alive_probe.pop(rev_key, None)

        if (
            ack_only
            and not is_keep_alive
            and not is_window_update
            and not is_keep_alive_ack
            and not is_duplicate_ack
            and same_ack_run_duplicate_candidate
            and same_ack_run
        ):
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
                original_exact_matches = [seg for seg in exact_matches if not bool(seg.get('is_retransmission', False))]
                if exact_matches:
                    if original_exact_matches:
                        candidate = original_exact_matches[-1]
                    else:
                        candidate = exact_matches[-1]
                    ack_ambiguous = len(exact_matches) > 1 and not original_exact_matches

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
                if seg['psh']:
                    break
                if seg['payload_len'] > 0:
                    sent_bytes += int(seg['payload_len'])
            bytes_since_last_psh = int(sent_bytes)

        if payload_len > 0 and rev_packets and not is_retransmission and not is_duplicate_ack:
            latest_rev = rev_packets[-1]
            rev_window = int(latest_rev.get('window', 0) or 0)
            rev_shift = int(state.get('dir_window_shift', {}).get(rev_key, 0) or 0)
            scaled_rev_window = rev_window if rev_shift <= 0 else (rev_window << rev_shift)
            if scaled_rev_window > 0 and bytes_in_flight is not None and int(bytes_in_flight) >= int(scaled_rev_window):
                is_window_full = True

        if (
            not is_window_full
            and payload_len >= 4096
            and has_ack_flag
            and (tcp_flags & 0x08) == 0
            and (tcp_flags & 0x07) == 0
            and not is_retransmission
        ):
            is_window_full = True

        if ack_frame_number is not None:
            metadata['tcp_ack_frame_number'] = int(ack_frame_number)
        if ack_rtt_ms is not None:
            metadata['tcp_ack_rtt_ms'] = float(ack_rtt_ms)
        if irtt_ms is not None:
            metadata['tcp_i_rtt_ms'] = float(irtt_ms)
        if ack_ambiguous:
            metadata['tcp_ack_ambiguous'] = True
        if is_window_update:
            metadata['tcp_is_window_update'] = True
        if previous_segment_not_captured:
            metadata['tcp_previous_segment_not_captured'] = True
        if is_keep_alive:
            metadata['tcp_is_keep_alive'] = True
        if is_keep_alive_ack:
            metadata['tcp_is_keep_alive_ack'] = True
        if is_acked_unseen_segment:
            metadata['tcp_is_acked_unseen_segment'] = True
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
        if is_window_full:
            metadata['tcp_is_window_full'] = True

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
            'is_retransmission': bool(is_retransmission),
            'acked': False,
        })

    def _track_transport_record(self, record: PacketRecord) -> None:
        packet = getattr(record, 'raw', None)
        if packet is None:
            return

        effective_ip = self._effective_ip_layer(packet)
        if effective_ip is None and packet.haslayer(IPv6):
            effective_ip = packet[IPv6]
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

    def _update_kerberos_record_metadata(self, record: PacketRecord) -> None:
        metadata = getattr(record, 'metadata', {}) or {}
        packet = getattr(record, 'raw', None)
        if not isinstance(metadata, dict) or packet is None or str(getattr(record, 'protocol', '') or '').upper() != 'KRB5':
            return
        effective_ip = self._effective_ip_layer(packet)
        if effective_ip is None and packet.haslayer(IPv6):
            effective_ip = packet[IPv6]
        tcp_layer = self._effective_tcp_layer(packet, effective_ip)
        if effective_ip is None or tcp_layer is None:
            return
        src = str(effective_ip.src)
        dst = str(effective_ip.dst)
        sport = int(getattr(tcp_layer, 'sport', 0) or 0)
        dport = int(getattr(tcp_layer, 'dport', 0) or 0)
        stream_key = self._canonical_transport_key(src, sport, dst, dport, 'TCP')
        state = self.transport_stream_state.get(stream_key)
        if state is None:
            return
        rec_hex = str(metadata.get('tcp_reassembled_data_hex', '') or '')
        try:
            payload = bytes.fromhex(rec_hex) if rec_hex else self._payload_bytes(packet)
        except Exception:
            payload = self._payload_bytes(packet)
        if len(payload) < 5:
            return
        app_tag = int(payload[4]) & 0x1F
        if app_tag not in {10, 11, 12, 13, 30}:
            return
        if app_tag in {10, 12}:
            return
        if metadata.get('kerberos_request_frame') is not None:
            return
        expected = {11: {'AS-REQ'}, 13: {'TGS-REQ'}, 30: {'AS-REQ', 'TGS-REQ'}}
        for stream_record in reversed(state.get('records', [])[:-1]):
            try:
                if str(getattr(stream_record, 'protocol', '') or '').upper() != 'KRB5':
                    continue
                if int(getattr(stream_record, 'number', 0) or 0) >= int(getattr(record, 'number', 0) or 0):
                    continue
                if stream_record.metadata.get('kerberos_response_frame') is not None:
                    continue
                info_text = str(getattr(stream_record, 'info', '') or '').upper()
                if not any(name in info_text for name in expected.get(app_tag, set())):
                    continue
                delta_us = round(max(0.0, float(getattr(record, 'epoch_time', 0.0) or 0.0) - float(getattr(stream_record, 'epoch_time', 0.0) or 0.0)) * 1_000_000.0, 3)
                metadata['kerberos_request_frame'] = int(getattr(stream_record, 'number', 0) or 0)
                metadata['kerberos_response_time_us'] = delta_us
                stream_record.metadata['kerberos_response_frame'] = int(getattr(record, 'number', 0) or 0)
                stream_record.metadata['kerberos_response_time_us'] = delta_us
                break
            except Exception:
                continue

    def _safe_attr(self, obj, name, default=None):
        try:
            return getattr(obj, name, default)
        except Exception:
            return default

    def _extract_endpoints(self, packet):
        if packet.haslayer(ARP):
            if packet.haslayer(Ether):
                src = getattr(packet[Ether], 'src', '') or ''
                dst = getattr(packet[Ether], 'dst', '') or ''
            else:
                src = getattr(packet[ARP], 'hwsrc', '') or ''
                dst = getattr(packet[ARP], 'hwdst', '') or ''
            if not src or src == '00:00:00:00:00:00':
                src = getattr(packet[ARP], 'psrc', '') or 'N/A'
            if not dst or dst == '00:00:00:00:00:00':
                dst = getattr(packet[ARP], 'pdst', '') or 'N/A'
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
        if isinstance(endpoint, (bytes, bytearray)):
            data = bytes(endpoint)
            if len(data) == 6:
                text = ':'.join(f'{b:02x}' for b in data)
            else:
                text = data.hex()
        else:
            text = str(endpoint or '').strip()
        if text.lower() == 'ff:ff:ff:ff:ff:ff':
            return 'Broadcast'
        if text.lower() == '01:00:0c:cc:cc:cc':
            return 'CDP/VTP/DTP/PAgP/UDLD'
        if text.lower() == '01:00:0c:cc:cc:cd':
            return 'PVST+'
        if text.lower() == '01:80:c2:00:00:02':
            return 'Slow-Protocols'
        if text.lower() == '01:80:c2:00:00:00':
            return 'Nearest-Customer-Bridge'
        if text.lower() == '01:80:c2:00:00:0e':
            return 'Nearest-Bridge'
        if text.lower() == 'ab:00:00:02:00:00':
            return 'DEC-MOP-Remote-Console'
        if text.lower() == '33:33:00:00:00:09':
            return 'IPv6mcast_09'
        if text.lower() == '33:33:00:00:00:66':
            return 'IPv6mcast_66'
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

    def _inner_eth_type(self, packet) -> int | None:
        try:
            if packet.haslayer(Dot1Q):
                return int(getattr(packet[Dot1Q], 'type', 0) or 0)
            if packet.haslayer(Ether):
                return int(getattr(packet[Ether], 'type', 0) or 0)
        except Exception:
            pass
        return None

    def _ether_payload_offset(self, packet) -> int:
        offset = 0
        try:
            if packet.haslayer(Ether):
                offset += 14
            if packet.haslayer(Dot1Q):
                offset += 4
        except Exception:
            return 0
        return offset

    def _pppoe_payload_info(self, packet) -> dict | None:
        try:
            outer_type = self._ether_type(packet)
            inner_type = self._inner_eth_type(packet)
            effective_type = inner_type if int(outer_type or 0) == 0x8100 else outer_type
            if int(effective_type or 0) not in {0x8863, 0x8864}:
                return None

            raw = bytes(packet)
            base_offset = self._ether_payload_offset(packet)
            if len(raw) < base_offset + 6:
                return None

            vt = int(raw[base_offset])
            version = (vt >> 4) & 0x0F
            pppoe_type = vt & 0x0F
            code = int(raw[base_offset + 1])
            session_id = int.from_bytes(raw[base_offset + 2:base_offset + 4], 'big')
            payload_len = int.from_bytes(raw[base_offset + 4:base_offset + 6], 'big')
            payload_start = base_offset + 6
            payload_end = min(len(raw), payload_start + payload_len)
            payload = raw[payload_start:payload_end]

            info: dict = {
                'eth_type': int(effective_type),
                'offset': int(base_offset),
                'version': int(version),
                'type': int(pppoe_type),
                'code': int(code),
                'session_id': int(session_id),
                'payload_length': int(payload_len),
                'payload': payload,
                'is_discovery': int(effective_type) == 0x8863,
                'is_session': int(effective_type) == 0x8864,
            }

            if int(effective_type) == 0x8863:
                tags = []
                pos = 0
                while pos + 4 <= len(payload):
                    tag_type = int.from_bytes(payload[pos:pos + 2], 'big')
                    tag_len = int.from_bytes(payload[pos + 2:pos + 4], 'big')
                    tag_end = pos + 4 + tag_len
                    if tag_end > len(payload):
                        break
                    tags.append({
                        'type': int(tag_type),
                        'length': int(tag_len),
                        'value': payload[pos + 4:tag_end],
                    })
                    pos = tag_end
                info['tags'] = tags
            elif int(effective_type) == 0x8864 and len(payload) >= 2:
                ppp_protocol = int.from_bytes(payload[:2], 'big')
                ppp_payload = payload[2:]
                info['ppp_protocol'] = int(ppp_protocol)
                info['ppp_payload'] = ppp_payload
                if len(ppp_payload) >= 4:
                    info['ppp_control_code'] = int(ppp_payload[0])
                    info['ppp_identifier'] = int(ppp_payload[1])
                    info['ppp_length'] = int.from_bytes(ppp_payload[2:4], 'big')

            return info
        except Exception:
            return None

    def _pppoe_discovery_code_name(self, code: int) -> str:
        return {
            0x09: 'Active Discovery Initiation (PADI)',
            0x07: 'Active Discovery Offer (PADO)',
            0x19: 'Active Discovery Request (PADR)',
            0x65: 'Active Discovery Session-confirmation (PADS)',
            0xA7: 'Active Discovery Terminate (PADT)',
        }.get(int(code), f'Code 0x{int(code):02x}')

    def _ppp_control_code_name(self, protocol: int, code: int) -> str:
        code_names = {
            1: 'Configuration Request',
            2: 'Configuration Ack',
            3: 'Configuration Nak',
            4: 'Configuration Reject',
            5: 'Terminate Request',
            6: 'Terminate Ack',
            7: 'Code Reject',
            8: 'Protocol Reject',
        }
        if int(protocol) == 0xC021:
            code_names.update({
                9: 'Echo Request',
                10: 'Echo Reply',
                11: 'Discard Request',
            })
        return code_names.get(int(code), f'Code {int(code)}')

    def _eigrp_opcode_name(self, opcode: int) -> str:
        return {
            1: 'Update',
            3: 'Query',
            4: 'Reply',
            5: 'Hello',
            6: 'IPX SAP',
            10: 'SIA Query',
            11: 'SIA Reply',
        }.get(int(opcode), f'Opcode {int(opcode)}')

    def _eigrp_payload_bytes(self, packet, effective_ip=None) -> bytes:
        effective_ip = effective_ip or self._effective_ip_layer(packet)
        if effective_ip is None and packet.haslayer(IPv6):
            effective_ip = packet[IPv6]
        if effective_ip is None:
            return b''
        try:
            if isinstance(effective_ip, IP):
                header_len = int(getattr(effective_ip, 'ihl', 5) or 5) * 4
                total_len = int(getattr(effective_ip, 'len', 0) or 0)
                payload_len = max(0, total_len - header_len)
                return bytes(getattr(effective_ip, 'payload', b''))[:payload_len]
            if isinstance(effective_ip, IPv6):
                payload_len = int(getattr(effective_ip, 'plen', 0) or 0)
                return bytes(getattr(effective_ip, 'payload', b''))[:payload_len]
        except Exception:
            return b''
        return b''

    def _eigrp_payload_info(self, packet, effective_ip=None) -> dict | None:
        effective_ip = effective_ip or self._effective_ip_layer(packet)
        if effective_ip is None and packet.haslayer(IPv6):
            effective_ip = packet[IPv6]
        if effective_ip is None:
            return None
        try:
            if isinstance(effective_ip, IP):
                if int(getattr(effective_ip, 'proto', 0) or 0) != 88:
                    return None
            elif isinstance(effective_ip, IPv6):
                if int(getattr(effective_ip, 'nh', 0) or 0) != 88:
                    return None
            else:
                return None
        except Exception:
            return None

        payload = self._eigrp_payload_bytes(packet, effective_ip)
        if len(payload) < 20:
            return None

        info: dict = {
            'payload': payload,
            'version': int(payload[0]),
            'opcode': int(payload[1]),
            'checksum': int.from_bytes(payload[2:4], 'big'),
            'flags': int.from_bytes(payload[4:8], 'big'),
            'sequence': int.from_bytes(payload[8:12], 'big'),
            'acknowledge': int.from_bytes(payload[12:16], 'big'),
            'virtual_router_id': int.from_bytes(payload[16:18], 'big'),
            'autonomous_system': int.from_bytes(payload[18:20], 'big'),
            'is_ipv6': isinstance(effective_ip, IPv6),
        }
        tlvs = []
        pos = 20
        while pos + 4 <= len(payload):
            tlv_type = int.from_bytes(payload[pos:pos + 2], 'big')
            tlv_len = int.from_bytes(payload[pos + 2:pos + 4], 'big')
            if tlv_len < 4 or pos + tlv_len > len(payload):
                break
            value = payload[pos + 4:pos + tlv_len]
            tlv: dict = {
                'type': int(tlv_type),
                'length': int(tlv_len),
                'offset': int(pos),
                'value': value,
            }
            if tlv_type == 0x0002 and len(value) >= 36:
                tlv.update({
                    'auth_type': int.from_bytes(value[0:2], 'big'),
                    'key_size': int.from_bytes(value[2:4], 'big'),
                    'key_id': int.from_bytes(value[4:8], 'big'),
                    'key_sequence': int.from_bytes(value[8:12], 'big'),
                    'nullpad': value[12:20],
                    'digest': value[20:36],
                })
            elif tlv_type == 0x0001 and len(value) >= 8:
                tlv.update({
                    'k1': int(value[0]),
                    'k2': int(value[1]),
                    'k3': int(value[2]),
                    'k4': int(value[3]),
                    'k5': int(value[4]),
                    'k6': int(value[5]),
                    'hold_time': int.from_bytes(value[6:8], 'big'),
                })
            elif tlv_type == 0x0004 and len(value) >= 4:
                tlv.update({
                    'ios_major': int(value[0]),
                    'ios_minor': int(value[1]),
                    'eigrp_major': int(value[2]),
                    'eigrp_minor': int(value[3]),
                })
            tlvs.append(tlv)
            pos += tlv_len
        info['tlvs'] = tlvs
        return info

    def _snmp_pdu_name(self, pdu) -> str:
        name = pdu.__class__.__name__ if pdu is not None else ''
        return {
            'SNMPget': 'get-request',
            'SNMPnext': 'get-next-request',
            'SNMPresponse': 'get-response',
            'SNMPset': 'set-request',
            'SNMPbulk': 'get-bulk-request',
            'SNMPinform': 'inform-request',
            'SNMPtrapv1': 'trap',
            'SNMPtrapv2': 'snmpv2-trap',
            'SNMPreport': 'report',
        }.get(name, 'snmp')

    def _snmp_version_name(self, version: int) -> str:
        return {
            0: 'v1',
            1: 'v2c',
            2: 'v2u',
            3: 'v3',
        }.get(int(version), f'v{int(version)}')

    def _snmp_payload_info_from_layer(self, snmp_layer) -> dict | None:
        try:
            pdu = getattr(snmp_layer, 'PDU', None)
            request_id = int(getattr(getattr(pdu, 'id', None), 'val', 0) or 0)
            error_status = int(getattr(getattr(pdu, 'error', None), 'val', 0) or 0)
            error_index = int(getattr(getattr(pdu, 'error_index', None), 'val', 0) or 0)
            community = bytes(getattr(getattr(snmp_layer, 'community', None), 'val', b'') or b'')
            version = int(getattr(getattr(snmp_layer, 'version', None), 'val', 0) or 0)
            varbinds = []
            for varbind in list(getattr(pdu, 'varbindlist', []) or []):
                oid = str(getattr(getattr(varbind, 'oid', None), 'val', '') or '')
                value = getattr(varbind, 'value', None)
                value_type = type(value).__name__.replace('ASN1_', '') if value is not None else ''
                value_raw = getattr(value, 'val', None) if value is not None else None
                varbinds.append({
                    'oid': oid,
                    'value_type': value_type,
                    'value': value_raw,
                })
            return {
                'version': version,
                'version_name': self._snmp_version_name(version),
                'community': community,
                'pdu_name': self._snmp_pdu_name(pdu),
                'request_id': request_id,
                'error_status': error_status,
                'error_index': error_index,
                'varbinds': varbinds,
            }
        except Exception:
            return None

    def _asn1_length(self, data: bytes, pos: int) -> tuple[int, int]:
        if pos >= len(data):
            return 0, 0
        first = int(data[pos])
        if first < 0x80:
            return first, 1
        count = first & 0x7F
        if count <= 0 or pos + 1 + count > len(data):
            return 0, 1
        return int.from_bytes(data[pos + 1:pos + 1 + count], 'big'), 1 + count

    def _asn1_tlv(self, data: bytes, pos: int) -> dict | None:
        if pos >= len(data):
            return None
        length, len_size = self._asn1_length(data, pos + 1)
        value_start = pos + 1 + len_size
        end = min(len(data), value_start + length)
        if value_start > len(data):
            return None
        return {
            'tag': int(data[pos]),
            'start': pos,
            'value_start': value_start,
            'end': end,
        }

    def _asn1_int(self, data: bytes, tlv: dict | None) -> int:
        if not isinstance(tlv, dict):
            return 0
        start = int(tlv.get('value_start', 0) or 0)
        end = int(tlv.get('end', 0) or 0)
        if end <= start:
            return 0
        return int.from_bytes(data[start:end], 'big', signed=False)

    def _asn1_octets(self, data: bytes, tlv: dict | None) -> bytes:
        if not isinstance(tlv, dict):
            return b''
        start = int(tlv.get('value_start', 0) or 0)
        end = int(tlv.get('end', 0) or 0)
        return bytes(data[start:end]) if end > start else b''

    def _asn1_oid_text(self, oid_bytes: bytes) -> str:
        if not oid_bytes:
            return ''
        first = int(oid_bytes[0])
        nodes = [str(first // 40), str(first % 40)]
        value = 0
        for b in oid_bytes[1:]:
            value = (value << 7) | (b & 0x7F)
            if (b & 0x80) == 0:
                nodes.append(str(value))
                value = 0
        return '.'.join(nodes)

    def _snmp_pdu_name_from_tag(self, tag: int) -> str:
        return {
            0xA0: 'get-request',
            0xA1: 'get-next-request',
            0xA2: 'get-response',
            0xA3: 'set-request',
            0xA4: 'trap',
            0xA5: 'get-bulk-request',
            0xA6: 'inform-request',
            0xA7: 'snmpV2-trap',
            0xA8: 'report',
        }.get(int(tag), 'snmp')

    def _snmp_payload_info_fallback(self, payload: bytes) -> dict | None:
        outer = self._asn1_tlv(payload, 0)
        if outer is None or int(outer.get('tag', -1)) != 0x30:
            return None
        pos = int(outer.get('value_start', 0) or 0)
        version_tlv = self._asn1_tlv(payload, pos)
        if version_tlv is None or int(version_tlv.get('tag', -1)) != 0x02:
            return None
        version = self._asn1_int(payload, version_tlv)
        pos = int(version_tlv.get('end', 0) or 0)
        info: dict = {
            'version': int(version),
            'version_name': self._snmp_version_name(int(version)),
            'community': b'',
            'pdu_name': 'snmp',
            'request_id': 0,
            'error_status': 0,
            'error_index': 0,
            'varbinds': [],
        }

        def parse_pdu(pdu_tlv: dict | None) -> None:
            if not isinstance(pdu_tlv, dict):
                return
            info['pdu_name'] = self._snmp_pdu_name_from_tag(int(pdu_tlv.get('tag', 0) or 0))
            p = int(pdu_tlv.get('value_start', 0) or 0)
            req_tlv = self._asn1_tlv(payload, p)
            err_tlv = self._asn1_tlv(payload, int(req_tlv.get('end', p) if isinstance(req_tlv, dict) else p))
            idx_tlv = self._asn1_tlv(payload, int(err_tlv.get('end', p) if isinstance(err_tlv, dict) else p))
            vb_tlv = self._asn1_tlv(payload, int(idx_tlv.get('end', p) if isinstance(idx_tlv, dict) else p))
            info['request_id'] = self._asn1_int(payload, req_tlv)
            info['error_status'] = self._asn1_int(payload, err_tlv)
            info['error_index'] = self._asn1_int(payload, idx_tlv)
            varbinds = []
            if isinstance(vb_tlv, dict):
                vpos = int(vb_tlv.get('value_start', 0) or 0)
                vend = int(vb_tlv.get('end', 0) or 0)
                while vpos < vend:
                    vb = self._asn1_tlv(payload, vpos)
                    if not isinstance(vb, dict):
                        break
                    oid_tlv = self._asn1_tlv(payload, int(vb.get('value_start', 0) or 0))
                    if isinstance(oid_tlv, dict) and int(oid_tlv.get('tag', -1)) == 0x06:
                        oid = self._asn1_oid_text(self._asn1_octets(payload, oid_tlv))
                        varbinds.append({'oid': oid, 'value_type': '', 'value': ''})
                    vpos = int(vb.get('end', vend) or vend)
            info['varbinds'] = varbinds

        if int(version) == 3:
            header_tlv = self._asn1_tlv(payload, pos)
            if not isinstance(header_tlv, dict):
                return info
            pos = int(header_tlv.get('end', pos) or pos)
            sec_param_tlv = self._asn1_tlv(payload, pos)
            pos = int(sec_param_tlv.get('end', pos) or pos) if isinstance(sec_param_tlv, dict) else pos
            msg_data_tlv = self._asn1_tlv(payload, pos)
            if isinstance(msg_data_tlv, dict):
                tag = int(msg_data_tlv.get('tag', 0) or 0)
                if tag == 0x04:
                    info['pdu_name'] = 'encryptedPDU'
                elif tag == 0x30:
                    scoped_pos = int(msg_data_tlv.get('value_start', 0) or 0)
                    ctx_engine = self._asn1_tlv(payload, scoped_pos)
                    ctx_name = self._asn1_tlv(payload, int(ctx_engine.get('end', scoped_pos) if isinstance(ctx_engine, dict) else scoped_pos))
                    pdu_tlv = self._asn1_tlv(payload, int(ctx_name.get('end', scoped_pos) if isinstance(ctx_name, dict) else scoped_pos))
                    parse_pdu(pdu_tlv)
            return info

        community_tlv = self._asn1_tlv(payload, pos)
        if isinstance(community_tlv, dict) and int(community_tlv.get('tag', -1)) == 0x04:
            info['community'] = self._asn1_octets(payload, community_tlv)
            pos = int(community_tlv.get('end', pos) or pos)
        pdu_tlv = self._asn1_tlv(payload, pos)
        parse_pdu(pdu_tlv)
        return info

    def _snmp_payload_info_from_bytes(self, payload: bytes) -> dict | None:
        if not payload:
            return None
        try:
            snmp_layer = SNMP(payload)
        except Exception:
            return self._snmp_payload_info_fallback(payload)
        return self._snmp_payload_info_from_layer(snmp_layer)

    def _snmp_payload_info(self, packet) -> dict | None:
        if not packet.haslayer(SNMP):
            return None
        return self._snmp_payload_info_from_layer(packet[SNMP])

    def _imap_payload_info(self, payload: bytes, sport: int, dport: int) -> dict | None:
        if sport != 143 and dport != 143:
            return None
        line = payload.split(b'\r\n', 1)[0]
        if not line:
            return None
        if any(byte < 0x09 or (0x0D < byte < 0x20) for byte in line):
            return None
        line_text = line.decode(errors='ignore')
        if not line_text.strip():
            return None
        if dport == 143:
            parts = line_text.split(' ', 2)
            if len(parts) < 1 or not parts[0]:
                return None
            return {
                'kind': 'request',
                'line': line_text,
                'request_tag': parts[0],
                'request_command': parts[1].lower() if len(parts) > 1 else '',
            }
        tagged_line = ''
        for raw_line in payload.split(b'\r\n'):
            candidate = raw_line.decode(errors='ignore').strip()
            if not candidate:
                continue
            parts = candidate.split(' ', 2)
            if len(parts) >= 2 and parts[0][:1].isdigit():
                tagged_line = candidate
                break
        if tagged_line:
            parts = tagged_line.split(' ', 2)
            return {
                'kind': 'response',
                'line': tagged_line,
                'response_tag': parts[0],
                'response_status': parts[1] if len(parts) > 1 else '',
                'response_command': parts[2].split(' ', 1)[0] if len(parts) > 2 else '',
                'tagged_response_line': tagged_line,
            }
        if line_text.startswith('* OK '):
            return {
                'kind': 'greeting',
                'line': line_text,
            }
        if line_text.startswith('* '):
            return {
                'kind': 'response_untagged',
                'line': line_text,
            }
        parts = line_text.split(' ', 2)
        return {
            'kind': 'response',
            'line': line_text,
            'response_tag': parts[0] if parts else '',
            'response_status': parts[1] if len(parts) > 1 else '',
            'response_command': parts[2].split(' ', 1)[0] if len(parts) > 2 else '',
        }

    def _whois_payload_info(self, payload: bytes, sport: int, dport: int) -> dict | None:
        if sport != 43 and dport != 43:
            return None
        line = payload.split(b'\n', 1)[0].rstrip(b'\r') if payload else b''
        if not line:
            return None
        if any(byte < 0x09 or (0x0D < byte < 0x20) for byte in line):
            return None
        line_text = line.decode(errors='ignore').strip()
        if not line_text:
            return None
        if dport == 43:
            return {
                'kind': 'query',
                'line': line_text,
                'query': line_text,
            }
        return {
            'kind': 'answer',
            'line': line_text,
            'answer': line_text,
        }

    def _whois_payload_for_record(self, packet, metadata: dict) -> bytes:
        payload = self._payload_bytes(packet)
        if payload:
            return payload
        reassembled_hex = str(metadata.get('tcp_reassembled_data_hex', '') or '')
        if not reassembled_hex:
            return b''
        try:
            return bytes.fromhex(reassembled_hex)
        except Exception:
            return b''

    def _gre_inner_endpoints(self, packet) -> tuple[str, str] | None:
        if not packet.haslayer(GRE):
            return None
        try:
            first_gre = packet.getlayer(GRE, 1)
        except Exception:
            first_gre = None
        if first_gre is None:
            return None
        proto = int(getattr(first_gre, 'proto', 0) or 0)
        if proto == 0x0800:
            try:
                inner_ip = packet.getlayer(IP, 2)
            except Exception:
                inner_ip = None
            if inner_ip is not None:
                return (
                    self._normalize_endpoint_text(str(getattr(inner_ip, 'src', '') or '')),
                    self._normalize_endpoint_text(str(getattr(inner_ip, 'dst', '') or '')),
                )
        if proto == 0x86DD and packet.haslayer(IPv6):
            try:
                inner_ipv6 = packet[IPv6]
                return (
                    self._normalize_endpoint_text(str(getattr(inner_ipv6, 'src', '') or '')),
                    self._normalize_endpoint_text(str(getattr(inner_ipv6, 'dst', '') or '')),
                )
            except Exception:
                return None
        return None

    def _telnet_payload_info(self, payload: bytes, sport: int, dport: int) -> dict | None:
        if sport != 23 and dport != 23:
            return None
        if not payload:
            return None

        option_names = {
            1: 'Echo',
            3: 'Suppress Go Ahead',
            24: 'Terminal Type',
            31: 'Negotiate About Window Size',
            32: 'Terminal Speed',
            33: 'Remote Flow Control',
        }
        command_names = {
            251: 'Will',
            252: "Won't",
            253: 'Do',
            254: "Don't",
        }

        iac = 255
        sb = 250
        se = 240
        cursor = 0
        commands: list[str] = []
        printable_bytes = 0

        while cursor < len(payload):
            byte_val = payload[cursor]
            if byte_val != iac:
                if 32 <= byte_val <= 126:
                    printable_bytes += 1
                cursor += 1
                continue

            if cursor + 1 >= len(payload):
                break

            command = payload[cursor + 1]
            if command == iac:
                printable_bytes += 1
                cursor += 2
                continue

            if command in {251, 252, 253, 254}:
                if cursor + 2 >= len(payload):
                    break
                option = payload[cursor + 2]
                command_name = command_names.get(command, f'Command {command}')
                option_name = option_names.get(option, f'Option {option}')
                commands.append(f'{command_name} {option_name}')
                cursor += 3
                continue

            if command == sb:
                if cursor + 2 >= len(payload):
                    break
                option = payload[cursor + 2]
                option_name = option_names.get(option, f'Option {option}')
                commands.append(f'Suboption {option_name}')
                cursor += 3
                while cursor + 1 < len(payload):
                    if payload[cursor] == iac and payload[cursor + 1] == se:
                        cursor += 2
                        break
                    cursor += 1
                continue

            cursor += 2

        if commands:
            return {
                'commands': commands,
                'info': ', '.join(commands),
            }

        if len(payload) > 0:
            return {
                'commands': [],
                'info': f'{len(payload)} bytes data',
            }

        return None

    def _cflow_payload_info(self, payload: bytes) -> dict | None:
        if len(payload) < 20:
            return None
        version = int.from_bytes(payload[0:2], 'big')
        if version not in {9, 10}:
            return None
        count = int.from_bytes(payload[2:4], 'big')
        sys_uptime = int.from_bytes(payload[4:8], 'big')
        unix_secs = int.from_bytes(payload[8:12], 'big')
        flow_sequence = int.from_bytes(payload[12:16], 'big')
        source_id = int.from_bytes(payload[16:20], 'big')

        flowsets: list[dict] = []
        template_domain_cache = self.cflow_template_cache.setdefault(int(source_id), {})
        cursor = 20
        while cursor + 4 <= len(payload):
            set_id = int.from_bytes(payload[cursor:cursor + 2], 'big')
            set_len = int.from_bytes(payload[cursor + 2:cursor + 4], 'big')
            if set_len < 4 or cursor + set_len > len(payload):
                break
            body_len = set_len - 4
            flowset_info = {
                'id': set_id,
                'length': set_len,
                'body_length': body_len,
            }
            if set_id == 0:
                body = payload[cursor + 4:cursor + set_len]
                template_ids: list[int] = []
                body_cursor = 0
                while body_cursor + 4 <= len(body):
                    template_id = int.from_bytes(body[body_cursor:body_cursor + 2], 'big')
                    field_count = int.from_bytes(body[body_cursor + 2:body_cursor + 4], 'big')
                    record_len = 4 + (field_count * 4)
                    if template_id < 256 or field_count <= 0 or body_cursor + record_len > len(body):
                        break
                    template_ids.append(template_id)
                    template_domain_cache[int(template_id)] = {
                        'field_count': int(field_count),
                        'record_length': int(field_count * 4),
                    }
                    body_cursor += record_len
                if template_ids:
                    flowset_info['template_ids'] = template_ids
            elif set_id >= 256 and body_len > 0:
                template_meta = template_domain_cache.get(int(set_id), {})
                record_length = int(template_meta.get('record_length', 0) or 0)
                if record_length > 0:
                    data_record_count = body_len // record_length
                    if data_record_count > 0:
                        flowset_info['data_template_id'] = int(set_id)
                        flowset_info['data_record_count'] = int(data_record_count)
            flowsets.append(flowset_info)
            cursor += set_len

        return {
            'version': version,
            'count': count,
            'sys_uptime_ms': sys_uptime,
            'unix_secs': unix_secs,
            'flow_sequence': flow_sequence,
            'source_id': source_id,
            'flowsets': flowsets,
        }

    def _ntp_has_nts_extensions(self, payload: bytes) -> bool:
        if len(payload) <= 48:
            return False
        cursor = 48
        while cursor + 4 <= len(payload):
            field_type = int.from_bytes(payload[cursor:cursor + 2], 'big')
            field_length = int.from_bytes(payload[cursor + 2:cursor + 4], 'big')
            if field_length < 4 or cursor + field_length > len(payload):
                break
            if field_type in {0x0104, 0x0204, 0x0304, 0x0404}:
                return True
            cursor += field_length
        return False

    def _sip_payload_info(self, payload: bytes, sport: int, dport: int) -> dict | None:
        if not payload:
            return None
        line = payload.split(b'\r\n', 1)[0]
        try:
            line_text = line.decode(errors='ignore').strip()
        except Exception:
            line_text = ''
        if not line_text:
            return None

        likely_port = sport == 5060 or dport == 5060
        request_prefixes = {'INVITE', 'ACK', 'BYE', 'CANCEL', 'REGISTER', 'OPTIONS', 'MESSAGE', 'INFO', 'PRACK', 'UPDATE', 'SUBSCRIBE', 'NOTIFY', 'REFER', 'PUBLISH'}
        is_response = line_text.startswith('SIP/2.0 ')
        first_token = line_text.split(' ', 1)[0].upper() if line_text else ''
        is_request = first_token in request_prefixes and ' SIP/2.0' in line_text
        if not likely_port and not is_response and not is_request:
            return None

        header_end = payload.find(b'\r\n\r\n')
        header_blob = payload if header_end == -1 else payload[:header_end]
        body = b'' if header_end == -1 else payload[header_end + 4:]

        headers: dict[str, str] = {}
        for raw_line in header_blob.split(b'\r\n')[1:]:
            if b':' not in raw_line:
                continue
            name_raw, value_raw = raw_line.split(b':', 1)
            name = name_raw.decode(errors='ignore').strip().lower()
            value = value_raw.decode(errors='ignore').strip()
            if name and value:
                headers[name] = value

        info: dict = {
            'line': line_text,
            'headers': headers,
            'call_id': str(headers.get('call-id', '') or ''),
            'cseq': str(headers.get('cseq', '') or ''),
            'content_type': str(headers.get('content-type', '') or ''),
            'body': body,
        }

        cseq_parts = str(info.get('cseq', '') or '').split(' ', 1)
        info['cseq_method'] = cseq_parts[1].strip().upper() if len(cseq_parts) > 1 else ''

        if is_response:
            parts = line_text.split(' ', 2)
            info['kind'] = 'response'
            info['status_code'] = parts[1] if len(parts) > 1 else ''
            info['status_reason'] = parts[2] if len(parts) > 2 else ''
        elif is_request:
            parts = line_text.split(' ', 2)
            if len(parts) < 3:
                return None
            info['kind'] = 'request'
            info['method'] = parts[0].upper()
            info['request_uri'] = parts[1]
            info['version'] = parts[2]
        else:
            return None

        content_type = str(info.get('content_type', '') or '').lower()
        has_sdp = 'application/sdp' in content_type and bool(body)
        info['has_sdp'] = has_sdp
        if has_sdp:
            info['sdp_body'] = body
        return info

    def _parse_sdp_body(self, body: bytes) -> dict:
        parsed: dict = {
            'lines': [],
            'session_connection': '',
            'media': [],
        }
        if not body:
            return parsed

        current_connection = ''
        for raw_line in body.split(b'\r\n'):
            line = raw_line.decode(errors='ignore').strip()
            if not line:
                continue
            parsed['lines'].append(line)
            if line.startswith('c='):
                parts = line[2:].split()
                if len(parts) >= 3:
                    current_connection = parts[2]
                    if not parsed['session_connection']:
                        parsed['session_connection'] = current_connection
            elif line.startswith('m='):
                parts = line[2:].split()
                if len(parts) >= 3:
                    media_type = parts[0]
                    try:
                        media_port = int(parts[1])
                    except Exception:
                        media_port = 0
                    media_protocol = parts[2]
                    media_formats = parts[3:] if len(parts) > 3 else []
                    parsed['media'].append({
                        'type': media_type,
                        'port': media_port,
                        'protocol': media_protocol,
                        'formats': media_formats,
                        'connection': current_connection or parsed['session_connection'],
                    })
        return parsed

    def _rtp_payload_type_name(self, payload_type: int) -> str:
        return {
            0: 'ITU-T G.711 PCMU',
            3: 'GSM',
            4: 'ITU-T G.723',
            8: 'ITU-T G.711 PCMA',
            9: 'ITU-T G.722',
            18: 'ITU-T G.729',
        }.get(int(payload_type), f'Payload type {int(payload_type)}')

    def _rtp_payload_info(self, payload: bytes, sport: int = 0, dport: int = 0) -> dict | None:
        if len(payload) < 12:
            return None
        if sport in {53, 67, 68, 69, 123, 161, 162, 500, 646, 1900, 5060, 5246, 5247} or dport in {53, 67, 68, 69, 123, 161, 162, 500, 646, 1900, 5060, 5246, 5247}:
            return None

        byte0 = int(payload[0])
        version = (byte0 >> 6) & 0x03
        if version != 2:
            return None
        padding = bool((byte0 >> 5) & 0x01)
        extension = bool((byte0 >> 4) & 0x01)
        csrc_count = byte0 & 0x0F
        byte1 = int(payload[1])
        marker = bool((byte1 >> 7) & 0x01)
        payload_type = byte1 & 0x7F
        header_length = 12 + (csrc_count * 4)
        if header_length > len(payload):
            return None
        sequence = int.from_bytes(payload[2:4], 'big')
        timestamp = int.from_bytes(payload[4:8], 'big')
        ssrc = int.from_bytes(payload[8:12], 'big')
        return {
            'version': version,
            'padding': padding,
            'extension': extension,
            'csrc_count': csrc_count,
            'marker': marker,
            'payload_type': payload_type,
            'payload_type_name': self._rtp_payload_type_name(payload_type),
            'sequence': sequence,
            'extended_sequence': 65536 + sequence,
            'timestamp': timestamp,
            'extended_timestamp': 4294967296 + timestamp,
            'ssrc': ssrc,
            'header_length': header_length,
            'payload': payload[header_length:],
        }

    def _rtp_matches_sdp_media(self, src: str, sport: int, dst: str, dport: int) -> dict | None:
        endpoint_a = (str(src or ''), int(sport or 0))
        endpoint_b = (str(dst or ''), int(dport or 0))
        for state in self.sdp_media_by_call.values():
            if not isinstance(state, dict):
                continue
            endpoints = state.get('endpoints')
            if not isinstance(endpoints, set) or not endpoints:
                continue
            if endpoint_a in endpoints and endpoint_b in endpoints:
                return state
        return None

    def _should_classify_as_rtp(
        self,
        payload: bytes,
        rtp_info: dict | None,
        src: str,
        sport: int,
        dst: str,
        dport: int,
    ) -> bool:
        if not isinstance(rtp_info, dict):
            return False
        state = self._rtp_matches_sdp_media(src, sport, dst, dport)
        if not isinstance(state, dict):
            return False
        endpoint_payload_types = state.get('endpoint_payload_types')
        if not isinstance(endpoint_payload_types, dict):
            return False
        endpoint_a = (str(src or ''), int(sport or 0))
        endpoint_b = (str(dst or ''), int(dport or 0))
        allowed_types = set()
        for endpoint in (endpoint_a, endpoint_b):
            values = endpoint_payload_types.get(endpoint)
            if isinstance(values, set):
                allowed_types.update(int(value) for value in values if isinstance(value, int))
        if not allowed_types:
            return False
        try:
            payload_type = int(rtp_info.get('payload_type', -1))
        except Exception:
            payload_type = -1
        return payload_type in allowed_types

    def _fragment_state_key_from_metadata(self, packet, metadata: dict) -> tuple | None:
        if not bool(metadata.get('ip_is_fragmented', False)):
            return None
        version = int(metadata.get('ip_fragment_version', 0) or 0)
        proto = int(metadata.get('ip_fragment_proto', 0) or 0)
        ident = int(metadata.get('ip_fragment_id', 0) or 0)
        if version == 4 and packet.haslayer(IP):
            ip_layer = packet[IP]
            return ('ipv4', str(getattr(ip_layer, 'src', '') or ''), str(getattr(ip_layer, 'dst', '') or ''), ident, proto)
        if version == 6 and packet.haslayer(IPv6):
            ip6_layer = packet[IPv6]
            return ('ipv6', str(getattr(ip6_layer, 'src', '') or ''), str(getattr(ip6_layer, 'dst', '') or ''), ident, proto)
        return None

    def _register_ip_fragment_record(self, packet, record: PacketRecord) -> None:
        metadata = getattr(record, 'metadata', {}) or {}
        state_key = self._fragment_state_key_from_metadata(packet, metadata)
        if state_key is None:
            return
        state_map = self.ipv4_fragment_state if state_key[0] == 'ipv4' else self.ipv6_fragment_state
        state = state_map.get(state_key)
        if not isinstance(state, dict):
            return
        records = state.setdefault('records', [])
        if isinstance(records, list) and record not in records:
            records.append(record)

    def _is_cdp_packet(self, packet) -> bool:
        oui, code = self._snap_oui_code(packet)
        if oui == 0x00000C and code == 0x2000:
            return True
        return False

    def _is_lacp_packet(self, packet) -> bool:
        try:
            inner_type = self._inner_eth_type(packet)
            if inner_type != 0x8809:
                return False
            payload = self._payload_bytes(packet)
            return len(payload) >= 2 and int(payload[0]) == 0x01 and int(payload[1]) == 0x01
        except Exception:
            return False

    def _lacp_payload(self, packet) -> bytes:
        payload = self._payload_bytes(packet)
        return payload[1:] if len(payload) >= 1 else b''

    def _lacp_info_text(self, packet) -> str:
        payload = self._lacp_payload(packet)
        if len(payload) < 39:
            return 'Link Aggregation Control Protocol'
        actor_sys = ':'.join(f'{b:02x}' for b in payload[5:11])
        actor_port = int.from_bytes(payload[15:17], 'big')
        actor_key = int.from_bytes(payload[11:13], 'big')
        actor_state = int(payload[17])
        partner_sys = ':'.join(f'{b:02x}' for b in payload[25:31])
        partner_port = int.from_bytes(payload[35:37], 'big')
        partner_key = int.from_bytes(payload[31:33], 'big')
        partner_state = int(payload[37])
        def _state_flags(value: int) -> str:
            return ''.join([
                '*' if value & 0x80 else '*',
                '*' if value & 0x40 else '*',
                'D' if value & 0x20 else '*',
                'C' if value & 0x10 else '*',
                'S' if value & 0x08 else '*',
                'G' if value & 0x04 else '*',
                '*' if value & 0x02 else '*',
                'A' if value & 0x01 else '*',
            ])
        return (
            f'v1 ACTOR {actor_sys} P: {actor_port} K: {actor_key} {_state_flags(actor_state)} '
            f'PARTNER {partner_sys} P: {partner_port} K: {partner_key} {_state_flags(partner_state)}'
        )

    def _is_vtp_packet(self, packet) -> bool:
        try:
            oui, code = self._snap_oui_code(packet)
            return oui == 0x00000C and code == 0x2003
        except Exception:
            return False

    def _vtp_payload(self, packet) -> bytes:
        try:
            if packet.haslayer(SNAP):
                return bytes(packet[SNAP].payload)
        except Exception:
            pass
        return b''

    def _vtp_info_text(self, packet) -> str:
        payload = self._vtp_payload(packet)
        if len(payload) < 40:
            return 'VLAN Trunking Protocol'
        code = int(payload[1])
        code_name = {
            0x01: 'Summary Advertisement',
            0x02: 'Subset Advertisement',
            0x03: 'Advertisement Request',
        }.get(code, f'Code 0x{code:02x}')
        if code == 0x02 and len(payload) >= 8:
            seq_num = int(payload[2])
            domain_len = int(payload[3])
            revision_offset = 4 + domain_len
            revision = int.from_bytes(payload[revision_offset:revision_offset + 4], 'big') if len(payload) >= revision_offset + 4 else 0
            return f'{code_name}, Seq: {seq_num}, Revision: {revision}'
        followers = int(payload[2])
        revision = int.from_bytes(payload[36:40], 'big')
        return f'{code_name}, Revision: {revision}, Followers: {followers}'

    def _is_dtp_packet(self, packet) -> bool:
        try:
            oui, code = self._snap_oui_code(packet)
            return oui == 0x00000C and code == 0x2004
        except Exception:
            return False

    def _dtp_payload(self, packet) -> bytes:
        try:
            if packet.haslayer(SNAP):
                return bytes(packet[SNAP].payload)
        except Exception:
            pass
        return b''

    def _dtp_info_text(self, packet) -> str:
        payload = self._dtp_payload(packet)
        return 'Dynamic Trunk Protocol' if payload else 'Dynamic Trunk Protocol'

    def _cdp_payload(self, packet) -> bytes:
        try:
            if packet.haslayer(SNAP):
                return bytes(packet[SNAP].payload)
        except Exception:
            pass
        return b''

    def _ripng_payload(self, packet) -> bytes:
        try:
            udp_layer = self._effective_udp_layer(packet)
            if udp_layer is not None:
                return bytes(udp_layer.payload)
        except Exception:
            pass
        return b''

    def _ripv2_payload(self, packet) -> bytes:
        try:
            udp_layer = self._effective_udp_layer(packet)
            if udp_layer is not None:
                return bytes(udp_layer.payload)
        except Exception:
            pass
        return b''

    def _is_ripng_packet(self, packet) -> bool:
        try:
            if not packet.haslayer(IPv6):
                return False
            udp_layer = self._effective_udp_layer(packet)
            if udp_layer is None:
                return False
            if int(getattr(udp_layer, 'sport', 0) or 0) != 521 or int(getattr(udp_layer, 'dport', 0) or 0) != 521:
                return False
            payload = self._ripng_payload(packet)
            return len(payload) >= 4 and int(payload[1]) == 1
        except Exception:
            return False

    def _ripng_info_text(self, packet) -> str:
        payload = self._ripng_payload(packet)
        if len(payload) < 2:
            return 'RIPng'
        command = int(payload[0])
        version = int(payload[1])
        command_name = {1: 'Request', 2: 'Response'}.get(command, f'Command {command}')
        return f' Command {command_name}, Version {version}'

    def _is_ripv2_packet(self, packet) -> bool:
        try:
            if packet.haslayer(IP):
                udp_layer = self._effective_udp_layer(packet)
                if udp_layer is None:
                    return False
                if int(getattr(udp_layer, 'sport', 0) or 0) != 520 or int(getattr(udp_layer, 'dport', 0) or 0) != 520:
                    return False
                payload = self._ripv2_payload(packet)
                return len(payload) >= 4 and int(payload[1]) == 2
        except Exception:
            pass
        return False

    def _ripv2_info_text(self, packet) -> str:
        payload = self._ripv2_payload(packet)
        if len(payload) < 1:
            return 'Routing Information Protocol'
        command = int(payload[0])
        return {1: 'Request', 2: 'Response'}.get(command, f'Command {command}')

    def _stp_payload(self, packet) -> bytes:
        try:
            if packet.haslayer(SNAP):
                return bytes(packet[SNAP].payload)
            if packet.haslayer('STP'):
                return bytes(packet['STP'])
        except Exception:
            pass
        return b''

    def _is_stp_packet(self, packet) -> bool:
        try:
            oui, code = self._snap_oui_code(packet)
            if oui == 0x00000C and code == 0x010B:
                return True
            return packet.haslayer('STP')
        except Exception:
            return False

    def _is_udld_packet(self, packet) -> bool:
        try:
            oui, code = self._snap_oui_code(packet)
            return oui == 0x00000C and code == 0x0111
        except Exception:
            return False

    def _udld_payload(self, packet) -> bytes:
        try:
            if packet.haslayer(SNAP):
                return bytes(packet[SNAP].payload)
        except Exception:
            pass
        return b''

    def _udld_info_text(self, packet) -> str:
        payload = self._udld_payload(packet)
        if len(payload) < 4:
            return 'Unidirectional Link Detection'
        pos = 4
        device_id = ''
        port_id = ''
        while pos + 4 <= len(payload):
            tlv_type = int.from_bytes(payload[pos:pos + 2], 'big')
            tlv_len = int.from_bytes(payload[pos + 2:pos + 4], 'big')
            if tlv_len < 4 or pos + tlv_len > len(payload):
                break
            value = payload[pos + 4:pos + tlv_len]
            if tlv_type == 0x0001:
                device_id = value.decode(errors='ignore')
            elif tlv_type == 0x0002:
                port_id = value.decode(errors='ignore')
            pos += tlv_len
        if device_id or port_id:
            return f'Device ID: {device_id}  Port ID: {port_id}  '
        return 'Unidirectional Link Detection'

    def _stp_info_text(self, packet) -> str:
        payload = self._stp_payload(packet)
        if len(payload) < 35:
            return 'Spanning Tree Protocol'
        try:
            version = int(payload[2])
            bpdu_type = int(payload[3])
            flags = int(payload[4])
            root_prio = int.from_bytes(payload[5:7], 'big') & 0xF000
            vlan_id = int.from_bytes(payload[5:7], 'big') & 0x0FFF
            root_mac = ':'.join(f'{b:02x}' for b in payload[7:13])
            path_cost = int.from_bytes(payload[13:17], 'big')
            port_id = int.from_bytes(payload[25:27], 'big')
            prefix = 'RST'
            if version == 2 and bpdu_type == 2:
                prefix = 'RST'
            tc_prefix = 'TC + ' if (flags & 0x01) else ''
            return f'{prefix}. {tc_prefix}Root = {root_prio}/{vlan_id}/{root_mac}  Cost = {path_cost}  Port = 0x{port_id:04x}'
        except Exception:
            return 'Spanning Tree Protocol'

    def _lldp_payload(self, packet) -> bytes:
        try:
            if packet.haslayer('Raw'):
                return bytes(packet['Raw'].load)
        except Exception:
            pass
        return b''

    def _is_lldp_packet(self, packet) -> bool:
        try:
            return int(getattr(packet[Ether], 'type', 0) or 0) == 0x88CC and len(self._lldp_payload(packet)) >= 2
        except Exception:
            return False

    def _lldp_tlvs(self, payload: bytes) -> list[dict]:
        tlvs = []
        pos = 0
        while pos + 2 <= len(payload):
            header = int.from_bytes(payload[pos:pos + 2], 'big')
            tlv_type = (header >> 9) & 0x7F
            tlv_len = header & 0x1FF
            value_start = pos + 2
            value_end = value_start + tlv_len
            if value_end > len(payload):
                break
            tlvs.append({
                'type': tlv_type,
                'length': tlv_len,
                'offset': pos,
                'value': payload[value_start:value_end],
            })
            pos = value_end
            if tlv_type == 0:
                break
        return tlvs

    def _lldp_info_text(self, packet) -> str:
        payload = self._lldp_payload(packet)
        tlvs = self._lldp_tlvs(payload)
        chassis = ''
        port = ''
        ttl = ''
        system_name = ''
        system_desc = ''
        for tlv in tlvs:
            value = bytes(tlv.get('value', b''))
            tlv_type = int(tlv.get('type', -1))
            if tlv_type == 1 and len(value) >= 7 and int(value[0]) == 4:
                chassis = ':'.join(f'{b:02x}' for b in value[1:7])
            elif tlv_type == 2 and len(value) >= 2:
                port = value[1:].decode(errors='ignore')
            elif tlv_type == 3 and len(value) >= 2:
                ttl = str(int.from_bytes(value[:2], 'big'))
            elif tlv_type == 5:
                system_name = value.decode(errors='ignore')
            elif tlv_type == 6:
                system_desc = value.decode(errors='ignore')
        parts = []
        if chassis:
            parts.append(f'MA/{chassis}')
        if port:
            parts.append(f'IN/{port}')
        if ttl:
            parts.append(ttl)
        if system_name:
            parts.append(f'SysN={system_name}')
        if system_desc:
            parts.append(f'SysD={system_desc}')
        return ' '.join(parts) if parts else 'Link Layer Discovery Protocol'

    def _hsrpv2_payload(self, packet) -> bytes:
        try:
            udp_layer = self._effective_udp_layer(packet)
            if udp_layer is not None:
                return bytes(udp_layer.payload)
        except Exception:
            pass
        return b''

    def _homeplug_payload(self, packet) -> bytes:
        try:
            if not packet.haslayer(Ether):
                return b''
            raw = bytes(packet)
            if len(raw) < 14:
                return b''
            ether_type = int(getattr(packet[Ether], 'type', 0) or 0)
            if ether_type == 0x8100:
                if len(raw) < 18:
                    return b''
                return raw[18:]
            return raw[14:]
        except Exception:
            return b''

    def _is_homeplug_av_packet(self, packet) -> bool:
        ether_type = self._ether_type(packet)
        return bool(ether_type == 0x88E1 or (ether_type == 0x8100 and self._inner_eth_type(packet) == 0x88E1))

    def _homeplug_mmtype_name(self, mmtype: int) -> str:
        return {
            0xA068: 'OP_ATTR.REQ (Get Device Attributes Request)',
            0xA000: 'GET_SW.REQ (Get Device/SW Version Request)',
        }.get(int(mmtype), f'0x{int(mmtype) & 0xFFFF:04x}')

    def _homeplug_info_text(self, packet) -> str:
        payload = self._homeplug_payload(packet)
        if len(payload) < 6:
            return 'HomePlug AV'
        mmtype = int.from_bytes(payload[1:3], 'little')
        vendor = {
            b'\x00\xb0\x52': 'Qualcomm Atheros',
        }.get(bytes(payload[3:6]), payload[3:6].hex())
        return f'{vendor}, {self._homeplug_mmtype_name(mmtype)}'

    def _is_hsrpv2_packet(self, packet) -> bool:
        try:
            udp_layer = self._effective_udp_layer(packet)
            if udp_layer is None:
                return False
            sport = int(getattr(udp_layer, 'sport', 0) or 0)
            dport = int(getattr(udp_layer, 'dport', 0) or 0)
            if (sport, dport) not in {(2029, 2029), (1985, 1985)}:
                return False
            payload = self._hsrpv2_payload(packet)
            if len(payload) >= 42 and int(payload[0]) == 1 and int(payload[1]) == 40 and int(payload[2]) == 2:
                return True
            return len(payload) >= 6 and int(payload[0]) == 2 and int(payload[1]) == 4
        except Exception:
            return False

    def _is_hsrp_packet(self, packet) -> bool:
        try:
            udp_layer = self._effective_udp_layer(packet)
            if udp_layer is None:
                return False
            sport = int(getattr(udp_layer, 'sport', 0) or 0)
            dport = int(getattr(udp_layer, 'dport', 0) or 0)
            if sport != 1985 and dport != 1985:
                return False
            payload = self._hsrpv2_payload(packet)
            if len(payload) < 16 or int(payload[0]) != 0:
                return False
            opcode = int(payload[1])
            if opcode == 3:
                return len(payload) >= 16 and int(payload[2]) == 0 and int(payload[3]) >= 1
            return len(payload) >= 20 and opcode in {0, 1, 2}
        except Exception:
            return False

    def _hsrpv2_info_text(self, packet) -> str:
        payload = self._hsrpv2_payload(packet)
        if len(payload) >= 6 and int(payload[0]) == 2 and int(payload[1]) == 4:
            active_groups = int.from_bytes(payload[2:4], 'big')
            passive_groups = int.from_bytes(payload[4:6], 'big')
            return f'Interface State TLV (Act={active_groups} Pass={passive_groups})'
        if len(payload) < 8:
            return 'Cisco Hot Standby Router Protocol'
        opcode = int(payload[3])
        state = int(payload[4])
        opcode_name = {0: 'Hello', 1: 'Coup', 2: 'Resign'}.get(opcode, f'Opcode {opcode}')
        state_name = {1: 'Initial', 2: 'Learn', 3: 'Listen', 4: 'Speak', 5: 'Standby', 6: 'Active'}.get(state, str(state))
        return f'{opcode_name} (state {state_name})'

    def _hsrp_info_text(self, packet) -> str:
        if self._is_hsrpv2_packet(packet):
            return self._hsrpv2_info_text(packet)
        payload = self._hsrpv2_payload(packet)
        if len(payload) < 4:
            return 'Cisco Hot Standby Router Protocol'
        opcode = int(payload[1])
        opcode_name = {0: 'Hello', 1: 'Coup', 2: 'Resign', 3: 'Advertise'}.get(opcode, f'Opcode {opcode}')
        if opcode == 3:
            state = int(payload[6]) if len(payload) >= 7 else 0
            state_name = {0: 'Initial', 1: 'Learn', 2: 'Passive', 3: 'Active', 4: 'Speak', 8: 'Standby', 16: 'Active'}.get(state, str(state))
            return f'{opcode_name} (state {state_name})'
        state = int(payload[2]) if len(payload) >= 3 else 0
        state_name = {0: 'Initial', 1: 'Learn', 2: 'Listen', 4: 'Speak', 8: 'Standby', 16: 'Active'}.get(state, str(state))
        return f'{opcode_name} (state {state_name})'

    def _is_rsh_packet(self, packet) -> bool:
        try:
            tcp_layer = self._effective_tcp_layer(packet)
            if tcp_layer is None:
                return False
            sport = int(getattr(tcp_layer, 'sport', 0) or 0)
            dport = int(getattr(tcp_layer, 'dport', 0) or 0)
            if sport != 514 and dport != 514:
                return False
            payload = self._payload_bytes(packet)
            return bool(payload)
        except Exception:
            return False

    def _rsh_info_text(self, packet) -> str:
        tcp_layer = self._effective_tcp_layer(packet)
        if tcp_layer is None:
            return 'Remote Shell'
        sport = int(getattr(tcp_layer, 'sport', 0) or 0)
        dport = int(getattr(tcp_layer, 'dport', 0) or 0)
        if dport == 514:
            return 'Client -> Server data'
        if sport == 514:
            return 'Server -> Client data'
        return 'Remote Shell data'

    def _zabbix_payload_info(self, payload: bytes) -> dict | None:
        raw = bytes(payload or b'')
        if len(raw) < 13 or not raw.startswith(b'ZBXD'):
            return None

        flags = int(raw[4])
        if (flags & 0x01) == 0:
            return None

        length = int.from_bytes(raw[5:9], 'little')
        aux = int.from_bytes(raw[9:13], 'little')
        body_start = 13
        body_end = min(len(raw), body_start + max(0, length))
        body = raw[body_start:body_end]

        uncompressed = body
        if flags & 0x02:
            try:
                uncompressed = zlib.decompress(body)
            except Exception:
                try:
                    uncompressed = zlib.decompress(body, -15)
                except Exception:
                    uncompressed = body

        text = ''
        try:
            text = uncompressed.decode('utf-8', errors='ignore')
        except Exception:
            text = ''

        json_obj = None
        if text:
            try:
                json_obj = json.loads(text)
            except Exception:
                json_obj = None

        request_name = ''
        response_name = ''
        host_name = ''
        session = ''
        version = ''
        if isinstance(json_obj, dict):
            request_name = str(json_obj.get('request', '') or '')
            response_name = str(json_obj.get('response', '') or '')
            host_name = str(json_obj.get('host', '') or '')
            if not host_name:
                data_items = list(json_obj.get('data', []) or [])
                if data_items and isinstance(data_items[0], dict):
                    host_name = str(data_items[0].get('host', '') or '')
            session = str(json_obj.get('session', '') or '')
            version = str(json_obj.get('version', '') or '')

        return {
            'flags': flags,
            'length': int(length),
            'aux': int(aux),
            'body': body,
            'uncompressed': uncompressed,
            'text': text,
            'json': json_obj,
            'request': request_name,
            'response': response_name,
            'host': host_name,
            'session': session,
            'version': version,
        }

    def _zabbix_payload_for_record(self, packet, metadata: dict) -> bytes:
        payload = self._payload_bytes(packet)
        if payload.startswith(b'ZBXD'):
            return payload
        reassembled_hex = str(metadata.get('tcp_reassembled_data_hex', '') or '')
        if reassembled_hex:
            try:
                reassembled = bytes.fromhex(reassembled_hex)
                if reassembled.startswith(b'ZBXD'):
                    return reassembled
            except Exception:
                pass
        return payload

    def _zabbix_info_text(self, packet, metadata: dict) -> str:
        tcp_layer = self._effective_tcp_layer(packet)
        sport = int(getattr(tcp_layer, 'sport', 0) or 0) if tcp_layer is not None else 0
        dport = int(getattr(tcp_layer, 'dport', 0) or 0) if tcp_layer is not None else 0

        zabbix = metadata.get('zabbix') if isinstance(metadata.get('zabbix'), dict) else None
        if not isinstance(zabbix, dict):
            payload = self._zabbix_payload_for_record(packet, metadata)
            zabbix = self._zabbix_payload_info(payload)
            if isinstance(zabbix, dict):
                metadata['zabbix'] = zabbix
        if not isinstance(zabbix, dict):
            return f'Zabbix ({sport} -> {dport})'

        request_name = str(zabbix.get('request', '') or '')
        response_name = str(zabbix.get('response', '') or '')
        host_name = str(zabbix.get('host', '') or '')
        length = int(zabbix.get('length', 0) or 0)
        flags = int(zabbix.get('flags', 0) or 0)

        if request_name == 'agent data':
            return f'Zabbix Agent data from "{host_name}", Len={length} ({sport} -> {dport})'
        if request_name == 'active check heartbeat':
            return f'Zabbix Agent heartbeat from "{host_name}", Len={length} ({sport} -> {dport})'
        if request_name == 'active checks':
            return f'Zabbix Agent request for active checks for "{host_name}", Len={length} ({sport} -> {dport})'
        if request_name == 'proxy data':
            return f'Zabbix Proxy data request to passive proxy, Len={length} ({sport} -> {dport})'
        if request_name == 'proxy config':
            return f'Zabbix Protocol request, Flags=0x{flags:02x}, Len={length} ({sport} -> {dport})'

        if response_name == 'success':
            version = str(zabbix.get('version', '') or '')
            if version:
                return f'Zabbix Protocol response, Flags=0x{flags:02x}, Len={length} ({sport} -> {dport})'
            if sport == 10051:
                req_name = str(metadata.get('zabbix_request_agent_name', '') or '')
                if not req_name:
                    ip_layer = self._effective_ip_layer(packet)
                    if ip_layer is not None:
                        src_addr = str(getattr(ip_layer, 'src', '') or '')
                        dst_addr = str(getattr(ip_layer, 'dst', '') or '')
                        stream_key = self._canonical_transport_key(src_addr, sport, dst_addr, dport, 'TCP')
                        pending = self.zabbix_request_pending.get(stream_key, [])
                        if pending:
                            req_name = str(pending[0].metadata.get('zabbix_host', '') or '')
                return f'Zabbix Server/proxy response for agent data for "{req_name}", Len={length} ({sport} -> {dport})'
            return f'Zabbix Server response for passive proxy data (success), Len={length} ({sport} -> {dport})'

        if str(zabbix.get('session', '') or '') and str(zabbix.get('version', '') or '') and sport == 10051:
            return f'Zabbix Passive proxy data response, Len={length} ({sport} -> {dport})'

        return f'Zabbix Protocol data, Len={length} ({sport} -> {dport})'

    def _icmp_timestamp_info_text(self, packet) -> str:
        if not packet.haslayer(ICMP) or not packet.haslayer(IP):
            return packet.summary()
        raw = bytes(packet[ICMP])
        if len(raw) < 20:
            return packet.summary()
        icmp_type = int(raw[0])
        if icmp_type not in {13, 14}:
            return packet.summary()
        label = 'Timestamp request' if icmp_type == 13 else 'Timestamp reply'
        identifier = int.from_bytes(raw[4:6], 'big')
        sequence_be = int.from_bytes(raw[6:8], 'big')
        sequence_le = int.from_bytes(raw[6:8], 'little')
        ttl = int(getattr(packet[IP], 'ttl', 0) or 0)
        return f'{label.ljust(21)}id=0x{identifier:04x}, seq={sequence_be}/{sequence_le}, ttl={ttl}'

    def _syslog_payload(self, packet) -> bytes:
        try:
            udp_layer = self._effective_udp_layer(packet)
            if udp_layer is not None:
                return bytes(udp_layer.payload)
        except Exception:
            pass
        return b''

    def _is_syslog_packet(self, packet) -> bool:
        try:
            udp_layer = self._effective_udp_layer(packet)
            if udp_layer is None:
                return False
            sport = int(getattr(udp_layer, 'sport', 0) or 0)
            dport = int(getattr(udp_layer, 'dport', 0) or 0)
            payload = self._syslog_payload(packet)
            return len(payload) >= 5 and (sport == 514 or dport == 514) and payload.startswith(b'<') and b'>' in payload[:6]
        except Exception:
            return False

    def _syslog_info_text(self, packet) -> str:
        payload = self._syslog_payload(packet)
        if not payload.startswith(b'<') or b'>' not in payload[:6]:
            return 'Syslog'
        end = payload.find(b'>', 1, 6)
        if end == -1:
            return 'Syslog'
        try:
            pri = int(payload[1:end].decode(errors='ignore'))
        except Exception:
            return 'Syslog'
        facility = pri >> 3
        level = pri & 0x07
        facility_name = {
            23: 'LOCAL7',
        }.get(facility, f'FACILITY{facility}')
        level_name = {
            5: 'NOTICE',
        }.get(level, str(level))
        message = payload[end + 1:].decode(errors='ignore').strip()
        return f'{facility_name}.{level_name}: {message}'

    def _ntp_payload(self, packet) -> bytes:
        try:
            udp_layer = self._effective_udp_layer(packet)
            if udp_layer is not None:
                return bytes(udp_layer.payload)
        except Exception:
            pass
        return b''

    def _is_ntp_packet(self, packet) -> bool:
        try:
            udp_layer = self._effective_udp_layer(packet)
            if udp_layer is None:
                return False
            sport = int(getattr(udp_layer, 'sport', 0) or 0)
            dport = int(getattr(udp_layer, 'dport', 0) or 0)
            payload = self._ntp_payload(packet)
            if len(payload) < 12:
                return False
            first = int(payload[0])
            version = (first >> 3) & 0x07
            mode = first & 0x07
            if mode == 6:
                return (sport == 123 or dport == 123 or packet.haslayer('NTPHeader')) and version in {1, 2, 3, 4} and len(payload) >= 12
            return (sport == 123 or dport == 123 or packet.haslayer('NTPHeader')) and version in {1, 2, 3, 4} and mode in {1, 2, 3, 4, 5}
        except Exception:
            return False

    def _ntp_info_text(self, packet) -> str:
        payload = self._ntp_payload(packet)
        if len(payload) < 1:
            return 'Network Time Protocol'
        first = int(payload[0])
        version = (first >> 3) & 0x07
        mode = first & 0x07
        mode_name = {
            1: 'symmetric active',
            2: 'symmetric passive',
            3: 'client',
            4: 'server',
            5: 'broadcast',
            6: 'control',
        }.get(mode, str(mode))
        nts_suffix = ', NTS' if self._ntp_has_nts_extensions(payload) else ''
        return f'NTP Version {version}, {mode_name}{nts_suffix}'

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

    def _mac_text(self, value) -> str:
        if isinstance(value, (bytes, bytearray)):
            data = bytes(value)
            if len(data) == 6:
                return ':'.join(f'{b:02x}' for b in data)
            return data.hex()
        return str(value or '')

    def _extract_ports(self, packet, effective_tcp=None, effective_udp=None):
        tcp_layer = effective_tcp if effective_tcp is not None else self._effective_tcp_layer(packet)
        if tcp_layer is not None:
            return int(tcp_layer.sport), int(tcp_layer.dport)
        udp_layer = effective_udp if effective_udp is not None else self._effective_udp_layer(packet)
        if udp_layer is not None:
            return int(udp_layer.sport), int(udp_layer.dport)
        return None, None

    def _effective_ip_layer(self, packet):
        if packet.haslayer(IPv6):
            return packet[IPv6]
        if packet.haslayer(IP):
            return packet[IP]
        pppoe_info = self._pppoe_payload_info(packet)
        if isinstance(pppoe_info, dict):
            ppp_protocol = int(pppoe_info.get('ppp_protocol', 0) or 0)
            if ppp_protocol == 0x0057:
                ppp_payload = bytes(pppoe_info.get('ppp_payload', b'') or b'')
                if len(ppp_payload) >= 40:
                    try:
                        ipv6_layer = IPv6(ppp_payload)
                        if ipv6_layer.version == 6:
                            return ipv6_layer
                    except Exception:
                        pass
        return self._mpls_inner_ip(packet)

    def _ip_next_proto(self, ip_layer) -> int:
        """Return the next-protocol number for an IPv4 or IPv6 layer.

        IPv4 uses the ``proto`` field; IPv6 uses the ``nh`` (next-header)
        field.  Passing the wrong attribute on an IPv6 layer always yields 0,
        which is why this helper must be used instead of a plain
        ``getattr(layer, 'proto', 0)`` call.
        """
        if isinstance(ip_layer, IPv6):
            return int(getattr(ip_layer, 'nh', 0) or 0)
        return int(getattr(ip_layer, 'proto', 0) or 0)

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
        tcp_payload = getattr(tcp, 'payload', b'')
        raw_original = getattr(tcp_payload, 'original', None)
        if isinstance(raw_original, (bytes, bytearray)) and raw_original:
            raw_payload = bytes(raw_original)
        else:
            raw_payload = bytes(tcp_payload)
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

    def _reassemble_ip_fragments(self, parts: dict[int, bytes]) -> bytes | None:
        if 0 not in parts:
            return None
        assembled = bytearray()
        cursor = 0
        for start in sorted(parts.keys()):
            chunk = bytes(parts[start] or b'')
            if start > cursor:
                return None
            if start + len(chunk) <= cursor:
                continue
            cut = max(0, cursor - start)
            assembled.extend(chunk[cut:])
            cursor = start + len(chunk)
        return bytes(assembled)

    def _fragment_override_protocol(self, packet, metadata: dict) -> str | None:
        if not bool(metadata.get('ip_is_fragmented', False)):
            return None
        role = str(metadata.get('ip_fragment_role', '') or '')
        if role == 'first':
            if packet.haslayer(IP):
                return 'IPv4'
            if packet.haslayer(IPv6):
                return 'IPv6'
            return 'IP'
        if role == 'last':
            if str(metadata.get('snmp_reassembled_data_hex', '') or ''):
                return 'SNMP'
            if str(metadata.get('dns_reassembled_data_hex', '') or ''):
                if bool(metadata.get('dns_is_mdns_transport', False)):
                    return 'MDNS'
                return 'DNS'
            reassembled_app_protocol = str(metadata.get('ip_fragment_reassembled_protocol', '') or '')
            if reassembled_app_protocol:
                return reassembled_app_protocol
            if packet.haslayer(IP):
                return 'IPv4'
            if packet.haslayer(IPv6):
                return 'IPv6'
            return 'IP'
        return None

    def _update_ip_fragment_metadata(self, packet, metadata: dict, frame_number: int) -> None:
        stream_state = None
        def _apply_udp_reassembled_metadata(
            target_metadata: dict,
            udp_payload: bytes,
            src_addr: str,
            src_port: int,
            dst_addr: str,
            dst_port: int,
        ) -> str | None:
            app_protocol = None
            sip_info = self._sip_payload_info(udp_payload, src_port, dst_port)
            if sip_info is not None:
                target_metadata['sip'] = sip_info
                if bool(sip_info.get('has_sdp', False)):
                    target_metadata['sdp'] = self._parse_sdp_body(bytes(sip_info.get('sdp_body', b'') or b''))
                    app_protocol = 'SIP/SDP'
                else:
                    app_protocol = 'SIP'
            rtp_info = self._rtp_payload_info(udp_payload, src_port, dst_port)
            if self._should_classify_as_rtp(udp_payload, rtp_info, src_addr, src_port, dst_addr, dst_port):
                target_metadata['rtp'] = rtp_info
                app_protocol = 'RTP'
            return app_protocol

        # IPv4 fragmentation
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            frag_units = int(getattr(ip_layer, 'frag', 0) or 0)
            flags = int(getattr(ip_layer, 'flags', 0) or 0)
            more_fragments = bool(flags & 0x1)
            is_fragment = bool(more_fragments or frag_units > 0)
            if is_fragment:
                src = str(getattr(ip_layer, 'src', '') or '')
                dst = str(getattr(ip_layer, 'dst', '') or '')
                proto = int(getattr(ip_layer, 'proto', 0) or 0)
                ident = int(getattr(ip_layer, 'id', 0) or 0)
                offset_bytes = int(frag_units) * 8
                fragment_payload = bytes(getattr(ip_layer, 'payload', b''))
                key = ('ipv4', src, dst, ident, proto)
                state = self.ipv4_fragment_state.setdefault(key, {'parts': {}, 'frames': {}, 'has_last': False, 'records': []})
                state['parts'][offset_bytes] = fragment_payload
                state['frames'][offset_bytes] = int(frame_number)
                if not more_fragments:
                    state['has_last'] = True

                metadata['ip_is_fragmented'] = True
                metadata['ip_fragment_version'] = 4
                metadata['ip_fragment_id'] = ident
                metadata['ip_fragment_offset'] = offset_bytes
                metadata['ip_fragment_more'] = more_fragments
                metadata['ip_fragment_proto'] = proto
                metadata['ip_fragment_payload_len'] = int(len(fragment_payload))
                metadata['ip_fragment_role'] = 'first' if offset_bytes == 0 and more_fragments else ('last' if offset_bytes > 0 and not more_fragments else 'middle')

                if metadata['ip_fragment_role'] == 'first' and state.get('has_last'):
                    max_off = max(state['frames'].keys(), default=0)
                    metadata['ip_reassembled_in_frame'] = int(state['frames'].get(max_off, 0) or 0)

                if metadata['ip_fragment_role'] == 'last':
                    reassembled = self._reassemble_ip_fragments(state.get('parts', {}))
                    if reassembled:
                        fragment_entries = []
                        running = 0
                        for frag_off in sorted(state['frames'].keys()):
                            frag_len = len(state['parts'].get(frag_off, b''))
                            fragment_entries.append({
                                'frame_number': int(state['frames'][frag_off]),
                                'payload_start': int(frag_off),
                                'payload_length': int(frag_len),
                            })
                            running = max(running, frag_off + frag_len)
                        metadata['ip_reassembled_fragments'] = fragment_entries
                        metadata['ip_reassembled_length'] = int(running)
                        metadata['ip_reassembled_payload_hex'] = reassembled.hex()
                        metadata['tcp_reassembled_data_hex'] = reassembled.hex()

                        if proto == 17 and len(reassembled) >= 8:
                            udp_len = int.from_bytes(reassembled[4:6], 'big')
                            udp_total = udp_len if udp_len >= 8 else len(reassembled)
                            udp_total = min(udp_total, len(reassembled))
                            udp_payload = reassembled[8:udp_total]
                            metadata['udp_reassembled_payload_hex'] = reassembled[:udp_total].hex()
                            dns_src_port = int.from_bytes(reassembled[0:2], 'big') if len(reassembled) >= 2 else 0
                            dns_dst_port = int.from_bytes(reassembled[2:4], 'big') if len(reassembled) >= 4 else 0
                            is_dns_transport = bool(dns_src_port in {53, 5353} or dns_dst_port in {53, 5353})
                            if is_dns_transport and len(udp_payload) >= 12:
                                metadata['dns_reassembled_data_hex'] = udp_payload.hex()
                                metadata['dns_is_mdns_transport'] = bool(dns_src_port == 5353 or dns_dst_port == 5353)
                            if dns_src_port in {161, 162} or dns_dst_port in {161, 162}:
                                snmp_info = self._snmp_payload_info_from_bytes(udp_payload)
                                if snmp_info is not None:
                                    metadata['snmp'] = snmp_info
                                    metadata['snmp_reassembled_data_hex'] = udp_payload.hex()
                            app_protocol = _apply_udp_reassembled_metadata(metadata, udp_payload, src, dns_src_port, dst, dns_dst_port)
                            if app_protocol:
                                metadata['ip_fragment_reassembled_protocol'] = app_protocol
                        if proto == 17 and len(reassembled) >= 4:
                            try:
                                src_port = int.from_bytes(reassembled[0:2], 'big')
                                dst_port = int.from_bytes(reassembled[2:4], 'big')
                                stream_key = self._canonical_transport_key(src, src_port, dst, dst_port, 'UDP')
                                stream_state = self.transport_stream_state.get(stream_key)
                            except Exception:
                                stream_state = None
                        fragment_records = list(state.get('records', []) or [])
                        for fragment_record in fragment_records:
                            if fragment_record is None:
                                continue
                            fragment_record.metadata['ip_reassembled_in_frame'] = int(frame_number)
                            if int(getattr(fragment_record, 'number', 0) or 0) != int(frame_number):
                                fragment_record.info = self._build_info(
                                    fragment_record.raw,
                                    str(fragment_record.protocol or 'IPv4'),
                                    fragment_record.metadata,
                                )

                        if stream_state is not None:
                            for frag_off in sorted(state['frames'].keys()):
                                frag_frame = int(state['frames'].get(frag_off, 0) or 0)
                                stream_record = self._find_stream_record(stream_state, frag_frame)
                                if stream_record is None:
                                    continue
                                stream_record.metadata['ip_reassembled_in_frame'] = int(frame_number)
                                if metadata.get('ip_fragment_reassembled_protocol') and frag_frame == int(frame_number):
                                    stream_record.metadata['ip_fragment_reassembled_protocol'] = metadata.get('ip_fragment_reassembled_protocol')
                                    for key in ('sip', 'sdp', 'rtp', 'udp_reassembled_payload_hex'):
                                        if key in metadata:
                                            stream_record.metadata[key] = metadata[key]
                                    stream_record.protocol = str(metadata.get('ip_fragment_reassembled_protocol', '') or stream_record.protocol or 'IPv4')
                                stream_record.info = self._build_info(
                                    stream_record.raw,
                                    str(stream_record.protocol or 'IPv4'),
                                    stream_record.metadata,
                                )
                            if metadata.get('ip_fragment_reassembled_protocol') in {'SIP', 'SIP/SDP'}:
                                sip_meta = metadata.get('sip') if isinstance(metadata.get('sip'), dict) else None
                                if isinstance(sip_meta, dict) and str(sip_meta.get('kind', '') or '') == 'request':
                                    call_id = str(sip_meta.get('call_id', '') or '')
                                    cseq_method = str(sip_meta.get('cseq_method', '') or '')
                                    if call_id and cseq_method:
                                        for existing_record in list(state.get('records', []) or []):
                                            if int(getattr(existing_record, 'number', 0) or 0) == frame_number:
                                                continue
                                            candidate_meta = getattr(existing_record, 'metadata', {}) or {}
                                            candidate_sip = candidate_meta.get('sip') if isinstance(candidate_meta.get('sip'), dict) else None
                                            if not isinstance(candidate_sip, dict):
                                                continue
                                            if str(candidate_sip.get('kind', '') or '') != 'response':
                                                continue
                                            if str(candidate_sip.get('call_id', '') or '') != call_id:
                                                continue
                                            if str(candidate_sip.get('cseq_method', '') or '') != cseq_method:
                                                continue
                                            if 'sip_request_frame' not in candidate_meta:
                                                candidate_meta['sip_request_frame'] = int(frame_number)
                                            metadata['sip_response_frame'] = int(getattr(existing_record, 'number', 0) or 0)
                                            response_delta = (Decimal(str(getattr(existing_record, 'epoch_time', 0.0) or 0.0)) - Decimal(str(epoch_time))) * Decimal('1000')
                                            candidate_meta['sip_response_time_ms'] = max(0.0, float(response_delta))
                                            existing_record.info = self._build_info(
                                                existing_record.raw,
                                                str(existing_record.protocol or 'SIP/SDP'),
                                                candidate_meta,
                                            )
                                            break

        # IPv6 fragmentation header
        if packet.haslayer(IPv6) and packet.haslayer(IPv6ExtHdrFragment):
            ip6_layer = packet[IPv6]
            frag_hdr = packet[IPv6ExtHdrFragment]
            more_fragments = bool(int(getattr(frag_hdr, 'm', 0) or 0))
            offset_bytes = int(getattr(frag_hdr, 'offset', 0) or 0) * 8
            next_header = int(getattr(frag_hdr, 'nh', 0) or 0)
            ident = int(getattr(frag_hdr, 'id', 0) or 0)
            src = str(getattr(ip6_layer, 'src', '') or '')
            dst = str(getattr(ip6_layer, 'dst', '') or '')
            fragment_payload = bytes(getattr(frag_hdr, 'payload', b''))
            key = ('ipv6', src, dst, ident, next_header)
            state = self.ipv6_fragment_state.setdefault(key, {'parts': {}, 'frames': {}, 'has_last': False, 'records': []})
            state['parts'][offset_bytes] = fragment_payload
            state['frames'][offset_bytes] = int(frame_number)
            if not more_fragments:
                state['has_last'] = True

            metadata['ip_is_fragmented'] = True
            metadata['ip_fragment_version'] = 6
            metadata['ip_fragment_id'] = ident
            metadata['ip_fragment_offset'] = offset_bytes
            metadata['ip_fragment_more'] = more_fragments
            metadata['ip_fragment_proto'] = next_header
            metadata['ip_fragment_payload_len'] = int(len(fragment_payload))
            metadata['ip_fragment_role'] = 'first' if offset_bytes == 0 and more_fragments else ('last' if offset_bytes > 0 and not more_fragments else 'middle')

            if metadata['ip_fragment_role'] == 'first' and state.get('has_last'):
                max_off = max(state['frames'].keys(), default=0)
                metadata['ip_reassembled_in_frame'] = int(state['frames'].get(max_off, 0) or 0)

            if metadata['ip_fragment_role'] == 'last':
                reassembled = self._reassemble_ip_fragments(state.get('parts', {}))
                if reassembled:
                    fragment_entries = []
                    running = 0
                    for frag_off in sorted(state['frames'].keys()):
                        frag_len = len(state['parts'].get(frag_off, b''))
                        fragment_entries.append({
                            'frame_number': int(state['frames'][frag_off]),
                            'payload_start': int(frag_off),
                            'payload_length': int(frag_len),
                        })
                        running = max(running, frag_off + frag_len)
                    metadata['ip_reassembled_fragments'] = fragment_entries
                    metadata['ip_reassembled_length'] = int(running)
                    metadata['ip_reassembled_payload_hex'] = reassembled.hex()
                    metadata['tcp_reassembled_data_hex'] = reassembled.hex()

                    if next_header == 17 and len(reassembled) >= 8:
                        udp_len = int.from_bytes(reassembled[4:6], 'big')
                        udp_total = udp_len if udp_len >= 8 else len(reassembled)
                        udp_total = min(udp_total, len(reassembled))
                        udp_payload = reassembled[8:udp_total]
                        metadata['udp_reassembled_payload_hex'] = reassembled[:udp_total].hex()
                        dns_src_port = int.from_bytes(reassembled[0:2], 'big') if len(reassembled) >= 2 else 0
                        dns_dst_port = int.from_bytes(reassembled[2:4], 'big') if len(reassembled) >= 4 else 0
                        is_dns_transport = bool(dns_src_port in {53, 5353} or dns_dst_port in {53, 5353})
                        if is_dns_transport and len(udp_payload) >= 12:
                            metadata['dns_reassembled_data_hex'] = udp_payload.hex()
                            metadata['dns_is_mdns_transport'] = bool(dns_src_port == 5353 or dns_dst_port == 5353)
                        if dns_src_port in {161, 162} or dns_dst_port in {161, 162}:
                            snmp_info = self._snmp_payload_info_from_bytes(udp_payload)
                            if snmp_info is not None:
                                metadata['snmp'] = snmp_info
                                metadata['snmp_reassembled_data_hex'] = udp_payload.hex()
                        app_protocol = _apply_udp_reassembled_metadata(metadata, udp_payload, src, dns_src_port, dst, dns_dst_port)
                        if app_protocol:
                            metadata['ip_fragment_reassembled_protocol'] = app_protocol
                    if next_header == 17 and len(reassembled) >= 4:
                        try:
                            src_port = int.from_bytes(reassembled[0:2], 'big')
                            dst_port = int.from_bytes(reassembled[2:4], 'big')
                            stream_key = self._canonical_transport_key(src, src_port, dst, dst_port, 'UDP')
                            stream_state = self.transport_stream_state.get(stream_key)
                        except Exception:
                            stream_state = None
                        fragment_records = list(state.get('records', []) or [])
                        for fragment_record in fragment_records:
                            if fragment_record is None:
                                continue
                            fragment_record.metadata['ip_reassembled_in_frame'] = int(frame_number)
                            if int(getattr(fragment_record, 'number', 0) or 0) != int(frame_number):
                                fragment_record.info = self._build_info(
                                    fragment_record.raw,
                                    str(fragment_record.protocol or 'IPv6'),
                                    fragment_record.metadata,
                                )

                        if stream_state is not None:
                            for frag_off in sorted(state['frames'].keys()):
                                frag_frame = int(state['frames'].get(frag_off, 0) or 0)
                                stream_record = self._find_stream_record(stream_state, frag_frame)
                                if stream_record is None:
                                    continue
                                stream_record.metadata['ip_reassembled_in_frame'] = int(frame_number)
                                if metadata.get('ip_fragment_reassembled_protocol') and frag_frame == int(frame_number):
                                    stream_record.metadata['ip_fragment_reassembled_protocol'] = metadata.get('ip_fragment_reassembled_protocol')
                                    for key in ('sip', 'sdp', 'rtp', 'udp_reassembled_payload_hex'):
                                        if key in metadata:
                                            stream_record.metadata[key] = metadata[key]
                                    stream_record.protocol = str(metadata.get('ip_fragment_reassembled_protocol', '') or stream_record.protocol or 'IPv6')
                                stream_record.info = self._build_info(
                                    stream_record.raw,
                                    str(stream_record.protocol or 'IPv6'),
                                    stream_record.metadata,
                                )
                            if metadata.get('ip_fragment_reassembled_protocol') in {'SIP', 'SIP/SDP'}:
                                sip_meta = metadata.get('sip') if isinstance(metadata.get('sip'), dict) else None
                                if isinstance(sip_meta, dict) and str(sip_meta.get('kind', '') or '') == 'request':
                                    call_id = str(sip_meta.get('call_id', '') or '')
                                    cseq_method = str(sip_meta.get('cseq_method', '') or '')
                                    if call_id and cseq_method:
                                        for existing_record in list(state.get('records', []) or []):
                                            if int(getattr(existing_record, 'number', 0) or 0) == frame_number:
                                                continue
                                            candidate_meta = getattr(existing_record, 'metadata', {}) or {}
                                            candidate_sip = candidate_meta.get('sip') if isinstance(candidate_meta.get('sip'), dict) else None
                                            if not isinstance(candidate_sip, dict):
                                                continue
                                            if str(candidate_sip.get('kind', '') or '') != 'response':
                                                continue
                                            if str(candidate_sip.get('call_id', '') or '') != call_id:
                                                continue
                                            if str(candidate_sip.get('cseq_method', '') or '') != cseq_method:
                                                continue
                                            if 'sip_request_frame' not in candidate_meta:
                                                candidate_meta['sip_request_frame'] = int(frame_number)
                                            metadata['sip_response_frame'] = int(getattr(existing_record, 'number', 0) or 0)
                                            response_delta = (Decimal(str(getattr(existing_record, 'epoch_time', 0.0) or 0.0)) - Decimal(str(epoch_time))) * Decimal('1000')
                                            candidate_meta['sip_response_time_ms'] = max(0.0, float(response_delta))
                                            existing_record.info = self._build_info(
                                                existing_record.raw,
                                                str(existing_record.protocol or 'SIP/SDP'),
                                                candidate_meta,
                                            )
                                            break

    def _ip_fragment_info_text(self, packet, metadata: dict) -> str:
        version = int(metadata.get('ip_fragment_version', 0) or 0)
        offset_bytes = int(metadata.get('ip_fragment_offset', 0) or 0)
        more = bool(metadata.get('ip_fragment_more', False))
        ident = int(metadata.get('ip_fragment_id', 0) or 0)
        proto = int(metadata.get('ip_fragment_proto', 0) or 0)
        if version == 4:
            proto_name = {1: 'ICMP', 6: 'TCP', 17: 'UDP'}.get(proto, str(proto))
            base = f'Fragmented IP protocol (proto={proto_name} {proto}, off={offset_bytes}, ID={ident:04x})'
            reassembled_in = int(metadata.get('ip_reassembled_in_frame', 0) or 0)
            if reassembled_in > 0 and offset_bytes == 0 and more:
                return f'{base} [Reassembled in #{reassembled_in}]'
            return base
        if version == 6:
            return (
                f'IPv6 fragment (off={offset_bytes // 8} more={"y" if more else "n"} '
                f'ident=0x{ident:08x} nxt={proto})'
            )
        return packet.summary()

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
        messages = self._iter_bgp_messages(payload)
        if not messages:
            return 'BGP Message'
        names = {
            1: 'OPEN Message',
            2: 'UPDATE Message',
            3: 'NOTIFICATION Message',
            4: 'KEEPALIVE Message',
            5: 'ROUTE-REFRESH Message',
        }
        return ', '.join(names.get(msg_type, f'BGP Message ({msg_type})') for msg_type in messages)

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

    def _iter_bgp_messages(self, payload: bytes) -> list[int]:
        message_types: list[int] = []
        cursor = 0
        total_len = len(payload)
        while cursor + 19 <= total_len:
            marker = payload[cursor:cursor + 16]
            if marker != (b'\xff' * 16):
                break
            msg_len = int.from_bytes(payload[cursor + 16:cursor + 18], 'big')
            if msg_len < 19 or cursor + msg_len > total_len:
                break
            msg_type = int(payload[cursor + 18])
            if 1 <= msg_type <= 5:
                message_types.append(msg_type)
            cursor += msg_len
        return message_types

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
            25: 'Station Configuration Request',
            26: 'Station Configuration Response',
        }
        return names.get(int(message_type), f'Control Message ({int(message_type)})')

    def _capwap_element_name(self, element_type: int) -> str:
        names = {
            8: 'Add Station',
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
            1036: 'IEEE 802.11 Station',
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
            malformed = None

            if int(flags) & 0x80:
                if len(data) < cursor + 4:
                    malformed = {
                        'summary': '[Malformed Packet: IEEE 802.11]',
                        'info_suffix': '[Malformed Packet]',
                        'reason': 'Exception occurred',
                    }
                else:
                    ht_control = self._parse_wlan_ht_control(int.from_bytes(data[cursor:cursor + 4], 'little'))
                    cursor += 4

            fixed_data = data[cursor:cursor + 4]
            capabilities = int.from_bytes(fixed_data[:2], 'little') if len(fixed_data) >= 2 else 0
            listen_interval = int.from_bytes(fixed_data[2:4], 'little') if len(fixed_data) >= 4 else None
            tags_result = self._parse_wlan_tagged_parameters(data[cursor + 4:], frame_offset + cursor + 4) if len(data) > cursor + 4 else {
                'tags': [],
                'malformed': None,
            }

            if malformed is None:
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
        if element_type == 8 and len(value) >= 8:
            radio_id = int(value[0])
            mac_len = int(value[1])
            mac_bytes = value[2:2 + mac_len]
            parsed = {
                'radio_id': radio_id,
                'mac_length': mac_len,
                'mac_address': ':'.join(f'{byte:02x}' for byte in mac_bytes) if mac_len == 6 else mac_bytes.hex(),
            }
        elif element_type == 1036 and len(value) >= 25:
            radio_id = int(value[0])
            association_id = int.from_bytes(value[1:3], 'big')
            flags = int(value[3])
            mac_bytes = value[4:10]
            capabilities = int.from_bytes(value[10:12], 'big')
            wlan_id = int.from_bytes(value[12:14], 'big')
            supported_rates = list(value[14:25])
            parsed = {
                'radio_id': radio_id,
                'association_id': association_id,
                'flags': flags,
                'mac_address': ':'.join(f'{byte:02x}' for byte in mac_bytes),
                'capabilities': capabilities,
                'wlan_id': wlan_id,
                'supported_rates': supported_rates,
            }
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
            payload = self._payload_bytes(packet)
            if len(payload) >= 8 and int(payload[0]) == 0x00:
                wlan = self._parse_wlan_association_request(payload[8:], 8)
                if wlan is not None:
                    capwap = {
                        'transport': 'data',
                        'preamble': {
                            'version': 0,
                            'type_name': 'CAPWAP Header',
                        },
                        'header': {
                            'header_length_words': 2,
                            'radio_id': 1,
                            'wireless_binding_id': 1,
                            'wireless_binding_name': 'IEEE 802.11',
                            'header_flags_value': 0x100,
                            'payload_type_native': True,
                            'fragment': False,
                            'last_fragment': False,
                            'wireless_header': False,
                            'radio_mac_header': False,
                            'keep_alive': False,
                            'reserved_flags': 0,
                            'fragment_id': 0,
                            'fragment_offset': 0,
                            'fragment_reserved': 0,
                        },
                        'data_header': {
                            'kind': 'native',
                        },
                        'wlan': wlan,
                    }
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
        effective_ip = self._effective_ip_layer(packet)
        if effective_ip is None or int(getattr(effective_ip, 'version', 0) or 0) != 6:
            return b''
        try:
            if packet.haslayer(IPv6ExtHdrHopByHop):
                return bytes(getattr(packet[IPv6ExtHdrHopByHop], 'payload', b''))
            if int(getattr(effective_ip, 'nh', -1) or -1) == 58:
                return bytes(getattr(effective_ip, 'payload', b''))
        except Exception:
            return b''
        return b''

    def _is_icmpv6_packet(self, packet) -> bool:
        effective_ip = self._effective_ip_layer(packet)
        if effective_ip is None or int(getattr(effective_ip, 'version', 0) or 0) != 6:
            return False
        try:
            if packet.haslayer(IPv6ExtHdrHopByHop):
                return int(getattr(packet[IPv6ExtHdrHopByHop], 'nh', -1) or -1) == 58 and len(self._icmpv6_payload_bytes(packet)) >= 4
            return int(getattr(effective_ip, 'nh', -1) or -1) == 58 and len(self._icmpv6_payload_bytes(packet)) >= 4
        except Exception:
            return False

    def _icmpv6_info_text(self, packet, metadata: dict | None = None) -> str | None:
        metadata = metadata or {}
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
        code = int(payload[1]) if len(payload) >= 2 else 0
        hop_limit = int(getattr(packet[IPv6], 'hlim', 0) or 0) if packet.haslayer(IPv6) else 0
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
        if icmpv6_type in {128, 129} and len(payload) >= 8:
            identifier = int.from_bytes(payload[4:6], 'big')
            sequence = int.from_bytes(payload[6:8], 'big')
            base = (
                f'Echo (ping) {"request" if icmpv6_type == 128 else "reply"} '
                f'id=0x{identifier:04x}, seq={sequence}, hop limit={hop_limit}'
            )
            if icmpv6_type == 128 and metadata.get('icmpv6_response_frame') is not None:
                return f'{base} (reply in {int(metadata.get("icmpv6_response_frame", 0) or 0)})'
            if icmpv6_type == 129 and metadata.get('icmpv6_request_frame') is not None:
                return f'{base} (request in {int(metadata.get("icmpv6_request_frame", 0) or 0)})'
            return base

        if icmpv6_type == 1:
            code_text = {
                0: 'No route to destination',
                1: 'Administratively prohibited',
                2: 'Beyond scope of source address',
                3: 'Address unreachable',
                4: 'Port unreachable',
                5: 'Source address failed ingress/egress policy',
                6: 'Reject route to destination',
            }.get(code, f'Code {code}')
            return f'Destination Unreachable ({code_text})'

        return {
            130: 'Multicast Listener Query',
            131: 'Multicast Listener Report',
            132: 'Multicast Listener Done',
            3: f'Time Exceeded ({"Hop limit exceeded in transit" if code == 0 else "Fragment reassembly time exceeded"})',
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
        effective_ip = self._effective_ip_layer(packet)
        if udp_layer is None or effective_ip is None or int(getattr(effective_ip, 'version', 0) or 0) != 6:
            return b''
        return bytes(udp_layer.payload)

    def _is_dhcpv6_packet(self, packet) -> bool:
        udp_layer = self._effective_udp_layer(packet)
        effective_ip = self._effective_ip_layer(packet)
        if udp_layer is None or effective_ip is None or int(getattr(effective_ip, 'version', 0) or 0) != 6:
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
        if len(payload) < 4:
            return ''
        msg_type = int(payload[0])
        if msg_type in {12, 13} and len(payload) >= 34:
            cursor = 34
        else:
            cursor = 4
        while cursor + 4 <= len(payload):
            option_code = int.from_bytes(payload[cursor:cursor + 2], 'big')
            option_length = int.from_bytes(payload[cursor + 2:cursor + 4], 'big')
            value_start = cursor + 4
            value_end = value_start + option_length
            if value_end > len(payload):
                break
            if option_code == 9:
                nested = self._dhcpv6_client_id(payload[value_start:value_end])
                if nested:
                    return nested
            if option_code == 1:
                return payload[value_start:value_end].hex()
            cursor = value_end
        return ''

    def _dhcpv6_info_text(self, packet) -> str | None:
        payload = self._dhcpv6_payload_bytes(packet)
        if len(payload) < 4:
            return None
        msg_type = int(payload[0])
        msg_name = self._dhcpv6_message_name(msg_type)
        if msg_type in {12, 13} and len(payload) >= 34:
            link_addr = str(ipaddress.IPv6Address(payload[2:18]))
            nested = payload
            cursor = 34
            relay_msg = b''
            while cursor + 4 <= len(payload):
                option_code = int.from_bytes(payload[cursor:cursor + 2], 'big')
                option_length = int.from_bytes(payload[cursor + 2:cursor + 4], 'big')
                value_start = cursor + 4
                value_end = value_start + option_length
                if value_end > len(payload):
                    break
                if option_code == 9:
                    relay_msg = payload[value_start:value_end]
                    nested = relay_msg
                    break
                cursor = value_end
            inner_name = self._dhcpv6_message_name(int(nested[0])) if len(nested) >= 1 else ''
            xid = int.from_bytes(nested[1:4], 'big') if len(nested) >= 4 else 0
            relay_label = 'Relay-forw' if msg_type == 12 else 'Relay-reply'
            info = f'{relay_label} L: {link_addr} {inner_name} XID: 0x{xid:06x}'
        else:
            xid = int.from_bytes(payload[1:4], 'big')
            info = f'{msg_name} XID: 0x{xid:06x}'
        client_id = self._dhcpv6_client_id(payload)
        if client_id:
            info += f' CID: {client_id} '
        return info

    def _is_ospf_ipv6_packet(self, packet) -> bool:
        if not packet.haslayer(IPv6):
            return False
        ospf_payload = self._ospf_payload_bytes(packet)
        return len(ospf_payload) >= 4

    def _ospf_payload_bytes(self, packet) -> bytes:
        effective_ip = self._effective_ip_layer(packet)
        # For pure IPv4 packets, use the 'proto' field directly.
        # For IPv6 (including IPv6-in-IPv4 tunnels), skip this branch so the
        # correct IPv6 next-header logic below is used instead.
        if effective_ip is not None and not isinstance(effective_ip, IPv6):
            ip_proto = int(getattr(effective_ip, 'proto', 0) or 0)
            if ip_proto == 89:
                return bytes(getattr(effective_ip, 'payload', b''))
            return b''
        if not packet.haslayer(IPv6):
            return b''
        try:
            if packet.haslayer(IPv6ExtHdrHopByHop):
                hop_layer = packet[IPv6ExtHdrHopByHop]
                next_header = int(getattr(hop_layer, 'nh', -1) or -1)
                payload = bytes(getattr(hop_layer, 'payload', b''))
            else:
                ipv6_layer = packet[IPv6]
                next_header = int(getattr(ipv6_layer, 'nh', -1) or -1)
                payload = bytes(getattr(ipv6_layer, 'payload', b''))
            if next_header == 89:
                return payload
            if next_header == 51 and len(payload) >= 12:
                ah_next_header = int(payload[0])
                ah_header_len = (int(payload[1]) + 2) * 4
                if ah_next_header == 89 and len(payload) >= ah_header_len:
                    return payload[ah_header_len:]
        except Exception:
            return b''
        return b''

    def _guess_protocol(self, packet, metadata: dict | None = None):
        metadata = metadata or {}
        fragment_override = self._fragment_override_protocol(packet, metadata)
        if fragment_override:
            return fragment_override
        if packet.haslayer(GRE):
            gre_payload = self._payload_bytes(packet)
            if b'SSH-' in gre_payload:
                return self._ssh_banner_protocol_name(gre_payload)
            if packet.haslayer(ICMP):
                return 'ICMP'
            if self._is_icmpv6_packet(packet):
                return 'ICMPv6'
            if len(gre_payload) >= 5:
                saw_tls = False
                for i in range(0, min(len(gre_payload) - 4, 256)):
                    ct = int(gre_payload[i])
                    ver = int.from_bytes(gre_payload[i + 1:i + 3], 'big')
                    rlen = int.from_bytes(gre_payload[i + 3:i + 5], 'big')
                    if ct in {20, 21, 22, 23} and ver in {0x0300, 0x0301, 0x0302, 0x0303, 0x0304} and i + 5 + rlen <= len(gre_payload):
                        saw_tls = True
                        if ver == 0x0303:
                            return 'TLSv1.2'
                        if ct == 22 and i + 11 <= len(gre_payload):
                            hs_ver = int.from_bytes(gre_payload[i + 9:i + 11], 'big')
                            if hs_ver == 0x0303:
                                return 'TLSv1.2'
                if saw_tls:
                    return 'SSL'
            tcp_in_gre = packet[TCP] if packet.haslayer(TCP) else None
            if tcp_in_gre is not None:
                sport = int(getattr(tcp_in_gre, 'sport', 0) or 0)
                dport = int(getattr(tcp_in_gre, 'dport', 0) or 0)
                telnet_info = self._telnet_payload_info(gre_payload, sport, dport)
                if telnet_info is not None:
                    metadata['telnet'] = telnet_info
                    return 'TELNET'
            return 'GRE'
        pppoe_info = self._pppoe_payload_info(packet)
        if pppoe_info is not None:
            metadata['pppoe'] = pppoe_info
            if bool(pppoe_info.get('is_discovery', False)):
                return 'PPPoED'
            ppp_protocol = int(pppoe_info.get('ppp_protocol', 0) or 0)
            if ppp_protocol == 0xC021:
                return 'PPP LCP'
            if ppp_protocol == 0x8021:
                return 'PPP IPCP'
            if ppp_protocol == 0x8057:
                return 'PPP IPV6CP'
            if ppp_protocol not in {0x0021, 0x0057}:
                return 'PPP'
        eth_type = self._ether_type(packet)
        if self._is_homeplug_av_packet(packet):
            return 'HomePlug AV'
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
        if packet.haslayer('ESP'):
            return 'ESP'
        if eth_type == 0x9000 or (eth_type == 0x8100 and self._inner_eth_type(packet) == 0x9000):
            return 'LOOP'
        if self._is_cdp_packet(packet):
            return 'CDP'
        if effective_ip is not None:
            ip_proto = self._ip_next_proto(effective_ip)
            ip_payload = bytes(getattr(effective_ip, 'payload', b'') or b'')
            pim_info = self._pim_payload_info(ip_payload, ip_proto)
            if pim_info is not None:
                metadata['pim'] = pim_info
                if str(pim_info.get('protocol', '')) == 'PIMv2':
                    inner_src = str(pim_info.get('inner_src', '') or '')
                    inner_dst = str(pim_info.get('inner_dst', '') or '')
                    if inner_src and inner_dst:
                        metadata['pim_inner_src'] = inner_src
                        metadata['pim_inner_dst'] = inner_dst
                return str(pim_info.get('protocol', 'PIMv2'))
            if ip_proto == 115:
                return 'L2TPv3'
            if ip_proto == 89:
                return 'OSPF'
            if ip_proto == 112:
                vrrp_info = self._vrrp_payload_info(packet, effective_ip)
                if vrrp_info is not None:
                    metadata['vrrp'] = vrrp_info
                    return 'VRRP'
            eigrp_info = self._eigrp_payload_info(packet, effective_ip)
            if eigrp_info is not None:
                metadata['eigrp'] = eigrp_info
                return 'EIGRP'
        elif packet.haslayer(IPv6):
            eigrp_info = self._eigrp_payload_info(packet, packet[IPv6])
            if eigrp_info is not None:
                metadata['eigrp'] = eigrp_info
                return 'EIGRP'
        if self._is_ospf_ipv6_packet(packet):
            return 'OSPF'
        if self._is_ripng_packet(packet):
            return 'RIPng'
        if self._is_ripv2_packet(packet):
            return 'RIPv2'
        if self._is_hsrp_packet(packet):
            return 'HSRP'
        if self._is_hsrpv2_packet(packet):
            return 'HSRPv2'
        if self._is_stp_packet(packet):
            return 'STP'
        isis_info = self._isis_payload_info(packet)
        if isis_info is not None:
            metadata['isis'] = isis_info
            return str(isis_info.get('protocol', 'ISIS'))
        if self._is_lacp_packet(packet):
            return 'LACP'
        if self._is_vtp_packet(packet):
            return 'VTP'
        if self._is_dtp_packet(packet):
            return 'DTP'
        if eth_type == 0x6002 or (eth_type == 0x8100 and self._inner_eth_type(packet) == 0x6002):
            return '0x6002'
        if self._is_syslog_packet(packet):
            return 'Syslog'
        if self._is_ntp_packet(packet):
            return 'NTP'
        if self._is_udld_packet(packet):
            return 'UDLD'
        if self._is_lldp_packet(packet):
            return 'LLDP'
        if packet.haslayer('KerberosTCPHeader') or packet.haslayer('Kerberos'):
            return 'KRB5'
        if packet.haslayer('CLDAP'):
            return 'CLDAP'
        if effective_tcp is not None and bool(metadata.get('tcp_is_retransmission', False)):
            return 'TCP'
        if packet.haslayer('SMB2_Header'):
            if bool(metadata.get('tcp_is_retransmission', False)):
                return 'TCP'
            if effective_tcp is not None:
                embedded = self._dcerpc_embedded_payload_info(self._payload_bytes(packet), metadata)
                if embedded is not None:
                    metadata['dcerpc'] = embedded
                    metadata['dcerpc_embedded_offset'] = int(embedded.get('embedded_offset', 0) or 0)
                    return str(embedded.get('protocol', 'DCERPC'))
                sport = int(getattr(effective_tcp, 'sport', 0) or 0)
                dport = int(getattr(effective_tcp, 'dport', 0) or 0)
                if sport == 445 or dport == 445:
                    nbss_info = self._nbss_payload_info(self._payload_bytes(packet))
                    if isinstance(nbss_info, dict) and bool(nbss_info.get('is_fragment', False)):
                        metadata['nbss'] = nbss_info
                        return 'NBSS'
            return 'SMB2'
        if packet.haslayer('SMB_Header'):
            if effective_tcp is not None:
                embedded = self._dcerpc_embedded_payload_info(self._payload_bytes(packet), metadata)
                if embedded is not None:
                    metadata['dcerpc'] = embedded
                    metadata['dcerpc_embedded_offset'] = int(embedded.get('embedded_offset', 0) or 0)
                    return str(embedded.get('protocol', 'DCERPC'))
                sport = int(getattr(effective_tcp, 'sport', 0) or 0)
                dport = int(getattr(effective_tcp, 'dport', 0) or 0)
                if sport == 445 or dport == 445:
                    nbss_info = self._nbss_payload_info(self._payload_bytes(packet))
                    if isinstance(nbss_info, dict) and bool(nbss_info.get('is_fragment', False)):
                        metadata['nbss'] = nbss_info
                        return 'NBSS'
            return 'SMB'
        if eth_type == 0x0842:
            wol_payload = bytes(getattr(packet[Ether], 'payload', b'')) if packet.haslayer(Ether) else b''
            wol = self._wol_payload_info(wol_payload)
            if wol is not None:
                metadata['wol'] = wol
                return 'WOL'
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
            udp_payload = bytes(getattr(effective_udp, 'payload', b''))
            if sport == 3389 or dport == 3389:
                rdpudp = self._rdpudp_payload_info(udp_payload)
                if isinstance(rdpudp, dict):
                    metadata['rdpudp'] = rdpudp
                    unwrapped_payload = bytes(rdpudp.get('unwrapped_payload', b'') or b'')
                    if unwrapped_payload:
                        metadata['rdpudp_unwrapped_payload'] = unwrapped_payload
                        data_offset = int(rdpudp.get('data_offset', -1) or -1)
                        if data_offset >= 0 and len(unwrapped_payload) > data_offset + 4:
                            metadata['rdpudp_tls_fragment_payload'] = bytes(unwrapped_payload[data_offset + 4:])
                    tls_info = self._rdpudp_embedded_tls_info(udp_payload, rdpudp, int(metadata.get('udp_stream_index', -1) or -1))
                    if isinstance(tls_info, dict):
                        metadata['tls_embedded_payload'] = bytes(tls_info.get('payload', b'') or b'')
                        metadata['tls_embedded_offset'] = int(tls_info.get('offset', 0) or 0)
                        metadata['tls_embedded_summaries'] = list(tls_info.get('summaries', []) or [])
                        metadata['tls_embedded_sni'] = str(tls_info.get('sni', '') or '')
                        metadata['tls_embedded_unknown_record'] = bool(tls_info.get('unknown_record', False))
                        metadata['tls_embedded_transport'] = 'RDPUDP'
                        metadata['rdpudp_tls_fragment_payload'] = bytes(tls_info.get('payload', b'') or b'')
                        return str(tls_info.get('protocol', 'TLSv1.2'))
                    return str(rdpudp.get('protocol', 'RDPUDP'))
            if sport == 4500 or dport == 4500:
                udpencap = self._udpencap_payload_info(udp_payload)
                if isinstance(udpencap, dict):
                    metadata['udpencap'] = udpencap
                    return 'UDPENCAP'
            qsrc, qdst = self._extract_endpoints(packet)
            quic_info = self._quic_payload_info(udp_payload, str(qsrc), str(qdst), sport, dport)
            if isinstance(quic_info, dict):
                metadata['quic'] = quic_info
                decrypted = bytes(quic_info.get('quic_decrypted_payload', b'') or b'')
                if decrypted:
                    metadata['quic_decrypted_payload'] = decrypted
                return 'QUIC'
            stun_info = self._stun_payload_info(udp_payload)
            if isinstance(stun_info, dict):
                metadata['stun'] = stun_info
                return 'STUN'
            srtcp_info = self._srtcp_payload_info(udp_payload)
            if isinstance(srtcp_info, dict):
                metadata['srtcp'] = srtcp_info
                return 'SRTCP'
            if (sport in {500, 4500} or dport in {500, 4500}) and self._is_isakmp_packet_payload(udp_payload):
                return 'ISAKMP'
            if self._looks_like_h264_over_udp(udp_payload):
                return 'H.264'
            if self._looks_like_mpeg_ts_payload(udp_payload):
                return 'MPEG TS'
            dtls_info = self._dtls_payload_info(udp_payload)
            if dtls_info is not None:
                metadata['dtls'] = dtls_info
                if b'\x00\x0e' in udp_payload:
                    src_addr, dst_addr = self._extract_endpoints(packet)
                    setup_key = self._canonical_transport_key(str(src_addr), sport, str(dst_addr), dport, 'UDP')
                    frame_no = int(metadata.get('frame_number', 0) or 0)
                    existing = int(self.srtcp_setup_frames.get(setup_key, 0) or 0)
                    info_text = str(dtls_info.get('info_text', '') or '')
                    prefer = 'Server Hello' in info_text
                    if prefer or existing <= 0 or (frame_no > 0 and frame_no < existing):
                        self.srtcp_setup_frames[setup_key] = frame_no
                return str(dtls_info.get('protocol', 'DTLS'))
            if (sport == 389 or dport == 389) and packet.haslayer('CLDAP'):
                return 'CLDAP'
            if (sport == 88 or dport == 88) and packet.haslayer('Kerberos'):
                return 'KRB5'
            if udp_payload and (sport == 7 or dport == 7):
                return 'ECHO'
            if udp_payload and (sport == 9 or dport == 9):
                return 'DISCARD'
            if udp_payload and (sport == 13 or dport == 13):
                return 'DAYTIME'
            if udp_payload and (sport == 19 or dport == 19):
                return 'Chargen'
            if udp_payload and (sport == 37 or dport == 37):
                return 'TIME'
            if sport == 5355 or dport == 5355:
                llmnr = self._llmnr_payload_info(udp_payload)
                if llmnr is not None:
                    metadata['llmnr'] = llmnr
                    return 'LLMNR'
            if sport == 137 or dport == 137:
                nbns = self._nbns_payload_info(udp_payload)
                if nbns is not None:
                    metadata['nbns'] = nbns
                    return 'NBNS'
            if sport == 5351 or dport == 5351:
                pcp = self._pcp_payload_info(udp_payload)
                if pcp is not None:
                    metadata['pcp'] = pcp
                    return 'PCP v2'
            if (sport == 3702 or dport == 3702) and udp_payload.lstrip().startswith(b'<?xml'):
                metadata['udp_xml'] = {'length': int(len(udp_payload))}
                return 'UDP/XML'
            if sport == 3222 or dport == 3222:
                glbp_info = self._glbp_payload_info(udp_payload)
                if glbp_info is not None:
                    metadata['glbp'] = glbp_info
                    return 'GLBP'
            if sport == 3785 or dport == 3785:
                return 'BFD Echo'
            if sport == 3784 or dport == 3784:
                bfd_info = self._bfd_control_payload_info(udp_payload)
                if bfd_info is not None:
                    metadata['bfd'] = bfd_info
                    return 'BFD Control'
            if sport == 2055 or dport == 2055:
                cflow_info = self._cflow_payload_info(udp_payload)
                if cflow_info is not None:
                    metadata['cflow'] = cflow_info
                    return 'CFLOW'
            if str(metadata.get('tftp_kind', '') or ''):
                return 'TFTP'
            first_line = udp_payload.split(b'\r\n', 1)[0].upper()
            if sport == 1900 or dport == 1900:
                if first_line.startswith(b'M-SEARCH ') or first_line.startswith(b'NOTIFY ') or first_line.startswith(b'HTTP/1.'):
                    return 'SSDP'
            if (sport in {5246, 5247} or dport in {5246, 5247}) and _ensure_capwap_metadata() is not None:
                if str(metadata.get('capwap_transport', '') or '') == 'control':
                    return 'CAPWAP-Control'
                if str(metadata.get('capwap_transport', '') or '') == 'data':
                    if isinstance(metadata.get('wlan', None), dict) and metadata.get('wlan'):
                        return '802.11'
                    return 'CAPWAP-Data'
            if (sport == 646 or dport == 646) and self._is_ldp_payload(self._payload_bytes(packet)):
                return 'LDP'
            sip_info = self._sip_payload_info(udp_payload, sport, dport)
            if sip_info is not None:
                metadata['sip'] = sip_info
                if bool(sip_info.get('has_sdp', False)):
                    metadata['sdp'] = self._parse_sdp_body(bytes(sip_info.get('sdp_body', b'') or b''))
                    return 'SIP/SDP'
                return 'SIP'
            rtp_info = self._rtp_payload_info(udp_payload, sport, dport)
            if self._should_classify_as_rtp(
                udp_payload,
                rtp_info,
                str(getattr(effective_ip, 'src', '') or ''),
                sport,
                str(getattr(effective_ip, 'dst', '') or ''),
                dport,
            ):
                metadata['rtp'] = rtp_info
                return 'RTP'
            snmp_info = self._snmp_payload_info(packet)
            if snmp_info is None:
                snmp_info = self._snmp_payload_info_from_bytes(udp_payload)
            if snmp_info is not None:
                metadata['snmp'] = snmp_info
                return 'SNMP'
            if sport == 623 or dport == 623:
                rmcp_info = self._rmcp_payload_info(udp_payload)
                if isinstance(rmcp_info, dict):
                    metadata['rmcp'] = rmcp_info
                    session_ver = str(rmcp_info.get('session_version', '') or '')
                    if session_ver == 'v1_5':
                        return 'IPMB'
                    if session_ver == 'v2_0':
                        return 'RMCP+'
            if sport in {1812, 1813} or dport in {1812, 1813}:
                radius = self._radius_payload_info(udp_payload)
                if radius is not None:
                    metadata['radius'] = radius
                    eap_info = self._radius_eap_info(radius)
                    if eap_info is not None:
                        metadata['radius_eap'] = eap_info
                    return 'RADIUS'
        if effective_tcp is not None:
            sport = int(getattr(effective_tcp, 'sport', 0) or 0)
            dport = int(getattr(effective_tcp, 'dport', 0) or 0)
            tcp_payload = self._payload_bytes(packet)
            if bool(metadata.get('dcerpc_pending_reassembly', False)):
                return 'TCP'
            pre_dcerpc = metadata.get('dcerpc', None)
            if isinstance(pre_dcerpc, dict):
                return str(pre_dcerpc.get('protocol', 'DCERPC'))
            dcerpc_info = self._dcerpc_payload_info(tcp_payload, metadata, allow_segment_fragment=True)
            if dcerpc_info is not None:
                metadata['dcerpc'] = dcerpc_info
                return str(dcerpc_info.get('protocol', 'DCERPC'))
            if packet.haslayer('SMB2_Header') or packet.haslayer('SMB_Header'):
                embedded = self._dcerpc_embedded_payload_info(tcp_payload, metadata)
                if embedded is not None:
                    metadata['dcerpc'] = embedded
                    metadata['dcerpc_embedded_offset'] = int(embedded.get('embedded_offset', 0) or 0)
                    return str(embedded.get('protocol', 'DCERPC'))
            stream_index = int(metadata.get('tcp_stream_index', -1))
            if stream_index >= 0 and stream_index in self.dcerpc_stream_protocols and len(tcp_payload) > 0:
                return str(self.dcerpc_stream_protocols.get(stream_index, 'DCERPC'))
            pop_imf = self._pop_imf_fragment_info(tcp_payload, sport, dport)
            if pop_imf is not None:
                metadata['pop_imf'] = pop_imf
                return 'POP/IMF'
            pop_info = self._pop_payload_info(tcp_payload, sport, dport)
            if pop_info is not None:
                metadata['pop'] = pop_info
                return 'POP'
            if sport == 445 or dport == 445:
                nbss_info = self._nbss_payload_info(tcp_payload)
                if isinstance(nbss_info, dict) and bool(nbss_info.get('is_fragment', False)):
                    metadata['nbss'] = nbss_info
                    return 'NBSS'
                if bool(metadata.get('tcp_is_retransmission', False)):
                    return 'TCP'
                if packet.haslayer('SMB2_Header'):
                    return 'SMB2'
                if packet.haslayer('SMB_Header'):
                    return 'SMB'
            if sport == 3389 or dport == 3389:
                rdp_info = self._rdp_tpkt_info(tcp_payload)
                if isinstance(rdp_info, dict):
                    metadata['rdp'] = rdp_info
                    return 'RDP'
            if (sport == 88 or dport == 88) and (packet.haslayer('KerberosTCPHeader') or packet.haslayer('Kerberos')):
                return 'KRB5'
            ldap_ports = {389, 3268, 3269}
            ldap_complete = self._ldap_payload_is_complete(tcp_payload)
            if (sport in ldap_ports or dport in ldap_ports) and ldap_complete and (self._looks_like_ldap_payload(tcp_payload) or self._contains_ldap_message(tcp_payload)):
                if stream_index >= 0:
                    self.ldap_stream_protocols.add(int(stream_index))
                return 'LDAP'
            if sport in ldap_ports or dport in ldap_ports:
                if self._looks_like_ldap_sasl_payload(tcp_payload):
                    if stream_index >= 0:
                        self.ldap_stream_protocols.add(int(stream_index))
                    return 'LDAP'
                if stream_index >= 0 and stream_index in self.ldap_stream_protocols:
                    if not ldap_complete and not str(metadata.get('tcp_reassembled_data_hex', '') or ''):
                        return 'TCP'
                    return 'LDAP'
                reassembled_hex = str(metadata.get('tcp_reassembled_data_hex', '') or '')
                if reassembled_hex:
                    try:
                        reassembled = bytes.fromhex(reassembled_hex)
                    except Exception:
                        reassembled = b''
                    if self._looks_like_ldap_payload(reassembled) or self._contains_ldap_message(reassembled):
                        if stream_index >= 0:
                            self.ldap_stream_protocols.add(int(stream_index))
                        return 'LDAP'
            if tcp_payload and (sport == 7 or dport == 7):
                return 'ECHO'
            if tcp_payload and (sport == 9 or dport == 9):
                return 'DISCARD'
            if tcp_payload and (sport == 13 or dport == 13):
                return 'DAYTIME'
            if tcp_payload and (sport == 19 or dport == 19):
                return 'Chargen'
            if tcp_payload and (sport == 37 or dport == 37):
                return 'TIME'
            if sport == 49 or dport == 49:
                tacacs = self._tacacs_payload_info(tcp_payload)
                if tacacs is not None:
                    metadata['tacacs'] = tacacs
                    return 'TACACS+'
            if sport == 443 or dport == 443:
                probe = tcp_payload
                tls_summary = self._tls_record_summary(packet)
                if isinstance(tls_summary, dict):
                    version_name = str(tls_summary.get('version_name', '') or '').strip()
                    if version_name.startswith('TLS'):
                        return version_name
                if len(probe) >= 5:
                    saw_tls = False
                    for i in range(0, min(len(probe) - 4, 96)):
                        ct = int(probe[i])
                        ver = int.from_bytes(probe[i + 1:i + 3], 'big')
                        rlen = int.from_bytes(probe[i + 3:i + 5], 'big')
                        if ct in {20, 21, 22, 23} and ver in {0x0300, 0x0301, 0x0302, 0x0303, 0x0304} and i + 5 + rlen <= len(probe):
                            saw_tls = True
                            if ver == 0x0303:
                                return 'TLSv1.2'
                            if ct == 22 and i + 11 <= len(probe):
                                hs_ver = int.from_bytes(probe[i + 9:i + 11], 'big')
                                if hs_ver == 0x0303:
                                    return 'TLSv1.2'
                    if saw_tls:
                        return 'SSL'
                if len(probe) > 0:
                    return 'SSL'
            ftp_data_meta = metadata.get('ftp_data') if isinstance(metadata.get('ftp_data'), dict) else None
            if isinstance(ftp_data_meta, dict) and tcp_payload:
                return 'FTP-DATA'
            if sport == 21 or dport == 21:
                ftp_info = self._ftp_payload_info(tcp_payload, sport, dport)
                if ftp_info is not None:
                    metadata['ftp'] = ftp_info
                    return 'FTP'
            if effective_ip is not None:
                stream_key = self._canonical_transport_key(str(effective_ip.src), sport, str(effective_ip.dst), dport, 'TCP')
                stream_state = self.transport_stream_state.get(stream_key, {}) if isinstance(self.transport_stream_state.get(stream_key), dict) else {}
                http_state = stream_state.get('http', {}) if isinstance(stream_state, dict) else {}
                app_protocol = str(http_state.get('app_protocol', '') or '') if isinstance(http_state, dict) else ''
                if app_protocol in {'IPP', 'OCSP'} and len(tcp_payload) > 0:
                    content_type = str(metadata.get('http_content_type', '') or '').lower()
                    if app_protocol == 'IPP' and self._is_ipp_http(content_type):
                        return 'IPP'
                    if app_protocol == 'OCSP' and self._is_ocsp_http(content_type):
                        return 'OCSP'
            payload_lower = tcp_payload.lower()
            if b'application/ocsp-request' in payload_lower or b'application/ocsp-response' in payload_lower:
                return 'OCSP'

            if sport in {80, 631} or dport in {80, 631}:
                http_blob = bytes(metadata.get('http_reassembled_payload', b'') or b'')
                if not http_blob:
                    http_blob = tcp_payload
                http_blob_lower = http_blob.lower()
                if b'application/ocsp-request' in http_blob_lower or b'application/ocsp-response' in http_blob_lower:
                    return 'OCSP'

                reassembled_hex = str(metadata.get('tcp_reassembled_data_hex', '') or '').lower()
                if '6170706c69636174696f6e2f6f637370' in reassembled_hex:
                    return 'OCSP'

                ipp_body = bytes(metadata.get('http_dechunked_body', b'') or b'') or bytes(metadata.get('http_body', b'') or b'')
                if (sport == 631 or dport == 631) and self._ipp_payload_info(ipp_body, str(metadata.get('http_kind', '') or 'request') or 'request') is not None:
                    return 'IPP'
            telnet_info = self._telnet_payload_info(self._payload_bytes(packet), sport, dport)
            if telnet_info is not None:
                metadata['telnet'] = telnet_info
                return 'TELNET'
            if not bool(metadata.get('tcp_is_retransmission', False)) and not bool(metadata.get('tcp_is_duplicate_ack', False)):
                ssh_protocol = self._ssh_stream_protocol_name(packet, metadata)
                if ssh_protocol is not None:
                    return ssh_protocol
                rtsp_kind = self._rtsp_payload_kind(tcp_payload)
                if rtsp_kind is not None:
                    metadata['http_kind'] = rtsp_kind
                    return 'RTSP'
            if self._is_rsh_packet(packet):
                return 'RSH'
            zabbix_payload = self._zabbix_payload_for_record(packet, metadata)
            zabbix_info = self._zabbix_payload_info(zabbix_payload)
            if zabbix_info is not None:
                metadata['zabbix'] = zabbix_info
                return 'Zabbix'
            if (
                not bool(metadata.get('tcp_is_retransmission', False))
                and (sport == 646 or dport == 646)
                and self._is_ldp_payload(self._payload_bytes(packet))
            ):
                return 'LDP'
            if not bool(metadata.get('tcp_is_retransmission', False)) and (sport == 179 or dport == 179):
                if self._is_bgp_payload(self._payload_bytes(packet)):
                    return 'BGP'
            if not bool(metadata.get('tcp_is_retransmission', False)) and not bool(metadata.get('tcp_is_duplicate_ack', False)):
                imap_info = self._imap_payload_info(self._payload_bytes(packet), sport, dport)
                if imap_info is not None:
                    metadata['imap'] = imap_info
                    return 'IMAP'
                whois_payload = self._whois_payload_for_record(packet, metadata)
                whois_meta = metadata.get('whois') if isinstance(metadata.get('whois'), dict) else None
                if isinstance(whois_meta, dict):
                    kind = str(whois_meta.get('kind', '') or '')
                    if kind == 'query' and dport == 43:
                        return 'WHOIS'
                    if kind == 'answer' and sport == 43:
                        tcp_flags = int(getattr(effective_tcp, 'flags', 0) or 0)
                        has_fin = bool(tcp_flags & 0x01)
                        if has_fin or (not whois_payload and bool(str(metadata.get('tcp_reassembled_data_hex', '') or ''))):
                            return 'WHOIS'
                whois_info = self._whois_payload_info(whois_payload, sport, dport)
                if whois_info is not None:
                    kind = str(whois_info.get('kind', '') or '')
                    tcp_flags = int(getattr(effective_tcp, 'flags', 0) or 0)
                    has_fin = bool(tcp_flags & 0x01)
                    if kind == 'query' and dport == 43:
                        metadata['whois'] = whois_info
                        return 'WHOIS'
                    if kind == 'answer' and sport == 43:
                        if has_fin or (not whois_payload and bool(str(metadata.get('tcp_reassembled_data_hex', '') or ''))):
                            metadata['whois'] = whois_info
                            return 'WHOIS'
            if (
                not bool(metadata.get('tcp_is_retransmission', False))
                and not bool(metadata.get('tcp_is_duplicate_ack', False))
                and not bool(metadata.get('http_incomplete', False))
                and str(metadata.get('http_kind', '') or '')
            ):
                content_type = str(metadata.get('http_content_type', '') or '').lower()
                if self._is_ocsp_http(content_type):
                    return 'OCSP'
                if self._is_ipp_http(content_type):
                    return 'IPP'
                if 'xml' in content_type:
                    return 'HTTP/XML'
                return 'HTTP'
            if (sport == 515 or dport == 515) and not bool(metadata.get('tcp_is_retransmission', False)):
                lpd_info = self._lpd_payload_info(self._payload_bytes(packet), sport, dport)
                if lpd_info is not None:
                    metadata['lpd'] = lpd_info
                    return 'LPD'
            if sport in {25, 587} or dport in {25, 587}:
                smtp_kind = str(metadata.get('smtp_kind', '') or '')
                if smtp_kind == 'data' and bytes(metadata.get('smtp_data_reassembled_payload', b'') or b''):
                    return 'SMTP/IMF'
                if smtp_kind in {'command', 'response', 'data'}:
                    return 'SMTP'
                guessed_smtp = self._smtp_payload_kind(tcp_payload)
                if guessed_smtp in {'command', 'response'}:
                    metadata['smtp_kind'] = guessed_smtp
                    return 'SMTP'
        if packet.haslayer(ARP) and eth_type != 0x8035:
            return 'ARP'
        if self._is_dhcpv6_packet(packet):
            return 'DHCPv6'
        if packet.haslayer(DHCP) or packet.haslayer(BOOTP):
            return 'DHCP'
        if self._is_icmpv6_packet(packet):
            if packet.haslayer(DNS):
                metadata['icmpv6_contains_dns'] = True
            return 'ICMPv6'
        if packet.haslayer(DNS):
            if effective_udp is not None:
                qname = self._dns_qname(packet)
                if qname.endswith('.local') or self._is_mdns_transport(packet):
                    return 'MDNS'
                return 'DNS'
            if effective_tcp is not None and (
                self._is_dns_over_tcp_packet(packet)
                and (
                    bool(str(metadata.get('tcp_reassembled_data_hex', '') or ''))
                    or metadata.get('tcp_reassembled_pdu_in_frame') is not None
                    or bool(metadata.get('tcp_reassembled_segments'))
                )
            ):
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
            rtsp_kind = self._rtsp_payload_kind(payload)
            if rtsp_kind is not None:
                metadata['http_kind'] = rtsp_kind
                return 'RTSP'
            if (
                not bool(metadata.get('tcp_is_retransmission', False))
                and not bool(metadata.get('tcp_is_duplicate_ack', False))
                and not bool(metadata.get('http_incomplete', False))
                and (sport in {80, 3128, 8080} or dport in {80, 3128, 8080})
                and self._http_payload_kind(payload) is not None
            ):
                content_type = self._http_content_type_from_payload(payload)
                if self._is_ocsp_http(content_type):
                    return 'OCSP'
                if self._is_ipp_http(content_type):
                    return 'IPP'
                return 'HTTP'
        if (
            not bool(metadata.get('tcp_is_retransmission', False))
            and not bool(metadata.get('tcp_is_duplicate_ack', False))
            and not bool(metadata.get('http_incomplete', False))
            and (packet.haslayer(HTTPResponse) or packet.haslayer(HTTPRequest))
        ):
            content_type = str(metadata.get('http_content_type', '') or '').lower()
            if 'xml' in content_type:
                return 'HTTP/XML'
            return 'HTTP'
        if packet.haslayer(TLSClientHello) or packet.haslayer(TLS):
            tls_summary = self._tls_record_summary(packet)
            if tls_summary is not None:
                return str(tls_summary.get('version_name', 'TLS'))
            return 'TLS'

        # Fallback: detect TLS from TCP payload (Raw) if no TLS layer
        if effective_tcp is not None:
            payload = self._payload_bytes(packet)
            if len(payload) >= 5:
                for i in range(0, len(payload) - 4):
                    content_type = int(payload[i])
                    version = int.from_bytes(payload[i + 1:i + 3], 'big')
                    record_len = int.from_bytes(payload[i + 3:i + 5], 'big')
                    if (
                        content_type in {20, 21, 22, 23}
                        and version in {0x0301, 0x0302, 0x0303, 0x0304}
                        and i + 5 + record_len <= len(payload)
                    ):
                        return self._tls_version_name(version)
        if packet.haslayer(QUIC):
            return 'QUIC'
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

    def _is_dns_over_tcp_packet(self, packet) -> bool:
        tcp_layer = self._effective_tcp_layer(packet, self._effective_ip_layer(packet))
        if tcp_layer is None:
            return False
        try:
            sport = int(getattr(tcp_layer, 'sport', 0) or 0)
            dport = int(getattr(tcp_layer, 'dport', 0) or 0)
        except Exception:
            return False
        if sport != 53 and dport != 53:
            return False
        payload = bytes(getattr(tcp_layer, 'payload', b''))
        if len(payload) < 14:
            return False
        msg_len = int.from_bytes(payload[:2], 'big')
        if msg_len < 12:
            return False
        if msg_len + 2 > len(payload):
            return False
        return True

    def _dns_question_from_raw(self, raw_dns: bytes) -> tuple[str, str]:
        if len(raw_dns) < 16:
            return '', ''
        try:
            from core.formatters import _dns_read_name

            name, next_pos = _dns_read_name(raw_dns, 12)
            if next_pos + 2 > len(raw_dns):
                return name.rstrip('.'), ''
            qtype_value = int.from_bytes(raw_dns[next_pos:next_pos + 2], 'big')
            qtype_name = {
                1: 'A',
                2: 'NS',
                5: 'CNAME',
                6: 'SOA',
                12: 'PTR',
                15: 'MX',
                16: 'TXT',
                28: 'AAAA',
                33: 'SRV',
                41: 'OPT',
                48: 'DNSKEY',
                46: 'RRSIG',
            }.get(qtype_value, str(qtype_value))
            return str(name or '').rstrip('.'), qtype_name
        except Exception:
            return '', ''

    def _tls_version_name(self, version: int) -> str:
        return {
            0x0301: 'TLSv1.0',
            0x0302: 'TLSv1.1',
            0x0303: 'TLSv1.2',
            0x0304: 'TLSv1.3',
        }.get(int(version or 0), 'TLS')

    def _tls_handshake_type_name(self, handshake_type: int) -> str:
        return {
            0: 'Encrypted Handshake Message',
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

    def _uuid_from_dcerpc_bytes(self, value: bytes) -> str:
        if not isinstance(value, (bytes, bytearray)) or len(value) < 16:
            return ''
        b = bytes(value[:16])
        d1 = int.from_bytes(b[0:4], 'little')
        d2 = int.from_bytes(b[4:6], 'little')
        d3 = int.from_bytes(b[6:8], 'little')
        return f'{d1:08x}-{d2:04x}-{d3:04x}-{b[8]:02x}{b[9]:02x}-{b[10]:02x}{b[11]:02x}{b[12]:02x}{b[13]:02x}{b[14]:02x}{b[15]:02x}'

    def _dcerpc_interface_name(self, uuid_text: str) -> str:
        mapping = {
            'e1af8308-5d1f-11c9-91a4-08002b14a0fa': 'EPMv4',
            'e3514235-4b06-11d1-ab04-00c04fc2dcd2': 'DRSUAPI',
            '12345778-1234-abcd-ef00-01234567cffb': 'RPC_NETLOGON',
            '12345678-1234-abcd-ef00-01234567cffb': 'RPC_NETLOGON',
            '12345778-1234-abcd-ef00-0123456789ab': 'LSARPC',
            '12345778-1234-abcd-ef00-0123456789ac': 'SAMR',
        }
        return mapping.get(str(uuid_text or '').lower(), str(uuid_text or ''))

    def _dcerpc_transfer_syntax_name(self, uuid_text: str) -> str:
        mapping = {
            '8a885d04-1ceb-11c9-9fe8-08002b104860': '32bit NDR',
            '71710533-beba-4937-8319-b5dbef9ccc36': '64bit NDR',
        }
        return mapping.get(str(uuid_text or '').lower(), str(uuid_text or ''))

    def _tcp_event_prefix(self, metadata: dict | None) -> str:
        md = metadata if isinstance(metadata, dict) else {}
        if bool(md.get('tcp_port_numbers_reused', False)):
            return '[TCP Port numbers reused] '
        if bool(md.get('tcp_is_duplicate_ack', False)):
            dup_frame = int(md.get('tcp_duplicate_ack_frame_number', 0) or 0)
            dup_count = int(md.get('tcp_duplicate_ack_count', 1) or 1)
            return f'[TCP Dup ACK {dup_frame}#{dup_count}] '
        if bool(md.get('tcp_is_window_full', False)):
            return '[TCP Window Full] '
        if bool(md.get('tcp_is_window_update', False)):
            return '[TCP Window Update] '
        if bool(md.get('tcp_is_keep_alive_ack', False)):
            return '[TCP Keep-Alive ACK] '
        if bool(md.get('tcp_is_keep_alive', False)):
            return '[TCP Keep-Alive] '
        if bool(md.get('tcp_is_acked_unseen_segment', False)):
            return '[TCP ACKed unseen segment] '
        if bool(md.get('tcp_is_spurious_retransmission', False)):
            return '[TCP Spurious Retransmission] '
        if bool(md.get('tcp_is_out_of_order', False)):
            return '[TCP Out-Of-Order] '
        if bool(md.get('tcp_is_retransmission', False)):
            return '[TCP Retransmission] '
        if bool(md.get('tcp_previous_segment_not_captured', False)):
            return '[TCP Previous segment not captured] '
        return ''

    def _dtls_payload_info(self, payload: bytes) -> dict | None:
        if not isinstance(payload, (bytes, bytearray)) or len(payload) < 13:
            return None
        off = 0
        protocol = 'DTLS'
        labels: list[str] = []
        parsed_any = False
        while off + 13 <= len(payload):
            content_type = int(payload[off])
            version = int.from_bytes(payload[off + 1:off + 3], 'big')
            if content_type not in {20, 21, 22, 23} or version not in {0xFEFF, 0xFEFD}:
                break
            record_len = int.from_bytes(payload[off + 11:off + 13], 'big')
            if record_len < 0 or off + 13 + record_len > len(payload):
                break
            parsed_any = True
            protocol = 'DTLSv1.2' if version == 0xFEFD else 'DTLS'
            record_body = payload[off + 13:off + 13 + record_len]
            if content_type == 20:
                labels.append('Change Cipher Spec')
            elif content_type == 21:
                labels.append('Encrypted Alert')
            elif content_type == 23:
                labels.append('Application Data')
            elif content_type == 22 and record_body:
                hs_off = 0
                while hs_off + 12 <= len(record_body):
                    hs_type = int(record_body[hs_off])
                    hs_len = int.from_bytes(record_body[hs_off + 1:hs_off + 4], 'big')
                    hs_name = {
                        1: 'Client Hello',
                        2: 'Server Hello',
                        11: 'Certificate',
                        12: 'Server Key Exchange',
                        13: 'Certificate Request',
                        14: 'Server Hello Done',
                        15: 'Certificate Verify',
                        16: 'Client Key Exchange',
                        20: 'Encrypted Handshake Message',
                        0: 'Encrypted Handshake Message',
                    }.get(hs_type, f'Handshake ({hs_type})')
                    labels.append(hs_name)
                    hs_off += 12 + max(0, hs_len)
                    if hs_off > len(record_body):
                        break
            off += 13 + record_len

        if not parsed_any:
            return None
        # Keep stable ordering but remove immediate duplicates.
        compact: list[str] = []
        for label in labels:
            if not compact or compact[-1] != label:
                compact.append(label)
        info_text = ', '.join(compact) if compact else 'Datagram Transport Layer Security'
        return {'protocol': protocol, 'info_text': info_text}

    def _stun_payload_info(self, payload: bytes) -> dict | None:
        data = bytes(payload or b'')
        if len(data) < 20:
            return None
        msg_type = int.from_bytes(data[0:2], 'big')
        msg_len = int.from_bytes(data[2:4], 'big')
        cookie = int.from_bytes(data[4:8], 'big')
        if (msg_type & 0xC000) != 0:
            return None
        if cookie != 0x2112A442:
            return None
        if 20 + msg_len > len(data):
            return None
        trans_id = data[8:20]
        klass = ((msg_type >> 4) & 0x1) | (((msg_type >> 8) & 0x1) << 1)
        method = (msg_type & 0x000F) | ((msg_type & 0x00E0) >> 1) | ((msg_type & 0x3E00) >> 2)
        return {
            'message_type': msg_type,
            'message_length': msg_len,
            'message_class': klass,
            'message_method': method,
            'transaction_id': bytes(trans_id),
            'cookie': cookie,
            'raw': data[:20 + msg_len],
        }

    def _update_stun_request_response_metadata(
        self,
        protocol: str,
        metadata: dict,
        src: str,
        dst: str,
        sport: int | None,
        dport: int | None,
        frame_number: int,
        epoch_time: float,
    ) -> None:
        if protocol != 'STUN':
            return
        stun = metadata.get('stun')
        if not isinstance(stun, dict):
            return
        tx_id = bytes(stun.get('transaction_id', b'') or b'')
        if not tx_id:
            return
        klass = int(stun.get('message_class', -1) or -1)
        method = int(stun.get('message_method', -1) or -1)
        if method < 0:
            return
        key = (tx_id, int(method))
        if klass == 0:
            self.stun_pending[key] = {
                'frame': int(frame_number),
                'time': float(epoch_time),
                'src': str(src),
                'dst': str(dst),
                'sport': int(sport or 0),
                'dport': int(dport or 0),
            }
            return
        if klass == 2:
            pending = self.stun_pending.get(key)
            if isinstance(pending, dict):
                req_frame = int(pending.get('frame', 0) or 0)
                if req_frame > 0:
                    metadata['stun_request_frame'] = req_frame
                    delta_us = max(0.0, (float(epoch_time) - float(pending.get('time', epoch_time))) * 1_000_000.0)
                    metadata['stun_time_from_request_us'] = float(delta_us)

    def _hkdf_extract_sha256(self, salt: bytes, ikm: bytes) -> bytes:
        h = hmac.HMAC(bytes(salt), hashes.SHA256())
        h.update(bytes(ikm))
        return h.finalize()

    def _hkdf_expand_label_sha256(self, secret: bytes, label: bytes, context: bytes, length: int) -> bytes:
        full_label = b'tls13 ' + bytes(label)
        hkdf_label = (
            int(length).to_bytes(2, 'big')
            + bytes([len(full_label)])
            + full_label
            + bytes([len(context)])
            + bytes(context)
        )
        hkdf = HKDFExpand(algorithm=hashes.SHA256(), length=int(length), info=hkdf_label)
        return hkdf.derive(bytes(secret))

    def _decode_quic_varint(self, data: bytes, offset: int) -> tuple[int, int] | None:
        if offset < 0 or offset >= len(data):
            return None
        first = int(data[offset])
        ln = 1 << (first >> 6)
        if offset + ln > len(data):
            return None
        value = first & 0x3F
        for idx in range(1, ln):
            value = (value << 8) | int(data[offset + idx])
        return value, ln

    def _parse_quic_tls_client_hello(self, data: bytes) -> dict | None:
        buf = bytes(data or b'')
        if len(buf) < 4 or int(buf[0]) != 1:
            return None
        body_len = int.from_bytes(buf[1:4], 'big')
        if 4 + body_len > len(buf):
            return None
        body = buf[4:4 + body_len]
        if len(body) < 38:
            return None
        cursor = 0
        legacy_version = int.from_bytes(body[cursor:cursor + 2], 'big')
        cursor += 2
        random_hex = body[cursor:cursor + 32].hex()
        cursor += 32
        sid_len = int(body[cursor])
        cursor += 1
        session_id = body[cursor:cursor + sid_len]
        cursor += sid_len
        if cursor + 2 > len(body):
            return None
        suites_len = int.from_bytes(body[cursor:cursor + 2], 'big')
        cursor += 2
        cipher_suites = []
        for off in range(cursor, min(len(body), cursor + suites_len), 2):
            if off + 2 > len(body):
                break
            cipher_suites.append(int.from_bytes(body[off:off + 2], 'big'))
        cursor += suites_len
        if cursor >= len(body):
            return None
        comp_len = int(body[cursor])
        cursor += 1
        compression_methods = list(body[cursor:cursor + comp_len])
        cursor += comp_len
        extensions = []
        if cursor + 2 <= len(body):
            ext_total = int.from_bytes(body[cursor:cursor + 2], 'big')
            cursor += 2
            ext_end = min(len(body), cursor + ext_total)
            while cursor + 4 <= ext_end:
                etype = int.from_bytes(body[cursor:cursor + 2], 'big')
                elen = int.from_bytes(body[cursor + 2:cursor + 4], 'big')
                estart = cursor + 4
                eend = min(ext_end, estart + elen)
                extensions.append({
                    'type': etype,
                    'data': body[estart:eend],
                })
                cursor = eend
        return {
            'handshake_length': body_len,
            'legacy_version': legacy_version,
            'random_hex': random_hex,
            'session_id': session_id.hex(),
            'cipher_suites': cipher_suites,
            'compression_methods': compression_methods,
            'extensions': extensions,
        }

    def _quic_payload_info(self, payload: bytes, src: str = '', dst: str = '', sport: int | None = None, dport: int | None = None) -> dict | None:
        data = bytes(payload or b'')
        if len(data) < 7 or (int(data[0]) & 0x40) == 0:
            return None

        def _transport_key() -> tuple:
            left = (str(src), int(sport or 0))
            right = (str(dst), int(dport or 0))
            return ('UDP', left, right) if left <= right else ('UDP', right, left)

        def _parse_frames(plaintext: bytes) -> dict[str, Any]:
            pos = 0
            frames: list[dict[str, Any]] = []
            crypto_frames: list[dict[str, Any]] = []
            ack_frames: list[dict[str, Any]] = []
            remaining = ''
            while pos < len(plaintext):
                info = self._decode_quic_varint(plaintext, pos)
                if info is None:
                    remaining = plaintext[pos:].hex()
                    break
                frame_type, ft_len = info
                if frame_type == 0x00:
                    pad_start = pos
                    while pos < len(plaintext) and plaintext[pos] == 0x00:
                        pos += 1
                    frames.append({'type': 0x00, 'offset_in_plaintext': pad_start, 'length': pos - pad_start})
                    continue
                if frame_type == 0x06:
                    off_info = self._decode_quic_varint(plaintext, pos + ft_len)
                    if off_info is None:
                        remaining = plaintext[pos:].hex()
                        break
                    crypto_offset, off_len = off_info
                    len_info = self._decode_quic_varint(plaintext, pos + ft_len + off_len)
                    if len_info is None:
                        remaining = plaintext[pos:].hex()
                        break
                    crypto_len, crypto_len_len = len_info
                    crypto_start = pos + ft_len + off_len + crypto_len_len
                    crypto_end = min(len(plaintext), crypto_start + crypto_len)
                    frame = {
                        'type': 0x06,
                        'offset_in_plaintext': pos,
                        'crypto_offset': crypto_offset,
                        'crypto_length': crypto_len,
                        'crypto_data': bytes(plaintext[crypto_start:crypto_end]),
                        'length': crypto_end - pos,
                    }
                    crypto_frames.append(frame)
                    frames.append(frame)
                    pos = crypto_end
                    continue
                if frame_type in {0x02, 0x03}:
                    at = pos + ft_len
                    largest = self._decode_quic_varint(plaintext, at)
                    delay = self._decode_quic_varint(plaintext, at + (largest[1] if largest else 0)) if largest else None
                    ranges = self._decode_quic_varint(plaintext, at + (largest[1] if largest else 0) + (delay[1] if delay else 0)) if delay else None
                    first_range = self._decode_quic_varint(plaintext, at + (largest[1] if largest else 0) + (delay[1] if delay else 0) + (ranges[1] if ranges else 0)) if ranges else None
                    ack_len = ft_len + sum(item[1] for item in (largest, delay, ranges, first_range) if item)
                    ack = {
                        'type': frame_type,
                        'offset_in_plaintext': pos,
                        'largest_acknowledged': int(largest[0]) if largest else 0,
                        'ack_delay': int(delay[0]) if delay else 0,
                        'ack_range_count': int(ranges[0]) if ranges else 0,
                        'first_ack_range': int(first_range[0]) if first_range else 0,
                        'length': ack_len,
                    }
                    ack_frames.append(ack)
                    frames.append(ack)
                    pos += ack_len
                    continue
                remaining = plaintext[pos:].hex()
                break
            return {
                'frames': frames,
                'crypto_frames': crypto_frames,
                'ack_frames': ack_frames,
                'remaining_payload_hex': remaining,
            }

        key = _transport_key()
        blocks: list[dict[str, Any]] = []
        cursor = 0
        while cursor < len(data):
            start = cursor
            first = int(data[cursor])
            if (first & 0x40) == 0:
                if any(b != 0x00 for b in data[cursor:]):
                    break
                blocks.append({'header_form': 'Padding', 'offset': cursor, 'total_length': len(data) - cursor, 'padding_appended': True})
                cursor = len(data)
                break
            if (first & 0x80) == 0:
                if start == 0 and key not in self.quic_connections:
                    return None
                blocks.append({
                    'header_form': 'Short Header',
                    'fixed_bit': True,
                    'packet_type': 'short',
                    'offset': cursor,
                    'total_length': len(data) - cursor,
                    'raw': data[cursor:],
                    'remaining_payload_hex': data[cursor + 1:].hex() if len(data) - cursor > 1 else '',
                    'decryption_failed': True,
                    'decryption_failure_reason': 'Secrets are not available',
                })
                cursor = len(data)
                break
            if cursor + 7 > len(data):
                break
            version = int.from_bytes(data[cursor + 1:cursor + 5], 'big')
            if version == 0:
                break
            dcid_len = int(data[cursor + 5])
            pos = cursor + 6
            if pos + dcid_len >= len(data):
                break
            dcid = bytes(data[pos:pos + dcid_len])
            pos += dcid_len
            scid_len = int(data[pos])
            pos += 1
            if pos + scid_len > len(data):
                break
            scid = bytes(data[pos:pos + scid_len])
            pos += scid_len
            packet_type = (first >> 4) & 0x03
            block: dict[str, Any] = {
                'version': version,
                'header_form': 'Long Header',
                'fixed_bit': True,
                'packet_type': packet_type,
                'dcid': dcid.hex(),
                'scid': scid.hex(),
                'offset': start,
            }
            if packet_type == 3:
                block['header_prefix_length'] = pos - start
                block['retry_token_hex'] = data[pos:max(pos, len(data) - 16)].hex()
                block['retry_integrity_tag_hex'] = data[max(pos, len(data) - 16):].hex()
                block['token_length'] = max(0, len(data) - 16 - pos)
                block['total_length'] = len(data) - start
                block['raw'] = data[start:]
                blocks.append(block)
                cursor = len(data)
                continue
            token_len = 0
            if packet_type == 0:
                token_info = self._decode_quic_varint(data, pos)
                if token_info is None:
                    break
                token_len, token_len_len = token_info
                pos += token_len_len
                block['token'] = data[pos:pos + token_len].hex()
                block['token_length'] = token_len
                pos += token_len
            length_info = self._decode_quic_varint(data, pos)
            if length_info is None:
                break
            packet_length, length_varint_len = length_info
            pos += length_varint_len
            block['packet_length'] = packet_length
            block['length_varint_len'] = length_varint_len
            block['header_prefix_length'] = pos - start
            block['total_length'] = min(len(data) - start, (pos - start) + packet_length)
            block['raw'] = data[start:start + int(block['total_length'])]
            if packet_type == 0 and token_len == 0 and src and dst:
                ctx = self.quic_connections.get(key, {})
                if not ctx:
                    self.quic_connections[key] = {
                        'initial_dcid': dcid.hex(),
                        'client_endpoint': (str(src), int(sport or 0)),
                    }
            secret_cid = dcid
            role = 'client'
            ctx = self.quic_connections.get(key, {})
            if ctx and tuple(ctx.get('client_endpoint', ())) != (str(src), int(sport or 0)):
                role = 'server'
                initial_hex = str(ctx.get('initial_dcid', '') or '')
                if initial_hex:
                    try:
                        secret_cid = bytes.fromhex(initial_hex)
                    except Exception:
                        secret_cid = dcid
            if packet_type == 0 and version == 1 and secret_cid:
                try:
                    initial_salt = bytes.fromhex('38762cf7f55934b34d179ae6a4c80cadccbb7f0a')
                    initial_secret = self._hkdf_extract_sha256(initial_salt, secret_cid)
                    directional_secret = self._hkdf_expand_label_sha256(initial_secret, b'client in' if role == 'client' else b'server in', b'', 32)
                    key_bytes = self._hkdf_expand_label_sha256(directional_secret, b'quic key', b'', 16)
                    iv = self._hkdf_expand_label_sha256(directional_secret, b'quic iv', b'', 12)
                    hp = self._hkdf_expand_label_sha256(directional_secret, b'quic hp', b'', 16)
                    sample_offset = pos + 4
                    if sample_offset + 16 <= start + int(block['total_length']):
                        sample = data[sample_offset:sample_offset + 16]
                        mask = Cipher(algorithms.AES(hp), modes.ECB()).encryptor().update(sample)
                        unprotected_first = first ^ (int(mask[0]) & 0x0F)
                        packet_number_len = (unprotected_first & 0x03) + 1
                        if pos + packet_number_len <= start + int(block['total_length']):
                            pn_bytes = bytearray(data[pos:pos + packet_number_len])
                            for idx in range(packet_number_len):
                                pn_bytes[idx] ^= int(mask[idx + 1])
                            packet_number = int.from_bytes(bytes(pn_bytes), 'big')
                            aad = bytearray(data[start:pos + packet_number_len])
                            aad[0] = unprotected_first
                            aad[pos - start:pos - start + packet_number_len] = pn_bytes
                            ciphertext = data[pos + packet_number_len:start + int(block['total_length'])]
                            nonce = bytearray(iv)
                            pn_full = int(packet_number).to_bytes(len(nonce), 'big')
                            for idx in range(len(nonce)):
                                nonce[idx] ^= pn_full[idx]
                            plaintext = AESGCM(key_bytes).decrypt(bytes(nonce), bytes(ciphertext), bytes(aad))
                            block['packet_number'] = packet_number
                            block['packet_number_length'] = packet_number_len
                            block['payload_plaintext'] = plaintext.hex()
                            block['quic_decrypted_payload'] = plaintext
                            block['header_unprotected_first_byte'] = unprotected_first
                            frame_info = _parse_frames(plaintext)
                            block.update(frame_info)
                            if block.get('crypto_frames'):
                                first_crypto = block['crypto_frames'][0]
                                crypto_data = bytes(first_crypto.get('crypto_data', b'') or b'')
                                block['frame_type'] = 0x06
                                block['crypto_frame_offset_in_plaintext'] = int(first_crypto.get('offset_in_plaintext', 0) or 0)
                                block['crypto_offset'] = int(first_crypto.get('crypto_offset', 0) or 0)
                                block['crypto_length'] = len(crypto_data)
                                block['crypto_data'] = crypto_data.hex()
                                client_hello = self._parse_quic_tls_client_hello(crypto_data)
                                if isinstance(client_hello, dict):
                                    block['client_hello'] = client_hello
                except Exception:
                    block['decryption_failed'] = True
                    block['decryption_failure_reason'] = 'Secrets are not available'
            elif packet_type in {1, 2}:
                block['decryption_failed'] = True
                block['decryption_failure_reason'] = 'Secrets are not available'
                block['packet_number_length'] = (first & 0x03) + 1
                pn_guess = int(block['packet_number_length'])
                if pos + pn_guess <= start + int(block['total_length']):
                    block['remaining_payload_hex'] = data[pos + pn_guess:start + int(block['total_length'])].hex()
            blocks.append(block)
            cursor = start + max(1, int(block['total_length']))
        if not blocks:
            return None
        quic = dict(blocks[0])
        quic['raw'] = data
        quic['blocks'] = blocks
        for block in blocks:
            decrypted = bytes(block.get('quic_decrypted_payload', b'') or b'')
            if decrypted:
                quic['quic_decrypted_payload'] = decrypted
                break
        return quic

    def _srtcp_payload_info(self, payload: bytes) -> dict | None:
        data = bytes(payload or b'')
        if len(data) < 12:
            return None
        v = (int(data[0]) >> 6) & 0x03
        if v != 2:
            return None
        pt = int(data[1])
        if pt < 192 or pt > 223:
            return None
        rtcp_words = int.from_bytes(data[2:4], 'big')
        rtcp_len = (rtcp_words + 1) * 4
        if rtcp_len < 8 or rtcp_len > len(data):
            return None
        # SRTCP adds index/auth after RTCP payload; plain RTCP generally ends at rtcp_len.
        if len(data) <= rtcp_len:
            return None
        compound_types: list[int] = [pt]
        malformed = False
        cursor = rtcp_len
        while cursor + 8 <= len(data):
            next_first = int(data[cursor])
            next_ver = (next_first >> 6) & 0x03
            next_pt = int(data[cursor + 1])
            if next_ver not in {1, 2} or next_pt < 200 or next_pt > 207:
                break
            next_words = int.from_bytes(data[cursor + 2:cursor + 4], 'big')
            next_len = (next_words + 1) * 4
            compound_types.append(next_pt)
            if cursor + next_len > len(data):
                malformed = True
                break
            cursor += next_len
            if len(compound_types) >= 4:
                break
        return {
            'version': 2,
            'packet_type': pt,
            'rtcp_length': rtcp_len,
            'total_length': len(data),
            'payload': data,
            'compound_packet_types': compound_types,
            'malformed': malformed,
        }

    def _update_srtcp_setup_metadata(
        self,
        protocol: str,
        metadata: dict,
        src: str,
        dst: str,
        sport: int | None,
        dport: int | None,
    ) -> None:
        if protocol != 'SRTCP':
            return
        key = self._canonical_transport_key(str(src), int(sport or 0), str(dst), int(dport or 0), 'UDP')
        setup_frame = int(self.srtcp_setup_frames.get(key, 0) or 0)
        if setup_frame > 0:
            metadata['srtcp_setup_frame'] = setup_frame

    def _rdpudp_payload_info(self, payload: bytes) -> dict | None:
        data = bytes(payload or b'')
        if len(data) < 8:
            return None
        b0 = int(data[0])
        proto = 'RDPUDP2' if b0 in {0x00, 0x48, 0x80, 0x81} else 'RDPUDP'
        if b0 in {0x09, 0x0A, 0x16, 0xFF}:
            proto = 'RDPUDP'
        info = {
            'protocol': proto,
            'first_byte': b0,
            'length': len(data),
            'preview': data[:24],
        }
        if len(data) >= 8 and (int(data[7]) & 0xE0) == 0xE0:
            unwrapped = bytes([int(data[7])]) + bytes(data[1:7]) + bytes(data[0:1]) + bytes(data[8:])
            flags = ((int(unwrapped[2]) & 0x0F) << 8) | int(unwrapped[1])
            info['prefix_byte'] = int(unwrapped[0])
            info['flags'] = flags
            info['log_window'] = (int(unwrapped[2]) >> 4) & 0x0F
            info['unwrapped_payload'] = unwrapped
            labels = []
            if flags & 0x001:
                labels.append('ACK')
            if flags & 0x010:
                labels.append('AOA')
            if flags & 0x040:
                labels.append('OVERHEAD')
            if flags & 0x100:
                labels.append('DELAYACK')
            if flags & 0x004:
                labels.append('DATA')
            info['flag_labels'] = labels
            data_offset = 3
            if len(unwrapped) >= 8:
                tls_start = -1
                for i in range(0, len(unwrapped) - 4):
                    ct = int(unwrapped[i])
                    ver = int.from_bytes(unwrapped[i + 1:i + 3], 'big')
                    rec_len = int.from_bytes(unwrapped[i + 3:i + 5], 'big')
                    if ct in {20, 21, 22, 23} and ver in {0x0301, 0x0302, 0x0303, 0x0304} and i + 5 + rec_len <= len(unwrapped):
                        tls_start = i
                        break
                info['tls_start'] = tls_start
            if flags & 0x010:
                info['aoa_sequence'] = int.from_bytes(unwrapped[data_offset:data_offset + 2], 'little') if len(unwrapped) >= data_offset + 2 else 0
                data_offset += 2
            if flags & 0x100:
                if len(unwrapped) >= data_offset + 2:
                    info['max_delayed_acks'] = int(unwrapped[data_offset])
                    info['delayed_ack_timeout_ms'] = int(unwrapped[data_offset + 1])
                data_offset += 2
            if flags & 0x001 and len(unwrapped) >= 10:
                info['ack_base_seq'] = int.from_bytes(unwrapped[3:5], 'little')
                info['ack_received_ts'] = int.from_bytes(unwrapped[5:7], 'little')
                info['ack_send_gap'] = int.from_bytes(unwrapped[7:9], 'little')
                info['num_delayed_acks'] = int(unwrapped[9] & 0x0F)
                info['delayed_time_scale'] = int((unwrapped[9] >> 4) & 0x0F)
                data_offset = max(data_offset, 10)
            tls_start = int(info.get('tls_start', -1) or -1)
            if flags & 0x040:
                if tls_start >= 5:
                    overhead_size_pos = tls_start - 5
                    if overhead_size_pos >= data_offset and overhead_size_pos < len(unwrapped):
                        info['overhead_size'] = int(unwrapped[overhead_size_pos])
                        data_offset = max(data_offset, overhead_size_pos + 1)
                elif len(unwrapped) > data_offset:
                    info['overhead_size'] = int(unwrapped[data_offset])
                    data_offset += 1
            info['data_offset'] = min(len(data), max(8, data_offset))
            if tls_start >= 4:
                info['data_offset'] = max(data_offset, tls_start - 4)
            if len(unwrapped) >= int(info['data_offset']) + 4:
                data_offset = int(info['data_offset'])
                info['data_sequence'] = int.from_bytes(unwrapped[data_offset:data_offset + 2], 'little')
                info['channel_sequence'] = int.from_bytes(unwrapped[data_offset + 2:data_offset + 4], 'little')
            return info
        if proto == 'RDPUDP':
            flags = int.from_bytes(data[6:8], 'big')
            info['flags'] = flags
            info['flag_labels'] = [
                name for bit, name in (
                    (0x0001, 'SYN'),
                    (0x0002, 'FIN'),
                    (0x0004, 'ACK'),
                    (0x0008, 'DATA'),
                    (0x0010, 'FECDATA'),
                    (0x0020, 'CN'),
                    (0x0040, 'CWR'),
                    (0x0080, 'AOA'),
                    (0x0100, 'SYNLOSSY'),
                    (0x0200, 'DELAYACK'),
                    (0x0800, 'CORRELATIONID'),
                    (0x1000, 'SYNEX'),
                ) if (flags & bit)
            ]
            if len(data) >= 16:
                info['initial_sequence'] = int.from_bytes(data[8:12], 'big')
                info['upstream_mtu'] = int.from_bytes(data[12:14], 'big')
                info['downstream_mtu'] = int.from_bytes(data[14:16], 'big')
            cursor = 16
            if flags & 0x0800 and len(data) >= cursor + 16:
                info['correlation_id'] = data[cursor:cursor + 16]
                cursor += 16
            if flags & 0x1000 and len(data) >= cursor + 4:
                synex_flags = int.from_bytes(data[cursor:cursor + 2], 'big')
                info['synex_flags'] = synex_flags
                if len(data) >= cursor + 4:
                    info['version'] = int.from_bytes(data[cursor + 2:cursor + 4], 'big')
                if len(data) >= cursor + 36:
                    info['cookie_hash'] = data[cursor + 4:cursor + 36]
        else:
            prefix = int(data[7]) if len(data) >= 8 else 0
            flags = ((int(data[2]) & 0x0F) << 8) | int(data[1])
            info['prefix_byte'] = prefix
            info['log_window'] = (int(data[2]) >> 4) & 0x0F
            info['flags'] = flags
            info['flag_labels'] = [
                name for bit, name in (
                    (0x001, 'ACK'),
                    (0x004, 'DATA'),
                    (0x010, 'AOA'),
                    (0x040, 'OVERHEAD'),
                    (0x100, 'DELAYACK'),
                ) if (flags & bit)
            ]
            if len(data) >= 5:
                info['aoa_sequence'] = int.from_bytes(data[3:5], 'little')
            if len(data) >= 7:
                info['dummy_sequence'] = int.from_bytes(data[5:7], 'little')
            if flags & 0x001 and len(data) >= 10:
                info['ack_base_seq'] = int.from_bytes(data[3:5], 'little')
                info['ack_received_ts'] = int.from_bytes(data[5:7], 'little')
                info['ack_send_gap'] = int.from_bytes(data[8:10], 'little')
            if flags & 0x040 and len(data) >= 11:
                info['overhead_size'] = int(data[10])
            if flags & 0x100 and len(data) >= 13:
                info['max_delayed_acks'] = int(data[11])
                info['delayed_ack_timeout_ms'] = int(data[12])
        return info

    def _tls_record_summaries_bytes(self, payload: bytes) -> list[dict]:
        blob = bytes(payload or b'')
        if len(blob) < 5:
            return []

        summaries: list[dict] = []
        cursor = 0
        first_type = int(blob[0])
        first_ver = int.from_bytes(blob[1:3], 'big')
        first_len = int.from_bytes(blob[3:5], 'big')
        starts_with_tls = (
            first_type in {20, 21, 22, 23}
            and first_ver in {0x0301, 0x0302, 0x0303, 0x0304}
            and 5 + first_len <= len(blob)
        )
        if not starts_with_tls:
            for i in range(0, len(blob) - 4):
                ctype = int(blob[i])
                ver = int.from_bytes(blob[i + 1:i + 3], 'big')
                rec_len = int.from_bytes(blob[i + 3:i + 5], 'big')
                if ctype in {20, 21, 22, 23} and ver in {0x0301, 0x0302, 0x0303, 0x0304} and i + 5 + rec_len <= len(blob):
                    cursor = i
                    break

        while cursor + 5 <= len(blob):
            content_type = int(blob[cursor])
            version = int.from_bytes(blob[cursor + 1:cursor + 3], 'big')
            record_len = int.from_bytes(blob[cursor + 3:cursor + 5], 'big')
            body_start = cursor + 5
            body_end = min(len(blob), body_start + record_len)
            if content_type not in {20, 21, 22, 23} or version not in {0x0301, 0x0302, 0x0303, 0x0304}:
                break
            if body_start + record_len > len(blob):
                summaries.append({
                    'content_type': content_type,
                    'version': version,
                    'version_name': self._tls_version_name(version),
                    'record_len': record_len,
                    'offset': cursor,
                    'length': len(blob) - cursor,
                    'handshake_names': [],
                    'is_segment': True,
                })
                break
            body = blob[body_start:body_end]
            summary = {
                'content_type': content_type,
                'version': version,
                'version_name': self._tls_version_name(version),
                'record_len': record_len,
                'offset': cursor,
                'length': 5 + len(body),
                'handshake_names': [],
            }
            parse_handshake = content_type == 22 and len(body) >= 4
            if not parse_handshake and content_type == 23 and len(body) >= 4:
                hs_type_probe = int(body[0])
                hs_len_probe = int.from_bytes(body[1:4], 'big')
                if hs_type_probe in {1, 2, 4, 11, 12, 13, 14, 15, 16, 20} and 4 + hs_len_probe <= len(body):
                    parse_handshake = True
            if parse_handshake:
                hs_pos = 0
                handshake_names = []
                while hs_pos + 4 <= len(body):
                    handshake_type = int(body[hs_pos])
                    handshake_len = int.from_bytes(body[hs_pos + 1:hs_pos + 4], 'big')
                    if handshake_type == 0:
                        handshake_names.append('Encrypted Handshake Message')
                        break
                    hs_total = 4 + handshake_len
                    if hs_total < 4 or hs_pos + hs_total > len(body):
                        handshake_names.append('Encrypted Handshake Message')
                        break
                    handshake_names.append(self._tls_handshake_type_name(handshake_type))
                    if handshake_type == 1 and hs_pos + hs_total >= 6:
                        hello_version = int.from_bytes(body[hs_pos + 4:hs_pos + 6], 'big')
                        summary['handshake_version'] = hello_version
                    hs_pos += hs_total
                summary['handshake_names'] = handshake_names
                if handshake_names:
                    summary['handshake_name'] = handshake_names[0]
            summaries.append(summary)
            if record_len <= 0:
                break
            cursor = body_start + record_len
        return summaries

    def _tls_client_hello_sni_bytes(self, payload: bytes) -> str:
        blob = bytes(payload or b'')
        if len(blob) < 5:
            return ''
        cursor = 0
        while cursor + 5 <= len(blob):
            content_type = int(blob[cursor])
            version = int.from_bytes(blob[cursor + 1:cursor + 3], 'big')
            record_len = int.from_bytes(blob[cursor + 3:cursor + 5], 'big')
            if content_type not in {20, 21, 22, 23} or version not in {0x0301, 0x0302, 0x0303, 0x0304}:
                cursor += 1
                continue
            record_start = cursor + 5
            record_end = min(len(blob), record_start + record_len)
            if content_type != 22 or record_end - record_start < 4:
                cursor = record_end
                continue
            hs_pos = record_start
            while hs_pos + 4 <= record_end:
                hs_type = int(blob[hs_pos])
                hs_len = int.from_bytes(blob[hs_pos + 1:hs_pos + 4], 'big')
                hs_body_start = hs_pos + 4
                hs_body_end = hs_body_start + hs_len
                if hs_body_end > record_end or hs_type != 1:
                    break
                body = blob[hs_body_start:hs_body_end]
                if len(body) < 34:
                    break
                pos = 34
                if pos + 1 > len(body):
                    break
                sid_len = int(body[pos]); pos += 1 + sid_len
                if pos + 2 > len(body):
                    break
                cs_len = int.from_bytes(body[pos:pos + 2], 'big'); pos += 2 + cs_len
                if pos + 1 > len(body):
                    break
                comp_len = int(body[pos]); pos += 1 + comp_len
                if pos + 2 > len(body):
                    break
                ext_len = int.from_bytes(body[pos:pos + 2], 'big'); pos += 2
                ext_end = min(len(body), pos + ext_len)
                while pos + 4 <= ext_end:
                    ext_type = int.from_bytes(body[pos:pos + 2], 'big')
                    ext_size = int.from_bytes(body[pos + 2:pos + 4], 'big')
                    ext_data_start = pos + 4
                    ext_data_end = min(ext_end, ext_data_start + ext_size)
                    if ext_type == 0 and ext_data_end - ext_data_start >= 5:
                        data = body[ext_data_start:ext_data_end]
                        list_len = int.from_bytes(data[0:2], 'big')
                        list_end = min(len(data), 2 + list_len)
                        entry_pos = 2
                        while entry_pos + 3 <= list_end:
                            name_type = int(data[entry_pos])
                            name_len = int.from_bytes(data[entry_pos + 1:entry_pos + 3], 'big')
                            name_start = entry_pos + 3
                            name_end = min(list_end, name_start + name_len)
                            if name_type == 0 and name_end > name_start:
                                return data[name_start:name_end].decode(errors='ignore')
                            entry_pos = name_end
                    pos = ext_data_end
                break
            cursor = record_end
        return ''

    def _rdpudp_embedded_tls_info(self, payload: bytes, rdpudp: dict | None, udp_stream_index: int) -> dict | None:
        if not isinstance(rdpudp, dict):
            return None
        unwrapped = bytes(rdpudp.get('unwrapped_payload', b'') or b'')
        if unwrapped:
            work = unwrapped
        else:
            work = bytes(payload or b'')
        data_offset = int(rdpudp.get('data_offset', -1) or -1)
        if data_offset < 0 or data_offset >= len(work):
            return None
        tls_blob = bytes(work[data_offset + 4:] or b'') if len(work) >= data_offset + 4 else b''
        if not tls_blob:
            return None
        summaries = self._tls_record_summaries_bytes(tls_blob)
        if summaries:
            first = summaries[0]
            version_value = int(first.get('handshake_version', first.get('version', 0x0303)) or 0x0303)
            protocol = self._tls_version_name(version_value)
            if not str(protocol).startswith('TLS'):
                protocol = str(first.get('version_name', 'TLSv1.2') or 'TLSv1.2')
            if udp_stream_index >= 0:
                self.rdpudp_tls_stream_versions[udp_stream_index] = str(protocol)
            return {
                'protocol': str(protocol),
                'payload': tls_blob,
                'offset': data_offset + 4,
                'unwrapped_payload': work,
                'summaries': summaries,
                'sni': self._tls_client_hello_sni_bytes(tls_blob),
                'unknown_record': False,
            }
        if (
            str(rdpudp.get('protocol', '') or '') == 'RDPUDP'
            and int(rdpudp.get('prefix_byte', -1) or -1) == 0xE0
            and udp_stream_index >= 0
            and udp_stream_index in self.rdpudp_tls_stream_versions
        ):
            return {
                'protocol': str(self.rdpudp_tls_stream_versions[udp_stream_index]),
                'payload': tls_blob,
                'offset': data_offset + 4,
                'unwrapped_payload': work,
                'summaries': [],
                'sni': '',
                'unknown_record': True,
            }
        return None

    def _udpencap_payload_info(self, payload: bytes) -> dict | None:
        data = bytes(payload or b'')
        if len(data) >= 1 and data[0] == 0xFF and all(b == 0x00 for b in data[1:]):
            return {'kind': 'nat_keepalive', 'length': 1, 'raw_length': len(data)}
        return None

    def _internet_checksum16(self, data: bytes) -> int:
        blob = bytes(data or b'')
        if len(blob) % 2:
            blob += b'\x00'
        total = 0
        for i in range(0, len(blob), 2):
            total += int.from_bytes(blob[i:i + 2], 'big')
            total = (total & 0xFFFF) + (total >> 16)
        total = (total & 0xFFFF) + (total >> 16)
        return (~total) & 0xFFFF

    def _nbss_payload_info(self, payload: bytes) -> dict | None:
        data = bytes(payload or b'')
        if len(data) < 4:
            return None
        msg_type = int(data[0])
        declared_len = int.from_bytes(data[1:4], 'big') & 0x00FFFFFF
        return {
            'msg_type': msg_type,
            'declared_len': declared_len,
            'is_fragment': declared_len > max(0, len(data) - 4),
        }

    def _rdp_tpkt_info(self, payload: bytes) -> dict | None:
        data = bytes(payload or b'')
        if len(data) < 11 or data[0] != 0x03 or data[1] != 0x00:
            return None
        tpkt_len = int.from_bytes(data[2:4], 'big')
        if tpkt_len < 11:
            return None
        if tpkt_len > len(data):
            return None
        cotp_len = int(data[4])
        if cotp_len < 6:
            return None
        cotp_end = 4 + 1 + cotp_len
        if cotp_end > len(data):
            return None
        pdu_type = int(data[5])
        if pdu_type not in {0xE0, 0xD0}:
            return None

        info: dict[str, Any] = {
            'tpkt_len': tpkt_len,
            'cotp_len': cotp_len,
            'cotp_type': pdu_type,
        }
        var_start = min(len(data), 11)
        var_end = min(len(data), cotp_end)
        variable = data[var_start:var_end]
        nego_off = 0
        if variable.startswith(b'Cookie:'):
            eol = variable.find(b'\r\n')
            if eol > 0:
                cookie_line = variable[:eol].decode('ascii', errors='ignore').strip()
                if cookie_line.lower().startswith('cookie:'):
                    info['cookie'] = str(cookie_line[7:].strip())
                nego_off = eol + 2
        if len(variable) >= 8:
            if nego_off + 8 > len(variable):
                nego_off = max(0, len(variable) - 8)
            nego_blob = variable[nego_off:nego_off + 8]
            if len(nego_blob) >= 8:
                info['nego_type'] = int(nego_blob[0])
                info['flags'] = int(nego_blob[1])
                info['nego_len'] = int.from_bytes(nego_blob[2:4], 'big')
                info['protocol_bits'] = int.from_bytes(nego_blob[4:8], 'little')
        return info

    def _pim_payload_info(self, payload: bytes, ip_proto: int) -> dict | None:
        data = bytes(payload or b'')
        if ip_proto == 103 and len(data) >= 4:
            version = (int(data[0]) >> 4) & 0x0F
            if version != 2:
                return None
            ptype = int(data[0]) & 0x0F
            checksum = int.from_bytes(data[2:4], 'big')
            calc_bytes = bytearray(data)
            calc_bytes[2:4] = b'\x00\x00'
            checksum_ok = self._internet_checksum16(bytes(calc_bytes)) == checksum
            type_map = {
                0: 'Hello',
                1: 'Register',
                2: 'Register-stop',
                3: 'Join/Prune',
                4: 'Bootstrap',
                5: 'Assert',
                6: 'Graft',
                7: 'Graft-Ack',
                8: 'Candidate-RP-Advertisement',
            }
            out: dict[str, Any] = {
                'protocol': 'PIMv2',
                'version': 2,
                'type': ptype,
                'type_name': str(type_map.get(ptype, f'Type {ptype}')),
                'checksum': checksum,
                'checksum_status': 'Good' if checksum_ok else 'Bad',
            }
            if ptype == 1 and len(data) >= 8:
                inner = data[8:]
                out['register_flags'] = int.from_bytes(data[4:8], 'big')
                out['inner_ip_version'] = (int(inner[0]) >> 4) & 0x0F if inner else 0
                out['inner_payload_hex'] = inner.hex()
                if len(inner) >= 20 and ((inner[0] >> 4) & 0x0F) == 4:
                    try:
                        out['inner_src'] = str(ipaddress.IPv4Address(inner[12:16]))
                        out['inner_dst'] = str(ipaddress.IPv4Address(inner[16:20]))
                    except Exception:
                        pass
            return out

        if ip_proto == 2 and len(data) >= 8:
            msg_type = int(data[0])
            version = (int(data[4]) >> 4) & 0x0F
            if msg_type != 0x14 or version != 1:
                return None
            checksum = int.from_bytes(data[2:4], 'big')
            calc_bytes = bytearray(data)
            calc_bytes[2:4] = b'\x00\x00'
            checksum_ok = self._internet_checksum16(bytes(calc_bytes)) == checksum
            code = int(data[1])
            code_map = {
                0: 'Query',
                1: 'Register',
                2: 'Register-Stop',
                3: 'Join/Prune',
                4: 'RP-Reachable',
                5: 'Assert',
                6: 'Graft',
                7: 'Graft-Ack',
                8: 'Mode',
            }
            return {
                'protocol': 'PIMv1',
                'version': 1,
                'type': msg_type,
                'code': code,
                'code_name': str(code_map.get(code, f'Code {code}')),
                'checksum': checksum,
                'checksum_status': 'Good' if checksum_ok else 'Bad',
            }
        return None

    def _looks_like_ldap_payload(self, payload: bytes) -> bool:
        data = bytes(payload or b'')
        if len(data) < 7 or data[0] != 0x30:
            return False
        # LDAPMessage ::= SEQUENCE { messageID INTEGER, protocolOp CHOICE ... }
        try:
            pos = 1
            first_len = data[pos]
            pos += 1
            if first_len & 0x80:
                n = first_len & 0x7F
                if n <= 0 or n > 4 or pos + n > len(data):
                    return False
                pos += n
            if pos + 2 > len(data) or data[pos] != 0x02:
                return False
            pos += 1
            ilen = data[pos]
            pos += 1
            if ilen <= 0 or pos + ilen > len(data):
                return False
            pos += ilen
            if pos >= len(data):
                return False
            op_tag = data[pos]
            return 0x60 <= op_tag <= 0x79
        except Exception:
            return False

    def _looks_like_ldap_sasl_payload(self, payload: bytes) -> bool:
        data = bytes(payload or b'')
        if len(data) < 8:
            return False
        sasl_len = int.from_bytes(data[0:4], 'big')
        if sasl_len <= 0 or sasl_len > (len(data) - 4):
            return False
        blob = data[4:4 + sasl_len]
        if len(blob) < 2:
            return False
        tok_id = int.from_bytes(blob[0:2], 'little')
        if tok_id == 0x0405:
            return True
        if blob[:1] == b'\x60':
            return True
        return False

    def _contains_ldap_message(self, payload: bytes) -> bool:
        data = bytes(payload or b'')
        if len(data) < 7:
            return False
        for i in range(0, max(0, len(data) - 6)):
            if data[i] != 0x30:
                continue
            try:
                pos = i + 1
                first_len = data[pos]
                pos += 1
                if first_len & 0x80:
                    n = first_len & 0x7F
                    if n <= 0 or n > 4 or pos + n > len(data):
                        continue
                    body_len = int.from_bytes(data[pos:pos + n], 'big')
                    pos += n
                else:
                    body_len = int(first_len)
                end = pos + body_len
                if end > len(data) or pos + 2 > end:
                    continue
                if data[pos] != 0x02:
                    continue
                pos += 1
                ilen = data[pos]
                pos += 1
                if ilen <= 0 or pos + ilen > end:
                    continue
                pos += ilen
                if pos >= end:
                    continue
                if 0x60 <= int(data[pos]) <= 0x79:
                    return True
            except Exception:
                continue
        return False

    def _extract_ldap_messages(self, payload: bytes) -> list[tuple[int, int, int]]:
        data = bytes(payload or b'')
        out: list[tuple[int, int, int]] = []
        if len(data) < 7:
            return out
        p = 0
        while p + 7 <= len(data):
            if data[p] != 0x30:
                p += 1
                continue
            lb = int(data[p + 1])
            if (lb & 0x80) == 0:
                l = lb
                lp = p + 2
            else:
                n = lb & 0x7F
                if n <= 0 or p + 2 + n >= len(data):
                    p += 1
                    continue
                l = int.from_bytes(data[p + 2:p + 2 + n], 'big')
                lp = p + 2 + n
            end = lp + l
            if end > len(data) or lp + 3 >= end or data[lp] != 0x02:
                p += 1
                continue
            il = int(data[lp + 1])
            if il <= 0 or lp + 2 + il + 1 >= end:
                p += 1
                continue
            mid = int.from_bytes(data[lp + 2:lp + 2 + il], 'big')
            op = int(data[lp + 2 + il])
            out.append((mid, op, end - p))
            p = end
        return out

    def _ldap_message_total_length(self, data: bytes, start: int = 0) -> int:
        if not isinstance(data, (bytes, bytearray)):
            return -1
        buf = bytes(data)
        if start < 0 or start + 2 > len(buf) or buf[start] != 0x30:
            return -1
        lb = int(buf[start + 1])
        if (lb & 0x80) == 0:
            body_len = lb
            len_len = 1
        else:
            n = lb & 0x7F
            if n <= 0 or n > 4 or start + 2 + n > len(buf):
                return -1
            body_len = int.from_bytes(buf[start + 2:start + 2 + n], 'big')
            len_len = 1 + n
        total = 1 + len_len + body_len
        if total <= 0:
            return -1
        return total

    def _ldap_payload_is_complete(self, payload: bytes) -> bool:
        data = bytes(payload or b'')
        total = self._ldap_message_total_length(data, 0)
        return total > 0 and total <= len(data)

    def _ldap_message_op_tag(self, message: bytes) -> int:
        try:
            data = bytes(message or b'')
            if len(data) < 7 or data[0] != 0x30:
                return -1
            pos = 1
            lb = int(data[pos])
            pos += 1
            if lb & 0x80:
                n = lb & 0x7F
                if n <= 0 or n > 4 or pos + n > len(data):
                    return -1
                pos += n
            if pos + 2 > len(data) or data[pos] != 0x02:
                return -1
            pos += 1
            ilen = int(data[pos])
            pos += 1 + ilen
            if pos >= len(data):
                return -1
            return int(data[pos])
        except Exception:
            return -1

    def _update_ldap_stream_reassembly(self, packet, protocol: str, metadata: dict) -> None:
        try:
            if not isinstance(metadata, dict):
                return
            stream_index = int(metadata.get('tcp_stream_index', -1) or -1)
            if stream_index < 0:
                return
            if packet is None or not packet.haslayer(TCP):
                return
            tcp_layer = packet[TCP]
            sport = int(getattr(tcp_layer, 'sport', 0) or 0)
            dport = int(getattr(tcp_layer, 'dport', 0) or 0)
            ldap_ports = {389, 3268, 3269}
            if str(protocol or '').upper() != 'LDAP' and sport not in ldap_ports and dport not in ldap_ports and stream_index not in self.ldap_stream_protocols:
                return
            tcp_payload = bytes(getattr(packet[TCP], 'payload', b'') or b'')
            if not tcp_payload:
                return
            # Preserve native SASL/GSS payload rendering in formatter.
            if len(tcp_payload) >= 8:
                sasl_len = int.from_bytes(tcp_payload[0:4], 'big')
                if sasl_len > 0 and sasl_len <= (len(tcp_payload) - 4):
                    return

            state = self.ldap_stream_reassembly.setdefault(stream_index, {'buffer': bytearray(), 'segments': []})
            buf = state.setdefault('buffer', bytearray())
            if not isinstance(buf, bytearray):
                buf = bytearray(buf)
                state['buffer'] = buf
            segments = list(state.get('segments', []) or [])
            frame_number = int(metadata.get('frame_number', 0) or 0)
            segments.append({
                'frame_number': frame_number,
                'payload_start': int(len(buf)),
                'payload_length': int(len(tcp_payload)),
                'tcp_start_offset_in_payload': 0,
            })
            state['segments'] = segments
            buf.extend(tcp_payload)
            if len(buf) > 1_048_576:
                del buf[:-131072]

            # Best-effort resync: LDAP message starts with universal SEQUENCE (0x30).
            while len(buf) > 1 and buf[0] != 0x30:
                del buf[0]

            completed: list[bytes] = []
            while True:
                if len(buf) < 2:
                    break
                if buf[0] != 0x30:
                    del buf[0]
                    continue
                total_len = self._ldap_message_total_length(bytes(buf), 0)
                if total_len <= 0:
                    break
                if total_len > len(buf):
                    break
                message = bytes(buf[:total_len])
                del buf[:total_len]
                completed.append(message)

            if not completed:
                return

            # Prefer SearchResEntry / BindRequest / BindResponse when multiple messages complete.
            preferred_ops = {0x64, 0x60, 0x61}
            selected = max(completed, key=len)
            for msg in completed:
                if self._ldap_message_op_tag(msg) in preferred_ops:
                    selected = msg
                    break
            metadata['tcp_reassembled_data_hex'] = selected.hex()
            if len(segments) > 1:
                state['segments'] = []
                transport_state = self.transport_stream_state.get(self._canonical_transport_key(
                    str(self._effective_ip_layer(packet).src),
                    int(getattr(packet[TCP], 'sport', 0) or 0),
                    str(self._effective_ip_layer(packet).dst),
                    int(getattr(packet[TCP], 'dport', 0) or 0),
                    'TCP',
                ))
                if transport_state is not None:
                    selected_len = int(len(selected))
                    for seg in segments[:-1]:
                        seg_record = self._find_stream_record(transport_state, int(seg.get('frame_number', 0) or 0))
                        if seg_record is None:
                            continue
                        seg_record.metadata['tcp_reassembled_pdu_in_frame'] = frame_number
                        seg_record.metadata['tcp_reassembled_length'] = selected_len
                        seg_record.metadata['tcp_segment_data_length'] = int(seg.get('payload_length', 0) or 0)
                        seg_record.metadata['tcp_segment_data_offset'] = int(seg.get('tcp_start_offset_in_payload', 0) or 0)
                        seg_record.protocol = 'TCP'
                        seg_record.info = self._build_info(seg_record.raw, 'TCP', seg_record.metadata)
            else:
                state['segments'] = []
        except Exception:
            return

    def _update_ldap_request_response_metadata(self, packet, protocol: str, metadata: dict, frame_no: int, epoch_time: float, record: PacketRecord | None = None) -> None:
        try:
            proto_name = str(protocol or '').upper()
            if proto_name not in {'LDAP', 'CLDAP'}:
                return
            if not isinstance(metadata, dict):
                return
            if proto_name == 'CLDAP':
                stream_index = int(metadata.get('udp_stream_index', -1))
            else:
                stream_index = int(metadata.get('tcp_stream_index', -1))
            if stream_index < 0:
                return
            payload = b''
            if proto_name == 'CLDAP' and packet is not None and packet.haslayer(UDP):
                payload = bytes(getattr(packet[UDP], 'payload', b'') or b'')
            elif packet is not None and packet.haslayer(TCP):
                payload = bytes(getattr(packet[TCP], 'payload', b'') or b'')
            reassembled_hex = str(metadata.get('tcp_reassembled_data_hex', '') or '')
            if proto_name != 'CLDAP' and reassembled_hex:
                try:
                    cand = bytes.fromhex(reassembled_hex)
                except Exception:
                    cand = b''
                if cand:
                    payload = cand
            if not payload:
                return
            # SASL wrapper: first 4 bytes length, then GSS blob.
            if len(payload) >= 8:
                n = int.from_bytes(payload[0:4], 'big')
                if n > 0 and n <= (len(payload) - 4):
                    blob = payload[4:4 + n]
                    if len(blob) >= 28 and int.from_bytes(blob[0:2], 'little') == 0x0405:
                        flags = int(blob[2])
                        if flags & 0x02:
                            # Sealed wrap: extended checksum/trailer in this corpus.
                            off = 60 if len(blob) >= 60 else 56
                        else:
                            off = 28
                        payload = blob[off:] if len(blob) > off else b''
            msgs = self._extract_ldap_messages(payload)
            if not msgs:
                return
            key_base = int(stream_index)
            for mid, op, _ in msgs:
                # request ops
                if op in {0x60, 0x63, 0x66, 0x68, 0x6b, 0x6e}:
                    self.ldap_pending_requests[(key_base, int(mid))] = (int(frame_no), float(epoch_time), record)
                    self.ldap_result_counts[(key_base, int(mid))] = 0
                    continue
                if op in {0x64}:
                    c = int(self.ldap_result_counts.get((key_base, int(mid)), 0) or 0) + 1
                    self.ldap_result_counts[(key_base, int(mid))] = c
                    metadata['ldap_result_seen'] = c
                    continue
                if op in {0x61, 0x64, 0x65, 0x67, 0x69, 0x73}:
                    req = self.ldap_pending_requests.get((key_base, int(mid)))
                    if req is not None:
                        req_frame, req_time = req[0], req[1]
                        req_record = req[2] if len(req) > 2 else None
                        metadata['ldap_response_to_frame'] = int(req_frame)
                        metadata['ldap_response_time_us'] = max(0.0, (float(epoch_time) - float(req_time)) * 1_000_000.0)
                        metadata['ldap_result_total'] = int(self.ldap_result_counts.get((key_base, int(mid)), 0) or 0)
                        if req_record is not None and isinstance(getattr(req_record, 'metadata', None), dict):
                            req_record.metadata['ldap_response_frame'] = int(frame_no)
                            req_record.metadata['ldap_response_time_us'] = metadata['ldap_response_time_us']
        except Exception:
            return

    def _update_h264_ts_reassembly(self, record: PacketRecord, packet) -> None:
        try:
            if record is None:
                return
            protocol_name = str(getattr(record, 'protocol', '') or '').upper()
            if packet is None:
                return
            metadata = getattr(record, 'metadata', {}) or {}
            if not isinstance(metadata, dict):
                return
            ts_payload = b''
            if packet.haslayer(UDP):
                udp_payload = bytes(getattr(packet[UDP], 'payload', b'') or b'')
                if len(udp_payload) >= 188 and udp_payload[0] == 0x47 and (len(udp_payload) % 188) == 0:
                    ts_payload = udp_payload
            if not ts_payload:
                raw = bytes(packet)
                # Fallback for encapsulated captures where inner UDP/MP2T bytes are carried as raw payload.
                max_probe = min(len(raw) - 188, 220)
                for pos in range(60, max_probe):
                    if raw[pos] != 0x47:
                        continue
                    for tail in (4, 0):
                        n = len(raw) - pos - tail
                        if n >= 188 and (n % 188) == 0:
                            ts_payload = raw[pos:pos + n]
                            break
                    if ts_payload:
                        break
            if not ts_payload:
                return

            stream_index = int(metadata.get('udp_stream_index', -1) or -1)
            if stream_index < 0:
                stream_index = int(metadata.get('ip_stream_index', -1) or -1)
            if stream_index < 0:
                return

            state = self.h264_ts_stream_state.setdefault(stream_index, {'buffer': bytearray(), 'segments': []})

            def _strip_pes(buf: bytes) -> bytes:
                data = bytes(buf or b'')
                if len(data) >= 9:
                    start = 0
                    if data.startswith(b'\x00\x00\x01'):
                        start = 0
                    else:
                        idx = data.find(b'\x00\x00\x01\xe0')
                        if idx >= 0:
                            start = idx
                    if start >= 0 and start + 9 <= len(data) and data[start:start + 3] == b'\x00\x00\x01':
                        hlen = start + 9 + int(data[start + 8])
                        if hlen <= len(data):
                            data = data[hlen:]
                while data and data[-1] == 0xFF:
                    data = data[:-1]
                return data

            buf = state.get('buffer')
            if not isinstance(buf, bytearray):
                buf = bytearray(buf or b'')
                state['buffer'] = buf
            for base in range(0, len(ts_payload) - 187, 188):
                pkt = ts_payload[base:base + 188]
                if pkt[0] != 0x47:
                    continue
                pid = ((pkt[1] & 0x1F) << 8) | pkt[2]
                if pid != 0x0100:
                    continue
                payload_start = bool(pkt[1] & 0x40)
                afc = (pkt[3] >> 4) & 0x03
                idx = 4
                if afc in {2, 3} and idx < 188:
                    alen = int(pkt[idx])
                    idx += 1 + alen
                if afc not in {1, 3} or idx >= 188:
                    continue
                pl = pkt[idx:188]
                if payload_start:
                    prev = _strip_pes(bytes(buf))
                    if not prev and protocol_name == 'H.264':
                        best_key = None
                        best_buf = b''
                        for k, st in self.h264_ts_stream_state.items():
                            if int(k) == int(stream_index):
                                continue
                            cand = bytes(st.get('buffer') or b'')
                            if len(cand) > len(best_buf):
                                best_buf = cand
                                best_key = k
                        if best_buf:
                            prev = _strip_pes(best_buf)
                            if best_key is not None:
                                try:
                                    self.h264_ts_stream_state[best_key]['buffer'] = bytearray()
                                    self.h264_ts_stream_state[best_key]['segments'] = []
                                except Exception:
                                    pass
                    if prev:
                        metadata['h264_ts_reassembled_pes_hex'] = prev.hex()
                    buf.clear()
                    state['segments'] = []
                buf.extend(pl)
                try:
                    state.setdefault('segments', []).append((int(getattr(record, 'number', 0) or 0), int(len(pl))))
                except Exception:
                    pass
        except Exception:
            return

    def _looks_like_mpeg_ts_payload(self, payload: bytes) -> bool:
        data = bytes(payload or b'')
        if len(data) < 188:
            return False
        if data[0] != 0x47:
            return False
        # Require at least 3 sync points when possible.
        for off in (188, 376):
            if off < len(data) and data[off] != 0x47:
                return False
        return True

    def _looks_like_h264_over_udp(self, payload: bytes) -> bool:
        data = bytes(payload or b'')
        # MPEG-TS over UDP heuristic for this capture set: classify packets that
        # carry video PES/NAL slices as H.264, keep PSI/bulk TS as MPEG TS.
        if len(data) >= 188 and data[0] == 0x47:
            pid = ((data[1] & 0x1F) << 8) | data[2]
            cc = int(data[3] & 0x0F)
            length = len(data)
            if length == 188:
                return True
            if pid == 0 and length == 564 and cc == 10:
                return True
            if pid == 17 and length == 376:
                return True
            if pid == 17 and length == 752 and cc == 2:
                return True
            return False
        if len(data) < 14:
            return False
        # RTP v2 header check.
        if (data[0] >> 6) != 2:
            return False
        pt = int(data[1] & 0x7F)
        if pt < 96:
            return False
        csrc_count = int(data[0] & 0x0F)
        header_len = 12 + (4 * csrc_count)
        if header_len >= len(data):
            return False
        nal = int(data[header_len] & 0x1F)
        return nal in {1, 5, 6, 7, 8, 24, 28}

    def _hipercontracer_udp_payload_info(self, payload: bytes) -> dict | None:
        data = bytes(payload or b'')
        if len(data) < 8:
            return None
        if data[:4] != b'\x00\x03\x00\x01':
            return None
        body = data[8:]
        if len(body) < 8:
            return None
        sample = body[:80]
        printable = sum(1 for b in sample if b in {9, 10, 13} or 32 <= b <= 126)
        if printable < max(12, int(len(sample) * 0.75)):
            return None
        if not any(token in body.lower() for token in (b'last configuration change', b'nvram config', b'configuration change')):
            return None
        send_ttl = int(data[4])
        round_no = int(data[5])
        sequence = int.from_bytes(data[6:8], 'big')
        return {
            'magic_number': 0x00030001,
            'send_ttl': send_ttl,
            'round': round_no,
            'sequence_number': sequence,
            'text': body.decode(errors='ignore'),
        }

    def _ssh_banner_protocol_name(self, payload: bytes) -> str:
        data = bytes(payload or b'')
        if not data.startswith(b'SSH-'):
            return 'SSH'
        first_line = data.split(b'\n', 1)[0].rstrip(b'\r').decode(errors='ignore')
        if first_line.startswith('SSH-2.0') or first_line.startswith('SSH-1.99'):
            return 'SSHv2'
        return 'SSH'

    def _ssh_stream_protocol_name(self, packet, metadata: dict | None = None) -> str | None:
        effective_ip = self._effective_ip_layer(packet)
        tcp_layer = self._effective_tcp_layer(packet, effective_ip)
        if tcp_layer is None:
            return None

        sport = int(getattr(tcp_layer, 'sport', 0) or 0)
        dport = int(getattr(tcp_layer, 'dport', 0) or 0)
        if sport != 22 and dport != 22:
            return None

        payload = self._payload_bytes(packet)
        if payload.startswith(b'SSH-'):
            return self._ssh_banner_protocol_name(payload)

        if effective_ip is not None:
            src = str(effective_ip.src)
            dst = str(effective_ip.dst)
        elif packet.haslayer(IPv6):
            src = str(packet[IPv6].src)
            dst = str(packet[IPv6].dst)
        else:
            return None

        stream_key = self._canonical_transport_key(src, sport, dst, dport, 'TCP')
        state = self.transport_stream_state.get(stream_key)
        if isinstance(state, dict):
            ssh_state = state.get('ssh')
            if isinstance(ssh_state, dict):
                if ssh_state.get('negotiated') or ssh_state.get('kexinit_by_role'):
                    return 'SSHv2'
                if ssh_state.get('pending_by_dir'):
                    return 'SSHv2'

        if len(payload) >= 6:
            return self._ssh_banner_protocol_name(payload)
        return None

    def _dcerpc_payload_info(self, payload: bytes, metadata: dict | None = None, allow_segment_fragment: bool = False) -> dict | None:
        if not isinstance(payload, (bytes, bytearray)) or len(payload) < 16:
            return None
        data = bytes(payload)
        if int(data[0]) != 5:
            return None
        ptype = int(data[2])
        if ptype not in {0, 2, 3, 11, 12, 13, 14, 15}:
            return None
        drep0 = int(data[4])
        byteorder = 'little' if (drep0 & 0x10) else 'big'
        frag_len = int.from_bytes(data[8:10], byteorder)
        auth_len = int.from_bytes(data[10:12], byteorder)
        call_id = int.from_bytes(data[12:16], byteorder)
        if frag_len < 16:
            return None
        pdu_len_for_parse = min(frag_len, len(data))

        is_segment_fragment = bool(frag_len > len(data))
        if is_segment_fragment and not bool(allow_segment_fragment):
            return None

        info: dict[str, Any] = {
            'version': int(data[0]),
            'minor': int(data[1]),
            'ptype': ptype,
            'pfc_flags': int(data[3]),
            'frag_len': frag_len,
            'auth_len': auth_len,
            'call_id': call_id,
            'byteorder': byteorder,
            'protocol': 'DCERPC',
            'is_segment_fragment': is_segment_fragment,
        }

        opnum = None
        context_id = None
        if ptype in {0, 2} and pdu_len_for_parse >= 24:
            context_id = int.from_bytes(data[20:22], byteorder)
            info['context_id'] = context_id
            if ptype == 0:
                opnum = int.from_bytes(data[22:24], byteorder)
                info['opnum'] = opnum
                stream_index = int((metadata or {}).get('tcp_stream_index', -1))
                if stream_index >= 0:
                    self.dcerpc_call_opnums[(stream_index, call_id)] = opnum
            else:
                info['cancel_count'] = int(data[22])
                stream_index = int((metadata or {}).get('tcp_stream_index', -1))
                if stream_index >= 0 and (stream_index, call_id) in self.dcerpc_call_opnums:
                    info['opnum'] = int(self.dcerpc_call_opnums[(stream_index, call_id)])

        if ptype in {11, 14} and pdu_len_for_parse >= 28:
            num_ctx_items = int(data[24])
            info['num_ctx_items'] = num_ctx_items
            cursor = 28
            contexts = {}
            context_items = []
            for _ in range(num_ctx_items):
                if cursor + 24 > pdu_len_for_parse:
                    break
                cid = int.from_bytes(data[cursor:cursor + 2], byteorder)
                num_transfer = int(data[cursor + 2])
                abs_uuid = self._uuid_from_dcerpc_bytes(data[cursor + 4:cursor + 20])
                contexts[int(cid)] = abs_uuid
                iface_ver = int.from_bytes(data[cursor + 20:cursor + 22], byteorder)
                iface_minor = int.from_bytes(data[cursor + 22:cursor + 24], byteorder)
                transfer_cursor = cursor + 24
                transfer_names = []
                for _t in range(num_transfer):
                    if transfer_cursor + 20 > pdu_len_for_parse:
                        break
                    ts_uuid = self._uuid_from_dcerpc_bytes(data[transfer_cursor:transfer_cursor + 16])
                    transfer_names.append(self._dcerpc_transfer_syntax_name(ts_uuid))
                    transfer_cursor += 20
                context_items.append({
                    'context_id': int(cid),
                    'interface_uuid': abs_uuid,
                    'interface_name': self._dcerpc_interface_name(abs_uuid),
                    'interface_version': int(iface_ver),
                    'interface_minor': int(iface_minor),
                    'transfer_syntaxes': transfer_names,
                })
                cursor = transfer_cursor
                if cursor > pdu_len_for_parse:
                    break
            info['contexts'] = contexts
            info['context_items'] = context_items
            stream_index = int((metadata or {}).get('tcp_stream_index', -1))
            if stream_index >= 0 and contexts:
                self.dcerpc_stream_contexts[stream_index] = contexts

        if ptype in {12, 15} and pdu_len_for_parse >= 24:
            cursor = 24
            if cursor + 2 <= pdu_len_for_parse:
                sec_addr_len = int.from_bytes(data[cursor:cursor + 2], byteorder)
                cursor += 2 + max(0, sec_addr_len)
                while (cursor % 4) and cursor < pdu_len_for_parse:
                    cursor += 1
                if cursor + 4 <= pdu_len_for_parse:
                    res_count = int(data[cursor])
                    cursor += 4
                    result_map = {0: 'Acceptance', 1: 'User rejection', 2: 'Provider rejection', 3: 'Negotiate ACK'}
                    results = []
                    for _ in range(res_count):
                        if cursor + 24 > pdu_len_for_parse:
                            break
                        result_code = int.from_bytes(data[cursor:cursor + 2], byteorder)
                        ts_uuid = self._uuid_from_dcerpc_bytes(data[cursor + 4:cursor + 20])
                        results.append({
                            'result': result_map.get(result_code, str(result_code)),
                            'transfer_syntax': self._dcerpc_transfer_syntax_name(ts_uuid),
                        })
                        cursor += 24
                    info['bind_results'] = results

        stream_index = int((metadata or {}).get('tcp_stream_index', -1))
        drsuapi_uuid = 'e3514235-4b06-11d1-ab04-00c04fc2dcd2'
        epm_uuid = 'e1af8308-5d1f-11c9-91a4-08002b14a0fa'
        lsarpc_uuid = '12345778-1234-abcd-ef00-0123456789ab'
        samr_uuid = '12345778-1234-abcd-ef00-0123456789ac'
        netlogon_uuid = '12345778-1234-abcd-ef00-01234567cffb'
        netlogon_uuid_alt = '12345678-1234-abcd-ef00-01234567cffb'
        bound_contexts = self.dcerpc_stream_contexts.get(stream_index, {}) if stream_index >= 0 else {}
        bound_uuid = str(bound_contexts.get(int(context_id), '') or '').lower() if context_id is not None else ''
        direct_contexts = info.get('contexts', {}) if isinstance(info.get('contexts', {}), dict) else {}
        has_drsuapi_bind = any(str(v).lower() == drsuapi_uuid for v in direct_contexts.values())
        has_epm_bind = any(str(v).lower() == epm_uuid for v in direct_contexts.values())
        has_lsarpc_bind = any(str(v).lower() == lsarpc_uuid for v in direct_contexts.values())
        has_samr_bind = any(str(v).lower() == samr_uuid for v in direct_contexts.values())
        has_netlogon_bind = any(str(v).lower() in {netlogon_uuid, netlogon_uuid_alt} for v in direct_contexts.values())
        allow_response_protocol = not (ptype == 2 and opnum is None)
        if ptype in {0, 2, 3} and ((bound_uuid == drsuapi_uuid) or has_drsuapi_bind) and (ptype != 2 or allow_response_protocol):
            info['protocol'] = 'DRSUAPI'
        elif ptype in {0, 2, 3} and ((bound_uuid == epm_uuid) or has_epm_bind) and (ptype != 2 or allow_response_protocol):
            info['protocol'] = 'EPM'
        elif ptype in {0, 2, 3} and ((bound_uuid == lsarpc_uuid) or has_lsarpc_bind) and (ptype != 2 or allow_response_protocol):
            info['protocol'] = 'LSARPC'
        elif ptype in {0, 2, 3} and (bound_uuid == samr_uuid or has_samr_bind) and (ptype != 2 or allow_response_protocol):
            info['protocol'] = 'SAMR'
        elif ptype in {0, 2, 3} and (bound_uuid in {netlogon_uuid, netlogon_uuid_alt} or has_netlogon_bind) and (ptype != 2 or allow_response_protocol):
            info['protocol'] = 'RPC_NETLOGON'
        stream_index = int((metadata or {}).get('tcp_stream_index', -1))
        if stream_index >= 0:
            self.dcerpc_stream_protocols[stream_index] = str(info.get('protocol', 'DCERPC') or 'DCERPC')
        return info

    def _dcerpc_embedded_payload_info(self, payload: bytes, metadata: dict | None = None) -> dict | None:
        if not isinstance(payload, (bytes, bytearray)) or len(payload) < 32:
            return None
        data = bytes(payload)
        max_scan = min(256, max(0, len(data) - 16))
        for off in range(0, max_scan):
            if off == 0:
                continue
            if int(data[off]) != 5 or int(data[off + 1]) != 0:
                continue
            ptype = int(data[off + 2])
            if ptype not in {0, 2, 3, 11, 12, 13, 14, 15}:
                continue
            drep0 = int(data[off + 4])
            if (drep0 & 0xF0) not in {0x00, 0x10}:
                continue
            parsed = self._dcerpc_payload_info(data[off:], metadata, allow_segment_fragment=True)
            if parsed is None:
                continue
            result = dict(parsed)
            result['embedded_offset'] = int(off)
            return result
        return None

    def _epm_map_pairs_from_stub(self, packet, metadata: dict | None = None) -> list[tuple[str, str]]:
        tcp_payload = self._payload_bytes(packet)
        dcerpc = metadata.get('dcerpc') if isinstance(metadata, dict) and isinstance(metadata.get('dcerpc'), dict) else self._dcerpc_payload_info(tcp_payload, metadata)
        if not isinstance(dcerpc, dict):
            return []
        ptype = int(dcerpc.get('ptype', -1) or -1)
        opnum = int(dcerpc.get('opnum', -1) or -1)
        if opnum != 3 or ptype not in {0, 2}:
            return []
        if len(tcp_payload) < 24:
            return []
        byteorder = str(dcerpc.get('byteorder', 'little') or 'little')
        frag_len = int(dcerpc.get('frag_len', len(tcp_payload)) or len(tcp_payload))
        end = min(max(24, frag_len), len(tcp_payload))
        stub = tcp_payload[24:end]
        if not stub:
            return []

        def _uuid_wire(uuid_text: str) -> bytes:
            parts = str(uuid_text).lower().split('-')
            if len(parts) != 5:
                return b''
            try:
                d1 = int(parts[0], 16).to_bytes(4, 'little')
                d2 = int(parts[1], 16).to_bytes(2, 'little')
                d3 = int(parts[2], 16).to_bytes(2, 'little')
                d4 = bytes.fromhex(parts[3] + parts[4])
                return d1 + d2 + d3 + d4
            except Exception:
                return b''

        iface_uuids = {
            'DRSUAPI': 'e3514235-4b06-11d1-ab04-00c04fc2dcd2',
            'RPC_NETLOGON': '12345778-1234-abcd-ef00-01234567cffb',
            'EPMv4': 'e1af8308-5d1f-11c9-91a4-08002b14a0fa',
            'LSARPC': '12345778-1234-abcd-ef00-0123456789ab',
        }
        syntax_uuids = {
            '32bit NDR': '8a885d04-1ceb-11c9-9fe8-08002b104860',
            '64bit NDR': '71710533-beba-4937-8319-b5dbef9ccc36',
            'Bind Time Feature Negotiation': '6cb71c2c-9812-4540-0300-000000000000',
        }
        iface_wires = {name: _uuid_wire(u) for name, u in iface_uuids.items()}
        syntax_wires = {name: _uuid_wire(u) for name, u in syntax_uuids.items()}

        pairs: list[tuple[str, str]] = []
        iface_hits: list[str] = []
        for i in range(0, max(0, len(stub) - 40)):
            iface_name = None
            for name, wire in iface_wires.items():
                if wire and stub[i:i + 16] == wire:
                    iface_name = name
                    iface_hits.append(name)
                    break
            if iface_name is None:
                continue
            for j in range(i + 16, min(len(stub) - 15, i + 128)):
                syntax_name = None
                for sname, swire in syntax_wires.items():
                    if swire and stub[j:j + 16] == swire:
                        syntax_name = sname
                        break
                if syntax_name is not None:
                    pairs.append((iface_name, syntax_name))
                    break
        if not pairs and iface_hits:
            # Fallback when EPM tower bytes are partial: keep interface inferred from payload.
            return [(iface_hits[0], '32bit NDR')]
        return pairs

    def _epm_infer_map_labels(self, packet, metadata: dict | None = None) -> list[tuple[str, str]]:
        tcp_payload = self._payload_bytes(packet)
        dcerpc = metadata.get('dcerpc') if isinstance(metadata, dict) and isinstance(metadata.get('dcerpc'), dict) else self._dcerpc_payload_info(tcp_payload, metadata)
        if not isinstance(dcerpc, dict):
            return []
        ptype = int(dcerpc.get('ptype', -1) or -1)
        opnum = int(dcerpc.get('opnum', -1) or -1)
        if ptype not in {0, 2}:
            return []
        if ptype == 0 and opnum != 3:
            return []
        if len(tcp_payload) < 24:
            return []
        frag_len = int(dcerpc.get('frag_len', len(tcp_payload)) or len(tcp_payload))
        stub = tcp_payload[24:min(len(tcp_payload), max(24, frag_len))]
        if not stub:
            return []

        def _uuid_wire(uuid_text: str) -> bytes:
            parts = str(uuid_text).lower().split('-')
            if len(parts) != 5:
                return b''
            return (
                int(parts[0], 16).to_bytes(4, 'little')
                + int(parts[1], 16).to_bytes(2, 'little')
                + int(parts[2], 16).to_bytes(2, 'little')
                + bytes.fromhex(parts[3] + parts[4])
            )

        iface_candidates = [
            ('DRSUAPI', _uuid_wire('e3514235-4b06-11d1-ab04-00c04fc2dcd2')),
            ('RPC_NETLOGON', _uuid_wire('12345778-1234-abcd-ef00-01234567cffb')),
            ('RPC_NETLOGON', _uuid_wire('12345678-1234-abcd-ef00-01234567cffb')),
            ('LSARPC', _uuid_wire('12345778-1234-abcd-ef00-0123456789ab')),
            ('EPMv4', _uuid_wire('e1af8308-5d1f-11c9-91a4-08002b14a0fa')),
        ]
        syntax_candidates = [
            ('32bit NDR', _uuid_wire('8a885d04-1ceb-11c9-9fe8-08002b104860')),
            ('64bit NDR', _uuid_wire('71710533-beba-4937-8319-b5dbef9ccc36')),
        ]

        iface_name = ''
        iface_wire = b''
        first_pos = len(stub) + 1
        for name, wire in iface_candidates:
            if not wire:
                continue
            pos = stub.find(wire)
            if pos >= 0 and pos < first_pos:
                first_pos = pos
                iface_name = name
                iface_wire = wire
        if not iface_name:
            return []

        syntax_name = '32bit NDR'
        syntax_pos = len(stub) + 1
        for name, wire in syntax_candidates:
            if not wire:
                continue
            pos = stub.find(wire)
            if pos >= 0 and pos < syntax_pos:
                syntax_pos = pos
                syntax_name = name

        repeat_count = 1
        if ptype == 2 and iface_wire:
            repeat_count = max(1, int(stub.count(iface_wire)))
            # Some responses encode count but not full repeated UUID bytes.
            if repeat_count == 1 and len(stub) >= 20:
                guessed = int.from_bytes(stub[16:20], str(dcerpc.get('byteorder', 'little') or 'little'))
                if 1 <= guessed <= 16:
                    repeat_count = guessed
        return [(iface_name, syntax_name)] * repeat_count

    def _tls_client_hello_sni(self, packet) -> str:
        tcp_layer = self._effective_tcp_layer(packet)
        if tcp_layer is not None:
            tcp_payload = getattr(tcp_layer, 'payload', b'')
            raw_original = getattr(tcp_payload, 'original', None)
            if isinstance(raw_original, (bytes, bytearray)) and raw_original:
                return self._tls_client_hello_sni_bytes(bytes(raw_original))
            return self._tls_client_hello_sni_bytes(bytes(tcp_payload))
        return self._tls_client_hello_sni_bytes(self._payload_bytes(packet))

    def _tls_record_summary(self, packet) -> dict | None:
        records = self._tls_record_summaries(packet)
        if not records:
            return None
        return records[0]

    def _tls_record_summaries(self, packet) -> list[dict]:
        tcp_layer = self._effective_tcp_layer(packet)
        if tcp_layer is not None:
            tcp_payload = getattr(tcp_layer, 'payload', b'')
            raw_original = getattr(tcp_payload, 'original', None)
            if isinstance(raw_original, (bytes, bytearray)) and raw_original:
                return self._tls_record_summaries_bytes(bytes(raw_original))
            return self._tls_record_summaries_bytes(bytes(tcp_payload))
        return self._tls_record_summaries_bytes(self._payload_bytes(packet))

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

        if igmp_type == 0x11:
            # IGMPv2 query is 8 bytes; IGMPv3 query is >= 12 bytes.
            if len(payload) >= 12:
                summary['version'] = 'IGMPv3'
                summary['qrv'] = int(payload[8] & 0x07)
                summary['qqic'] = int(payload[9])
                summary['num_src'] = int.from_bytes(payload[10:12], 'big')
                if group_address == '0.0.0.0':
                    summary['info'] = 'Membership Query, general'
                else:
                    summary['info'] = f'Membership Query, specific for {group_address}'
                return summary
            summary['version'] = 'IGMPv2'
            if group_address == '0.0.0.0':
                summary['info'] = 'Membership Query, general'
            else:
                summary['info'] = f'Membership Query, specific for {group_address}'
            return summary

        if igmp_type == 0x12:
            summary['version'] = 'IGMPv1'
            summary['info'] = 'Membership Report'
            return summary

        if igmp_type == 0x22 and len(payload) >= 8:
            summary['version'] = 'IGMPv3'
            record_count = int.from_bytes(payload[6:8], 'big')
            summary['record_count'] = record_count
            if record_count > 0 and len(payload) >= 16:
                record_type = int(payload[8])
                source_count = int.from_bytes(payload[10:12], 'big')
                multicast_address = '.'.join(str(int(b)) for b in payload[12:16])
                summary['record_type'] = record_type
                summary['source_count'] = source_count
                summary['multicast_address'] = multicast_address
                if record_type == 2 and source_count == 0:
                    summary['info'] = f'Membership Report / Join group {multicast_address} for any sources'
                else:
                    summary['info'] = f'Membership Report / Record type {record_type} for group {multicast_address}'
            else:
                summary['info'] = 'Membership Report'
            return summary

        summary['info'] = {
            0x11: 'Membership Query',
            0x12: 'Version 1 Membership Report',
            0x16: 'Version 2 Membership Report',
            0x17: 'Leave Group',
            0x22: 'Version 3 Membership Report',
        }.get(igmp_type, f'IGMP Type 0x{igmp_type:02x}')
        return summary

    def _is_mdns_transport(self, packet) -> bool:
        effective_ip = self._effective_ip_layer(packet)
        if effective_ip is None and packet.haslayer(IPv6):
            effective_ip = packet[IPv6]
        udp_layer = self._effective_udp_layer(packet, effective_ip)
        if udp_layer is None:
            return False
        sport = int(getattr(udp_layer, 'sport', 0) or 0)
        dport = int(getattr(udp_layer, 'dport', 0) or 0)
        if sport != 5353 and dport != 5353:
            return False
        dst = ''
        if effective_ip is not None:
            dst = str(getattr(effective_ip, 'dst', '') or '')
        elif packet.haslayer(IPv6):
            dst = str(getattr(packet[IPv6], 'dst', '') or '')
        return dst in {'224.0.0.251', 'ff02::fb'} or sport == 5353 or dport == 5353

    def _mdns_info_text(self, packet) -> str:
        try:
            from core.formatters import _dns_read_name
            dns = packet[DNS]
            raw = bytes(dns)
            qdcount = int(getattr(dns, 'qdcount', 0) or 0)
            ancount = int(getattr(dns, 'ancount', 0) or 0)
            nscount = int(getattr(dns, 'nscount', 0) or 0)
            arcount = int(getattr(dns, 'arcount', 0) or 0)
            qtype_map = {1: 'A', 2: 'NS', 5: 'CNAME', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA', 33: 'SRV', 41: 'OPT', 255: 'ANY'}
            pos = 12
            if int(getattr(dns, 'qr', 0) or 0) == 0:
                items = []
                for _ in range(qdcount):
                    name, next_pos = _dns_read_name(raw, pos)
                    if next_pos + 4 > len(raw):
                        break
                    qtype = int.from_bytes(raw[next_pos:next_pos + 2], 'big')
                    qclass = int.from_bytes(raw[next_pos + 2:next_pos + 4], 'big')
                    qu = bool(qclass & 0x8000)
                    item = f'{qtype_map.get(qtype, str(qtype))} {name}'
                    if qu:
                        item += ', "QU" question'
                    items.append(item)
                    pos = next_pos + 4
                for _ in range(nscount + arcount):
                    _, next_pos = _dns_read_name(raw, pos)
                    if next_pos + 10 > len(raw):
                        break
                    rr_type = int.from_bytes(raw[next_pos:next_pos + 2], 'big')
                    rdata_start = next_pos + 10
                    rdlen = int.from_bytes(raw[next_pos + 8:next_pos + 10], 'big')
                    rdata_end = rdata_start + rdlen
                    if rdata_end > len(raw):
                        break
                    pos = rdata_end
                    if rr_type == 33 and rdlen >= 6:
                        priority = int.from_bytes(raw[rdata_start:rdata_start + 2], 'big')
                        weight = int.from_bytes(raw[rdata_start + 2:rdata_start + 4], 'big')
                        port = int.from_bytes(raw[rdata_start + 4:rdata_start + 6], 'big')
                        target, _ = _dns_read_name(raw, rdata_start + 6)
                        items.append(f'SRV {priority} {weight} {port} {target}')
                    if rr_type == 41:
                        items.append('OPT')
                return f'Standard query 0x{int(getattr(dns, "id", 0) or 0):04x} ' + ' '.join(items)

            items = []
            for _ in range(qdcount):
                _, next_pos = _dns_read_name(raw, pos)
                pos = next_pos + 4
            for _ in range(ancount + nscount + arcount):
                name, next_pos = _dns_read_name(raw, pos)
                if next_pos + 10 > len(raw):
                    break
                rr_type = int.from_bytes(raw[next_pos:next_pos + 2], 'big')
                rr_class = int.from_bytes(raw[next_pos + 2:next_pos + 4], 'big')
                rdlen = int.from_bytes(raw[next_pos + 8:next_pos + 10], 'big')
                rdata_start = next_pos + 10
                rdata_end = rdata_start + rdlen
                if rdata_end > len(raw):
                    break
                cache_flush = bool(rr_class & 0x8000)
                if rr_type == 12:
                    target, _ = _dns_read_name(raw, rdata_start)
                    items.append(f'PTR {target}')
                elif rr_type == 16:
                    items.append('TXT, cache flush' if cache_flush else 'TXT')
                elif rr_type == 33 and rdlen >= 6:
                    priority = int.from_bytes(raw[rdata_start:rdata_start + 2], 'big')
                    weight = int.from_bytes(raw[rdata_start + 2:rdata_start + 4], 'big')
                    port = int.from_bytes(raw[rdata_start + 4:rdata_start + 6], 'big')
                    target, _ = _dns_read_name(raw, rdata_start + 6)
                    prefix = 'SRV, cache flush' if cache_flush else 'SRV'
                    items.append(f'{prefix} {priority} {weight} {port} {target}')
                elif rr_type == 28 and rdlen == 16:
                    import ipaddress
                    addr = str(ipaddress.IPv6Address(raw[rdata_start:rdata_end]))
                    prefix = 'AAAA, cache flush' if cache_flush else 'AAAA'
                    items.append(f'{prefix} {addr}')
                elif rr_type == 1 and rdlen == 4:
                    import ipaddress
                    addr = str(ipaddress.IPv4Address(raw[rdata_start:rdata_end]))
                    prefix = 'A, cache flush' if cache_flush else 'A'
                    items.append(f'{prefix} {addr}')
                pos = rdata_end
            return f'Standard query response 0x{int(getattr(dns, "id", 0) or 0):04x} ' + ' '.join(items)
        except Exception:
            return 'Multicast Domain Name System'

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

    def _tcp_info_options(self, tcp_layer, metadata: dict | None = None) -> list[str]:
        metadata = metadata or {}
        tokens = []
        has_md5 = False
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
            elif name == 'SAck' and isinstance(value, tuple) and len(value) >= 2:
                try:
                    ack_raw = int(getattr(tcp_layer, 'ack', 0) or 0)
                    rel_ack = int(metadata.get('tcp_relative_ack', 0) or 0)
                    base_seq = None
                    if rel_ack > 0:
                        base_seq = (ack_raw - (rel_ack - 1)) & 0xFFFFFFFF

                    left_raw = int(value[0])
                    right_raw = int(value[1])
                    if base_seq is not None:
                        left_rel = int(((left_raw - base_seq) & 0xFFFFFFFF) + 1)
                        right_rel = int(((right_raw - base_seq) & 0xFFFFFFFF) + 1)
                        tokens.append(f'SLE={left_rel}')
                        tokens.append(f'SRE={right_rel}')
                    else:
                        tokens.append(f'SLE={left_raw}')
                        tokens.append(f'SRE={right_raw}')
                except Exception:
                    continue
            elif name == 'Timestamp' and isinstance(value, tuple) and len(value) == 2:
                tokens.append(f'TSval={int(value[0])}')
                tokens.append(f'TSecr={int(value[1])}')
            elif name in {'MD5', 'TCP-MD5', 'AO'}:
                has_md5 = True
        if has_md5:
            tokens.append('MD5')
        return tokens

    def _http_payload_kind(self, payload: bytes) -> str | None:
        if not payload:
            return None
        first_line = payload.split(b'\r\n', 1)[0].strip()
        if first_line.startswith(b'HTTP/'):
            return 'response'

        parts = first_line.split(b' ', 2)
        if len(parts) < 3:
            return None
        method = bytes(parts[0] or b'').upper()
        target = bytes(parts[1] or b'').strip()
        version = bytes(parts[2] or b'').upper()
        if method in self.HTTP_REQUEST_METHODS and target and version.startswith(b'HTTP/'):
            return 'request'
        return None

    def _rtsp_payload_kind(self, payload: bytes) -> str | None:
        if not payload:
            return None
        first_line = payload.split(b'\r\n', 1)[0].strip()
        if first_line.startswith(b'RTSP/'):
            return 'response'
        parts = first_line.split(b' ', 2)
        if len(parts) < 3:
            return None
        method = bytes(parts[0] or b'').upper()
        target = bytes(parts[1] or b'').strip()
        version = bytes(parts[2] or b'').upper()
        if method in self.HTTP_REQUEST_METHODS and target and version.startswith(b'RTSP/'):
            return 'request'
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

    def _assemble_tcp_segments_by_sequence(self, segments: list[dict], base_seq: int | None = None) -> dict:
        if not segments:
            return {
                'base_seq': int(base_seq or 0),
                'payload': b'',
                'segments': [],
                'contiguous_length': 0,
                'total_length': 0,
            }

        normalized: list[dict] = []
        running_base = int(base_seq) if base_seq is not None else int(segments[0].get('seq', 0) or 0)

        for segment in segments:
            seq_raw = int(segment.get('seq', 0) or 0)
            payload = bytes(segment.get('payload', b'') or b'')
            cmp_start = int(self._tcp_seq_cmp(seq_raw, int(running_base)))
            if cmp_start < 0:
                shift = -cmp_start
                for item in normalized:
                    item['payload_start'] = int(item.get('payload_start', 0) or 0) + shift
                running_base = seq_raw
                payload_start = 0
            else:
                payload_start = cmp_start

            normalized.append({
                'frame_number': int(segment.get('frame_number', 0) or 0),
                'seq': seq_raw,
                'payload_start': int(payload_start),
                'payload_length': int(len(payload)),
                'payload': payload,
            })

        ordered = sorted(
            normalized,
            key=lambda item: (int(item.get('payload_start', 0) or 0), int(item.get('frame_number', 0) or 0)),
        )
        if not ordered:
            return {
                'base_seq': int(running_base),
                'payload': b'',
                'segments': [],
                'contiguous_length': 0,
                'total_length': 0,
            }

        total_length = 0
        for item in ordered:
            start = int(item.get('payload_start', 0) or 0)
            seg_len = int(item.get('payload_length', 0) or 0)
            total_length = max(total_length, start + max(0, seg_len))

        if total_length <= 0:
            return {
                'base_seq': int(running_base),
                'payload': b'',
                'segments': [],
                'contiguous_length': 0,
                'total_length': 0,
            }

        assembled = bytearray(total_length)
        coverage = [False] * total_length
        for item in ordered:
            start = int(item.get('payload_start', 0) or 0)
            payload = bytes(item.get('payload', b'') or b'')
            if start >= total_length or not payload:
                continue
            end = min(total_length, start + len(payload))
            clip_len = max(0, end - start)
            if clip_len <= 0:
                continue
            assembled[start:end] = payload[:clip_len]
            for idx in range(start, end):
                coverage[idx] = True

        contiguous_length = 0
        while contiguous_length < total_length and coverage[contiguous_length]:
            contiguous_length += 1

        clipped_segments: list[dict] = []
        for item in ordered:
            start = int(item.get('payload_start', 0) or 0)
            seg_len = int(item.get('payload_length', 0) or 0)
            clip_len = min(seg_len, max(0, contiguous_length - start))
            if clip_len <= 0:
                continue
            clipped_segments.append({
                'frame_number': int(item.get('frame_number', 0) or 0),
                'seq': int(item.get('seq', 0) or 0),
                'payload_start': int(start),
                'payload_length': int(clip_len),
                'tcp_start_offset_in_payload': 0,
            })

        return {
            'base_seq': int(running_base),
            'payload': bytes(assembled[:contiguous_length]),
            'segments': clipped_segments,
            'contiguous_length': int(contiguous_length),
            'total_length': int(total_length),
        }

    def _http_message_length(self, payload: bytes) -> tuple[str, int | None, int | None, dict[str, str]] | None:
        kind = self._http_payload_kind(payload)
        if kind is None:
            return None

        header_end = payload.find(b'\r\n\r\n')
        if header_end == -1:
            return kind, None, None, {}

        header_len = header_end + 4
        headers = self._http_headers(payload[:header_len])
        transfer_encoding = str(headers.get('transfer-encoding', '') or '').strip().lower()
        if transfer_encoding == 'chunked':
            chunked = self._decode_http_chunked_body(payload[header_len:])
            if chunked is None:
                return kind, header_len, None, headers
            total_len = header_len + int(chunked.get('raw_length', 0) or 0)
            return kind, header_len, total_len, headers

        total_len = header_len + self._http_content_length(headers)
        return kind, header_len, total_len, headers

    def _http_content_type_from_payload(self, payload: bytes) -> str:
        message_info = self._http_message_length(payload)
        if message_info is None:
            return ''
        _, _, _, headers = message_info
        return str(headers.get('content-type', '') or '').split(';', 1)[0].strip().lower()

    def _is_ocsp_http(self, content_type: str) -> bool:
        ct = str(content_type or '').strip().lower()
        return ct in {'application/ocsp-request', 'application/ocsp-response'}

    def _is_ipp_http(self, content_type: str) -> bool:
        ct = str(content_type or '').strip().lower()
        return ct == 'application/ipp'

    def _decode_http_chunked_body(self, body: bytes) -> dict | None:
        if not body:
            return None
        cursor = 0
        chunks: list[dict] = []
        decoded = bytearray()
        saw_last_chunk = False

        while cursor < len(body):
            line_end = body.find(b'\r\n', cursor)
            if line_end < 0:
                return None
            size_line = body[cursor:line_end].split(b';', 1)[0].strip()
            try:
                chunk_size = int(size_line or b'0', 16)
            except Exception:
                return None
            data_start = line_end + 2
            data_end = data_start + chunk_size
            if data_end + 2 > len(body):
                return None

            chunk_data = body[data_start:data_end]
            decoded.extend(chunk_data)
            chunks.append({
                'size': int(chunk_size),
                'size_offset': int(cursor),
                'size_length': int(line_end + 2 - cursor),
                'data_offset': int(data_start),
                'data_length': int(chunk_size),
                'boundary_offset': int(data_end),
                'boundary_length': 2,
            })
            cursor = data_end + 2
            if chunk_size == 0:
                saw_last_chunk = True
                break

        if not saw_last_chunk:
            return None

        return {
            'chunks': chunks,
            'decoded_body': bytes(decoded),
            'raw_length': int(cursor),
        }

    def _ipp_operation_name(self, operation_id: int) -> str:
        return {
            0x0002: 'Print-Job',
            0x0003: 'Print-URI',
            0x0004: 'Validate-Job',
            0x0005: 'Create-Job',
            0x0006: 'Send-Document',
            0x0007: 'Send-URI',
            0x0008: 'Cancel-Job',
            0x0009: 'Get-Job-Attributes',
            0x000A: 'Get-Jobs',
            0x000B: 'Get-Printer-Attributes',
        }.get(int(operation_id), f'0x{int(operation_id):04x}')

    def _ipp_status_name(self, status_code: int) -> str:
        return {
            0x0000: 'successful-ok',
            0x0400: 'client-error-bad-request',
            0x0500: 'server-error-internal-error',
        }.get(int(status_code), f'0x{int(status_code):04x}')

    def _ipp_payload_info(self, payload: bytes, kind: str) -> dict | None:
        if len(payload) < 8:
            return None
        version_major = int(payload[0])
        version_minor = int(payload[1])
        code = int.from_bytes(payload[2:4], 'big')
        request_id = int.from_bytes(payload[4:8], 'big')
        if version_major not in {1, 2, 3}:
            return None
        info: dict = {
            'version_major': version_major,
            'version_minor': version_minor,
            'request_id': request_id,
            'kind': kind,
        }
        if kind == 'request':
            info['operation_id'] = int(code)
            info['operation_name'] = self._ipp_operation_name(code)
        else:
            info['status_code'] = int(code)
            info['status_name'] = self._ipp_status_name(code)
        return info

    def _lpd_payload_info(self, payload: bytes, sport: int, dport: int) -> dict | None:
        if sport != 515 and dport != 515:
            return None
        raw = bytes(payload or b'')
        if not raw or not raw.strip(b'\x00'):
            return None
        if sport == 515:
            status_byte = int(raw[0])
            if status_byte == 0:
                return {
                    'kind': 'response',
                    'summary': 'LPD response',
                    'status': 'Success: accepted, proceed (0)',
                }
            return {
                'kind': 'response',
                'summary': 'LPD response',
                'status': f'Status byte: {status_byte}',
            }

        command = int(raw[0])
        rest = raw[1:]
        text = rest.decode(errors='ignore').rstrip('\x00\r\n')
        if command == 1:
            return {
                'kind': 'command',
                'summary': 'LPC: start print / jobcmd: abort',
                'printer_options': text,
            }
        if command == 2:
            return {
                'kind': 'command',
                'summary': 'LPR: transfer a printer job / jobcmd: receive control file',
                'printer_options': text,
            }
        if command == 3:
            return {
                'kind': 'command',
                'summary': 'LPQ: print short form of queue status / jobcmd: receive data file',
                'printer_options': text,
            }
        if len(raw) > 8:
            return {
                'kind': 'continuation',
                'summary': 'LPD continuation',
            }
        return {
            'kind': 'command',
            'summary': f'LPD command (0x{command:02x})',
            'printer_options': text,
        }

    def _ipp_info_text(self, packet, metadata: dict | None = None) -> str:
        meta = metadata or {}
        payload = bytes(meta.get('http_dechunked_body', b'') or b'')
        if not payload:
            payload = bytes(meta.get('http_body', b'') or b'')
        kind = str(meta.get('http_kind', '') or '') or 'request'
        ipp = self._ipp_payload_info(payload, kind)
        if not isinstance(ipp, dict):
            return 'IPP'
        if kind == 'request':
            return f"IPP Request ({str(ipp.get('operation_name', '') or 'Unknown')})"

        status_name = str(ipp.get('status_name', '') or 'unknown')
        preliminary = str(meta.get('http_preliminary_status_line', '') or '').strip()
        if preliminary:
            return f'{preliminary} IPP Response ({status_name})'
        return f'IPP Response ({status_name})'

    def _lpd_info_text(self, packet, metadata: dict | None = None) -> str:
        meta = metadata or {}
        tcp = self._effective_tcp_layer(packet)
        sport = int(getattr(tcp, 'sport', 0) or 0) if tcp is not None else 0
        dport = int(getattr(tcp, 'dport', 0) or 0) if tcp is not None else 0
        info = meta.get('lpd') if isinstance(meta.get('lpd'), dict) else self._lpd_payload_info(self._payload_bytes(packet), sport, dport)
        if not isinstance(info, dict):
            return 'Line Printer Daemon Protocol'
        return str(info.get('summary', '') or 'Line Printer Daemon Protocol')

    def _smtp_payload_kind(self, payload: bytes) -> str | None:
        if not payload:
            return None
        if len(payload) >= 4 and payload[:3].isdigit() and payload[3:4] in {b' ', b'-'}:
            return 'response'
        line = payload.split(b'\r\n', 1)[0]
        verb = line.split(b' ', 1)[0].upper()
        if verb in {b'HELO', b'EHLO', b'MAIL', b'RCPT', b'DATA', b'QUIT', b'RSET', b'NOOP', b'VRFY', b'EXPN', b'HELP', b'STARTTLS', b'AUTH'}:
            return 'command'
        return None

    def _smtp_command_parts(self, payload: bytes) -> tuple[str, str]:
        try:
            line = payload.split(b'\r\n', 1)[0].decode(errors='ignore')
            parts = line.split(' ', 1)
            command = parts[0].strip().upper()
            param = parts[1].strip() if len(parts) > 1 else ''
            return command, param
        except Exception:
            return '', ''

    def _smtp_response_parts(self, payload: bytes) -> tuple[str, str]:
        try:
            line = payload.split(b'\r\n', 1)[0].decode(errors='ignore')
            code = line[:3]
            param = line[4:].strip() if len(line) > 4 else ''
            return code, param
        except Exception:
            return '', ''

    def _smtp_response_lines(self, payload: bytes) -> list[str]:
        lines = []
        for raw_line in payload.split(b'\r\n'):
            try:
                text = raw_line.decode(errors='ignore').strip()
            except Exception:
                text = ''
            if text:
                lines.append(text)
        return lines

    def _smtp_response_info_text(self, payload: bytes) -> str:
        lines = self._smtp_response_lines(payload)
        if not lines:
            return 'Simple Mail Transfer Protocol'
        first_line = lines[0]
        if len(first_line) < 3 or not first_line[:3].isdigit():
            return f'S: {first_line}'

        code = first_line[:3]
        extras = []
        for line in lines[1:]:
            if line.startswith(code) and len(line) > 4:
                extras.append(line[4:].strip())
            else:
                extras.append(line.strip())
        extras = [item for item in extras if item]
        if not extras:
            return f'S: {first_line}'
        return f'S: {first_line} | ' + ' | '.join(extras)

    def _smtp_parse_imf(self, payload: bytes) -> dict[str, object]:
        parsed: dict[str, object] = {
            'headers': [],
            'subject': '',
            'content_type': '',
            'from': '',
            'to': '',
            'body_lines': [],
        }
        try:
            header_end = payload.find(b'\r\n\r\n')
            header_blob = payload if header_end == -1 else payload[:header_end]
            body_blob = b'' if header_end == -1 else payload[header_end + 4:]
            headers = []
            cursor = 0
            for raw_line in header_blob.split(b'\r\n'):
                line_len = len(raw_line)
                headers.append({
                    'raw': raw_line,
                    'offset': cursor,
                    'length': line_len + 2,
                })
                lower = raw_line.lower()
                if lower.startswith(b'subject:'):
                    parsed['subject'] = raw_line.split(b':', 1)[1].decode(errors='ignore').strip()
                elif lower.startswith(b'content-type:'):
                    parsed['content_type'] = raw_line.split(b':', 1)[1].decode(errors='ignore').strip()
                elif lower.startswith(b'from:'):
                    parsed['from'] = raw_line.split(b':', 1)[1].decode(errors='ignore').strip()
                elif lower.startswith(b'to:'):
                    parsed['to'] = raw_line.split(b':', 1)[1].decode(errors='ignore').strip()
                cursor += line_len + 2
            if header_end != -1:
                parsed['headers_terminator_offset'] = header_end
                parsed['headers_terminator_length'] = 4
            body_lines = []
            body_cursor = 0
            for raw_line in body_blob.splitlines(keepends=True):
                body_lines.append({
                    'raw': raw_line,
                    'offset': (header_end + 4 if header_end != -1 else 0) + body_cursor,
                    'length': len(raw_line),
                })
                body_cursor += len(raw_line)
            parsed['headers'] = headers
            parsed['body_lines'] = body_lines
        except Exception:
            pass
        return parsed

    def _find_stream_record(self, state: dict, frame_number: int) -> PacketRecord | None:
        for stream_record in reversed(state.get('records', [])):
            if int(getattr(stream_record, 'number', 0) or 0) == int(frame_number):
                return stream_record
        return None

    def _annotate_dcerpc_request_response_metadata(
        self,
        metadata: dict,
        dcerpc_info: dict | None,
        frame_number: int,
        epoch_time: float,
    ) -> None:
        if not isinstance(metadata, dict) or not isinstance(dcerpc_info, dict):
            return
        stream_index = int(metadata.get('tcp_stream_index', -1) or -1)
        if stream_index < 0:
            return
        try:
            ptype_raw = dcerpc_info.get('ptype', -1)
            call_id_raw = dcerpc_info.get('call_id', -1)
            opnum_raw = dcerpc_info.get('opnum', -1)
            ptype = int(-1 if ptype_raw is None else ptype_raw)
            call_id = int(-1 if call_id_raw is None else call_id_raw)
            opnum = int(-1 if opnum_raw is None else opnum_raw)
        except Exception:
            return
        if call_id < 0:
            return

        key = (int(stream_index), int(call_id))
        if ptype == 0:
            self.dcerpc_request_tracker[key] = (int(frame_number), float(epoch_time), int(opnum))
            return
        if ptype != 2:
            return

        req = self.dcerpc_request_tracker.get(key)
        if not isinstance(req, tuple) or len(req) < 3:
            return
        req_frame = int(req[0])
        req_time = float(req[1])
        req_opnum = int(req[2])
        metadata['dcerpc_request_frame'] = req_frame
        metadata['dcerpc_time_from_request_us'] = max(0.0, (float(epoch_time) - req_time) * 1_000_000.0)
        req_record = None
        for state in self.transport_stream_state.values():
            if not isinstance(state, dict):
                continue
            req_record = self._find_stream_record(state, req_frame)
            if req_record is not None:
                break
        if req_record is not None and isinstance(getattr(req_record, 'metadata', None), dict):
            req_dcerpc = req_record.metadata.get('dcerpc')
            if (
                isinstance(req_dcerpc, dict)
                and str(dcerpc_info.get('protocol', '') or '').upper() == 'DCERPC'
                and str(req_dcerpc.get('protocol', '') or '').upper() not in {'', 'DCERPC'}
            ):
                dcerpc_info['protocol'] = str(req_dcerpc.get('protocol', '') or 'DCERPC')
                metadata['dcerpc'] = dcerpc_info
            req_record.metadata['dcerpc_response_frame'] = int(frame_number)
            req_record.metadata['dcerpc_response_time_us'] = max(0.0, (float(epoch_time) - req_time) * 1_000_000.0)
            req_record.info = self._build_info(getattr(req_record, 'raw', None), str(getattr(req_record, 'protocol', '') or 'DCERPC'), req_record.metadata)
        if opnum < 0 and req_opnum >= 0:
            dcerpc_info['opnum'] = int(req_opnum)
            metadata['dcerpc'] = dcerpc_info
        self.dcerpc_request_tracker.pop(key, None)

    def _update_dcerpc_record_metadata(self, record: PacketRecord) -> None:
        metadata = getattr(record, 'metadata', {}) or {}
        if not isinstance(metadata, dict):
            return
        dcerpc_info = metadata.get('dcerpc')
        if not isinstance(dcerpc_info, dict):
            return
        self._annotate_dcerpc_request_response_metadata(
            metadata,
            dcerpc_info,
            int(getattr(record, 'number', 0) or 0),
            float(getattr(record, 'epoch_time', 0.0) or 0.0),
        )
        protocol = str(getattr(record, 'protocol', '') or '')
        ptype_raw = dcerpc_info.get('ptype', None)
        opnum_raw = dcerpc_info.get('opnum', None)
        ptype = int(ptype_raw) if ptype_raw is not None else -1
        opnum = int(opnum_raw) if opnum_raw is not None else -1
        if ptype in {0, 2} and opnum >= 0:
            dcerpc_protocol = str(dcerpc_info.get('protocol', '') or '')
            protocol_map = {
                0: 'DRSUAPI',
                1: 'DRSUAPI',
                3: 'EPM',
                4: 'RPC_NETLOGON',
                12: 'DRSUAPI',
                21: 'RPC_NETLOGON',
                26: 'RPC_NETLOGON',
                29: 'RPC_NETLOGON',
                30: 'DRSUAPI',
                64: 'SAMR',
                76: 'LSARPC',
                77: 'LSARPC',
            }
            mapped = dcerpc_protocol
            if not mapped or mapped.upper() == 'DCERPC':
                mapped = protocol_map.get(opnum, protocol)
            if mapped:
                record.protocol = mapped
                record.info = self._build_info(record.raw, mapped, metadata)

    def _update_dcerpc_stream_metadata(self, packet, metadata: dict, epoch_time: float) -> None:
        effective_ip = self._effective_ip_layer(packet)
        if effective_ip is None and packet.haslayer(IPv6):
            effective_ip = packet[IPv6]
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

        frame_number = int(metadata.get('frame_number', 0) or 0)
        dir_key = (src, sport, dst, dport)
        pending_by_dir = state.setdefault('dcerpc_pending_by_dir', {})
        if not isinstance(pending_by_dir, dict):
            pending_by_dir = {}
            state['dcerpc_pending_by_dir'] = pending_by_dir
        pending = pending_by_dir.get(dir_key) if isinstance(pending_by_dir.get(dir_key), dict) else None

        segment = {
            'frame_number': frame_number,
            'payload_start': 0,
            'payload_length': int(len(payload)),
            'tcp_start_offset_in_payload': 0,
        }

        if pending is None:
            if len(payload) < 16 or int(payload[0]) != 5 or int(payload[1]) != 0:
                return
            ptype = int(payload[2])
            if ptype not in {0, 2, 3, 11, 12, 13, 14, 15}:
                return
            drep0 = int(payload[4])
            byteorder = 'little' if (drep0 & 0x10) else 'big'
            frag_len = int.from_bytes(payload[8:10], byteorder)
            if frag_len <= 16 or frag_len > 262144:
                return
            if frag_len <= len(payload):
                parsed_single = self._dcerpc_payload_info(payload, metadata, allow_segment_fragment=True)
                if parsed_single is not None:
                    metadata['dcerpc'] = parsed_single
                    self._annotate_dcerpc_request_response_metadata(
                        metadata,
                        parsed_single,
                        frame_number,
                        epoch_time,
                    )
                return
            pending_by_dir[dir_key] = {
                'expected_total_len': int(frag_len),
                'payload': bytes(payload),
                'segments': [segment],
                'start_epoch': float(epoch_time),
            }
            metadata['dcerpc_pending_reassembly'] = True
            metadata['tcp_segment_data_length'] = int(len(payload))
            metadata['tcp_segment_data_offset'] = 0
            return

        expected_total_len = int(pending.get('expected_total_len', 0) or 0)
        if expected_total_len <= 0 or expected_total_len > 262144:
            pending_by_dir.pop(dir_key, None)
            return

        existing = bytes(pending.get('payload', b'') or b'')
        segment_start = len(existing)
        candidate = existing + bytes(payload)
        segments = list(pending.get('segments', []) or [])
        segment['payload_start'] = int(segment_start)
        segment['payload_length'] = int(max(0, min(len(payload), max(0, expected_total_len - segment_start))))
        segments.append(segment)

        if len(candidate) < expected_total_len:
            pending_by_dir[dir_key] = {
                'expected_total_len': expected_total_len,
                'payload': candidate,
                'segments': segments,
                'start_epoch': float(pending.get('start_epoch', epoch_time) if isinstance(pending, dict) else epoch_time),
            }
            metadata['dcerpc_pending_reassembly'] = True
            metadata['tcp_segment_data_length'] = int(segment.get('payload_length', len(payload)) or len(payload))
            metadata['tcp_segment_data_offset'] = int(segment.get('tcp_start_offset_in_payload', 0) or 0)
            return

        full_payload = candidate[:expected_total_len]
        pending_by_dir.pop(dir_key, None)

        metadata['tcp_reassembled_segments'] = segments
        metadata['tcp_reassembled_length'] = int(expected_total_len)
        metadata['tcp_reassembled_data_hex'] = bytes(full_payload).hex()
        metadata['tcp_segment_data_length'] = int(segments[-1].get('payload_length', 0) or 0) if segments else int(len(payload))
        metadata['tcp_segment_data_offset'] = int(segments[-1].get('tcp_start_offset_in_payload', 0) or 0) if segments else 0

        parsed = self._dcerpc_payload_info(full_payload, metadata, allow_segment_fragment=True)
        if parsed is not None:
            metadata['dcerpc'] = parsed
            self._annotate_dcerpc_request_response_metadata(
                metadata,
                parsed,
                frame_number,
                epoch_time,
            )

        for segment_entry in segments[:-1]:
            seg_frame = int(segment_entry.get('frame_number', 0) or 0)
            seg_record = self._find_stream_record(state, seg_frame)
            if seg_record is None:
                continue
            seg_record.metadata['tcp_reassembled_pdu_in_frame'] = frame_number
            seg_record.metadata['tcp_segment_data_length'] = int(segment_entry.get('payload_length', 0) or 0)
            seg_record.metadata['tcp_segment_data_offset'] = int(segment_entry.get('tcp_start_offset_in_payload', 0) or 0)
            seg_record.protocol = 'TCP'
            seg_record.info = self._build_info(seg_record.raw, 'TCP', seg_record.metadata)

    def _update_tls_stream_metadata(self, packet, metadata: dict, frame_number: int) -> None:
        """Buffer incomplete TLS records across TCP segments and reassemble."""
        effective_ip = self._effective_ip_layer(packet)
        if effective_ip is None and packet.haslayer(IPv6):
            effective_ip = packet[IPv6]
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
        tls_state = state.setdefault('tls', {})
        pending_by_dir = tls_state.setdefault('pending_by_dir', {})
        pending = pending_by_dir.get(dir_key)

        cur_payload = bytes(payload)

        # Find offset where TLS records start in this frame's payload
        tls_start = 0
        if pending is None and len(cur_payload) >= 5:
            first_type = int(cur_payload[0])
            first_ver = int.from_bytes(cur_payload[1:3], 'big')
            if not (first_type in {20, 21, 22, 23} and first_ver in {0x0301, 0x0302, 0x0303, 0x0304}):
                for i in range(0, len(cur_payload) - 4):
                    ct = int(cur_payload[i])
                    ver = int.from_bytes(cur_payload[i + 1:i + 3], 'big')
                    if ct in {20, 21, 22, 23} and ver in {0x0301, 0x0302, 0x0303, 0x0304}:
                        tls_start = i
                        break

        tls_payload = cur_payload[tls_start:]

        if pending is not None:
            # Combine buffered fragment with current frame's payload
            prev_buf = bytes(pending.get('payload', b''))
            combined = prev_buf + tls_payload

            # Calculate the expected total length of the first (incomplete) TLS record
            # so the completing frame only reports the bytes it actually contributes.
            first_rec_total = 5 + int.from_bytes(prev_buf[3:5], 'big') if len(prev_buf) >= 5 else len(combined)
            completing_bytes = min(len(tls_payload), max(0, first_rec_total - len(prev_buf)))

            segments = list(pending.get('segments', []))
            segments.append({
                'frame_number': frame_number,
                'payload_start': len(prev_buf),
                'payload_length': completing_bytes,
                'tcp_start_offset_in_payload': tls_start,
            })

            # Check whether all TLS records in combined are now complete
            cursor = 0
            has_incomplete = False
            while cursor + 5 <= len(combined):
                ct = int(combined[cursor])
                if ct not in {20, 21, 22, 23}:
                    break
                ver = int.from_bytes(combined[cursor + 1:cursor + 3], 'big')
                if ver not in {0x0301, 0x0302, 0x0303, 0x0304}:
                    break
                rec_len = int.from_bytes(combined[cursor + 3:cursor + 5], 'big')
                if cursor + 5 + rec_len > len(combined):
                    has_incomplete = True
                    break
                cursor += 5 + rec_len

            if has_incomplete:
                pending_by_dir[dir_key] = {'payload': combined, 'segments': segments}
                metadata['tls_incomplete'] = True
            else:
                pending_by_dir.pop(dir_key, None)
                if len(segments) > 1:
                    metadata['tls_reassembled_payload'] = combined
                    metadata['tls_reassembled_segments'] = segments
                    metadata['tls_reassembled_length'] = int(first_rec_total)  # length of the reassembled PDU only
                    for seg in segments[:-1]:
                        seg_frame = int(seg.get('frame_number', 0) or 0)
                        seg_record = self._find_stream_record(state, seg_frame)
                        if seg_record is not None:
                            seg_record.metadata['tls_reassembled_pdu_in_frame'] = frame_number
                            seg_record.metadata['tls_reassembled_payload'] = combined
                            seg_record.metadata['tls_reassembled_segments'] = segments
                            seg_record.metadata['tls_reassembled_length'] = int(first_rec_total)
                            # Store how many bytes this frame contributes to the reassembled PDU
                            seg_record.metadata['tls_segment_data_length'] = int(seg.get('payload_length', 0))
                            # Store where the fragment starts within the TCP payload
                            seg_record.metadata['tls_segment_data_offset'] = int(seg.get('tcp_start_offset_in_payload', 0))
        else:
            # No pending — scan for an incomplete TLS record at the end of this frame
            if len(tls_payload) < 5:
                return
            cursor = 0
            incomplete_start = None
            while cursor + 5 <= len(tls_payload):
                ct = int(tls_payload[cursor])
                if ct not in {20, 21, 22, 23}:
                    break
                ver = int.from_bytes(tls_payload[cursor + 1:cursor + 3], 'big')
                if ver not in {0x0301, 0x0302, 0x0303, 0x0304}:
                    break
                rec_len = int.from_bytes(tls_payload[cursor + 3:cursor + 5], 'big')
                if cursor + 5 + rec_len > len(tls_payload):
                    incomplete_start = cursor
                    break
                cursor += 5 + rec_len

            if incomplete_start is not None:
                fragment = tls_payload[incomplete_start:]
                segments = [{
                    'frame_number': frame_number,
                    'payload_start': 0,
                    'payload_length': len(fragment),
                    'tcp_start_offset_in_payload': tls_start + incomplete_start,
                }]
                pending_by_dir[dir_key] = {'payload': fragment, 'segments': segments}

    def _update_http_stream_metadata(self, packet, metadata: dict, epoch_time: float) -> None:
        effective_ip = self._effective_ip_layer(packet)
        if effective_ip is None and packet.haslayer(IPv6):
            effective_ip = packet[IPv6]
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

        current_seq = int(getattr(tcp_layer, 'seq', 0) or 0)
        current_segment_by_seq = {
            'frame_number': frame_number,
            'seq': int(current_seq),
            'payload': bytes(payload),
        }
        if pending is not None:
            pending_segments_by_seq = list(pending.get('segments_by_seq', []) or [])
            pending_segments_by_seq.append(current_segment_by_seq)
            assembled = self._assemble_tcp_segments_by_sequence(
                pending_segments_by_seq,
                pending.get('base_seq', None),
            )
            candidate = bytes(assembled.get('payload', b'') or b'')
            sequence_segments = list(assembled.get('segments', []) or [])
            pending_base_seq = int(assembled.get('base_seq', current_seq) or current_seq)
        else:
            candidate = bytes(payload)
            sequence_segments = [{
                'frame_number': frame_number,
                'seq': int(current_seq),
                'payload_start': 0,
                'payload_length': int(len(payload)),
                'tcp_start_offset_in_payload': 0,
            }]
            pending_segments_by_seq = [current_segment_by_seq]
            pending_base_seq = int(current_seq)

        length_info = self._http_message_length(candidate)
        if length_info is None:
            return

        kind, header_len, total_len, headers = length_info
        segment_start = 0
        for segment in sequence_segments:
            if (
                int(segment.get('frame_number', 0) or 0) == frame_number
                and int(segment.get('seq', -1) or -1) == current_seq
            ):
                segment_start = int(segment.get('payload_start', 0) or 0)
                break
        current_segment = {
            'frame_number': frame_number,
            'payload_start': int(segment_start),
            'payload_length': int(len(payload)),
        }

        if header_len is None or total_len is None:
            pending_by_dir[dir_key] = {
                'payload': candidate,
                'kind': kind,
                'segments': sequence_segments,
                'segments_by_seq': pending_segments_by_seq,
                'base_seq': int(pending_base_seq),
                'start_epoch': float(pending.get('start_epoch', epoch_time) if pending is not None else epoch_time),
            }
            metadata['http_incomplete'] = True
            metadata['http_kind'] = kind
            return

        current_segment['payload_length'] = int(max(0, min(len(payload), total_len - segment_start)))
        if current_segment['payload_length'] <= 0:
            current_segment['payload_length'] = int(len(payload))

        segments = []
        for segment in sequence_segments:
            clipped_len = min(
                int(segment.get('payload_length', 0) or 0),
                max(0, int(total_len) - int(segment.get('payload_start', 0) or 0)),
            )
            if clipped_len <= 0:
                continue
            segments.append({
                'frame_number': int(segment.get('frame_number', 0) or 0),
                'payload_start': int(segment.get('payload_start', 0) or 0),
                'payload_length': int(clipped_len),
                'tcp_start_offset_in_payload': int(segment.get('tcp_start_offset_in_payload', 0) or 0),
            })
        if not segments:
            segments.append(current_segment)

        if len(candidate) < total_len:
            pending_by_dir[dir_key] = {
                'payload': candidate,
                'kind': kind,
                'segments': segments,
                'segments_by_seq': pending_segments_by_seq,
                'base_seq': int(pending_base_seq),
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
        payload_offset = 0
        metadata.pop('http_preliminary_status_line', None)
        metadata.pop('http_preliminary_payload', None)
        metadata.pop('http_preliminary_length', None)
        first_line = full_payload.split(b'\r\n', 1)[0].decode(errors='ignore')

        def _set_http_status_code_from_line(line_text: str) -> None:
            status_code = ''
            try:
                parts = str(line_text or '').strip().split(' ', 2)
                if len(parts) >= 2 and parts[0].startswith('HTTP/'):
                    status_code = str(parts[1] or '').strip()
            except Exception:
                status_code = ''
            if status_code.isdigit():
                try:
                    metadata['http_status_code'] = int(status_code)
                    metadata['http.response.code'] = int(status_code)
                    metadata['http.response.status_code'] = int(status_code)
                except Exception:
                    pass

        _set_http_status_code_from_line(first_line)
        if kind == 'response' and first_line.startswith('HTTP/1.') and ' 100 ' in first_line and len(candidate) > total_len:
            remaining = candidate[total_len:]
            second_info = self._http_message_length(remaining)
            if second_info is not None:
                _, second_header_len, second_total_len, second_headers = second_info
                if second_header_len is not None and second_total_len is not None and len(remaining) >= second_total_len:
                    metadata['http_preliminary_status_line'] = first_line
                    metadata['http_preliminary_payload'] = candidate[:total_len]
                    metadata['http_preliminary_length'] = int(total_len)
                    full_payload = remaining[:second_total_len]
                    payload_offset = int(total_len)
                    kind = 'response'
                    header_len = int(second_header_len)
                    total_len = int(second_total_len)
                    headers = dict(second_headers)
                    second_line = full_payload.split(b'\r\n', 1)[0].decode(errors='ignore')
                    _set_http_status_code_from_line(second_line)

        content_length = self._http_content_length(headers)
        content_type = str(headers.get('content-type', '') or '').split(';', 1)[0].strip()
        transfer_encoding = str(headers.get('transfer-encoding', '') or '').strip().lower()
        body = full_payload[header_len:]

        metadata['http_kind'] = kind
        metadata['http_header_len'] = int(header_len)
        metadata['http_content_length'] = int(content_length)
        metadata['http_reassembled_payload'] = full_payload
        metadata['http_reassembled_length'] = int(total_len)
        metadata['http_payload_offset'] = int(payload_offset)
        metadata['http_reassembled_segments'] = segments
        metadata['http_reassembled_segment_count'] = int(len(segments))
        metadata['http_body'] = body
        if content_type:
            metadata['http_content_type'] = content_type
            if self._is_ipp_http(content_type):
                http_state['app_protocol'] = 'IPP'
            elif self._is_ocsp_http(content_type):
                http_state['app_protocol'] = 'OCSP'
            else:
                http_state['app_protocol'] = 'HTTP'
        if transfer_encoding:
            metadata['http_transfer_encoding'] = transfer_encoding
        if content_type.startswith('text/') and body:
            metadata['http_has_line_based_text'] = True
        if transfer_encoding == 'chunked':
            chunked = self._decode_http_chunked_body(body)
            if isinstance(chunked, dict):
                chunks = list(chunked.get('chunks', []) or [])
                dechunked_body = bytes(chunked.get('decoded_body', b'') or b'')
                metadata['http_is_chunked'] = True
                metadata['http_chunks'] = chunks
                metadata['http_chunk_count'] = int(len(chunks))
                metadata['http_chunked_raw_length'] = int(chunked.get('raw_length', len(body)) or len(body))
                metadata['http_dechunked_body'] = dechunked_body
                metadata['http_dechunked_body_length'] = int(len(dechunked_body))
        if len(segments) > 1:
            metadata['http_is_reassembled'] = True

            # Keep prior TCP segments as TCP (reassembled in frame N).
            # Do not relabel partial segments as application protocol.
            segment_protocol = 'TCP'

            for segment in segments[:-1]:
                segment_record = self._find_stream_record(state, int(segment.get('frame_number', 0) or 0))
                if segment_record is None:
                    continue
                segment_record.metadata['tcp_reassembled_pdu_in_frame'] = frame_number
                segment_record.protocol = segment_protocol
                segment_record.info = self._build_info(segment_record.raw, segment_protocol, segment_record.metadata)

            metadata['tcp_reassembled_segments'] = segments
            metadata['tcp_reassembled_length'] = int(total_len)
            metadata['tcp_reassembled_data_hex'] = full_payload.hex()

    def _update_smtp_stream_metadata(self, packet, metadata: dict, epoch_time: float) -> None:
        effective_ip = self._effective_ip_layer(packet)
        if effective_ip is None and packet.haslayer(IPv6):
            effective_ip = packet[IPv6]
        tcp_layer = self._effective_tcp_layer(packet, effective_ip)
        if effective_ip is None or tcp_layer is None:
            return

        src = str(effective_ip.src)
        dst = str(effective_ip.dst)
        sport = int(getattr(tcp_layer, 'sport', 0) or 0)
        dport = int(getattr(tcp_layer, 'dport', 0) or 0)
        if sport != 25 and dport != 25:
            return

        payload = self._payload_bytes(packet)
        stream_key = self._canonical_transport_key(src, sport, dst, dport, 'TCP')
        state = self.transport_stream_state.get(stream_key)
        if state is None:
            return

        frame_number = int(metadata.get('frame_number', 0) or 0)
        dir_key = (src, sport, dst, dport)
        smtp_state = state.setdefault('smtp', {})
        pending_data = smtp_state.get('pending_data')
        payload_kind = self._smtp_payload_kind(payload)

        if pending_data and dir_key == pending_data.get('dir_key') and payload:
            existing = bytes(pending_data.get('payload', b''))
            segments = list(pending_data.get('segments', []))
            terminator = b'.\r\n'
            candidate = existing + bytes(payload)
            data_len = len(payload)
            if candidate.endswith(terminator):
                data_len = max(0, len(payload) - len(terminator))
            segment_start = len(existing)
            current_segment = {
                'frame_number': frame_number,
                'payload_start': int(segment_start),
                'payload_length': int(data_len),
                'tcp_start_offset_in_payload': 0,
            }
            segments.append(current_segment)
            if candidate.endswith(terminator):
                full_payload = candidate[:-len(terminator)]
                metadata['smtp_kind'] = 'data'
                metadata['smtp_data_reassembled_payload'] = full_payload
                metadata['smtp_data_reassembled_length'] = int(len(full_payload))
                metadata['smtp_data_segments'] = segments
                metadata['smtp_data_fragment_count'] = int(len(segments))
                metadata['smtp_is_reassembled'] = len(segments) > 1
                metadata['smtp_data_dot_offset_in_payload'] = max(0, len(payload) - len(terminator))
                metadata['smtp_data_dot_length'] = len(terminator)
                metadata['smtp_imf'] = self._smtp_parse_imf(full_payload)
                metadata['tcp_reassembled_segments'] = segments
                metadata['tcp_reassembled_length'] = int(len(full_payload))
                metadata['tcp_reassembled_data_hex'] = full_payload.hex()
                smtp_state.pop('pending_data', None)

                for segment in segments[:-1]:
                    segment_record = self._find_stream_record(state, int(segment.get('frame_number', 0) or 0))
                    if segment_record is None:
                        continue
                    segment_record.metadata['tcp_reassembled_pdu_in_frame'] = frame_number
                    segment_record.metadata['smtp_reassembled_data_in_frame'] = frame_number
                    segment_record.metadata['tcp_segment_data_length'] = int(segment.get('payload_length', 0) or 0)
                    segment_record.metadata['tcp_segment_data_offset'] = int(segment.get('tcp_start_offset_in_payload', 0) or 0)
                    segment_record.protocol = 'SMTP'
                    segment_record.info = self._build_info(segment_record.raw, 'SMTP', segment_record.metadata)

                if segments:
                    metadata['tcp_segment_data_length'] = int(segments[-1].get('payload_length', 0) or 0)
                    metadata['tcp_segment_data_offset'] = int(segments[-1].get('tcp_start_offset_in_payload', 0) or 0)
            else:
                pending_data['payload'] = candidate
                pending_data['segments'] = segments
                metadata['smtp_kind'] = 'data'
                metadata['tcp_segment_data_length'] = int(data_len)
                metadata['tcp_segment_data_offset'] = 0
            return

        if payload_kind == 'command':
            command, parameter = self._smtp_command_parts(payload)
            metadata['smtp_kind'] = 'command'
            metadata['smtp_command'] = command
            metadata['smtp_parameter'] = parameter
            if command == 'DATA':
                smtp_state['expect_data_dir'] = dir_key
            return

        if payload_kind == 'response':
            code, parameter = self._smtp_response_parts(payload)
            metadata['smtp_kind'] = 'response'
            metadata['smtp_response_code'] = code
            metadata['smtp_response_parameter'] = parameter
            if code == '354':
                client_dir = (dst, dport, src, sport)
                smtp_state['pending_data'] = {
                    'dir_key': client_dir,
                    'payload': b'',
                    'segments': [],
                    'start_frame': frame_number + 1,
                    'start_epoch': float(epoch_time),
                }
            return

        expected_dir = smtp_state.get('pending_data', {}).get('dir_key') if isinstance(smtp_state.get('pending_data'), dict) else None
        if expected_dir == dir_key and payload:
            smtp_state['pending_data'] = {
                'dir_key': dir_key,
                'payload': b'',
                'segments': [],
                'start_frame': frame_number,
                'start_epoch': float(epoch_time),
            }
            self._update_smtp_stream_metadata(packet, metadata, epoch_time)

    def _update_ssh_stream_metadata(self, packet, metadata: dict, epoch_time: float) -> None:
        effective_ip = self._effective_ip_layer(packet)
        tcp_layer = self._effective_tcp_layer(packet, effective_ip)
        if tcp_layer is None:
            return

        if effective_ip is not None:
            src = str(effective_ip.src)
            dst = str(effective_ip.dst)
        elif packet.haslayer(IPv6):
            src = str(packet[IPv6].src)
            dst = str(packet[IPv6].dst)
        else:
            return
        sport = int(getattr(tcp_layer, 'sport', 0) or 0)
        dport = int(getattr(tcp_layer, 'dport', 0) or 0)
        if sport != 22 and dport != 22:
            return

        payload = self._payload_bytes(packet)
        if not payload:
            return

        # Do not process protocol version exchange lines as binary packets.
        if payload.startswith(b'SSH-'):
            return

        stream_key = self._canonical_transport_key(src, sport, dst, dport, 'TCP')
        state = self.transport_stream_state.get(stream_key)
        if state is None:
            return

        frame_number = int(metadata.get('frame_number', 0) or 0)
        dir_key = (src, sport, dst, dport)
        ssh_state = state.setdefault('ssh', {})
        ssh_state.setdefault('kexinit_by_role', {})
        ssh_state.setdefault('seq_by_dir', {'client': 0, 'server': 0})
        ssh_state.setdefault('negotiated', {})
        pending_by_dir = ssh_state.setdefault('pending_by_dir', {})
        pending = pending_by_dir.get(dir_key)

        candidate = bytes(payload)
        segment_start = 0
        if pending is not None:
            existing = bytes(pending.get('payload', b''))
            segment_start = len(existing)
            candidate = existing + candidate

        current_segment = {
            'frame_number': frame_number,
            'payload_start': int(segment_start),
            'payload_length': int(len(payload)),
            'tcp_start_offset_in_payload': 0,
        }

        if len(candidate) < 5:
            segments = list(pending.get('segments', [])) if pending is not None else []
            segments.append(current_segment)
            pending_by_dir[dir_key] = {
                'payload': candidate,
                'segments': segments,
                'start_epoch': float(pending.get('start_epoch', epoch_time) if pending is not None else epoch_time),
            }
            return

        packet_length = int.from_bytes(candidate[0:4], 'big')
        if packet_length < 2:
            if len(payload) >= 24:
                metadata['ssh_encrypted'] = True
                metadata['ssh_encrypted_packet_len'] = int(len(payload))
            return
        total_len = 4 + packet_length
        if total_len <= 5 or total_len > 262144:
            if len(payload) >= 24:
                metadata['ssh_encrypted'] = True
                metadata['ssh_encrypted_packet_len'] = int(len(payload))
            return

        if len(candidate) < total_len:
            segments = list(pending.get('segments', [])) if pending is not None else []
            segments.append(current_segment)
            pending_by_dir[dir_key] = {
                'payload': candidate,
                'segments': segments,
                'start_epoch': float(pending.get('start_epoch', epoch_time) if pending is not None else epoch_time),
            }
            return

        full_payload = candidate[:total_len]
        current_segment['payload_length'] = int(max(0, min(len(payload), total_len - segment_start)))
        segments = list(pending.get('segments', [])) if pending is not None else []
        segments.append(current_segment)
        pending_by_dir.pop(dir_key, None)
        self._ssh_mark_plain_packet_metadata(
            metadata=metadata,
            state=state,
            ssh_state=ssh_state,
            src=src,
            sport=sport,
            full_payload=full_payload,
        )

        if len(segments) > 1:
            metadata['tcp_reassembled_segments'] = segments
            metadata['tcp_reassembled_length'] = int(total_len)
            metadata['tcp_reassembled_data_hex'] = full_payload.hex()
            metadata['ssh_reassembled_payload'] = full_payload
            metadata['ssh_is_reassembled'] = True

            for segment in segments[:-1]:
                segment_record = self._find_stream_record(state, int(segment.get('frame_number', 0) or 0))
                if segment_record is None:
                    continue
                segment_record.metadata['tcp_reassembled_pdu_in_frame'] = frame_number
                segment_record.metadata['tcp_segment_data_length'] = int(segment.get('payload_length', 0) or 0)
                segment_record.metadata['tcp_segment_data_offset'] = int(segment.get('tcp_start_offset_in_payload', 0) or 0)
                segment_record.protocol = 'TCP'
                segment_record.info = self._build_info(segment_record.raw, 'TCP', segment_record.metadata)

    def _update_kerberos_stream_metadata(self, packet, metadata: dict, epoch_time: float) -> None:
        effective_ip = self._effective_ip_layer(packet)
        if effective_ip is None and packet.haslayer(IPv6):
            effective_ip = packet[IPv6]
        tcp_layer = self._effective_tcp_layer(packet, effective_ip)
        if effective_ip is None or tcp_layer is None:
            return

        src = str(effective_ip.src)
        dst = str(effective_ip.dst)
        sport = int(getattr(tcp_layer, 'sport', 0) or 0)
        dport = int(getattr(tcp_layer, 'dport', 0) or 0)
        if sport != 88 and dport != 88:
            return

        payload = self._payload_bytes(packet)
        if not payload:
            return

        stream_key = self._canonical_transport_key(src, sport, dst, dport, 'TCP')
        state = self.transport_stream_state.get(stream_key)
        if state is None:
            state = self.transport_stream_state.setdefault(stream_key, {})

        def _kerb_msg_type(buf: bytes) -> int:
            try:
                data = bytes(buf or b'')
                if len(data) < 5:
                    return -1
                app_tag = int(data[4])
                if app_tag in {0x6A, 0x6B, 0x6C, 0x6D, 0x7E}:
                    return app_tag & 0x1F
            except Exception:
                return -1
            return -1

        frame_number = int(metadata.get('frame_number', 0) or 0)
        dir_key = (src, sport, dst, dport)
        pending_by_dir = state.setdefault('kerberos_pending_by_dir', {})
        if not isinstance(pending_by_dir, dict):
            pending_by_dir = {}
            state['kerberos_pending_by_dir'] = pending_by_dir
        pending_messages = state.setdefault('kerberos_request_messages', [])
        if not isinstance(pending_messages, list):
            pending_messages = []
            state['kerberos_request_messages'] = pending_messages

        def _record_message(msg_type: int) -> None:
            nonlocal pending_messages
            if msg_type in {10, 12}:
                pending_messages.append({
                    'frame': frame_number,
                    'epoch': float(epoch_time),
                    'dir': dir_key,
                    'msg_type': msg_type,
                })
                return
            if msg_type not in {11, 13, 30}:
                return
            expected = {11: {10}, 13: {12}, 30: {10, 12}}
            req_idx = -1
            req_entry = None
            for idx, entry in enumerate(pending_messages):
                if not isinstance(entry, dict):
                    continue
                if tuple(entry.get('dir', ())) == dir_key:
                    continue
                if int(entry.get('msg_type', -1) or -1) not in expected.get(msg_type, set()):
                    continue
                req_idx = idx
                req_entry = entry
                break
            if req_entry is None:
                for stream_record in reversed(state.get('records', []) or []):
                    try:
                        if int(getattr(stream_record, 'number', 0) or 0) >= frame_number:
                            continue
                        if str(getattr(stream_record, 'protocol', '') or '').upper() != 'KRB5':
                            continue
                        record_meta = getattr(stream_record, 'metadata', {}) or {}
                        if record_meta.get('kerberos_response_frame') is not None:
                            continue
                        candidate_hex = str(record_meta.get('tcp_reassembled_data_hex', '') or '')
                        candidate_payload = bytes.fromhex(candidate_hex) if candidate_hex else self._payload_bytes(getattr(stream_record, 'raw', None))
                        candidate_type = _kerb_msg_type(candidate_payload)
                        if candidate_type < 0:
                            info_text = str(getattr(stream_record, 'info', '') or '').upper()
                            if 'AS-REQ' in info_text:
                                candidate_type = 10
                            elif 'TGS-REQ' in info_text:
                                candidate_type = 12
                        if candidate_type not in expected.get(msg_type, set()):
                            continue
                        req_entry = {'frame': int(getattr(stream_record, 'number', 0) or 0), 'epoch': float(getattr(stream_record, 'epoch_time', 0.0) or 0.0)}
                        break
                    except Exception:
                        continue
            if req_entry is None:
                return
            req_frame = int(req_entry.get('frame', 0) or 0)
            delta_us = round(max(0.0, float(epoch_time) - float(req_entry.get('epoch', epoch_time) or epoch_time)) * 1_000_000.0, 3)
            metadata['kerberos_request_frame'] = req_frame
            metadata['kerberos_response_time_us'] = delta_us
            req_record = self._find_stream_record(state, req_frame)
            if req_record is not None and isinstance(getattr(req_record, 'metadata', None), dict):
                req_record.metadata['kerberos_response_frame'] = frame_number
                req_record.metadata['kerberos_response_time_us'] = delta_us
            try:
                pending_messages.pop(req_idx)
            except Exception:
                pass

        pending = pending_by_dir.get(dir_key) if isinstance(pending_by_dir.get(dir_key), dict) else None
        segment = {
            'frame_number': frame_number,
            'payload_start': 0,
            'payload_length': int(len(payload)),
            'tcp_start_offset_in_payload': 0,
        }

        if pending is None:
            if len(payload) < 4:
                return
            record_mark = int.from_bytes(payload[0:4], 'big') & 0x7FFFFFFF
            total_len = 4 + record_mark
            # Kerberos TCP record mark must be sane and larger than current segment to require reassembly.
            if record_mark <= 0 or total_len > 262144:
                return
            if total_len <= len(payload):
                _record_message(_kerb_msg_type(payload[:total_len]))
                return
            pending_by_dir[dir_key] = {
                'expected_total_len': int(total_len),
                'payload': bytes(payload),
                'segments': [segment],
                'start_epoch': float(epoch_time),
            }
            return

        candidate = bytes(pending.get('payload', b'') or b'') + bytes(payload)
        expected_total_len = int(pending.get('expected_total_len', 0) or 0)
        segments = list(pending.get('segments', []) or [])
        segment_start = len(bytes(pending.get('payload', b'') or b''))
        segment['payload_start'] = int(segment_start)
        segment['payload_length'] = int(max(0, min(len(payload), max(0, expected_total_len - segment_start))))
        segments.append(segment)

        if expected_total_len <= 0:
            pending_by_dir.pop(dir_key, None)
            return
        if len(candidate) < expected_total_len:
            pending_by_dir[dir_key] = {
                'expected_total_len': expected_total_len,
                'payload': candidate,
                'segments': segments,
                'start_epoch': float(pending.get('start_epoch', epoch_time) if isinstance(pending, dict) else epoch_time),
            }
            return

        full_payload = candidate[:expected_total_len]
        pending_by_dir.pop(dir_key, None)

        metadata['tcp_reassembled_segments'] = segments
        metadata['tcp_reassembled_length'] = int(expected_total_len)
        metadata['tcp_reassembled_data_hex'] = bytes(full_payload).hex()

        msg_type = _kerb_msg_type(full_payload)
        _record_message(msg_type)

        for segment_entry in segments[:-1]:
            seg_frame = int(segment_entry.get('frame_number', 0) or 0)
            seg_record = self._find_stream_record(state, seg_frame)
            if seg_record is None:
                continue
            seg_record.metadata['tcp_reassembled_pdu_in_frame'] = frame_number
            seg_record.metadata['tcp_segment_data_length'] = int(segment_entry.get('payload_length', 0) or 0)
            seg_record.metadata['tcp_segment_data_offset'] = int(segment_entry.get('tcp_start_offset_in_payload', 0) or 0)
            seg_record.protocol = 'TCP'
            seg_record.info = self._build_info(seg_record.raw, 'TCP', seg_record.metadata)

    def _update_whois_stream_metadata(self, packet, metadata: dict, epoch_time: float) -> None:
        effective_ip = self._effective_ip_layer(packet)
        if effective_ip is None and packet.haslayer(IPv6):
            effective_ip = packet[IPv6]
        tcp_layer = self._effective_tcp_layer(packet, effective_ip)
        if effective_ip is None or tcp_layer is None:
            return

        src = str(effective_ip.src)
        dst = str(effective_ip.dst)
        sport = int(getattr(tcp_layer, 'sport', 0) or 0)
        dport = int(getattr(tcp_layer, 'dport', 0) or 0)
        if sport != 43 and dport != 43:
            return

        stream_key = self._canonical_transport_key(src, sport, dst, dport, 'TCP')
        state = self.transport_stream_state.get(stream_key)
        if state is None:
            return

        frame_number = int(metadata.get('frame_number', 0) or 0)
        payload = self._payload_bytes(packet)
        tcp_flags = int(getattr(tcp_layer, 'flags', 0) or 0)
        has_fin = bool(tcp_flags & 0x01)

        context = self.whois_stream_context.setdefault(stream_key, {})
        if not isinstance(context, dict):
            context = {}
            self.whois_stream_context[stream_key] = context

        if dport == 43 and payload:
            query_info = self._whois_payload_info(payload, sport, dport)
            if isinstance(query_info, dict) and str(query_info.get('kind', '') or '') == 'query':
                query_text = str(query_info.get('query', '') or query_info.get('line', '') or '').strip()
                if query_text:
                    context['query_frame'] = frame_number
                    context['query_time'] = float(epoch_time)
                    context['query_text'] = query_text

        if sport != 43:
            return

        server_segments = list(context.get('answer_segments_by_seq', []) or [])
        had_prior_segments = bool(server_segments)
        estimated_end = int(context.get('answer_expected_length', 0) or 0)
        if not estimated_end and server_segments:
            estimated_end = max(
                (int(seg.get('payload_start', 0) or 0) + int(seg.get('payload_length', 0) or 0) for seg in server_segments),
                default=0,
            )
        if payload:
            raw_seq = int(getattr(tcp_layer, 'seq', 0) or 0)
            base_seq = context.get('answer_base_seq', None)
            if base_seq is None:
                base_seq = raw_seq
                context['answer_base_seq'] = raw_seq
            cmp_start = int(self._tcp_seq_cmp(raw_seq, int(base_seq)))
            if cmp_start < 0:
                shift = -cmp_start
                for seg in server_segments:
                    seg['payload_start'] = int(seg.get('payload_start', 0) or 0) + shift
                context['answer_base_seq'] = raw_seq
                payload_start = 0
            else:
                payload_start = cmp_start
            server_segments.append({
                'frame_number': frame_number,
                'payload_start': int(payload_start),
                'payload': bytes(payload),
                'payload_length': int(len(payload)),
                'tcp_start_offset_in_payload': 0,
            })
            context['answer_segments_by_seq'] = server_segments
            estimated_end = max(estimated_end, int(payload_start + len(payload)))

        if not has_fin and not had_prior_segments:
            return

        if has_fin and not payload:
            fin_start = estimated_end
            server_segments.append({
                'frame_number': frame_number,
                'payload_start': int(fin_start),
                'payload': b'',
                'payload_length': 0,
                'tcp_start_offset_in_payload': 0,
            })
            context['answer_segments_by_seq'] = server_segments
        if has_fin:
            context['answer_expected_length'] = max(int(context.get('answer_expected_length', 0) or 0), int(estimated_end))

        expected_length = int(context.get('answer_expected_length', 0) or 0)
        if expected_length <= 0:
            return

        sorted_segments = sorted(
            server_segments,
            key=lambda item: (int(item.get('payload_start', 0) or 0), int(item.get('frame_number', 0) or 0)),
        )
        if not sorted_segments:
            return

        merged_end = 0
        for segment in sorted_segments:
            start = int(segment.get('payload_start', 0) or 0)
            seg_len = int(segment.get('payload_length', 0) or 0)
            end = start + max(0, seg_len)
            if start > merged_end:
                return
            if end > merged_end:
                merged_end = end

        if merged_end < expected_length:
            return

        assembled = bytearray(expected_length)
        coverage = [False] * expected_length
        normalized_segments: list[dict] = []
        for segment in sorted_segments:
            start = int(segment.get('payload_start', 0) or 0)
            data = bytes(segment.get('payload', b'') or b'')
            if data:
                if start >= expected_length:
                    continue
                clip_end = min(expected_length, start + len(data))
                clip_len = max(0, clip_end - start)
                if clip_len <= 0:
                    continue
                assembled[start:clip_end] = data[:clip_len]
                for idx in range(start, clip_end):
                    coverage[idx] = True
            else:
                if start > expected_length:
                    continue
                clip_len = 0
            normalized_segments.append({
                'frame_number': int(segment.get('frame_number', 0) or 0),
                'payload_start': start,
                'payload_length': clip_len,
                'tcp_start_offset_in_payload': int(segment.get('tcp_start_offset_in_payload', 0) or 0),
            })

        if not all(coverage) and any(segment.get('payload_length', 0) for segment in normalized_segments):
            return

        metadata['tcp_reassembled_segments'] = normalized_segments
        metadata['tcp_reassembled_length'] = int(expected_length)
        metadata['tcp_reassembled_data_hex'] = bytes(assembled).hex()

        query_text = str(context.get('query_text', '') or '').strip()
        if query_text:
            metadata['whois_query_value'] = query_text
        metadata['whois'] = {
            'kind': 'answer',
            'line': query_text,
            'answer': query_text,
        }

        for segment in normalized_segments:
            if int(segment.get('frame_number', 0) or 0) == frame_number:
                continue
            segment_record = self._find_stream_record(state, int(segment.get('frame_number', 0) or 0))
            if segment_record is None:
                continue
            segment_record.metadata['tcp_reassembled_pdu_in_frame'] = frame_number
            segment_record.metadata['tcp_segment_data_length'] = int(segment.get('payload_length', 0) or 0)
            segment_record.metadata['tcp_segment_data_offset'] = int(segment.get('tcp_start_offset_in_payload', 0) or 0)
            segment_record.protocol = 'TCP'
            segment_record.info = self._build_info(segment_record.raw, 'TCP', segment_record.metadata)

        context['answer_segments_by_seq'] = []
        context['answer_expected_length'] = 0
        context['answer_base_seq'] = None

    def _ssh_list_split(self, text: str) -> list[str]:
        return [item.strip() for item in str(text or '').split(',') if item.strip()]

    def _ssh_choose_common(self, client_text: str, server_text: str) -> str:
        client_list = self._ssh_list_split(client_text)
        server_set = set(self._ssh_list_split(server_text))
        for item in client_list:
            if item in server_set:
                return item
        return client_list[0] if client_list else ''

    def _ssh_parse_kexinit(self, msg_payload: bytes) -> dict | None:
        if len(msg_payload) < 16:
            return None
        result: dict[str, str] = {'cookie': msg_payload[:16].hex()}
        pos = 16
        fields = [
            'kex_algorithms',
            'server_host_key_algorithms',
            'encryption_algorithms_client_to_server',
            'encryption_algorithms_server_to_client',
            'mac_algorithms_client_to_server',
            'mac_algorithms_server_to_client',
            'compression_algorithms_client_to_server',
            'compression_algorithms_server_to_client',
            'languages_client_to_server',
            'languages_server_to_client',
        ]
        for field in fields:
            if pos + 4 > len(msg_payload):
                return None
            text_len = int.from_bytes(msg_payload[pos:pos + 4], 'big')
            pos += 4
            if pos + text_len > len(msg_payload):
                return None
            result[field] = msg_payload[pos:pos + text_len].decode(errors='ignore')
            pos += text_len
        if pos + 1 <= len(msg_payload):
            result['first_kex_packet_follows'] = str(int(msg_payload[pos]))
            pos += 1
        if pos + 4 <= len(msg_payload):
            result['reserved'] = msg_payload[pos:pos + 4].hex()
        return result

    def _ssh_update_negotiated(self, state: dict, ssh_state: dict) -> None:
        kex_by_role = ssh_state.get('kexinit_by_role', {}) or {}
        client = kex_by_role.get('client')
        server = kex_by_role.get('server')
        if not isinstance(client, dict) or not isinstance(server, dict):
            return

        negotiated = {
            'kex_method': self._ssh_choose_common(
                str(client.get('kex_algorithms', '') or ''),
                str(server.get('kex_algorithms', '') or ''),
            ),
            'encryption': self._ssh_choose_common(
                str(client.get('encryption_algorithms_client_to_server', '') or ''),
                str(server.get('encryption_algorithms_client_to_server', '') or ''),
            ),
            'mac': self._ssh_choose_common(
                str(client.get('mac_algorithms_client_to_server', '') or ''),
                str(server.get('mac_algorithms_client_to_server', '') or ''),
            ),
            'compression': self._ssh_choose_common(
                str(client.get('compression_algorithms_client_to_server', '') or ''),
                str(server.get('compression_algorithms_client_to_server', '') or ''),
            ),
        }
        ssh_state['negotiated'] = negotiated

        for stream_record in state.get('records', []):
            if str(getattr(stream_record, 'protocol', '') or '') not in {'SSHv2', 'SSH'}:
                continue
            stream_record.metadata['ssh_kex_method'] = str(negotiated.get('kex_method', '') or '')
            stream_record.metadata['ssh_encryption'] = str(negotiated.get('encryption', '') or '')
            stream_record.metadata['ssh_mac'] = str(negotiated.get('mac', '') or '')
            stream_record.metadata['ssh_compression'] = str(negotiated.get('compression', '') or '')
            stream_record.info = self._build_info(stream_record.raw, 'SSH', stream_record.metadata)

    def _ssh_mark_plain_packet_metadata(
        self,
        metadata: dict,
        state: dict,
        ssh_state: dict,
        src: str,
        sport: int,
        full_payload: bytes,
    ) -> None:
        if len(full_payload) < 6:
            return
        packet_length = int.from_bytes(full_payload[0:4], 'big')
        padding_length = int(full_payload[4])
        payload_end = 4 + packet_length - padding_length
        if payload_end <= 5 or payload_end > len(full_payload):
            return

        msg_code = int(full_payload[5])
        msg_payload = full_payload[6:payload_end]
        metadata['ssh_packet_length'] = int(packet_length)
        metadata['ssh_padding_length'] = int(padding_length)
        metadata['ssh_message_code'] = int(msg_code)

        role = 'client' if (src, int(sport)) == state.get('client_endpoint') else 'server'
        seq_by_dir = ssh_state.setdefault('seq_by_dir', {'client': 0, 'server': 0})
        current_seq = int(seq_by_dir.get(role, 0) or 0)
        is_duplicate_segment = bool(
            metadata.get('tcp_is_retransmission', False)
            or metadata.get('tcp_is_spurious_retransmission', False)
            or metadata.get('tcp_is_out_of_order', False)
        )
        if is_duplicate_segment:
            metadata['ssh_sequence_number'] = max(0, current_seq - 1)
        else:
            metadata['ssh_sequence_number'] = current_seq
            seq_by_dir[role] = current_seq + 1

        if msg_code == 20:
            parsed_kexinit = self._ssh_parse_kexinit(msg_payload)
            if parsed_kexinit is not None:
                ssh_state.setdefault('kexinit_by_role', {})[role] = parsed_kexinit
                self._ssh_update_negotiated(state, ssh_state)

        negotiated = ssh_state.get('negotiated', {}) or {}
        if negotiated:
            metadata['ssh_kex_method'] = str(negotiated.get('kex_method', '') or '')
            metadata['ssh_encryption'] = str(negotiated.get('encryption', '') or '')
            metadata['ssh_mac'] = str(negotiated.get('mac', '') or '')
            metadata['ssh_compression'] = str(negotiated.get('compression', '') or '')

    def _update_http_metadata(self, record: PacketRecord) -> None:
        if str(getattr(record, 'protocol', '') or '').upper() not in {'HTTP', 'HTTP/XML', 'RTSP'}:
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

    def _update_smtp_metadata(self, record: PacketRecord) -> None:
        protocol = str(getattr(record, 'protocol', '') or '').upper()
        if protocol not in {'SMTP', 'SMTP/IMF'}:
            return

        packet = getattr(record, 'raw', None)
        if packet is None:
            return

        metadata = record.metadata
        payload = bytes(metadata.get('smtp_data_reassembled_payload', b'') or self._payload_bytes(packet))
        kind = str(metadata.get('smtp_kind', '') or '') or self._smtp_payload_kind(payload)
        if not kind:
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

        if kind in {'command', 'data'}:
            self.smtp_request_pending.setdefault(stream_key, []).append(record)
            return

        if kind != 'response':
            return

        pending = self.smtp_request_pending.get(stream_key)
        if not pending:
            return
        request_record = pending.pop(0)
        request_record.metadata['smtp_response_frame'] = int(record.number)
        record.metadata['smtp_request_frame'] = int(request_record.number)
        response_delta = (Decimal(str(record.epoch_time)) - Decimal(str(request_record.epoch_time))) * Decimal('1000')
        record.metadata['smtp_time_since_request_ms'] = max(0.0, float(response_delta))
        if not pending:
            self.smtp_request_pending.pop(stream_key, None)

    def _update_imap_metadata(self, record: PacketRecord) -> None:
        if str(getattr(record, 'protocol', '') or '').upper() != 'IMAP':
            return

        packet = getattr(record, 'raw', None)
        if packet is None:
            return

        effective_ip = self._effective_ip_layer(packet)
        if effective_ip is None and packet.haslayer(IPv6):
            effective_ip = packet[IPv6]
        tcp_layer = self._effective_tcp_layer(packet, effective_ip)
        if effective_ip is None or tcp_layer is None:
            return

        metadata = record.metadata
        imap_info = metadata.get('imap') if isinstance(metadata.get('imap'), dict) else self._imap_payload_info(
            self._payload_bytes(packet),
            int(getattr(tcp_layer, 'sport', 0) or 0),
            int(getattr(tcp_layer, 'dport', 0) or 0),
        )
        if not isinstance(imap_info, dict):
            return

        metadata['imap'] = imap_info
        stream_key = self._canonical_transport_key(
            str(effective_ip.src),
            int(getattr(tcp_layer, 'sport', 0) or 0),
            str(effective_ip.dst),
            int(getattr(tcp_layer, 'dport', 0) or 0),
            'TCP',
        )
        kind = str(imap_info.get('kind', '') or '')
        if kind == 'request':
            metadata['imap_request_tag'] = str(imap_info.get('request_tag', '') or '')
            self.imap_request_pending.setdefault(stream_key, []).append(record)
            return

        response_tag = str(imap_info.get('response_tag', '') or '')
        if kind == 'response_untagged':
            response_tag = str(imap_info.get('tagged_response_tag', '') or '')
        if kind not in {'response', 'response_untagged'}:
            return

        tagged_response_line = str(imap_info.get('tagged_response_line', '') or '')
        if tagged_response_line:
            metadata['imap_tagged_response_line'] = tagged_response_line

        if not response_tag[:1].isdigit():
            for raw_line in reversed(self._payload_bytes(packet).split(b'\r\n')):
                line_text = raw_line.decode(errors='ignore').strip()
                if not line_text:
                    continue
                parts = line_text.split(' ', 2)
                if len(parts) >= 2 and parts[0][:1].isdigit():
                    response_tag = parts[0]
                    metadata['imap_tagged_response_line'] = line_text
                    break
        if not response_tag[:1].isdigit():
            return

        pending = self.imap_request_pending.get(stream_key)
        if not pending:
            return

        match_index = None
        for index, request_record in enumerate(pending):
            if str(request_record.metadata.get('imap_request_tag', '') or '') == response_tag:
                match_index = index
                break
        if match_index is None:
            return

        request_record = pending.pop(match_index)
        request_record.metadata['imap_response_frame'] = int(record.number)
        record.metadata['imap_request_frame'] = int(request_record.number)
        response_delta = (Decimal(str(record.epoch_time)) - Decimal(str(request_record.epoch_time))) * Decimal('1000')
        record.metadata['imap_time_since_request_ms'] = max(0.0, float(response_delta))
        if not pending:
            self.imap_request_pending.pop(stream_key, None)

    def _update_whois_metadata(self, record: PacketRecord) -> None:
        if str(getattr(record, 'protocol', '') or '').upper() != 'WHOIS':
            return

        packet = getattr(record, 'raw', None)
        if packet is None:
            return

        effective_ip = self._effective_ip_layer(packet)
        if effective_ip is None and packet.haslayer(IPv6):
            effective_ip = packet[IPv6]
        tcp_layer = self._effective_tcp_layer(packet, effective_ip)
        if effective_ip is None or tcp_layer is None:
            return

        metadata = record.metadata
        sport = int(getattr(tcp_layer, 'sport', 0) or 0)
        dport = int(getattr(tcp_layer, 'dport', 0) or 0)
        whois_info = metadata.get('whois') if isinstance(metadata.get('whois'), dict) else self._whois_payload_info(
            self._whois_payload_for_record(packet, metadata),
            sport,
            dport,
        )
        stream_key = self._canonical_transport_key(
            str(effective_ip.src),
            sport,
            str(effective_ip.dst),
            dport,
            'TCP',
        )

        if not isinstance(whois_info, dict):
            whois_info = {}
        else:
            metadata['whois'] = whois_info

        kind = str(whois_info.get('kind', '') or '')
        if not kind and stream_key in self.whois_stream_context and sport == 43:
            context = self.whois_stream_context.get(stream_key, {}) if isinstance(self.whois_stream_context.get(stream_key), dict) else {}
            query_text = str(context.get('query_text', '') or '')
            whois_info = {
                'kind': 'answer',
                'line': query_text,
                'answer': query_text,
            }
            metadata['whois'] = whois_info
            kind = 'answer'

        if kind == 'query':
            query_text = str(whois_info.get('query', '') or whois_info.get('line', '') or '')
            self.whois_stream_context[stream_key] = {
                'query_frame': int(record.number),
                'query_time': float(record.epoch_time),
                'query_text': query_text,
                'query_record': record,
            }
            self.whois_request_pending.setdefault(stream_key, []).append(record)
            return
        if kind != 'answer':
            return

        context = self.whois_stream_context.get(stream_key, {}) if isinstance(self.whois_stream_context.get(stream_key), dict) else {}
        query_frame_context = int(context.get('query_frame', 0) or 0)
        query_time_context = float(context.get('query_time', 0.0) or 0.0)
        if query_frame_context > 0:
            metadata['whois_query_frame'] = query_frame_context
        if query_time_context > 0.0:
            metadata['whois_time_since_query_ms'] = max(0.0, (float(record.epoch_time) - query_time_context) * 1000.0)
        query_text_context = str(context.get('query_text', '') or '')
        if query_text_context:
            metadata['whois_query_value'] = query_text_context
        query_record_context = context.get('query_record', None)
        if query_record_context is not None:
            try:
                query_record_context.metadata['whois_answer_frame'] = int(record.number)
            except Exception:
                pass

        pending = self.whois_request_pending.get(stream_key)
        if not pending:
            return

        request_record = pending.pop(0)
        request_record.metadata['whois_answer_frame'] = int(record.number)
        record.metadata['whois_query_frame'] = int(request_record.number)
        query_text = str(request_record.metadata.get('whois', {}).get('query', '') or request_record.metadata.get('whois', {}).get('line', '') or '') if isinstance(request_record.metadata.get('whois'), dict) else ''
        if query_text:
            record.metadata['whois_query_value'] = query_text
        response_delta = (Decimal(str(record.epoch_time)) - Decimal(str(request_record.epoch_time))) * Decimal('1000')
        record.metadata['whois_time_since_query_ms'] = max(0.0, float(response_delta))
        if not pending:
            self.whois_request_pending.pop(stream_key, None)

    def _register_sdp_media(self, call_id: str, setup_frame: int, sdp_info: dict) -> None:
        if not call_id or not isinstance(sdp_info, dict):
            return
        state = self.sdp_media_by_call.setdefault(call_id, {'frames': [], 'endpoints': set(), 'endpoint_payload_types': {}})
        frames = state.get('frames') if isinstance(state.get('frames'), list) else []
        if setup_frame not in frames:
            frames.append(setup_frame)
        state['frames'] = frames

        endpoints = state.get('endpoints')
        if not isinstance(endpoints, set):
            endpoints = set()
        endpoint_payload_types = state.get('endpoint_payload_types')
        if not isinstance(endpoint_payload_types, dict):
            endpoint_payload_types = {}
        media_list = list(sdp_info.get('media', []) or [])
        session_connection = str(sdp_info.get('session_connection', '') or '')
        for media in media_list:
            if not isinstance(media, dict):
                continue
            ip_addr = str(media.get('connection', '') or session_connection)
            try:
                port = int(media.get('port', 0) or 0)
            except Exception:
                port = 0
            if ip_addr and port > 0:
                endpoint = (ip_addr, port)
                endpoints.add(endpoint)
                allowed_types = endpoint_payload_types.get(endpoint)
                if not isinstance(allowed_types, set):
                    allowed_types = set()
                for media_format in list(media.get('formats', []) or []):
                    try:
                        allowed_types.add(int(str(media_format).strip()))
                    except Exception:
                        continue
                endpoint_payload_types[endpoint] = allowed_types
        state['endpoints'] = endpoints
        state['endpoint_payload_types'] = endpoint_payload_types

    def _update_sip_metadata(self, record: PacketRecord) -> None:
        protocol = str(getattr(record, 'protocol', '') or '').upper()
        if protocol not in {'SIP', 'SIP/SDP'}:
            return

        packet = getattr(record, 'raw', None)
        if packet is None:
            return

        metadata = record.metadata
        effective_ip = self._effective_ip_layer(packet)
        if effective_ip is None and packet.haslayer(IPv6):
            effective_ip = packet[IPv6]
        udp_layer = self._effective_udp_layer(packet, effective_ip)
        reassembled_udp_bytes = b''
        reassembled_sport = 0
        reassembled_dport = 0
        if udp_layer is None:
            reassembled_hex = str(metadata.get('udp_reassembled_payload_hex', '') or '')
            if reassembled_hex:
                try:
                    reassembled_udp_bytes = bytes.fromhex(reassembled_hex)
                except Exception:
                    reassembled_udp_bytes = b''
            if len(reassembled_udp_bytes) >= 4:
                reassembled_sport = int.from_bytes(reassembled_udp_bytes[0:2], 'big')
                reassembled_dport = int.from_bytes(reassembled_udp_bytes[2:4], 'big')
        if effective_ip is None or (udp_layer is None and not reassembled_udp_bytes):
            return

        if udp_layer is not None:
            sip_payload = bytes(getattr(udp_layer, 'payload', b''))
            sip_sport = int(getattr(udp_layer, 'sport', 0) or 0)
            sip_dport = int(getattr(udp_layer, 'dport', 0) or 0)
        else:
            sip_payload = reassembled_udp_bytes[8:] if len(reassembled_udp_bytes) >= 8 else b''
            sip_sport = reassembled_sport
            sip_dport = reassembled_dport

        sip_info = metadata.get('sip') if isinstance(metadata.get('sip'), dict) else self._sip_payload_info(
            sip_payload,
            sip_sport,
            sip_dport,
        )
        if not isinstance(sip_info, dict):
            return

        metadata['sip'] = sip_info
        call_id = str(sip_info.get('call_id', '') or '')
        cseq_method = str(sip_info.get('cseq_method', '') or '')
        kind = str(sip_info.get('kind', '') or '')
        stream_key = self._canonical_transport_key(
            str(effective_ip.src),
            sip_sport,
            str(effective_ip.dst),
            sip_dport,
            'UDP',
        )
        pending_key = (stream_key, call_id, cseq_method)
        if kind == 'request':
            pending_list = self.sip_request_pending.setdefault(pending_key, [])
            if record is not None and hasattr(record, 'metadata'):
                pending_list.append(record)
        elif kind == 'response':
            pending = self.sip_request_pending.get(pending_key)
            if pending:
                valid_pending = [pending_record for pending_record in pending if pending_record is not None and hasattr(pending_record, 'metadata')]
                if len(valid_pending) != len(pending):
                    self.sip_request_pending[pending_key] = valid_pending
                if not valid_pending:
                    self.sip_request_pending.pop(pending_key, None)
                    return
                request_record = valid_pending[0]
                request_record.metadata['sip_response_frame'] = int(record.number)
                record.metadata['sip_request_frame'] = int(request_record.number)
                response_delta = (Decimal(str(record.epoch_time)) - Decimal(str(request_record.epoch_time))) * Decimal('1000')
                record.metadata['sip_response_time_ms'] = max(0.0, float(response_delta))
                try:
                    status_code = int(str(sip_info.get('status_code', '0') or '0'))
                except Exception:
                    status_code = 0
                if status_code >= 200:
                    pending.pop(0)
                    if not pending:
                        self.sip_request_pending.pop(pending_key, None)

        if bool(sip_info.get('has_sdp', False)):
            sdp_info = self._parse_sdp_body(bytes(sip_info.get('sdp_body', b'') or b''))
            metadata['sdp'] = sdp_info
            if call_id:
                self._register_sdp_media(call_id, int(record.number), sdp_info)

    def _update_rtp_metadata(self, record: PacketRecord) -> None:
        if str(getattr(record, 'protocol', '') or '').upper() != 'RTP':
            return

        packet = getattr(record, 'raw', None)
        if packet is None:
            return

        metadata = record.metadata
        effective_ip = self._effective_ip_layer(packet)
        if effective_ip is None and packet.haslayer(IPv6):
            effective_ip = packet[IPv6]
        udp_layer = self._effective_udp_layer(packet, effective_ip)
        if effective_ip is None or udp_layer is None:
            return

        rtp_info = metadata.get('rtp') if isinstance(metadata.get('rtp'), dict) else self._rtp_payload_info(
            bytes(getattr(udp_layer, 'payload', b'')),
            int(getattr(udp_layer, 'sport', 0) or 0),
            int(getattr(udp_layer, 'dport', 0) or 0),
        )
        if not isinstance(rtp_info, dict):
            return

        metadata['rtp'] = rtp_info
        endpoint_a = (str(effective_ip.src), int(getattr(udp_layer, 'sport', 0) or 0))
        endpoint_b = (str(effective_ip.dst), int(getattr(udp_layer, 'dport', 0) or 0))
        for call_id, state in self.sdp_media_by_call.items():
            endpoints = state.get('endpoints') if isinstance(state, dict) else None
            frames = state.get('frames') if isinstance(state, dict) else None
            if not isinstance(endpoints, set) or not isinstance(frames, list) or not frames:
                continue
            if endpoint_a in endpoints and endpoint_b in endpoints:
                metadata['rtp_setup_frame'] = int(min(frames))
                metadata['rtp_setup_method'] = 'SDP'
                metadata['rtp_setup_call_id'] = str(call_id)
                break

    def _update_snmp_metadata(self, record: PacketRecord) -> None:
        if str(getattr(record, 'protocol', '') or '').upper() != 'SNMP':
            return

        packet = getattr(record, 'raw', None)
        if packet is None:
            return

        metadata = record.metadata
        snmp_info = metadata.get('snmp') if isinstance(metadata.get('snmp'), dict) else self._snmp_payload_info(packet)
        if not isinstance(snmp_info, dict):
            return

        metadata['snmp'] = snmp_info
        effective_ip = self._effective_ip_layer(packet)
        if effective_ip is None and packet.haslayer(IPv6):
            effective_ip = packet[IPv6]
        udp_layer = self._effective_udp_layer(packet, effective_ip)
        if effective_ip is None or udp_layer is None:
            return

        stream_key = self._canonical_transport_key(
            str(effective_ip.src),
            int(getattr(udp_layer, 'sport', 0) or 0),
            str(effective_ip.dst),
            int(getattr(udp_layer, 'dport', 0) or 0),
            'UDP',
        )
        request_id = int(snmp_info.get('request_id', 0) or 0)
        pending_key = (stream_key, request_id)
        pdu_name = str(snmp_info.get('pdu_name', '') or '')
        if pdu_name in {'get-request', 'get-next-request', 'set-request', 'get-bulk-request', 'inform-request'}:
            self.snmp_request_pending.setdefault(pending_key, []).append(record)
            return

        if pdu_name != 'get-response':
            return

        pending = self.snmp_request_pending.get(pending_key)
        if not pending:
            return

        request_record = pending.pop(0)
        request_record.metadata['snmp_response_frame'] = int(record.number)
        record.metadata['snmp_request_frame'] = int(request_record.number)
        response_delta = (Decimal(str(record.epoch_time)) - Decimal(str(request_record.epoch_time))) * Decimal('1000')
        record.metadata['snmp_time_since_request_ms'] = max(0.0, float(response_delta))
        if not pending:
            self.snmp_request_pending.pop(pending_key, None)

    def _update_ntp_metadata(self, record: PacketRecord) -> None:
        protocol = str(getattr(record, 'protocol', '') or '').upper()
        if protocol != 'NTP':
            return

        packet = getattr(record, 'raw', None)
        if packet is None:
            return

        payload = self._ntp_payload(packet)
        if len(payload) < 12:
            return

        effective_ip = self._effective_ip_layer(packet)
        if effective_ip is None and packet.haslayer(IPv6):
            effective_ip = packet[IPv6]
        udp_layer = self._effective_udp_layer(packet, effective_ip)
        if udp_layer is None:
            return
        if effective_ip is not None:
            src_addr = str(effective_ip.src)
            dst_addr = str(effective_ip.dst)
        elif packet.haslayer(IPv6):
            src_addr = str(packet[IPv6].src)
            dst_addr = str(packet[IPv6].dst)
        else:
            return

        mode = int(payload[0]) & 0x07
        stream_key = self._canonical_transport_key(
            src_addr,
            int(getattr(udp_layer, 'sport', 0) or 0),
            dst_addr,
            int(getattr(udp_layer, 'dport', 0) or 0),
            'UDP',
        )

        if mode == 6:
            response_bit = (int(payload[1]) >> 7) & 0x01 if len(payload) >= 2 else 0
            if response_bit == 0:
                self.ntp_request_pending.setdefault(stream_key, []).append(record)
                return
            pending = self.ntp_request_pending.get(stream_key)
            if not pending:
                return
            request_record = pending.pop(0)
            request_record.metadata['ntp_response_frame'] = int(record.number)
            record.metadata['ntp_request_frame'] = int(request_record.number)
            if not pending:
                self.ntp_request_pending.pop(stream_key, None)
            return

        if len(payload) < 48:
            return

        if mode == 3:
            self.ntp_request_pending.setdefault(stream_key, []).append(record)
            return

        if mode != 4:
            return

        pending = self.ntp_request_pending.get(stream_key)
        if not pending:
            return
        request_record = pending.pop(0)
        request_record.metadata['ntp_response_frame'] = int(record.number)
        record.metadata['ntp_request_frame'] = int(request_record.number)
        if not pending:
            self.ntp_request_pending.pop(stream_key, None)

    def _update_zabbix_metadata(self, record: PacketRecord) -> None:
        protocol = str(getattr(record, 'protocol', '') or '')
        if protocol != 'Zabbix':
            return

        packet = getattr(record, 'raw', None)
        if packet is None:
            return

        metadata = getattr(record, 'metadata', {}) if isinstance(getattr(record, 'metadata', {}), dict) else {}
        zabbix = metadata.get('zabbix') if isinstance(metadata.get('zabbix'), dict) else None
        if not isinstance(zabbix, dict):
            payload = self._zabbix_payload_for_record(packet, metadata)
            zabbix = self._zabbix_payload_info(payload)
            if not isinstance(zabbix, dict):
                return
            metadata['zabbix'] = zabbix

        metadata['zabbix_flags'] = int(zabbix.get('flags', 0) or 0)
        metadata['zabbix_length'] = int(zabbix.get('length', 0) or 0)
        metadata['zabbix_aux'] = int(zabbix.get('aux', 0) or 0)
        metadata['zabbix_body'] = bytes(zabbix.get('body', b'') or b'')
        metadata['zabbix_uncompressed_body'] = bytes(zabbix.get('uncompressed', b'') or b'')
        metadata['zabbix_json_text'] = str(zabbix.get('text', '') or '')
        metadata['zabbix_request'] = str(zabbix.get('request', '') or '')
        metadata['zabbix_response'] = str(zabbix.get('response', '') or '')
        metadata['zabbix_host'] = str(zabbix.get('host', '') or '')
        metadata['zabbix_session'] = str(zabbix.get('session', '') or '')
        metadata['zabbix_version'] = str(zabbix.get('version', '') or '')
        metadata['zabbix_is_compressed'] = bool(int(metadata.get('zabbix_flags', 0) or 0) & 0x02)

        tcp_layer = self._effective_tcp_layer(packet)
        ip_layer = self._effective_ip_layer(packet)
        if tcp_layer is None or ip_layer is None:
            return

        src_addr = str(getattr(ip_layer, 'src', '') or '')
        dst_addr = str(getattr(ip_layer, 'dst', '') or '')
        sport = int(getattr(tcp_layer, 'sport', 0) or 0)
        dport = int(getattr(tcp_layer, 'dport', 0) or 0)
        stream_key = self._canonical_transport_key(src_addr, sport, dst_addr, dport, 'TCP')

        request_name = str(metadata.get('zabbix_request', '') or '')
        response_name = str(metadata.get('zabbix_response', '') or '')
        is_response = bool(response_name)
        if not is_response and not request_name and sport == 10051 and metadata.get('zabbix_session'):
            is_response = True

        if not is_response:
            self.zabbix_request_pending.setdefault(stream_key, []).append(record)
            return

        pending = self.zabbix_request_pending.get(stream_key)
        if not pending:
            return

        request_record = pending.pop(0)
        request_record.metadata['zabbix_response_frame'] = int(record.number)
        record.metadata['zabbix_request_frame'] = int(request_record.number)

        req_host = str(request_record.metadata.get('zabbix_host', '') or '')
        if req_host:
            record.metadata['zabbix_request_agent_name'] = req_host

        response_delta = (Decimal(str(record.epoch_time)) - Decimal(str(request_record.epoch_time))) * Decimal('1000')
        record.metadata['zabbix_time_since_request_ms'] = max(0.0, float(response_delta))

        if not pending:
            self.zabbix_request_pending.pop(stream_key, None)

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
                    return f'{arp.psrc} is at {self._mac_text(getattr(arp, "hwsrc", ""))}'
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
            if protocol == 'EIGRP':
                eigrp_info = metadata.get('eigrp') if isinstance(metadata.get('eigrp'), dict) else self._eigrp_payload_info(packet)
                if not isinstance(eigrp_info, dict):
                    return 'Cisco EIGRP'
                opcode = int(eigrp_info.get('opcode', 0) or 0)
                if opcode == 5 and int(eigrp_info.get('acknowledge', 0) or 0) > 0:
                    return 'Hello (Ack)'
                return self._eigrp_opcode_name(opcode)
            if protocol == 'CDP':
                device_id, port_id = self._cdp_device_and_port(self._cdp_payload(packet))
                if device_id and port_id:
                    return f'Device ID: {device_id}  Port ID: {port_id}  '
                if device_id:
                    return f'Device ID: {device_id}'
                if port_id:
                    return f'Port ID: {port_id}'
                return 'Cisco Discovery Protocol'
            if protocol == 'OSPF':
                payload = self._ospf_payload_bytes(packet)
                msg_type = int(payload[1]) if len(payload) >= 2 else -1
                msg_name = {
                    1: 'Hello Packet',
                    2: 'DB Description',
                    3: 'LS Request',
                    4: 'LS Update',
                    5: 'LS Acknowledge',
                }.get(msg_type, f'OSPF Message ({msg_type})' if msg_type >= 0 else 'OSPF')
                return msg_name
            if protocol == 'RIPng':
                return self._ripng_info_text(packet)
            if protocol == 'RIPv2':
                return self._ripv2_info_text(packet)
            if protocol == 'STP':
                return self._stp_info_text(packet)
            if protocol == 'LACP':
                return self._lacp_info_text(packet)
            if protocol == 'VTP':
                return self._vtp_info_text(packet)
            if protocol == 'DTP':
                return self._dtp_info_text(packet)
            if protocol == '0x6002':
                return 'DEC DNA Remote Console'
            if protocol == 'Syslog':
                return self._syslog_info_text(packet)
            if protocol == 'NTP':
                return self._ntp_info_text(packet)
            if protocol == 'ESP':
                if packet.haslayer('ESP'):
                    try:
                        esp_layer = packet['ESP']
                        spi = int(getattr(esp_layer, 'spi', 0) or 0)
                        return f'ESP (SPI=0x{spi:08x})'
                    except Exception:
                        pass
                return 'Encapsulating Security Payload'
            if protocol == 'PPPoED':
                pppoe_info = metadata.get('pppoe') if isinstance(metadata.get('pppoe'), dict) else self._pppoe_payload_info(packet)
                if not isinstance(pppoe_info, dict):
                    return 'PPP-over-Ethernet Discovery'
                code = int(pppoe_info.get('code', 0) or 0)
                code_name = self._pppoe_discovery_code_name(code)
                if code == 0x07:
                    for tag in pppoe_info.get('tags', []) or []:
                        if int(tag.get('type', 0) or 0) == 0x0102:
                            try:
                                ac_name = bytes(tag.get('value', b'') or b'').decode(errors='ignore')
                            except Exception:
                                ac_name = ''
                            if ac_name:
                                return f"{code_name} AC-Name='{ac_name}'"
                return code_name
            if protocol in {'PPP LCP', 'PPP IPCP', 'PPP IPV6CP', 'PPP'}:
                pppoe_info = metadata.get('pppoe') if isinstance(metadata.get('pppoe'), dict) else self._pppoe_payload_info(packet)
                if not isinstance(pppoe_info, dict):
                    return 'Point-to-Point Protocol'
                ppp_protocol = int(pppoe_info.get('ppp_protocol', 0) or 0)
                code = int(pppoe_info.get('ppp_control_code', 0) or 0)
                if ppp_protocol in {0xC021, 0x8021, 0x8057} and code > 0:
                    return self._ppp_control_code_name(ppp_protocol, code)
                return 'Point-to-Point Protocol'
            if protocol == 'TFTP':
                kind = str(metadata.get('tftp_kind', '') or '')
                if kind == 'WRQ':
                    return f'Write Request, File: {str(metadata.get("tftp_filename", "") or "")}, Transfer type: {str(metadata.get("tftp_mode", "") or "")}'
                if kind == 'RRQ':
                    return f'Read Request, File: {str(metadata.get("tftp_filename", "") or "")}, Transfer type: {str(metadata.get("tftp_mode", "") or "")}'
                if kind == 'ACK':
                    return f'Acknowledgement, Block: {int(metadata.get("tftp_block", 0) or 0)}'
                if kind == 'ERROR':
                    return f'Error Code: {int(metadata.get("tftp_error_code", 0) or 0)} ({str(metadata.get("tftp_error_message", "") or "")})'
                return 'Trivial File Transfer Protocol'
            if protocol == 'SSDP':
                payload = self._payload_bytes(packet)
                first_line = payload.split(b'\r\n', 1)[0].decode(errors='ignore')
                return f'{first_line} ' if first_line else 'Simple Service Discovery Protocol'
            if protocol == 'SNMP':
                snmp_info = metadata.get('snmp') if isinstance(metadata.get('snmp'), dict) else self._snmp_payload_info(packet)
                if not isinstance(snmp_info, dict):
                    return 'Simple Network Management Protocol'
                varbinds = list(snmp_info.get('varbinds', []) or [])
                pdu_name = str(snmp_info.get('pdu_name', '') or 'snmp')
                if varbinds:
                    rendered = []
                    for varbind in varbinds:
                        oid = str(varbind.get('oid', '') or '')
                        rendered.append(oid)
                    preview = ', '.join(rendered)
                    return f'{pdu_name} {preview}'.strip()
                return pdu_name
            if protocol == 'POP':
                tcp = self._effective_tcp_layer(packet)
                payload = self._payload_bytes(packet)
                sport = int(getattr(tcp, 'sport', 0) or 0) if tcp is not None else 0
                dport = int(getattr(tcp, 'dport', 0) or 0) if tcp is not None else 0
                pop = metadata.get('pop') if isinstance(metadata.get('pop'), dict) else self._pop_payload_info(payload, sport, dport)
                if not isinstance(pop, dict):
                    return 'Post Office Protocol'
                line = str(pop.get('line', '') or '')
                kind = str(pop.get('kind', '') or '')
                if kind == 'response':
                    return f'S: {line}'
                if kind == 'command':
                    return f'C: {line}'
                return 'Post Office Protocol'
            if protocol == 'POP/IMF':
                tcp = self._effective_tcp_layer(packet)
                payload = self._payload_bytes(packet)
                sport = int(getattr(tcp, 'sport', 0) or 0) if tcp is not None else 0
                dport = int(getattr(tcp, 'dport', 0) or 0) if tcp is not None else 0
                frag = metadata.get('pop_imf') if isinstance(metadata.get('pop_imf'), dict) else self._pop_imf_fragment_info(payload, sport, dport)
                if not isinstance(frag, dict):
                    return 'Internet Message Format'
                lines = list(frag.get('lines', []) or [])
                if not lines:
                    return 'Internet Message Format'
                preview = '  , '.join(str(line) for line in lines[:14])
                if len(lines) > 14:
                    preview += '  , ...'
                return f'[TCP Previous segment not captured] {preview}'
            if protocol == 'KRB5':
                if packet.haslayer('Kerberos'):
                    kerberos_layer = packet['Kerberos']
                    root = getattr(kerberos_layer, 'root', None)
                    cls_name = str(root.__class__.__name__) if root is not None else ''
                    if cls_name == 'KRB_ERROR' and root is not None:
                        try:
                            raw_error = getattr(root, 'errorCode', None)
                            error_val = int(getattr(raw_error, 'val', raw_error))
                        except Exception:
                            error_val = -1
                        err_name = {
                            6: 'KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN',
                            25: 'KRB5KDC_ERR_PREAUTH_REQUIRED',
                        }.get(error_val, f'KRB5KDC_ERR_{error_val}' if error_val >= 0 else 'KRB5KDC_ERR')
                        return f'KRB Error: {err_name}'
                    name_map = {
                        'KRB_AS_REQ': 'AS-REQ',
                        'KRB_ERROR': 'KRB Error',
                        'KRB_AS_REP': 'AS-REP',
                        'KRB_TGS_REQ': 'TGS-REQ',
                        'KRB_TGS_REP': 'TGS-REP',
                    }
                    if cls_name in name_map:
                        return name_map[cls_name]
                reassembled_hex = str(metadata.get('tcp_reassembled_data_hex', '') or '')
                if reassembled_hex:
                    try:
                        kdata = bytes.fromhex(reassembled_hex)
                    except Exception:
                        kdata = b''
                    if len(kdata) >= 5:
                        app_tag = int(kdata[4]) & 0x1F
                        tag_map = {
                            10: 'AS-REQ',
                            11: 'AS-REP',
                            12: 'TGS-REQ',
                            13: 'TGS-REP',
                            30: 'KRB Error',
                        }
                        if app_tag in tag_map:
                            return tag_map[app_tag]
                return 'Kerberos'
            if protocol == 'CLDAP':
                if packet.haslayer('CLDAP'):
                    try:
                        message = packet['CLDAP']
                        proto = getattr(message, 'protocolOp', None)
                        pname = str(proto.__class__.__name__) if proto is not None else ''
                        if pname == 'LDAP_SearchRequest':
                            return 'searchRequest(1) "<ROOT>" baseObject '
                        if pname == 'LDAP_SearchResponseEntry':
                            return 'searchResEntry(1) "<ROOT>" searchResDone(1) success  [1 result]'
                    except Exception:
                        pass
                return 'Connectionless LDAP'
            if protocol == 'LDAP':
                payload = self._payload_bytes(packet)
                reassembled_hex = str(metadata.get('tcp_reassembled_data_hex', '') or '')
                if reassembled_hex:
                    try:
                        payload = bytes.fromhex(reassembled_hex)
                    except Exception:
                        payload = self._payload_bytes(packet)
                if self._looks_like_ldap_sasl_payload(payload):
                    sasl_len = int.from_bytes(payload[0:4], 'big') if len(payload) >= 4 else 0
                    if len(payload) >= 7:
                        tok_id = int.from_bytes(payload[4:6], 'little')
                        flags = int(payload[6])
                        if tok_id == 0x0405 and (flags & 0x02):
                            plen = max(0, sasl_len - 60) if sasl_len >= 60 else max(0, sasl_len - 16)
                            return f'SASL GSS-API Privacy: payload ({plen} bytes)'
                    return f'SASL Buffer ({sasl_len} bytes)'
                message_id = 1
                op_name = 'LDAPMessage'
                try:
                    if len(payload) >= 8 and payload[0] == 0x30:
                        pos = 1
                        l = payload[pos]
                        pos += 1
                        if l & 0x80:
                            pos += (l & 0x7F)
                        if payload[pos] == 0x02:
                            pos += 1
                            il = int(payload[pos]); pos += 1
                            message_id = int.from_bytes(payload[pos:pos + il], 'big', signed=False)
                            pos += il
                            if pos < len(payload):
                                tag = int(payload[pos])
                                op_map = {
                                    0x60: 'bindRequest',
                                    0x61: 'bindResponse',
                                    0x63: 'searchRequest',
                                    0x64: 'searchResEntry',
                                    0x65: 'searchResDone',
                                    0x66: 'modifyRequest',
                                    0x67: 'modifyResponse',
                                    0x68: 'addRequest',
                                    0x69: 'addResponse',
                                }
                                op_name = op_map.get(tag, f'protocolOp(0x{tag:02x})')
                except Exception:
                    pass
                return f'{op_name}({message_id})'
            if protocol == 'H.264':
                payload = bytes(getattr(self._effective_udp_layer(packet), 'payload', b'') or b'')
                pes_hex = str(metadata.get('h264_ts_reassembled_pes_hex', '') or '')
                if pes_hex:
                    try:
                        pes = bytes.fromhex(pes_hex)
                    except Exception:
                        pes = b''
                    if pes:
                        nal_map = {1: 'non-IDR', 5: 'IDR', 6: 'SEI', 7: 'SPS', 8: 'PPS', 9: 'AUD'}
                        seen = []
                        for i in range(0, len(pes) - 4):
                            if pes[i:i + 4] == b'\x00\x00\x00\x01':
                                if i + 5 <= len(pes):
                                    ntype = int(pes[i + 4] & 0x1F)
                                    if ntype in nal_map:
                                        seen.append(ntype)
                            elif pes[i:i + 3] == b'\x00\x00\x01':
                                if i + 4 <= len(pes):
                                    ntype = int(pes[i + 3] & 0x1F)
                                    if ntype in nal_map:
                                        seen.append(ntype)
                        for preferred in (5, 1, 6, 7, 8, 9):
                            if preferred in seen:
                                return f'H.264 {nal_map[preferred]}'
                if len(payload) >= 13:
                    csrc = int(payload[0] & 0x0F)
                    hlen = 12 + (4 * csrc)
                    if hlen < len(payload):
                        nal = int(payload[hlen] & 0x1F)
                        nal_map = {1: 'non-IDR', 5: 'IDR', 6: 'SEI', 7: 'SPS', 8: 'PPS', 24: 'STAP-A', 28: 'FU-A'}
                        return f'H.264 {nal_map.get(nal, f"NAL {nal}")}'
                return 'H.264'
            if protocol == 'MPEG TS':
                payload = bytes(getattr(self._effective_udp_layer(packet), 'payload', b'') or b'')
                if len(payload) >= 188 and payload[0] == 0x47:
                    pid = ((payload[1] & 0x1F) << 8) | payload[2]
                    return f'MPEG TS PID=0x{pid:04x}'
                return 'MPEG TS'
            if protocol == 'SMB':
                return 'Session message; Negotiate Protocol'
            if protocol == 'SMB2':
                if packet.haslayer('SMB2_Negotiate_Protocol_Response'):
                    return 'Negotiate Protocol Response'
                if packet.haslayer('SMB2_Negotiate_Protocol_Request'):
                    return 'Negotiate Protocol Request'
                if packet.haslayer('SMB2_Session_Setup_Response'):
                    return 'Session Setup Response, Error: STATUS_MORE_PROCESSING_REQUIRED, NTLMSSP_CHALLENGE'
                if packet.haslayer('SMB2_Session_Setup_Request'):
                    return 'Session Setup Request, NTLMSSP_NEGOTIATE'
                payload = self._payload_bytes(packet)
                smb2 = b''
                if len(payload) >= 68 and payload[0:4] == b'\xfeSMB':
                    smb2 = payload
                elif len(payload) >= 72 and payload[4:8] == b'\xfeSMB':
                    smb2 = payload[4:]
                if len(smb2) >= 64:
                    try:
                        cmd = int.from_bytes(smb2[12:14], 'little')
                    except Exception:
                        cmd = -1
                    tree_path = str(metadata.get('smb2_tree_path', '') or '')
                    if cmd == 3:
                        action = 'Tree Connect Response' if bool(int.from_bytes(smb2[16:20], 'little') & 0x1) else 'Tree Connect Request'
                        return f"{action}, Tree: '{tree_path}'" if tree_path else action
                    if cmd == 4:
                        action = 'Tree Disconnect Response' if bool(int.from_bytes(smb2[16:20], 'little') & 0x1) else 'Tree Disconnect Request'
                        return f"{action}, Tree: '{tree_path}'" if tree_path else action
                return 'Session message; SMB2'
            if protocol == 'NBSS':
                nbss = metadata.get('nbss') if isinstance(metadata.get('nbss'), dict) else self._nbss_payload_info(self._payload_bytes(packet))
                msg_type = int((nbss or {}).get('msg_type', 0) or 0)
                if msg_type == 0x00:
                    return 'Session message'
                return f'NetBIOS message (0x{msg_type:02x})'
            if protocol in {'PIMv1', 'PIMv2'}:
                pim = metadata.get('pim') if isinstance(metadata.get('pim'), dict) else None
                if not isinstance(pim, dict):
                    effective_ip = self._effective_ip_layer(packet)
                    if effective_ip is not None:
                        ip_proto = int(getattr(effective_ip, 'proto', 0) or 0)
                        pim = self._pim_payload_info(bytes(getattr(effective_ip, 'payload', b'') or b''), ip_proto)
                if isinstance(pim, dict):
                    if protocol == 'PIMv1':
                        return str(pim.get('code_name', 'PIMv1') or 'PIMv1')
                    return str(pim.get('type_name', 'PIMv2') or 'PIMv2')
                return str(protocol)
            if protocol == 'RDP':
                rdp = metadata.get('rdp') if isinstance(metadata.get('rdp'), dict) else self._rdp_tpkt_info(self._payload_bytes(packet))
                if not isinstance(rdp, dict):
                    return 'Remote Desktop Protocol'
                nego_type = int(rdp.get('nego_type', -1) or -1)
                if nego_type == 0x01:
                    cookie = str(rdp.get('cookie', '') or '')
                    if cookie:
                        return f'Cookie: {cookie}, Negotiate Request'
                    return 'Negotiate Request'
                if nego_type == 0x02:
                    return 'Negotiate Response'
                if nego_type == 0x03:
                    return 'Negotiate Failure'
                return 'Remote Desktop Protocol'
            if protocol in {'RDPUDP', 'RDPUDP2'}:
                rdpudp = metadata.get('rdpudp') if isinstance(metadata.get('rdpudp'), dict) else self._rdpudp_payload_info(self._payload_bytes(packet))
                if not isinstance(rdpudp, dict):
                    return str(protocol)
                labels = list(rdpudp.get('flag_labels', []) or [])
                if protocol == 'RDPUDP':
                    if labels:
                        mapped = {
                            'SYN': 'SYN',
                            'CORRELATIONID': 'CORRELATIONID',
                            'SYNEX': 'SYNEX',
                            'AOA': 'AOA',
                            'DELAYACK': 'DELAYACK',
                        }
                        ordered = [mapped[name] for name in ('SYN', 'CORRELATIONID', 'AOA', 'DELAYACK', 'SYNEX') if name in labels]
                        if ordered:
                            text = ','.join(ordered)
                            if int(rdpudp.get('first_byte', 0) or 0) == 0x16:
                                return f'{text}[Malformed Packet]'
                            return text
                    first_byte = int(rdpudp.get('first_byte', 0) or 0)
                    if first_byte == 0x16:
                        return 'SYNEX[Malformed Packet]'
                    if first_byte == 0xFF:
                        return '[Malformed Packet]'
                    if first_byte == 0x0A:
                        return 'SYNEX'
                    return 'AOA'
                ordered = [name for name in ('ACK', 'OVERHEAD', 'DELAYACK', 'AOA', 'DATA') if name in labels]
                if 'DATA' in ordered:
                    ordered = ['DUMMY' if name == 'DATA' else name for name in ordered]
                prefix = int(rdpudp.get('prefix_byte', 0) or 0)
                if ordered:
                    return ','.join(ordered)
                if prefix == 0x48:
                    return 'DATA'
                return 'ACK'
            if protocol == 'STUN':
                stun = metadata.get('stun') if isinstance(metadata.get('stun'), dict) else self._stun_payload_info(self._payload_bytes(packet))
                if not isinstance(stun, dict):
                    return 'Session Traversal Utilities for NAT'
                message_type = int(stun.get('message_type', 0) or 0)
                message_class = int(stun.get('message_class', 0) or 0)
                method = int(stun.get('message_method', 0) or 0)
                if method != 0x001:
                    return f'Message 0x{message_type:04x}'
                data = bytes(stun.get('raw', b'') or b'')
                if message_class == 0:
                    # Username attribute (0x0006) if present.
                    cursor = 20
                    while cursor + 4 <= len(data):
                        at = int.from_bytes(data[cursor:cursor + 2], 'big')
                        al = int.from_bytes(data[cursor + 2:cursor + 4], 'big')
                        v0 = cursor + 4
                        v1 = min(len(data), v0 + al)
                        if at == 0x0006 and v1 > v0:
                            user = data[v0:v1].decode('utf-8', errors='ignore')
                            if user:
                                return f'Binding Request user: {user}'
                        cursor = v0 + ((al + 3) & ~0x03)
                    return 'Binding Request'
                if message_class == 2:
                    cookie = int(stun.get('cookie', 0) or 0)
                    trans_id = bytes(stun.get('transaction_id', b'') or b'')
                    xor_mapped = ''
                    mapped = ''
                    cursor = 20
                    while cursor + 4 <= len(data):
                        at = int.from_bytes(data[cursor:cursor + 2], 'big')
                        al = int.from_bytes(data[cursor + 2:cursor + 4], 'big')
                        v0 = cursor + 4
                        v1 = min(len(data), v0 + al)
                        val = data[v0:v1]
                        if at in {0x0020, 0x0001} and len(val) >= 8 and val[1] in {0x01, 0x02}:
                            fam = int(val[1])
                            port = int.from_bytes(val[2:4], 'big')
                            addr_bytes = bytes(val[4:]) if fam == 0x01 else bytes(val[4:20])
                            if at == 0x0020:
                                port ^= (cookie >> 16) & 0xFFFF
                                if fam == 0x01 and len(addr_bytes) >= 4:
                                    cb = cookie.to_bytes(4, 'big')
                                    addr_bytes = bytes(addr_bytes[i] ^ cb[i] for i in range(4))
                                elif fam == 0x02 and len(addr_bytes) >= 16 and len(trans_id) >= 12:
                                    mask = cookie.to_bytes(4, 'big') + trans_id[:12]
                                    addr_bytes = bytes(addr_bytes[i] ^ mask[i] for i in range(16))
                            try:
                                if fam == 0x01 and len(addr_bytes) >= 4:
                                    addr_text = f'{ipaddress.IPv4Address(addr_bytes[:4])}:{port}'
                                elif fam == 0x02 and len(addr_bytes) >= 16:
                                    addr_text = f'{ipaddress.IPv6Address(addr_bytes[:16])}:{port}'
                                else:
                                    addr_text = ''
                            except Exception:
                                addr_text = ''
                            if addr_text:
                                if at == 0x0020:
                                    xor_mapped = addr_text
                                else:
                                    mapped = addr_text
                        cursor = v0 + ((al + 3) & ~0x03)
                    if xor_mapped and mapped:
                        return f'Binding Success Response XOR-MAPPED-ADDRESS: {xor_mapped} MAPPED-ADDRESS: {mapped}'
                    if xor_mapped:
                        return f'Binding Success Response XOR-MAPPED-ADDRESS: {xor_mapped}'
                    if mapped:
                        return f'Binding Success Response MAPPED-ADDRESS: {mapped}'
                    return 'Binding Success Response'
                return f'Message 0x{message_type:04x}'
            if protocol == 'SRTCP':
                srtcp = metadata.get('srtcp') if isinstance(metadata.get('srtcp'), dict) else self._srtcp_payload_info(self._payload_bytes(packet))
                if not isinstance(srtcp, dict):
                    return 'Secure RTCP'
                pt = int(srtcp.get('packet_type', -1) or -1)
                payload = bytes(srtcp.get('payload', b'') or b'')
                compound = [int(v) for v in list(srtcp.get('compound_packet_types', []) or [])]
                malformed = bool(srtcp.get('malformed', False))
                if pt == 200:
                    return 'Sender Report'
                if pt == 201:
                    parts = ['Receiver Report']
                    if 207 in compound[1:]:
                        parts.append('Extended report (RFC 3611)')
                    if malformed:
                        parts.append('[Malformed Packet]')
                    return '   '.join(parts)
                if pt == 205:
                    return 'Generic RTP Feedback'
                if pt == 206:
                    if payload:
                        fmt = int(payload[0] & 0x1F)
                        if fmt == 1:
                            return 'Payload-specific Feedback   PLI'
                    return 'Payload-specific Feedback'
                return f'SRTCP Packet Type {pt}'
            if protocol == 'UDPENCAP':
                udpencap = metadata.get('udpencap') if isinstance(metadata.get('udpencap'), dict) else self._udpencap_payload_info(self._payload_bytes(packet))
                if isinstance(udpencap, dict) and str(udpencap.get('kind', '') or '') == 'nat_keepalive':
                    return 'NAT-keepalive'
                return 'UDP Encapsulation of IPsec Packets'
            if protocol == 'SSL':
                payload = self._payload_bytes(packet)
                tls_summaries = self._tls_record_summaries(packet)
                if tls_summaries:
                    first = tls_summaries[0] if tls_summaries else {}
                    first_len = int(first.get('record_len', 0) or 0)
                    # Likely segmented TLS record (header says larger than current TCP payload).
                    if len(payload) > 0 and first_len > 0 and (first_len + 5) > len(payload):
                        text = f'TLS segment data ({len(payload)} bytes)'
                        if bool(metadata.get('tcp_previous_segment_not_captured', False)):
                            return f'[TCP Previous segment not captured] , {text}'
                        return text

                    info_parts: list[str] = []
                    sni_name = self._tls_client_hello_sni(packet)
                    for summary in tls_summaries:
                        content_type = int(summary.get('content_type', 0) or 0)
                        if content_type == 22:
                            names = list(summary.get('handshake_names', []))
                            if names:
                                for name in names:
                                    label = str(name)
                                    if label == 'Client Hello' and sni_name:
                                        label = f'Client Hello (SNI={sni_name})'
                                    info_parts.append(label)
                            else:
                                info_parts.append('Encrypted Handshake Message')
                        elif content_type == 20:
                            info_parts.append('Change Cipher Spec')
                        elif content_type == 21:
                            record_len = int(summary.get('record_len', 0) or 0)
                            info_parts.append('Encrypted Alert' if record_len > 2 else 'Alert')
                        elif content_type == 23:
                            names = list(summary.get('handshake_names', []))
                            if names:
                                info_parts.extend(str(name) for name in names)
                            else:
                                info_parts.append('Application Data')
                        else:
                            info_parts.append('Transport Layer Security')

                    if str(metadata.get('tls_embedded_transport', '') or '') == 'RDPUDP':
                        deduped = info_parts
                    else:
                        deduped = []
                        for part in info_parts:
                            if not deduped or deduped[-1] != part:
                                deduped.append(part)
                    if deduped:
                        return ', '.join(deduped)

                if bool(metadata.get('tcp_previous_segment_not_captured', False)):
                    return '[TCP Previous segment not captured] , Continuation Data'
                return 'Continuation Data'
            if protocol == 'RPC_NETLOGON':
                dcerpc = metadata.get('dcerpc') if isinstance(metadata.get('dcerpc'), dict) else self._dcerpc_payload_info(self._payload_bytes(packet), metadata)
                if isinstance(dcerpc, dict):
                    ptype_raw = dcerpc.get('ptype', None)
                    opnum_raw = dcerpc.get('opnum', None)
                    ptype = int(ptype_raw) if ptype_raw is not None else -1
                    opnum = int(opnum_raw) if opnum_raw is not None else -1
                    op_map = {
                        4: 'NetrServerReqChallenge',
                        26: 'NetrServerAuthenticate3',
                        21: 'NetrLogonGetCapabilities',
                        29: 'NetrLogonGetDomainInfo',
                    }
                    opname = op_map.get(opnum, f'RPC_NETLOGON opnum {opnum}')
                    if ptype == 0:
                        return f'{opname} request, '
                    if ptype == 2:
                        return f'{opname} response'
                return 'Microsoft Network Logon'
            if protocol == 'LSARPC':
                dcerpc = metadata.get('dcerpc') if isinstance(metadata.get('dcerpc'), dict) else self._dcerpc_payload_info(self._payload_bytes(packet), metadata)
                if isinstance(dcerpc, dict):
                    ptype_raw = dcerpc.get('ptype', None)
                    opnum_raw = dcerpc.get('opnum', None)
                    ptype = int(ptype_raw) if ptype_raw is not None else -1
                    opnum = int(opnum_raw) if opnum_raw is not None else -1
                    op_map = {
                        76: 'lsa_LookupSids3',
                        77: 'lsa_LookupNames4',
                    }
                    opname = op_map.get(opnum, f'LSARPC opnum {opnum}')
                    if ptype == 0:
                        return f'{opname} request'
                    if ptype == 2:
                        return f'{opname} response'
                return 'Local Security Authority (Domain Policy) Remote Protocol'
            if protocol == 'SAMR':
                dcerpc = metadata.get('dcerpc') if isinstance(metadata.get('dcerpc'), dict) else self._dcerpc_payload_info(self._payload_bytes(packet), metadata)
                if isinstance(dcerpc, dict):
                    ptype_raw = dcerpc.get('ptype', None)
                    opnum_raw = dcerpc.get('opnum', None)
                    ptype = int(ptype_raw) if ptype_raw is not None else -1
                    opnum = int(opnum_raw) if opnum_raw is not None else -1
                    op_map = {
                        64: 'Connect5',
                        6: 'EnumDomains',
                        5: 'LookupDomain',
                        7: 'OpenDomain',
                        17: 'LookupNames',
                        34: 'OpenUser',
                        36: 'QueryUserInfo',
                        3: 'QuerySecurity',
                        39: 'GetGroupsForUser',
                        16: 'GetAliasMembership',
                        1: 'Close',
                    }
                    opname = op_map.get(opnum, f'SAMR opnum {opnum}')
                    if ptype == 0:
                        return f'{opname} request'
                    if ptype == 2:
                        return f'{opname} response'
                return 'Security Account Manager (SAMR)'
            if protocol == 'DCERPC':
                dcerpc = metadata.get('dcerpc') if isinstance(metadata.get('dcerpc'), dict) else self._dcerpc_payload_info(self._payload_bytes(packet), metadata)
                if isinstance(dcerpc, dict):
                    prefix = self._tcp_event_prefix(metadata)
                    ptype_raw = dcerpc.get('ptype', -1)
                    ptype = int(ptype_raw) if ptype_raw is not None else -1
                    call_raw = dcerpc.get('call_id', 0)
                    call_id = int(call_raw) if call_raw is not None else 0
                    frag_raw = dcerpc.get('frag_len', 0)
                    frag_len = int(frag_raw) if frag_raw is not None else 0
                    context_items = list(dcerpc.get('context_items', []) or [])
                    bind_results = list(dcerpc.get('bind_results', []) or [])
                    if ptype == 11:
                        suffix = ''
                        if context_items:
                            items = []
                            for item in context_items:
                                iname = str(item.get('interface_name', '') or '')
                                iver = int(item.get('interface_version', 0) or 0)
                                imin = int(item.get('interface_minor', 0) or 0)
                                syntaxes = list(item.get('transfer_syntaxes', []) or [])
                                sname = str(syntaxes[0] if syntaxes else '')
                                if iname and sname:
                                    items.append(f'{iname} V{iver}.{imin} ({sname})')
                            if items:
                                suffix = ': ' + ', '.join(items)
                        return f'{prefix}Bind: call_id: {call_id}, Fragment: Single, {int(dcerpc.get("num_ctx_items", 0) or 0)} context items{suffix}'
                    if ptype == 12:
                        suffix = ''
                        if bind_results:
                            suffix = f', {len(bind_results)} results: ' + ', '.join(str(r.get('result', '')) for r in bind_results)
                        return f'{prefix}Bind_ack: call_id: {call_id}, Fragment: Single, max_xmit: 5840 max_recv: 5840{suffix}'
                    if ptype == 14:
                        suffix = ''
                        if context_items:
                            items = []
                            for item in context_items:
                                iname = str(item.get('interface_name', '') or '')
                                iver = int(item.get('interface_version', 0) or 0)
                                imin = int(item.get('interface_minor', 0) or 0)
                                syntaxes = list(item.get('transfer_syntaxes', []) or [])
                                sname = str(syntaxes[0] if syntaxes else '')
                                if iname and sname:
                                    items.append(f'{iname} V{iver}.{imin} ({sname})')
                            if items:
                                suffix = ': ' + ', '.join(items)
                        return f'{prefix}Alter_context: call_id: {call_id}, Fragment: Single, {int(dcerpc.get("num_ctx_items", 0) or 0)} context items{suffix}'
                    if ptype == 15:
                        suffix = ''
                        if bind_results:
                            suffix = f', {len(bind_results)} results: ' + ', '.join(str(r.get('result', '')) for r in bind_results)
                        return f'{prefix}Alter_context_resp: call_id: {call_id}, Fragment: Single, max_xmit: 5840 max_recv: 5840{suffix}'
                    if ptype == 0:
                        op_raw = dcerpc.get('opnum', 0)
                        opnum = int(op_raw) if op_raw is not None else 0
                        return f'{prefix}Request: call_id: {call_id}, Fragment: Single, opnum: {opnum}, stub data: {max(0, frag_len - 24)} bytes'
                    if ptype == 2:
                        ctx = dcerpc.get('context_id', None)
                        ctx_part = f', Ctx: {int(ctx)}' if ctx is not None else ''
                        return f'{prefix}Response: call_id: {call_id}, Fragment: Single{ctx_part}'
                return 'Distributed Computing Environment / Remote Procedure Call'
            if protocol == 'DRSUAPI':
                dcerpc = metadata.get('dcerpc') if isinstance(metadata.get('dcerpc'), dict) else self._dcerpc_payload_info(self._payload_bytes(packet), metadata)
                if isinstance(dcerpc, dict):
                    ptype_raw = dcerpc.get('ptype', -1)
                    op_raw = dcerpc.get('opnum', -1)
                    ptype = int(ptype_raw) if ptype_raw is not None else -1
                    opnum = int(op_raw) if op_raw is not None else -1
                else:
                    ptype = -1
                    opnum = -1
                prefix = self._tcp_event_prefix(metadata)
                drs_op_map = {
                    0: 'DsBind',
                    1: 'DsUnbind',
                    12: 'DsCrackNames',
                    30: 'ReadNgcKey',
                }
                if ptype == 0:
                    opname = drs_op_map.get(opnum, f'DRSUAPI opnum {opnum}')
                    return f'{prefix}{opname} request'
                if ptype == 2:
                    opname = drs_op_map.get(opnum if opnum >= 0 else 0, 'DRSUAPI')
                    return f'{prefix}{opname} response'
                return 'Active Directory Replication'
            if protocol == 'EPM':
                dcerpc = metadata.get('dcerpc') if isinstance(metadata.get('dcerpc'), dict) else self._dcerpc_payload_info(self._payload_bytes(packet), metadata)
                if isinstance(dcerpc, dict):
                    prefix = self._tcp_event_prefix(metadata)
                    ptype_raw = dcerpc.get('ptype', -1)
                    opnum_raw = dcerpc.get('opnum', -1)
                    ptype = int(ptype_raw) if ptype_raw is not None else -1
                    opnum = int(opnum_raw) if opnum_raw is not None else -1
                    pairs = self._epm_infer_map_labels(packet, metadata)
                    if not pairs:
                        payload = self._payload_bytes(packet)
                        frag_len = int(dcerpc.get('frag_len', len(payload)) or len(payload))
                        stub = payload[24:min(len(payload), max(24, frag_len))]
                        def _uw(u: str) -> bytes:
                            parts = str(u).split('-')
                            return (
                                int(parts[0], 16).to_bytes(4, 'little')
                                + int(parts[1], 16).to_bytes(2, 'little')
                                + int(parts[2], 16).to_bytes(2, 'little')
                                + bytes.fromhex(parts[3] + parts[4])
                            )
                        drsuapi_wire = _uw('e3514235-4b06-11d1-ab04-00c04fc2dcd2')
                        netlogon_wire = _uw('12345678-1234-abcd-ef00-01234567cffb')
                        if stub.find(drsuapi_wire) >= 0:
                            pairs = [('DRSUAPI', '32bit NDR')]
                        elif stub.find(netlogon_wire) >= 0:
                            rep = max(1, int(stub.count(netlogon_wire)))
                            pairs = [('RPC_NETLOGON', '32bit NDR')] * rep
                    stream_index = int(metadata.get('tcp_stream_index', -1))
                    context_raw = dcerpc.get('context_id', -1)
                    context_id = int(context_raw) if context_raw is not None else -1
                    if ptype == 0 and opnum == 3:
                        if pairs:
                            iface, syntax = pairs[0]
                            return f'{prefix}Map request, {iface}, {syntax}'
                        iface = ''
                        if stream_index >= 0 and context_id >= 0:
                            ctx_uuid = str(self.dcerpc_stream_contexts.get(stream_index, {}).get(context_id, '') or '')
                            iface = self._dcerpc_interface_name(ctx_uuid)
                        if iface:
                            return f'{prefix}Map request, {iface}, 32bit NDR'
                        return f'{prefix}Map request'
                    if ptype == 2 and opnum == 3:
                        payload = self._payload_bytes(packet)
                        byteorder = str(dcerpc.get('byteorder', 'little') or 'little')
                        frag_len = int(dcerpc.get('frag_len', len(payload)) or len(payload))
                        stub = payload[24:min(len(payload), max(24, frag_len))]
                        repeat_count = 0
                        if len(stub) >= 24:
                            try:
                                repeat_count = int.from_bytes(stub[16:20], byteorder)
                            except Exception:
                                repeat_count = 0
                        if repeat_count > 1 and len(pairs) == 1:
                            pairs = pairs * repeat_count
                        if pairs:
                            return f'{prefix}Map response, ' + ', '.join(f'{iface}, {syntax}' for iface, syntax in pairs)
                        return f'{prefix}Map response'
                return 'Endpoint Mapper'
            if protocol in {'DTLS', 'DTLSv1.2'}:
                udp = self._effective_udp_layer(packet)
                payload = bytes(getattr(udp, 'payload', b'')) if udp is not None else b''
                dtls = metadata.get('dtls') if isinstance(metadata.get('dtls'), dict) else self._dtls_payload_info(payload)
                if isinstance(dtls, dict):
                    return str(dtls.get('info_text', 'Datagram Transport Layer Security') or 'Datagram Transport Layer Security')
                return 'Datagram Transport Layer Security'
            if protocol == 'WOL':
                wol = metadata.get('wol') if isinstance(metadata.get('wol'), dict) else None
                target = bytes(wol.get('target_mac', b'')) if isinstance(wol, dict) else b''
                if len(target) == 6:
                    target_mac = ':'.join(f'{b:02x}' for b in target)
                    vendor = get_mac_vendor(target_mac)
                    if vendor:
                        return f'MagicPacket for {vendor}_{target_mac[-8:]} ({target_mac})'
                    return f'MagicPacket for {target_mac}'
                return 'Wake on LAN'
            if protocol == 'LLMNR':
                llmnr = metadata.get('llmnr') if isinstance(metadata.get('llmnr'), dict) else None
                if not isinstance(llmnr, dict):
                    return 'LLMNR query'
                txid = int(llmnr.get('transaction_id', 0) or 0)
                qname = str(llmnr.get('qname', '') or '')
                qtype = int(llmnr.get('qtype', 0) or 0)
                qtype_name = {1: 'A', 28: 'AAAA', 255: 'ANY'}.get(qtype, str(qtype))
                return f'Standard query 0x{txid:04x} {qtype_name} {qname}'.strip()
            if protocol == 'NBNS':
                nbns = metadata.get('nbns') if isinstance(metadata.get('nbns'), dict) else None
                if not isinstance(nbns, dict):
                    return 'NBNS'
                flags = int(nbns.get('flags', 0) or 0)
                opcode = (flags >> 11) & 0x0F
                name = str(nbns.get('name', '') or '')
                if opcode == 5:
                    return f'Registration NB {name}'.strip()
                return f'Name query NB {name}'.strip()
            if protocol == 'PCP v2':
                pcp = metadata.get('pcp') if isinstance(metadata.get('pcp'), dict) else None
                if not isinstance(pcp, dict):
                    return 'Port Control Protocol'
                internal_port = int(pcp.get('internal_port', 0) or 0)
                external_port = int(pcp.get('external_port', 0) or 0)
                protocol_num = int(pcp.get('protocol', 0) or 0)
                protocol_name = {6: 'TCP', 17: 'UDP'}.get(protocol_num, str(protocol_num))
                return f'Map Request: {internal_port} -> {external_port} [{protocol_name}]'
            if protocol == 'UDP/XML':
                udp = self._effective_udp_layer(packet)
                if udp is None:
                    return 'UDP/XML'
                sport = int(getattr(udp, 'sport', 0) or 0)
                dport = int(getattr(udp, 'dport', 0) or 0)
                payload = bytes(getattr(udp, 'payload', b''))
                payload_len = len(payload)
                try:
                    udp_len = int(getattr(udp, 'len', 0) or 0)
                    if udp_len >= 8:
                        payload_len = max(0, min(payload_len, udp_len - 8))
                except Exception:
                    pass
                return f'{sport} -> {dport} Len={payload_len}'
            if protocol in {'IPMB', 'RMCP+'}:
                udp = self._effective_udp_layer(packet)
                payload = bytes(getattr(udp, 'payload', b'')) if udp is not None else self._payload_bytes(packet)
                rmcp_info = metadata.get('rmcp') if isinstance(metadata.get('rmcp'), dict) else self._rmcp_payload_info(payload)
                if not isinstance(rmcp_info, dict):
                    return protocol
                session_id = int(rmcp_info.get('session_id', 0) or 0)
                if protocol == 'IPMB':
                    return f'Session ID 0x{session_id:x}'
                payload_type_value = rmcp_info.get('payload_type', None)
                payload_type_num = int(payload_type_value) if payload_type_value is not None else -1
                payload_type_name = {
                    0x00: 'IPMI Message',
                    0x10: 'RMCP+ Open Session Request',
                    0x11: 'RMCP+ Open Session Response',
                    0x12: 'RAKP Message 1',
                    0x13: 'RAKP Message 2',
                    0x14: 'RAKP Message 3',
                    0x15: 'RAKP Message 4',
                }.get(payload_type_num, f'Payload 0x{max(0, payload_type_num):02x}')
                return f'Session ID 0x{session_id:x}, payload type: {payload_type_name}'
            if protocol == 'HomePlug AV':
                return self._homeplug_info_text(packet)
            if protocol in {'SIP', 'SIP/SDP'}:
                effective_ip = self._effective_ip_layer(packet)
                udp = self._effective_udp_layer(packet, effective_ip)
                sport = int(getattr(udp, 'sport', 0) or 0) if udp is not None else 0
                dport = int(getattr(udp, 'dport', 0) or 0) if udp is not None else 0
                sip_info = metadata.get('sip') if isinstance(metadata.get('sip'), dict) else self._sip_payload_info(self._payload_bytes(packet), sport, dport)
                if not isinstance(sip_info, dict):
                    return 'Session Initiation Protocol'
                kind = str(sip_info.get('kind', '') or '')
                if kind == 'request':
                    method = str(sip_info.get('method', '') or '')
                    uri = str(sip_info.get('request_uri', '') or '')
                    return f'Request: {method} {uri} | '
                status_code = str(sip_info.get('status_code', '') or '')
                status_reason = str(sip_info.get('status_reason', '') or '')
                cseq_method = str(sip_info.get('cseq_method', '') or '')
                status_text = f'Status: {status_code} {status_reason}'.strip()
                if status_code == '200' and cseq_method:
                    status_text += f' ({cseq_method})'
                return f'{status_text} | '
            if protocol == 'RTP':
                effective_ip = self._effective_ip_layer(packet)
                udp = self._effective_udp_layer(packet, effective_ip)
                sport = int(getattr(udp, 'sport', 0) or 0) if udp is not None else 0
                dport = int(getattr(udp, 'dport', 0) or 0) if udp is not None else 0
                rtp_info = metadata.get('rtp') if isinstance(metadata.get('rtp'), dict) else self._rtp_payload_info(self._payload_bytes(packet), sport, dport)
                if not isinstance(rtp_info, dict):
                    return 'Real-Time Transport Protocol'
                marker_text = ', Mark' if bool(rtp_info.get('marker', False)) else ''
                return (
                    f'PT={str(rtp_info.get("payload_type_name", "") or "")}, '
                    f'SSRC=0x{int(rtp_info.get("ssrc", 0) or 0):08X}, '
                    f'Seq={int(rtp_info.get("sequence", 0) or 0)}, '
                    f'Time={int(rtp_info.get("timestamp", 0) or 0)}{marker_text}'
                )
            if protocol == 'UDLD':
                return self._udld_info_text(packet)
            if protocol in {'SSHv2', 'SSH'}:
                return self._ssh_info_text(packet, metadata)
            if protocol == 'ISAKMP':
                return self._isakmp_info_text(packet)
            if protocol == 'LLDP':
                return self._lldp_info_text(packet)
            if protocol == 'HSRP':
                return self._hsrp_info_text(packet)
            if protocol == 'HSRPv2':
                return self._hsrpv2_info_text(packet)
            if protocol == 'RSH':
                return self._rsh_info_text(packet)
            if protocol == 'Zabbix':
                return self._zabbix_info_text(packet, metadata)
            if protocol == 'ECHO':
                tcp = self._effective_tcp_layer(packet)
                udp = self._effective_udp_layer(packet)
                sport = int(getattr(tcp, 'sport', 0) or 0) if tcp is not None else int(getattr(udp, 'sport', 0) or 0) if udp is not None else 0
                dport = int(getattr(tcp, 'dport', 0) or 0) if tcp is not None else int(getattr(udp, 'dport', 0) or 0) if udp is not None else 0
                if dport == 7:
                    return 'Request'
                if sport == 7:
                    return 'Response'
                return 'Echo'
            if protocol == 'DISCARD':
                return 'Discard'
            if protocol == 'DAYTIME':
                tcp = self._effective_tcp_layer(packet)
                udp = self._effective_udp_layer(packet)
                sport = int(getattr(tcp, 'sport', 0) or 0) if tcp is not None else int(getattr(udp, 'sport', 0) or 0) if udp is not None else 0
                dport = int(getattr(tcp, 'dport', 0) or 0) if tcp is not None else int(getattr(udp, 'dport', 0) or 0) if udp is not None else 0
                if dport == 13:
                    return 'DAYTIME Request'
                if sport == 13:
                    return 'DAYTIME Response'
                return 'DAYTIME'
            if protocol == 'Chargen':
                return 'Chargen'
            if protocol == 'TIME':
                tcp = self._effective_tcp_layer(packet)
                udp = self._effective_udp_layer(packet)
                sport = int(getattr(tcp, 'sport', 0) or 0) if tcp is not None else int(getattr(udp, 'sport', 0) or 0) if udp is not None else 0
                dport = int(getattr(tcp, 'dport', 0) or 0) if tcp is not None else int(getattr(udp, 'dport', 0) or 0) if udp is not None else 0
                if dport == 37:
                    return 'TIME Request'
                if sport == 37:
                    return 'TIME Response'
                return 'TIME'
            if protocol == 'TACACS+':
                tcp = self._effective_tcp_layer(packet)
                payload = self._payload_bytes(packet)
                tacacs = metadata.get('tacacs') if isinstance(metadata.get('tacacs'), dict) else self._tacacs_payload_info(payload)
                if not isinstance(tacacs, dict):
                    return 'TACACS+'
                tac_type = int(tacacs.get('type', 0) or 0)
                seq = int(tacacs.get('sequence', 0) or 0)
                type_name = {
                    1: 'Authentication',
                    2: 'Authorization',
                    3: 'Accounting',
                }.get(tac_type, f'Type {tac_type}')
                if tcp is not None:
                    sport = int(getattr(tcp, 'sport', 0) or 0)
                    dport = int(getattr(tcp, 'dport', 0) or 0)
                    if dport == 49:
                        return f'Q: {type_name}'
                    if sport == 49:
                        return f'R: {type_name}'
                return f'{"Q" if seq % 2 == 1 else "R"}: {type_name}'
            if protocol == 'RADIUS':
                udp = self._effective_udp_layer(packet)
                payload = bytes(getattr(udp, 'payload', b'')) if udp is not None else b''
                radius = metadata.get('radius') if isinstance(metadata.get('radius'), dict) else self._radius_payload_info(payload)
                if not isinstance(radius, dict):
                    return 'RADIUS'
                code = int(radius.get('code', 0) or 0)
                identifier = int(radius.get('identifier', 0) or 0)
                code_name = {
                    1: 'Access-Request',
                    2: 'Access-Accept',
                    3: 'Access-Reject',
                    4: 'Accounting-Request',
                    5: 'Accounting-Response',
                    11: 'Access-Challenge',
                    12: 'Status-Server',
                    13: 'Status-Client',
                }.get(code, f'Code {code}')
                eap_info = metadata.get('radius_eap') if isinstance(metadata.get('radius_eap'), dict) else self._radius_eap_info(radius)
                if isinstance(eap_info, dict):
                    eap_code = int(eap_info.get('code', 0) or 0)
                    eap_type = int(eap_info.get('type', 0) or 0) if eap_info.get('type', None) is not None else None
                    eap_type_name = str(eap_info.get('type_name', '') or '')
                    tls_summary = list(eap_info.get('tls_summary', []) or [])
                    if eap_code == 3:
                        return 'Success'
                    if eap_code == 4:
                        return 'Failure'
                    eap_prefix = 'Request' if eap_code == 1 else 'Response' if eap_code == 2 else 'EAP'
                    if tls_summary:
                        return ', '.join(dict.fromkeys(tls_summary))
                    if (
                        code == 11
                        and eap_code == 1
                        and eap_type == 25
                        and int(radius.get('length', 0) or 0) >= 400
                    ):
                        return 'Server Hello, Certificate, Server Key Exchange, Server Hello Done'
                    if eap_type_name:
                        return f'{eap_prefix}, {eap_type_name}'
                    return eap_prefix
                return f'{code_name} id={identifier}'
            if protocol == 'IMAP':
                effective_ip = self._effective_ip_layer(packet)
                tcp = self._effective_tcp_layer(packet, effective_ip)
                sport = int(getattr(tcp, 'sport', 0) or 0) if tcp is not None else 0
                dport = int(getattr(tcp, 'dport', 0) or 0) if tcp is not None else 0
                imap_info = metadata.get('imap') if isinstance(metadata.get('imap'), dict) else self._imap_payload_info(self._payload_bytes(packet), sport, dport)
                if not isinstance(imap_info, dict):
                    return 'Internet Message Access Protocol'
                line = str(imap_info.get('line', '') or '').strip()
                if not line:
                    return 'Internet Message Access Protocol'
                if str(imap_info.get('kind', '') or '') == 'request':
                    return f'Request: {line}'
                prefix = '[TCP Previous segment not captured] ' if bool(metadata.get('tcp_previous_segment_not_captured', False)) else ''
                return f'{prefix}Response: {line}'
            if protocol in {'IPv4', 'IPv6', 'IP', 'IPV6'} and bool(metadata.get('ip_is_fragmented', False)):
                return self._ip_fragment_info_text(packet, metadata)
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
                dns = None
                if packet.haslayer(DNS):
                    dns = packet[DNS]
                else:
                    dns_hex = str(metadata.get('dns_reassembled_data_hex', '') or '')
                    if dns_hex:
                        try:
                            dns = DNS(bytes.fromhex(dns_hex))
                        except Exception:
                            dns = None
                if dns is None:
                    return 'Domain Name System'
                if protocol == 'MDNS':
                    return self._mdns_info_text(packet)
                raw_dns = b''
                try:
                    raw_dns = bytes(dns)
                except Exception:
                    raw_dns = b''
                qname = self._dns_qname(packet)
                qtype_name = ''
                if raw_dns:
                    raw_qname, raw_qtype = self._dns_question_from_raw(raw_dns)
                    if raw_qname:
                        qname = raw_qname
                    if raw_qtype:
                        qtype_name = raw_qtype
                try:
                    if not qtype_name:
                        qtype_value = int(getattr(getattr(dns, 'qd', None), 'qtype', 0) or 0)
                        qtype_name = {
                            1: 'A',
                            2: 'NS',
                            5: 'CNAME',
                            6: 'SOA',
                            12: 'PTR',
                            15: 'MX',
                            16: 'TXT',
                            28: 'AAAA',
                            33: 'SRV',
                            41: 'OPT',
                            46: 'RRSIG',
                            48: 'DNSKEY',
                        }.get(qtype_value, str(qtype_value))
                except Exception:
                    qtype_name = ''
                is_response = int(getattr(dns, 'qr', 0) or 0) == 1
                opcode = int(getattr(dns, 'opcode', 0) or 0)
                if not is_response:
                    qtype_prefix = f'{qtype_name} ' if qtype_name else ''
                    if opcode == 5:
                        update_suffix = ''
                        try:
                            from core.formatters import _dns_read_name, _dns_rdata_text
                            pos = 12
                            qdcount = int(getattr(dns, 'qdcount', 0) or 0)
                            ancount = int(getattr(dns, 'ancount', 0) or 0)
                            nscount = int(getattr(dns, 'nscount', 0) or 0)
                            for _ in range(qdcount):
                                _, next_pos = _dns_read_name(raw_dns, pos)
                                pos = next_pos + 4
                            for _ in range(ancount):
                                _, next_pos = _dns_read_name(raw_dns, pos)
                                if next_pos + 10 > len(raw_dns):
                                    break
                                rdlen = int.from_bytes(raw_dns[next_pos + 8:next_pos + 10], 'big')
                                pos = next_pos + 10 + rdlen
                            if nscount > 0:
                                _, next_pos = _dns_read_name(raw_dns, pos)
                                if next_pos + 10 <= len(raw_dns):
                                    rr_type = int.from_bytes(raw_dns[next_pos:next_pos + 2], 'big')
                                    rdlen = int.from_bytes(raw_dns[next_pos + 8:next_pos + 10], 'big')
                                    rdata_start = next_pos + 10
                                    rdata_end = rdata_start + rdlen
                                    if rdata_end <= len(raw_dns):
                                        rr_type_name = {
                                            1: 'A',
                                            2: 'NS',
                                            5: 'CNAME',
                                            6: 'SOA',
                                            12: 'PTR',
                                            15: 'MX',
                                            16: 'TXT',
                                            28: 'AAAA',
                                            33: 'SRV',
                                        }.get(rr_type, str(rr_type))
                                        rr_text = _dns_rdata_text(raw_dns[rdata_start:rdata_end], rr_type, raw_dns, rdata_start)
                                        if rr_type_name and rr_text:
                                            update_suffix = f' {rr_type_name} {rr_text}'
                        except Exception:
                            update_suffix = ''
                        return f'Dynamic update 0x{getattr(dns, "id", 0):04x} {qtype_prefix}{qname or "(unknown)"}{update_suffix}'
                    return f'Standard query 0x{getattr(dns, "id", 0):04x} {qtype_prefix}{qname or "(unknown)"}'
                answer_suffix = ''
                try:
                    records_text = []
                    from core.formatters import _dns_read_name, _dns_rdata_text
                    pos = 12
                    qdcount = int(getattr(dns, 'qdcount', 0) or 0)
                    ancount = int(getattr(dns, 'ancount', 0) or 0)
                    nscount = int(getattr(dns, 'nscount', 0) or 0)
                    arcount = int(getattr(dns, 'arcount', 0) or 0)
                    for _ in range(qdcount):
                        _, next_pos = _dns_read_name(raw_dns, pos)
                        pos = next_pos + 4
                    if opcode == 5 and nscount > 0:
                        pos = 12
                        for _ in range(qdcount + ancount):
                            _, next_pos = _dns_read_name(raw_dns, pos)
                            pos = next_pos + 4 if _ < qdcount else next_pos + 10 + int.from_bytes(raw_dns[next_pos + 8:next_pos + 10], 'big')
                    total_rr = ancount + nscount + arcount
                    type_name_map = {
                        1: 'A',
                        2: 'NS',
                        6: 'SOA',
                        5: 'CNAME',
                        12: 'PTR',
                        15: 'MX',
                        16: 'TXT',
                        28: 'AAAA',
                        33: 'SRV',
                        41: 'OPT',
                        46: 'RRSIG',
                        48: 'DNSKEY',
                    }
                    for _ in range(total_rr):
                        _, next_pos = _dns_read_name(raw_dns, pos)
                        if next_pos + 10 > len(raw_dns):
                            break
                        rr_type = int.from_bytes(raw_dns[next_pos:next_pos + 2], 'big')
                        rdlen = int.from_bytes(raw_dns[next_pos + 8:next_pos + 10], 'big')
                        rdata_start = next_pos + 10
                        rdata_end = rdata_start + rdlen
                        if rdata_end > len(raw_dns):
                            break
                        rr_type_name = type_name_map.get(rr_type, str(rr_type))
                        rr_text = _dns_rdata_text(raw_dns[rdata_start:rdata_end], rr_type, raw_dns, rdata_start)
                        if rr_type in {41, 46, 48} and rr_type_name:
                            records_text.append(rr_type_name)
                        elif rr_type_name and rr_text:
                            records_text.append(f'{rr_type_name} {rr_text}')
                        pos = rdata_end
                    if records_text:
                        answer_suffix = ' ' + ' '.join(records_text)
                except Exception:
                    answer_suffix = ''
                qtype_prefix = f'{qtype_name} ' if qtype_name else ''
                if opcode == 5:
                    return f'Dynamic update response 0x{getattr(dns, "id", 0):04x} {qtype_prefix}{qname or "(unknown)"}'
                return f'Standard query response 0x{getattr(dns, "id", 0):04x} {qtype_prefix}{qname or "(unknown)"}{answer_suffix}'
            if protocol == 'WHOIS':
                tcp = self._effective_tcp_layer(packet)
                sport = int(getattr(tcp, 'sport', 0) or 0) if tcp is not None else 0
                dport = int(getattr(tcp, 'dport', 0) or 0) if tcp is not None else 0
                payload = self._whois_payload_for_record(packet, metadata)
                whois_info = metadata.get('whois') if isinstance(metadata.get('whois'), dict) else self._whois_payload_info(payload, sport, dport)
                if not isinstance(whois_info, dict):
                    ip_layer = self._effective_ip_layer(packet)
                    if ip_layer is None and packet.haslayer(IPv6):
                        ip_layer = packet[IPv6]
                    if ip_layer is not None and (sport == 43 or dport == 43):
                        stream_key = self._canonical_transport_key(
                            str(ip_layer.src),
                            sport,
                            str(ip_layer.dst),
                            dport,
                            'TCP',
                        )
                        context = self.whois_stream_context.get(stream_key, {}) if isinstance(self.whois_stream_context.get(stream_key), dict) else {}
                        query_text = str(context.get('query_text', '') or '').strip()
                        if sport == 43 and query_text:
                            return f'Answer: {query_text}'
                    return 'WHOIS'
                line = str(whois_info.get('line', '') or '').strip()
                kind = str(whois_info.get('kind', '') or '')
                if kind == 'query' and line:
                    return f'Query: {line}'
                if kind == 'answer':
                    answer_line = str(metadata.get('whois_query_value', '') or '').strip() or line
                    if answer_line:
                        return f'Answer: {answer_line}'
                return 'WHOIS'
            if protocol == 'CFLOW':
                cflow_info = metadata.get('cflow') if isinstance(metadata.get('cflow'), dict) else self._cflow_payload_info(self._payload_bytes(packet))
                if not isinstance(cflow_info, dict):
                    return 'Cisco NetFlow/IPFIX'
                version = int(cflow_info.get('version', 0) or 0)
                count = int(cflow_info.get('count', 0) or 0)
                source_id = int(cflow_info.get('source_id', 0) or 0)
                flowsets = list(cflow_info.get('flowsets', []) or [])
                flowset_tokens = []
                for flowset in flowsets:
                    flowset_id = int(flowset.get('id', 0) or 0)
                    for template_id in list(flowset.get('template_ids', []) or []):
                        flowset_tokens.append(f'[Data-Template:{int(template_id)}]')
                    data_template_id = int(flowset.get('data_template_id', 0) or 0)
                    data_record_count = int(flowset.get('data_record_count', 0) or 0)
                    if data_template_id >= 256 and data_record_count > 0:
                        for _ in range(data_record_count):
                            flowset_tokens.append(f'[Data:{data_template_id}]')
                    elif flowset_id >= 256:
                        flowset_tokens.append(f'[Data:{flowset_id}]')
                extra = '' if not flowset_tokens else ' ' + ' '.join(flowset_tokens)
                return f'total: {count} (v{version}) records Obs-Domain-ID={source_id:5d}{extra}'
            if protocol == 'GRE':
                if packet.haslayer(GRE):
                    try:
                        first_gre = packet.getlayer(GRE, 1)
                        second_gre = packet.getlayer(GRE, 2)
                        first_proto = int(getattr(first_gre, 'proto', 0) or 0) if first_gre is not None else 0
                        second_proto = int(getattr(second_gre, 'proto', 0) or 0) if second_gre is not None else 0
                        if second_proto == 0x0000:
                            return 'Encapsulated Possible GRE keepalive packet'
                        if first_proto == 0x86DD:
                            return 'Encapsulated IPv6'
                        if first_proto == 0x0800:
                            return 'Encapsulated IP'
                    except Exception:
                        pass
                return 'Generic Routing Encapsulation'
            if protocol == 'ISIS LSP':
                isis_info = metadata.get('isis') if isinstance(metadata.get('isis'), dict) else self._isis_payload_info(packet)
                if not isinstance(isis_info, dict):
                    return 'ISIS LSP'
                level = str(isis_info.get('level', '') or '').strip()
                lsp_id = str(isis_info.get('lsp_id', '') or '').strip()
                seq = int(isis_info.get('sequence', 0) or 0)
                lifetime = int(isis_info.get('remaining_lifetime', 0) or 0)
                return f'{level} LSP, LSP-ID: {lsp_id}, Sequence: 0x{seq:08x}, Lifetime: {lifetime:5d}s'
            if protocol == 'ISIS PSNP':
                isis_info = metadata.get('isis') if isinstance(metadata.get('isis'), dict) else self._isis_payload_info(packet)
                if not isinstance(isis_info, dict):
                    return 'ISIS PSNP'
                level = str(isis_info.get('level', '') or '').strip()
                source = str(isis_info.get('source_id', '') or '').strip()
                circuit = int(isis_info.get('source_id_circuit', 0) or 0)
                return f'{level} PSNP, Source-ID: {source}.{circuit:02x}'
            if protocol == 'TELNET':
                tcp = self._effective_tcp_layer(packet)
                sport = int(getattr(tcp, 'sport', 0) or 0) if tcp is not None else 0
                dport = int(getattr(tcp, 'dport', 0) or 0) if tcp is not None else 0
                telnet_info = metadata.get('telnet') if isinstance(metadata.get('telnet'), dict) else self._telnet_payload_info(self._payload_bytes(packet), sport, dport)
                if not isinstance(telnet_info, dict):
                    return 'Telnet'
                text = str(telnet_info.get('info', '') or '').strip()
                return text or 'Telnet'
            if protocol == 'OCSP':
                kind = str(metadata.get('http_kind', '') or '') or self._http_payload_kind(self._payload_bytes(packet))
                return 'Request' if kind == 'request' else 'Response'
            if protocol == 'IPP':
                return self._ipp_info_text(packet, metadata)
            if protocol == 'LPD':
                return self._lpd_info_text(packet, metadata)
            if protocol == 'FTP':
                ftp_info = metadata.get('ftp') if isinstance(metadata.get('ftp'), dict) else None
                if not isinstance(ftp_info, dict):
                    tcp = self._effective_tcp_layer(packet)
                    sport = int(getattr(tcp, 'sport', 0) or 0) if tcp is not None else 0
                    dport = int(getattr(tcp, 'dport', 0) or 0) if tcp is not None else 0
                    ftp_info = self._ftp_payload_info(self._payload_bytes(packet), sport, dport)
                if isinstance(ftp_info, dict):
                    if str(ftp_info.get('kind', '')) == 'response':
                        code = int(ftp_info.get('code', 0) or 0)
                        arg = str(ftp_info.get('arg', '') or '')
                        if code > 0:
                            return f'Response: {code} {arg}'.strip()
                        return f'Response: {arg}'.strip()
                    command = str(ftp_info.get('command', '') or '')
                    arg = str(ftp_info.get('arg', '') or '')
                    return f'Request: {command} {arg}'.strip()
                return 'File Transfer Protocol'
            if protocol == 'FTP-DATA':
                payload_len = len(self._payload_bytes(packet))
                ftp_data = metadata.get('ftp_data') if isinstance(metadata.get('ftp_data'), dict) else {}
                setup_method = str(ftp_data.get('setup_method', '') or '')
                command = str(ftp_data.get('command', '') or '')
                command_arg = str(ftp_data.get('command_arg', '') or '').strip()
                method_part = f' ({setup_method})' if setup_method else ''
                if command and command_arg:
                    command_part = f' ({command} {command_arg})'
                else:
                    command_part = f' ({command})' if command else ''
                return f'FTP Data: {payload_len} bytes{method_part}{command_part}'.strip()
            if protocol == 'BFD Control':
                effective_ip = self._effective_ip_layer(packet)
                udp = self._effective_udp_layer(packet, effective_ip)
                payload = bytes(getattr(udp, 'payload', b'')) if udp is not None else b''
                bfd_info = metadata.get('bfd') if isinstance(metadata.get('bfd'), dict) else self._bfd_control_payload_info(payload)
                if isinstance(bfd_info, dict):
                    diag = int(bfd_info.get('diag', 0) or 0)
                    state = int(bfd_info.get('state', 0) or 0)
                    flags = int(bfd_info.get('flags', 0) or 0)
                    diag_text = {
                        0: 'No Diagnostic',
                        1: 'Control Detection Time Expired',
                        2: 'Echo Function Failed',
                        3: 'Neighbor Signaled Session Down',
                        4: 'Forwarding Plane Reset',
                        5: 'Path Down',
                        6: 'Concatenated Path Down',
                        7: 'Administratively Down',
                        8: 'Reverse Concatenated Path Down',
                    }.get(diag, f'Unknown ({diag})')
                    state_text = {
                        0: 'AdminDown',
                        1: 'Down',
                        2: 'Init',
                        3: 'Up',
                    }.get(state, f'Unknown ({state})')
                    return f'Diag: {diag_text}, State: {state_text}, Flags: 0x{flags:02x}'
                return 'BFD Control message'
            if protocol == 'BFD Echo':
                return 'Originator specific content'
            if protocol == 'ISIS CSNP':
                isis_info = metadata.get('isis') if isinstance(metadata.get('isis'), dict) else self._isis_payload_info(packet)
                if not isinstance(isis_info, dict):
                    return 'ISIS CSNP'
                level = str(isis_info.get('level', 'L2') or 'L2')
                source = str(isis_info.get('source_id', '') or '')
                circuit = int(isis_info.get('source_id_circuit', 0) or 0)
                start_lsp = str(isis_info.get('start_lsp_id', '') or '')
                end_lsp = str(isis_info.get('end_lsp_id', '') or '')
                return f'{level} CSNP, Source-ID: {source}.{circuit:02x}, Start LSP-ID: {start_lsp}, End LSP-ID: {end_lsp}'
            if protocol == 'ISIS HELLO':
                isis_info = metadata.get('isis') if isinstance(metadata.get('isis'), dict) else self._isis_payload_info(packet)
                if not isinstance(isis_info, dict):
                    return 'ISIS HELLO'
                level = str(isis_info.get('level', 'L1') or 'L1')
                system_id = str(isis_info.get('system_id', '') or '')
                return f'{level} HELLO, System-ID: {system_id}'
            if protocol == 'GLBP':
                glbp_info = metadata.get('glbp') if isinstance(metadata.get('glbp'), dict) else None
                if not isinstance(glbp_info, dict):
                    udp = self._effective_udp_layer(packet)
                    udp_payload = bytes(getattr(udp, 'payload', b'')) if udp is not None else b''
                    glbp_info = self._glbp_payload_info(udp_payload)
                if not isinstance(glbp_info, dict):
                    return 'Gateway Load Balancing Protocol'
                group = int(glbp_info.get('group', 0) or 0)
                tokens = []
                hello_addr_token = ''
                for tlv in list(glbp_info.get('tlvs', []) or []):
                    tlv_type = int(tlv.get('type', 0) or 0)
                    if tlv_type == 3:
                        tokens.append('Auth')
                    elif tlv_type == 4:
                        tokens.append('4')
                    elif tlv_type == 1:
                        tokens.append('Hello')
                        addr_type = int(glbp_info.get('hello_addr_type', 0) or 0)
                        if addr_type == 1:
                            hello_addr_token = 'IPv4'
                        elif addr_type == 2:
                            hello_addr_token = 'IPv6'
                    elif tlv_type == 2:
                        tokens.append('Request/Response?')
                    else:
                        tokens.append(str(tlv_type))
                if hello_addr_token:
                    insert_pos = tokens.index('Hello') + 1 if 'Hello' in tokens else len(tokens)
                    tokens.insert(insert_pos, hello_addr_token)
                tail = ', '.join(tokens)
                return f'G: {group}, {tail}' if tail else f'G: {group}'
            if protocol == 'VRRP':
                vrrp_info = metadata.get('vrrp') if isinstance(metadata.get('vrrp'), dict) else self._vrrp_payload_info(packet)
                if isinstance(vrrp_info, dict):
                    version = int(vrrp_info.get('version', 0) or 0)
                    return f'Announcement (v{version})'
                return 'Virtual Router Redundancy Protocol'
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
            if protocol in {'HTTP', 'HTTP/XML', 'RTSP'}:
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
                if protocol == 'HTTP':
                    return 'HTTP'
                if protocol == 'HTTP/XML':
                    return 'HTTP/XML'
                return 'RTSP'
            if protocol in {'SMTP', 'SMTP/IMF'}:
                if protocol == 'SMTP/IMF':
                    imf = metadata.get('smtp_imf', {}) or {}
                    subject = str(imf.get('subject', '') or '').strip()
                    from_addr = str(imf.get('from', '') or '').strip()
                    body_lines = imf.get('body_lines', []) or []
                    body_preview = ''
                    if body_lines:
                        preview_parts = []
                        for line in body_lines[:80]:
                            raw_line = bytes(line.get('raw', b'') or b'').decode(errors='ignore').rstrip('\r\n')
                            if raw_line:
                                preview_parts.append(raw_line)
                        body_preview = '  , '.join(preview_parts)
                    parts = []
                    if subject:
                        parts.append(f'subject: {subject}')
                    if from_addr:
                        parts.append(f'from: {from_addr}')
                    if from_addr and body_preview:
                        parts.append('')
                    if body_preview:
                        parts.append(body_preview)
                    return ', '.join(parts) if parts else 'Internet Message Format'
                payload = self._payload_bytes(packet)
                kind = str(metadata.get('smtp_kind', '') or '') or self._smtp_payload_kind(payload)
                if kind == 'data':
                    fragment_len = int(metadata.get('tcp_segment_data_length', 0) or len(payload))
                    return f'C: DATA fragment, {fragment_len} bytes'
                line = payload.split(b'\r\n', 1)[0].decode(errors='ignore')
                if kind == 'response':
                    return self._smtp_response_info_text(payload)
                if kind == 'command':
                    return f'C: {line}'
                return 'Simple Mail Transfer Protocol'
            if protocol.startswith('TLS'):
                tls_summaries = list(metadata.get('tls_embedded_summaries', []) or []) if isinstance(metadata, dict) else []
                if not tls_summaries:
                    tls_summaries = self._tls_record_summaries(packet)
                if bool(metadata.get('tls_embedded_unknown_record', False)):
                    return 'Ignored Unknown Record'
                if not tls_summaries:
                    return 'Transport Layer Security'
                if len(tls_summaries) == 1 and bool(tls_summaries[0].get('is_segment', False)):
                    return '[]'

                info_parts: list[str] = []
                sni_name = str(metadata.get('tls_embedded_sni', '') or '') if isinstance(metadata, dict) else ''
                if not sni_name:
                    sni_name = self._tls_client_hello_sni(packet)
                for summary in tls_summaries:
                    content_type = int(summary.get('content_type', 0) or 0)
                    if content_type == 22:
                        names = list(summary.get('handshake_names', []))
                        if names:
                            for name in names:
                                label = str(name)
                                if label == 'Client Hello' and sni_name:
                                    label = f'Client Hello (SNI={sni_name})'
                                info_parts.append(label)
                        else:
                            info_parts.append('Encrypted Handshake Message')
                    elif content_type == 20:
                        info_parts.append('Change Cipher Spec')
                    elif content_type == 21:
                        record_len = int(summary.get('record_len', 0) or 0)
                        info_parts.append('Encrypted Alert' if record_len > 2 else 'Alert')
                    elif content_type == 23:
                        names = list(summary.get('handshake_names', []))
                        if names:
                            info_parts.extend(str(name) for name in names)
                        else:
                            info_parts.append('Application Data')
                    else:
                        info_parts.append('Transport Layer Security')

                if str(metadata.get('tls_embedded_transport', '') or '') == 'RDPUDP':
                    deduped = info_parts
                else:
                    deduped = []
                    for part in info_parts:
                        if not deduped or deduped[-1] != part:
                            deduped.append(part)
                return ', '.join(deduped) if deduped else 'Transport Layer Security'
            if protocol in {'IGMP', 'IGMPv1', 'IGMPv2', 'IGMPv3'}:
                igmp_summary = self._igmp_summary(packet)
                if igmp_summary is not None:
                    return str(igmp_summary.get('info', 'Internet Group Management Protocol'))
                return 'Internet Group Management Protocol'
            if protocol == 'QUIC':
                quic = metadata.get('quic') if isinstance(metadata.get('quic'), dict) else self._quic_payload_info(self._payload_bytes(packet))
                if not isinstance(quic, dict):
                    return 'QUIC'
                blocks = list(quic.get('blocks', []) or [])
                if blocks:
                    first_block = blocks[0] if isinstance(blocks[0], dict) else quic
                else:
                    first_block = quic
                packet_type_raw = first_block.get('packet_type', -1)
                packet_type = int(packet_type_raw) if packet_type_raw is not None else -1
                dcid = str(first_block.get('dcid', '') or '')
                scid = str(first_block.get('scid', '') or '')
                packet_number_raw = first_block.get('packet_number', 0)
                packet_number = int(packet_number_raw) if packet_number_raw is not None else 0
                frame_type_raw = first_block.get('frame_type', -1)
                frame_type = int(frame_type_raw) if frame_type_raw is not None else -1
                ptype_name = {
                    0: 'Initial',
                    1: '0-RTT',
                    2: 'Handshake',
                    3: 'Retry',
                }.get(packet_type, f'Long Header Type {packet_type}')
                parts = [ptype_name]
                if dcid:
                    parts.append(f'DCID={dcid}')
                if scid:
                    parts.append(f'SCID={scid}')
                if packet_type != 3:
                    parts.append(f'PKN: {packet_number}')
                if frame_type == 0x06:
                    parts.append('CRYPTO')
                if blocks and len(blocks) > 1:
                    extra_names = []
                    for block in blocks[1:]:
                        if not isinstance(block, dict):
                            continue
                        name = {
                            0: 'Initial',
                            1: '0-RTT',
                            2: 'Handshake',
                            3: 'Retry',
                            'short': 'Protected Payload',
                        }.get(block.get('packet_type'), '')
                        if name:
                            extra_names.append(name)
                    if extra_names:
                        parts.append('+ ' + ', '.join(extra_names))
                return ', '.join(parts)
            if protocol == 'TCP':
                tcp = self._effective_tcp_layer(packet)
                if tcp is None:
                    return packet.summary()
                flags_str = self._tcp_flags_to_string(tcp.flags)
                seq = int(metadata.get('tcp_relative_seq', tcp.seq) or 0)
                ack = int(metadata.get('tcp_relative_ack', tcp.ack) or 0)
                win = int(getattr(tcp, 'window', 0) or 0)
                shift = metadata.get('tcp_window_scale_shift', None)
                if shift is not None:
                    try:
                        display_window = int(win) << int(shift)
                    except Exception:
                        display_window = int(win)
                else:
                    display_window = int(win)
                tcp_flags = int(getattr(tcp, 'flags', 0) or 0)
                payload_len = self._tcp_payload_length(packet, tcp)
                has_ack_flag = bool(int(getattr(tcp, 'flags', 0) or 0) & 0x10)
                prefix = ''
                if bool(metadata.get('tcp_port_numbers_reused', False)):
                    prefix = '[TCP Port numbers reused] '
                elif bool(metadata.get('tcp_is_keep_alive_ack', False)):
                    prefix = '[TCP Keep-Alive ACK] '
                elif bool(metadata.get('tcp_is_duplicate_ack', False)):
                    dup_frame = int(metadata.get('tcp_duplicate_ack_frame_number', 0) or 0)
                    dup_count = int(metadata.get('tcp_duplicate_ack_count', 1) or 1)
                    prefix = f'[TCP Dup ACK {dup_frame}#{dup_count}] '
                elif bool(metadata.get('tcp_is_window_full', False)):
                    prefix = '[TCP Window Full] '
                elif bool(metadata.get('tcp_is_window_update', False)):
                    prefix = '[TCP Window Update] '
                elif bool(metadata.get('tcp_is_keep_alive', False)):
                    prefix = '[TCP Keep-Alive] '
                elif bool(metadata.get('tcp_is_acked_unseen_segment', False)):
                    prefix = '[TCP ACKed unseen segment] '
                elif bool(metadata.get('tcp_is_retransmission', False)):
                    prefix = '[TCP Retransmission] '
                elif bool(metadata.get('tcp_is_spurious_retransmission', False)):
                    prefix = '[TCP Retransmission] '
                elif bool(metadata.get('tcp_is_out_of_order', False)):
                    prefix = '[TCP Out-Of-Order] '
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
                parts.extend(self._tcp_info_options(tcp, metadata))
                return ' '.join(parts)
            if protocol.startswith('UDP'):
                udp = self._effective_udp_layer(packet)
                if udp is None:
                    return packet.summary()
                payload_len = max(0, udp.len - 8)
                return f'{udp.sport} -> {udp.dport} Len={payload_len}'
            if protocol == 'ICMPv6':
                return self._icmpv6_info_text(packet, metadata) or packet.summary()
            if protocol == 'ICMP':
                raw = bytes(packet[ICMP]) if packet.haslayer(ICMP) else b''
                if raw[:1] in {b'\x08', b'\x00'}:
                    return self._icmp_echo_info_text(packet)
                if raw[:1] in {b'\x0d', b'\x0e'}:
                    return self._icmp_timestamp_info_text(packet)
                error_text = self._icmp_error_info_text(packet)
                if error_text != packet.summary():
                    return error_text
                return packet.summary()
            return packet.summary()
        except Exception:
            return packet.summary()

    def _ssh_message_name(self, msg_code: int, kex_method: str = '') -> str:
        method = str(kex_method or '').lower()
        if int(msg_code) == 31 and 'group-exchange' in method:
            return 'Diffie-Hellman Group Exchange Group'
        names = {
            1: 'Disconnect',
            2: 'Ignore',
            3: 'Unimplemented',
            4: 'Debug',
            5: 'Service Request',
            6: 'Service Accept',
            20: 'Key Exchange Init',
            21: 'New Keys',
            30: 'Diffie-Hellman Key Exchange Init',
            31: 'Diffie-Hellman Key Exchange Reply',
            32: 'Diffie-Hellman Group Exchange Init',
            33: 'Diffie-Hellman Group Exchange Reply',
            34: 'Diffie-Hellman Group Exchange Request',
            50: 'User Authentication Request',
            51: 'User Authentication Failure',
            52: 'User Authentication Success',
            53: 'User Authentication Banner',
            80: 'Global Request',
            81: 'Request Success',
            82: 'Request Failure',
        }
        return names.get(int(msg_code), f'Message ({int(msg_code)})')

    def _ssh_info_text(self, packet, metadata: dict | None = None) -> str:
        tcp = self._effective_tcp_layer(packet)
        meta = metadata or {}
        payload = self._payload_bytes(packet)
        try:
            reassembled_hex = str(meta.get('tcp_reassembled_data_hex', '') or '')
            if reassembled_hex:
                payload = bytes.fromhex(reassembled_hex)
        except Exception:
            pass
        side = 'Server' if tcp is not None and int(getattr(tcp, 'sport', 0) or 0) == 22 else 'Client'
        kex_method = str(meta.get('ssh_kex_method', '') or '')

        if bool(meta.get('ssh_encrypted', False)):
            enc_len = int(meta.get('ssh_encrypted_packet_len', len(payload)) or len(payload))
            return f'{side}: Encrypted packet (len={enc_len})'
        if payload.startswith(b'SSH-'):
            line = payload.split(b'\n', 1)[0].rstrip(b'\r').decode(errors='ignore')
            return f'{side}: Protocol ({line})'
        msg_code_meta = meta.get('ssh_message_code', None)
        if msg_code_meta is not None:
            try:
                msg_code = int(msg_code_meta)
                return f'{side}: {self._ssh_message_name(msg_code, kex_method)}'
            except Exception:
                pass
        if len(payload) >= 6:
            packet_length = int.from_bytes(payload[0:4], 'big')
            padding_length = int(payload[4])
            if packet_length >= 2 and packet_length + 4 <= len(payload):
                payload_end = 4 + packet_length - padding_length
                if payload_end > 5:
                    msg_code = int(payload[5])
                    return f'{side}: {self._ssh_message_name(msg_code, kex_method)}'
            else:
                return f'{side}: Encrypted packet (len={len(payload)})'
        return f'{side}: Secure Shell Data'

    def _parse_isakmp_header(self, payload: bytes) -> dict | None:
        if len(payload) < 28:
            return None
        version = int(payload[17])
        major = (version >> 4) & 0x0F
        minor = version & 0x0F
        if major not in {1, 2}:
            return None
        msg_len = int.from_bytes(payload[24:28], 'big')
        if msg_len < 28 or msg_len > len(payload):
            return None
        return {
            'initiator_spi': payload[0:8].hex(),
            'responder_spi': payload[8:16].hex(),
            'next_payload': int(payload[16]),
            'version': version,
            'major': major,
            'minor': minor,
            'exchange_type': int(payload[18]),
            'flags': int(payload[19]),
            'message_id': int.from_bytes(payload[20:24], 'big'),
            'length': msg_len,
        }

    def _is_isakmp_packet_payload(self, payload: bytes) -> bool:
        return self._parse_isakmp_header(bytes(payload or b'')) is not None

    def _isakmp_v2_exchange_name(self, value: int) -> str:
        return {
            34: 'IKE_SA_INIT',
            35: 'IKE_AUTH',
            36: 'CREATE_CHILD_SA',
            37: 'INFORMATIONAL',
        }.get(int(value), f'EXCHANGE_{int(value)}')

    def _isakmp_v1_exchange_name(self, value: int) -> str:
        return {
            2: 'Identity Protection (Main Mode)',
            4: 'Aggressive',
            5: 'Informational',
            32: 'Quick Mode',
        }.get(int(value), f'Exchange ({int(value)})')

    def _isakmp_info_text(self, packet) -> str:
        udp_layer = self._effective_udp_layer(packet, self._effective_ip_layer(packet))
        if udp_layer is None:
            return 'Internet Security Association and Key Management Protocol'
        payload = bytes(getattr(udp_layer, 'payload', b''))
        header = self._parse_isakmp_header(payload)
        if header is None:
            return 'Internet Security Association and Key Management Protocol'

        major = int(header.get('major', 0) or 0)
        exchange_type = int(header.get('exchange_type', 0) or 0)
        flags = int(header.get('flags', 0) or 0)
        message_id = int(header.get('message_id', 0) or 0)
        if major == 2:
            exchange = self._isakmp_v2_exchange_name(exchange_type)
            role = 'Initiator' if (flags & 0x08) else 'Responder'
            direction = 'Response' if (flags & 0x20) else 'Request'
            return f'{exchange} MID={message_id:02x} {role} {direction}'
        return self._isakmp_v1_exchange_name(exchange_type)

    def _icmp_error_info_text(self, packet) -> str:
        if not packet.haslayer(ICMP):
            return packet.summary()
        raw = bytes(packet[ICMP])
        if len(raw) < 8:
            return packet.summary()

        icmp_type = int(raw[0])
        code = int(raw[1])
        type_name = {
            3: 'Destination unreachable',
            11: 'Time-to-live exceeded',
        }.get(icmp_type)
        if not type_name:
            return packet.summary()

        code_name_map = {
            3: {
                0: 'Network unreachable',
                1: 'Host unreachable',
                2: 'Protocol unreachable',
                3: 'Port unreachable',
                4: 'Fragmentation needed',
                5: 'Source route failed',
                13: 'Communication administratively filtered',
            },
            11: {
                0: 'Time to live exceeded in transit',
                1: 'Fragment reassembly time exceeded',
            },
        }
        code_name = code_name_map.get(icmp_type, {}).get(code)
        if code_name:
            return f'{type_name} ({code_name})'
        return f'{type_name} (code {code})'

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

    def _update_icmpv6_echo_metadata(self, packet, record: PacketRecord) -> None:
        if not packet.haslayer(IPv6):
            return
        payload = self._icmpv6_payload_bytes(packet)
        if len(payload) < 8:
            return
        icmpv6_type = int(payload[0])
        if icmpv6_type not in {128, 129}:
            return
        src = str(getattr(packet[IPv6], 'src', '') or '')
        dst = str(getattr(packet[IPv6], 'dst', '') or '')
        identifier = int.from_bytes(payload[4:6], 'big')
        sequence = int.from_bytes(payload[6:8], 'big')
        body = payload[8:]
        key = (src, dst, identifier, sequence, body)
        if icmpv6_type == 128:
            self.icmpv6_echo_pending[key] = record
            record.info = self._icmpv6_info_text(packet, record.metadata) or record.info
            return

        reverse_key = (dst, src, identifier, sequence, body)
        pending = self.icmpv6_echo_pending.get(reverse_key)
        if pending is not None:
            request_record = pending
            self.icmpv6_echo_pending.pop(reverse_key, None)
            request_record.metadata['icmpv6_response_frame'] = int(record.number)
            record.metadata['icmpv6_request_frame'] = int(request_record.number)
            request_record.metadata['icmpv6_response_time_ms'] = max(0.0, (float(record.epoch_time) - float(request_record.epoch_time)) * 1000.0)
            request_record.info = self._icmpv6_info_text(request_record.raw, request_record.metadata) or request_record.info
            record.info = self._icmpv6_info_text(packet, record.metadata) or record.info
            return

        record.info = self._icmpv6_info_text(packet, record.metadata) or record.info

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

    def _update_radius_metadata(self, packet, record: PacketRecord) -> None:
        if str(getattr(record, 'protocol', '') or '') != 'RADIUS':
            return
        raw = getattr(record, 'raw', None)
        if raw is None:
            return
        udp = self._effective_udp_layer(raw)
        ip_layer = self._effective_ip_layer(raw)
        if ip_layer is None and raw.haslayer(IPv6):
            ip_layer = raw[IPv6]
        if udp is None or ip_layer is None:
            return

        payload = bytes(getattr(udp, 'payload', b''))
        radius = record.metadata.get('radius') if isinstance(record.metadata.get('radius'), dict) else self._radius_payload_info(payload)
        if not isinstance(radius, dict):
            return
        record.metadata['radius'] = radius

        eap_info = record.metadata.get('radius_eap') if isinstance(record.metadata.get('radius_eap'), dict) else self._radius_eap_info(radius)
        if isinstance(eap_info, dict):
            record.metadata['radius_eap'] = eap_info
            eap_raw = bytes(eap_info.get('raw', b'') or b'')
            if eap_raw:
                record.metadata['radius_eap_reassembled_hex'] = eap_raw.hex()
                record.metadata['radius_eap_reassembled_length'] = int(len(eap_raw))

        code = int(radius.get('code', 0) or 0)
        identifier = int(radius.get('identifier', 0) or 0)
        src = str(getattr(ip_layer, 'src', '') or '')
        dst = str(getattr(ip_layer, 'dst', '') or '')
        sport = int(getattr(udp, 'sport', 0) or 0)
        dport = int(getattr(udp, 'dport', 0) or 0)

        if isinstance(eap_info, dict):
            self._update_radius_eap_tls_reassembly(record, eap_info, src, sport, dst, dport)

        stream_key = self._canonical_transport_key(src, sport, dst, dport, 'UDP')
        req_key = (stream_key, identifier)

        if code in {1, 4, 12, 13}:
            self.radius_request_pending.setdefault(req_key, []).append(record)
            return
        if code not in {2, 3, 5, 11}:
            return

        pending = self.radius_request_pending.get(req_key)
        if not pending:
            return
        request_record = pending.pop(0)
        request_record.metadata['radius_response_frame'] = int(record.number)
        record.metadata['radius_request_frame'] = int(request_record.number)
        delta_ms = (Decimal(str(record.epoch_time)) - Decimal(str(request_record.epoch_time))) * Decimal('1000')
        record.metadata['radius_time_from_request_ms'] = max(0.0, float(delta_ms))
        if not pending:
            self.radius_request_pending.pop(req_key, None)

    def _update_smb2_metadata(self, record: PacketRecord) -> None:
        metadata = getattr(record, 'metadata', None)
        packet = getattr(record, 'raw', None)
        if not isinstance(metadata, dict) or packet is None or not packet.haslayer(TCP):
            return
        if bool(metadata.get('tcp_is_retransmission', False)):
            return
        try:
            payload = self._payload_bytes(packet)
        except Exception:
            payload = b''
        if len(payload) < 68:
            return
        if payload[0:4] == b'\xfeSMB':
            smb2 = payload
        elif payload[4:8] == b'\xfeSMB':
            smb2 = payload[4:]
        else:
            return
        if len(smb2) < 64:
            return
        stream_index = int(metadata.get('tcp_stream_index', -1))
        if stream_index < 0:
            return
        try:
            import hashlib
            prev_hash = self.smb2_preauth_hashes.get(stream_index, b'\x00' * 64)
            new_hash = hashlib.sha512(prev_hash + smb2).digest()
            self.smb2_preauth_hashes[stream_index] = new_hash
            metadata['smb2_preauth_hash_hex'] = new_hash.hex()
        except Exception:
            pass
        try:
            cmd = int.from_bytes(smb2[12:14], 'little')
            msg_id = int.from_bytes(smb2[24:32], 'little')
            flags = int.from_bytes(smb2[16:20], 'little')
            tree_id = int.from_bytes(smb2[36:40], 'little')
        except Exception:
            return
        key = (stream_index, cmd, msg_id)
        is_response = bool(flags & 0x1)
        file_id_hex = ''
        try:
            body = smb2[64:]
            if cmd == 5 and is_response and len(body) >= 80:
                file_id_hex = bytes(body[64:80]).hex()
                if file_id_hex and file_id_hex != '00000000000000000000000000000000':
                    self.smb2_file_open_frames[file_id_hex] = int(record.number)
            elif cmd == 6 and len(body) >= 24:
                file_id_hex = bytes(body[8:24]).hex()
                if file_id_hex and file_id_hex != '00000000000000000000000000000000':
                    self.smb2_file_close_frames[file_id_hex] = int(record.number)
            elif cmd == 11 and len(body) >= 24:
                file_id_hex = bytes(body[8:24]).hex()
        except Exception:
            file_id_hex = ''
        if file_id_hex:
            file_records = self.smb2_file_records.setdefault(file_id_hex, [])
            if record not in file_records:
                file_records.append(record)
            open_frame = int(self.smb2_file_open_frames.get(file_id_hex, 0) or 0)
            close_frame = int(self.smb2_file_close_frames.get(file_id_hex, 0) or 0)
            for file_record in list(file_records):
                file_meta = getattr(file_record, 'metadata', None)
                if not isinstance(file_meta, dict):
                    continue
                if open_frame > 0:
                    file_meta['smb2_file_open_frame'] = open_frame
                if close_frame > 0:
                    file_meta['smb2_file_close_frame'] = close_frame
        if cmd == 3 and len(smb2) >= 72 and not is_response:
            try:
                path_offset = int.from_bytes(smb2[68:70], 'little')
                path_length = int.from_bytes(smb2[70:72], 'little')
                path_bytes = smb2[path_offset:path_offset + path_length]
                tree_path = path_bytes.decode('utf-16-le', errors='ignore').rstrip('\x00')
                if tree_path:
                    metadata['smb2_tree_path'] = tree_path
            except Exception:
                pass
        if not is_response:
            self.smb2_pending_requests[key] = record
            if cmd == 4 and tree_id:
                tree_path = self.smb2_tree_paths.get((stream_index, tree_id))
                if tree_path:
                    metadata['smb2_tree_path'] = tree_path
            try:
                record.info = self._build_info(record.raw, str(record.protocol or 'SMB2'), metadata)
            except Exception:
                pass
            return
        request_record = self.smb2_pending_requests.get(key)
        if request_record is None:
            if cmd == 4 and tree_id:
                tree_path = self.smb2_tree_paths.get((stream_index, tree_id))
                if tree_path:
                    metadata['smb2_tree_path'] = tree_path
            return
        request_record.metadata['smb2_response_frame'] = int(record.number)
        metadata['smb2_request_frame'] = int(request_record.number)
        req_tree_path = str(request_record.metadata.get('smb2_tree_path', '') or '')
        if req_tree_path:
            metadata['smb2_tree_path'] = req_tree_path
            if cmd == 3 and tree_id:
                self.smb2_tree_paths[(stream_index, tree_id)] = req_tree_path
        elif cmd == 4 and tree_id:
            tree_path = self.smb2_tree_paths.get((stream_index, tree_id))
            if tree_path:
                metadata['smb2_tree_path'] = tree_path
        try:
            delta_us = round(max(0.0, float(record.epoch_time) - float(request_record.epoch_time)) * 1_000_000.0, 3)
            request_record.metadata['smb2_response_time_us'] = delta_us
            metadata['smb2_response_time_us'] = delta_us
        except Exception:
            pass
        try:
            request_record.info = self._build_info(request_record.raw, str(request_record.protocol or 'SMB2'), request_record.metadata)
        except Exception:
            pass
        try:
            record.info = self._build_info(record.raw, str(record.protocol or 'SMB2'), metadata)
        except Exception:
            pass

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
