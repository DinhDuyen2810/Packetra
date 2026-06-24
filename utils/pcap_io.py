import gzip
import os
import tempfile
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from scapy.all import ARP, Ether, bind_layers, conf, rdpcap, wrpcap
from scapy.utils import PcapNgWriter, PcapReader

from utils.pcapng_parser import PcapngParser, PcapngMetadata, PcapngFileWriter


bind_layers(Ether, ARP, type=0x8035)


@dataclass
class CaptureMetadata:
    """Metadata extracted from capture file."""
    file_comment: str = ''
    section_hardware: str = ''
    section_os: str = ''
    section_application: str = ''
    interfaces: List[Dict] = field(default_factory=list)
    packet_interfaces: Dict[int, int] = field(default_factory=dict)
    packet_comments: Dict[int, str] = field(default_factory=dict)


def normalize_capture_extension(filename: str, file_format: str) -> str:
    """Ensure capture filename extension matches selected format."""
    file_format = (file_format or 'pcap').strip().lower()
    ext = '.pcapng' if file_format == 'pcapng' else '.pcap'
    root, _ = os.path.splitext(filename)
    if filename.lower().endswith('.gz') or filename.lower().endswith('.lz4'):
        root, _ = os.path.splitext(root)
    return root + ext


def apply_compression_suffix(filename: str, compression: str) -> str:
    """Append compression suffix when needed (.gz or .lz4)."""
    compression = (compression or 'none').strip().lower()
    if compression == 'gzip':
        return filename if filename.lower().endswith('.gz') else f'{filename}.gz'
    if compression == 'lz4':
        return filename if filename.lower().endswith('.lz4') else f'{filename}.lz4'
    return filename


def _write_uncompressed_capture(filename: str, packets: List, file_format: str):
    fmt = (file_format or 'pcap').strip().lower()
    if fmt == 'pcapng':
        writer = PcapNgWriter(filename)
        try:
            for pkt in packets:
                writer.write(pkt)
        finally:
            writer.close()
        return

    wrpcap(filename, packets)


def _packet_output_metadata(packet_number: int, metadata: CaptureMetadata | None) -> tuple[list[str], bytes | None]:
    if metadata is None:
        return [], None
    packet_comments = dict(getattr(metadata, 'packet_comments', {}) or {})
    comment = str(packet_comments.get(int(packet_number), '') or '').strip()
    comments = [comment] if comment else []

    packet_interfaces = dict(getattr(metadata, 'packet_interfaces', {}) or {})
    interface_id = packet_interfaces.get(int(packet_number), None)
    interface_name = ''
    if interface_id is not None:
        for interface in list(getattr(metadata, 'interfaces', []) or []):
            try:
                raw_interface_id = interface.get('interface_id', -1)
                parsed_interface_id = -1 if raw_interface_id is None else int(raw_interface_id)
                matches = parsed_interface_id == int(interface_id)
            except Exception:
                matches = False
            if not matches:
                continue
            interface_name = str(interface.get('name', '') or '').strip()
            if not interface_name:
                interface_name = str(interface.get('description', '') or '').strip()
            if not interface_name:
                interface_name = f'interface-{int(interface_id)}'
            break
    return comments, (interface_name.encode('utf-8') if interface_name else None)


def _write_uncompressed_capture_with_metadata(filename: str, packets: List, file_format: str, metadata: CaptureMetadata | None):
    fmt = str(file_format or '').strip().lower()
    if fmt == 'pcapng':
        writer = PcapNgWriter(filename)
        try:
            for packet_number, pkt in enumerate(list(packets or []), start=1):
                if not getattr(writer, 'header_present', False):
                    writer.header_present = True
                    writer._write_block_shb()
                    writer.interfaces2id = {b'__packetra_placeholder__': -1}
                raw_pkt = bytes(pkt)
                comments, ifname = _packet_output_metadata(packet_number, metadata)
                sec = float(getattr(pkt, 'time', 0.0) or 0.0)
                wirelen = int(getattr(pkt, 'wirelen', len(raw_pkt)) or len(raw_pkt))
                try:
                    linktype = conf.l2types.layer2num[pkt.__class__]
                except KeyError:
                    linktype = 1
                writer._write_packet(
                    raw_pkt,
                    linktype=linktype,
                    sec=sec,
                    caplen=len(raw_pkt),
                    wirelen=wirelen,
                    ifname=ifname,
                    comments=comments,
                )
        finally:
            writer.close()
        save_pcapng_capture_metadata(filename, metadata)
        return
    _write_uncompressed_capture(filename, packets, file_format)


def save_capture_file(filename: str, packets: List, file_format: str = 'pcap', compression: str = 'none') -> str:
    return save_capture_file_with_metadata(filename, packets, metadata=None, file_format=file_format, compression=compression)


def save_capture_file_with_metadata(
    filename: str,
    packets: List,
    metadata: CaptureMetadata | None = None,
    file_format: str = 'pcap',
    compression: str = 'none',
) -> str:
    """Save packets with explicit format/compression and return actual output path."""
    fmt = (file_format or 'pcap').strip().lower()
    comp = (compression or 'none').strip().lower()

    base_filename = normalize_capture_extension(filename, fmt)
    output_filename = apply_compression_suffix(base_filename, comp)

    if comp == 'none':
        _write_uncompressed_capture_with_metadata(output_filename, packets, fmt, metadata)
        return output_filename

    fd, temp_path = tempfile.mkstemp(suffix='.pcapng' if fmt == 'pcapng' else '.pcap')
    os.close(fd)
    try:
        _write_uncompressed_capture_with_metadata(temp_path, packets, fmt, metadata)

        if comp == 'gzip':
            with open(temp_path, 'rb') as src, gzip.open(output_filename, 'wb') as dst:
                while True:
                    chunk = src.read(1024 * 1024)
                    if not chunk:
                        break
                    dst.write(chunk)
            return output_filename

        if comp == 'lz4':
            try:
                import lz4.frame
            except Exception as exc:
                raise RuntimeError('LZ4 compression requested but lz4 package is not installed.') from exc

            with open(temp_path, 'rb') as src, open(output_filename, 'wb') as out_file:
                compressor = lz4.frame.LZ4FrameCompressor()
                out_file.write(compressor.begin())
                while True:
                    chunk = src.read(1024 * 1024)
                    if not chunk:
                        break
                    out_file.write(compressor.compress(chunk))
                out_file.write(compressor.flush())
            return output_filename

        raise ValueError(f'Unsupported compression: {comp}')
    finally:
        try:
            os.remove(temp_path)
        except OSError:
            pass


def save_pcap(filename, packets):
    """Backward-compatible save API (pcap, uncompressed)."""
    save_capture_file(filename, packets, file_format='pcap', compression='none')


def save_pcapng_file_comment(filename: str, comment: str) -> bool:
    """Persist file-level comment into a pcapng file."""
    if not filename or not filename.lower().endswith('.pcapng'):
        return False
    return PcapngFileWriter(filename).update_file_comment(comment)


def save_pcapng_packet_comments(filename: str, packet_comments: Dict[int, str]) -> bool:
    """Persist per-packet comments into a pcapng file."""
    if not filename or not filename.lower().endswith('.pcapng'):
        return False
    return PcapngFileWriter(filename).update_packet_comments(packet_comments or {})


def clone_capture_metadata(metadata: CaptureMetadata | None) -> CaptureMetadata:
    if not isinstance(metadata, CaptureMetadata):
        return CaptureMetadata()
    cloned = CaptureMetadata()
    cloned.file_comment = str(metadata.file_comment or '')
    cloned.section_hardware = str(metadata.section_hardware or '')
    cloned.section_os = str(metadata.section_os or '')
    cloned.section_application = str(metadata.section_application or '')
    cloned.interfaces = deepcopy(list(metadata.interfaces or []))
    cloned.packet_interfaces = dict(metadata.packet_interfaces or {})
    cloned.packet_comments = dict(metadata.packet_comments or {})
    return cloned


def save_pcapng_capture_metadata(filename: str, metadata: CaptureMetadata | None) -> bool:
    """Persist supported PCAPNG metadata after packet bytes are written.

    Currently supported:
    - file comment (SHB comment)
    - per-packet comments (EPB comments)

    Interface metadata is not rewritten here because the current writer only
    supports updating comments safely.
    """
    if not filename or not filename.lower().endswith('.pcapng'):
        return False
    if not isinstance(metadata, CaptureMetadata):
        return True
    ok = True
    ok = bool(save_pcapng_file_comment(filename, str(metadata.file_comment or ''))) and ok
    ok = bool(save_pcapng_packet_comments(filename, dict(metadata.packet_comments or {}))) and ok
    return ok


def load_capture_metadata(filename: str) -> CaptureMetadata:
    """Load capture metadata only (without loading all packets)."""
    metadata = CaptureMetadata()

    # Try to extract metadata from PCAPNG format
    try:
        normalized = str(filename or '').strip().lower()
        if normalized.endswith('.pcapng'):
            parser = PcapngParser(filename)
            pcapng_metadata = parser.parse()

            # Transfer metadata
            metadata.file_comment = pcapng_metadata.file_comment
            metadata.packet_interfaces = pcapng_metadata.packet_interfaces
            metadata.packet_comments = pcapng_metadata.packet_comments

            # Convert interface info to dict format for easier access
            for iface in pcapng_metadata.interfaces:
                link_type_name = PcapngParser.get_link_type_name(iface.link_type)

                # Get snaplen in bytes - handle both string and int formats
                snaplen_bytes = iface.snaplen
                if isinstance(snaplen_bytes, str):
                    try:
                        snaplen_bytes = int(snaplen_bytes)
                    except Exception:
                        snaplen_bytes = 262144  # default

                snaplen_str = f'{snaplen_bytes} bytes' if snaplen_bytes > 0 else 'Unknown'

                # Get interface name - prefer non-empty
                iface_name = iface.name.strip() if iface.name else '-'
                if not iface_name:
                    iface_name = '-'

                # Get description - prefer non-empty, fallback to Unknown
                iface_desc = iface.description.strip() if iface.description else ''
                if not iface_desc:
                    iface_desc = 'Unknown'

                # Get capture filter - handle both cases
                capture_filter = iface.capture_filter.strip() if iface.capture_filter else 'none'
                if not capture_filter:
                    capture_filter = 'none'

                metadata.interfaces.append({
                    'interface_id': iface.interface_id,
                    'name': iface_name,
                    'description': iface_desc,
                    'comment': iface.comment if iface.comment else 'Unknown',
                    'dropped_packets': str(iface.dropped_count) if iface.dropped_count > 0 else 'Unknown',
                    'capture_filter': capture_filter,
                    'link_type': link_type_name,
                    'snaplen': snaplen_str,
                    'ipv4_addr': iface.ipv4_addr,
                    'ipv6_addr': iface.ipv6_addr,
                    'mac_addr': iface.mac_addr,
                    'speed': iface.speed,
                    'os': iface.os,
                    'hardware': iface.hardware,
                })

            metadata.section_hardware = (pcapng_metadata.section_hardware or '').strip()
            metadata.section_os = (pcapng_metadata.section_os or '').strip()
            metadata.section_application = (pcapng_metadata.section_application or '').strip()
    except Exception as e:
        # If pcapng parsing fails, continue with packets only
        print(f'Warning: Could not extract pcapng metadata: {e}')

    return metadata


def iter_pcap_packets(filename: str):
    """Stream packets from capture file to avoid full-file preload latency."""
    reader = PcapReader(filename)
    try:
        for packet in reader:
            yield packet
    finally:
        try:
            reader.close()
        except Exception:
            pass


def load_pcap(filename) -> Tuple:
    """Backward-compatible full load API."""
    packets = rdpcap(filename)
    metadata = load_capture_metadata(filename)
    return packets, metadata


def get_pcap_packet_count(filename: str) -> int:
    """Quickly count the packets in a pcap or pcapng file without full parsing."""
    try:
        with open(filename, 'rb') as f:
            magic = f.read(4)
            if len(magic) < 4:
                return 0
            
            # PCAPNG
            if magic == b'\x0a\x0d\x0d\x0a' or magic == b'\x0a\x0d\x0d\x0a'[::-1]:
                parser = PcapngParser(filename)
                parser.parse()
                return parser.packet_count
            
            # Classic PCAP
            if magic in (b'\xa1\xb2\xc3\xd4', b'\xd4\xc3\xb2\xa1', b'\xa1\xb2\x3c\x4d', b'\x4d\x3c\xb2\xa1'):
                f.seek(24)
                count = 0
                is_little = magic in (b'\xd4\xc3\xb2\xa1', b'\x4d\x3c\xb2\xa1')
                endian = 'little' if is_little else 'big'
                while True:
                    header = f.read(16)
                    if len(header) < 16:
                        break
                    incl_len = int.from_bytes(header[8:12], endian)
                    if incl_len < 0:
                        break
                    f.seek(incl_len, 1)
                    count += 1
                return count
    except Exception:
        pass
    return 0
