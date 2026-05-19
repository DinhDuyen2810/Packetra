import gzip
import os
import tempfile
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from scapy.all import ARP, Ether, bind_layers, rdpcap, wrpcap
from scapy.utils import PcapNgWriter

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


def save_capture_file(filename: str, packets: List, file_format: str = 'pcap', compression: str = 'none') -> str:
    """Save packets with explicit format/compression and return actual output path."""
    fmt = (file_format or 'pcap').strip().lower()
    comp = (compression or 'none').strip().lower()

    base_filename = normalize_capture_extension(filename, fmt)
    output_filename = apply_compression_suffix(base_filename, comp)

    if comp == 'none':
        _write_uncompressed_capture(output_filename, packets, fmt)
        return output_filename

    fd, temp_path = tempfile.mkstemp(suffix='.pcapng' if fmt == 'pcapng' else '.pcap')
    os.close(fd)
    try:
        _write_uncompressed_capture(temp_path, packets, fmt)

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


def load_pcap(filename) -> Tuple:
    """Load PCAP/PCAPNG file and extract packets + metadata.

    Returns:
        (packets, metadata) where metadata contains file_comment, interfaces, packet_comments
    """
    packets = rdpcap(filename)
    metadata = CaptureMetadata()

    # Try to extract metadata from PCAPNG format
    try:
        if filename.lower().endswith(('.pcapng', '.pcap')):
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

    return packets, metadata
