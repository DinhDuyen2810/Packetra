import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple
from scapy.all import rdpcap, wrpcap
from utils.pcapng_parser import PcapngParser, PcapngMetadata, PcapngFileWriter


@dataclass
class CaptureMetadata:
    """Metadata extracted from capture file."""
    file_comment: str = ''
    section_hardware: str = ''
    section_os: str = ''
    section_application: str = ''
    interfaces: List[Dict] = field(default_factory=list)
    packet_comments: Dict[int, str] = field(default_factory=dict)


def save_pcap(filename, packets):
    wrpcap(filename, packets)


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
            metadata.packet_comments = pcapng_metadata.packet_comments
            
            # Convert interface info to dict format for easier access
            for iface in pcapng_metadata.interfaces:
                link_type_name = PcapngParser.get_link_type_name(iface.link_type)
                
                # Get snaplen in bytes - handle both string and int formats
                snaplen_bytes = iface.snaplen
                if isinstance(snaplen_bytes, str):
                    try:
                        snaplen_bytes = int(snaplen_bytes)
                    except:
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
        print(f"Warning: Could not extract pcapng metadata: {e}")
    
    return packets, metadata

