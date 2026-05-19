"""
PCAPNG format parser for extracting metadata.
Reads Section Header Block (SHB), Interface Description Blocks (IDB), 
and Enhanced Packet Block (EPB) metadata.
"""
import struct
import io
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class InterfaceInfo:
    """Metadata for a single interface from IDB (Interface Description Block)."""
    interface_id: int
    link_type: int
    snaplen: int
    name: str = ''
    description: str = ''
    comment: str = ''
    ipv4_addr: str = ''
    ipv6_addr: str = ''
    mac_addr: str = ''
    speed: str = ''
    timestamp_resolution: str = ''
    timezone: str = ''
    os: str = ''
    hardware: str = ''
    dropped_count: int = 0
    capture_filter: str = ''


@dataclass
class PcapngMetadata:
    """Extracted metadata from PCAPNG file."""
    file_comment: str = ''
    section_hardware: str = ''
    section_os: str = ''
    section_application: str = ''
    interfaces: List[InterfaceInfo] = field(default_factory=list)
    packet_interfaces: Dict[int, int] = field(default_factory=dict)  # packet_number -> interface_id
    packet_comments: Dict[int, str] = field(default_factory=dict)  # packet_number -> comment


class PcapngParser:
    """Parse PCAPNG format and extract metadata (comments, interfaces, etc)."""
    
    # Block type constants
    BLOCK_SHB = 0x0A0D0D0A  # Section Header Block
    BLOCK_IDB = 0x00000001  # Interface Description Block
    BLOCK_EPB = 0x00000006  # Enhanced Packet Block
    
    # Option type constants (used in TLV options)
    OPT_ENDOFOPT = 0
    OPT_COMMENT = 1
    SHB_OPT_HARDWARE = 2
    SHB_OPT_OS = 3
    SHB_OPT_USERAPPL = 4
    
    # IDB option types (per pcapng spec)
    IDB_OPT_ENDOFOPT = 0
    IDB_OPT_COMMENT = 1
    IDB_OPT_NAME = 2
    IDB_OPT_DESCRIPTION = 3
    IDB_OPT_IPv4ADDR = 4
    IDB_OPT_IPv6ADDR = 5
    IDB_OPT_MACADDR = 6
    IDB_OPT_SPEED = 7
    IDB_OPT_TSRESOL = 8
    IDB_OPT_TIMEZONE = 9
    IDB_OPT_FILTER = 10  # Capture filter
    IDB_OPT_OS = 11
    IDB_OPT_FCSLEN = 12
    IDB_OPT_TSOFFSET = 13
    IDB_OPT_HARDWARE = 14
    
    # EPB option types
    EPB_OPT_ENDOFOPT = 0
    EPB_OPT_FLAGS = 2
    EPB_OPT_DROPCOUNT = 4
    EPB_OPT_PACKETID = 5
    EPB_OPT_QUEUE = 6
    EPB_OPT_VERDICT = 7
    EPB_OPT_COMMENT = 1
    
    def __init__(self, filename: str):
        self.filename = filename
        self.metadata = PcapngMetadata()
        self.packet_count = 0
        self.byte_order = '<'  # little-endian by default
        
    def parse(self) -> PcapngMetadata:
        """Parse PCAPNG file and extract metadata."""
        try:
            with open(self.filename, 'rb') as f:
                self._parse_file(f)
        except (IOError, struct.error) as e:
            print(f"Error parsing pcapng file: {e}")
        return self.metadata
    
    def _parse_file(self, f):
        """Read and parse PCAPNG blocks from file."""
        byte_order_detected = False
        
        while True:
            # Read block type (4 bytes) - always in file's native byte order
            block_type_bytes = f.read(4)
            if len(block_type_bytes) < 4:
                break
            
            # Try both byte orders for the first block to auto-detect
            try:
                block_type = struct.unpack(self.byte_order + 'I', block_type_bytes)[0]
            except:
                block_type = 0
            
            # Read block length (4 bytes)
            block_len_bytes = f.read(4)
            if len(block_len_bytes) < 4:
                break
            
            try:
                block_len = struct.unpack(self.byte_order + 'I', block_len_bytes)[0]
            except:
                block_len = 0
            
            # Read block data (block_len - 12 bytes, since we read 8 bytes already)
            block_data_len = block_len - 12
            if block_data_len < 0 or block_data_len > 100_000_000:  # Sanity check
                break
                
            block_data = f.read(block_data_len)
            if len(block_data) < block_data_len:
                break
            
            # Read end block length (4 bytes)
            end_len_bytes = f.read(4)
            if len(end_len_bytes) < 4:
                break
            
            # Determine byte order from first SHB if not detected yet
            if not byte_order_detected and block_type in (self.BLOCK_SHB, 0x0A0D0D0A):
                # Check magic number in SHB to determine byte order
                if len(block_data) >= 4:
                    magic_le = struct.unpack('<I', block_data[0:4])[0]
                    magic_be = struct.unpack('>I', block_data[0:4])[0]
                    
                    if magic_le == 0x1A2B3C4D:
                        self.byte_order = '<'
                        byte_order_detected = True
                    elif magic_be == 0x1A2B3C4D:
                        self.byte_order = '>'
                        byte_order_detected = True
                    
                    # Re-read block type and length with correct byte order
                    block_type = struct.unpack(self.byte_order + 'I', block_type_bytes)[0]
                    block_len = struct.unpack(self.byte_order + 'I', block_len_bytes)[0]
            
            # Parse specific block types
            if block_type == self.BLOCK_SHB:
                self._parse_shb(block_data)
            elif block_type == self.BLOCK_IDB:
                self._parse_idb(block_data)
            elif block_type == self.BLOCK_EPB:
                self._parse_epb(block_data)
    
    def _parse_shb(self, data: bytes):
        """Parse Section Header Block to extract file-level comment."""
        if len(data) < 8:
            return
        
        # SHB structure: magic (4), major_version (2), minor_version (2), section_length (8)
        # Then options (TLV)
        options_start = 16
        if len(data) >= options_start:
            self._parse_options(data[options_start:], 'shb')
    
    def _parse_idb(self, data: bytes):
        """Parse Interface Description Block to extract interface metadata."""
        if len(data) < 8:
            return
        
        interface_id = len(self.metadata.interfaces)
        
        # IDB structure: link_type (2), reserved (2), snaplen (4), then options (TLV)
        link_type = struct.unpack(self.byte_order + 'H', data[0:2])[0]
        snaplen = struct.unpack(self.byte_order + 'I', data[4:8])[0]
        
        iface_info = InterfaceInfo(
            interface_id=interface_id,
            link_type=link_type,
            snaplen=snaplen
        )
        
        # Parse options
        options_start = 8
        if len(data) > options_start:
            option_data = data[options_start:]
            self._parse_idb_options(option_data, iface_info)
        
        self.metadata.interfaces.append(iface_info)
    
    def _parse_epb(self, data: bytes):
        """Parse Enhanced Packet Block to extract packet-level comment."""
        if len(data) < 20:
            return
        
        # EPB structure: interface_id (4), timestamp_high (4), timestamp_low (4),
        # captured_len (4), packet_len (4), packet_data, options
        interface_id = struct.unpack(self.byte_order + 'I', data[0:4])[0]
        captured_len = struct.unpack(self.byte_order + 'I', data[12:16])[0]
        packet_number = self.packet_count + 1
        self.metadata.packet_interfaces[packet_number] = interface_id
        
        # Packet data starts at offset 20, ends at 20 + captured_len
        # Options start after packet data (with padding to 4-byte boundary)
        packet_end = 20 + captured_len
        # Align to 4-byte boundary
        options_start = (packet_end + 3) & ~3
        
        if options_start <= len(data):
            option_data = data[options_start:]
            self._parse_epb_options(option_data, packet_number, interface_id)
        
        self.packet_count += 1
    
    def _parse_options(self, data: bytes, block_type: str):
        """Parse TLV options for SHB."""
        offset = 0
        while offset + 4 <= len(data):
            opt_type = struct.unpack(self.byte_order + 'H', data[offset:offset+2])[0]
            opt_len = struct.unpack(self.byte_order + 'H', data[offset+2:offset+4])[0]
            
            if opt_type == self.OPT_ENDOFOPT:
                break
            
            opt_value_start = offset + 4
            opt_value_end = opt_value_start + opt_len
            
            if opt_value_end <= len(data):
                opt_value = data[opt_value_start:opt_value_end]
                if opt_type == self.OPT_COMMENT:
                    try:
                        self.metadata.file_comment = opt_value.decode('utf-8', errors='replace')
                    except:
                        pass
                elif block_type == 'shb' and opt_type == self.SHB_OPT_HARDWARE:
                    try:
                        self.metadata.section_hardware = opt_value.decode('utf-8', errors='replace')
                    except:
                        pass
                elif block_type == 'shb' and opt_type == self.SHB_OPT_OS:
                    try:
                        self.metadata.section_os = opt_value.decode('utf-8', errors='replace')
                    except:
                        pass
                elif block_type == 'shb' and opt_type == self.SHB_OPT_USERAPPL:
                    try:
                        self.metadata.section_application = opt_value.decode('utf-8', errors='replace')
                    except:
                        pass
            
            # Move to next option (accounting for 4-byte alignment)
            offset = opt_value_end + (4 - (opt_len % 4)) % 4
    
    def _parse_idb_options(self, data: bytes, iface_info: InterfaceInfo):
        """Parse TLV options for IDB (Interface Description Block)."""
        offset = 0
        while offset + 4 <= len(data):
            opt_type = struct.unpack(self.byte_order + 'H', data[offset:offset+2])[0]
            opt_len = struct.unpack(self.byte_order + 'H', data[offset+2:offset+4])[0]
            
            if opt_type == self.IDB_OPT_ENDOFOPT:
                break
            
            opt_value_start = offset + 4
            opt_value_end = opt_value_start + opt_len
            
            if opt_value_end <= len(data):
                opt_value = data[opt_value_start:opt_value_end]
                
                if opt_type == self.IDB_OPT_NAME:
                    try:
                        iface_info.name = opt_value.decode('utf-8', errors='replace')
                    except:
                        pass
                elif opt_type == self.IDB_OPT_DESCRIPTION:
                    try:
                        iface_info.description = opt_value.decode('utf-8', errors='replace')
                    except:
                        pass
                elif opt_type == self.IDB_OPT_COMMENT:
                    try:
                        iface_info.comment = opt_value.decode('utf-8', errors='replace')
                    except:
                        pass
                elif opt_type == self.IDB_OPT_FILTER:
                    try:
                        # Filter option: first byte is filter type, rest is filter string
                        if len(opt_value) > 1:
                            filter_str = opt_value[1:].decode('utf-8', errors='replace').strip()
                            if filter_str:
                                iface_info.capture_filter = filter_str
                            else:
                                iface_info.capture_filter = 'none'
                        else:
                            iface_info.capture_filter = 'none'
                    except:
                        iface_info.capture_filter = 'none'
                elif opt_type == self.IDB_OPT_IPv4ADDR and len(opt_value) >= 4:
                    try:
                        iface_info.ipv4_addr = '.'.join(str(b) for b in opt_value[:4])
                    except:
                        pass
                elif opt_type == self.IDB_OPT_IPv6ADDR and len(opt_value) >= 16:
                    try:
                        parts = [hex(struct.unpack(self.byte_order + 'H', opt_value[i:i+2])[0]) for i in range(0, 16, 2)]
                        iface_info.ipv6_addr = ':'.join(parts)
                    except:
                        pass
                elif opt_type == self.IDB_OPT_MACADDR and len(opt_value) >= 6:
                    try:
                        iface_info.mac_addr = ':'.join(f'{b:02x}' for b in opt_value[:6])
                    except:
                        pass
                elif opt_type == self.IDB_OPT_SPEED:
                    try:
                        speed_bps = struct.unpack(self.byte_order + 'Q', opt_value[:8])[0] if len(opt_value) >= 8 else 0
                        iface_info.speed = f'{speed_bps // 1_000_000} Mbps' if speed_bps > 0 else ''
                    except:
                        pass
                elif opt_type == self.IDB_OPT_OS:
                    try:
                        iface_info.os = opt_value.decode('utf-8', errors='replace')
                    except:
                        pass
                elif opt_type == self.IDB_OPT_HARDWARE:
                    try:
                        iface_info.hardware = opt_value.decode('utf-8', errors='replace')
                    except:
                        pass
            
            # Move to next option (accounting for 4-byte alignment)
            offset = opt_value_end + (4 - (opt_len % 4)) % 4
    
    def _parse_epb_options(self, data: bytes, packet_number: int, interface_id: int):
        """Parse TLV options for EPB (Enhanced Packet Block)."""
        offset = 0
        while offset + 4 <= len(data):
            opt_type = struct.unpack(self.byte_order + 'H', data[offset:offset+2])[0]
            opt_len = struct.unpack(self.byte_order + 'H', data[offset+2:offset+4])[0]
            
            if opt_type == self.EPB_OPT_ENDOFOPT:
                break
            
            opt_value_start = offset + 4
            opt_value_end = opt_value_start + opt_len
            
            if opt_value_end <= len(data):
                opt_value = data[opt_value_start:opt_value_end]
                if opt_type == self.EPB_OPT_COMMENT:
                    try:
                        comment = opt_value.decode('utf-8', errors='replace')
                        self.metadata.packet_comments[packet_number] = comment
                    except:
                        pass
                elif opt_type == self.EPB_OPT_DROPCOUNT:
                    try:
                        drop_count = struct.unpack(self.byte_order + 'Q', opt_value[:8])[0] if len(opt_value) >= 8 else 0
                        if 0 <= interface_id < len(self.metadata.interfaces):
                            self.metadata.interfaces[interface_id].dropped_count += int(drop_count)
                    except:
                        pass
            
            # Move to next option (accounting for 4-byte alignment)
            offset = opt_value_end + (4 - (opt_len % 4)) % 4
    
    @staticmethod
    def get_link_type_name(link_type: int) -> str:
        """Convert link_type number to human-readable name."""
        link_types = {
            0: 'NULL',
            1: 'Ethernet',
            2: 'Token Ring',
            3: 'ARCNET',
            4: 'Slip',
            5: 'PPP',
            6: 'FDDI',
            7: 'PPP HDH',
            8: 'PPPover Ether',
            9: 'ATM RFC1483',
            10: 'Raw',
            11: 'Slip Bsdos',
            12: 'PPP BSD',
            13: 'IPv4',
            14: 'IPv6',
            15: 'HIPL',
            16: 'DOCSIS',
            17: 'Linux LLC',
            18: 'Linux SLL',
            19: 'LocalTalk',
            20: 'CAN',
            21: 'InfoCom',
            22: 'PFLog',
            23: 'Cisco HDLC',
            24: 'IEEE 802.11',
            25: 'FreeBSD Bluetooth',
            26: 'MTP2',
            27: 'MTP3',
            28: 'SCCP',
            29: 'Docsis30',
            30: 'A429',
            31: 'A653 ICE',
            32: 'USB',
            33: 'Bluetooth HCI UART',
            34: 'IEEE 802.16 MAC CPS',
            35: 'USB Linux',
            36: 'CAN socketcan',
            37: 'Raw AFT',
            38: 'IPNET',
            39: 'CAN FD socketcan',
            40: 'DAbus',
            41: 'IPMB',
            42: 'AX.25',
            43: 'RAWHDLC',
            44: 'IEEE 802.3br mPackets',
            45: 'TypeScript',
            46: 'Netlink',
            47: 'Netfilter NFLOG',
            48: 'NETANALYZER',
            49: 'NETANALYZER transparent',
            50: 'IPOIB',
            51: 'MPEG2 TS',
            52: 'NG40',
            53: 'NFC LLCP',
            54: 'Netfilter LOG',
            55: 'Linux cooked-mode capture v1',
            56: 'Netfilter LOG',
            57: 'GSM Um',
            58: 'GMMPOP2',
            59: 'TUN TAP',
            60: 'GSM Um MUX',
            61: 'RF4FF',
            62: 'Bluetooth monitormode',
            63: 'IEEE 802.15.4 TAP',
            64: 'Microwave oven (real)',
            65: 'Ethernet transparent',
            66: 'IP',
            67: 'IEEE 802.11 redcap',
            68: 'GMMPOP',
            69: 'Raw IP',
            70: 'LOWPAN',
            71: 'LAPD',
            72: 'PPP with direction',
            73: 'GPRS LLC',
            74: 'LIN',
            75: 'Netlink',
            76: 'Linux evdev',
            77: 'OpenBSD pflog',
            78: 'CAN with FD',
            79: 'Data plane driver',
            80: 'GMMP',
            81: 'FC-2',
            82: 'SERIAL',
            83: 'Netlink',
            84: 'ISO 14443-4',
            85: 'OpenBSD pflog',
            86: 'Raw USB packets',
            87: 'NFLOG',
            88: 'NETLINK',
            89: 'Bluetooth Linux-Bluetooth',
            90: 'Bluetooth Linux-Monitor',
            91: 'Bluetooth Linux-Bredr',
            92: 'Bluetooth Linux-LE',
            93: 'pflog',
            94: 'IEEE 802.11 ax',
            95: 'NETLINK netfilter',
            96: 'Microwave oven (emulated)',
            97: 'ERF',
            98: 'Linux SLL',
            101: 'Raw IP',
            104: 'Fddi',
            105: 'USB audio',
            106: 'CVNET',
            107: 'Bluetooth monitormode',
            108: 'NETLINK nl80211',
            110: 'IEEE 802.11 Radiotap',
            112: 'CAIF',
            113: 'Linux cooked-mode capture v1',
            114: 'IEEE 802.15.4 nonASF',
            115: 'Raw AFT',
            116: 'ISO 14443-4',
            117: 'Raw IP',
            118: 'Linux SLL',
            119: 'Freescale FLEXRAY',
            120: 'Linux GPIO Bitbang',
            121: 'MXP2',
            122: 'Serial win',
            123: 'SLL Linux cooked',
            124: 'NETLINK',
            125: 'IEEE 802.15.4 Tap',
            126: 'Bus for Linux',
            127: 'Netfilter LOG',
            128: 'Canary',
            129: 'Raw IP',
            130: 'IEEE 802.11 Radiotap',
            131: 'RFC 7468 CBOR',
            132: 'Raw IP raw',
            147: 'Linux SLL',
            148: 'OpenBSD pflog',
            160: 'Linux SLL',
            162: 'NETLINK',
            163: 'Linux SLL',
            274: 'IEEE 802.3br mPackets',
        }
        return link_types.get(link_type, f'Unknown ({link_type})')


class PcapngFileWriter:
    """Write/update comments in PCAPNG files."""
    
    BLOCK_SHB = 0x0A0D0D0A
    OPT_COMMENT = 1
    OPT_ENDOFOPT = 0
    
    def __init__(self, filename: str):
        self.filename = filename
        self.byte_order = '<'
    
    def update_file_comment(self, new_comment: str) -> bool:
        """Update file-level comment in PCAPNG file."""
        try:
            with open(self.filename, 'rb') as f:
                file_data = f.read()
            
            if len(file_data) < 8:
                return False
            
            # Parse and update SHB safely
            new_data = self._update_shb_in_data(file_data, new_comment)
            if not new_data:
                return False
            
            # Write back
            with open(self.filename, 'w+b') as f:
                f.write(new_data)
            
            return True
        except Exception as e:
            print(f"Error updating PCAPNG file: {e}")
            return False
    
    def _update_shb_in_data(self, data: bytes, new_comment: str) -> bytes:
        """Update SHB comment in file data with valid block lengths and alignment."""
        if len(data) < 32:
            return b''

        block_type = struct.unpack('<I', data[0:4])[0]
        if block_type != self.BLOCK_SHB:
            return b''

        byte_order = None
        old_block_len = 0
        for candidate in ('<', '>'):
            try:
                test_len = struct.unpack(candidate + 'I', data[4:8])[0]
            except Exception:
                continue
            if test_len < 28 or test_len > len(data):
                continue
            trailer = data[test_len - 4:test_len]
            if trailer != struct.pack(candidate + 'I', test_len):
                continue
            body = data[8:test_len - 4]
            if len(body) >= 4 and struct.unpack(candidate + 'I', body[0:4])[0] == 0x1A2B3C4D:
                byte_order = candidate
                old_block_len = test_len
                break

        if not byte_order:
            return b''

        body = data[8:old_block_len - 4]
        if len(body) < 16:
            return b''

        fixed_header = body[:16]
        options = body[16:]

        # Keep all SHB options except existing comment.
        rebuilt_options = bytearray()
        offset = 0
        while offset + 4 <= len(options):
            opt_type = struct.unpack(byte_order + 'H', options[offset:offset + 2])[0]
            opt_len = struct.unpack(byte_order + 'H', options[offset + 2:offset + 4])[0]
            if opt_type == self.OPT_ENDOFOPT:
                break

            value_start = offset + 4
            value_end = value_start + opt_len
            if value_end > len(options):
                break

            if opt_type != self.OPT_COMMENT:
                rebuilt_options.extend(options[offset:offset + 4])
                rebuilt_options.extend(options[value_start:value_end])
                padding = (4 - (opt_len % 4)) % 4
                if padding:
                    rebuilt_options.extend(b'\x00' * padding)

            offset = value_end + ((4 - (opt_len % 4)) % 4)

        comment_bytes = (new_comment or '').encode('utf-8')
        if comment_bytes:
            rebuilt_options.extend(struct.pack(byte_order + 'HH', self.OPT_COMMENT, len(comment_bytes)))
            rebuilt_options.extend(comment_bytes)
            padding = (4 - (len(comment_bytes) % 4)) % 4
            if padding:
                rebuilt_options.extend(b'\x00' * padding)

        rebuilt_options.extend(struct.pack(byte_order + 'HH', self.OPT_ENDOFOPT, 0))

        new_body = fixed_header + bytes(rebuilt_options)
        new_block_len = 8 + len(new_body) + 4
        if new_block_len % 4 != 0:
            pad = 4 - (new_block_len % 4)
            new_body += b'\x00' * pad
            new_block_len += pad

        new_shb = bytearray()
        new_shb.extend(data[0:4])
        new_shb.extend(struct.pack(byte_order + 'I', new_block_len))
        new_shb.extend(new_body)
        new_shb.extend(struct.pack(byte_order + 'I', new_block_len))

        return bytes(new_shb) + data[old_block_len:]
