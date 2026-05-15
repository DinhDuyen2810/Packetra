import logging
import os
import time
from PySide6.QtCore import QThread, Signal
from scapy.all import Ether, Raw, sniff
from scapy.utils import RawPcapNgReader, RawPcapReader

log = logging.getLogger('capture')

class PacketSniffer(QThread):
    packet_captured = Signal(object)
    error_occurred = Signal(str)
    status_changed = Signal(str)

    def __init__(self, iface: str, capture_filter: str = ''):
        super().__init__()
        self.iface = iface
        self.capture_filter = (capture_filter or '').strip()
        self.running = True
        self._stream = None
        self._reader = None

    def run(self):
        self.status_changed.emit(f'Capturing on {self.iface}')
        try:
            if self._is_pipe_interface(self.iface):
                self._capture_from_pipe()
            else:
                while self.running:
                    sniff(
                        iface=self.iface,
                        prn=self.handle_packet,
                        store=False,
                        timeout=0.2,
                        filter=self.capture_filter or None,
                    )
        except Exception as exc:
            msg = f'Capture failed on {self.iface}: {exc}'
            log.exception(msg)
            self.error_occurred.emit(msg)
        finally:
            self._close_pipe_resources()
            self.status_changed.emit('Capture stopped')

    def _is_pipe_interface(self, iface: str) -> bool:
        return str(iface or '').lower().startswith('\\\\.\\pipe\\')

    def _capture_from_pipe(self):
        if self.capture_filter:
            self.status_changed.emit('Pipe capture ignores local capture filter; source process controls filtering')

        self.status_changed.emit(f'Connecting to pipe {self.iface}')
        self._stream = self._open_windows_pipe_stream(self.iface)

        magic = self._stream.read(4)
        if len(magic) < 4:
            raise RuntimeError('Named pipe closed before a capture header was received')

        if magic == b'\x0a\x0d\x0d\x0a':
            self._reader = RawPcapNgReader.__new__(RawPcapNgReader)
            RawPcapNgReader.__init__(self._reader, self.iface, self._stream, magic)
        else:
            self._reader = RawPcapReader.__new__(RawPcapReader)
            RawPcapReader.__init__(self._reader, self.iface, self._stream, magic)

        self.status_changed.emit(f'Capturing from pipe {self.iface}')
        while self.running:
            try:
                packet_data = self._reader._read_packet()
            except EOFError:
                break
            except Exception as exc:
                raise RuntimeError(f'Invalid PCAP stream from {self.iface}: {exc}') from exc

            if packet_data is None:
                break

            packet = self._decode_pipe_packet(packet_data)
            self.handle_packet(packet)

        if self.running:
            self.status_changed.emit(f'Pipe source closed: {self.iface}')

    def _open_windows_pipe_stream(self, pipe_name: str):
        try:
            import msvcrt
            import win32file
            import win32pipe
            import pywintypes
        except Exception as exc:
            raise RuntimeError('Named pipe capture on Windows requires pywin32') from exc

        deadline = time.time() + 10.0
        while self.running:
            try:
                handle = win32file.CreateFile(
                    pipe_name,
                    win32file.GENERIC_READ,
                    0,
                    None,
                    win32file.OPEN_EXISTING,
                    0,
                    None,
                )
                fd = msvcrt.open_osfhandle(int(handle.Detach()), os.O_RDONLY | os.O_BINARY)
                return os.fdopen(fd, 'rb', buffering=0)
            except pywintypes.error as exc:
                if exc.winerror not in (2, 231):
                    raise RuntimeError(f'Cannot open named pipe {pipe_name}: {exc}') from exc
                remaining_ms = max(0, int((deadline - time.time()) * 1000))
                if remaining_ms <= 0:
                    raise RuntimeError(f'Cannot open named pipe {pipe_name}: timeout waiting for server') from exc
                try:
                    win32pipe.WaitNamedPipe(pipe_name, min(500, remaining_ms))
                except pywintypes.error:
                    time.sleep(0.1)
            except OSError as exc:
                raise RuntimeError(f'Cannot open named pipe {pipe_name}: {exc}') from exc

        raise RuntimeError(f'Capture stopped before named pipe {pipe_name} was opened')

    def _decode_pipe_packet(self, packet_data):
        raw_bytes, metadata = packet_data
        linktype = getattr(metadata, 'linktype', getattr(self._reader, 'linktype', 1))

        if int(linktype or 1) == 1:
            packet = Ether(raw_bytes)
        else:
            packet = Raw(raw_bytes)

        timestamp = self._packet_timestamp(metadata)
        if timestamp is not None:
            packet.time = timestamp

        return packet

    def _packet_timestamp(self, metadata):
        if hasattr(metadata, 'sec') and hasattr(metadata, 'usec'):
            return float(metadata.sec) + (float(metadata.usec) / 1_000_000.0)

        if hasattr(metadata, 'tshigh') and hasattr(metadata, 'tslow') and hasattr(metadata, 'tsresol'):
            raw_ts = (int(metadata.tshigh) << 32) | int(metadata.tslow)
            resolution = int(metadata.tsresol) or 1_000_000
            return float(raw_ts) / float(resolution)

        return None

    def handle_packet(self, packet):

        if not self.running:
            return

        # ---- preserve interface metadata ----

        if not hasattr(packet, 'sniffed_on') or not packet.sniffed_on:
            packet.sniffed_on = self.iface

        # optional aliases for formatter
        packet.interface_name = packet.sniffed_on
        packet.interface_description = 'Named Pipe' if self._is_pipe_interface(self.iface) else 'Ethernet'

        self.packet_captured.emit(packet)

    def _close_pipe_resources(self):
        reader = self._reader
        self._reader = None
        if reader is not None:
            try:
                reader.close()
            except Exception:
                pass

        stream = self._stream
        self._stream = None
        if stream is not None:
            try:
                stream.close()
            except Exception:
                pass

    def stop(self):
        self.running = False
        self._close_pipe_resources()
