import logging
import os
import time
import json
import select
from urllib.parse import unquote
from PySide6.QtCore import QThread, Signal
from PySide6.QtCore import QSettings
from scapy.all import Ether, Raw, sniff
from scapy.utils import RawPcapNgReader, RawPcapReader

from core.remote_capture import SSHRemoteCapture

log = logging.getLogger('capture')


class _ChannelStream:
    """File-like wrapper over Paramiko channel for streaming PCAP bytes."""

    def __init__(self, channel, is_running):
        self._channel = channel
        self._is_running = is_running
        self._buffer = bytearray()

    def read(self, size=-1):
        if size == 0:
            return b''

        if size is None or size < 0:
            chunks = [bytes(self._buffer)] if self._buffer else []
            self._buffer.clear()
            while self._is_running():
                if self._channel.recv_ready():
                    data = self._channel.recv(65536)
                    if not data:
                        break
                    chunks.append(data)
                    continue
                if self._channel.exit_status_ready():
                    break
                time.sleep(0.01)
            return b''.join(chunks)

        while len(self._buffer) < size and self._is_running():
            if self._channel.recv_ready():
                data = self._channel.recv(max(1, min(65536, size - len(self._buffer))))
                if not data:
                    break
                self._buffer.extend(data)
                continue
            if self._channel.exit_status_ready():
                break
            time.sleep(0.01)

        if not self._buffer:
            return b''

        out = bytes(self._buffer[:size])
        del self._buffer[:size]
        return out

    def close(self):
        self._buffer.clear()

class RemotePacketSniffer(QThread):
    packet_captured = Signal(object)
    error_occurred = Signal(str)
    status_changed = Signal(str)

    def __init__(self, iface: str, capture_filter: str = ''):
        super().__init__()
        self.iface = iface
        self.capture_filter = (capture_filter or '').strip()
        self.running = True
        self._reader = None
        self._ssh = None
        self._channel = None

    def run(self):
        self.status_changed.emit(f'Capturing on remote {self.iface}')
        try:
            # Parse remote info: remote://user@host:port/iface
            import re
            m = re.match(r'remote://([^@]+)@([^:/]+):(\d+)/(.*)', self.iface)
            if not m:
                raise RuntimeError('Invalid remote interface string')
            username, host, port, iface = unquote(m.group(1)), m.group(2), int(m.group(3)), unquote(m.group(4))

            remote_cfg = self._find_remote_config(host, port, username, iface)
            if remote_cfg is None:
                raise RuntimeError(f'Remote host config not found for {username}@{host}:{port}')

            auth_type = str(remote_cfg.get('auth_type', 'Null'))
            password = str(remote_cfg.get('password', '') or '') if auth_type == 'Password' else None
            os_type = str(remote_cfg.get('os_type', 'linux')).lower()

            self._ssh = SSHRemoteCapture(
                host=host,
                port=port,
                username=username,
                password=password,
                key_path=None,
                os_type=os_type,
                auth_type=auth_type,
            )
            target_iface = str(remote_cfg.get('target', iface)).strip() or iface
            self._channel = self._ssh.start_capture(target_iface, self.capture_filter)
            stream = _ChannelStream(self._channel, lambda: self.running)
            # Read first 4 bytes to detect PCAP/PCAPNG
            magic = stream.read(4)
            if len(magic) < 4:
                if not self.running:
                    return
                stderr_text = self._read_channel_stderr(timeout_sec=0.8)
                stdout_text = self._read_channel_stdout(timeout_sec=0.8)
                if stderr_text:
                    raise RuntimeError(f'Remote closed before capture header. Remote error: {stderr_text}')
                if stdout_text:
                    raise RuntimeError(f'Remote closed before capture header. Remote output: {stdout_text}')
                raise RuntimeError('Remote closed before a capture header was received')

            # Detect format
            if magic == b'\x0a\x0d\x0d\x0a':
                self._reader = RawPcapNgReader.__new__(RawPcapNgReader)
                RawPcapNgReader.__init__(self._reader, self.iface, stream, magic)
            else:
                self._reader = RawPcapReader.__new__(RawPcapReader)
                RawPcapReader.__init__(self._reader, self.iface, stream, magic)
            self.status_changed.emit(f'Capturing from remote {self.iface}')
            while self.running:
                try:
                    packet_data = self._reader._read_packet()
                except EOFError:
                    break
                except Exception as exc:
                    raise RuntimeError(f'Invalid PCAP stream from remote {self.iface}: {exc}') from exc
                if packet_data is None:
                    break
                packet = self._decode_packet(packet_data)
                self.handle_packet(packet)
            if self.running:
                self.status_changed.emit(f'Remote source closed: {self.iface}')
        except Exception as exc:
            if self.running:
                msg = f'Remote capture failed on {self.iface}: {exc}'
                log.exception(msg)
                self.error_occurred.emit(msg)
        finally:
            self._close_resources()
            self.status_changed.emit('Capture stopped')

    def _decode_packet(self, packet_data):
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
        if not hasattr(packet, 'sniffed_on') or not packet.sniffed_on:
            packet.sniffed_on = self.iface
        packet.interface_name = packet.sniffed_on
        packet.interface_description = 'Remote Interface'
        self.packet_captured.emit(packet)

    def _find_remote_config(self, host: str, port: int, username: str, target_iface: str):
        settings = QSettings('Packetra', 'Packetra')
        remotes_json = settings.value('remote_interfaces', '[]', str)
        try:
            remotes = json.loads(remotes_json)
        except Exception:
            return None

        for remote in remotes:
            r_host = str(remote.get('host', '')).strip()
            r_port = int(remote.get('port', 22) or 22)
            r_user = str(remote.get('username', '')).strip()
            if r_host == host and r_port == port and r_user == username:
                for iface in remote.get('interfaces', []):
                    iface_target = str(iface.get('target', iface.get('name', ''))).strip()
                    iface_name = str(iface.get('name', '')).strip()
                    requested = str(target_iface).strip()
                    if iface_target == requested or iface_name == requested:
                        merged = dict(remote)
                        merged['target'] = iface_target or requested
                        merged['friendly_name'] = iface_name or requested
                        return merged
        return None

    def _read_channel_stderr(self, timeout_sec: float = 0.5) -> str:
        if not self._channel:
            return ''
        data = []
        deadline = time.time() + max(0.0, float(timeout_sec))
        while time.time() < deadline:
            try:
                if self._channel.recv_stderr_ready():
                    chunk = self._channel.recv_stderr(4096)
                    if chunk:
                        data.append(chunk.decode(errors='ignore'))
                    continue
                if self._channel.exit_status_ready():
                    # one last drain attempt
                    if self._channel.recv_stderr_ready():
                        chunk = self._channel.recv_stderr(4096)
                        if chunk:
                            data.append(chunk.decode(errors='ignore'))
                    break
                # tiny wait without busy loop
                select.select([], [], [], 0.05)
            except Exception:
                break
        return ''.join(data).strip()

    def _read_channel_stdout(self, timeout_sec: float = 0.5) -> str:
        if not self._channel:
            return ''
        data = []
        deadline = time.time() + max(0.0, float(timeout_sec))
        while time.time() < deadline:
            try:
                if self._channel.recv_ready():
                    chunk = self._channel.recv(4096)
                    if chunk:
                        data.append(chunk.decode(errors='ignore'))
                    continue
                if self._channel.exit_status_ready():
                    if self._channel.recv_ready():
                        chunk = self._channel.recv(4096)
                        if chunk:
                            data.append(chunk.decode(errors='ignore'))
                    break
                select.select([], [], [], 0.05)
            except Exception:
                break
        return ''.join(data).strip()

    def _close_resources(self):
        reader = self._reader
        self._reader = None
        if reader is not None:
            try:
                reader.close()
            except Exception:
                pass
        if self._channel:
            try:
                self._channel.close()
            except Exception:
                pass
        if self._ssh:
            try:
                self._ssh.close()
            except Exception:
                pass

    def stop(self):
        self.running = False
        self._close_resources()

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
