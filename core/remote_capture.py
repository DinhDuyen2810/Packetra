import paramiko
import logging
import re

log = logging.getLogger('remote_capture')

class SSHRemoteCapture:
    _shared_clients = {}

    def __init__(self, host, port=22, username=None, password=None, key_path=None, os_type='linux', auth_type='Null'):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.key_path = key_path
        self.os_type = os_type
        self.auth_type = auth_type
        self.client = None
        self._connect()

    def _cache_key(self):
        return (
            str(self.host or '').strip(),
            int(self.port or 22),
            str(self.username or '').strip(),
            str(self.os_type or 'linux').strip().lower(),
            str(self.auth_type or 'Null').strip().lower(),
        )

    def _connect(self):
        if not self.host:
            raise RuntimeError('Remote host is empty')
        if not self.username:
            raise RuntimeError(f'Missing username for remote host {self.host}')

        cache_key = self._cache_key()
        existing = self._shared_clients.get(cache_key)
        if existing is not None:
            transport = existing.get_transport()
            if transport and transport.is_active():
                self.client = existing
                return
            try:
                existing.close()
            except Exception:
                pass
            self._shared_clients.pop(cache_key, None)

        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            auth = str(self.auth_type or 'Null').strip().lower()
            if self.key_path:
                self.client.connect(
                    self.host,
                    port=self.port,
                    username=self.username,
                    key_filename=self.key_path,
                    timeout=8,
                    banner_timeout=8,
                    auth_timeout=8,
                    look_for_keys=True,
                    allow_agent=True,
                )
            elif auth == 'password':
                if not self.password:
                    raise RuntimeError(f'Password auth selected but password is empty for {self.username}@{self.host}:{self.port}')
                self.client.connect(
                    self.host,
                    port=self.port,
                    username=self.username,
                    password=self.password,
                    timeout=8,
                    banner_timeout=8,
                    auth_timeout=8,
                    look_for_keys=False,
                    allow_agent=False,
                )
            else:
                # Null auth means key/agent auth only.
                self.client.connect(
                    self.host,
                    port=self.port,
                    username=self.username,
                    timeout=8,
                    banner_timeout=8,
                    auth_timeout=8,
                    look_for_keys=True,
                    allow_agent=True,
                )
            transport = self.client.get_transport()
            if transport is not None:
                transport.set_keepalive(30)
            self._shared_clients[cache_key] = self.client
        except Exception as exc:
            log.error(f'SSH connection failed: {exc}')
            raise

    def _build_windows_agent_cmd(self, args: str) -> str:
        args = str(args or '').strip()
        # Prefer explicit install paths to avoid stale PATH ordering in non-interactive SSH sessions.
        inner = (
            'if exist "C:\\RemoteCaptureAgent\\RemoteCaptureAgent.cmd" '
            f'("C:\\RemoteCaptureAgent\\RemoteCaptureAgent.cmd" {args}) '
            'else if exist "C:\\Program Files\\RemoteCaptureAgent\\RemoteCaptureAgent.cmd" '
            f'("C:\\Program Files\\RemoteCaptureAgent\\RemoteCaptureAgent.cmd" {args}) '
            f'else (RemoteCaptureAgent.cmd {args})'
        )
        # OpenSSH on Windows may use either cmd.exe or powershell as default shell.
        # Always execute through cmd.exe so the IF/ELSE syntax above is interpreted reliably.
        return f'cmd /d /s /c "{inner}"'

    def list_interfaces(self):
        if self.os_type == 'linux':
            cmd = 'tcpdump -D'
        else:
            cmd = self._build_windows_agent_cmd('--list')
        _stdin, stdout, stderr = self.client.exec_command(cmd)
        output = stdout.read().decode(errors='ignore')
        err = stderr.read().decode(errors='ignore').strip()
        if err and not output:
            raise RuntimeError(err)
        if self.os_type == 'linux':
            # Parse tcpdump -D output, keeping only the actual iface token.
            # Example line: "1. ens224 [Up, Running, Connected]" -> "ens224"
            names = []
            for raw_line in output.splitlines():
                line = raw_line.strip()
                if not line:
                    continue
                match = re.match(r'^\s*\d+\.\s*([^\s]+)', line)
                if match:
                    names.append(match.group(1).strip())
                else:
                    names.append(line)
            return names
        else:
            # Parse agent output (assume one per line)
            return [line.strip() for line in output.splitlines() if line.strip()]

    def start_capture(self, iface, bpf_filter=None, promiscuous=True):
        if self.os_type == 'linux':
            iface = str(iface or '').split(' [', 1)[0].strip()
            cmd = f"tcpdump -n -s 0 -i '{iface}' -U -w -"
            if not bool(promiscuous):
                cmd += ' -p'
            if bpf_filter:
                cmd += f' {bpf_filter}'
        else:
            # cmd.exe double-quote escape: use "" to embed a literal "
            iface_escaped = str(iface or '').replace('"', '""')
            args = f'--capture --iface "{iface_escaped}" --stdout'
            if bpf_filter:
                filter_escaped = str(bpf_filter).replace('"', '""')
                args += f' --filter "{filter_escaped}"'
            if promiscuous:
                args += ' --promiscuous'
            cmd = self._build_windows_agent_cmd(args)
        transport = self.client.get_transport()
        channel = transport.open_session()
        channel.exec_command(cmd)
        return channel

    def close(self, force=False):
        if self.client:
            if force:
                try:
                    self.client.close()
                finally:
                    self._shared_clients.pop(self._cache_key(), None)
                    self.client = None

# Usage example (for backend integration):
# rc = SSHRemoteCapture(host, port, username, password, key_path, os_type, auth_type)
# interfaces = rc.list_interfaces()
# channel = rc.start_capture(iface)
# while True:
#     data = channel.recv(4096)
#     if not data:
#         break
#     ... # feed to local analyzer
# rc.close()
