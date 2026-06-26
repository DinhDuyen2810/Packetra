import argparse
import ctypes
import logging
import os
import re
import struct
import subprocess
import sys
import tempfile
import time
import urllib.request
import winreg
from glob import glob
import win32serviceutil
import win32service
import win32event
import servicemanager

def _ensure_scapy():
    try:
        from scapy.all import sniff, get_if_list, raw, Ether, IP, IPv6, UDP, Raw
        return sniff, get_if_list, raw, Ether, IP, IPv6, UDP, Raw
    except ModuleNotFoundError:
        raise RuntimeError('Scapy is not installed on remote host. Please install scapy before running the agent.')

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s %(message)s')

AGENT_SERVICE_NAME = "PacketraAgent"
AGENT_INSTALL_DIR = os.path.dirname(os.path.abspath(sys.executable if getattr(sys, "frozen", False) else __file__))
OPENSSH_PATH = r"C:\Windows\System32\OpenSSH"
NPCAP_FALLBACK_URL = "https://npcap.com/dist/npcap-1.88.exe"
BOOTSTRAP_LOG_PATH = os.path.join(tempfile.gettempdir(), "PacketraAgent-bootstrap.log")


def _is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _run_command(command, check=True, shell=False):
    result = subprocess.run(
        command,
        check=False,
        shell=shell,
        capture_output=True,
        text=True,
    )
    if check and result.returncode != 0:
        raise RuntimeError((result.stderr or result.stdout or "").strip() or f"Command failed: {command}")
    return result


def _append_bootstrap_log(message):
    try:
        with open(BOOTSTRAP_LOG_PATH, "a", encoding="utf-8") as handle:
            handle.write(message.rstrip() + "\n")
    except Exception:
        pass


def _show_bootstrap_error(message):
    try:
        ctypes.windll.user32.MessageBoxW(
            0,
            message,
            "PacketraAgent Setup Error",
            0x10,
        )
    except Exception:
        pass


def _run_powershell(script, check=True):
    return _run_command(
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ],
        check=check,
    )


def _service_exists(service_name):
    result = _run_command(["sc.exe", "query", service_name], check=False)
    return result.returncode == 0


def _service_is_running(service_name):
    result = _run_command(["sc.exe", "query", service_name], check=False)
    text = f"{result.stdout}\n{result.stderr}".upper()
    return "RUNNING" in text


def _append_machine_path(path_value):
    normalized = os.path.normcase(os.path.normpath(path_value))
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
            0,
            winreg.KEY_READ | winreg.KEY_WRITE,
        ) as key:
            current, reg_type = winreg.QueryValueEx(key, "Path")
            parts = [p for p in str(current or "").split(";") if p]
            normalized_parts = {os.path.normcase(os.path.normpath(p)) for p in parts}
            if normalized not in normalized_parts:
                parts.append(path_value)
                winreg.SetValueEx(key, "Path", 0, reg_type, ";".join(parts))
    except FileNotFoundError:
        pass
    os.environ["PATH"] = os.environ.get("PATH", "") + (";" if os.environ.get("PATH") else "") + path_value


def _find_npcap_download_url():
    override = str(os.environ.get("PACKETRA_NPCAP_URL", "") or "").strip()
    if override:
        return override
    try:
        with urllib.request.urlopen("https://npcap.com/", timeout=15) as response:
            html = response.read().decode("utf-8", errors="ignore")
        match = re.search(r"https://npcap\.com/dist/npcap-[0-9.]+\.exe", html, flags=re.IGNORECASE)
        if match:
            return match.group(0)
        match = re.search(r"/dist/npcap-[0-9.]+\.exe", html, flags=re.IGNORECASE)
        if match:
            return "https://npcap.com" + match.group(0)
    except Exception:
        pass
    return NPCAP_FALLBACK_URL


def _find_local_npcap_installer():
    override = str(os.environ.get("PACKETRA_NPCAP_INSTALLER", "") or "").strip()
    if override and os.path.exists(override):
        return override
    patterns = [
        os.path.join(AGENT_INSTALL_DIR, "npcap*.exe"),
        os.path.join(os.path.dirname(AGENT_INSTALL_DIR), "npcap*.exe"),
        os.path.join(tempfile.gettempdir(), "npcap*.exe"),
    ]
    for pattern in patterns:
        matches = sorted(glob(pattern), reverse=True)
        for match in matches:
            if os.path.isfile(match):
                return match
    return ""


def _ensure_openssh():
    for capability in ("OpenSSH.Client~~~~0.0.1.0", "OpenSSH.Server~~~~0.0.1.0"):
        state = _run_powershell(f"(Get-WindowsCapability -Online -Name '{capability}').State").stdout.strip()
        if state.lower() != "installed":
            _run_powershell(f"Add-WindowsCapability -Online -Name '{capability}'")
    _append_machine_path(OPENSSH_PATH)
    _run_powershell(
        "Set-Service -Name sshd -StartupType Automatic; "
        "if ((Get-Service sshd).Status -ne 'Running') { Start-Service sshd }"
    )
    _run_powershell(
        "if (-not (Get-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -ErrorAction SilentlyContinue)) { "
        "New-NetFirewallRule -Name 'OpenSSH-Server-In-TCP' -DisplayName 'OpenSSH Server (sshd)' "
        "-Enabled True -Direction Inbound -Protocol TCP -Action Allow -LocalPort 22 | Out-Null }"
    )


def _ensure_npcap():
    if _service_exists("npcap") or _service_exists("npcapwatchdog"):
        return
    installer_path = _find_local_npcap_installer()
    if not installer_path:
        url = _find_npcap_download_url()
        installer_name = os.path.basename(url) or "npcap-installer.exe"
        temp_dir = tempfile.mkdtemp(prefix="packetra-npcap-")
        installer_path = os.path.join(temp_dir, installer_name)
        with urllib.request.urlopen(url, timeout=60) as response, open(installer_path, "wb") as output:
            output.write(response.read())
    # Free Npcap does not support silent install, so we launch the official GUI installer
    # and wait until the user completes it.
    result = subprocess.run(
        [installer_path, "/winpcap_mode=yes", "/admin_only=no"],
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError("Npcap installer did not complete successfully.")
    if not (_service_exists("npcap") or _service_exists("npcapwatchdog")):
        raise RuntimeError("Npcap still appears to be missing after installation.")


def _ensure_agent_service():
    exe_path = os.path.abspath(sys.executable if getattr(sys, "frozen", False) else sys.argv[0])
    _append_machine_path(os.path.dirname(exe_path))
    if _service_exists(AGENT_SERVICE_NAME):
        _run_command([exe_path, "--startup", "auto", "update"])
    else:
        _run_command([exe_path, "--startup", "auto", "install"])
    if not _service_is_running(AGENT_SERVICE_NAME):
        _run_command([exe_path, "start"])


def bootstrap_install():
    if not _is_admin():
        raise RuntimeError("Administrator privileges are required to install PacketraAgent prerequisites.")
    _append_bootstrap_log("=== bootstrap install start ===")
    _ensure_openssh()
    _append_bootstrap_log("OpenSSH ready.")
    _ensure_npcap()
    _append_bootstrap_log("Npcap ready.")
    _ensure_agent_service()
    _append_bootstrap_log("PacketraAgent service ready.")
    _append_bootstrap_log("=== bootstrap install done ===")


def bootstrap_uninstall():
    if not _is_admin():
        raise RuntimeError("Administrator privileges are required to remove the PacketraAgent service.")
    _append_bootstrap_log("=== bootstrap uninstall start ===")
    exe_path = os.path.abspath(sys.executable if getattr(sys, "frozen", False) else sys.argv[0])
    if _service_exists(AGENT_SERVICE_NAME):
        _run_command([exe_path, "stop"], check=False)
        _run_command([exe_path, "remove"], check=False)
    _append_bootstrap_log("=== bootstrap uninstall done ===")

def list_interfaces():
    sniff, get_if_list, _raw, _Ether, _IP, _IPv6, _UDP, _Raw = _ensure_scapy()

    def _clean_name(value):
        text = str(value or '').strip()
        if not text:
            return ''
        text = re.sub(r'-(WFP|Fortinet NDIS|Npcap Packet Driver|VirtualBox NDIS|QoS Packet Scheduler|Native WiFi Filter|Virtual WiFi Filter).*$', '', text, flags=re.IGNORECASE)
        text = re.sub(r'-000\d+$', '', text, flags=re.IGNORECASE)
        return text.strip()

    def _is_noise(value):
        low = str(value or '').lower()
        blocked_keywords = (
            'lightweight filter', 'wfp ', 'ndis', 'qos packet scheduler',
            'npcap packet driver', 'virtual wifi filter', 'native wifi filter',
            'miniport', 'teredo', '6to4', 'ip-https', 'kernel debugger',
        )
        return any(k in low for k in blocked_keywords)

    try:
        from scapy.arch.windows import get_windows_if_list
        merged = {}
        for entry in get_windows_if_list():
            if isinstance(entry, dict):
                dev_name = entry.get('name') or ''
                win_name = entry.get('win_name') or ''
                desc = entry.get('description') or entry.get('friendly_name') or ''

                display = _clean_name(win_name) or _clean_name(desc)
                target = str(dev_name).strip() if dev_name else str(win_name).strip()

                if not display:
                    continue
                if _is_noise(display) and _is_noise(target):
                    continue

                key = display.lower()
                score = 0
                if not _is_noise(display):
                    score += 10
                if 'virtual' not in display.lower():
                    score += 2
                prev = merged.get(key)
                if prev is None or score > prev[0]:
                    merged[key] = (score, display, target)
                continue
            try:
                name, dev, _desc = entry
                display = _clean_name(str(name).strip())
                target = str(dev or name).strip()
                if display and not (_is_noise(display) and _is_noise(target)):
                    key = display.lower()
                    prev = merged.get(key)
                    if prev is None:
                        merged[key] = (5, display, target)
            except Exception:
                pass

        rows = sorted((v[1], v[2]) for v in merged.values())
        print('testinterface || testinterface')
        for display, target in rows:
            print(f"{display} || {target}")
        return
    except Exception:
        pass

    print('testinterface || testinterface')
    for iface in get_if_list():
        print(f"{iface} || {iface}")

def capture_to_stdout(iface, bpf_filter='', promiscuous=True):
    if sys.platform == 'win32':
        try:
            import msvcrt
            msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
        except Exception:
            pass 

    sniff, _get_if_list, raw, Ether, IP, IPv6, UDP, Raw = _ensure_scapy()
    capture_iface = str(iface or '').strip()
    
    if sys.platform == 'win32':
        try:
            from scapy.arch.windows import get_windows_if_list
            requested = capture_iface.lower()
            for entry in get_windows_if_list():
                if not isinstance(entry, dict):
                    continue
                dev_name = str(entry.get('name') or '').strip()
                win_name = str(entry.get('win_name') or '').strip()
                friendly = str(entry.get('friendly_name') or '').strip()
                desc = str(entry.get('description') or '').strip()
                candidates = [dev_name, win_name, friendly, desc]
                if any(str(c or '').strip().lower() == requested for c in candidates):
                    if dev_name:
                        capture_iface = dev_name
                    break
        except Exception:
            pass

    out = getattr(sys.stdout, 'buffer', sys.stdout)
    stream_linktype = None

    def _classify_packet(pkt):
        pkt_bytes = b''
        try:
            pkt_bytes = bytes(getattr(pkt, 'original', b'') or b'')
        except Exception:
            pkt_bytes = b''
        if not pkt_bytes:
            pkt_bytes = raw(pkt)

        if isinstance(pkt, Ether) or pkt.haslayer(Ether):
            return pkt_bytes, 1
        if isinstance(pkt, IPv6) or pkt.haslayer(IPv6):
            return pkt_bytes, 229
        if isinstance(pkt, IP) or pkt.haslayer(IP):
            return pkt_bytes, 228

        if pkt_bytes:
            version = (pkt_bytes[0] >> 4) & 0x0F
            if version == 4:
                return pkt_bytes, 228
            if version == 6:
                return pkt_bytes, 229
        return pkt_bytes, 1

    def _ensure_header(linktype):
        nonlocal stream_linktype
        if stream_linktype is not None:
            return
        stream_linktype = int(linktype or 1)
        out.write(struct.pack('<IHHIIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, stream_linktype))
        out.flush()

    def _emit(pkt_bytes, pkt_time=None):
        _ensure_header(stream_linktype or 1)
        now = float(pkt_time) if pkt_time is not None else time.time()
        ts_sec = int(now)
        ts_usec = int((now - ts_sec) * 1_000_000)
        incl_len = len(pkt_bytes)
        out.write(struct.pack('<IIII', ts_sec, ts_usec, incl_len, incl_len))
        out.write(pkt_bytes)
        out.flush()

    if capture_iface.lower() == 'testinterface':
        seq = 1
        while True:
            pkt = Ether(dst='ff:ff:ff:ff:ff:ff', src='02:00:00:00:00:01') / IP(src='10.10.10.1', dst='10.10.10.2') / UDP(sport=50000, dport=50001) / Raw(load=f'packetra-test-{seq}'.encode('ascii'))
            pkt_bytes, linktype = _classify_packet(pkt)
            _ensure_header(linktype)
            _emit(pkt_bytes, pkt_time=time.time())
            seq += 1
            time.sleep(0.25)

    def _write(pkt):
        pkt_bytes, linktype = _classify_packet(pkt)
        _ensure_header(linktype)
        _emit(pkt_bytes, pkt_time=getattr(pkt, 'time', None))

    sniff(
        iface=capture_iface,
        prn=_write,
        store=False,
        filter=bpf_filter or None,
        promisc=bool(promiscuous),
    )


class PacketraAgentService(win32serviceutil.ServiceFramework):
    _svc_name_ = AGENT_SERVICE_NAME
    _svc_display_name_ = "Packetra Remote Capture Agent"
    _svc_description_ = "Provides remote packet capture capabilities for Packetra over SSH."

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)

    def SvcDoRun(self):
        # Service just waits. The actual command execution is done via SSH executing this script with args.
        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE,
                              servicemanager.PYS_SERVICE_STARTED,
                              (self._svc_name_, ''))
        win32event.WaitForSingleObject(self.hWaitStop, win32event.INFINITE)


def main():
    if "--bootstrap-install" in sys.argv:
        try:
            bootstrap_install()
            return
        except Exception as exc:
            import traceback
            detail = traceback.format_exc()
            _append_bootstrap_log(detail)
            _show_bootstrap_error(
                "PacketraAgent setup failed while preparing prerequisites or the service.\n\n"
                f"Reason: {exc}\n\n"
                f"Bootstrap log: {BOOTSTRAP_LOG_PATH}"
            )
            raise

    if "--bootstrap-uninstall" in sys.argv:
        try:
            bootstrap_uninstall()
            return
        except Exception as exc:
            import traceback
            detail = traceback.format_exc()
            _append_bootstrap_log(detail)
            _show_bootstrap_error(
                "PacketraAgent removal failed.\n\n"
                f"Reason: {exc}\n\n"
                f"Bootstrap log: {BOOTSTRAP_LOG_PATH}"
            )
            raise

    if len(sys.argv) == 1:
        # Run as service if no arguments
        win32serviceutil.HandleCommandLine(PacketraAgentService)
        return

    parser = argparse.ArgumentParser(description='Packetra Remote Capture Agent')
    parser.add_argument('--list', action='store_true')
    parser.add_argument('--capture', action='store_true')
    parser.add_argument('--iface', default='')
    parser.add_argument('--stdout', action='store_true')
    parser.add_argument('--filter', default='')
    parser.add_argument('--promiscuous', action='store_true')
    
    # Custom hack because win32serviceutil consumes args like 'install', 'start', etc.
    if sys.argv[1] in ('install', 'start', 'stop', 'remove', 'update'):
        win32serviceutil.HandleCommandLine(PacketraAgentService)
        return
        
    args, _ = parser.parse_known_args()

    if args.list:
        list_interfaces()
        return

    if args.capture and args.stdout and args.iface:
        try:
            capture_to_stdout(args.iface, args.filter, args.promiscuous)
        except Exception as exc:
            import traceback
            traceback.print_exc()
            sys.stderr.write(f'capture_to_stdout error: {exc}\n')
            sys.stderr.flush()
            sys.exit(1)
        return

if __name__ == '__main__':
    main()
