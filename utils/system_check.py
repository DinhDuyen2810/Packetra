import os
import sys
import subprocess
import ctypes
import re


def _hidden_startupinfo():
    if sys.platform != 'win32':
        return None
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    return startupinfo


def is_npcap_installed():
    if sys.platform != 'win32':
        return False

    windir = os.environ.get('WINDIR', r'C:\Windows')
    base_dirs = [
        os.path.join(windir, 'System32', 'Npcap'),
        os.path.join(windir, 'System32'),
        os.path.join(windir, 'Sysnative', 'Npcap'),
        os.path.join(windir, 'Sysnative'),
        os.path.join(windir, 'SysWOW64', 'Npcap'),
        os.path.join(windir, 'SysWOW64'),
    ]

    has_packet_dll = any(os.path.exists(os.path.join(d, 'Packet.dll')) for d in base_dirs)
    has_wpcap_dll = any(os.path.exists(os.path.join(d, 'wpcap.dll')) for d in base_dirs)
    dlls_ok = has_packet_dll and has_wpcap_dll

    driver_paths = [
        os.path.join(windir, 'System32', 'drivers', 'npcap.sys'),
        os.path.join(windir, 'Sysnative', 'drivers', 'npcap.sys'),
    ]
    driver_ok = any(os.path.exists(p) for p in driver_paths)

    try:
        output = subprocess.check_output(['sc.exe', 'query', 'npcap'], text=True, errors='ignore')
        normalized = output.upper()
        service_present = 'SERVICE_NAME: NPCAP' in normalized
        service_running = re.search(r'STATE\s*:\s*4\b', normalized) is not None
    except Exception:
        service_present = False
        service_running = False

    try:
        pnputil_output = subprocess.check_output(
            ['pnputil', '/enum-drivers'],
            text=True,
            errors='ignore'
        )
        pnputil_ok = 'npcap.inf' in pnputil_output.lower()
    except Exception:
        pnputil_ok = False

    # Consider Npcap installed if files and driver/service metadata are present.
    files_ok = dlls_ok and driver_ok
    metadata_ok = service_present or pnputil_ok
    return files_ok and metadata_ok


def _npcap_base_dirs():
    windir = os.environ.get('WINDIR', r'C:\Windows')
    return [
        os.path.join(windir, 'System32', 'Npcap'),
        os.path.join(windir, 'System32'),
        os.path.join(windir, 'Sysnative', 'Npcap'),
        os.path.join(windir, 'Sysnative'),
        os.path.join(windir, 'SysWOW64', 'Npcap'),
        os.path.join(windir, 'SysWOW64'),
    ]


def _get_windows_file_version(file_path):
    if sys.platform != 'win32' or not file_path or not os.path.exists(file_path):
        return ''

    try:
        import win32api  # type: ignore

        info = win32api.GetFileVersionInfo(file_path, '\\')
        ms = info['FileVersionMS']
        ls = info['FileVersionLS']
        version = (
            win32api.HIWORD(ms),
            win32api.LOWORD(ms),
            win32api.HIWORD(ls),
            win32api.LOWORD(ls),
        )
        return '.'.join(str(part) for part in version)
    except Exception:
        pass

    escaped_path = file_path.replace("'", "''")
    command = [
        'powershell',
        '-NoProfile',
        '-Command',
        f"(Get-Item -LiteralPath '{escaped_path}').VersionInfo.ProductVersion",
    ]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            errors='ignore',
            timeout=5,
            startupinfo=_hidden_startupinfo(),
        )
        version = (completed.stdout or '').strip()
        if version:
            return version
    except Exception:
        pass
    return ''


def get_npcap_info():
    if sys.platform != 'win32':
        return {
            'installed': False,
            'version': '',
            'dll_path': '',
            'driver_path': '',
            'service_status': 'Unsupported platform',
        }

    dll_candidates = []
    for base_dir in _npcap_base_dirs():
        dll_candidates.append(os.path.join(base_dir, 'wpcap.dll'))
        dll_candidates.append(os.path.join(base_dir, 'Packet.dll'))
    dll_path = next((path for path in dll_candidates if os.path.exists(path)), '')

    windir = os.environ.get('WINDIR', r'C:\Windows')
    driver_candidates = [
        os.path.join(windir, 'System32', 'drivers', 'npcap.sys'),
        os.path.join(windir, 'Sysnative', 'drivers', 'npcap.sys'),
    ]
    driver_path = next((path for path in driver_candidates if os.path.exists(path)), '')

    service_status = 'Not found'
    try:
        completed = subprocess.run(
            ['sc.exe', 'query', 'npcap'],
            capture_output=True,
            text=True,
            errors='ignore',
            timeout=5,
            startupinfo=_hidden_startupinfo(),
        )
        output = (completed.stdout or '').upper()
        if 'RUNNING' in output:
            service_status = 'Running'
        elif 'STOPPED' in output:
            service_status = 'Stopped'
        elif 'SERVICE_NAME: NPCAP' in output:
            service_status = 'Installed'
    except Exception:
        pass

    version = _get_windows_file_version(dll_path) or _get_windows_file_version(driver_path)

    return {
        'installed': bool(dll_path or driver_path) and is_npcap_installed(),
        'version': version,
        'dll_path': dll_path,
        'driver_path': driver_path,
        'service_status': service_status,
    }


def install_npcap():
    base_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
    installer = os.path.join(base_dir, 'npcap-setup.exe')

    if not os.path.exists(installer):
        return False

    try:
        ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            installer,
            None,
            None,
            1
        )
        return True
    except Exception:
        return False
