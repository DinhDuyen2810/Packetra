import os
import sys
import subprocess
import ctypes
import re


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