import os
import sys
import subprocess
import ctypes


def is_npcap_installed():
    system32 = r'C:\Windows\System32'
    dlls = ['wpcap.dll', 'Packet.dll']
    dlls_ok = all(os.path.exists(os.path.join(system32, f)) for f in dlls)

    try:
        output = subprocess.check_output(['sc', 'query', 'npcap'], text=True)
        service_ok = 'RUNNING' in output
    except Exception:
        service_ok = False

    return dlls_ok and service_ok


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
            "/S",
            None,
            1
        )
        return True
    except Exception:
        return False