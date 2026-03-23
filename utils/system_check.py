import os

def is_npcap_installed():
    paths = [
        r"C:\Windows\System32\Npcap",
        r"C:\Program Files\Npcap",
        r"C:\Program Files (x86)\Npcap"
    ]
    
    for path in paths:
        if os.path.exists(path):
            return True
    
    return False

import subprocess
import sys

def install_npcap():
    try:
        subprocess.run(
            ["npcap-setup.exe", "/S"],
            check=True
        )
        return True
    except Exception as e:
        print("Install failed:", e)
        return False