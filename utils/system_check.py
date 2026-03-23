import os
import subprocess
import sys


def is_npcap_installed():
    paths = [
        r"C:\Windows\System32\Npcap",
        r"C:\Program Files\Npcap",
        r"C:\Program Files (x86)\Npcap",
    ]
    return any(os.path.exists(p) for p in paths)


def install_npcap():
    """
    Tìm npcap-setup.exe trong cùng thư mục với script đang chạy,
    sau đó cài đặt silently.

    FIX #6: trước đây gọi "npcap-setup.exe" không có đường dẫn
    → FileNotFoundError nếu file không nằm trong PATH.
    """
    # Tìm installer cạnh file đang chạy (hoặc cạnh main.py)
    base_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
    installer = os.path.join(base_dir, "npcap-setup.exe")

    if not os.path.exists(installer):
        print(f"Không tìm thấy installer tại: {installer}")
        return False

    try:
        subprocess.run([installer, "/S"], check=True)
        return True
    except subprocess.CalledProcessError as e:
        print(f"Install failed (exit code {e.returncode}):", e)
        return False
    except Exception as e:
        print("Install failed:", e)
        return False