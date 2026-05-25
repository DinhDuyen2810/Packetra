import logging
import os
import sys

# Reduce noisy Qt font-db warnings before Qt is imported.
qt_rules = os.environ.get('QT_LOGGING_RULES', '').strip()
extra_qt_rules = 'qt.text.font.db=false'
if qt_rules:
    if extra_qt_rules not in qt_rules:
        os.environ['QT_LOGGING_RULES'] = f'{qt_rules};{extra_qt_rules}'
else:
    os.environ['QT_LOGGING_RULES'] = extra_qt_rules

from PySide6.QtWidgets import QApplication, QMessageBox

from gui.application import ApplicationWindow
from utils.system_check import is_npcap_installed, install_npcap

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s %(name)s: %(message)s',
    datefmt='%H:%M:%S'
)
log = logging.getLogger('main')
# Scapy TLS key-log parser can emit unknown cipher-suite warnings that are
# irrelevant for UI startup; keep runtime logs at ERROR to avoid console noise.
logging.getLogger('scapy.runtime').setLevel(logging.ERROR)


def ensure_npcap():
    if sys.platform != 'win32':
        return True

    if is_npcap_installed():
        return True

    reply = QMessageBox.question(
        None,
        'Npcap Required',
        'Npcap chưa được cài đặt hoặc không hoạt động.\n'
        'Bạn có muốn cài tự động không?',
        QMessageBox.Yes | QMessageBox.No,
    )

    if reply != QMessageBox.Yes:
        QMessageBox.warning(
            None,
            'Warning',
            'Ứng dụng cần Npcap để hoạt động trên Windows.\n'
            'Vui lòng cài đặt rồi chạy lại.'
        )
        return False

    ok = install_npcap()

    if not ok:
        QMessageBox.critical(
            None,
            'Error',
            'Không thể khởi chạy trình cài đặt Npcap.\n'
            'Hãy thử chạy ứng dụng bằng quyền Administrator.'
        )
        return False

    QMessageBox.information(
        None,
        'Installing Npcap',
        'Trình cài đặt Npcap đã được mở.\n'
        'Vui lòng hoàn tất cài đặt (bấm Yes nếu có UAC),\n'
        'sau đó mở lại ứng dụng.'
    )

    return False


if __name__ == '__main__':
    app = QApplication(sys.argv)

    if not ensure_npcap():
        sys.exit(1)

    window = ApplicationWindow()

    # ---- resize window to 80% of screen ----

    screen = app.primaryScreen()
    geometry = screen.availableGeometry()

    width = int(geometry.width() * 0.8)
    height = int(geometry.height() * 0.8)

    window.resize(width, height)

    # center window
    x = geometry.x() + (geometry.width() - width) // 2
    y = geometry.y() + (geometry.height() - height) // 2

    window.move(x, y)

    window.show()

    sys.exit(app.exec())
