from gui.main_window import MainWindow
from gui.interface_selector import InterfaceSelector
from PySide6.QtWidgets import QApplication, QMessageBox
import sys
import logging

from utils.system_check import is_npcap_installed, install_npcap

# ===== LOGGING SETUP =====
logging.basicConfig(
    level=logging.DEBUG,
    format="[%(asctime)s] %(levelname)s %(name)s: %(message)s",
    datefmt="%H:%M:%S",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("main")


def ensure_npcap():
    log.info("Kiểm tra Npcap...")
    if not is_npcap_installed():
        log.warning("Npcap CHƯA được cài đặt.")
        reply = QMessageBox.question(
            None,
            "Npcap Required",
            "Npcap chưa được cài.\nBạn có muốn cài tự động không?",
            QMessageBox.Yes | QMessageBox.No,
        )
        if reply == QMessageBox.Yes:
            success = install_npcap()
            if success:
                QMessageBox.information(
                    None, "Success", "Cài đặt Npcap thành công!\nVui lòng mở lại ứng dụng."
                )
                sys.exit(0)
            else:
                QMessageBox.critical(None, "Error", "Cài đặt thất bại!")
                sys.exit(1)
        else:
            QMessageBox.warning(None, "Warning", "Ứng dụng cần Npcap để chạy.")
            sys.exit(1)
    else:
        log.info("Npcap đã được cài đặt.")


if __name__ == "__main__":
    app = QApplication(sys.argv)

    ensure_npcap()

    selector = InterfaceSelector()
    selector.show()

    # FIX: dùng list 1 phần tử thay vì nonlocal.
    # nonlocal không dùng được ở đây vì biến nằm ở if-__name__-scope,
    # không phải trong function → Pylance/Python báo lỗi.
    # List là mutable nên hàm con ghi vào _ref[0] mà không cần nonlocal.
    _ref = [None]

    def start_capture():
        iface = selector.get_selected_interface()
        log.info(f"Interface được chọn: {iface!r}")

        if not iface:
            QMessageBox.warning(None, "Error", "Vui lòng chọn interface!")
            return

        selector.close()

        _ref[0] = MainWindow(iface)   # giữ reference → window không bị garbage collect
        _ref[0].show()
        log.info(f"MainWindow đã mở với iface={iface!r}")

    selector.start_btn.clicked.connect(start_capture)

    sys.exit(app.exec())