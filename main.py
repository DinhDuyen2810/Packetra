from gui.main_window import MainWindow
from gui.interface_selector import InterfaceSelector
from PySide6.QtWidgets import QApplication, QMessageBox
import sys

from utils.system_check import is_npcap_installed, install_npcap


def ensure_npcap():
    if not is_npcap_installed():
        reply = QMessageBox.question(
            None,
            "Npcap Required",
            "Npcap chưa được cài.\nBạn có muốn cài tự động không?",
            QMessageBox.Yes | QMessageBox.No
        )

        if reply == QMessageBox.Yes:
            success = install_npcap()

            if success:
                QMessageBox.information(None, "Success", "Cài đặt Npcap thành công!\nVui lòng mở lại ứng dụng.")
                sys.exit(0)
            else:
                QMessageBox.critical(None, "Error", "Cài đặt thất bại!")
                sys.exit(1)
        else:
            QMessageBox.warning(None, "Warning", "Ứng dụng cần Npcap để chạy.")
            sys.exit(1)


if __name__ == "__main__":
    app = QApplication(sys.argv)

    # 🔥 Check Npcap trước
    ensure_npcap()

    selector = InterfaceSelector()
    selector.show()
    

    def start_capture():
        iface = selector.get_selected_interface()

        if not iface:
            QMessageBox.warning(None, "Error", "Vui lòng chọn interface!")
            return

        selector.close()

        window = MainWindow(iface)
        window.show()

    selector.start_btn.clicked.connect(start_capture)

    sys.exit(app.exec())