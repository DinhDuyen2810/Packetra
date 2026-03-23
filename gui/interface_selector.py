import logging
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QListWidget, QPushButton, QLabel
)
from PySide6.QtCore import QTimer

from utils.network_utils import get_interfaces, get_traffic

log = logging.getLogger("interface_selector")


class InterfaceSelector(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Select Interface")
        self.resize(400, 500)

        # FIX: đổi self.layout → self.main_layout
        # self.layout() là method có sẵn của QWidget, ghi đè nó gây crash
        self.main_layout = QVBoxLayout()

        self.label = QLabel("Select Network Interface  (cập nhật mỗi 1s)")
        self.list_widget = QListWidget()
        self.start_btn = QPushButton("Start Capture")

        self.main_layout.addWidget(self.label)
        self.main_layout.addWidget(self.list_widget)
        self.main_layout.addWidget(self.start_btn)
        self.setLayout(self.main_layout)

        # {display_name: scapy_name}
        self.interfaces = get_interfaces()
        log.info(f"Interfaces found: { {k: v for k, v in self.interfaces.items()} }")

        self.prev_traffic = get_traffic()

        self.update_list()

        # QTimer: cập nhật traffic mỗi 1 giây
        self._timer = QTimer(self)          # parent=self → timer sống cùng widget
        self._timer.timeout.connect(self.update_list)
        self._timer.start(1000)
        log.debug("Timer started (1000ms)")

    def update_list(self):
        current = get_traffic()

        items = []
        for display_name, scapy_name in self.interfaces.items():
            prev = self.prev_traffic.get(display_name, 0)
            now  = current.get(display_name, 0)
            speed = max(now - prev, 0)          # bytes trong 1 giây
            items.append((display_name, scapy_name, speed))
            log.debug(f"  {display_name}: {speed/1024:.2f} KB/s")

        # sort theo traffic giảm dần
        items.sort(key=lambda x: x[2], reverse=True)

        # Nhớ item đang chọn để giữ lại sau khi clear
        selected_display = None
        cur = self.list_widget.currentItem()
        if cur:
            selected_display = cur.text().split("|")[0].strip()

        self.list_widget.clear()

        for display_name, scapy_name, speed in items:
            text = f"{display_name}  |  {speed / 1024:.2f} KB/s"
            self.list_widget.addItem(text)

        # Khôi phục selection (hoặc chọn row 0)
        restored = False
        if selected_display:
            for i in range(self.list_widget.count()):
                if self.list_widget.item(i).text().startswith(selected_display):
                    self.list_widget.setCurrentRow(i)
                    restored = True
                    break
        if not restored and self.list_widget.count() > 0:
            self.list_widget.setCurrentRow(0)

        self.prev_traffic = current

    def get_selected_interface(self):
        """Trả về scapy network name của interface đang chọn."""
        item = self.list_widget.currentItem()
        if not item:
            log.warning("Không có interface nào được chọn.")
            return None

        display_name = item.text().split("|")[0].strip()
        scapy_name = self.interfaces.get(display_name)
        log.info(f"get_selected_interface: display={display_name!r}  scapy={scapy_name!r}")
        return scapy_name