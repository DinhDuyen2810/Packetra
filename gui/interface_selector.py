from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QListWidget, QPushButton, QLabel
)
from PySide6.QtCore import QTimer

from utils.network_utils import get_interfaces, get_traffic


class InterfaceSelector(QWidget):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Select Interface")
        self.resize(400, 500)

        self.layout = QVBoxLayout()

        self.label = QLabel("Select Network Interface")
        self.list_widget = QListWidget()
        self.start_btn = QPushButton("Start Capture")

        self.layout.addWidget(self.label)
        self.layout.addWidget(self.list_widget)
        self.layout.addWidget(self.start_btn)

        self.setLayout(self.layout)

        # 🔥 LẤY MAPPING CHUẨN (HIỂN THỊ → SCAPY)
        self.interfaces = get_interfaces()
        print("SCAPY IFACES:", get_interfaces())
        self.prev_traffic = get_traffic()

        self.update_list()

        # update traffic mỗi 1s
        self.timer = QTimer()
        self.timer.timeout.connect(self.update_list)
        self.timer.start(1000)

    def update_list(self):
        current = get_traffic()

        items = []

        for iface in self.interfaces:
            prev = self.prev_traffic.get(iface, 0)
            now = current.get(iface, 0)

            speed = now - prev
            items.append((iface, speed))

        # sort theo traffic giảm dần
        items.sort(key=lambda x: x[1], reverse=True)

        self.list_widget.clear()

        for iface, speed in items:
            text = f"{iface}  |  {speed/1024:.2f} KB/s"
            self.list_widget.addItem(text)

        # auto chọn interface có traffic cao nhất
        if self.list_widget.count() > 0:
            self.list_widget.setCurrentRow(0)

        self.prev_traffic = current

    def get_selected_interface(self):
        item = self.list_widget.currentItem()
        print("SCAPY IFACES:", get_interfaces())
        if item:
            return item.text().split("|")[0].strip()
        return None