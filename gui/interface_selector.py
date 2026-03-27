import logging
from PySide6.QtCore import QTimer, Qt
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QListWidget,
    QPushButton,
    QLabel,
    QLineEdit,
    QComboBox,
    QMenuBar,
    QToolButton,
)

from utils.network_utils import get_interfaces, get_traffic

log = logging.getLogger("interface_selector")


class InterfaceSelector(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Packetra Network Analyzer")
        self.resize(1200, 760)

        self.main_layout = QVBoxLayout()
        self.main_layout.setContentsMargins(10, 8, 10, 10)
        self.main_layout.setSpacing(8)

        self._build_menu_bar()
        self._build_toolbar()
        self._build_filter_row()
        self._build_capture_header()
        self._build_interface_list()

        self.setLayout(self.main_layout)

        # {display_name: scapy_name}
        self.interfaces = get_interfaces()
        log.info(f"Interfaces found: { {k: v for k, v in self.interfaces.items()} }")

        self.prev_traffic = get_traffic()
        self.update_list()

        # QTimer: cập nhật traffic mỗi 1 giây
        self._timer = QTimer(self)
        self._timer.timeout.connect(self.update_list)
        self._timer.start(1000)
        log.debug("Timer started (1000ms)")

    def _build_menu_bar(self):
        menu_bar = QMenuBar()
        for name in ["File", "Edit", "View", "Go", "Capture", "Analyze", "Statistics", "Telephony", "Wireless", "Tools", "Help"]:
            menu_bar.addMenu(name)
        self.main_layout.addWidget(menu_bar)

    def _build_toolbar(self):
        toolbar_row = QHBoxLayout()
        toolbar_row.setSpacing(6)

        for text in ["▶", "■", "⟳", "⚙", "📁", "💾", "🔍", "↶", "↷"]:
            btn = QToolButton()
            btn.setText(text)
            btn.setEnabled(False)
            btn.setFixedSize(28, 26)
            toolbar_row.addWidget(btn)

        toolbar_row.addStretch()
        self.main_layout.addLayout(toolbar_row)

    def _build_filter_row(self):
        row = QHBoxLayout()
        row.setSpacing(6)

        self.display_filter_input = QLineEdit()
        self.display_filter_input.setPlaceholderText("Apply a display filter ... <Ctrl-/>")

        self.apply_filter_btn = QPushButton("➡")
        self.apply_filter_btn.setEnabled(False)
        self.apply_filter_btn.setFixedWidth(36)

        self.extra_btn = QPushButton("+")
        self.extra_btn.setEnabled(False)
        self.extra_btn.setFixedWidth(28)

        row.addWidget(self.display_filter_input)
        row.addWidget(self.apply_filter_btn)
        row.addWidget(self.extra_btn)
        self.main_layout.addLayout(row)

    def _build_capture_header(self):
        title = QLabel("Capture")
        title.setStyleSheet("font-size: 34px; font-weight: 700;")

        subtitle_row = QHBoxLayout()
        subtitle_row.setSpacing(6)

        using_filter_label = QLabel("...using this filter")
        using_filter_label.setStyleSheet("font-weight: 600;")

        self.capture_filter_input = QLineEdit()
        self.capture_filter_input.setPlaceholderText("Enter a capture filter ...")

        self.interface_scope_combo = QComboBox()
        self.interface_scope_combo.addItems(["All interfaces shown", "Only active interfaces", "Wireless only"])

        subtitle_row.addWidget(using_filter_label)
        subtitle_row.addWidget(self.capture_filter_input)
        subtitle_row.addWidget(self.interface_scope_combo)

        self.main_layout.addSpacing(8)
        self.main_layout.addWidget(title)
        self.main_layout.addLayout(subtitle_row)

    def _build_interface_list(self):
        self.list_widget = QListWidget()
        self.list_widget.setAlternatingRowColors(True)
        self.list_widget.setSelectionMode(QListWidget.SingleSelection)
        self.list_widget.setUniformItemSizes(True)

        # giữ tương thích với main.py (nhấn nút để bắt đầu)
        self.start_btn = QPushButton("Start Capture")
        self.start_btn.setCursor(Qt.PointingHandCursor)
        self.start_btn.setFixedHeight(34)

        self.main_layout.addWidget(self.list_widget, stretch=1)
        self.main_layout.addWidget(self.start_btn)

    def update_list(self):
        current = get_traffic()

        items = []
        for display_name, scapy_name in self.interfaces.items():
            prev = self.prev_traffic.get(display_name, 0)
            now = current.get(display_name, 0)
            speed = max(now - prev, 0)  # bytes trong 1 giây
            items.append((display_name, scapy_name, speed))
            log.debug(f"  {display_name}: {speed / 1024:.2f} KB/s")

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