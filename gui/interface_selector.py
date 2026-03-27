import logging
import time
from PySide6.QtCore import QTimer, Qt
from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QHBoxLayout,
    QPushButton,
    QLabel,
    QLineEdit,
    QComboBox,
    QMenuBar,
    QToolButton,
    QTreeWidget,
    QTreeWidgetItem,
    QAbstractItemView,
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

        # Lịch sử lưu lượng để vẽ mini dashboard (sparkline)
        self.traffic_history = {name: [0.0] * 24 for name in self.interfaces.keys()}
        self.smoothed_speed = {name: 0.0 for name in self.interfaces.keys()}

        # Snapshot 2 lần khi mở selector để xếp interface có traffic lên trước.
        # Dùng delay ngắn để không làm đơ UI quá lâu.
        initial_prev = get_traffic()
        time.sleep(0.25)
        initial_now = get_traffic()

        self.prev_traffic = initial_now
        self.active_interfaces = []
        self.inactive_interfaces = []

        for name in self.interfaces.keys():
            delta = max(initial_now.get(name, 0) - initial_prev.get(name, 0), 0)
            if delta > 0:
                self.active_interfaces.append(name)
            else:
                self.inactive_interfaces.append(name)

        self.refresh_list_structure()
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
        self.list_widget = QTreeWidget()
        self.list_widget.setColumnCount(2)
        self.list_widget.setHeaderLabels(["Interface", "Traffic"])
        self.list_widget.header().setStretchLastSection(False)
        self.list_widget.header().setDefaultAlignment(Qt.AlignLeft)
        self.list_widget.header().resizeSection(0, 720)
        self.list_widget.header().resizeSection(1, 320)
        self.list_widget.setAlternatingRowColors(True)
        self.list_widget.setSelectionMode(QAbstractItemView.SingleSelection)
        self.list_widget.setUniformRowHeights(True)

        # giữ tương thích với main.py (nhấn nút để bắt đầu)
        self.start_btn = QPushButton("Start Capture")
        self.start_btn.setCursor(Qt.PointingHandCursor)
        self.start_btn.setFixedHeight(34)

        self.main_layout.addWidget(self.list_widget, stretch=1)
        self.main_layout.addWidget(self.start_btn)

    def _ordered_interfaces(self):
        return self.active_interfaces + self.inactive_interfaces

    def refresh_list_structure(self):
        selected_display = self.get_selected_display_name()

        self.list_widget.clear()

        for display_name in self._ordered_interfaces():
            item = QTreeWidgetItem([display_name, ""])
            item.setData(0, Qt.UserRole, display_name)
            self.list_widget.addTopLevelItem(item)

        if selected_display:
            self.select_display(selected_display)
        elif self.list_widget.topLevelItemCount() > 0:
            self.list_widget.setCurrentItem(self.list_widget.topLevelItem(0))

    def get_selected_display_name(self):
        item = self.list_widget.currentItem()
        if not item:
            return None
        return item.data(0, Qt.UserRole)

    def select_display(self, display_name):
        for i in range(self.list_widget.topLevelItemCount()):
            item = self.list_widget.topLevelItem(i)
            if item.data(0, Qt.UserRole) == display_name:
                self.list_widget.setCurrentItem(item)
                return

    def _sparkline(self, values):
        bars = "▁▂▃▄▅▆▇█"
        max_val = max(values) if values else 0
        if max_val <= 0:
            return "▁" * max(1, len(values))

        out = []
        for v in values:
            idx = int((v / max_val) * (len(bars) - 1))
            idx = max(0, min(idx, len(bars) - 1))
            out.append(bars[idx])
        return "".join(out)

    def update_list(self):
        current = get_traffic()

        # Nếu interface đang inactive mà có traffic sau khi mở selector,
        # chuyển nó lên cuối nhóm active (giống yêu cầu).
        promoted = []
        for display_name in list(self.inactive_interfaces):
            prev = self.prev_traffic.get(display_name, 0)
            now = current.get(display_name, 0)
            speed = max(now - prev, 0)
            if speed > 0:
                self.inactive_interfaces.remove(display_name)
                self.active_interfaces.append(display_name)
                promoted.append(display_name)

        if promoted:
            log.info(f"Promoted to active (append bottom active-group): {promoted}")
            self.refresh_list_structure()

        # Cập nhật text + dashboard, KHÔNG đảo thứ tự liên tục.
        for i in range(self.list_widget.topLevelItemCount()):
            item = self.list_widget.topLevelItem(i)
            display_name = item.data(0, Qt.UserRole)
            if not display_name:
                continue

            prev = self.prev_traffic.get(display_name, 0)
            now = current.get(display_name, 0)
            speed = max(now - prev, 0)

            history = self.traffic_history.setdefault(display_name, [0.0] * 24)

            # Làm mượt để đồ thị lên/xuống dần thay vì giật cục theo từng giây
            prev_smooth = self.smoothed_speed.get(display_name, 0.0)
            alpha = 0.35
            smooth_speed = (alpha * speed) + ((1 - alpha) * prev_smooth)
            self.smoothed_speed[display_name] = smooth_speed

            history.append(smooth_speed)
            if len(history) > 24:
                history.pop(0)

            spark = self._sparkline(history)
            item.setText(0, f"{display_name}  |  {speed / 1024:.2f} KB/s")
            item.setText(1, spark)

        self.prev_traffic = current

    def get_selected_interface(self):
        """Trả về scapy network name của interface đang chọn."""
        item = self.list_widget.currentItem()
        if not item:
            log.warning("Không có interface nào được chọn.")
            return None

        display_name = item.data(0, Qt.UserRole)
        scapy_name = self.interfaces.get(display_name)
        log.info(f"get_selected_interface: display={display_name!r}  scapy={scapy_name!r}")
        return scapy_name