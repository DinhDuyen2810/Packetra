import logging
from PySide6.QtCore import QThread, Signal
from scapy.all import sniff

log = logging.getLogger("capture")


class PacketSniffer(QThread):
    packet_captured = Signal(object)
    error_occurred  = Signal(str)       # emit khi sniff() ném exception

    def __init__(self, iface):
        super().__init__()
        self.iface   = iface
        self.running = True
        log.debug(f"PacketSniffer tạo cho iface={iface!r}")

    def run(self):
        log.info(f"Bắt đầu sniff trên {self.iface!r}")
        try:
            sniff(
                iface=self.iface,
                prn=self.handle_packet,
                store=False,
                stop_filter=lambda x: not self.running,
            )
        except Exception as e:
            msg = f"sniff() lỗi trên {self.iface!r}: {e}"
            log.error(msg)
            self.error_occurred.emit(msg)
        log.info("sniff() đã kết thúc.")

    def handle_packet(self, packet):
        self.packet_captured.emit(packet)

    def stop(self):
        log.info("Đặt running=False để dừng sniffer.")
        self.running = False