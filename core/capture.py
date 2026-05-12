import logging
from PySide6.QtCore import QThread, Signal
from scapy.all import sniff

log = logging.getLogger('capture')

class PacketSniffer(QThread):
    packet_captured = Signal(object)
    error_occurred = Signal(str)
    status_changed = Signal(str)

    def __init__(self, iface: str, capture_filter: str = ''):
        super().__init__()
        self.iface = iface
        self.capture_filter = (capture_filter or '').strip()
        self.running = True

    def run(self):
        self.status_changed.emit(f'Capturing on {self.iface}')
        try:
            while self.running:
                sniff(
                    iface=self.iface,
                    prn=self.handle_packet,
                    store=False,
                    timeout=0.2,
                    filter=self.capture_filter or None,
                )
        except Exception as exc:
            msg = f'Capture failed on {self.iface}: {exc}'
            log.exception(msg)
            self.error_occurred.emit(msg)
        finally:
            self.status_changed.emit('Capture stopped')

    def handle_packet(self, packet):

        if not self.running:
            return

        # ---- preserve interface metadata ----

        if not hasattr(packet, 'sniffed_on') or not packet.sniffed_on:
            packet.sniffed_on = self.iface

        # optional aliases for formatter
        packet.interface_name = packet.sniffed_on
        packet.interface_description = 'Ethernet'

        self.packet_captured.emit(packet)

    def stop(self):
        self.running = False
