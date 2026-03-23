from PySide6.QtCore import QThread, Signal
from scapy.all import sniff

class PacketSniffer(QThread):
    packet_captured = Signal(object)

    def __init__(self, iface):
        super().__init__()
        self.iface = iface
        self.running = True

    def run(self):
        sniff(
            iface=self.iface,
            prn=self.handle_packet,
            store=False,
            stop_filter=lambda x: not self.running
        )

    def handle_packet(self, packet):
        self.packet_captured.emit(packet)

    def stop(self):
        self.running = False