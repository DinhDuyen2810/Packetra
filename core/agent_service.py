import argparse
import logging
import re
import sys
import os
import struct
import time
import win32serviceutil
import win32service
import win32event
import servicemanager

def _ensure_scapy():
    try:
        from scapy.all import sniff, get_if_list, raw, Ether, IP, UDP, Raw
        return sniff, get_if_list, raw, Ether, IP, UDP, Raw
    except ModuleNotFoundError:
        raise RuntimeError('Scapy is not installed on remote host. Please install scapy before running the agent.')

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s %(message)s')

def list_interfaces():
    sniff, get_if_list, _raw, _Ether, _IP, _UDP, _Raw = _ensure_scapy()

    def _clean_name(value):
        text = str(value or '').strip()
        if not text:
            return ''
        text = re.sub(r'-(WFP|Fortinet NDIS|Npcap Packet Driver|VirtualBox NDIS|QoS Packet Scheduler|Native WiFi Filter|Virtual WiFi Filter).*$', '', text, flags=re.IGNORECASE)
        text = re.sub(r'-000\d+$', '', text, flags=re.IGNORECASE)
        return text.strip()

    def _is_noise(value):
        low = str(value or '').lower()
        blocked_keywords = (
            'lightweight filter', 'wfp ', 'ndis', 'qos packet scheduler',
            'npcap packet driver', 'virtual wifi filter', 'native wifi filter',
            'miniport', 'teredo', '6to4', 'ip-https', 'kernel debugger',
        )
        return any(k in low for k in blocked_keywords)

    try:
        from scapy.arch.windows import get_windows_if_list
        merged = {}
        for entry in get_windows_if_list():
            if isinstance(entry, dict):
                dev_name = entry.get('name') or ''
                win_name = entry.get('win_name') or ''
                desc = entry.get('description') or entry.get('friendly_name') or ''

                display = _clean_name(win_name) or _clean_name(desc)
                target = str(dev_name).strip() if dev_name else str(win_name).strip()

                if not display:
                    continue
                if _is_noise(display) and _is_noise(target):
                    continue

                key = display.lower()
                score = 0
                if not _is_noise(display):
                    score += 10
                if 'virtual' not in display.lower():
                    score += 2
                prev = merged.get(key)
                if prev is None or score > prev[0]:
                    merged[key] = (score, display, target)
                continue
            try:
                name, dev, _desc = entry
                display = _clean_name(str(name).strip())
                target = str(dev or name).strip()
                if display and not (_is_noise(display) and _is_noise(target)):
                    key = display.lower()
                    prev = merged.get(key)
                    if prev is None:
                        merged[key] = (5, display, target)
            except Exception:
                pass

        rows = sorted((v[1], v[2]) for v in merged.values())
        print('testinterface || testinterface')
        for display, target in rows:
            print(f"{display} || {target}")
        return
    except Exception:
        pass

    print('testinterface || testinterface')
    for iface in get_if_list():
        print(f"{iface} || {iface}")

def capture_to_stdout(iface, bpf_filter='', promiscuous=True):
    if sys.platform == 'win32':
        try:
            import msvcrt
            msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)
        except Exception:
            pass 

    sniff, _get_if_list, raw, Ether, IP, UDP, Raw = _ensure_scapy()
    capture_iface = str(iface or '').strip()
    
    if sys.platform == 'win32':
        try:
            from scapy.arch.windows import get_windows_if_list
            requested = capture_iface.lower()
            for entry in get_windows_if_list():
                if not isinstance(entry, dict):
                    continue
                dev_name = str(entry.get('name') or '').strip()
                win_name = str(entry.get('win_name') or '').strip()
                friendly = str(entry.get('friendly_name') or '').strip()
                desc = str(entry.get('description') or '').strip()
                candidates = [dev_name, win_name, friendly, desc]
                if any(str(c or '').strip().lower() == requested for c in candidates):
                    if dev_name:
                        capture_iface = dev_name
                    break
        except Exception:
            pass

    out = getattr(sys.stdout, 'buffer', sys.stdout)
    out.write(struct.pack('<IHHIIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    out.flush()

    def _emit(pkt_bytes, pkt_time=None):
        now = float(pkt_time) if pkt_time is not None else time.time()
        ts_sec = int(now)
        ts_usec = int((now - ts_sec) * 1_000_000)
        incl_len = len(pkt_bytes)
        out.write(struct.pack('<IIII', ts_sec, ts_usec, incl_len, incl_len))
        out.write(pkt_bytes)
        out.flush()

    if capture_iface.lower() == 'testinterface':
        seq = 1
        while True:
            pkt = Ether(dst='ff:ff:ff:ff:ff:ff', src='02:00:00:00:00:01') / IP(src='10.10.10.1', dst='10.10.10.2') / UDP(sport=50000, dport=50001) / Raw(load=f'packetra-test-{seq}'.encode('ascii'))
            _emit(raw(pkt), pkt_time=time.time())
            seq += 1
            time.sleep(0.25)

    def _write(pkt):
        _emit(raw(pkt), pkt_time=getattr(pkt, 'time', None))

    sniff(
        iface=capture_iface,
        prn=_write,
        store=False,
        filter=bpf_filter or None,
        promisc=bool(promiscuous),
    )


class PacketraAgentService(win32serviceutil.ServiceFramework):
    _svc_name_ = "PacketraAgent"
    _svc_display_name_ = "Packetra Remote Capture Agent"
    _svc_description_ = "Provides remote packet capture capabilities for Packetra over SSH."

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)

    def SvcDoRun(self):
        # Service just waits. The actual command execution is done via SSH executing this script with args.
        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE,
                              servicemanager.PYS_SERVICE_STARTED,
                              (self._svc_name_, ''))
        win32event.WaitForSingleObject(self.hWaitStop, win32event.INFINITE)


def main():
    if len(sys.argv) == 1:
        # Run as service if no arguments
        win32serviceutil.HandleCommandLine(PacketraAgentService)
        return

    parser = argparse.ArgumentParser(description='Packetra Remote Capture Agent')
    parser.add_argument('--list', action='store_true')
    parser.add_argument('--capture', action='store_true')
    parser.add_argument('--iface', default='')
    parser.add_argument('--stdout', action='store_true')
    parser.add_argument('--filter', default='')
    parser.add_argument('--promiscuous', action='store_true')
    
    # Custom hack because win32serviceutil consumes args like 'install', 'start', etc.
    if sys.argv[1] in ('install', 'start', 'stop', 'remove', 'update'):
        win32serviceutil.HandleCommandLine(PacketraAgentService)
        return
        
    args, _ = parser.parse_known_args()

    if args.list:
        list_interfaces()
        return

    if args.capture and args.stdout and args.iface:
        try:
            capture_to_stdout(args.iface, args.filter, args.promiscuous)
        except Exception as exc:
            import traceback
            traceback.print_exc()
            sys.stderr.write(f'capture_to_stdout error: {exc}\n')
            sys.stderr.flush()
            sys.exit(1)
        return

if __name__ == '__main__':
    main()
