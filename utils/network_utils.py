import psutil
import sys
import json


def get_interface_details():
    """Get interface details including GUID and description for Windows."""
    details = {}
    
    if sys.platform == 'win32':
        try:
            from scapy.all import conf
            from scapy.arch.windows import get_windows_if_list
            import re
            
            # Get Scapy's Windows interface list (includes GUID)
            try:
                win_ifaces = get_windows_if_list()  # Returns list of (name, guid, description) tuples
                guid_map = {name: guid for name, guid, _ in win_ifaces}
            except Exception:
                guid_map = {}
            
            # Build mapping: interface_name -> details
            interfaces_dict = get_interfaces()  # {iface_name: display_name}
            
            # Map Scapy objects by interface name
            for iface_obj in conf.ifaces.values():
                iface_name = getattr(iface_obj, 'name', '')
                
                # Only process interfaces we know about
                if iface_name not in interfaces_dict:
                    continue
                
                # Try to get GUID from Windows interface list first
                guid_str = guid_map.get(iface_name)
                
                # If not found, try parsing from Scapy object
                if not guid_str:
                    # Try various Scapy attributes
                    for attr in ['pcap_name', '_name', 'network_name']:
                        if hasattr(iface_obj, attr):
                            val = str(getattr(iface_obj, attr, ''))
                            if '{' in val and '}' in val:  # Contains GUID with braces
                                guid_str = val
                                break
                
                # Extract GUID pattern if we have a string like \Device\NPF_Ethernet
                if not guid_str or not ('{' in guid_str):
                    obj_repr = repr(iface_obj)
                    match = re.search(r'\{[0-9A-Fa-f-]+\}', obj_repr)
                    if match:
                        guid_str = f'\\Device\\NPF_{match.group(0)}'
                
                # Ensure proper format with \Device\NPF_
                if guid_str and not guid_str.startswith('\\Device\\'):
                    if '{' in guid_str:
                        guid_str = f'\\Device\\NPF_{{{guid_str.strip("{}")}}}'
                    else:
                        guid_str = f'\\Device\\NPF_{guid_str}'
                
                # Fallback to device name if no GUID found
                if not guid_str:
                    guid_str = f'\\Device\\NPF_{iface_name}'
                
                # Extract description from Scapy
                description = getattr(iface_obj, 'description', '') or ''
                
                # Get friendly name from our interfaces dict
                friendly_name = interfaces_dict.get(iface_name, iface_name)
                
                details[iface_name] = {
                    'guid': guid_str,
                    'friendly_name': friendly_name,
                    'description': description
                }
        except Exception:
            pass
    
    return details


def get_interfaces():
    result = {}
    try:
        from scapy.all import conf
        scapy_map = {}
        for iface in conf.ifaces.values():
            desc = (getattr(iface, 'description', '') or '').lower()
            network_name = getattr(iface, 'network_name', '') or getattr(iface, 'name', '') or ''
            if desc and network_name:
                scapy_map[desc] = network_name
        for name in psutil.net_io_counters(pernic=True).keys():
            result[name] = scapy_map.get(name.lower(), name)
    except Exception:
        for name in psutil.net_io_counters(pernic=True).keys():
            result[name] = name
    return result


def get_traffic():
    stats = psutil.net_io_counters(pernic=True)
    return {iface: data.bytes_sent + data.bytes_recv for iface, data in stats.items()}
