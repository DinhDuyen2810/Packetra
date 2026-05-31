from __future__ import annotations

from dataclasses import dataclass


PRODUCT_CISCO = "Cisco IOS ACL"
PRODUCT_IPFILTER = "IP Filter (ipfilter)"
PRODUCT_IPFW = "IPFirewall (ipfw)"
PRODUCT_IPTABLES = "Netfilter (iptables)"
PRODUCT_PF = "Packet Filter (pf)"
PRODUCT_NETSH_OLD = "Windows Firewall netsh (old syntax)"
PRODUCT_NETSH_NEW = "Windows Firewall netsh (new syntax)"
# Compatibility alias used by existing UI code.
PRODUCT_NETSH = PRODUCT_NETSH_NEW

ACTION_ALLOW = "allow"
ACTION_DENY = "deny"

DIRECTION_INBOUND = "inbound"
DIRECTION_OUTBOUND = "outbound"

RULE_SOURCE_MAC = "source_mac"
RULE_DESTINATION_MAC = "destination_mac"
RULE_SOURCE_IPV4 = "source_ipv4"
RULE_DESTINATION_IPV4 = "destination_ipv4"
RULE_SOURCE_TCP_PORT = "source_tcp_port"
RULE_DESTINATION_TCP_PORT = "destination_tcp_port"
RULE_SOURCE_UDP_PORT = "source_udp_port"
RULE_DESTINATION_UDP_PORT = "destination_udp_port"
RULE_SOURCE_IPV4_PORT = "source_ipv4_source_port"
RULE_DESTINATION_IPV4_PORT = "destination_ipv4_destination_port"
RULE_IPV4_PAIR = "ipv4_pair"
RULE_IPV4_PAIR_PORT_PAIR = "ipv4_pair_port_pair"

RULE_TYPES = [
    (RULE_SOURCE_MAC, "Source MAC Address"),
    (RULE_DESTINATION_MAC, "Destination MAC Address"),
    (RULE_SOURCE_IPV4, "Source IPv4 Address"),
    (RULE_DESTINATION_IPV4, "Destination IPv4 Address"),
    (RULE_SOURCE_TCP_PORT, "Source TCP Port"),
    (RULE_DESTINATION_TCP_PORT, "Destination TCP Port"),
    (RULE_SOURCE_UDP_PORT, "Source UDP Port"),
    (RULE_DESTINATION_UDP_PORT, "Destination UDP Port"),
    (RULE_SOURCE_IPV4_PORT, "Source IPv4 + Source Port"),
    (RULE_DESTINATION_IPV4_PORT, "Destination IPv4 + Destination Port"),
    (RULE_IPV4_PAIR, "IPv4 Pair"),
    (RULE_IPV4_PAIR_PORT_PAIR, "IPv4 Pair + Port Pair"),
]

RULE_LABELS = {rule_id: label for rule_id, label in RULE_TYPES}


@dataclass(frozen=True)
class PacketAclSnapshot:
    frame_number: int
    protocol: str
    eth_src: str = ""
    eth_dst: str = ""
    ip_src: str = ""
    ip_dst: str = ""
    ip_proto: int | None = None
    tcp_src_port: int | None = None
    tcp_dst_port: int | None = None
    udp_src_port: int | None = None
    udp_dst_port: int | None = None
    interface_name: str = ""

    def has_acl_usable_fields(self) -> bool:
        return any(
            [
                bool(self.eth_src),
                bool(self.eth_dst),
                bool(self.ip_src),
                bool(self.ip_dst),
                self.tcp_src_port is not None,
                self.tcp_dst_port is not None,
                self.udp_src_port is not None,
                self.udp_dst_port is not None,
            ]
        )


def action_keyword(product: str, action: str) -> str:
    allow = str(action or ACTION_ALLOW).lower() == ACTION_ALLOW
    if product == PRODUCT_CISCO:
        return "permit" if allow else "deny"
    if product in {PRODUCT_IPFILTER, PRODUCT_PF}:
        return "pass" if allow else "block"
    if product == PRODUCT_IPFW:
        return "allow" if allow else "deny"
    if product == PRODUCT_IPTABLES:
        return "ACCEPT" if allow else "DROP"
    if product == PRODUCT_NETSH_OLD:
        return "ENABLE" if allow else "DISABLE"
    if product == PRODUCT_NETSH_NEW:
        return "allow" if allow else "block"
    return "allow" if allow else "deny"


def _has_tcp_ports(snapshot: PacketAclSnapshot) -> bool:
    return snapshot.tcp_src_port is not None or snapshot.tcp_dst_port is not None


def _has_udp_ports(snapshot: PacketAclSnapshot) -> bool:
    return snapshot.udp_src_port is not None or snapshot.udp_dst_port is not None


def rule_type_supported_by_packet(snapshot: PacketAclSnapshot, rule_type: str) -> bool:
    if rule_type == RULE_SOURCE_MAC:
        return bool(snapshot.eth_src)
    if rule_type == RULE_DESTINATION_MAC:
        return bool(snapshot.eth_dst)
    if rule_type == RULE_SOURCE_IPV4:
        return bool(snapshot.ip_src)
    if rule_type == RULE_DESTINATION_IPV4:
        return bool(snapshot.ip_dst)
    if rule_type == RULE_SOURCE_TCP_PORT:
        return snapshot.tcp_src_port is not None
    if rule_type == RULE_DESTINATION_TCP_PORT:
        return snapshot.tcp_dst_port is not None
    if rule_type == RULE_SOURCE_UDP_PORT:
        return snapshot.udp_src_port is not None
    if rule_type == RULE_DESTINATION_UDP_PORT:
        return snapshot.udp_dst_port is not None
    if rule_type == RULE_SOURCE_IPV4_PORT:
        return bool(snapshot.ip_src) and (_has_tcp_ports(snapshot) or _has_udp_ports(snapshot))
    if rule_type == RULE_DESTINATION_IPV4_PORT:
        return bool(snapshot.ip_dst) and (_has_tcp_ports(snapshot) or _has_udp_ports(snapshot))
    if rule_type == RULE_IPV4_PAIR:
        return bool(snapshot.ip_src) and bool(snapshot.ip_dst)
    if rule_type == RULE_IPV4_PAIR_PORT_PAIR:
        has_tcp_pair = snapshot.tcp_src_port is not None and snapshot.tcp_dst_port is not None
        has_udp_pair = snapshot.udp_src_port is not None and snapshot.udp_dst_port is not None
        return bool(snapshot.ip_src) and bool(snapshot.ip_dst) and (has_tcp_pair or has_udp_pair)
    return False


def product_supports_rule_type(product: str, rule_type: str) -> bool:
    if product in {PRODUCT_NETSH_OLD, PRODUCT_NETSH_NEW}:
        return rule_type in {
            RULE_SOURCE_TCP_PORT,
            RULE_DESTINATION_TCP_PORT,
            RULE_SOURCE_UDP_PORT,
            RULE_DESTINATION_UDP_PORT,
            RULE_SOURCE_IPV4_PORT,
            RULE_DESTINATION_IPV4_PORT,
        }
    if product in {PRODUCT_IPFILTER, PRODUCT_PF, PRODUCT_CISCO}:
        return rule_type not in {RULE_SOURCE_MAC, RULE_DESTINATION_MAC}
    if product in {PRODUCT_IPFW, PRODUCT_IPTABLES}:
        return True
    return False


def available_rule_types(snapshot: PacketAclSnapshot, product: str) -> list[dict]:
    result = []
    for rule_id, label in RULE_TYPES:
        packet_ok = rule_type_supported_by_packet(snapshot, rule_id)
        product_ok = product_supports_rule_type(product, rule_id)
        enabled = packet_ok and product_ok
        reason = ""
        if not packet_ok:
            reason = "This packet does not contain required fields for this rule type."
        elif not product_ok:
            reason = "The selected firewall product does not support this rule type."
        result.append({"id": rule_id, "label": label, "enabled": enabled, "reason": reason})
    return result


def _prefer_transport_for_ports(snapshot: PacketAclSnapshot, prefer_source: bool = True) -> tuple[str, int]:
    if prefer_source:
        if snapshot.tcp_src_port is not None:
            return "tcp", int(snapshot.tcp_src_port)
        if snapshot.udp_src_port is not None:
            return "udp", int(snapshot.udp_src_port)
        if snapshot.tcp_dst_port is not None:
            return "tcp", int(snapshot.tcp_dst_port)
        if snapshot.udp_dst_port is not None:
            return "udp", int(snapshot.udp_dst_port)
    else:
        if snapshot.tcp_dst_port is not None:
            return "tcp", int(snapshot.tcp_dst_port)
        if snapshot.udp_dst_port is not None:
            return "udp", int(snapshot.udp_dst_port)
        if snapshot.tcp_src_port is not None:
            return "tcp", int(snapshot.tcp_src_port)
        if snapshot.udp_src_port is not None:
            return "udp", int(snapshot.udp_src_port)
    raise ValueError("This packet does not contain TCP or UDP port information.")


def _pair_transport(snapshot: PacketAclSnapshot) -> tuple[str, int, int]:
    if snapshot.tcp_src_port is not None and snapshot.tcp_dst_port is not None:
        return "tcp", int(snapshot.tcp_src_port), int(snapshot.tcp_dst_port)
    if snapshot.udp_src_port is not None and snapshot.udp_dst_port is not None:
        return "udp", int(snapshot.udp_src_port), int(snapshot.udp_dst_port)
    raise ValueError("This packet does not contain complete source/destination port pair.")


def _ip32(ip: str) -> str:
    text = str(ip or "").strip()
    if not text:
        return text
    return text if "/" in text else f"{text}/32"


def _iptables_chain(direction: str) -> str:
    return "INPUT" if str(direction or DIRECTION_INBOUND).lower() == DIRECTION_INBOUND else "OUTPUT"


def _ipf_direction(direction: str) -> str:
    return "in" if str(direction or DIRECTION_INBOUND).lower() == DIRECTION_INBOUND else "out"


def _interface_or(snapshot: PacketAclSnapshot, default_name: str) -> str:
    value = str(snapshot.interface_name or "").strip()
    return value or default_name


def _rule_header(product_name: str, snapshot: PacketAclSnapshot, direction: str, action: str) -> str:
    dir_label = "inbound" if str(direction).lower() == DIRECTION_INBOUND else "outbound"
    act_label = "allow" if str(action).lower() == ACTION_ALLOW else "deny"
    return (
        f"! {product_name} rule for packet {int(snapshot.frame_number)}\n"
        f"! Direction={dir_label}, Action={act_label}\n"
    )


def generate_rule(
    snapshot: PacketAclSnapshot,
    product: str,
    action: str,
    direction: str,
    rule_type: str,
) -> str:
    if not rule_type_supported_by_packet(snapshot, rule_type):
        raise ValueError("This packet does not contain required information for the selected rule type.")
    if not product_supports_rule_type(product, rule_type):
        raise ValueError("The selected firewall product does not support this rule type.")

    if product == PRODUCT_CISCO:
        return _generate_cisco(snapshot, action, direction, rule_type)
    if product == PRODUCT_IPFILTER:
        return _generate_ipfilter(snapshot, action, direction, rule_type)
    if product == PRODUCT_IPFW:
        return _generate_ipfw(snapshot, action, direction, rule_type)
    if product == PRODUCT_IPTABLES:
        return _generate_iptables(snapshot, action, direction, rule_type)
    if product == PRODUCT_PF:
        return _generate_pf(snapshot, action, direction, rule_type)
    if product == PRODUCT_NETSH_OLD:
        return _generate_netsh_old(snapshot, action, direction, rule_type)
    if product == PRODUCT_NETSH_NEW:
        return _generate_netsh_new(snapshot, action, direction, rule_type)
    raise ValueError("Unsupported firewall product.")


def generate_rules_bundle(
    snapshot: PacketAclSnapshot,
    product: str,
    action: str,
    direction: str,
) -> str:
    ordered = [
        RULE_SOURCE_IPV4,
        RULE_DESTINATION_IPV4,
        RULE_SOURCE_TCP_PORT,
        RULE_DESTINATION_TCP_PORT,
        RULE_SOURCE_UDP_PORT,
        RULE_DESTINATION_UDP_PORT,
        RULE_SOURCE_IPV4_PORT,
        RULE_DESTINATION_IPV4_PORT,
        RULE_IPV4_PAIR,
        RULE_IPV4_PAIR_PORT_PAIR,
        RULE_SOURCE_MAC,
        RULE_DESTINATION_MAC,
    ]
    lines = [f"! {product} rules for packet {int(snapshot.frame_number)}"]
    any_rule = False
    for rule_type in ordered:
        if not rule_type_supported_by_packet(snapshot, rule_type):
            continue
        if not product_supports_rule_type(product, rule_type):
            continue
        try:
            body = generate_rule(snapshot, product, action, direction, rule_type)
        except Exception:
            continue
        any_rule = True
        lines.append("")
        lines.append(f"! {RULE_LABELS.get(rule_type, rule_type)}")
        body_lines = [str(v).rstrip() for v in str(body or "").splitlines()]
        if body_lines and body_lines[0].startswith("! "):
            body_lines = body_lines[1:]
        lines.extend([line for line in body_lines if line != ""])
    if not any_rule:
        raise ValueError("No applicable rules can be generated from this packet for the selected product.")
    return "\n".join(lines).strip()


def _generate_cisco(snapshot: PacketAclSnapshot, action: str, direction: str, rule_type: str) -> str:
    action_kw = action_keyword(PRODUCT_CISCO, action)
    header = _rule_header(PRODUCT_CISCO, snapshot, direction, action)
    if rule_type == RULE_SOURCE_IPV4:
        return (
            f"{header}! Standard ACL\n"
            f"access-list NUMBER {action_kw} host {snapshot.ip_src}\n\n"
            f"! Extended ACL\n"
            f"access-list NUMBER {action_kw} ip host {snapshot.ip_src} any"
        )
    if rule_type == RULE_DESTINATION_IPV4:
        return (
            f"{header}! Standard ACL\n"
            f"access-list NUMBER {action_kw} host {snapshot.ip_dst}\n\n"
            f"! Extended ACL\n"
            f"access-list NUMBER {action_kw} ip host {snapshot.ip_dst} any"
        )
    if rule_type == RULE_SOURCE_TCP_PORT:
        return f"{header}access-list NUMBER {action_kw} tcp any any eq {int(snapshot.tcp_src_port)}"
    if rule_type == RULE_DESTINATION_TCP_PORT:
        return f"{header}access-list NUMBER {action_kw} tcp any any eq {int(snapshot.tcp_dst_port)}"
    if rule_type == RULE_SOURCE_UDP_PORT:
        return f"{header}access-list NUMBER {action_kw} udp any any eq {int(snapshot.udp_src_port)}"
    if rule_type == RULE_DESTINATION_UDP_PORT:
        return f"{header}access-list NUMBER {action_kw} udp any any eq {int(snapshot.udp_dst_port)}"
    if rule_type == RULE_SOURCE_IPV4_PORT:
        proto, port = _prefer_transport_for_ports(snapshot, prefer_source=True)
        return f"{header}access-list NUMBER {action_kw} {proto} host {snapshot.ip_src} eq {port} any"
    if rule_type == RULE_DESTINATION_IPV4_PORT:
        proto, port = _prefer_transport_for_ports(snapshot, prefer_source=False)
        return f"{header}access-list NUMBER {action_kw} {proto} host {snapshot.ip_dst} eq {port} any"
    if rule_type == RULE_IPV4_PAIR:
        return f"{header}access-list NUMBER {action_kw} ip host {snapshot.ip_src} host {snapshot.ip_dst}"
    if rule_type == RULE_IPV4_PAIR_PORT_PAIR:
        proto, sport, dport = _pair_transport(snapshot)
        return f"{header}access-list NUMBER {action_kw} {proto} host {snapshot.ip_src} eq {sport} host {snapshot.ip_dst} eq {dport}"
    raise ValueError("The selected firewall product does not support this rule type.")


def _generate_ipfilter(snapshot: PacketAclSnapshot, action: str, direction: str, rule_type: str) -> str:
    action_kw = action_keyword(PRODUCT_IPFILTER, action)
    iface = _interface_or(snapshot, "le0")
    ipf_dir = _ipf_direction(direction)
    header = _rule_header(PRODUCT_IPFILTER, snapshot, direction, action)
    base = f"{action_kw} {ipf_dir} on {iface}"
    if rule_type == RULE_SOURCE_IPV4:
        return f"{header}{base} from {snapshot.ip_src} to any"
    if rule_type == RULE_DESTINATION_IPV4:
        return f"{header}{base} from {snapshot.ip_dst} to any"
    if rule_type == RULE_SOURCE_TCP_PORT:
        return f"{header}{base} proto tcp from any to any port = {int(snapshot.tcp_src_port)}"
    if rule_type == RULE_DESTINATION_TCP_PORT:
        return f"{header}{base} proto tcp from any to any port = {int(snapshot.tcp_dst_port)}"
    if rule_type == RULE_SOURCE_UDP_PORT:
        return f"{header}{base} proto udp from any to any port = {int(snapshot.udp_src_port)}"
    if rule_type == RULE_DESTINATION_UDP_PORT:
        return f"{header}{base} proto udp from any to any port = {int(snapshot.udp_dst_port)}"
    if rule_type == RULE_SOURCE_IPV4_PORT:
        proto, port = _prefer_transport_for_ports(snapshot, prefer_source=True)
        return f"{header}{base} proto {proto} from {snapshot.ip_src} port = {port} to any"
    if rule_type == RULE_DESTINATION_IPV4_PORT:
        proto, port = _prefer_transport_for_ports(snapshot, prefer_source=False)
        return f"{header}{base} proto {proto} from {snapshot.ip_dst} port = {port} to any"
    if rule_type == RULE_IPV4_PAIR:
        return f"{header}{base} from {snapshot.ip_src} to {snapshot.ip_dst}"
    if rule_type == RULE_IPV4_PAIR_PORT_PAIR:
        proto, sport, dport = _pair_transport(snapshot)
        return f"{header}{base} proto {proto} from {snapshot.ip_src} port = {sport} to {snapshot.ip_dst} port = {dport}"
    raise ValueError("The selected firewall product does not support this rule type.")


def _generate_ipfw(snapshot: PacketAclSnapshot, action: str, direction: str, rule_type: str) -> str:
    action_kw = action_keyword(PRODUCT_IPFW, action)
    ipfw_dir = "in" if str(direction or DIRECTION_INBOUND).lower() == DIRECTION_INBOUND else "out"
    header = _rule_header(PRODUCT_IPFW, snapshot, direction, action)
    if rule_type == RULE_SOURCE_MAC:
        return f"{header}add {action_kw} MAC {snapshot.eth_src} any {ipfw_dir}"
    if rule_type == RULE_DESTINATION_MAC:
        return f"{header}add {action_kw} MAC {snapshot.eth_dst} any {ipfw_dir}"
    if rule_type == RULE_SOURCE_IPV4:
        return f"{header}add {action_kw} ip from {snapshot.ip_src} to any {ipfw_dir}"
    if rule_type == RULE_DESTINATION_IPV4:
        return f"{header}add {action_kw} ip from {snapshot.ip_dst} to any {ipfw_dir}"
    if rule_type == RULE_SOURCE_TCP_PORT:
        return f"{header}add {action_kw} tcp from any to any {int(snapshot.tcp_src_port)} {ipfw_dir}"
    if rule_type == RULE_DESTINATION_TCP_PORT:
        return f"{header}add {action_kw} tcp from any to any {int(snapshot.tcp_dst_port)} {ipfw_dir}"
    if rule_type == RULE_SOURCE_UDP_PORT:
        return f"{header}add {action_kw} udp from any to any {int(snapshot.udp_src_port)} {ipfw_dir}"
    if rule_type == RULE_DESTINATION_UDP_PORT:
        return f"{header}add {action_kw} udp from any to any {int(snapshot.udp_dst_port)} {ipfw_dir}"
    if rule_type == RULE_SOURCE_IPV4_PORT:
        proto, port = _prefer_transport_for_ports(snapshot, prefer_source=True)
        return f"{header}add {action_kw} {proto} from {snapshot.ip_src} {port} to any {ipfw_dir}"
    if rule_type == RULE_DESTINATION_IPV4_PORT:
        proto, port = _prefer_transport_for_ports(snapshot, prefer_source=False)
        return f"{header}add {action_kw} {proto} from {snapshot.ip_dst} {port} to any {ipfw_dir}"
    if rule_type == RULE_IPV4_PAIR:
        return f"{header}add {action_kw} ip from {snapshot.ip_src} to {snapshot.ip_dst} {ipfw_dir}"
    if rule_type == RULE_IPV4_PAIR_PORT_PAIR:
        proto, sport, dport = _pair_transport(snapshot)
        return f"{header}add {action_kw} {proto} from {snapshot.ip_src} {sport} to {snapshot.ip_dst} {dport} {ipfw_dir}"
    raise ValueError("Unsupported rule type.")


def _generate_iptables(snapshot: PacketAclSnapshot, action: str, direction: str, rule_type: str) -> str:
    action_kw = action_keyword(PRODUCT_IPTABLES, action)
    chain = _iptables_chain(direction)
    iface = _interface_or(snapshot, "eth0")
    iface_flag = "--in-interface" if chain == "INPUT" else "--out-interface"
    header = _rule_header(PRODUCT_IPTABLES, snapshot, direction, action)
    base = f"iptables --append {chain} {iface_flag} {iface}"
    if rule_type == RULE_SOURCE_MAC:
        return f"{header}{base} --mac-source {snapshot.eth_src} --jump {action_kw}"
    if rule_type == RULE_DESTINATION_MAC:
        return f"{header}{base} --mac-source {snapshot.eth_dst} --jump {action_kw}"
    if rule_type == RULE_SOURCE_IPV4:
        return f"{header}{base} --source {_ip32(snapshot.ip_src)} --jump {action_kw}"
    if rule_type == RULE_DESTINATION_IPV4:
        return f"{header}{base} --destination {_ip32(snapshot.ip_dst)} --jump {action_kw}"
    if rule_type == RULE_SOURCE_TCP_PORT:
        return f"{header}{base} --protocol tcp --source-port {int(snapshot.tcp_src_port)} --jump {action_kw}"
    if rule_type == RULE_DESTINATION_TCP_PORT:
        return f"{header}{base} --protocol tcp --destination-port {int(snapshot.tcp_dst_port)} --jump {action_kw}"
    if rule_type == RULE_SOURCE_UDP_PORT:
        return f"{header}{base} --protocol udp --source-port {int(snapshot.udp_src_port)} --jump {action_kw}"
    if rule_type == RULE_DESTINATION_UDP_PORT:
        return f"{header}{base} --protocol udp --destination-port {int(snapshot.udp_dst_port)} --jump {action_kw}"
    if rule_type == RULE_SOURCE_IPV4_PORT:
        proto, port = _prefer_transport_for_ports(snapshot, prefer_source=True)
        return f"{header}{base} --protocol {proto} --source {_ip32(snapshot.ip_src)} --source-port {port} --jump {action_kw}"
    if rule_type == RULE_DESTINATION_IPV4_PORT:
        proto, port = _prefer_transport_for_ports(snapshot, prefer_source=False)
        return f"{header}{base} --protocol {proto} --source {_ip32(snapshot.ip_dst)} --source-port {port} --jump {action_kw}"
    if rule_type == RULE_IPV4_PAIR:
        return f"{header}{base} --source {_ip32(snapshot.ip_src)} --destination {_ip32(snapshot.ip_dst)} --jump {action_kw}"
    if rule_type == RULE_IPV4_PAIR_PORT_PAIR:
        proto, sport, dport = _pair_transport(snapshot)
        return f"{header}{base} --protocol {proto} --source {_ip32(snapshot.ip_src)} --source-port {sport} --destination {_ip32(snapshot.ip_dst)} --destination-port {dport} --jump {action_kw}"
    raise ValueError("Unsupported rule type.")


def _generate_pf(snapshot: PacketAclSnapshot, action: str, direction: str, rule_type: str) -> str:
    action_kw = action_keyword(PRODUCT_PF, action)
    pf_dir = _ipf_direction(direction)
    header = _rule_header(PRODUCT_PF, snapshot, direction, action)
    base = f"{action_kw} {pf_dir} quick on $ext_if"
    if rule_type == RULE_SOURCE_IPV4:
        return f"{header}{base} from {snapshot.ip_src} to any"
    if rule_type == RULE_DESTINATION_IPV4:
        return f"{header}{base} from {snapshot.ip_dst} to any"
    if rule_type == RULE_SOURCE_TCP_PORT:
        return f"{header}{base} proto tcp from any to any port {int(snapshot.tcp_src_port)}"
    if rule_type == RULE_DESTINATION_TCP_PORT:
        return f"{header}{base} proto tcp from any to any port {int(snapshot.tcp_dst_port)}"
    if rule_type == RULE_SOURCE_UDP_PORT:
        return f"{header}{base} proto udp from any to any port {int(snapshot.udp_src_port)}"
    if rule_type == RULE_DESTINATION_UDP_PORT:
        return f"{header}{base} proto udp from any to any port {int(snapshot.udp_dst_port)}"
    if rule_type == RULE_SOURCE_IPV4_PORT:
        proto, port = _prefer_transport_for_ports(snapshot, prefer_source=True)
        return f"{header}{base} proto {proto} from {snapshot.ip_src} to any port {port}"
    if rule_type == RULE_DESTINATION_IPV4_PORT:
        proto, port = _prefer_transport_for_ports(snapshot, prefer_source=False)
        return f"{header}{base} proto {proto} from {snapshot.ip_dst} to any port {port}"
    if rule_type == RULE_IPV4_PAIR:
        return f"{header}{base} from {snapshot.ip_src} to {snapshot.ip_dst}"
    if rule_type == RULE_IPV4_PAIR_PORT_PAIR:
        proto, sport, dport = _pair_transport(snapshot)
        return f"{header}{base} proto {proto} from {snapshot.ip_src} port {sport} to {snapshot.ip_dst} port {dport}"
    raise ValueError("The selected firewall product does not support this rule type.")


def _generate_netsh_old(snapshot: PacketAclSnapshot, action: str, direction: str, rule_type: str) -> str:
    enabled = action_keyword(PRODUCT_NETSH_OLD, action)
    proto, s_port = _prefer_transport_for_ports(snapshot, prefer_source=True)
    _proto2, d_port = _prefer_transport_for_ports(snapshot, prefer_source=False)
    header = _rule_header(PRODUCT_NETSH_OLD, snapshot, direction, action)
    if rule_type == RULE_SOURCE_TCP_PORT:
        return f"{header}add portopening tcp {int(snapshot.tcp_src_port)} Wireshark {enabled}"
    if rule_type == RULE_DESTINATION_TCP_PORT:
        return f"{header}add portopening tcp {int(snapshot.tcp_dst_port)} Wireshark {enabled}"
    if rule_type == RULE_SOURCE_UDP_PORT:
        return f"{header}add portopening udp {int(snapshot.udp_src_port)} Wireshark {enabled}"
    if rule_type == RULE_DESTINATION_UDP_PORT:
        return f"{header}add portopening udp {int(snapshot.udp_dst_port)} Wireshark {enabled}"
    if rule_type == RULE_SOURCE_IPV4_PORT:
        return f"{header}add portopening {proto} {s_port} Wireshark {enabled} {snapshot.ip_src}"
    if rule_type == RULE_DESTINATION_IPV4_PORT:
        return f"{header}add portopening {proto} {d_port} Wireshark {enabled} {snapshot.ip_dst}"
    raise ValueError("The selected firewall product does not support this rule type.")


def _generate_netsh_new(snapshot: PacketAclSnapshot, action: str, direction: str, rule_type: str) -> str:
    netsh_dir = "in" if str(direction or DIRECTION_INBOUND).lower() == DIRECTION_INBOUND else "out"
    action_kw = action_keyword(PRODUCT_NETSH_NEW, action)
    header = _rule_header(PRODUCT_NETSH_NEW, snapshot, direction, action)
    base = f'netsh advfirewall firewall add rule name="Wireshark Packet {int(snapshot.frame_number)}" dir={netsh_dir} action={action_kw}'
    if rule_type == RULE_SOURCE_TCP_PORT:
        return f"{header}{base} protocol=tcp localport={int(snapshot.tcp_src_port)}"
    if rule_type == RULE_DESTINATION_TCP_PORT:
        return f"{header}{base} protocol=tcp localport={int(snapshot.tcp_dst_port)}"
    if rule_type == RULE_SOURCE_UDP_PORT:
        return f"{header}{base} protocol=udp localport={int(snapshot.udp_src_port)}"
    if rule_type == RULE_DESTINATION_UDP_PORT:
        return f"{header}{base} protocol=udp localport={int(snapshot.udp_dst_port)}"
    if rule_type == RULE_SOURCE_IPV4_PORT:
        proto, port = _prefer_transport_for_ports(snapshot, prefer_source=True)
        return f"{header}{base} protocol={proto} localport={port} remoteip={snapshot.ip_src}"
    if rule_type == RULE_DESTINATION_IPV4_PORT:
        proto, port = _prefer_transport_for_ports(snapshot, prefer_source=False)
        return f"{header}{base} protocol={proto} localport={port} remoteip={snapshot.ip_dst}"
    raise ValueError("The selected firewall product does not support this rule type.")
