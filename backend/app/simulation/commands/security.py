"""Simulated security and reconnaissance commands: host discovery and port scanning.

All scans run purely against the simulated network model and engine.
No real packets or sockets are ever opened.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ..connectivity import Outcome, attempt_connection
from ..core.addressing import (
    format_cidr,
    ip_in_network,
    is_valid_ipv4,
    netmask_to_prefix,
    network_address,
    parse_cidr,
    prefix_to_netmask,
)
from ..core.events import EventType, Severity
from ..devices.host import Host
from ..icmp.message import ECHO_PAYLOAD_BYTES, IcmpMessage, IcmpType
from ..ipv4.packet import IPProtocol, IPv4Packet
from ..transport.segment import TransportProtocol
from ..transport.services import describe_port, lookup, service_name
from .registry import CommandContext, CommandResult

if TYPE_CHECKING:
    from ..devices.base import Device

COMMON_PORTS = [21, 22, 25, 53, 80, 110, 123, 143, 443, 3306]
MAX_SCAN_PORTS = 25


def cmd_netdiscover(ctx: CommandContext) -> CommandResult:
    """Discover active simulated hosts within the local subnet or a specified CIDR range."""
    host = ctx.device
    engine = ctx.engine
    network = ctx.network

    if not host.ip_interfaces or not host.ip_interfaces[0].ipv4:
        return CommandResult(
            output=["netdiscover: This device has no IPv4 address to scan from."],
            success=False,
        )

    primary_iface = host.ip_interfaces[0]
    assert primary_iface.ipv4 and primary_iface.netmask

    target_cidr: str | None = None
    args = list(ctx.args)
    if args:
        if args[0] in ("-r", "--range", "-i"):
            if len(args) < 2:
                return CommandResult(
                    output=["Usage: netdiscover [-r <cidr>]", "Example: netdiscover -r 192.168.1.0/24"],
                    success=False,
                )
            target_cidr = args[1]
        elif "/" in args[0] or is_valid_ipv4(args[0]):
            target_cidr = args[0]
        else:
            return CommandResult(
                output=[
                    f"netdiscover: unrecognized option '{args[0]}'",
                    "Usage: netdiscover [-r <cidr>]",
                ],
                success=False,
            )

    if target_cidr is None:
        net_addr = network_address(primary_iface.ipv4, primary_iface.netmask)
        prefix = netmask_to_prefix(primary_iface.netmask)
        target_cidr = f"{net_addr}/{prefix}"

    parsed = parse_cidr(target_cidr)
    if parsed is None:
        return CommandResult(
            output=[
                f"netdiscover: invalid CIDR or subnet '{target_cidr}'",
                "Example: netdiscover -r 192.168.1.0/24",
            ],
            success=False,
        )

    scan_network, scan_netmask = parsed
    scan_prefix = netmask_to_prefix(scan_netmask)
    full_cidr = f"{scan_network}/{scan_prefix}"

    engine.log(
        EventType.SECURITY_SCAN,
        f"{host.name}: starting host discovery sweep across {full_cidr}",
        device=host,
        interface=primary_iface,
    )

    discovered: list[dict[str, str]] = []

    # Find devices in simulated network having an interface in this subnet
    candidates: list[tuple[Device, str, str]] = []  # (dev, ip, mac)
    for dev in network.devices.values():
        for iface in dev.interfaces:
            if iface.enabled and iface.ipv4 and ip_in_network(iface.ipv4, scan_network, scan_netmask):
                candidates.append((dev, iface.ipv4, iface.mac))

    # Sort candidates by IP
    candidates.sort(key=lambda item: tuple(int(p) for p in item[1].split(".")))

    for dev, target_ip, target_mac in candidates:
        if target_ip == primary_iface.ipv4:
            # Local interface
            discovered.append({
                "ip": target_ip,
                "mac": target_mac,
                "name": dev.name,
                "status": "Active (Local host)",
            })
            continue

        # Check reachability through simulator
        # 1. If in same local subnet, resolve via ARP:
        is_local = ip_in_network(target_ip, primary_iface.ipv4, primary_iface.netmask)
        if is_local:
            resolved_mac = engine.resolve_arp(host, target_ip, primary_iface)
            if resolved_mac:
                role_tag = " (Gateway)" if host.config.gateway == target_ip else ""
                discovered.append({
                    "ip": target_ip,
                    "mac": resolved_mac,
                    "name": dev.name,
                    "status": f"Active{role_tag}",
                })
        else:
            # Routed subnet: send simulated ICMP echo
            probe = IPv4Packet(
                src_ip=host.select_source_ip(target_ip) or primary_iface.ipv4,
                dst_ip=target_ip,
                protocol=IPProtocol.ICMP,
                payload=IcmpMessage(type=IcmpType.ECHO_REQUEST, identifier=99, sequence=1),
                ttl=64,
                length=ECHO_PAYLOAD_BYTES,
            )
            host.icmp_inbox.clear()
            emissions = host.send_ipv4(probe, engine)
            if emissions:
                engine.run(host, emissions)
                reply = next(
                    (item for item in host.icmp_inbox if item[1].type is IcmpType.ECHO_REPLY),
                    None,
                )
                if reply is not None:
                    discovered.append({
                        "ip": target_ip,
                        "mac": target_mac,
                        "name": dev.name,
                        "status": "Active (Routed)",
                    })

    lines = [
        f"Currently scanning: {full_cidr} | Screen View: Unique Hosts",
        "",
        f" {'IP':<17} {'MAC Address':<21} {'Device Name':<16} Status",
        f" {'─'*16:<17} {'─'*20:<21} {'─'*15:<16} {'─'*15}",
    ]

    if not discovered:
        lines.append(f" No active hosts responded in {full_cidr}.")
    else:
        for entry in discovered:
            lines.append(
                f" {entry['ip']:<17} {entry['mac']:<21} {entry['name']:<16} {entry['status']}"
            )

    lines.append("")
    lines.append(f"{len(discovered)} host(s) discovered in {full_cidr}.")
    return CommandResult(output=lines, success=True)


def cmd_nmap(ctx: CommandContext) -> CommandResult:
    """Scan ports on a simulated target device, respecting services and firewall rules."""
    host = ctx.device
    engine = ctx.engine

    if not host.ip_interfaces or not host.ip_interfaces[0].ipv4:
        return CommandResult(
            output=["nmap: This device has no IPv4 address to scan from."],
            success=False,
        )

    if not ctx.args:
        return CommandResult(
            output=[
                "Usage: nmap [-p <ports>] [--syn|--tcp] <target>",
                "Examples:",
                "  nmap 192.168.1.50",
                "  nmap -p 80,443,3306 web.netquest.local",
                "  nmap -p 20-25 192.168.1.1",
            ],
            success=False,
        )

    args = list(ctx.args)
    ports: list[int] = []
    target: str | None = None

    idx = 0
    while idx < len(args):
        arg = args[idx]
        if arg in ("-p", "--ports", "-port"):
            idx += 1
            if idx >= len(args):
                return CommandResult(output=["nmap: option '-p' requires an argument."], success=False)
            port_spec = args[idx]
            parsed_ports = _parse_ports(port_spec)
            if parsed_ports is None:
                return CommandResult(
                    output=[f"nmap: invalid port specification '{port_spec}'."],
                    success=False,
                )
            ports.extend(parsed_ports)
        elif arg.startswith("-p"):
            port_spec = arg[2:]
            parsed_ports = _parse_ports(port_spec)
            if parsed_ports is None:
                return CommandResult(
                    output=[f"nmap: invalid port specification '{port_spec}'."],
                    success=False,
                )
            ports.extend(parsed_ports)
        elif arg in ("-sS", "--syn", "-sT", "--tcp"):
            pass  # Supported flags
        elif not arg.startswith("-"):
            target = arg
        else:
            return CommandResult(
                output=[f"nmap: unrecognized option '{arg}'."],
                success=False,
            )
        idx += 1

    if not target:
        return CommandResult(
            output=["nmap: no target specified."],
            success=False,
        )

    if not ports:
        ports = list(COMMON_PORTS)
    else:
        # Deduplicate and sort, capping at MAX_SCAN_PORTS
        ports = sorted(list(set(ports)))[:MAX_SCAN_PORTS]

    target_address, dns_response = host.resolve_target(target, engine)
    if target_address is None:
        detail = (
            f"could not resolve {target}"
            if dns_response is None
            else f"DNS answered {dns_response.status.value} for {target}"
        )
        return CommandResult(
            output=[f"nmap: failed to resolve target '{target}': {detail}"],
            success=False,
        )

    engine.log(
        EventType.SECURITY_SCAN,
        f"{host.name}: scanning {len(ports)} ports on {target} [{target_address}]",
        device=host,
    )

    lines = [
        f"Starting NetQuest Nmap (simulated) against {target} ({target_address})",
    ]

    scan_results: list[dict[str, str]] = []
    open_count = 0
    filtered_count = 0
    closed_count = 0

    for port in ports:
        attempt = attempt_connection(host, target_address, port, engine, TransportProtocol.TCP)
        svc_name = _service_name_for(port)

        if attempt.outcome == Outcome.OPEN:
            state = "open"
            reason = "syn-ack from host"
            open_count += 1
        elif attempt.outcome == Outcome.REFUSED:
            state = "closed"
            reason = "conn-refused (RST)"
            closed_count += 1
        elif attempt.outcome == Outcome.FILTERED:
            state = "filtered"
            reason = f"no-response (dropped at {attempt.blocked_at or 'firewall'})"
            filtered_count += 1
        elif attempt.outcome in (Outcome.NO_ROUTE, Outcome.UNREACHABLE):
            state = "filtered"
            reason = f"{attempt.outcome} ({attempt.detail})"
            filtered_count += 1
        else:
            state = "filtered"
            reason = attempt.detail
            filtered_count += 1

        scan_results.append({
            "port": f"{port}/tcp",
            "state": state,
            "service": svc_name,
            "reason": reason,
        })

    # Host status indicator
    if open_count > 0 or closed_count > 0:
        lines.append("Host is up (responses received).")
    else:
        lines.append("Host may be down or silently dropping all probe traffic.")
    lines.append("")

    lines.append(f"{'PORT':<10} {'STATE':<10} {'SERVICE':<12} REASON")
    for r in scan_results:
        lines.append(f"{r['port']:<10} {r['state']:<10} {r['service']:<12} {r['reason']}")

    lines.append("")
    lines.append(
        f"Nmap done: {len(ports)} scanned ports on {target} ({open_count} open, "
        f"{filtered_count} filtered, {closed_count} closed)."
    )
    return CommandResult(output=lines, success=True)


def _parse_ports(spec: str) -> list[int] | None:
    result: list[int] = []
    for item in spec.split(","):
        item = item.strip()
        if not item:
            continue
        if "-" in item:
            start_str, _, end_str = item.partition("-")
            if not start_str.isdigit() or not end_str.isdigit():
                return None
            start, end = int(start_str), int(end_str)
            if start < 1 or end > 65535 or start > end:
                return None
            # Limit range expansion
            if end - start > MAX_SCAN_PORTS:
                end = start + MAX_SCAN_PORTS
            result.extend(range(start, end + 1))
        else:
            if not item.isdigit():
                svc = lookup(item)
                if svc is not None:
                    result.append(svc.port)
                    continue
                return None
            p = int(item)
            if not 1 <= p <= 65535:
                return None
            result.append(p)
    return result


def _service_name_for(port: int) -> str:
    name = service_name(TransportProtocol.TCP, port)
    if name:
        return name.lower()
    return "unknown"


def cmd_vulnscan(ctx: CommandContext) -> CommandResult:
    """Educational vulnerability audit for simulated devices.

    Audits configured services and firewall policies against educational
    best-practice baselines.
    """
    target_dev = ctx.device
    if ctx.args:
        target_name_or_ip = ctx.args[0].strip()
        # Find device in network by name or IP
        found = None
        for dev in ctx.network.devices.values():
            if dev.name.lower() == target_name_or_ip.lower():
                found = dev
                break
            for iface in dev.interfaces:
                if iface.ipv4 and str(iface.ipv4) == target_name_or_ip:
                    found = dev
                    break
            if found:
                break
        if not found:
            # Try DNS resolution
            resolved_ip = _resolve_target(ctx, target_name_or_ip)
            if resolved_ip:
                for dev in ctx.network.devices.values():
                    for iface in dev.interfaces:
                        if iface.ipv4 and str(iface.ipv4) == resolved_ip:
                            found = dev
                            break
                    if found:
                        break
        if not found:
            return CommandResult(
                output=[f"vulnscan: target '{target_name_or_ip}' not found in simulated network."],
                success=False,
            )
        target_dev = found

    lines = [
        f"NetQuest Educational Vulnerability Audit — Target: {target_dev.name}",
        "NOTE: Demonstrative educational findings for simulated network services only.",
        "----------------------------------------------------------------------",
        "",
    ]

    findings: list[dict[str, str]] = []

    # Check listening services
    listening_services = [s for s in target_dev.config.services if s.enabled]
    service_map = {(s.protocol.upper(), s.port): s for s in listening_services}

    if ("TCP", 21) in service_map:
        findings.append({
            "id": "EDU-VULN-001",
            "title": "Cleartext FTP Authentication Service Enabled",
            "severity": "HIGH",
            "desc": "File Transfer Protocol (port 21/tcp) transmits credentials and data in unencrypted plaintext.",
            "impact": "Simulated attacker can capture credentials via packet inspection or ARP spoofing.",
            "remediation": "Disable FTP service on target, migrate to SSH (port 22/tcp), or block port 21 via firewall.",
        })

    if ("TCP", 80) in service_map and ("TCP", 443) not in service_map:
        findings.append({
            "id": "EDU-VULN-002",
            "title": "Unencrypted HTTP Web Service Without TLS",
            "severity": "MEDIUM",
            "desc": "Web service is running over unencrypted HTTP (port 80/tcp) with no HTTPS (port 443/tcp) transport encryption.",
            "impact": "Web requests and responses can be intercepted and modified in transit.",
            "remediation": "Enable HTTPS service or restrict web port access with firewall rules.",
        })

    if ("TCP", 25) in service_map:
        findings.append({
            "id": "EDU-VULN-003",
            "title": "Unauthenticated / Plaintext SMTP Relay Exposed",
            "severity": "LOW",
            "desc": "Simple Mail Transfer Protocol on port 25/tcp allows plaintext mail relay without authentication.",
            "impact": "Potential for unauthorized relaying or plaintext message interception.",
            "remediation": "Configure restrictive firewall rules or disable unnecessary mail relay.",
        })

    # Check firewall rules if any services are listening
    if listening_services and not getattr(target_dev.config, "firewall_rules", None):
        findings.append({
            "id": "EDU-VULN-004",
            "title": "Missing Ingress Firewall Protection",
            "severity": "LOW",
            "desc": f"Device {target_dev.name} has listening services but no firewall rules configured.",
            "impact": "All listening ports are exposed to all connected simulation subnets.",
            "remediation": "Configure stateful or port-specific firewall rules to enforce least-privilege access.",
        })

    if not findings:
        lines.append(f"✓ No educational vulnerability findings detected on {target_dev.name}.")
        lines.append("  All active services and firewall policies adhere to security baselines.")
    else:
        lines.append(f"Found {len(findings)} educational security finding(s):")
        lines.append("")
        for idx, f in enumerate(findings, 1):
            lines.append(f"[{idx}] {f['id']} [{f['severity']}]: {f['title']}")
            lines.append(f"    Details:     {f['desc']}")
            lines.append(f"    Impact:      {f['impact']}")
            lines.append(f"    Remediation: {f['remediation']}")
            lines.append("")

    return CommandResult(output=lines, success=True)

