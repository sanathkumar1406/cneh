"""Educational security scenarios: ARP Spoofing and Controlled Floods.

All scenarios execute purely within the simulator's virtual network engine.
No external network calls, raw sockets, or real packets are ever used.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import TYPE_CHECKING, Any

from ..arp.packet import ArpOperation, ArpPacket
from ..core.addressing import is_valid_ipv4, same_subnet
from ..core.events import EventType, Severity
from ..core.mac import BROADCAST_MAC
from ..core.models import Emission
from ..devices.base import Device
from ..devices.host import Host
from ..ethernet.frame import EtherType, EthernetFrame, next_flow_id
from ..icmp.message import ECHO_PAYLOAD_BYTES, IcmpMessage, IcmpType
from ..ipv4.packet import IPProtocol, IPv4Packet
from ..transport.segment import (
    TcpFlag,
    TransportProtocol,
    TransportSegment,
    next_ephemeral_port,
)
from .engine import SecurityEventEngine
from .events import AlertCategory, AlertSeverity, SecurityAlert

if TYPE_CHECKING:
    from ..core.engine import SimulationEngine
    from ..core.network import Network


@dataclass
class ArpSpoofResult:
    success: bool
    victim_id: str
    victim_name: str
    victim_ip: str
    gateway_id: str
    gateway_name: str
    gateway_ip: str
    attacker_id: str
    attacker_name: str
    attacker_mac: str
    legitimate_gateway_mac: str
    victim_arp_before: str | None
    victim_arp_after: str | None
    traffic_redirected: bool
    mitigated: bool
    mitigation_reason: str
    alerts: list[SecurityAlert] = field(default_factory=list)
    output: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["alerts"] = [a.to_dict() if isinstance(a, SecurityAlert) else a for a in self.alerts]
        return data


@dataclass
class FloodResult:
    success: bool
    scenario_type: str  # "syn" | "icmp" | "udp"
    source_id: str
    source_name: str
    source_ip: str
    target_id: str
    target_name: str
    target_ip: str
    target_port: int | None
    packets_sent: int
    packets_delivered: int
    packets_dropped: int
    service_available: bool
    simulated_availability_pct: float
    simulated_latency_ms: float
    mitigated: bool
    mitigation_reason: str
    alerts: list[SecurityAlert] = field(default_factory=list)
    output: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["alerts"] = [a.to_dict() if isinstance(a, SecurityAlert) else a for a in self.alerts]
        return data


def run_arp_spoof_scenario(
    network: Network,
    engine: SimulationEngine,
    victim_id: str,
    gateway_id: str,
    attacker_id: str,
) -> ArpSpoofResult:
    """Execute an educational ARP spoofing scenario against the virtual network."""
    victim = network.device(victim_id)
    gateway = network.device(gateway_id)
    attacker = network.device(attacker_id)

    if not victim or not gateway or not attacker:
        return ArpSpoofResult(
            success=False,
            victim_id=victim_id,
            victim_name=victim.name if victim else "unknown",
            victim_ip="",
            gateway_id=gateway_id,
            gateway_name=gateway.name if gateway else "unknown",
            gateway_ip="",
            attacker_id=attacker_id,
            attacker_name=attacker.name if attacker else "unknown",
            attacker_mac="",
            legitimate_gateway_mac="",
            victim_arp_before=None,
            victim_arp_after=None,
            traffic_redirected=False,
            mitigated=False,
            mitigation_reason="One or more selected devices do not exist in this topology.",
            output=["Error: Target devices not found in topology."],
        )

    # Validate IP addresses and network placement
    v_iface = next((i for i in victim.interfaces if i.enabled and i.ipv4), None)
    g_iface = next((i for i in gateway.interfaces if i.enabled and i.ipv4), None)
    a_iface = next((i for i in attacker.interfaces if i.enabled and i.ipv4), None)

    if not v_iface or not g_iface or not a_iface:
        return ArpSpoofResult(
            success=False,
            victim_id=victim.id,
            victim_name=victim.name,
            victim_ip=v_iface.ipv4 if v_iface else "",
            gateway_id=gateway.id,
            gateway_name=gateway.name,
            gateway_ip=g_iface.ipv4 if g_iface else "",
            attacker_id=attacker.id,
            attacker_name=attacker.name,
            attacker_mac=a_iface.mac if a_iface else "",
            legitimate_gateway_mac=g_iface.mac if g_iface else "",
            victim_arp_before=None,
            victim_arp_after=None,
            traffic_redirected=False,
            mitigated=False,
            mitigation_reason="All devices must have enabled IPv4 network adapters.",
            output=["Error: Devices lack valid enabled IPv4 adapters."],
        )

    victim_ip = v_iface.ipv4
    gateway_ip = g_iface.ipv4
    attacker_ip = a_iface.ipv4
    legit_gw_mac = g_iface.mac.upper()
    attacker_mac = a_iface.mac.upper()

    # Initial state: ensure victim knows legitimate gateway MAC
    initial_entry = getattr(victim, "arp_table", None)
    if initial_entry:
        if not initial_entry.lookup(gateway_ip):
            initial_entry.insert(gateway_ip, legit_gw_mac, dynamic=True)
    victim_arp_before = victim.arp_table.lookup(gateway_ip) if hasattr(victim, "arp_table") else None

    # Step 1: Attacker sends forged gratuitous/unicast ARP reply to victim:
    # "gateway_ip is at attacker_mac"
    forged_arp = ArpPacket(
        operation=ArpOperation.REPLY,
        sender_mac=a_iface.mac,
        sender_ip=gateway_ip,
        target_mac=v_iface.mac,
        target_ip=victim_ip,
    )
    forged_frame = EthernetFrame(
        src_mac=a_iface.mac,
        dst_mac=v_iface.mac,
        ethertype=EtherType.ARP,
        payload=forged_arp,
        flow_id=next_flow_id(),
    )

    engine.log(
        EventType.SECURITY_SCAN,
        f"[ATTACK] {attacker.name} forged ARP reply: claiming {gateway_ip} is at {attacker_mac}",
        device=attacker,
        interface=a_iface,
        frame=forged_frame,
    )

    # Deliver forged ARP frame to victim
    engine.send(attacker, a_iface.id, forged_frame)

    # Inspect victim's ARP table after forged reply
    victim_arp_after = victim.arp_table.lookup(gateway_ip) if hasattr(victim, "arp_table") else None

    # Determine if mitigation stopped it (e.g. static ARP binding)
    arp_entry = victim.arp_table.get(gateway_ip) if hasattr(victim, "arp_table") else None
    is_static = bool(arp_entry and not arp_entry.dynamic)
    mitigated = is_static and (victim_arp_after == legit_gw_mac)

    mitigation_reason = ""
    if mitigated:
        mitigation_reason = f"Victim has static ARP protection: mapping {gateway_ip} -> {legit_gw_mac} is locked and rejected forged update."
    elif victim_arp_after == attacker_mac:
        mitigation_reason = f"Vulnerable: Victim accepted forged ARP reply and mapped gateway {gateway_ip} to attacker MAC {attacker_mac}."

    # Step 2: Send test traffic from victim to gateway to verify path redirection
    test_packet = IPv4Packet(
        src_ip=victim_ip,
        dst_ip=gateway_ip,
        protocol=IPProtocol.ICMP,
        payload=IcmpMessage(type=IcmpType.ECHO_REQUEST, identifier=101, sequence=1),
        ttl=64,
        length=ECHO_PAYLOAD_BYTES,
    )
    emissions = victim.send_ipv4(test_packet, engine)
    traffic_redirected = False
    if emissions:
        delivered_frame = emissions[0].frame
        if delivered_frame.dst_mac.upper() == attacker_mac:
            traffic_redirected = True
        engine.run(victim, emissions)

    # Step 3: Run security detection rules
    sec_engine = SecurityEventEngine(network, engine)
    alerts = sec_engine.evaluate()

    output = [
        f"=== Simulated Educational ARP Spoofing Scenario ===",
        f"Attacker : {attacker.name} [{attacker_ip} | {attacker_mac}]",
        f"Target   : {victim.name} [{victim_ip} | {v_iface.mac}]",
        f"Gateway  : {gateway.name} [{gateway_ip} | {legit_gw_mac}]",
        "",
        f"Victim ARP before : {gateway_ip} -> {victim_arp_before}",
        f"Victim ARP after  : {gateway_ip} -> {victim_arp_after}",
        f"Traffic Redirected: {'YES (Intercepted by Attacker)' if traffic_redirected else 'NO (Normal Path)'}",
        f"Mitigation Status : {'PROTECTED (Static Binding Enforced)' if mitigated else 'EXPOSED (Dynamic Overwrite)'}",
        "",
        f"Security Findings : {len(alerts)} alert(s) generated.",
    ]
    for a in alerts:
        output.append(f" - [{a.severity.upper()}] {a.rule}: {a.reason}")

    return ArpSpoofResult(
        success=True,
        victim_id=victim.id,
        victim_name=victim.name,
        victim_ip=victim_ip,
        gateway_id=gateway.id,
        gateway_name=gateway.name,
        gateway_ip=gateway_ip,
        attacker_id=attacker.id,
        attacker_name=attacker.name,
        attacker_mac=attacker_mac,
        legitimate_gateway_mac=legit_gw_mac,
        victim_arp_before=victim_arp_before,
        victim_arp_after=victim_arp_after,
        traffic_redirected=traffic_redirected,
        mitigated=mitigated,
        mitigation_reason=mitigation_reason,
        alerts=alerts,
        output=output,
    )


def reset_arp_spoof_scenario(
    network: Network,
    victim_id: str,
    gateway_id: str,
) -> tuple[bool, str]:
    """Restore clean, legitimate ARP mappings without destroying user topology."""
    victim = network.device(victim_id)
    gateway = network.device(gateway_id)

    if not victim or not gateway:
        return False, "Target devices not found in topology."

    g_iface = next((i for i in gateway.interfaces if i.enabled and i.ipv4), None)
    if not g_iface or not hasattr(victim, "arp_table"):
        return False, "Devices lack valid ARP configuration."

    gateway_ip = g_iface.ipv4
    legit_mac = g_iface.mac.upper()

    # Re-insert legitimate mapping (preserving dynamic flag as dynamic)
    victim.arp_table.remove(gateway_ip)
    victim.arp_table.insert(gateway_ip, legit_mac, dynamic=True)
    return True, f"Reset complete: {victim.name} ARP mapping for {gateway_ip} restored to legitimate MAC {legit_mac}."


def run_flood_scenario(
    network: Network,
    engine: SimulationEngine,
    source_id: str,
    target_id: str,
    scenario_type: str = "syn",  # "syn" | "icmp" | "udp"
    packet_count: int = 25,
    target_port: int = 80,
) -> FloodResult:
    """Execute a controlled, bounded traffic flood simulation to demonstrate DoS and mitigation."""
    source = network.device(source_id)
    target = network.device(target_id)

    if not source or not target:
        return FloodResult(
            success=False,
            scenario_type=scenario_type,
            source_id=source_id,
            source_name=source.name if source else "unknown",
            source_ip="",
            target_id=target_id,
            target_name=target.name if target else "unknown",
            target_ip="",
            target_port=target_port,
            packets_sent=0,
            packets_delivered=0,
            packets_dropped=0,
            service_available=False,
            simulated_availability_pct=0.0,
            simulated_latency_ms=0.0,
            mitigated=False,
            mitigation_reason="Source or target device does not exist.",
            output=["Error: Source or target device not found."],
        )

    src_iface = next((i for i in source.interfaces if i.enabled and i.ipv4), None)
    dst_iface = next((i for i in target.interfaces if i.enabled and i.ipv4), None)

    if not src_iface or not dst_iface:
        return FloodResult(
            success=False,
            scenario_type=scenario_type,
            source_id=source.id,
            source_name=source.name,
            source_ip="",
            target_id=target.id,
            target_name=target.name,
            target_ip="",
            target_port=target_port,
            packets_sent=0,
            packets_delivered=0,
            packets_dropped=0,
            service_available=False,
            simulated_availability_pct=0.0,
            simulated_latency_ms=0.0,
            mitigated=False,
            mitigation_reason="Both source and target must have active IPv4 addresses.",
            output=["Error: Missing IPv4 address on source or target."],
        )

    # Bound parameters to prevent simulation freeze
    count = max(5, min(packet_count, 50))
    src_ip = src_iface.ipv4
    dst_ip = dst_iface.ipv4

    engine.log(
        EventType.SECURITY_SCAN,
        f"[FLOOD] Initiating {count} packets of {scenario_type.upper()} flood from {source.name} to {target.name}",
        device=source,
    )

    delivered = 0
    dropped = 0
    mitigated_by_firewall = False
    mitigation_reason = "No mitigation detected: target service overloaded."

    # Generate synthetic traffic packets inside the simulator
    for seq in range(1, count + 1):
        if scenario_type.lower() == "syn":
            segment = TransportSegment(
                protocol=TransportProtocol.TCP,
                src_port=next_ephemeral_port(),
                dst_port=target_port,
                flag=TcpFlag.SYN,
            )
            emissions = source.send_segment(dst_ip, segment, engine)
        elif scenario_type.lower() == "udp":
            segment = TransportSegment(
                protocol=TransportProtocol.UDP,
                src_port=next_ephemeral_port(),
                dst_port=target_port,
            )
            emissions = source.send_segment(dst_ip, segment, engine)
        else:  # ICMP
            packet = IPv4Packet(
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=IPProtocol.ICMP,
                payload=IcmpMessage(type=IcmpType.ECHO_REQUEST, identifier=200, sequence=seq),
                ttl=64,
                length=ECHO_PAYLOAD_BYTES,
            )
            emissions = source.send_ipv4(packet, engine)

        if not emissions:
            dropped += 1
            continue

        mark = len(engine.events)
        engine.run(source, emissions)
        events_this_frame = engine.events[mark:]

        # Check if dropped by firewall
        fw_drop = any(e.type == EventType.FIREWALL_DENY for e in events_this_frame)
        if fw_drop:
            dropped += 1
            mitigated_by_firewall = True
            mitigation_reason = "Firewall rule successfully dropped flood traffic."
        else:
            delivered += 1

    # Model simulated server availability & queue pressure
    if mitigated_by_firewall:
        availability_pct = 100.0
        latency_ms = 1.2
        service_available = True
    else:
        # Without mitigation, large flood causes queue pressure & service degradation
        availability_pct = max(10.0, 100.0 - (delivered * 3.5))
        latency_ms = min(350.0, 10.0 + (delivered * 12.0))
        service_available = availability_pct >= 50.0

    # Run detection engine
    sec_engine = SecurityEventEngine(network, engine)
    alerts = sec_engine.evaluate()

    output = [
        f"=== Controlled Traffic Flood Simulation ({scenario_type.upper()}) ===",
        f"Source          : {source.name} [{src_ip}]",
        f"Target          : {target.name} [{dst_ip}:{target_port}]",
        f"Packets Sent    : {count}",
        f"Delivered       : {delivered}",
        f"Dropped         : {dropped}",
        f"Service Health  : {availability_pct:.1f}% availability (Simulated latency: {latency_ms:.1f}ms)",
        f"Mitigation State: {'MITIGATED' if mitigated_by_firewall else 'UNMITIGATED'}",
        f"Explanation     : {mitigation_reason}",
        "",
        f"Security Findings: {len(alerts)} alert(s) triggered.",
    ]
    for a in alerts:
        output.append(f" - [{a.severity.upper()}] {a.rule}: {a.reason}")

    return FloodResult(
        success=True,
        scenario_type=scenario_type.lower(),
        source_id=source.id,
        source_name=source.name,
        source_ip=src_ip,
        target_id=target.id,
        target_name=target.name,
        target_ip=dst_ip,
        target_port=target_port,
        packets_sent=count,
        packets_delivered=delivered,
        packets_dropped=dropped,
        service_available=service_available,
        simulated_availability_pct=availability_pct,
        simulated_latency_ms=latency_ms,
        mitigated=mitigated_by_firewall,
        mitigation_reason=mitigation_reason,
        alerts=alerts,
        output=output,
    )
