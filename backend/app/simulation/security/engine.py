"""Deterministic Security Event Engine.

Inspects simulation event traces and packet snapshots to evaluate security rules,
producing structured, explainable alerts with concrete evidence.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from ..core.events import EventType, Severity, SimEvent
from .events import AlertCategory, AlertSeverity, SecurityAlert

if TYPE_CHECKING:
    from ..core.engine import SimulationEngine
    from ..core.network import Network


class SecurityEventEngine:
    def __init__(self, network: Network, engine: SimulationEngine) -> None:
        self.network = network
        self.engine = engine
        self.alerts: list[SecurityAlert] = []
        self._alert_keys: set[tuple[str, str, str, str]] = set()
        self._counter = 0

    def evaluate(self) -> list[SecurityAlert]:
        """Run all detection rules against the current simulation run."""
        self._detect_reconnaissance()
        self._detect_arp_anomalies()
        self._detect_floods()
        self._detect_firewall_blocks()
        return self.alerts

    def add_alert(
        self,
        category: AlertCategory | str,
        severity: AlertSeverity | str,
        source: str,
        target: str,
        reason: str,
        rule: str,
        evidence: dict[str, Any],
        recommendation: str,
        protocol: str | None = None,
        port: int | None = None,
        sequence: int = 0,
        confirmed_attack: bool = False,
        mitigated: bool = False,
    ) -> SecurityAlert | None:
        cat_val = category.value if isinstance(category, AlertCategory) else str(category)
        sev_val = severity.value if isinstance(severity, AlertSeverity) else str(severity)

        dedup_key = (cat_val, rule, source, target)
        if dedup_key in self._alert_keys:
            return None
        self._alert_keys.add(dedup_key)

        self._counter += 1
        alert = SecurityAlert(
            id=f"alert-{self._counter:03d}",
            category=cat_val,
            severity=sev_val,
            source=source,
            target=target,
            protocol=protocol,
            port=port,
            reason=reason,
            evidence=evidence,
            rule=rule,
            sequence=sequence,
            recommendation=recommendation,
            mitigated=mitigated,
            confirmed_attack=confirmed_attack,
        )
        self.alerts.append(alert)

        # Log into the simulation event trace so it appears in the Event Log and Packet Visualizer
        ev_severity = Severity.WARNING
        if sev_val in (AlertSeverity.HIGH.value, AlertSeverity.CRITICAL.value):
            ev_severity = Severity.ERROR
        elif sev_val == AlertSeverity.INFO.value:
            ev_severity = Severity.INFO

        self.engine.log(
            EventType.SECURITY_ALERT,
            f"[{sev_val.upper()}] {rule}: {reason}",
            severity=ev_severity,
        )
        return alert

    # -- Detection Rules -------------------------------------------------

    def _detect_reconnaissance(self) -> None:
        """Detect port scans and host discovery sweeps."""
        # Check port scan probes: SYN segments or connection attempts to multiple ports
        probes_by_pair: dict[tuple[str, str], list[int]] = {}  # (src, dst) -> [dst_port]
        for packet in self.engine.packets.values():
            if packet.src_ip and packet.dst_ip and packet.dst_port:
                # Exclude return replies (SYN-ACK or RST) from being misclassified as scans
                if packet.tcp_flag in ("SYN-ACK", "RST"):
                    continue
                pair = (packet.src_ip, packet.dst_ip)
                probes_by_pair.setdefault(pair, []).append(packet.dst_port)

        for (src_ip, dst_ip), ports in probes_by_pair.items():
            unique_ports = sorted(list(set(ports)))
            if len(unique_ports) >= 4:
                self.add_alert(
                    category=AlertCategory.RECONNAISSANCE,
                    severity=AlertSeverity.MEDIUM,
                    source=src_ip,
                    target=dst_ip,
                    reason=f"Sequential port probe observed across {len(unique_ports)} ports.",
                    rule="PORT_SCAN_DETECTED",
                    evidence={
                        "scanned_ports": unique_ports[:15],
                        "unique_port_count": len(unique_ports),
                        "total_probes": len(ports),
                        "threshold": 4,
                    },
                    recommendation="Review exposed service ports and configure firewall ingress rules to drop unauthorized probes.",
                    confirmed_attack=True,
                )

        # Check host discovery: multiple ARP requests or ICMP sweeps from one host
        discovery_events = [
            e for e in self.engine.events if e.type == EventType.SECURITY_SCAN
        ]
        if discovery_events:
            for ev in discovery_events:
                dev_name = ev.device_name or "local-host"
                if "sweep across" in ev.message or "host discovery" in ev.message:
                    self.add_alert(
                        category=AlertCategory.RECONNAISSANCE,
                        severity=AlertSeverity.LOW,
                        source=dev_name,
                        target="local-subnet",
                        reason=ev.message,
                        rule="HOST_DISCOVERY_SWEEP",
                        evidence={"event_seq": ev.seq, "message": ev.message},
                        recommendation="Segment internal networks with VLANs and restrict broadcast domains where appropriate.",
                        sequence=ev.seq,
                        confirmed_attack=False,
                    )

    def _detect_arp_anomalies(self) -> None:
        """Detect conflicting ARP announcements, unexpected MAC changes, and gateway spoofing."""
        # 1. Look for ARP reply packets where sender IP does not match the actual NIC owning that IP
        actual_ip_to_mac: dict[str, str] = {}
        actual_ip_to_dev: dict[str, str] = {}
        for dev in self.network.devices.values():
            for iface in dev.interfaces:
                if iface.ipv4 and iface.mac:
                    actual_ip_to_mac[iface.ipv4] = iface.mac.upper()
                    actual_ip_to_dev[iface.ipv4] = dev.name

        for snap in self.engine.packets.values():
            if snap.arp_operation == "reply" and snap.arp_sender_ip and snap.arp_sender_mac:
                claimed_ip = snap.arp_sender_ip
                claimed_mac = snap.arp_sender_mac.upper()
                legit_mac = actual_ip_to_mac.get(claimed_ip)

                if legit_mac and legit_mac != claimed_mac:
                    # Legitimate MAC mismatch: This is a forged ARP announcement!
                    legit_owner = actual_ip_to_dev.get(claimed_ip, "Legitimate Device")
                    is_gw = False
                    for dev in self.network.devices.values():
                        if dev.config.gateway == claimed_ip:
                            is_gw = True
                            break

                    severity = AlertSeverity.CRITICAL if is_gw else AlertSeverity.HIGH
                    reason = (
                        f"ARP Spoofing detected: IP {claimed_ip} (legitimately owned by {legit_owner} "
                        f"[{legit_mac}]) was claimed by forged MAC {claimed_mac}."
                    )
                    if is_gw:
                        reason += " Target IP is a default gateway — traffic interception risk!"

                    self.add_alert(
                        category=AlertCategory.SPOOFING,
                        severity=severity,
                        source=claimed_mac,
                        target=claimed_ip,
                        reason=reason,
                        rule="ARP_SPOOF_DETECTED",
                        evidence={
                            "spoofed_ip": claimed_ip,
                            "legitimate_mac": legit_mac,
                            "forged_mac": claimed_mac,
                            "is_gateway": is_gw,
                            "legitimate_owner": legit_owner,
                        },
                        recommendation=(
                            "Configure static ARP bindings (`arp -s <ip> <mac>`), enforce trusted "
                            "IP-to-MAC bindings, or enable ARP inspection on switches."
                        ),
                        confirmed_attack=True,
                    )

    def _detect_floods(self) -> None:
        """Detect SYN flood, ICMP flood, and UDP volume spikes."""
        syn_count_by_target: dict[str, int] = {}
        icmp_count_by_target: dict[str, int] = {}
        udp_count_by_target: dict[str, int] = {}
        source_by_target: dict[str, set[str]] = {}

        for snap in self.engine.packets.values():
            src = snap.src_ip or snap.src_mac
            dst = snap.dst_ip or snap.dst_mac
            if not dst:
                continue

            source_by_target.setdefault(dst, set()).add(src)

            if snap.tcp_flag == "SYN":
                syn_count_by_target[dst] = syn_count_by_target.get(dst, 0) + 1
            elif snap.icmp_type == "echo-request":
                icmp_count_by_target[dst] = icmp_count_by_target.get(dst, 0) + 1
            elif snap.transport_protocol == "UDP":
                udp_count_by_target[dst] = udp_count_by_target.get(dst, 0) + 1

        # Evaluate SYN flood (threshold: >= 10 unacknowledged SYNs)
        for target, count in syn_count_by_target.items():
            if count >= 10:
                sources = list(source_by_target.get(target, []))
                self.add_alert(
                    category=AlertCategory.FLOOD,
                    severity=AlertSeverity.HIGH,
                    source=", ".join(sources[:3]),
                    target=target,
                    reason=f"Abnormal SYN volume: {count} SYN packets directed at {target}.",
                    rule="TCP_SYN_FLOOD_DETECTED",
                    evidence={
                        "syn_packets": count,
                        "threshold": 10,
                        "target": target,
                        "sources": sources,
                    },
                    recommendation="Enable SYN cookies, restrict incoming TCP connection rates, or block attacking IP on the firewall.",
                    protocol="TCP",
                    confirmed_attack=True,
                )

        # Evaluate ICMP flood (threshold: >= 15 ICMP packets)
        for target, count in icmp_count_by_target.items():
            if count >= 15:
                sources = list(source_by_target.get(target, []))
                self.add_alert(
                    category=AlertCategory.FLOOD,
                    severity=AlertSeverity.MEDIUM,
                    source=", ".join(sources[:3]),
                    target=target,
                    reason=f"ICMP Echo Flood: {count} ICMP packets directed at {target}.",
                    rule="ICMP_FLOOD_DETECTED",
                    evidence={
                        "icmp_packets": count,
                        "threshold": 15,
                        "target": target,
                        "sources": sources,
                    },
                    recommendation="Rate-limit ICMP echo requests or drop ICMP on the border firewall.",
                    protocol="ICMP",
                    confirmed_attack=True,
                )

        # Evaluate UDP flood (threshold: >= 15 UDP packets)
        for target, count in udp_count_by_target.items():
            if count >= 15:
                sources = list(source_by_target.get(target, []))
                self.add_alert(
                    category=AlertCategory.FLOOD,
                    severity=AlertSeverity.MEDIUM,
                    source=", ".join(sources[:3]),
                    target=target,
                    reason=f"UDP Flood: {count} UDP datagrams sent to {target}.",
                    rule="UDP_FLOOD_DETECTED",
                    evidence={
                        "udp_packets": count,
                        "threshold": 15,
                        "target": target,
                        "sources": sources,
                    },
                    recommendation="Rate-limit UDP ingress or filter unused UDP ports.",
                    protocol="UDP",
                    confirmed_attack=True,
                )

    def _detect_firewall_blocks(self) -> None:
        """Detect and summarize firewall enforcement actions."""
        deny_events = [e for e in self.engine.events if e.type == EventType.FIREWALL_DENY]
        if not deny_events:
            return

        for ev in deny_events[:5]:  # Bound alert count
            self.add_alert(
                category=AlertCategory.FIREWALL,
                severity=AlertSeverity.INFO,
                source=ev.from_device_id or "unauthorized-source",
                target=ev.to_device_id or "protected-target",
                reason=f"Firewall policy enforced: {ev.message}",
                rule="FIREWALL_PACKET_BLOCKED",
                evidence={"message": ev.message, "seq": ev.seq},
                recommendation="Firewall filter successfully blocked packet. Maintain current rule ordering.",
                sequence=ev.seq,
                mitigated=True,
                confirmed_attack=False,
            )
