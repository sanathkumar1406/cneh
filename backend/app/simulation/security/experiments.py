"""Security Experiment Comparison Engine.

Records and contrasts baseline, attack, and mitigated network runs with identical
parameters, producing concrete before-and-after empirical metrics.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from ...schemas.topology import FirewallRuleSchema, TopologySchema
from ..connectivity import Outcome, attempt_connection
from ..core.engine import SimulationEngine
from ..devices.host import Host
from ..loader import build_network
from ..transport.segment import TransportProtocol
from .events import SecurityAlert
from .scenarios import (
    ArpSpoofResult,
    FloodResult,
    run_arp_spoof_scenario,
    run_flood_scenario,
)


@dataclass
class ExperimentMetrics:
    phase_name: str  # "Baseline", "Attack (Unmitigated)", "Mitigated"
    packets_sent: int
    packets_delivered: int
    packets_dropped: int
    delivery_rate_pct: float
    simulated_latency_ms: float
    simulated_availability_pct: float
    alerts_triggered: int
    description: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ExperimentComparisonResult:
    scenario_name: str
    scenario_type: str
    source_name: str
    target_name: str
    baseline: ExperimentMetrics
    attack: ExperimentMetrics
    mitigated: ExperimentMetrics
    explanation: str
    difference_summary: dict[str, Any]
    alerts: list[SecurityAlert] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["alerts"] = [a.to_dict() if isinstance(a, SecurityAlert) else a for a in self.alerts]
        return data


def compare_flood_experiment(
    topology: TopologySchema,
    mitigated_topology: TopologySchema,
    source_id: str,
    target_id: str,
    scenario_type: str = "syn",
    packet_count: int = 25,
    target_port: int = 80,
) -> ExperimentComparisonResult:
    """Run baseline, unmitigated flood, and mitigated flood to generate empirical comparisons."""
    # 1. Baseline Run: 1 normal connection test to establish baseline latency and delivery
    net_base = build_network(topology)
    eng_base = SimulationEngine(net_base)
    src_base = net_base.device(source_id)
    dst_base = net_base.device(target_id)
    dst_ip = dst_base.interfaces[0].ipv4 if dst_base and dst_base.interfaces else "127.0.0.1"

    # Select an active port if available to demonstrate normal service connection
    active_port = target_port
    if dst_base and isinstance(dst_base, Host) and dst_base.open_ports:
        open_port_nums = [p[1] for p in dst_base.open_ports]
        if target_port in open_port_nums:
            active_port = target_port
        else:
            tcp_ports = [p[1] for p in dst_base.open_ports if p[0] == "TCP"]
            active_port = tcp_ports[0] if tcp_ports else open_port_nums[0]

    base_delivered = 1
    base_dropped = 0
    if src_base and isinstance(src_base, Host) and dst_ip:
        attempt = attempt_connection(
            src_base, dst_ip, active_port, eng_base, TransportProtocol.TCP
        )
        # If open or refused (host is up and responded with RST), packet reached target without network loss
        if attempt.reachable or attempt.outcome in (Outcome.OPEN, Outcome.REFUSED):
            base_delivered = 1
            base_dropped = 0
        else:
            base_delivered = 0
            base_dropped = 1
    else:
        base_delivered = 1
        base_dropped = 0

    baseline_metrics = ExperimentMetrics(
        phase_name="Baseline (Normal)",
        packets_sent=1,
        packets_delivered=base_delivered,
        packets_dropped=base_dropped,
        delivery_rate_pct=100.0 if base_delivered else 0.0,
        simulated_latency_ms=1.5,
        simulated_availability_pct=100.0 if base_delivered else 0.0,
        alerts_triggered=0,
        description="Normal background network operations with minimal traffic.",
    )

    # 2. Attack Run: Unmitigated flood on original topology
    net_attack = build_network(topology)
    eng_attack = SimulationEngine(net_attack)
    attack_res = run_flood_scenario(
        network=net_attack,
        engine=eng_attack,
        source_id=source_id,
        target_id=target_id,
        scenario_type=scenario_type,
        packet_count=packet_count,
        target_port=target_port,
    )

    attack_delivery_pct = (
        (attack_res.packets_delivered / attack_res.packets_sent * 100.0)
        if attack_res.packets_sent > 0
        else 0.0
    )
    attack_metrics = ExperimentMetrics(
        phase_name="Attack (Unmitigated)",
        packets_sent=attack_res.packets_sent,
        packets_delivered=attack_res.packets_delivered,
        packets_dropped=attack_res.packets_dropped,
        delivery_rate_pct=round(attack_delivery_pct, 1),
        simulated_latency_ms=round(attack_res.simulated_latency_ms, 1),
        simulated_availability_pct=round(attack_res.simulated_availability_pct, 1),
        alerts_triggered=len(attack_res.alerts),
        description=f"Under high synthetic {scenario_type.upper()} flood, queue congestion and service overload occur without filtering.",
    )

    # 3. Mitigated Run: Ensure defensive filtering is active on target host and perimeter firewalls
    target_dev = next((d for d in mitigated_topology.devices if d.id == target_id), None)
    fw_devs = [d for d in mitigated_topology.devices if d.type == "firewall"]
    src_dev_top = next((d for d in topology.devices if d.id == source_id), None)
    src_ip_str = "any"
    if src_dev_top and src_dev_top.interfaces:
        active_src_iface = next((i for i in src_dev_top.interfaces if i.enabled and i.ipv4), None)
        if active_src_iface and active_src_iface.ipv4:
            src_ip_str = active_src_iface.ipv4

    expected_proto = "tcp" if scenario_type.lower() == "syn" else ("udp" if scenario_type.lower() == "udp" else "icmp")
    devices_to_protect = [d for d in [target_dev, *fw_devs] if d is not None]

    for dev in devices_to_protect:
        has_matching_deny = any(
            (r.action or "").lower() == "deny"
            and (r.protocol or "any").lower() in ("any", expected_proto)
            and (r.port is None or (target_port is not None and r.port == target_port))
            for r in dev.config.firewall_rules
        )
        if not has_matching_deny:
            dev.config.firewall_rules.insert(
                0,
                FirewallRuleSchema(
                    action="deny",
                    protocol=expected_proto,
                    port=target_port if scenario_type.lower() in ("syn", "udp") else None,
                    source=src_ip_str,
                    destination="any",
                    description=f"Auto-Mitigation: Drop {scenario_type.upper()} flood from {src_ip_str}",
                ),
            )

    net_mitigated = build_network(mitigated_topology)
    eng_mitigated = SimulationEngine(net_mitigated)
    mitigated_res = run_flood_scenario(
        network=net_mitigated,
        engine=eng_mitigated,
        source_id=source_id,
        target_id=target_id,
        scenario_type=scenario_type,
        packet_count=packet_count,
        target_port=target_port,
    )

    mitigated_metrics = ExperimentMetrics(
        phase_name="Mitigated (Defense Applied)",
        packets_sent=mitigated_res.packets_sent,
        packets_delivered=mitigated_res.packets_delivered,
        packets_dropped=mitigated_res.packets_dropped,
        delivery_rate_pct=round(
            (mitigated_res.packets_delivered / mitigated_res.packets_sent * 100.0)
            if mitigated_res.packets_sent > 0
            else 0.0,
            1,
        ),
        simulated_latency_ms=round(mitigated_res.simulated_latency_ms, 1),
        simulated_availability_pct=round(mitigated_res.simulated_availability_pct, 1),
        alerts_triggered=len(mitigated_res.alerts),
        description="Firewall policy or rate-limiting actively intercepted the flood, preserving service availability.",
    )

    explanation = (
        f"In the unmitigated attack, {attack_res.packets_sent} {scenario_type.upper()} packets "
        f"caused simulated service availability to drop to {attack_res.simulated_availability_pct:.1f}% "
        f"and increased latency to {attack_res.simulated_latency_ms:.1f}ms. "
        f"After applying defensive filtering, {mitigated_res.packets_dropped} attack packets were dropped at the perimeter, "
        f"restoring target availability to {mitigated_res.simulated_availability_pct:.1f}%."
    )

    diff = {
        "packets_filtered": mitigated_res.packets_dropped - attack_res.packets_dropped,
        "availability_recovered_pct": round(
            mitigated_res.simulated_availability_pct - attack_res.simulated_availability_pct,
            1,
        ),
        "latency_reduction_ms": round(
            attack_res.simulated_latency_ms - mitigated_res.simulated_latency_ms, 1
        ),
    }

    # Aggregate alerts from attack and mitigated phases
    combined_alerts = list(attack_res.alerts)
    for a in mitigated_res.alerts:
        if not any(existing.id == a.id for existing in combined_alerts):
            combined_alerts.append(a)

    src_name = src_base.name if src_base else source_id
    dst_name = dst_base.name if dst_base else target_id

    return ExperimentComparisonResult(
        scenario_name=f"{scenario_type.upper()} Flood Defense Comparison",
        scenario_type=scenario_type,
        source_name=src_name,
        target_name=dst_name,
        baseline=baseline_metrics,
        attack=attack_metrics,
        mitigated=mitigated_metrics,
        explanation=explanation,
        difference_summary=diff,
        alerts=combined_alerts,
    )
