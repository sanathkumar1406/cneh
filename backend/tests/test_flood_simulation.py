"""Tests for controlled flood simulation, DoS detection, mitigations, and experiment comparison."""

from __future__ import annotations

import pytest
from app.schemas.topology import FirewallRuleSchema
from app.simulation.core.engine import SimulationEngine
from app.simulation.loader import build_network
from app.simulation.security.experiments import compare_flood_experiment
from app.simulation.security.scenarios import run_flood_scenario
from builders import TopologyBuilder, http, two_pc_lan


class TestFloodSimulation:
    def test_unmitigated_syn_flood(self):
        net = two_pc_lan()
        topology = net.build()
        network = build_network(topology)
        engine = SimulationEngine(network)

        src_id = net.device_id("PC-01")
        dst_id = net.device_id("PC-02")

        res = run_flood_scenario(
            network=network,
            engine=engine,
            source_id=src_id,
            target_id=dst_id,
            scenario_type="syn",
            packet_count=20,
            target_port=80,
        )

        assert res.success
        assert res.packets_sent == 20
        assert res.packets_delivered > 0
        assert res.mitigated is False
        assert res.simulated_availability_pct < 100.0

        # Check alert
        syn_alerts = [a for a in res.alerts if a.rule == "TCP_SYN_FLOOD_DETECTED"]
        assert len(syn_alerts) == 1
        assert syn_alerts[0].category == "flood"
        assert syn_alerts[0].severity == "high"

    def test_unmitigated_icmp_flood(self):
        net = two_pc_lan()
        topology = net.build()
        network = build_network(topology)
        engine = SimulationEngine(network)

        src_id = net.device_id("PC-01")
        dst_id = net.device_id("PC-02")

        res = run_flood_scenario(
            network=network,
            engine=engine,
            source_id=src_id,
            target_id=dst_id,
            scenario_type="icmp",
            packet_count=20,
        )

        assert res.success
        assert res.packets_sent == 20
        icmp_alerts = [a for a in res.alerts if a.rule == "ICMP_FLOOD_DETECTED"]
        assert len(icmp_alerts) == 1
        assert icmp_alerts[0].category == "flood"

    def test_unmitigated_udp_flood(self):
        net = two_pc_lan()
        topology = net.build()
        network = build_network(topology)
        engine = SimulationEngine(network)

        src_id = net.device_id("PC-01")
        dst_id = net.device_id("PC-02")

        res = run_flood_scenario(
            network=network,
            engine=engine,
            source_id=src_id,
            target_id=dst_id,
            scenario_type="udp",
            packet_count=20,
            target_port=53,
        )

        assert res.success
        assert res.packets_sent == 20
        udp_alerts = [a for a in res.alerts if a.rule == "UDP_FLOOD_DETECTED"]
        assert len(udp_alerts) == 1
        assert udp_alerts[0].category == "flood"

    def test_firewall_mitigated_syn_flood(self):
        net = TopologyBuilder()
        net.pc("PC-01", "192.168.1.10")
        net.server("Server-01", "192.168.1.50", services=[http()])
        # Inline firewall with deny rule for PC-01 attack traffic
        rules = [
            FirewallRuleSchema(action="deny", protocol="tcp", source="192.168.1.10", port=80, description="Block attacker SYN flood"),
            FirewallRuleSchema(action="allow", protocol="any", description="Allow other"),
        ]
        net.firewall("FW-01", rules=rules, default_policy="allow")
        net.link("PC-01", 0, "FW-01", 0)
        net.link("FW-01", 1, "Server-01", 0)

        topology = net.build()
        network = build_network(topology)
        engine = SimulationEngine(network)

        src_id = net.device_id("PC-01")
        dst_id = net.device_id("Server-01")

        res = run_flood_scenario(
            network=network,
            engine=engine,
            source_id=src_id,
            target_id=dst_id,
            scenario_type="syn",
            packet_count=20,
            target_port=80,
        )

        assert res.success
        assert res.packets_sent == 20
        # All packets dropped by firewall
        assert res.packets_dropped == 20
        assert res.packets_delivered == 0
        assert res.mitigated is True
        assert res.simulated_availability_pct == 100.0

    def test_experiment_comparison(self):
        # Baseline topology without defense
        net1 = TopologyBuilder()
        net1.pc("PC-01", "192.168.1.10")
        net1.server("Server-01", "192.168.1.50", services=[http()])
        net1.firewall("FW-01", rules=[], default_policy="allow")
        net1.link("PC-01", 0, "FW-01", 0)
        net1.link("FW-01", 1, "Server-01", 0)
        topo1 = net1.build()

        # Mitigated topology with firewall block
        net2 = TopologyBuilder()
        net2.pc("PC-01", "192.168.1.10")
        net2.server("Server-01", "192.168.1.50", services=[http()])
        rules = [
            FirewallRuleSchema(action="deny", protocol="tcp", source="192.168.1.10", port=80, description="Block SYN flood"),
        ]
        net2.firewall("FW-01", rules=rules, default_policy="allow")
        net2.link("PC-01", 0, "FW-01", 0)
        net2.link("FW-01", 1, "Server-01", 0)
        topo2 = net2.build()

        comp = compare_flood_experiment(
            topology=topo1,
            mitigated_topology=topo2,
            source_id=net1.device_id("PC-01"),
            target_id=net1.device_id("Server-01"),
            scenario_type="syn",
            packet_count=20,
            target_port=80,
        )

        assert comp.scenario_type == "syn"
        assert comp.baseline.phase_name.startswith("Baseline")
        assert comp.attack.simulated_availability_pct < comp.mitigated.simulated_availability_pct
        assert comp.mitigated.packets_dropped > comp.attack.packets_dropped
        assert "packets_filtered" in comp.difference_summary
        assert comp.difference_summary["availability_recovered_pct"] > 0
        assert len(comp.explanation) > 20
