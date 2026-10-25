"""Tests for simulated educational ARP spoofing, detection, and mitigations."""

from __future__ import annotations

import pytest
from app.simulation.core.engine import SimulationEngine
from app.simulation.loader import build_network
from app.simulation.security.scenarios import (
    reset_arp_spoof_scenario,
    run_arp_spoof_scenario,
)
from builders import TopologyBuilder


def three_node_lan():
    """Setup: Victim (PC-01), Attacker (PC-02), Gateway (Router-01) on Switch (SW-01)."""
    net = TopologyBuilder()
    net.pc("PC-01", "192.168.1.10", gateway="192.168.1.1")
    net.pc("PC-02", "192.168.1.20", gateway="192.168.1.1")
    net.router("Router-01", interfaces=[("192.168.1.1", "255.255.255.0")])
    net.switch("SW-01", ports=8)
    net.link("PC-01", 0, "SW-01", 0)
    net.link("PC-02", 0, "SW-01", 1)
    net.link("Router-01", 0, "SW-01", 2)
    return net


class TestArpSpoofing:
    def test_unmitigated_arp_spoofing_redirects_traffic(self):
        net = three_node_lan()
        topology = net.build()
        network = build_network(topology)
        engine = SimulationEngine(network)

        v_id = net.device_id("PC-01")
        g_id = net.device_id("Router-01")
        a_id = net.device_id("PC-02")

        res = run_arp_spoof_scenario(
            network=network,
            engine=engine,
            victim_id=v_id,
            gateway_id=g_id,
            attacker_id=a_id,
        )

        assert res.success
        assert res.victim_arp_after == res.attacker_mac
        assert res.victim_arp_after != res.legitimate_gateway_mac
        assert res.traffic_redirected is True
        assert res.mitigated is False

        # Verify security alert was raised with high/critical severity
        alerts = [a for a in res.alerts if a.rule == "ARP_SPOOF_DETECTED"]
        assert len(alerts) == 1
        alert = alerts[0]
        assert alert.severity in ("high", "critical")
        assert alert.confirmed_attack is True
        assert alert.evidence["forged_mac"] == res.attacker_mac
        assert alert.evidence["spoofed_ip"] == "192.168.1.1"

    def test_static_arp_mitigation_prevents_spoofing(self):
        net = three_node_lan()
        topology = net.build()
        network = build_network(topology)
        engine = SimulationEngine(network)

        v_id = net.device_id("PC-01")
        g_id = net.device_id("Router-01")
        a_id = net.device_id("PC-02")

        victim = network.device(v_id)
        gateway = network.device(g_id)
        gw_mac = gateway.interfaces[0].mac

        # Apply static ARP binding on victim
        victim.arp_table.insert("192.168.1.1", gw_mac, dynamic=False)

        res = run_arp_spoof_scenario(
            network=network,
            engine=engine,
            victim_id=v_id,
            gateway_id=g_id,
            attacker_id=a_id,
        )

        assert res.success
        # Static mapping was preserved
        assert res.victim_arp_after == gw_mac.upper()
        assert res.traffic_redirected is False
        assert res.mitigated is True

    def test_reset_arp_spoof_scenario(self):
        net = three_node_lan()
        topology = net.build()
        network = build_network(topology)
        engine = SimulationEngine(network)

        v_id = net.device_id("PC-01")
        g_id = net.device_id("Router-01")
        a_id = net.device_id("PC-02")

        # First run spoof
        run_arp_spoof_scenario(
            network=network,
            engine=engine,
            victim_id=v_id,
            gateway_id=g_id,
            attacker_id=a_id,
        )

        victim = network.device(v_id)
        assert victim.arp_table.lookup("192.168.1.1") != network.device(g_id).interfaces[0].mac.upper()

        # Reset
        success, msg = reset_arp_spoof_scenario(network, v_id, g_id)
        assert success
        assert victim.arp_table.lookup("192.168.1.1") == network.device(g_id).interfaces[0].mac.upper()
