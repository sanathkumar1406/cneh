"""Tests for the Security Event Engine."""

from __future__ import annotations

import pytest
from app.schemas.topology import FirewallRuleSchema
from app.simulation.runner import run_command, run_connection_test
from builders import (
    TopologyBuilder,
    http,
    https,
    two_pc_lan,
)


def exec_cmd(net: TopologyBuilder, source: str, command: str):
    topology = net.build()
    return run_command(topology, net.device_id(source), command)


class TestSecurityEngine:
    def test_single_ping_does_not_trigger_false_alerts(self):
        net = two_pc_lan()
        res = exec_cmd(net, "PC-01", "ping 192.168.1.20 -n 2")
        assert res.success
        # Single benign ping should NOT trigger flood or spoof alerts
        alert_rules = [a.rule for a in res.alerts]
        assert "PORT_SCAN_DETECTED" not in alert_rules
        assert "ICMP_FLOOD_DETECTED" not in alert_rules
        assert "ARP_SPOOF_DETECTED" not in alert_rules

    def test_port_scan_detection(self):
        net = TopologyBuilder()
        net.pc("PC-01", "192.168.1.10")
        net.server("Server-01", "192.168.1.50", services=[http(), https(enabled=False)])
        net.switch("SW-01")
        net.link("PC-01", 0, "SW-01", 0)
        net.link("Server-01", 0, "SW-01", 1)

        res = exec_cmd(net, "PC-01", "nmap -p 21,22,80,443,3306 192.168.1.50")
        assert res.success
        scan_alerts = [a for a in res.alerts if a.rule == "PORT_SCAN_DETECTED"]
        assert len(scan_alerts) == 1
        alert = scan_alerts[0]
        assert alert.category == "reconnaissance"
        assert alert.severity == "medium"
        assert alert.target == "192.168.1.50"
        assert alert.confirmed_attack is True
        assert "scanned_ports" in alert.evidence
        assert alert.evidence["unique_port_count"] >= 4
        assert "firewall" in alert.recommendation.lower()

    def test_host_discovery_detection(self):
        net = two_pc_lan()
        res = exec_cmd(net, "PC-01", "netdiscover")
        assert res.success
        discovery_alerts = [a for a in res.alerts if a.rule == "HOST_DISCOVERY_SWEEP"]
        assert len(discovery_alerts) == 1
        alert = discovery_alerts[0]
        assert alert.category == "reconnaissance"
        assert alert.severity == "low"
        assert "sweep across" in alert.reason.lower()

    def test_firewall_block_alert(self):
        net = TopologyBuilder()
        net.pc("PC-01", "192.168.1.10")
        net.server("Server-01", "192.168.1.50", services=[http()])
        rules = [
            FirewallRuleSchema(action="deny", protocol="tcp", port=80, description="Block HTTP"),
        ]
        net.firewall("FW-01", rules=rules, default_policy="allow")
        net.link("PC-01", 0, "FW-01", 0)
        net.link("FW-01", 1, "Server-01", 0)

        topology = net.build()
        res = run_connection_test(topology, net.device_id("PC-01"), "192.168.1.50", 80, "TCP")
        assert not res.reachable
        fw_alerts = [a for a in res.alerts if a.rule == "FIREWALL_PACKET_BLOCKED"]
        assert len(fw_alerts) >= 1
        assert fw_alerts[0].category == "firewall"
        assert fw_alerts[0].mitigated is True
