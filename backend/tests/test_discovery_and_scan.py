"""Tests for host discovery (netdiscover) and simulated port scanning (nmap)."""

from __future__ import annotations

import pytest
from app.schemas.topology import FirewallRuleSchema
from app.simulation.runner import run_command
from builders import (
    TopologyBuilder,
    apply_state,
    http,
    https,
    routed_network,
    ssh,
    two_pc_lan,
)


def exec_cmd(net: TopologyBuilder, source: str, command: str):
    topology = net.build()
    return run_command(topology, net.device_id(source), command)


def joined(result) -> str:
    return "\n".join(result.output)


class TestHostDiscovery:
    def test_netdiscover_local_subnet(self):
        net = two_pc_lan()
        res = exec_cmd(net, "PC-01", "netdiscover")
        assert res.success
        out = joined(res)
        assert "192.168.1.10" in out  # Local PC-01
        assert "192.168.1.20" in out  # Remote PC-02
        assert "PC-02" in out
        assert "2 host(s) discovered" in out

    def test_netdiscover_with_range_arg(self):
        net = two_pc_lan()
        res = exec_cmd(net, "PC-01", "netdiscover -r 192.168.1.0/24")
        assert res.success
        out = joined(res)
        assert "192.168.1.20" in out

    def test_netdiscover_invalid_cidr(self):
        net = two_pc_lan()
        res = exec_cmd(net, "PC-01", "netdiscover -r invalid_cidr")
        assert not res.success
        assert "invalid CIDR" in joined(res)

    def test_netdiscover_unconnected_host(self):
        net = TopologyBuilder()
        net.pc("PC-01", "10.0.0.5")
        res = exec_cmd(net, "PC-01", "netdiscover")
        assert res.success
        out = joined(res)
        assert "1 host(s) discovered" in out  # Only local host

    def test_netdiscover_routed_subnet(self):
        net = routed_network()
        # From PC-01, scan 10.0.0.0/24 across the router
        res = exec_cmd(net, "PC-01", "netdiscover -r 10.0.0.0/24")
        assert res.success
        out = joined(res)
        assert "10.0.0.50" in out
        assert "Server-01" in out


class TestPortScanning:
    def test_nmap_open_and_closed_ports(self):
        net = TopologyBuilder()
        net.pc("PC-01", "192.168.1.10")
        net.server("Server-01", "192.168.1.50", services=[http(), https(enabled=False)])
        net.switch("SW-01")
        net.link("PC-01", 0, "SW-01", 0)
        net.link("Server-01", 0, "SW-01", 1)

        res = exec_cmd(net, "PC-01", "nmap -p 80,443,22 192.168.1.50")
        assert res.success
        out = joined(res)
        assert "80/tcp" in out
        assert "open" in out
        assert "http" in out
        # 443 is disabled, so host sends RST
        assert "443/tcp" in out
        assert "closed" in out
        # 22 is not configured, so host sends RST
        assert "22/tcp" in out
        assert "closed" in out

    def test_nmap_filtered_by_firewall(self):
        net = TopologyBuilder()
        net.pc("PC-01", "192.168.1.10")
        net.server("Server-01", "192.168.1.50", services=[http(), ssh()])
        rules = [
            FirewallRuleSchema(action="deny", protocol="tcp", port=22, description="Block SSH"),
            FirewallRuleSchema(action="allow", protocol="any", description="Allow rest"),
        ]
        net.firewall("FW-01", rules=rules)
        net.link("PC-01", 0, "FW-01", 0)
        net.link("FW-01", 1, "Server-01", 0)

        res = exec_cmd(net, "PC-01", "nmap -p 80,22 192.168.1.50")
        assert res.success
        out = joined(res)
        assert "80/tcp" in out and "open" in out
        assert "22/tcp" in out and "filtered" in out

    def test_nmap_invalid_target(self):
        net = two_pc_lan()
        res = exec_cmd(net, "PC-01", "nmap nonexistent.local")
        assert not res.success
        assert "failed to resolve" in joined(res)

    def test_nmap_invalid_port_specification(self):
        net = two_pc_lan()
        res = exec_cmd(net, "PC-01", "nmap -p 999999 192.168.1.20")
        assert not res.success
        assert "invalid port" in joined(res)


class TestStaticArp:
    def test_arp_set_static_entry(self):
        net = two_pc_lan()
        topo = net.build()
        pc1_id = net.device_id("PC-01")

        res1 = run_command(topo, pc1_id, "arp -s 192.168.1.20 02:00:aa:bb:cc:dd")
        assert res1.success
        assert "Static ARP mapping added" in joined(res1)

        topo = apply_state(topo, res1)
        res2 = run_command(topo, pc1_id, "arp")
        assert res2.success
        out = joined(res2)
        assert "192.168.1.20" in out
        assert "02:00:AA:BB:CC:DD" in out.upper()
        assert "static" in out
