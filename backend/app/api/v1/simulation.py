"""Simulation endpoints."""

from __future__ import annotations

from fastapi import APIRouter

from ...schemas.simulation import (
    ArpResetRequest,
    ArpSpoofRequest,
    ArpSpoofResponse,
    CommandRequest,
    CommandResponse,
    ConnectionRequest,
    ConnectionResponse,
    DeviceStateSchema,
    ExperimentComparisonRequest,
    ExperimentComparisonResponse,
    FloodRequest,
    FloodResponse,
    PacketSchema,
    SecurityAlertSchema,
    SimEventSchema,
    ValidationResponse,
)
from ...schemas.topology import TopologySchema
from ...simulation.commands import COMMAND_SETS
from ...simulation.core.engine import SimulationEngine
from ...simulation.loader import build_network, collect_state
from ...simulation.runner import run_command, run_connection_test
from ...simulation.security.experiments import compare_flood_experiment
from ...simulation.security.scenarios import (
    reset_arp_spoof_scenario,
    run_arp_spoof_scenario,
    run_flood_scenario,
)
from ...simulation.transport.services import WELL_KNOWN
from ...simulation.validation import validate_topology

router = APIRouter(tags=["simulation"])


@router.post("/simulate/command", response_model=CommandResponse)
def simulate_command(request: CommandRequest) -> CommandResponse:
    """Run one terminal command against a topology.

    The topology travels with the request, so the backend holds no session
    state. The response carries the terminal output, the ordered event trace
    that drives the packet animation, inspector records for every frame that
    crossed a wire, and the learned tables to write back into the document.
    """
    return run_command(request.topology, request.device_id, request.command)


@router.post("/simulate/connect", response_model=ConnectionResponse)
def simulate_connection(request: ConnectionRequest) -> ConnectionResponse:
    """Test whether one device can actually reach a port on another.

    Runs the same engine the terminal does, so the verdict, the hop path and
    the point where traffic stopped all come from real packets. The distinction
    between *refused* (the host said no) and *filtered* (something in between
    swallowed it) is preserved, because that is what tells a learner whether to
    look at the server or at the firewall.
    """
    return run_connection_test(
        request.topology,
        request.source_device_id,
        request.destination,
        request.port,
        request.protocol,
    )


@router.get("/services")
def list_services() -> list[dict[str, object]]:
    """The service catalogue the config panel offers as one-click ports."""
    return [
        {
            "name": service.name,
            "protocol": service.protocol.value,
            "port": service.port,
            "description": service.description,
        }
        for service in WELL_KNOWN
    ]


@router.post("/topology/validate", response_model=ValidationResponse)
def validate(topology: TopologySchema) -> ValidationResponse:
    """Report configuration mistakes that need no traffic to detect."""
    return validate_topology(topology)


@router.get("/commands")
def list_commands() -> dict[str, list[dict[str, str]]]:
    """Command reference per device type, used by the terminal's help panel."""
    return {
        kind: [
            {"name": c.name, "usage": c.usage or c.name, "summary": c.summary}
            for c in sorted(command_set.commands, key=lambda c: c.name)
        ]
        for kind, command_set in COMMAND_SETS.items()
    }


# -- Educational Security Scenarios & Experiments -----------------------


@router.post("/simulate/scenario/arp-spoof", response_model=ArpSpoofResponse)
def simulate_arp_spoof(request: ArpSpoofRequest) -> ArpSpoofResponse:
    """Execute educational ARP spoofing against the virtual network."""
    network = build_network(request.topology)
    engine = SimulationEngine(network)
    result = run_arp_spoof_scenario(
        network=network,
        engine=engine,
        victim_id=request.victim_id,
        gateway_id=request.gateway_id,
        attacker_id=request.attacker_id,
    )
    return ArpSpoofResponse(
        success=result.success,
        victim_id=result.victim_id,
        victim_name=result.victim_name,
        victim_ip=result.victim_ip,
        gateway_id=result.gateway_id,
        gateway_name=result.gateway_name,
        gateway_ip=result.gateway_ip,
        attacker_id=result.attacker_id,
        attacker_name=result.attacker_name,
        attacker_mac=result.attacker_mac,
        legitimate_gateway_mac=result.legitimate_gateway_mac,
        victim_arp_before=result.victim_arp_before,
        victim_arp_after=result.victim_arp_after,
        traffic_redirected=result.traffic_redirected,
        mitigated=result.mitigated,
        mitigation_reason=result.mitigation_reason,
        alerts=[SecurityAlertSchema(**a.to_dict()) for a in result.alerts],
        output=result.output,
        events=[SimEventSchema(**event.to_dict()) for event in engine.events],
        packets=[PacketSchema(**packet.to_dict()) for packet in engine.packets.values()],
        device_state={
            dev_id: DeviceStateSchema(**state)
            for dev_id, state in collect_state(network).items()
        },
    )


@router.post("/simulate/scenario/arp-reset")
def reset_arp_spoof(request: ArpResetRequest) -> dict[str, object]:
    """Restore clean, legitimate ARP mappings without destroying user topology."""
    network = build_network(request.topology)
    success, message = reset_arp_spoof_scenario(
        network=network,
        victim_id=request.victim_id,
        gateway_id=request.gateway_id,
    )
    return {
        "success": success,
        "message": message,
        "device_state": {
            dev_id: DeviceStateSchema(**state)
            for dev_id, state in collect_state(network).items()
        },
    }


@router.post("/simulate/scenario/flood", response_model=FloodResponse)
def simulate_flood(request: FloodRequest) -> FloodResponse:
    """Execute a controlled, bounded traffic flood simulation (SYN, UDP, or ICMP)."""
    network = build_network(request.topology)
    engine = SimulationEngine(network)
    result = run_flood_scenario(
        network=network,
        engine=engine,
        source_id=request.source_id,
        target_id=request.target_id,
        scenario_type=request.scenario_type,
        packet_count=request.packet_count,
        target_port=request.target_port,
    )
    return FloodResponse(
        success=result.success,
        scenario_type=result.scenario_type,
        source_id=result.source_id,
        source_name=result.source_name,
        source_ip=result.source_ip,
        target_id=result.target_id,
        target_name=result.target_name,
        target_ip=result.target_ip,
        target_port=result.target_port,
        packets_sent=result.packets_sent,
        packets_delivered=result.packets_delivered,
        packets_dropped=result.packets_dropped,
        service_available=result.service_available,
        simulated_availability_pct=result.simulated_availability_pct,
        simulated_latency_ms=result.simulated_latency_ms,
        mitigated=result.mitigated,
        mitigation_reason=result.mitigation_reason,
        alerts=[SecurityAlertSchema(**a.to_dict()) for a in result.alerts],
        output=result.output,
        events=[SimEventSchema(**event.to_dict()) for event in engine.events],
        packets=[PacketSchema(**packet.to_dict()) for packet in engine.packets.values()],
        device_state={
            dev_id: DeviceStateSchema(**state)
            for dev_id, state in collect_state(network).items()
        },
    )


@router.post("/simulate/experiment/compare", response_model=ExperimentComparisonResponse)
def compare_experiment(request: ExperimentComparisonRequest) -> ExperimentComparisonResponse:
    """Compare baseline, unmitigated attack, and mitigated network behavior."""
    result = compare_flood_experiment(
        topology=request.topology,
        mitigated_topology=request.mitigated_topology,
        source_id=request.source_id,
        target_id=request.target_id,
        scenario_type=request.scenario_type,
        packet_count=request.packet_count,
        target_port=request.target_port,
    )
    return ExperimentComparisonResponse(
        scenario_name=result.scenario_name,
        scenario_type=result.scenario_type,
        source_name=result.source_name,
        target_name=result.target_name,
        baseline=result.baseline.to_dict(),
        attack=result.attack.to_dict(),
        mitigated=result.mitigated.to_dict(),
        explanation=result.explanation,
        difference_summary=result.difference_summary,
        alerts=[SecurityAlertSchema(**a.to_dict()) for a in result.alerts],
    )

