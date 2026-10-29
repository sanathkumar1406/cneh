import {
  AlertTriangle,
  CheckCircle2,
  Flame,
  Lock,
  RotateCcw,
  Scale,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Zap,
} from 'lucide-react'
import { useState } from 'react'

import { Button } from '@/components/ui/Button'
import { Empty, Field, SectionTitle, TextInput } from '@/components/ui/Field'
import { ApiError, api } from '@/lib/api'
import { useSimulationStore } from '@/stores/simulationStore'
import { toDocument, useTopologyStore } from '@/stores/topologyStore'
import { useUiStore } from '@/stores/uiStore'
import type {
  ArpSpoofResult,
  ExperimentComparisonResult,
  FloodResult,
} from '@/types'

type LabMode = 'scenarios' | 'comparison' | 'alerts'
type ScenarioType = 'arp' | 'flood'
type FloodType = 'syn' | 'icmp' | 'udp'

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'bg-bad/20 text-bad border-bad/40',
  high: 'bg-bad/15 text-bad border-bad/30',
  medium: 'bg-warn/15 text-warn border-warn/30',
  low: 'bg-accent/15 text-accent border-accent/30',
  info: 'bg-line text-ink-dim border-line',
}

export function SecurityLab() {
  const devices = useTopologyStore((state) => state.devices)
  const applyDeviceState = useTopologyStore((state) => state.applyDeviceState)
  const notify = useUiStore((state) => state.notify)
  const simulationLoad = useSimulationStore((state) => state.load)
  const storedAlerts = useSimulationStore((state) => state.alerts)
  const clearAlerts = useSimulationStore((state) => state.clearAlerts)

  const [mode, setMode] = useState<LabMode>('scenarios')
  const [scenarioType, setScenarioType] = useState<ScenarioType>('arp')

  // ARP Spoofing State
  const pcs = devices.filter((d) => d.type === 'pc' || d.type === 'server')
  const gateways = devices.filter((d) => d.type === 'router' || d.type === 'server')
  const [victimId, setVictimId] = useState<string>(pcs[0]?.id ?? '')
  const [gatewayId, setGatewayId] = useState<string>(gateways[0]?.id ?? '')
  const [attackerId, setAttackerId] = useState<string>(pcs[1]?.id ?? '')
  const [arpLoading, setArpLoading] = useState(false)
  const [arpResult, setArpResult] = useState<ArpSpoofResult | null>(null)

  // Flood State
  const [floodType, setFloodType] = useState<FloodType>('syn')
  const [floodSourceId, setFloodSourceId] = useState<string>(pcs[0]?.id ?? '')
  const [floodTargetId, setFloodTargetId] = useState<string>(pcs[1]?.id ?? '')
  const [packetCount, setPacketCount] = useState<number>(25)
  const [targetPort, setTargetPort] = useState<number>(80)
  const [floodLoading, setFloodLoading] = useState(false)
  const [floodResult, setFloodResult] = useState<FloodResult | null>(null)

  // Comparison State
  const [compLoading, setCompLoading] = useState(false)
  const [compResult, setCompResult] = useState<ExperimentComparisonResult | null>(null)

  const effectiveVictim = pcs.find((p) => p.id === victimId)?.id ?? pcs[0]?.id ?? ''
  const effectiveGateway = gateways.find((g) => g.id === gatewayId)?.id ?? gateways[0]?.id ?? ''
  const effectiveAttacker = pcs.find((p) => p.id === attackerId && p.id !== effectiveVictim)?.id ?? pcs[1]?.id ?? ''

  const effectiveFloodSource = pcs.find((p) => p.id === floodSourceId)?.id ?? pcs[0]?.id ?? ''
  const effectiveFloodTarget = pcs.find((p) => p.id === floodTargetId && p.id !== effectiveFloodSource)?.id ?? pcs[1]?.id ?? ''

  // --- Handlers ---

  const handleRunArpSpoof = async () => {
    if (!effectiveVictim || !effectiveGateway || !effectiveAttacker) {
      notify('Select victim, gateway, and attacker devices.', 'error')
      return
    }
    setArpLoading(true)
    try {
      const res = await api.simulateArpSpoof(toDocument(), effectiveVictim, effectiveGateway, effectiveAttacker)
      setArpResult(res)
      applyDeviceState(res.device_state)
      simulationLoad(res.events, res.packets, res.alerts)
      notify(res.mitigated ? 'Static ARP defense blocked the spoof!' : 'ARP poisoned: traffic redirected to attacker!', res.mitigated ? 'info' : 'error')
    } catch (e) {
      const msg = e instanceof ApiError ? e.message : 'ARP spoof scenario failed.'
      notify(msg, 'error')
    } finally {
      setArpLoading(false)
    }
  }

  const handleResetArp = async () => {
    if (!effectiveVictim || !effectiveGateway) return
    setArpLoading(true)
    try {
      const res = await api.resetArpSpoof(toDocument(), effectiveVictim, effectiveGateway)
      applyDeviceState(res.device_state)
      setArpResult(null)
      notify('ARP tables restored to clean state.', 'success')
    } catch (e) {
      notify('Reset failed.', 'error')
    } finally {
      setArpLoading(false)
    }
  }

  const handleApplyStaticArp = async () => {
    const vDev = devices.find((d) => d.id === effectiveVictim)
    const gDev = devices.find((d) => d.id === effectiveGateway)
    const gIface = gDev?.interfaces.find((i) => i.enabled && i.ipv4)
    if (!vDev || !gIface || !gIface.ipv4) {
      notify('Gateway lacks an IPv4 address to bind.', 'error')
      return
    }
    try {
      const cmd = `arp -s ${gIface.ipv4} ${gIface.mac}`
      const res = await api.runCommand(toDocument(), vDev.id, cmd)
      applyDeviceState(res.device_state)
      notify(`Static mapping configured: ${gIface.ipv4} -> ${gIface.mac}`, 'success')
      // Rerun scenario to reflect defense
      handleRunArpSpoof()
    } catch (e) {
      notify('Failed to apply static ARP mapping.', 'error')
    }
  }

  const handleRunFlood = async () => {
    if (!effectiveFloodSource || !effectiveFloodTarget) {
      notify('Select flood source and target devices.', 'error')
      return
    }
    setFloodLoading(true)
    try {
      const res = await api.simulateFlood(
        toDocument(),
        effectiveFloodSource,
        effectiveFloodTarget,
        floodType,
        packetCount,
        targetPort,
      )
      setFloodResult(res)
      applyDeviceState(res.device_state)
      simulationLoad(res.events, res.packets, res.alerts)
      notify(res.mitigated ? 'Firewall dropped the flood traffic!' : `Flood delivered: service degraded to ${res.simulated_availability_pct.toFixed(0)}%!`, res.mitigated ? 'success' : 'error')
    } catch (e) {
      const msg = e instanceof ApiError ? e.message : 'Flood simulation failed.'
      notify(msg, 'error')
    } finally {
      setFloodLoading(false)
    }
  }

  const handleRunComparison = async () => {
    if (!effectiveFloodSource || !effectiveFloodTarget) {
      notify('Select source and target for comparison.', 'error')
      return
    }
    setCompLoading(true)
    try {
      const baseTopo = toDocument()
      // Create a mitigated copy of topology with defense rules applied to target host and perimeter firewalls
      const mitigatedTopo = JSON.parse(JSON.stringify(baseTopo))
      const targetDev = mitigatedTopo.devices.find((d: any) => d.id === effectiveFloodTarget)
      const fwDevs = mitigatedTopo.devices.filter((d: any) => d.type === 'firewall')
      const srcDev = baseTopo.devices.find((d: any) => d.id === effectiveFloodSource)
      const activeSrcIface = srcDev?.interfaces?.find((i: any) => i.enabled && i.ipv4)
      const srcIp = activeSrcIface?.ipv4 || srcDev?.interfaces?.[0]?.ipv4 || 'any'

      const devicesToProtect = [targetDev, ...fwDevs].filter(Boolean)
      for (const dev of devicesToProtect) {
        if (!dev.config.firewall_rules) {
          dev.config.firewall_rules = []
        }
        dev.config.firewall_rules.unshift({
          action: 'deny',
          protocol: floodType === 'syn' ? 'tcp' : floodType === 'udp' ? 'udp' : 'icmp',
          port: floodType === 'syn' || floodType === 'udp' ? targetPort : null,
          source: srcIp,
          destination: 'any',
          description: `Defense: Drop ${floodType.toUpperCase()} flood from ${srcIp}`,
        })
      }

      const res = await api.compareExperiment(
        baseTopo,
        mitigatedTopo,
        effectiveFloodSource,
        effectiveFloodTarget,
        floodType,
        packetCount,
        targetPort,
      )
      setCompResult(res)
      if (res.alerts && res.alerts.length > 0) {
        useSimulationStore.getState().addAlerts(res.alerts)
      }
      notify('3-Phase experiment completed successfully.', 'success')
    } catch (e) {
      notify('Experiment comparison failed.', 'error')
    } finally {
      setCompLoading(false)
    }
  }

  return (
    <div className="flex h-full min-h-0 flex-col overflow-hidden bg-surface font-sans text-xs">
      {/* Sub-header navigation */}
      <div className="flex shrink-0 items-center justify-between border-b border-line px-3 py-1.5 bg-panel">
        <div className="flex items-center gap-1.5">
          <span className="flex h-5 w-5 items-center justify-center rounded bg-bad/15 text-bad">
            <ShieldAlert size={13} />
          </span>
          <span className="font-semibold text-ink">Network Security Lab</span>
        </div>

        <div className="flex rounded border border-line bg-surface p-0.5">
          <button
            type="button"
            onClick={() => setMode('scenarios')}
            className={`rounded px-2.5 py-0.5 text-[11px] font-medium transition-colors ${
              mode === 'scenarios' ? 'bg-raised text-ink shadow-xs' : 'text-ink-faint hover:text-ink'
            }`}
          >
            Attack Scenarios
          </button>
          <button
            type="button"
            onClick={() => setMode('comparison')}
            className={`flex items-center gap-1 rounded px-2.5 py-0.5 text-[11px] font-medium transition-colors ${
              mode === 'comparison' ? 'bg-raised text-ink shadow-xs' : 'text-ink-faint hover:text-ink'
            }`}
          >
            <Scale size={11} />
            Experiment Comparison
          </button>
          <button
            type="button"
            onClick={() => setMode('alerts')}
            className={`flex items-center gap-1 rounded px-2.5 py-0.5 text-[11px] font-medium transition-colors ${
              mode === 'alerts' ? 'bg-raised text-ink shadow-xs' : 'text-ink-faint hover:text-ink'
            }`}
          >
            <AlertTriangle size={11} />
            Alerts ({storedAlerts.length})
          </button>
        </div>
      </div>

      {/* Main Tab Views */}
      <div className="min-h-0 flex-1 overflow-y-auto p-3">
        {mode === 'scenarios' && (
          <div className="space-y-4">
            {/* Scenario Selector */}
            <div className="flex gap-2">
              <button
                type="button"
                onClick={() => setScenarioType('arp')}
                className={`flex-1 rounded-md border p-2 text-left transition-all ${
                  scenarioType === 'arp'
                    ? 'border-accent bg-accent/10 text-ink'
                    : 'border-line bg-panel text-ink-dim hover:border-line-soft'
                }`}
              >
                <div className="flex items-center gap-1.5 font-medium">
                  <Shield size={14} className={scenarioType === 'arp' ? 'text-accent' : 'text-ink-faint'} />
                  ARP Poisoning & Interception (L2)
                </div>
                <div className="mt-1 text-[11px] text-ink-faint">
                  Forges ARP replies to redirect gateway traffic to an attacker. Test static ARP defenses.
                </div>
              </button>

              <button
                type="button"
                onClick={() => setScenarioType('flood')}
                className={`flex-1 rounded-md border p-2 text-left transition-all ${
                  scenarioType === 'flood'
                    ? 'border-accent bg-accent/10 text-ink'
                    : 'border-line bg-panel text-ink-dim hover:border-line-soft'
                }`}
              >
                <div className="flex items-center gap-1.5 font-medium">
                  <Flame size={14} className={scenarioType === 'flood' ? 'text-bad' : 'text-ink-faint'} />
                  Controlled Traffic Flood / DoS (L4)
                </div>
                <div className="mt-1 text-[11px] text-ink-faint">
                  Synthesizes TCP SYN, UDP, or ICMP bursts to test service overload and firewall drops.
                </div>
              </button>
            </div>

            {/* ARP Scenario Config & Execution */}
            {scenarioType === 'arp' && (
              <div className="grid grid-cols-1 gap-3 lg:grid-cols-3">
                <div className="rounded-md border border-line bg-panel p-3 space-y-3">
                  <SectionTitle>Scenario Participants</SectionTitle>
                  <Field label="Victim Device" hint="Target of the poisoned cache">
                    <select
                      value={effectiveVictim}
                      onChange={(e) => setVictimId(e.target.value)}
                      className="w-full rounded border border-line bg-surface px-2 py-1 font-mono text-[11px]"
                    >
                      {pcs.map((d) => (
                        <option key={d.id} value={d.id}>
                          {d.name} ({d.interfaces[0]?.ipv4 || 'no IP'})
                        </option>
                      ))}
                    </select>
                  </Field>

                  <Field label="Legitimate Gateway" hint="IP being spoofed">
                    <select
                      value={effectiveGateway}
                      onChange={(e) => setGatewayId(e.target.value)}
                      className="w-full rounded border border-line bg-surface px-2 py-1 font-mono text-[11px]"
                    >
                      {gateways.map((d) => (
                        <option key={d.id} value={d.id}>
                          {d.name} ({d.interfaces[0]?.ipv4 || 'no IP'})
                        </option>
                      ))}
                    </select>
                  </Field>

                  <Field label="Attacker Device" hint="Originates forged ARP replies">
                    <select
                      value={effectiveAttacker}
                      onChange={(e) => setAttackerId(e.target.value)}
                      className="w-full rounded border border-line bg-surface px-2 py-1 font-mono text-[11px]"
                    >
                      {pcs
                        .filter((d) => d.id !== effectiveVictim)
                        .map((d) => (
                          <option key={d.id} value={d.id}>
                            {d.name} ({d.interfaces[0]?.ipv4 || 'no IP'})
                          </option>
                        ))}
                    </select>
                  </Field>

                  <div className="pt-2 flex flex-col gap-1.5">
                    <Button
                      variant="primary"
                      size="sm"
                      onClick={handleRunArpSpoof}
                      disabled={arpLoading}
                      className="w-full gap-1.5"
                    >
                      <Zap size={12} />
                      {arpLoading ? 'Simulating...' : 'Launch ARP Spoof'}
                    </Button>
                    <div className="flex gap-1.5">
                      <Button
                        size="sm"
                        onClick={handleApplyStaticArp}
                        className="flex-1 gap-1"
                        title="Configure static ARP on victim"
                      >
                        <Lock size={11} />
                        Apply Static Binding
                      </Button>
                      <Button
                        variant="default"
                        size="sm"
                        onClick={handleResetArp}
                        className="gap-1 text-ink-faint hover:text-ink"
                        title="Reset victim ARP cache"
                      >
                        <RotateCcw size={11} />
                        Reset
                      </Button>
                    </div>
                  </div>
                </div>

                {/* Outcome Display */}
                <div className="lg:col-span-2 rounded-md border border-line bg-panel p-3">
                  <SectionTitle>Observation & Redirection Status</SectionTitle>
                  {!arpResult ? (
                    <Empty>
                      Select devices and click <span className="text-ink font-semibold">Launch ARP Spoof</span> to simulate forged ARP messages.
                    </Empty>
                  ) : (
                    <div className="space-y-3">
                      <div className="grid grid-cols-2 gap-2 text-[11px]">
                        <div className="rounded border border-line bg-surface p-2">
                          <span className="text-ink-faint block">Victim Gateway Mapping Before</span>
                          <span className="font-mono text-ink font-semibold">{arpResult.victim_arp_before || 'Not resolved'}</span>
                          <span className="text-[10px] text-ok block mt-0.5">Legitimate Gateway MAC</span>
                        </div>
                        <div className="rounded border border-line bg-surface p-2">
                          <span className="text-ink-faint block">Victim Gateway Mapping After</span>
                          <span className="font-mono text-ink font-semibold">{arpResult.victim_arp_after}</span>
                          <span className={`text-[10px] font-semibold block mt-0.5 ${arpResult.mitigated ? 'text-ok' : 'text-bad'}`}>
                            {arpResult.mitigated ? 'Protected by Static ARP' : 'Poisoned (Attacker MAC)'}
                          </span>
                        </div>
                      </div>

                      <div className={`flex items-start gap-2 rounded-md border p-2.5 ${arpResult.traffic_redirected ? 'border-bad/30 bg-bad/10 text-bad' : 'border-ok/30 bg-ok/10 text-ok'}`}>
                        {arpResult.traffic_redirected ? <ShieldAlert size={16} className="shrink-0 mt-0.5" /> : <ShieldCheck size={16} className="shrink-0 mt-0.5" />}
                        <div>
                          <div className="font-semibold text-xs">
                            {arpResult.traffic_redirected ? 'Traffic Interception Active' : 'Traffic Route Secure'}
                          </div>
                          <div className="text-[11px] leading-relaxed text-ink-dim mt-0.5">
                            {arpResult.mitigation_reason}
                          </div>
                        </div>
                      </div>

                      <div className="rounded border border-line bg-surface p-2 font-mono text-[11px] space-y-1">
                        {arpResult.output.map((line, idx) => (
                          <div key={idx} className={line.startsWith(' - [CRITICAL]') ? 'text-bad' : line.startsWith(' - [') ? 'text-warn' : 'text-ink-dim'}>
                            {line}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Flood Scenario Config & Execution */}
            {scenarioType === 'flood' && (
              <div className="grid grid-cols-1 gap-3 lg:grid-cols-3">
                <div className="rounded-md border border-line bg-panel p-3 space-y-3">
                  <SectionTitle>Flood Parameters</SectionTitle>
                  <Field label="Attack Scenario Type">
                    <div className="flex gap-1">
                      {(['syn', 'icmp', 'udp'] as FloodType[]).map((t) => (
                        <button
                          key={t}
                          type="button"
                          onClick={() => setFloodType(t)}
                          className={`flex-1 rounded py-1 font-mono text-[11px] font-medium uppercase border ${
                            floodType === t ? 'border-bad bg-bad/15 text-bad' : 'border-line bg-surface text-ink-dim'
                          }`}
                        >
                          {t}
                        </button>
                      ))}
                    </div>
                  </Field>

                  <Field label="Source Host">
                    <select
                      value={effectiveFloodSource}
                      onChange={(e) => setFloodSourceId(e.target.value)}
                      className="w-full rounded border border-line bg-surface px-2 py-1 font-mono text-[11px]"
                    >
                      {pcs.map((d) => (
                        <option key={d.id} value={d.id}>
                          {d.name} ({d.interfaces[0]?.ipv4 || 'no IP'})
                        </option>
                      ))}
                    </select>
                  </Field>

                  <Field label="Target Host">
                    <select
                      value={effectiveFloodTarget}
                      onChange={(e) => setFloodTargetId(e.target.value)}
                      className="w-full rounded border border-line bg-surface px-2 py-1 font-mono text-[11px]"
                    >
                      {pcs
                        .filter((d) => d.id !== effectiveFloodSource)
                        .map((d) => (
                          <option key={d.id} value={d.id}>
                            {d.name} ({d.interfaces[0]?.ipv4 || 'no IP'})
                          </option>
                        ))}
                    </select>
                  </Field>

                  <div className="grid grid-cols-2 gap-2">
                    <Field label="Packet Burst Count">
                      <select
                        value={packetCount}
                        onChange={(e) => setPacketCount(Number(e.target.value))}
                        className="w-full rounded border border-line bg-surface px-2 py-1 font-mono text-[11px]"
                      >
                        <option value={15}>15 packets</option>
                        <option value={25}>25 packets</option>
                        <option value={35}>35 packets</option>
                        <option value={50}>50 packets (Max)</option>
                      </select>
                    </Field>

                    <Field label="Target Port">
                      <TextInput
                        value={String(targetPort)}
                        onChange={(e) => setTargetPort(Number(e.target.value) || 80)}
                        placeholder="80"
                      />
                    </Field>
                  </div>

                  <Button
                    variant="danger"
                    size="sm"
                    onClick={handleRunFlood}
                    disabled={floodLoading}
                    className="w-full gap-1.5"
                  >
                    <Flame size={12} />
                    {floodLoading ? 'Flooding...' : `Run ${floodType.toUpperCase()} Flood`}
                  </Button>
                </div>

                {/* Flood Output & Service Impact Gauge */}
                <div className="lg:col-span-2 rounded-md border border-line bg-panel p-3">
                  <SectionTitle>Target Impact & Service Telemetry</SectionTitle>
                  {!floodResult ? (
                    <Empty>
                      Configure flood parameters and click <span className="text-bad font-semibold">Run Flood</span> to measure synthetic service pressure.
                    </Empty>
                  ) : (
                    <div className="space-y-3">
                      {/* Telemetry Cards */}
                      <div className="grid grid-cols-4 gap-2 text-center">
                        <div className="rounded border border-line bg-surface p-2">
                          <span className="text-ink-faint text-[10px] block">Burst Packets</span>
                          <span className="font-mono text-base font-semibold text-ink">{floodResult.packets_sent}</span>
                        </div>
                        <div className="rounded border border-line bg-surface p-2">
                          <span className="text-ink-faint text-[10px] block">Delivered</span>
                          <span className={`font-mono text-base font-semibold ${floodResult.packets_delivered > 0 && !floodResult.mitigated ? 'text-bad' : 'text-ink-dim'}`}>
                            {floodResult.packets_delivered}
                          </span>
                        </div>
                        <div className="rounded border border-line bg-surface p-2">
                          <span className="text-ink-faint text-[10px] block">Filtered/Dropped</span>
                          <span className={`font-mono text-base font-semibold ${floodResult.packets_dropped > 0 ? 'text-ok' : 'text-ink-dim'}`}>
                            {floodResult.packets_dropped}
                          </span>
                        </div>
                        <div className="rounded border border-line bg-surface p-2">
                          <span className="text-ink-faint text-[10px] block">Availability</span>
                          <span className={`font-mono text-base font-semibold ${floodResult.simulated_availability_pct >= 80 ? 'text-ok' : floodResult.simulated_availability_pct >= 40 ? 'text-warn' : 'text-bad'}`}>
                            {floodResult.simulated_availability_pct.toFixed(0)}%
                          </span>
                        </div>
                      </div>

                      <div className={`flex items-start gap-2 rounded-md border p-2.5 ${floodResult.mitigated ? 'border-ok/30 bg-ok/10 text-ok' : 'border-bad/30 bg-bad/10 text-bad'}`}>
                        {floodResult.mitigated ? <CheckCircle2 size={16} className="shrink-0 mt-0.5" /> : <Flame size={16} className="shrink-0 mt-0.5" />}
                        <div>
                          <div className="font-semibold text-xs">
                            {floodResult.mitigated ? 'Firewall Mitigation Active' : 'Service Degradation Observed'}
                          </div>
                          <div className="text-[11px] leading-relaxed text-ink-dim mt-0.5">
                            {floodResult.mitigation_reason} (Modeled latency: {floodResult.simulated_latency_ms.toFixed(1)}ms)
                          </div>
                        </div>
                      </div>

                      <div className="rounded border border-line bg-surface p-2 font-mono text-[11px] space-y-1">
                        {floodResult.output.map((line, idx) => (
                          <div key={idx} className={line.startsWith(' - [') ? 'text-warn' : 'text-ink-dim'}>
                            {line}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Experiment Comparison Tab */}
        {mode === 'comparison' && (
          <div className="space-y-4">
            <div className="rounded-md border border-line bg-panel p-3 space-y-3">
              <div className="flex items-center justify-between border-b border-line-soft pb-2">
                <div>
                  <div className="font-semibold text-ink">3-Phase Empirical Comparison</div>
                  <div className="text-[11px] text-ink-faint">
                    Compares Baseline (normal traffic), Unmitigated Attack, and Defended Traffic under identical workload.
                  </div>
                </div>
                <Button
                  variant="primary"
                  size="sm"
                  onClick={handleRunComparison}
                  disabled={compLoading}
                  className="gap-1.5"
                >
                  <Scale size={13} />
                  {compLoading ? 'Testing 3 Phases...' : 'Run Experiment Comparison'}
                </Button>
              </div>

              {/* Experiment Configuration Parameters */}
              <div className="grid grid-cols-2 sm:grid-cols-5 gap-2 pt-1">
                <Field label="Attacker (Source)">
                  <select
                    value={effectiveFloodSource}
                    onChange={(e) => setFloodSourceId(e.target.value)}
                    className="w-full rounded border border-line bg-surface px-2 py-1 font-mono text-[11px]"
                  >
                    {pcs.map((d) => (
                      <option key={d.id} value={d.id}>
                        {d.name} ({d.interfaces[0]?.ipv4 || 'no IP'})
                      </option>
                    ))}
                  </select>
                </Field>

                <Field label="Target Host">
                  <select
                    value={effectiveFloodTarget}
                    onChange={(e) => setFloodTargetId(e.target.value)}
                    className="w-full rounded border border-line bg-surface px-2 py-1 font-mono text-[11px]"
                  >
                    {pcs
                      .filter((d) => d.id !== effectiveFloodSource)
                      .map((d) => (
                        <option key={d.id} value={d.id}>
                          {d.name} ({d.interfaces[0]?.ipv4 || 'no IP'})
                        </option>
                      ))}
                  </select>
                </Field>

                <Field label="Flood Type">
                  <select
                    value={floodType}
                    onChange={(e) => setFloodType(e.target.value as FloodType)}
                    className="w-full rounded border border-line bg-surface px-2 py-1 font-mono text-[11px]"
                  >
                    <option value="syn">TCP SYN Flood</option>
                    <option value="udp">UDP Flood</option>
                    <option value="icmp">ICMP Echo</option>
                  </select>
                </Field>

                <Field label="Burst Count">
                  <select
                    value={packetCount}
                    onChange={(e) => setPacketCount(Number(e.target.value))}
                    className="w-full rounded border border-line bg-surface px-2 py-1 font-mono text-[11px]"
                  >
                    <option value={15}>15 packets</option>
                    <option value={20}>20 packets</option>
                    <option value={25}>25 packets</option>
                    <option value={35}>35 packets</option>
                    <option value={50}>50 packets (Max)</option>
                  </select>
                </Field>

                <Field label="Target Port">
                  <TextInput
                    value={String(targetPort)}
                    onChange={(e) => setTargetPort(Number(e.target.value) || 80)}
                    placeholder="80"
                  />
                </Field>
              </div>
            </div>

            {!compResult ? (
              <Empty>
                Click <span className="font-semibold text-ink">Run Experiment Comparison</span> to record and contrast live before-and-after simulator data.
              </Empty>
            ) : (
              <div className="space-y-3">
                {/* 3-Column Metrics Table */}
                <div className="grid grid-cols-3 gap-2">
                  {[compResult.baseline, compResult.attack, compResult.mitigated].map((m, idx) => (
                    <div
                      key={idx}
                      className={`rounded-md border p-3 ${
                        idx === 0
                          ? 'border-line bg-panel'
                          : idx === 1
                          ? 'border-bad/30 bg-bad/5'
                          : 'border-ok/30 bg-ok/5'
                      }`}
                    >
                      <div className="flex items-center justify-between border-b border-line-soft pb-1.5">
                        <span className="font-semibold text-ink">{m.phase_name}</span>
                        <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${idx === 1 ? 'bg-bad/20 text-bad' : idx === 2 ? 'bg-ok/20 text-ok' : 'bg-line text-ink-dim'}`}>
                          {m.simulated_availability_pct.toFixed(0)}% Health
                        </span>
                      </div>
                      <div className="mt-2 space-y-1.5 text-[11px] font-mono">
                        <div className="flex justify-between">
                          <span className="text-ink-faint">Packets Sent:</span>
                          <span className="text-ink">{m.packets_sent}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-ink-faint">Delivered:</span>
                          <span className={idx === 1 ? 'text-bad' : 'text-ink'}>{m.packets_delivered}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-ink-faint">Filtered / Dropped:</span>
                          <span className={idx === 2 ? 'text-ok font-semibold' : 'text-ink'}>{m.packets_dropped}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-ink-faint">Latency (Simulated):</span>
                          <span className="text-ink">{m.simulated_latency_ms.toFixed(1)}ms</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-ink-faint">Alerts Triggered:</span>
                          <span className={m.alerts_triggered > 0 ? 'text-warn font-semibold' : 'text-ink-dim'}>
                            {m.alerts_triggered}
                          </span>
                        </div>
                      </div>
                      <div className="mt-2 text-[10px] text-ink-dim italic border-t border-line-soft pt-1.5">
                        {m.description}
                      </div>
                    </div>
                  ))}
                </div>

                {/* Analytical Explanation */}
                <div className="rounded-md border border-line bg-panel p-3">
                  <SectionTitle>Experiment Findings & Explanation</SectionTitle>
                  <p className="text-[11.5px] leading-relaxed text-ink-dim mt-1">
                    {compResult.explanation}
                  </p>
                  <div className="mt-2 flex gap-4 text-xs font-mono">
                    <span className="text-ok">✓ Packets Filtered: +{compResult.difference_summary.packets_filtered}</span>
                    <span className="text-ok">✓ Availability Recovered: +{compResult.difference_summary.availability_recovered_pct}%</span>
                    <span className="text-ok">✓ Latency Reduced: -{compResult.difference_summary.latency_reduction_ms}ms</span>
                  </div>
                </div>
              </div>
            )}
          </div>
        )}

        {/* Alerts Feed Tab */}
        {mode === 'alerts' && (
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-ink">
                Detected Threats & Explainable Rules ({storedAlerts.length})
              </span>
              {storedAlerts.length > 0 && (
                <Button size="sm" variant="ghost" onClick={clearAlerts} className="text-[11px] h-6 px-2">
                  Clear Alerts
                </Button>
              )}
            </div>

            {storedAlerts.length === 0 ? (
              <Empty>
                No active threats detected. Run a port scan (<span className="font-mono text-ink">nmap</span>), ARP spoofing scenario, or flood attack to trigger security rules.
              </Empty>
            ) : (
              <div className="space-y-2">
                {storedAlerts.map((alert) => (
                  <div key={alert.id} className="rounded-md border border-line bg-panel p-3 space-y-2">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase border ${SEVERITY_COLORS[alert.severity] || 'bg-line'}`}>
                          {alert.severity}
                        </span>
                        <span className="font-semibold text-ink font-mono text-[11px]">{alert.rule}</span>
                        <span className="text-ink-faint text-[10px]">({alert.category})</span>
                      </div>
                      <span className="text-ink-faint font-mono text-[10px]">{alert.source} → {alert.target}</span>
                    </div>

                    <div className="text-xs text-ink-dim">{alert.reason}</div>

                    {/* Evidence & Recommendation */}
                    <div className="rounded bg-surface p-2 text-[11px] font-mono border border-line-soft">
                      <div className="text-ink-faint text-[10px] uppercase font-bold tracking-wider mb-1">Observed Evidence</div>
                      <div className="text-ink-dim text-[10.5px]">
                        {Object.entries(alert.evidence).map(([k, v]) => (
                          <span key={k} className="mr-3 inline-block">
                            <span className="text-ink-faint">{k}:</span> {typeof v === 'object' ? JSON.stringify(v) : String(v)}
                          </span>
                        ))}
                      </div>
                    </div>

                    <div className="text-[11px] text-ok bg-ok/5 border border-ok/20 rounded px-2.5 py-1.5 flex items-start gap-1.5">
                      <ShieldCheck size={13} className="shrink-0 mt-0.5" />
                      <span><span className="font-semibold">Recommended Defense:</span> {alert.recommendation}</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
