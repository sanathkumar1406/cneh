# Network Security Learning Simulator

An educational extension to NetQuest transforming the interactive packet simulation environment into a **Network Security Laboratory** for Computer Networks and Ethical Hacking curricula.

---

## 1. Overview & Educational Philosophy

The Network Security Learning Simulator allows students and educators to study network reconnaissance, protocol vulnerabilities, denial-of-service dynamics, and defensive mitigations in a deterministic, observable environment.

**Mandatory Safety Principle**:
This simulator operates **strictly within simulated virtual network state**. It never binds raw host sockets, transmits attack packets across real interfaces, scans external subnets, or contacts third-party services. All packet generation, forwarding, detection, and mitigation occur inside the in-memory `SimulationEngine`.

---

## 2. Retained Core Networking Features

The simulator preserves all underlying NetQuest capabilities:
- **Topology Canvas**: Drag-and-drop PCs, laptops, servers, switches, routers, and firewalls.
- **Addressing & Subnets**: Full IPv4 addressing, netmasks, broadcast domains, default gateways.
- **Protocol Stack**: Ethernet framing, MAC learning tables, ARP caching, ICMP echo/errors, TCP 3-way handshake simulation, UDP transport, DNS resolution, DHCP leasing.
- **Stateful Firewall & NAT**: Access-lists with default allow/deny, state tracking on return legs, and outside interface NAT translations.
- **Hop-by-Hop Packet Inspector**: Full visibility into headers, payload types, and hop-by-hop forwarding decisions across physical links.

---

## 3. Implemented Security Modules

### Feature 1: Host Discovery (`netdiscover`)
- **Simulated Reconnaissance**: Scans the local subnet or a specified CIDR range (e.g. `netdiscover -r 192.168.1.0/24`) by issuing simulated ARP queries or ICMP discovery probes across connected switches.
- **Device State**: Reports IP address, MAC address, simulated hostname, and status (`active`, `unreachable`).
- **Terminal Integration**:
  ```text
  netdiscover
  netdiscover -r 192.168.1.0/24
  ```

### Feature 2: Simulated Port Scanning (`nmap`)
- **Targeted Port Enumeration**: Probes simulated TCP/UDP services on target devices.
- **Port State Accuracy**:
  - `open`: Target device actively runs the listening service and firewall permits traffic.
  - `closed`: Target host is reachable but service is not listening (responds with simulated TCP RST).
  - `filtered`: Inline firewall or host access list denies/drops probe packet silently.
- **Service Mapping**: Inspects well-known ports including 21 (FTP), 22 (SSH), 25 (SMTP), 53 (DNS), 80 (HTTP), 110 (POP3), 123 (NTP), 143 (IMAP), 443 (HTTPS), 3306 (MySQL).
- **Terminal Integration**:
  ```text
  nmap 192.168.1.50
  nmap -p 80,443,21,22 web.netquest.local
  nmap -p 20-25 192.168.1.1
  ```

### Feature 3: Static ARP Defense & ARP Spoofing Simulation
- **Static ARP Table Entries**: Added `arp -s <ip> <mac>` command to host terminals and persistent static ARP bindings in `DeviceRuntimeSchema`.
- **Cache Poison Protection**: Dynamic ARP replies cannot overwrite static entries (`static_arp`).
- **ARP Spoofing Scenario**:
  - Educational scenario configuring Victim, Gateway, and Attacker on a shared switch/broadcast domain.
  - Generates forged gratuitous ARP replies associating the Gateway's IP with the Attacker's MAC.
  - Visualizes legitimate mapping before the attack, modified mapping after poisoning, and subsequent traffic diversion.
  - **Explainable Detection**: Flags `ARP_SPOOF_DETECTED` (or `GATEWAY_MAC_CHANGED`) when an IP's MAC binding abruptly alters or contradicts known mappings.
  - **Mitigation & Reset**: Apply static ARP bindings to inoculate the victim; one-click reset restores pristine ARP caches.

### Feature 4: Controlled Flood Simulation (SYN, UDP, ICMP)
- **Synthetic Traffic Generation**: Simulates high-rate traffic bursts bounded by safe parameter limits (default 5–20 packets, configurable rate 10–50 pkts/sec).
- **Queuing & Overload Modeling**:
  - Measures target device queue pressure, simulated service latency increases, and packet drop percentage under stress.
- **Attack Variations**:
  - **TCP SYN Flood**: Half-open connection pressure targeting open TCP ports (e.g. 80).
  - **ICMP Echo Flood**: High-frequency ping flood exhausting target interface processing.
  - **UDP Flood**: High-volume UDP datagrams directed at diagnostic/service ports.
- **Detection Rules**:
  - `TCP_SYN_FLOOD_DETECTED`: Triggered when SYN packet frequency exceeds threshold per time window.
  - `ICMP_FLOOD_DETECTED`: Triggered on excessive echo-request rate.
  - `UDP_FLOOD_DETECTED`: Triggered on high-rate UDP streams.

### Feature 5: Security Event Engine
- **Deterministic Rule Evaluation**: Inspects packets passing through `SimulationEngine` delivery loops and terminal commands.
- **Standardized Alert Schema**:
  - `id`: Unique event identifier.
  - `category`: `reconnaissance`, `spoofing`, `dos`, `firewall`, `policy`.
  - `severity`: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.
  - `source_id`, `target_id`, `protocol`, `port`.
  - `reason`: Plain-language explanation of what triggered the detection.
  - `evidence`: Specific metric (e.g., `observed_rate: 35.0 pkts/s`, `threshold: 10.0 pkts/s`).
  - `recommended_action`: Actionable security remediation guidance.
- **Alert Deduplication**: Suppresses redundant alert storms during continuous flood events.

### Feature 6: Empirical 3-Phase Experiment Comparison
- **Repeatable Scientific Methodology**:
  1. **Phase 1 (Baseline)**: Normal background traffic between source and target.
  2. **Phase 2 (Attack)**: Identical scenario parameters executing attack flood/spoof without defenses.
  3. **Phase 3 (Mitigated)**: Same attack scenario rerun with firewall rules or static ARP bindings active.
- **Measured Metrics**:
  - Total packets generated
  - Packets successfully delivered
  - Packets dropped
  - Simulated latency (ms)
  - Simulated traffic rate (pkts/sec)
  - Security alerts triggered
  - Simulated service availability (%)
- **Visual Diff**: Displays a comprehensive before-and-after comparison table explaining the defense mechanism's efficacy.

### Feature 7: Educational Vulnerability Audit (`vulnscan`)
- **Baseline Service & Policy Audit**: Audits simulated hosts or remote servers against educational configuration baselines:
  - `EDU-VULN-001` (HIGH): Cleartext FTP service listening on port 21.
  - `EDU-VULN-002` (MEDIUM): Unencrypted HTTP service on port 80 without HTTPS.
  - `EDU-VULN-003` (LOW): Unauthenticated SMTP relay on port 25.
  - `EDU-VULN-004` (LOW): Device with active services but zero firewall access-lists.
- **Remediation Loop**: Students can apply fixes (disable service via device config or add firewall rules) and rerun `vulnscan` to verify resolution.

---

## 4. Architecture & Data Flow

```text
 ┌────────────────────────────────────────────────────────┐
 │                      React Frontend                    │
 │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
 │  │ Canvas / Lab │  │ Terminal     │  │ SecurityLab  │  │
 │  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘  │
 └─────────┼─────────────────┼─────────────────┼──────────┘
           │                 │                 │
           ▼ HTTP POST       ▼ HTTP POST       ▼ HTTP POST
 ┌────────────────────────────────────────────────────────┐
 │                   FastAPI Backend                      │
 │  /simulate/command        /scenario/arp-spoof          │
 │  /simulate/connection     /scenario/flood              │
 │                           /experiment/compare          │
 └─────────────────────────┬──────────────────────────────┘
                           │
                           ▼
 ┌────────────────────────────────────────────────────────┐
 │                  Simulation Engine                     │
 │  - Delivery Loop       - Security Event Engine         │
 │  - Packet Routing      - Rule Deduplication            │
 │  - ARP / MAC Tables    - Queue & Overload Modeling     │
 └────────────────────────────────────────────────────────┘
```

The frontend maintains the master `TopologyDocument` and transfers it statelessly with every simulation request. The backend deserializes the topology into memory, executes all packet delivery loops, evaluates security rules, updates device runtime state (ARP tables, routing tables), and returns the results.

---

## 5. Quickstart & Verification (Windows / Linux / macOS)

### Backend Setup
```powershell
# In Windows PowerShell:
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt

# Run backend API server on port 8000
uvicorn app.main:app --reload --port 8000
```

### Frontend Setup
```powershell
# In a new PowerShell window:
cd frontend
npm install
npm run dev
# Open http://localhost:5173
```

### Automated Testing
```powershell
# Run the complete test suite (308 tests passing):
cd backend
python -m pytest tests -v

# Run frontend typecheck and production build:
cd frontend
npm run typecheck
npm run build
```

---

## 6. Security Scenarios Walkthrough

### Scenario A: Subnet Reconnaissance and Port Scanning
1. In the simulation, open a PC terminal (e.g. `PC-01`).
2. Type `netdiscover` to identify connected devices on the local subnet.
3. Type `nmap <target-ip>` to enumerate services (e.g. ports 21, 22, 80, 443).
4. Run `vulnscan` to view educational security findings.

### Scenario B: ARP Spoofing Demonstration
1. Open the **Security Lab** tab in the bottom dock.
2. Under **Scenarios**, select **ARP Cache Poisoning**.
3. Choose the Victim, Gateway, and Attacker devices.
4. Click **Launch ARP Spoof Scenario**.
5. Observe the poisoned ARP mapping and generated `ARP_SPOOF_DETECTED` alert.
6. Open the Victim's terminal and configure `arp -s <gateway-ip> <legitimate-mac>`.
7. Re-run or test connection: the forged packets fail to poison the static entry.
8. Click **Reset Scenario** to restore clean ARP state.

### Scenario C: DoS Flood & Firewall Mitigation Experiment
1. In **Security Lab**, switch to the **Experiment Comparison** tab.
2. Select an Attacker, Target, flood type (e.g. `TCP SYN Flood`), and packet count (e.g. 20 packets).
3. Click **Execute 3-Phase Experiment**.
4. The engine records:
   - Baseline normal traffic
   - Attack traffic (high drop rate, elevated latency, alerts)
   - Mitigated traffic (firewall blocks attack packets, restoring service health)
5. Review the side-by-side metric comparison table and summary.
