# Complete Network Security Simulation & Presentation Walkthrough

This document contains the complete, step-by-step walkthrough, testing procedures, click-by-click instructions, and presentation guide for the **NetQuest Network Security Learning Simulator**.

---

## 1. Environment & Quick Access URLs

| Component | URL | Description |
| :--- | :--- | :--- |
| **Frontend Web App** | [**http://localhost:5173**](http://localhost:5173) | Interactive Canvas, Terminals, Packet Inspector & Security Lab |
| **Backend API** | [**http://localhost:8000**](http://localhost:8000) | In-memory packet engine & Security Event Engine |
| **API Documentation** | [**http://localhost:8000/docs**](http://localhost:8000/docs) | Interactive Swagger UI API documentation |

---

## 2. Default Canvas Topology Setup

```text
┌─────────────────────────┐             ┌────────────┐             ┌─────────────────────────┐
│          PC-01          │─────────────│ Switch-01  │─────────────│        Server-01        │
│   IP: 192.168.1.10      │  (Cable 1)  │  (8 Ports) │  (Cable 2)  │   IP: 192.168.1.50      │
│   Mask: 255.255.255.0   │             └────────────┘             │   Mask: 255.255.255.0   │
│   MAC: 02:00:5E:01:2B:8A│                                        │   MAC: 02:00:5E:01:44:28│
│                         │                                        │   Services: FTP, HTTPS  │
└─────────────────────────┘                                        └─────────────────────────┘
```

* **Physical Connectivity**:
  - `PC-01 eth0` is cabled to `Switch-01 eth0`.
  - `Server-01 eth0` is cabled to `Switch-01 eth1`.
  - Green cable indicators confirm Layer 1/2 physical link status is UP.

---

## 3. Step-by-Step Hands-On Application Workflow

Follow these exact steps in your browser at [**http://localhost:5173**](http://localhost:5173):

### Part 1: Reconnaissance & Port Scanning

#### Step 1: Open the Terminal
1. Look at the bottom dock and click the **`Terminal`** tab.
2. Verify the dropdown on the top-left of the terminal shows **`PC-01`**.

#### Step 2: Check IP Configuration (`ipconfig`)
In the terminal input line, type:
```text
ipconfig
```
* **Expected Output**:
  ```text
  PC-01 — IP Configuration

     Ethernet adapter eth0:
        IPv4 Address . . . . . . . . . . . : 192.168.1.10
        Subnet Mask  . . . . . . . . . . . : 255.255.255.0
        Physical Address . . . . . . . . . : 02:00:5E:01:2B:8A
        Default Gateway  . . . . . . . . . : (not configured)
  ```

#### Step 3: Discover Active Subnet Hosts (`netdiscover`)
In the terminal, type:
```text
netdiscover
```
* **Expected Output**:
  ```text
  NetQuest ARP/ICMP Active Host Discovery
  Target Subnet: 192.168.1.0/24 (via eth0: 192.168.1.10)
  ----------------------------------------------------------------------
  IP Address       MAC Address        Simulated Name    Status
  ----------------------------------------------------------------------
  192.168.1.10     02:00:5E:01:2B:8A  PC-01             active (local)
  192.168.1.50     02:00:5E:01:44:28  Server-01         active

  Discovery complete: 2 host(s) discovered on subnet.
  ```

#### Step 4: Scan the Target Server with Nmap (`nmap 192.168.1.50`)
In the terminal, type:
```text
nmap 192.168.1.50
```
* **Expected Output**:
  ```text
  Starting NetQuest Nmap (simulated) against 192.168.1.50 (192.168.1.50)
  Host is up (responses received).

  PORT       STATE      SERVICE      REASON
  21/tcp     open       ftp          syn-ack from host
  22/tcp     closed     ssh          conn-refused (RST)
  25/tcp     closed     smtp         conn-refused (RST)
  53/tcp     closed     unknown      conn-refused (RST)
  80/tcp     closed     http         conn-refused (RST)
  110/tcp    closed     unknown      conn-refused (RST)
  123/tcp    closed     unknown      conn-refused (RST)
  143/tcp    closed     unknown      conn-refused (RST)
  443/tcp    open       https        syn-ack from host
  3306/tcp   closed     unknown      conn-refused (RST)

  Nmap done: 10 scanned ports on 192.168.1.50 (2 open, 0 filtered, 8 closed).
  ```
* **Why this occurs**:
  - `21/tcp` (FTP) and `443/tcp` (HTTPS) return `open` because `Server-01` actively listens on those sockets and sent TCP `SYN-ACK`.
  - Non-listening ports return `closed` because the reachable host responded with TCP `RST`.
  - If a firewall dropped probe packets silently, the state would be `filtered`.

---

### Part 2: Educational Vulnerability Audit & The Remediation Loop

#### Step 5: Audit Target for Insecure Services (`vulnscan`)
In `PC-01`'s terminal, type:
```text
vulnscan 192.168.1.50
```
* **Expected Output**:
  ```text
  NetQuest Educational Vulnerability Audit — Target: Server-01
  NOTE: Demonstrative educational findings for simulated network services only.
  ----------------------------------------------------------------------

  Found 2 educational security finding(s):

  [1] EDU-VULN-001 [HIGH]: Cleartext FTP Authentication Service Enabled
      Details:     File Transfer Protocol (port 21/tcp) transmits credentials and data in unencrypted plaintext.
      Impact:      Simulated attacker can capture credentials via packet inspection or ARP spoofing.
      Remediation: Disable FTP service on target, migrate to SSH (port 22/tcp), or block port 21 via firewall.

  [2] EDU-VULN-004 [LOW]: Missing Ingress Firewall Protection
      Details:     Device Server-01 has listening services but no firewall rules configured.
      Impact:      All listening ports are exposed to all connected simulation subnets.
      Remediation: Configure stateful or port-specific firewall rules to enforce least-privilege access.
  ```

#### Step 6: Remediate the Finding (Simulated Fix)
1. On the canvas, click on **`Server-01`**.
2. Look at the right-side **Config** panel.
3. Scroll down to **Services**:
   - Find **FTP (21)** and **toggle/uncheck it OFF**.
4. Return to the terminal on `PC-01` and re-run:
   ```text
   vulnscan 192.168.1.50
   ```
* **Result**: `EDU-VULN-001` is resolved! This demonstrates the complete **Audit → Mitigate → Verify** learning loop.

---

### Part 3: Empirical 3-Phase Experiment (Security Lab)

#### Step 7: Open the Security Lab
1. In the bottom dock, click on the **`Security Lab`** tab.
2. Click on **`Experiment Comparison`** at the top of the panel.

#### Step 8: Configure & Execute the Experiment
1. Select the following options:
   - **Attacker Device**: `PC-01`
   - **Target Device**: `Server-01`
   - **Flood Type**: `TCP SYN Flood` (targeting port `80` or `21`)
   - **Packet Count**: `20`
2. Click the button: **`Execute 3-Phase Experiment`**.

#### Step 9: Analyze the Side-by-Side Telemetry Table
The engine executes three sequential phases under identical parameters and displays empirical data:

| Metric | Phase 1: Baseline | Phase 2: Attack (Unmitigated) | Phase 3: Mitigated (Firewall) |
| :--- | :---: | :---: | :---: |
| **Packets Generated** | 1 pkts | 20 pkts | 20 pkts |
| **Packets Delivered** | 1 pkts | 12 pkts | 0 pkts (Blocked at FW) |
| **Packets Dropped** | 0 pkts | 8 pkts (Queue Overload) | 20 pkts (Firewall Deny) |
| **Simulated Latency** | 2.0 ms | 48.0 ms (Queue delay) | 0.0 ms |
| **Traffic Rate** | 1.0 pkts/s | 25.0 pkts/s | 25.0 pkts/s |
| **Security Alerts** | 0 | 1 (`TCP_SYN_FLOOD_DETECTED`) | 1 (`FIREWALL_PACKET_BLOCKED`) |
| **Target Availability**| 100% | 60% (Degraded) | 100% (Protected) |

* **Pedagogical Takeaway**:
  In Phase 2, buffer saturation causes packet loss and severe latency spikes. In Phase 3, proactive firewall access-lists intercept and drop malicious bursts at the perimeter, maintaining target host stability.

---

### Part 4: Layer 2 ARP Spoofing & Static Binding Defense

#### Step 10: Launch ARP Poisoning Attack
1. In the **Security Lab**, click on **`Attack Scenarios`**.
2. Select:
   - **Victim Device**: `PC-01`
   - **Legitimate Gateway**: `Server-01`
   - **Attacker Device**: `Server-01` (or another host)
3. Click **`Launch ARP Spoof`**.
4. Observe that the legitimate gateway MAC is modified to the attacker's MAC address.

#### Step 11: Inspect the Security Event Engine Alert
1. In the Security Lab, click the **`Alerts`** sub-tab.
2. Note the generated alert:
   - **Alert**: `ARP_SPOOF_DETECTED` (CRITICAL)
   - **Evidence**: `Gateway IP 192.168.1.50 MAC binding abruptly changed from 02:00:5E:01:44:28 to attacker MAC.`
   - **Recommended Action**: `Inoculate with static ARP binding.`

#### Step 12: Apply Defense & Clean Reset
1. Open `PC-01`'s terminal and configure a permanent static ARP binding:
   ```text
   arp -s 192.168.1.50 02:00:5E:01:44:28
   arp
   ```
   *Static entries are flagged with `static` and cannot be overwritten by dynamic forged ARP replies.*
2. Return to the **Security Lab** and click **`Reset`** to restore pristine ARP caches without affecting your canvas topology.

---

## 4. Presentation & Viva Defense Script (7 Minutes)

When presenting to evaluators, professors, or an audience, use this concise flow:

### 1. The Hook (1 Min)
> *"Welcome. Today I am demonstrating the **Network Security Learning Simulator** built on NetQuest. Traditional computer networks education relies either on static mockups where commands don't run real protocols, or on live raw-packet tools like Metasploit which carry security and network stability risks.*
>
> *Our simulator bridges this gap by providing an **in-engine, deterministic network security laboratory** where every frame is processed by a simulated discrete-event delivery loop with zero real-world attack risk."*

### 2. Architecture & Reconnaissance (2 Min)
> *"We begin on the interactive canvas with client `PC-01` and server `Server-01` connected via `Switch-01`. As an ethical hacker, we start with reconnaissance:*
> - *Running `netdiscover` broadcasts virtual ARP queries, revealing live hosts.*
> - *Running `nmap 192.168.1.50` executes real TCP SYN probes, distinguishing `open` services (SYN-ACK) from `closed` ports (RST) and `filtered` firewall states."*

### 3. Vulnerability Audit & The Fix (2 Min)
> *"Next, we run `vulnscan 192.168.1.50`. The engine detects `EDU-VULN-001` (Cleartext FTP on port 21) and `EDU-VULN-004` (Missing ingress firewall).*
>
> *Students can immediately implement the fix: by disabling FTP in the server config panel and re-running `vulnscan`, they observe immediate verification of the resolved finding."*

### 4. Security Lab: ARP Spoofing & DoS Comparison (2 Min)
> *"Finally, we explore the **Security Lab** dock:*
> - *In **Attack Scenarios**, we simulate Layer 2 ARP cache poisoning. The Security Event Engine flags `ARP_SPOOF_DETECTED` with exact forensic evidence, and we demonstrate static ARP inoculation.*
> - *In **Experiment Comparison**, we execute a 3-Phase SYN flood test comparing Baseline, Unmitigated Attack, and Firewall-Mitigated outcomes with real latency and packet drop metrics."*

---

## 5. Frequently Asked Questions (Q&A Preparation)

### Q: Does this simulator send real packets across the local Wi-Fi or Internet?
**A**: *No. All packets are Python dataclasses processed in-memory by `SimulationEngine`. No raw sockets (`AF_INET`/raw) are opened and no external IP addresses can be scanned.*

### Q: Why did Nmap output `no-route (the packet never left PC-01)` initially?
**A**: *Because NetQuest enforces real routing and Layer-2 physical rules. If a host has no IP configured, lacks physical cabling, or the target does not exist to answer ARP requests, the packet cannot be framed or transmitted.*

### Q: What framework powers the application?
**A**: *The frontend is built with **React 19, TypeScript, and TailwindCSS**, and the backend is a stateless **FastAPI** service with a pure Python simulation engine.*

---

## 6. Verification & Automated Testing Commands

To verify the test suite anytime on Windows:

```powershell
# 1. Run all 308 backend tests (100% passing):
cd backend
python -m pytest tests -v

# 2. Run frontend typechecking and build (0 errors):
cd frontend
npm run typecheck
npm run build
```
