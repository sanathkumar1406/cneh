# NetQuest Security Demonstrations — Step-by-Step Guide (`steps.md`)

This guide provides the exact click-by-click, command-by-command instructions to demonstrate the 4 core pillars of the **Network Security Learning Simulator** at [**http://localhost:5173**](http://localhost:5173).

---

## 1. Network Setup and Reconnaissance

### Objective:
Demonstrate topology layout verification, Layer 3 IP configuration, active subnet ARP host discovery, and Layer 4 TCP port scanning.

```text
PC-01 (192.168.1.10) ────[Cable]──── Switch-01 ────[Cable]──── Server-01 (192.168.1.50)
```

### Step-by-Step Actions:
1. **Verify Canvas Topology**:
   - Point out **`PC-01`**, **`Switch-01`**, and **`Server-01`** on the canvas.
   - Point out the **green link indicator dots** on the cables, confirming Layer 1/2 physical and data-link connectivity.
2. **Inspect IP Configuration (`ipconfig`)**:
   - In the bottom dock, click on the **`Terminal`** tab.
   - In the top-left dropdown, verify **`PC-01`** is selected.
   - In the input line, type and press Enter:
     ```text
     ipconfig
     ```
   - **What to highlight**: Show that `eth0` has IP `192.168.1.10` and Netmask `255.255.255.0`.
3. **Discover Active Subnet Hosts (`netdiscover`)**:
   - In the terminal, type and press Enter:
     ```text
     netdiscover
     ```
   - **What to highlight**: Show that `PC-01` broadcasts simulated ARP queries across `Switch-01`. It discovers:
     - `192.168.1.10` (`PC-01`, active local)
     - `192.168.1.50` (`Server-01`, active with MAC `02:00:5E:01:44:28`).
4. **Scan Server Ports (`nmap`)**:
   - In the terminal, type and press Enter:
     ```text
     nmap 192.168.1.50
     ```
   - **What to highlight**:
     - **`21/tcp (FTP)`** and **`443/tcp (HTTPS)`** are reported as **`open`** because the server sent back a TCP `SYN-ACK`.
     - Inactive ports (e.g. 22, 25, 80) return **`closed`** because the reachable host returned TCP `RST`.
     - If blocked by a firewall rule, the port state would report **`filtered`**.

---

## 2. Vulnerability Audit and Remediation Loop

### Objective:
Identify cleartext service vulnerabilities on the target, apply a defensive reconfiguration, and verify the remediation loop.

### Step-by-Step Actions:
1. **Run the Vulnerability Audit (`vulnscan`)**:
   - In `PC-01`'s terminal, type and press Enter:
     ```text
     vulnscan 192.168.1.50
     ```
   - **What to highlight**:
     - `EDU-VULN-001 [HIGH]`: Cleartext FTP Authentication Service Enabled on port 21. Explain that FTP sends credentials in plaintext, making it vulnerable to packet sniffing and MITM interception.
     - `EDU-VULN-004 [LOW]`: Missing Ingress Firewall Protection on Server-01.
2. **Apply the Remediation**:
   - Click on the **`Server-01`** device on the canvas.
   - In the **Config** panel on the right side of the screen, scroll down to **Services**.
   - **Toggle off / uncheck FTP (21)**.
3. **Verify the Fix (Closed-Loop Verification)**:
   - Go back to `PC-01`'s terminal in the bottom dock.
   - Re-run:
     ```text
     vulnscan 192.168.1.50
     ```
   - **What to highlight**: Point out that **`EDU-VULN-001` has disappeared!** The system dynamically confirms that the cleartext vulnerability has been remediated.

---

## 3. Flood Attack and Defense Comparison

### Objective:
Execute a controlled denial-of-service traffic flood, observe buffer queue saturation and packet loss, and demonstrate how firewall filtering restores target availability.

### Step-by-Step Actions:
1. **Open the Experiment Panel**:
   - In the bottom dock, click on the **`Security Lab`** tab.
   - At the top of the panel, click on **`Experiment Comparison`**.
2. **Configure Parameters**:
   - **Attacker Device**: `PC-01`
   - **Target Device**: `Server-01`
   - **Flood Type**: `TCP SYN Flood` (targeting port `80` or `21`)
   - **Packet Count**: `20`
3. **Execute the 3-Phase Experiment**:
   - Click the blue button: **`Execute 3-Phase Experiment`**.
4. **Analyze the Telemetry Comparison Table**:
   - Point out the 3 side-by-side empirical telemetry columns:
     - **Phase 1 (Baseline - Normal)**: **1 packet sent, 1 delivered, 0 dropped**, **100% health**, low latency (**1.5 ms**), 0 alerts. Normal, clean network connectivity before any attack.
     - **Phase 2 (Attack - Unmitigated)**: **25 packets sent, 25 delivered, 0 dropped/filtered**. High-rate SYN burst floods the target socket buffers without filtering. Service health drops drastically to **13%**, simulated latency climbs to **310.0 ms**, and a high-severity security alert is triggered.
     - **Phase 3 (Mitigated - Defense Applied)**: **25 packets sent, 25 dropped / filtered at the perimeter/host firewall, 0 delivered**. Firewall rules actively intercept and drop the flood bursts. Target service health is restored to **100%**, and latency drops back to **1.2 ms**.
   - **What to highlight**: Emphasize that these metrics are computed dynamically from simulated packet transmissions crossing virtual NIC interfaces, not from hardcoded numbers.

5. **Inspect the Generated Security Alerts**:
   - At the top of the Security Lab dock, click the **`Alerts (N)`** tab (e.g., `Alerts (1)`).
   - **What to highlight**:
     - Point to the **`TCP_SYN_FLOOD_DETECTED`** card.
     - Point out the **Observed Evidence**: `syn_packets: 25`, `threshold: 10`, `target: 192.168.1.50`, `sources: 192.168.1.10`.
     - Point out the **Recommended Defense**: *"Enable SYN cookies, restrict incoming TCP connection rates, or block attacking IP on the firewall."*

---

## 4. ARP Spoofing and Defense

### Objective:
Simulate Layer 2 Man-in-the-Middle cache poisoning, inspect the Security Event Engine's alert, apply a static ARP defense, and cleanly reset the scenario.

### Step-by-Step Actions:
1. **Launch the ARP Spoofing Scenario**:
   - In the **Security Lab** tab, click on **`Attack Scenarios`**.
   - Under **ARP Cache Poisoning**, select:
     - **Victim Device**: `PC-01`
     - **Legitimate Gateway**: `Server-01`
     - **Attacker Device**: `Server-01` (or another host on the subnet)
   - Click **`Launch ARP Spoof`**.
   - **What to highlight**: Show that the legitimate gateway MAC mapping in the victim's ARP cache was altered and replaced with the attacker's MAC.
2. **Inspect the Security Alert**:
   - In the Security Lab sub-tabs, click on **`Alerts`**.
   - **What to highlight**:
     - Point to the **CRITICAL** alert badge: `ARP_SPOOF_DETECTED`.
     - Show the forensic evidence: The IP's MAC binding abruptly altered.
     - Point out the actionable recommendation: *"Inoculate with static ARP binding."*
3. **Apply Static ARP Mapping Defense**:
   - Switch back to the **Terminal** tab on `PC-01`.
   - Type and press Enter:
     ```text
     arp -s 192.168.1.50 02:00:5E:01:44:28
     arp
     ```
   - **What to highlight**: Point to the **`static`** flag. In NetQuest, static entries are immutable and immune to dynamic forged ARP reply packets.
4. **Reset the Scenario**:
   - Go back to **Security Lab** → **Attack Scenarios**.
   - Click the **`Reset`** button.
   - **What to highlight**: Pristine ARP caches are restored without losing any canvas topology or device configuration.

---

## 5. Top Navigation Controls & Canvas Overview

Explain these controls whenever the evaluator asks about interface navigation:

- **`+ NETQUEST`**: Brand title and active topology name (e.g., *"Untitled network"* or custom topology).
- **`New`**: Clears the canvas to construct a brand-new network topology from scratch.
- **`Load`**: Opens a pre-saved topology configuration (e.g., Starter Lab, Three-Tier Subnet, DMZ Firewall).
- **`Save`**: Exports the current topology, device configurations, and firewall rules as a persistent JSON document.
- **`Level 2 · IPv4`**: Displays current challenge progression level and active protocol mode (Level 1 L2 Switching → Level 2 IPv4 Routing & Firewalls → Level 3 Advanced Security).
- **`100 XP`**: Experience points earned by successfully solving interactive networking and security challenges.
- **Canvas Zoom Controls (`+` / `-` / `Fit`)**: Zoom into device NICs, zoom out, or fit the entire topology to the viewport.
- **Minimap (Lower-Right)**: An interactive overview map enabling rapid panning across large, enterprise-scale network topologies.

---

## 6. End-to-End Project Presentation Sequence

When giving a full 5–10 minute demonstration to faculty or evaluators, follow this exact sequence:

1. **Build the Topology**:
   - Drag a **PC**, **Switch**, and **Web Server** (or **Firewall**) onto the canvas and connect them with cables.
2. **Configure Devices**:
   - Click each device to inspect IP addresses, subnet masks, default gateways, and listening services.
3. **Test Normal Connectivity**:
   - In `PC-01` terminal, run `ipconfig`, `netdiscover`, and `connect 192.168.1.50 80` (or `443`). Verify normal 100% delivery and <2ms latency.
4. **Simulate a Denial-of-Service Flood**:
   - Open **Security Lab** → **Experiment Comparison**. Launch a 25-packet SYN flood.
   - Show that target availability drops to **13%** and latency surges to **310ms**.
5. **Apply Defense & Compare**:
   - Show how defensive firewall filtering drops all 25 malicious packets, restoring health to **100%** and latency to **1.2ms**.
6. **Inspect Threat Alerts**:
   - Click the **Alerts** tab. Walk through `TCP_SYN_FLOOD_DETECTED`, observed packet counts, and remediation advice.
7. **Inspect Events & Packets**:
   - Open the **Events** and **Packets** tabs to show the exact packet frames (SYN flags, FIREWALL_DENY logs) proving the simulator's deterministic fidelity.

---

## Quick Presenter Reference Card

| Demonstration | Command / Action | What the Evaluator Sees |
| :--- | :--- | :--- |
| **1. Reconnaissance** | `ipconfig` → `netdiscover` → `nmap 192.168.1.50` | Active ARP discovery of subnet devices; open vs closed port enumeration. |
| **2. Vulnerability Audit** | `vulnscan 192.168.1.50` → Toggle FTP off → Re-scan | `EDU-VULN-001` detected, remediated on the server, and verified clean. |
| **3. Flood & Comparison** | Security Lab → `Experiment Comparison` → Run | Side-by-side table: Baseline (100% health, 0 dropped) vs Attack (13% health, 310ms lag) vs Mitigated (100% health, 25 dropped by firewall). |
| **4. Security Alerts** | Security Lab → `Alerts (N)` | Explainable rule trigger with observed evidence, severity badge, and mitigation advice. |
| **5. ARP Spoof & Defense** | Security Lab → `Launch ARP Spoof` → Check Alerts → `arp -s` | Cache poisoned, `ARP_SPOOF_DETECTED` alert triggered, static ARP defense applied, clean reset. |

