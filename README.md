# PEER'S SIEM Log Analyzer: Multi-Source Telemetry Parser & Anomaly Correlation Engine

[![Python Version](https://img.shields.io/badge/Python-3.10%2B-blue.svg?style=for-the-badge&logo=python)](https://www.python.org/)
[![Security Standard](https://img.shields.io/badge/NIST-SP%20800--61%20Rev.2-red.svg?style=for-the-badge&logo=nist)](https://csrc.nist.gov/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE%20ATT%26CK-T1110%20%7C%20T1078%20%7C%20T1114.003-orange.svg?style=for-the-badge)](https://attack.mitre.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)
[![Unit Tests](https://img.shields.io/badge/Unit%20Tests-6%2F6%20Passed-brightgreen.svg?style=for-the-badge)](tests/test_siem_analyzer.py)
[![Platform](https://img.shields.io/badge/Platform-Kali%20Linux%20%7C%20Windows-black.svg?style=for-the-badge&logo=linux)](https://www.kali.org/)

> **Day 13 Cybersecurity Internship Deliverable**  
> **Company:** Sqrock IT Solutions  
> **Specialization:** Social Engineering & Authentication Security Simulations Using Python  
> **Developer:** Mohammed Peer Siddiqui  
> **Repository:** [https://github.com/MdPeerSiddiqui/SIEM-Log-Analyzer](https://github.com/MdPeerSiddiqui/SIEM-Log-Analyzer)

---

## 📌 Executive Overview

Modern Security Operations Centers (SOCs) face severe alert fatigue caused by un-correlated, fragmented log streams. Adversaries exploit these blind spots by executing multi-stage attack campaigns: credential brute forcing or password spraying, authenticating via geographically dispersed VPN relays, and immediately configuring covert persistence mechanisms (such as automated mailbox forwarding rules). In isolation, these events appear low-priority or benign; correlated across time and identity, they represent a critical breach in progress.

**PEER'S SIEM Log Analyzer v2.0** is an enterprise-grade correlation and threat detection engine developed for **Day 13** of the Sqrock IT Solutions Cybersecurity Internship. It parses heterogeneous telemetry feeds (Windows Event IDs 4624/4625, Exchange PowerShell cmdlets, FortiGate VPN authentication sessions, and Squid proxy feeds), normalizes them into unified event schemas, and applies temporal windowing and geodesic mathematical algorithms to detect high-confidence threats in real time.

```
+========================================================================+
|             PEER'S SIEM LOG ANALYZER v2.0 - ARCHITECTURE               |
+========================================================================+
|                                                                        |
|  [Disparate Telemetry Feeds]                                           |
|   - Windows Security (Event 4624, 4625)                                |
|   - MS Exchange / M365 (New-InboxRule, rule=forward_all)               |
|   - FortiGate VPN Gateways (Auth, Lat/Lon Geolocation)                 |
|   - Squid HTTP Web Proxy (403, SQLi Lures)                             |
|          |                                                             |
|          v                                                             |
|  [Unified Schema Normalization Engine]                                 |
|     - Timestamp harmonization (UTC), identity extraction, IP indexing  |
|          |                                                             |
|          v                                                             |
|  [Multi-Dimensional Behavioral Correlation Core]                       |
|   +------------------------------------------------------------------+ |
|   | Rule 1: Brute Force & Password Spraying (T1110)                  | |
|   | Rule 2: Suspicious Mailbox Auto-Forwarding Exfiltration (T1114)  | |
|   | Rule 3: Geodesic Haversine Impossible Travel Velocity (T1078.004)| |
|   | Rule 4: End-to-End Account Takeover (ATO) Kill Chain Synthesis   | |
|   +------------------------------------------------------------------+ |
|          |                                                             |
|          +-----------------------------+-------------------------------+
|          |                             |                               |
|          v                             v                               v
|  [Triage Console / CLI]         [JSON Telemetry Audit]       [Executive 7-Page PDF]
|   - Prioritized MITRE Alerts    - alerts/siem_alert_report   - Day13_SIEM_Report
+========================================================================+
```

---

## 🎯 Key Correlation Rules & Behavioral Analytics

1. **Rule 1: Brute Force & Password Spray Detection (`T1110.001`):**
   - Correlates Windows Event ID 4625 (Logon Failure) across configurable sliding windows.
   - Detects clusters of $\ge 3$ failed authentication attempts from a single source IP or targeting a specific user entity.

2. **Rule 2: Malicious Inbox Auto-Forwarding Tripwire (`T1114.003` / `T1020`):**
   - Monitors Exchange PowerShell management cmdlets (`New-InboxRule`, `Set-Mailbox`).
   - Flags suspicious rules redirecting internal communications to external adversary drop addresses (`rule=forward_all`).

3. **Rule 3: Great-Circle Impossible Travel Velocity Engine (`T1078.004`):**
   - Implements the spherical **Haversine formula** to measure geodesic distance ($km$) between consecutive logins for identical user credentials across global VPN endpoints.
   - Computes physical travel velocity ($km/h$) and raises a CRITICAL alert if speed exceeds commercial aviation thresholds ($800\text{ km/h}$).

4. **Rule 4: Multi-Stage Account Takeover (ATO) Chain Synthesis:**
   - Synthesizes disparate events into a single unified kill chain: Multiple failed logins $\rightarrow$ Successful logon from external IP $\rightarrow$ Mailbox forwarding rule creation.
   - Eliminates alert fatigue by providing Level 2 SOC analysts with a single cohesive incident dossier.

---

## 🔬 Mathematical Formulation: Impossible Travel Geodesics

The engine computes the spherical distance $d$ between two coordinates $(\phi_1, \lambda_1)$ and $(\phi_2, \lambda_2)$ where $\phi$ is latitude and $\lambda$ is longitude using the Haversine equation:

$$a = \sin^2\left(\frac{\Delta \phi}{2}\right) + \cos(\phi_1) \cdot \cos(\phi_2) \cdot \sin^2\left(\frac{\Delta \lambda}{2}\right)$$

$$c = 2 \cdot \text{atan2}\left(\sqrt{a}, \sqrt{1 - a}\right)$$

$$d = R \cdot c \quad (\text{where Earth radius } R = 6,371.0\text{ km})$$

The required physical velocity $v$ across the elapsed time interval $\Delta t = t_2 - t_1$ (in hours) is:

$$v = \frac{d}{\Delta t}$$

$$\text{Trigger Condition: } v > 800.0\text{ km/h} \quad \wedge \quad d > 500\text{ km} \implies \text{CRITICAL ALERT}$$

In our empirical evaluation, user `m.siddiqui` authenticated from New York ($40.71^\circ\text{ N}, 74.01^\circ\text{ W}$) to Tokyo ($35.68^\circ\text{ N}, 139.65^\circ\text{ E}$) in $35.4$ minutes ($\Delta t = 0.59\text{ h}$). Distance $d = 10,849.32\text{ km}$, yielding a velocity of **$18,388.68\text{ km/h}$** ($22.9\times$ commercial jet speed), triggering an immediate automated containment workflow.

---

## 📊 Correlated Alert Summary

| Alert ID | Severity | MITRE ATT&CK | Affected Entity | Core Detection Finding |
|:---|:---:|:---|:---|:---|
| **ALRT-ATO-j.smith** | `CRITICAL` | `T1078 / T1110 / T1114.003` | User: `j.smith` | Multi-stage ATO: 5 failed logins $\rightarrow$ Success $\rightarrow$ External forward rule. |
| **ALRT-EXCH-081824** | `CRITICAL` | `T1114.003` (Collection) | Mailbox: `j.smith` | Auto-forward rule to `attacker-drop@proton.me` (`rule=forward_all`). |
| **ALRT-TRAVEL-m_siddiqui** | `CRITICAL` | `T1078.004` (Defense Evasion) | User: `m.siddiqui` | Impossible Travel: NY to Tokyo in 35 min ($18,388.68\text{ km/h}$). |
| **ALRT-BF-198_51_100_42** | `HIGH` | `T1110.001` (Brute Force) | IP: `198.51.100.42` | 5 authentication failures against `j.smith` within 93 seconds. |

---

## 🛠️ Project Structure

```
Day13_SIEM_Log_Analysis/
├── alerts/
│   ├── siem_alert_report.json          # Machine-readable structured alert telemetry
│   └── siem_triage_summary.txt         # SOC analyst executive triage briefing
├── logs/
│   └── security_events.log             # Multi-source Windows, Exchange, VPN & Proxy logs
├── reports/
│   ├── screenshots/                    # Programmatically generated Kali terminal proofs
│   │   ├── 01_kali_init_banner.png
│   │   ├── 02_master_menu.png
│   │   ├── 03_event_ingestion_parsing.png
│   │   ├── 04_threat_correlation_alerts.png
│   │   ├── 05_impossible_travel_detail.png
│   │   └── 06_github_repo_overview.png
│   └── Day13_SIEM_Log_Analysis_Report_Sqrock_MdPeerSiddiqui.pdf # 7-page executive report
├── scripts/
│   ├── generate_terminal_screens.py    # Headless PIL terminal visual generator
│   └── generate_day13_pdf.py           # Multi-page ReportLab PDF compiler
├── tests/
│   └── test_siem_analyzer.py           # 6 automated PyUnit test cases
├── siem_analyzer.py                    # Multi-source log correlation & threat engine
├── requirements.txt                    # Project dependencies
├── LICENSE                             # MIT Open Source License
└── README.md                           # Master documentation
```

---

## 🚀 Quickstart Guide

### 1. Prerequisites & Environment Setup
Clone the repository and install dependencies:

```bash
git clone https://github.com/MdPeerSiddiqui/SIEM-Log-Analyzer.git
cd SIEM-Log-Analyzer
python -m venv .venv
source .venv/bin/activate  # On Windows: .\.venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Run Automated Unit Tests
Verify all parsing rules, Haversine math, and correlation logic:

```bash
python -m unittest tests/test_siem_analyzer.py -v
```

Output:
```
test_account_takeover_chain_and_export ... ok
test_brute_force_detection ... ok
test_impossible_travel_haversine ... ok
test_log_ingestion ... ok
test_multi_source_parsing ... ok
test_suspicious_forwarding_rules ... ok

----------------------------------------------------------------------
Ran 6 tests in 0.023s

OK
```

### 3. Launch Interactive Command Line Interface
Launch the interactive SIEM console:

```bash
python siem_analyzer.py
```

Console options:
- `[1] Ingest & Parse Multi-Source Security Logs` - Reads logs and normalizes into structured event objects.
- `[2] Run Full Correlation Engine (Detect All Threats)` - Executes all 4 behavioral analytics rules and prints alerts.
- `[3] Analyze Impossible Travel Incidents` - Deep dive into geolocation coordinates, time deltas, and velocity.
- `[4] Inspect Compromised Mailbox Forwarding Rules` - Pinpoints unauthorized auto-forwarding parameters.
- `[5] Export SIEM Audit Reports` - Generates `alerts/siem_alert_report.json` and `alerts/siem_triage_summary.txt`.
- `[6] Exit Suite`

---

## 📜 Standards & Compliance Alignment

| Standard / Framework | Control Identifier | Application in Suite |
|:---|:---|:---|
| **NIST SP 800-61 Rev. 2** | §3.2 Detection & Analysis | Multi-source log correlation, anomaly identification, and triage reporting. |
| **CIS Controls v8** | Control 8 (Audit Log Management) | Centralized collection, analysis, and alerting on access control logs. |
| **MITRE ATT&CK** | T1110, T1078, T1114.003 | Detection of Password Spraying, Valid Accounts, and Email Forwarding Rules. |
| **ISO/IEC 27001:2022** | Control A.8.15 (Logging) & A.8.16 (Monitoring) | Monitoring anomalous events and triggering incident response containment. |

---

## ⚖️ License
Distributed under the MIT License. See [LICENSE](LICENSE) for full legal text.

**Author:** Mohammed Peer Siddiqui  
**Internship:** Sqrock IT Solutions Cybersecurity Internship Phase 1 (Day 13)
