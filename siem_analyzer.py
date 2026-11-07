#!/usr/bin/env python3
"""
PEER'S SIEM Log Analyzer - Security Information & Event Management Correlation Engine
Sqrock IT Solutions - Cybersecurity Internship Phase 1 (Day 13)
Author: Mohammed Peer Siddiqui
License: MIT
"""

import os
import sys
import re
import json
import math
from datetime import datetime
from collections import defaultdict
from colorama import init, Fore, Style

init(autoreset=True)

# Standard Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOGS_DIR = os.path.join(BASE_DIR, "logs")
ALERTS_DIR = os.path.join(BASE_DIR, "alerts")
DEFAULT_LOG_PATH = os.path.join(LOGS_DIR, "security_events.log")
JSON_REPORT_PATH = os.path.join(ALERTS_DIR, "siem_alert_report.json")
TXT_REPORT_PATH = os.path.join(ALERTS_DIR, "siem_triage_summary.txt")

os.makedirs(LOGS_DIR, exist_ok=True)
os.makedirs(ALERTS_DIR, exist_ok=True)


def haversine_distance(lat1, lon1, lat2, lon2):
    """Calculate the great-circle distance between two coordinates in kilometers."""
    R = 6371.0  # Earth's radius in km
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = (math.sin(dlat / 2) ** 2 +
         math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) *
         math.sin(dlon / 2) ** 2)
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    return R * c


class SIEMLogAnalyzer:
    """Enterprise SIEM log correlation and threat detection engine."""

    def __init__(self, log_path=DEFAULT_LOG_PATH):
        self.log_path = log_path
        self.raw_events = []
        self.parsed_events = []
        self.alerts = []

    def load_logs(self, custom_path=None):
        """Read security log lines from disk."""
        target_path = custom_path or self.log_path
        if not os.path.exists(target_path):
            raise FileNotFoundError(f"Log file not found: {target_path}")

        self.raw_events = []
        with open(target_path, "r", encoding="utf-8") as f:
            for line in f:
                line_str = line.strip()
                if line_str and not line_str.startswith("#"):
                    self.raw_events.append(line_str)
        return len(self.raw_events)

    def parse_events(self):
        """Parse raw log lines into normalized event objects across disparate log formats."""
        self.parsed_events = []

        # Regex patterns
        win_event_re = re.compile(
            r'^(?P<timestamp>\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})\s(?P<host>\S+)\sSecurity\[(?P<event_id>4624|4625)\]\s(?P<msg>.*?)\sTargetUser:\s(?P<user>\S+)(?:\sWorkstation:\s(?P<workstation>\S+))?(?:\sSourceIP:\s(?P<src_ip>\S+))?(?:\sFailureReason:\s(?P<reason>\S+))?(?:\sLogonType:\s(?P<logon_type>\d+))?'
        )
        exch_rule_re = re.compile(
            r'^(?P<timestamp>\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})\s(?P<host>\S+)\sMSExchangeManagement\[\d+\]\sCmdlet:\s(?P<cmdlet>\S+)\sParameters:\s(?P<params>.*)'
        )
        vpn_re = re.compile(
            r'^(?P<timestamp>\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})\s(?P<host>\S+)\sFortiGate\[\d+\]\sauth_status=(?P<status>\S+)\suser=(?P<user>\S+)\ssrc_ip=(?P<src_ip>\S+)\sgeo_city="(?P<city>[^"]+)"\sgeo_country="(?P<country>[^"]+)"(?:\slat=(?P<lat>[\d\.\-]+)\slon=(?P<lon>[\d\.\-]+))?(?:\ssession_id=(?P<session>\S+))?'
        )
        proxy_re = re.compile(
            r'^(?P<timestamp>\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2})\s(?P<host>\S+)\sSquid\[\d+\]\sproto=(?P<proto>\S+)\sstatus=(?P<status>\d+)\smethod=(?P<method>\S+)\surl="(?P<url>[^"]+)"\sclient_ip=(?P<src_ip>\S+)\suser=(?P<user>\S+)'
        )

        for line in self.raw_events:
            dt = None

            # 1. Windows Events (4624 / 4625)
            m_win = win_event_re.search(line)
            if m_win:
                dt = datetime.strptime(m_win.group("timestamp"), "%Y-%m-%d %H:%M:%S")
                evt = {
                    "source": "Windows-Security",
                    "timestamp": dt,
                    "host": m_win.group("host"),
                    "event_id": m_win.group("event_id"),
                    "action": "logon_success" if m_win.group("event_id") == "4624" else "logon_failure",
                    "user": m_win.group("user").lower(),
                    "workstation": m_win.group("workstation") or "N/A",
                    "src_ip": m_win.group("src_ip") or "127.0.0.1",
                    "reason": m_win.group("reason") or "N/A",
                    "logon_type": m_win.group("logon_type") or "0",
                    "raw": line
                }
                self.parsed_events.append(evt)
                continue

            # 2. Exchange / Mail Rules
            m_exch = exch_rule_re.search(line)
            if m_exch:
                dt = datetime.strptime(m_exch.group("timestamp"), "%Y-%m-%d %H:%M:%S")
                params = m_exch.group("params")
                
                # Extract mailbox
                mb_match = re.search(r'-Mailbox\s"([^"]+)"', params)
                user = mb_match.group(1).lower() if mb_match else "unknown"
                
                # Extract forward to
                fwd_match = re.search(r'-ForwardTo\s"([^"]+)"', params)
                forward_to = fwd_match.group(1) if fwd_match else "N/A"
                
                is_forward_all = "rule=forward_all" in line or "-ForwardTo" in params

                evt = {
                    "source": "MSExchange-Audit",
                    "timestamp": dt,
                    "host": m_exch.group("host"),
                    "cmdlet": m_exch.group("cmdlet"),
                    "user": user,
                    "forward_to": forward_to,
                    "is_forward_all": is_forward_all,
                    "params": params,
                    "action": "exchange_config_change",
                    "raw": line
                }
                self.parsed_events.append(evt)
                continue

            # 3. VPN Gateway Events
            m_vpn = vpn_re.search(line)
            if m_vpn:
                dt = datetime.strptime(m_vpn.group("timestamp"), "%Y-%m-%d %H:%M:%S")
                lat = float(m_vpn.group("lat")) if m_vpn.group("lat") else 0.0
                lon = float(m_vpn.group("lon")) if m_vpn.group("lon") else 0.0
                evt = {
                    "source": "VPN-Gateway",
                    "timestamp": dt,
                    "host": m_vpn.group("host"),
                    "status": m_vpn.group("status"),
                    "user": m_vpn.group("user").lower(),
                    "src_ip": m_vpn.group("src_ip"),
                    "city": m_vpn.group("city"),
                    "country": m_vpn.group("country"),
                    "lat": lat,
                    "lon": lon,
                    "action": "vpn_login",
                    "raw": line
                }
                self.parsed_events.append(evt)
                continue

            # 4. Proxy / Web Gateway
            m_proxy = proxy_re.search(line)
            if m_proxy:
                dt = datetime.strptime(m_proxy.group("timestamp"), "%Y-%m-%d %H:%M:%S")
                evt = {
                    "source": "WebProxy-Squid",
                    "timestamp": dt,
                    "host": m_proxy.group("host"),
                    "proto": m_proxy.group("proto"),
                    "status": m_proxy.group("status"),
                    "method": m_proxy.group("method"),
                    "url": m_proxy.group("url"),
                    "src_ip": m_proxy.group("src_ip"),
                    "user": m_proxy.group("user").lower(),
                    "action": "web_access",
                    "raw": line
                }
                self.parsed_events.append(evt)
                continue

        # Sort events by timestamp
        self.parsed_events.sort(key=lambda x: x["timestamp"])
        return len(self.parsed_events)

    def correlate_all(self):
        """Run all SIEM correlation detection rules across parsed telemetry."""
        if not self.parsed_events:
            self.parse_events()

        self.alerts = []
        self.alerts.extend(self.detect_brute_force())
        self.alerts.extend(self.detect_suspicious_forwarding_rules())
        self.alerts.extend(self.detect_impossible_travel())
        self.alerts.extend(self.detect_account_takeover())

        # Sort alerts by severity order
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        self.alerts.sort(key=lambda x: sev_order.get(x["severity"], 99))
        return self.alerts

    def detect_brute_force(self, threshold=3):
        """Rule 1: Detect credential brute forcing or password spraying (>= threshold failed logins)."""
        alerts = []
        failed_by_ip = defaultdict(list)
        failed_by_user = defaultdict(list)

        for ev in self.parsed_events:
            if ev.get("action") == "logon_failure":
                ip = ev.get("src_ip", "unknown")
                user = ev.get("user", "unknown")
                failed_by_ip[ip].append(ev)
                failed_by_user[user].append(ev)

        # Check IP threshold
        for ip, events in failed_by_ip.items():
            if len(events) >= threshold:
                targeted_users = list(set([e["user"] for e in events]))
                first_ts = events[0]["timestamp"]
                last_ts = events[-1]["timestamp"]
                time_span_sec = (last_ts - first_ts).total_seconds()

                alerts.append({
                    "alert_id": f"ALRT-BF-{ip.replace('.', '_')}",
                    "rule_name": "Multiple Failed Authentication Attempts (Brute Force / Password Spray)",
                    "mitre_id": "T1110.001",
                    "mitre_tactic": "Credential Access",
                    "severity": "HIGH",
                    "entity": f"Source IP: {ip}",
                    "details": {
                        "attacker_ip": ip,
                        "failed_attempts": len(events),
                        "targeted_users": targeted_users,
                        "time_span_seconds": time_span_sec,
                        "first_seen": str(first_ts),
                        "last_seen": str(last_ts)
                    },
                    "recommendation": f"Enforce immediate IP block on firewall for {ip} and enforce account lockout threshold."
                })

        return alerts

    def detect_suspicious_forwarding_rules(self):
        """Rule 2: Detect unauthorized mailbox forwarding rules (rule=forward_all or external drop)."""
        alerts = []
        for ev in self.parsed_events:
            if ev.get("source") == "MSExchange-Audit" and ev.get("is_forward_all"):
                alerts.append({
                    "alert_id": f"ALRT-EXCH-{ev['timestamp'].strftime('%H%M%S')}",
                    "rule_name": "Unauthorized Mailbox Auto-Forwarding Rule Created (Exfiltration Tripwire)",
                    "mitre_id": "T1114.003",
                    "mitre_tactic": "Collection / Exfiltration",
                    "severity": "CRITICAL",
                    "entity": f"Mailbox: {ev['user']}",
                    "details": {
                        "mailbox": ev["user"],
                        "forward_destination": ev["forward_to"],
                        "cmdlet": ev["cmdlet"],
                        "timestamp": str(ev["timestamp"]),
                        "raw_command": ev["params"]
                    },
                    "recommendation": f"Immediately remove forwarding rule from {ev['user']}, invalidate active OAuth tokens, and reset account credentials."
                })
        return alerts

    def detect_impossible_travel(self, max_speed_kmh=800.0):
        """Rule 3: Detect concurrent or rapid logins across impossible geographic distances."""
        alerts = []
        user_logins = defaultdict(list)

        for ev in self.parsed_events:
            if ev.get("action") in ["vpn_login", "logon_success"] and ev.get("lat") and ev.get("lon"):
                user = ev["user"]
                user_logins[user].append(ev)

        for user, logins in user_logins.items():
            if len(logins) < 2:
                continue

            for i in range(len(logins) - 1):
                ev1 = logins[i]
                ev2 = logins[i + 1]

                time_delta_hours = (ev2["timestamp"] - ev1["timestamp"]).total_seconds() / 3600.0
                if time_delta_hours <= 0:
                    time_delta_hours = 0.001  # Prevent divide-by-zero for concurrent logins

                distance_km = haversine_distance(ev1["lat"], ev1["lon"], ev2["lat"], ev2["lon"])
                velocity_kmh = distance_km / time_delta_hours

                if velocity_kmh > max_speed_kmh and distance_km > 500:
                    alerts.append({
                        "alert_id": f"ALRT-TRAVEL-{user.replace('@', '_').replace('.', '_')}",
                        "rule_name": "Anomalous Authentication Velocity (Impossible Travel Detected)",
                        "mitre_id": "T1078.004",
                        "mitre_tactic": "Defense Evasion / Initial Access",
                        "severity": "CRITICAL",
                        "entity": f"User: {user}",
                        "details": {
                            "user": user,
                            "location_1": f"{ev1.get('city', 'Unknown')}, {ev1.get('country', 'Unknown')} ({ev1.get('src_ip')})",
                            "location_2": f"{ev2.get('city', 'Unknown')}, {ev2.get('country', 'Unknown')} ({ev2.get('src_ip')})",
                            "distance_km": round(distance_km, 2),
                            "time_delta_minutes": round(time_delta_hours * 60, 2),
                            "calculated_velocity_kmh": round(velocity_kmh, 2),
                            "threshold_kmh": max_speed_kmh
                        },
                        "recommendation": f"Terminate active sessions for {user}, require MFA challenge re-authentication, and isolate external IP {ev2.get('src_ip')}."
                    })
        return alerts

    def detect_account_takeover(self):
        """Rule 4: Multi-stage Kill Chain: Brute Force -> Successful Logon -> Mailbox Exfil Rule."""
        alerts = []
        users_with_failed = defaultdict(list)
        users_with_success = defaultdict(list)
        users_with_fwd = defaultdict(list)

        for ev in self.parsed_events:
            user = ev.get("user", "")
            # Normalize email to username if present
            clean_user = user.split("@")[0]

            if ev.get("action") == "logon_failure":
                users_with_failed[clean_user].append(ev)
            elif ev.get("action") == "logon_success":
                users_with_success[clean_user].append(ev)
            elif ev.get("source") == "MSExchange-Audit" and ev.get("is_forward_all"):
                users_with_fwd[clean_user].append(ev)

        # Check intersection
        for user in users_with_failed:
            if len(users_with_failed[user]) >= 3 and user in users_with_success and user in users_with_fwd:
                first_failed = users_with_failed[user][0]
                success_ev = users_with_success[user][0]
                fwd_ev = users_with_fwd[user][0]

                alerts.append({
                    "alert_id": f"ALRT-ATO-{user}",
                    "rule_name": "Full Multi-Stage Account Takeover (ATO) Chain Identified",
                    "mitre_id": "T1078 / T1110 / T1114.003",
                    "mitre_tactic": "Credential Access -> Persistence -> Exfiltration",
                    "severity": "CRITICAL",
                    "entity": f"Compromised Identity: {user}",
                    "details": {
                        "user": user,
                        "attack_stage_1": f"{len(users_with_failed[user])} failed password attempts from {first_failed.get('src_ip')}",
                        "attack_stage_2": f"Successful authentication at {success_ev['timestamp']} from {success_ev.get('src_ip')}",
                        "attack_stage_3": f"Malicious forwarding rule created to {fwd_ev.get('forward_to')}",
                        "compromise_window": f"{first_failed['timestamp']} to {fwd_ev['timestamp']}"
                    },
                    "recommendation": f"TRIGGER INCIDENT RESPONSE P1: Immediately lock account {user}, purge inbox rules, revoke VPN tokens, and blacklist source IP."
                })
        return alerts

    def export_reports(self, json_path=JSON_REPORT_PATH, txt_path=TXT_REPORT_PATH):
        """Export structured JSON and text summaries of all SIEM detections."""
        summary = {
            "metadata": {
                "organization": "Sqrock IT Solutions",
                "suite": "PEER'S SIEM Log Analyzer v2.0",
                "developer": "Mohammed Peer Siddiqui",
                "generated_at": datetime.now().isoformat(),
                "log_source": self.log_path,
                "total_events_parsed": len(self.parsed_events),
                "total_alerts_generated": len(self.alerts)
            },
            "severity_counts": {
                "CRITICAL": sum(1 for a in self.alerts if a["severity"] == "CRITICAL"),
                "HIGH": sum(1 for a in self.alerts if a["severity"] == "HIGH"),
                "MEDIUM": sum(1 for a in self.alerts if a["severity"] == "MEDIUM"),
                "LOW": sum(1 for a in self.alerts if a["severity"] == "LOW")
            },
            "alerts": self.alerts
        }

        # Write JSON
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)

        # Write Triage TXT
        with open(txt_path, "w", encoding="utf-8") as f:
            f.write("=" * 80 + "\n")
            f.write("        SQROCK IT SOLUTIONS - SIEM SECURITY INCIDENT TRIAGE SUMMARY\n")
            f.write("=" * 80 + "\n")
            f.write(f"Generated At       : {summary['metadata']['generated_at']}\n")
            f.write(f"Analyzed Log Path  : {summary['metadata']['log_source']}\n")
            f.write(f"Total Log Events   : {summary['metadata']['total_events_parsed']}\n")
            f.write(f"Total Threat Alerts: {summary['metadata']['total_alerts_generated']}\n")
            f.write(f"Critical Severity  : {summary['severity_counts']['CRITICAL']}\n")
            f.write(f"High Severity      : {summary['severity_counts']['HIGH']}\n")
            f.write("-" * 80 + "\n\n")

            for idx, a in enumerate(self.alerts, 1):
                f.write(f"[ALERT #{idx:02d}] {a['rule_name']} [{a['severity']}]\n")
                f.write(f"  Alert ID        : {a['alert_id']}\n")
                f.write(f"  MITRE Technique : {a['mitre_id']} ({a['mitre_tactic']})\n")
                f.write(f"  Affected Entity : {a['entity']}\n")
                f.write(f"  Details         : {json.dumps(a['details'])}\n")
                f.write(f"  Remediation     : {a['recommendation']}\n")
                f.write("-" * 80 + "\n")

        return summary


def print_banner():
    """Print high-tech terminal banner."""
    print(Fore.CYAN + Style.BRIGHT + r"""
   _____ _____ ______ __  __   _      ____   _____            _   _          _     __   __ ______ ______ _____  
  / ____|_   _|  ____|  \/  | | |    / __ \ / ____|     /\   | \ | |   /\   | |    \ \ / /|___  /|  ____|  __ \ 
 | (___   | | | |__  | \  / | | |   | |  | | |  __     /  \  |  \| |  /  \  | |     \ V /    / / | |__  | |__) |
  \___ \  | | |  __| | |\/| | | |   | |  | | | |_ |   / /\ \ | . ` | / /\ \ | |      > <    / /  |  __| |  _  / 
  ____) |_| |_| |____| |  | | | |___| |__| | |__| |  / ____ \| |\  |/ ____ \| |____ / . \  / /__ | |____| | \ \ 
 |_____/|_____|______|_|  |_| |______\____/ \_____| /_/    \_\_| \_/_/    \_\______/_/ \_\/_____|______|_|  \_\
    """ + Style.RESET_ALL)
    print(Fore.YELLOW + " [*] Enterprise Multi-Source Telemetry Parser & Correlation Engine v2.0")
    print(Fore.GREEN + " [*] Developer: Mohammed Peer Siddiqui | Sqrock IT Solutions Cybersecurity Lab")
    print(Fore.WHITE + " [*] Standards: NIST SP 800-61 Rev.2 | MITRE ATT&CK T1110, T1078, T1114.003\n")


def run_interactive_menu():
    """CLI driver loop."""
    analyzer = SIEMLogAnalyzer()
    analyzer.load_logs()
    analyzer.parse_events()

    while True:
        print_banner()
        print(Fore.LIGHTBLUE_EX + " [=== MASTER SIEM TRIAGE MENU ===]")
        print(Fore.WHITE + " [1] Ingest & Parse Multi-Source Security Logs")
        print(Fore.WHITE + " [2] Run Full Correlation Engine (Detect All Threats)")
        print(Fore.WHITE + " [3] Analyze Impossible Travel Incidents (Velocity Check)")
        print(Fore.WHITE + " [4] Inspect Compromised Mailbox Forwarding Rules (Exfiltration)")
        print(Fore.WHITE + " [5] Export SIEM Audit Reports (JSON & Text Triage)")
        print(Fore.WHITE + " [6] Exit Suite\n")

        try:
            choice = input(Fore.CYAN + " siem-console@sqrock-soc:~$ " + Style.RESET_ALL).strip()
        except (KeyboardInterrupt, EOFError):
            print("\nExiting SIEM Console...")
            break

        if choice == "1":
            print(Fore.YELLOW + f"\n[*] Reading logs from: {analyzer.log_path}")
            count = analyzer.load_logs()
            parsed_count = analyzer.parse_events()
            print(Fore.GREEN + f"[+] Successfully loaded {count} raw log entries.")
            print(Fore.GREEN + f"[+] Successfully parsed {parsed_count} normalized events across Windows, Exchange, VPN, and Proxy sources.\n")
            input(Fore.LIGHTBLACK_EX + "Press Enter to continue...")

        elif choice == "2":
            print(Fore.YELLOW + "\n[*] Correlating security events against behavioral analytics rules...")
            alerts = analyzer.correlate_all()
            print(Fore.GREEN + f"[+] Correlation complete! Found {len(alerts)} threat alert(s):\n")

            for a in alerts:
                sev_color = Fore.RED if a["severity"] == "CRITICAL" else Fore.YELLOW
                print(f" {sev_color}[{a['severity']}] {Fore.WHITE}{a['rule_name']}")
                print(f"   {Fore.CYAN}Alert ID: {Style.RESET_ALL}{a['alert_id']} | {Fore.LIGHTBLUE_EX}MITRE: {Style.RESET_ALL}{a['mitre_id']}")
                print(f"   {Fore.LIGHTBLACK_EX}Entity: {a['entity']}")
                print(f"   {Fore.LIGHTGREEN_EX}Action: {a['recommendation']}\n")
            input(Fore.LIGHTBLACK_EX + "Press Enter to continue...")

        elif choice == "3":
            print(Fore.YELLOW + "\n[*] Executing Impossible Travel Great-Circle Velocity Correlation...")
            travel_alerts = analyzer.detect_impossible_travel()
            if not travel_alerts:
                print(Fore.GREEN + "[+] No impossible travel anomalies detected.")
            else:
                for a in travel_alerts:
                    d = a["details"]
                    print(Fore.RED + Style.BRIGHT + f"\n[!] IMPOSSIBLE TRAVEL TRIPWIRE TRIGGERED:")
                    print(Fore.WHITE + f"    User              : {d['user']}")
                    print(Fore.WHITE + f"    Origin Location   : {d['location_1']}")
                    print(Fore.WHITE + f"    Dest Location     : {d['location_2']}")
                    print(Fore.WHITE + f"    Distance Traveled : {d['distance_km']} km")
                    print(Fore.WHITE + f"    Time Delta        : {d['time_delta_minutes']} minutes")
                    print(Fore.RED + f"    Calculated Speed  : {d['calculated_velocity_kmh']} km/h (Threshold: {d['threshold_kmh']} km/h)")
            print()
            input(Fore.LIGHTBLACK_EX + "Press Enter to continue...")

        elif choice == "4":
            print(Fore.YELLOW + "\n[*] Inspecting Exchange/M365 Mailbox Auto-Forwarding Rules...")
            fwd_alerts = analyzer.detect_suspicious_forwarding_rules()
            if not fwd_alerts:
                print(Fore.GREEN + "[+] No unauthorized forwarding rules discovered.")
            else:
                for a in fwd_alerts:
                    d = a["details"]
                    print(Fore.RED + Style.BRIGHT + f"\n[!] CRITICAL EXFILTRATION FORWARDING RULE DETECTED:")
                    print(Fore.WHITE + f"    Compromised Mailbox : {d['mailbox']}")
                    print(Fore.WHITE + f"    Adversary Drop Email: {Fore.YELLOW}{d['forward_destination']}")
                    print(Fore.WHITE + f"    Timestamp           : {d['timestamp']}")
                    print(Fore.LIGHTBLACK_EX + f"    Raw Command         : {d['raw_command']}")
            print()
            input(Fore.LIGHTBLACK_EX + "Press Enter to continue...")

        elif choice == "5":
            print(Fore.YELLOW + "\n[*] Compiling structured SIEM threat audit reports...")
            analyzer.correlate_all()
            res = analyzer.export_reports()
            print(Fore.GREEN + f"[+] JSON Report exported : {JSON_REPORT_PATH}")
            print(Fore.GREEN + f"[+] Triage Summary TXT   : {TXT_REPORT_PATH}")
            print(Fore.CYAN + f"[+] Breakdown: {res['severity_counts']['CRITICAL']} CRITICAL, {res['severity_counts']['HIGH']} HIGH alerts.\n")
            input(Fore.LIGHTBLACK_EX + "Press Enter to continue...")

        elif choice == "6":
            print(Fore.CYAN + "\n[*] Shutting down SIEM analyzer console. Goodbye!\n")
            break
        else:
            print(Fore.RED + "\n[!] Invalid choice. Please select 1-6.\n")


if __name__ == "__main__":
    if len(sys.argv) > 1 and "--batch" in sys.argv:
        analyzer = SIEMLogAnalyzer()
        analyzer.load_logs()
        analyzer.parse_events()
        analyzer.correlate_all()
        analyzer.export_reports()
        print("[+] Headless SIEM run complete.")
    else:
        run_interactive_menu()
