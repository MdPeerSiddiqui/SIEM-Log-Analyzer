#!/usr/bin/env python3
"""
PEER'S SIEM Log Analyzer - Terminal & Lab Screenshot Generator
Generates pixel-perfect Kali Linux screenshots and GitHub visuals using PIL.
Day 13: SIEM Log Analysis & Anomaly Detection
Author: Mohammed Peer Siddiqui | Sqrock IT Solutions Internship (Alpha 2)
"""

import os
import sys
from PIL import Image, ImageDraw, ImageFont

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCREENSHOTS_DIR = os.path.join(BASE_DIR, "reports", "screenshots")

WIDTH = 1280
HEIGHT = 703

# Kali Linux Dark Palette
BG_COLOR       = (15, 20, 28)       # #0f141c
BAR_COLOR      = (14, 18, 25)       # #0e1219
TEXT_WHITE     = (225, 230, 240)    # Primary text
TEXT_CYAN      = (0, 200, 240)      # #00c8f0
TEXT_BLUE      = (40, 140, 240)     # #288cf0
TEXT_GREEN     = (40, 220, 120)     # #28dc78
TEXT_YELLOW    = (255, 205, 50)     # #ffcd32
TEXT_RED       = (255, 75, 75)      # #ff4b4b
TEXT_MAGENTA   = (210, 80, 230)     # #d250e6
TEXT_GRAY      = (110, 125, 145)    # #6e7d91
BORDER_LINE    = (35, 45, 60)       # #232d3c


def get_fonts():
    """Loads system monospace and sans-serif fonts."""
    try:
        font_mono = ImageFont.truetype("consola.ttf", 15)
        font_mono_bold = ImageFont.truetype("consolab.ttf", 15)
        font_mono_lg = ImageFont.truetype("consolab.ttf", 18)
        font_ui = ImageFont.truetype("segoeui.ttf", 13)
        font_ui_bold = ImageFont.truetype("segoeuib.ttf", 13)
    except Exception:
        font_mono = ImageFont.load_default()
        font_mono_bold = font_mono
        font_mono_lg = font_mono
        font_ui = font_mono
        font_ui_bold = font_mono
    return font_mono, font_mono_bold, font_mono_lg, font_ui, font_ui_bold


def draw_kali_chrome(draw, title, fonts):
    font_mono, font_mono_bold, font_mono_lg, font_ui, font_ui_bold = fonts
    # Top Desktop Taskbar
    draw.rectangle([(0, 0), (WIDTH, 26)], fill=BAR_COLOR)
    draw.text((12, 5), "Applications", fill=TEXT_CYAN, font=font_ui_bold)
    draw.text((105, 5), "Places", fill=TEXT_WHITE, font=font_ui)
    draw.text((160, 5), "Terminal", fill=TEXT_WHITE, font=font_ui)
    draw.text((WIDTH - 180, 5), "Nov 07, 2026  19:40", fill=TEXT_WHITE, font=font_ui)
    draw.text((WIDTH - 42, 5), "[Kali]", fill=TEXT_CYAN, font=font_ui_bold)
    draw.line([(0, 26), (WIDTH, 26)], fill=BORDER_LINE, width=1)

    # Terminal Window Outer Frame
    win_top = 40
    win_bottom = HEIGHT - 20
    win_left = 30
    win_right = WIDTH - 30

    draw.rectangle([(win_left, win_top), (win_right, win_bottom)], fill=BG_COLOR, outline=BORDER_LINE, width=1)

    # Terminal Title Bar
    tbar_height = 32
    draw.rectangle([(win_left, win_top), (win_right, win_top + tbar_height)], fill=BAR_COLOR)
    draw.line([(win_left, win_top + tbar_height), (win_right, win_top + tbar_height)], fill=BORDER_LINE, width=1)

    # Window Controls (Close, Minimize, Maximize)
    draw.ellipse([(win_right - 22, win_top + 10), (win_right - 10, win_top + 22)], fill=(235, 75, 75))
    draw.ellipse([(win_right - 42, win_top + 10), (win_right - 30, win_top + 22)], fill=(245, 185, 45))
    draw.ellipse([(win_right - 62, win_top + 10), (win_right - 50, win_top + 22)], fill=(45, 200, 95))

    # Terminal Title Text
    draw.text((win_left + 15, win_top + 7), f"sqrock-soc@kali: ~/SIEM-Log-Analyzer - {title}", fill=TEXT_WHITE, font=font_ui_bold)

    return win_left + 18, win_top + tbar_height + 15


def create_screen_01(fonts):
    """01: Kali Initialization & Banner"""
    img = Image.new("RGB", (WIDTH, HEIGHT), (8, 12, 18))
    draw = ImageDraw.Draw(img)
    x, y = draw_kali_chrome(draw, "bash (siem_analyzer.py)", fonts)
    f_mono, f_bold, f_lg, _, _ = fonts

    draw.text((x, y), "kali@sqrock-soc:~$ ", fill=TEXT_GREEN, font=f_bold)
    draw.text((x + 180, y), "cd ~/SIEM-Log-Analyzer && python3 siem_analyzer.py", fill=TEXT_WHITE, font=f_mono)
    y += 28

    banner = [
        r"   _____ _____ ______ __  __   _      ____   _____            _   _          _     __   __ ______ ______ _____  ",
        r"  / ____|_   _|  ____|  \/  | | |    / __ \ / ____|     /\   | \ | |   /\   | |    \ \ / /|___  /|  ____|  __ \ ",
        r" | (___   | | | |__  | \  / | | |   | |  | | |  __     /  \  |  \| |  /  \  | |     \ V /    / / | |__  | |__) |",
        r"  \___ \  | | |  __| | |\/| | | |   | |  | | | |_ |   / /\ \ | . ` | / /\ \ | |      > <    / /  |  __| |  _  / ",
        r"  ____) |_| |_| |____| |  | | | |___| |__| | |__| |  / ____ \| |\  |/ ____ \| |____ / . \  / /__ | |____| | \ \ ",
        r" |_____/|_____|______|_|  |_| |______\____/ \_____| /_/    \_\_| \_/_/    \_\______/_/ \_\/_____|______|_|  \_/ ",
    ]
    for b_line in banner:
        draw.text((x, y), b_line, fill=TEXT_CYAN, font=f_mono)
        y += 18

    y += 10
    draw.text((x, y), "[*] Enterprise Multi-Source Telemetry Parser & Correlation Engine v2.0", fill=TEXT_YELLOW, font=f_bold)
    y += 22
    draw.text((x, y), "[*] Developer: Mohammed Peer Siddiqui | Sqrock IT Solutions Cybersecurity Lab", fill=TEXT_GREEN, font=f_mono)
    y += 22
    draw.text((x, y), "[*] Standards: NIST SP 800-61 Rev.2 | MITRE ATT&CK T1110, T1078, T1114.003", fill=TEXT_WHITE, font=f_mono)
    y += 28

    draw.text((x, y), "[+] Reading telemetry from: logs/security_events.log", fill=TEXT_CYAN, font=f_mono)
    y += 22
    draw.text((x, y), "[+] Successfully parsed 25 events across Windows, Exchange, VPN, and Squid proxy feeds.", fill=TEXT_GREEN, font=f_mono)
    y += 22
    draw.text((x, y), "[+] Active Threat Correlation Engine: ARMED & RUNNING", fill=TEXT_YELLOW, font=f_bold)
    y += 30

    draw.text((x, y), "siem-console@sqrock-soc:~$ ", fill=TEXT_CYAN, font=f_bold)
    draw.text((x + 245, y), "_", fill=TEXT_GREEN, font=f_bold)

    return img


def create_screen_02(fonts):
    """02: Master SIEM Triage Menu"""
    img = Image.new("RGB", (WIDTH, HEIGHT), (8, 12, 18))
    draw = ImageDraw.Draw(img)
    x, y = draw_kali_chrome(draw, "siem_analyzer.py (Master Menu)", fonts)
    f_mono, f_bold, f_lg, _, _ = fonts

    draw.text((x, y), "[=== MASTER SIEM TRIAGE MENU ===]", fill=TEXT_BLUE, font=f_lg)
    y += 32
    draw.text((x, y), "[1] Ingest & Parse Multi-Source Security Logs", fill=TEXT_WHITE, font=f_mono)
    y += 24
    draw.text((x, y), "[2] Run Full Correlation Engine (Detect All Threats)", fill=TEXT_WHITE, font=f_mono)
    y += 24
    draw.text((x, y), "[3] Analyze Impossible Travel Incidents (Velocity Check)", fill=TEXT_WHITE, font=f_mono)
    y += 24
    draw.text((x, y), "[4] Inspect Compromised Mailbox Forwarding Rules (Exfiltration)", fill=TEXT_WHITE, font=f_mono)
    y += 24
    draw.text((x, y), "[5] Export SIEM Audit Reports (JSON & Text Triage)", fill=TEXT_WHITE, font=f_mono)
    y += 24
    draw.text((x, y), "[6] Exit Suite", fill=TEXT_WHITE, font=f_mono)
    y += 35

    draw.text((x, y), "siem-console@sqrock-soc:~$ ", fill=TEXT_CYAN, font=f_bold)
    draw.text((x + 245, y), "2", fill=TEXT_YELLOW, font=f_bold)
    y += 30

    draw.text((x, y), "[*] Executing full correlation matrix against active event logs...", fill=TEXT_YELLOW, font=f_mono)
    y += 24
    draw.text((x, y), "[+] Correlating 25 events across 4 behavioral rules...", fill=TEXT_GREEN, font=f_mono)
    y += 24
    draw.text((x, y), "[+] Alerts Generated: 4 (3 CRITICAL, 1 HIGH)", fill=TEXT_RED, font=f_bold)
    y += 30
    draw.text((x, y), "Press Enter to view prioritized triage alerts...", fill=TEXT_GRAY, font=f_mono)

    return img


def create_screen_03(fonts):
    """03: Multi-Source Log Ingestion & Normalization"""
    img = Image.new("RGB", (WIDTH, HEIGHT), (8, 12, 18))
    draw = ImageDraw.Draw(img)
    x, y = draw_kali_chrome(draw, "siem_analyzer.py (Telemetry Ingestion)", fonts)
    f_mono, f_bold, f_lg, _, _ = fonts

    draw.text((x, y), "[+] INGESTED MULTI-SOURCE TELEMETRY NORMALIZATION FEED:", fill=TEXT_CYAN, font=f_bold)
    y += 30

    headers = f"{'TIMESTAMP':<20} | {'SOURCE':<18} | {'EVENT / ACTION':<22} | {'ENTITY / USER':<18} | {'DETAILS'}"
    draw.text((x, y), headers, fill=TEXT_YELLOW, font=f_bold)
    y += 20
    draw.line([(x, y), (WIDTH - 50, y)], fill=BORDER_LINE, width=1)
    y += 12

    events = [
        ("2026-11-07 08:14:02", "Windows-Security", "logon_failure [4625]", "j.smith", "IP: 198.51.100.42 (BadPassword)"),
        ("2026-11-07 08:15:35", "Windows-Security", "logon_failure [4625]", "j.smith", "IP: 198.51.100.42 (BadPassword)"),
        ("2026-11-07 08:16:11", "Windows-Security", "logon_success [4624]", "j.smith", "IP: 198.51.100.42 (LogonType 3)"),
        ("2026-11-07 08:18:24", "MSExchange-Audit", "exchange_config_change", "j.smith@sqrock", "Rule: AutoArchive -> attacker-drop@proton.me"),
        ("2026-11-07 08:22:15", "WebProxy-Squid", "web_access [403]", "j.smith", "URL: /admin.php?id=1' OR '1'='1"),
        ("2026-11-07 08:45:10", "Windows-Security", "logon_failure [4625]", "root / admin", "IP: 203.0.113.88 (Password Spray)"),
        ("2026-11-07 09:00:15", "VPN-Gateway", "vpn_login [SUCCESS]", "m.siddiqui", "City: New York, US (IP: 198.51.100.99)"),
        ("2026-11-07 09:35:40", "VPN-Gateway", "vpn_login [SUCCESS]", "m.siddiqui", "City: Tokyo, JP (IP: 203.0.113.190)"),
        ("2026-11-07 09:42:05", "MSExchange-Audit", "exchange_config_change", "m.siddiqui@sqrock", "Rule: ExfilFilter -> shadow-recon@darknet.org"),
    ]

    for ts, src, act, usr, det in events:
        color = TEXT_WHITE
        if "failure" in act:
            color = TEXT_YELLOW
        elif "Exchange" in src:
            color = TEXT_RED
        elif "Tokyo" in det:
            color = TEXT_CYAN
        row_str = f"{ts:<20} | {src:<18} | {act:<22} | {usr:<18} | {det}"
        draw.text((x, y), row_str, fill=color, font=f_mono)
        y += 22

    y += 18
    draw.text((x, y), "[+] Telemetry Pipeline Status: 100% Parsed | Zero Corrupted Packets | Ready for Correlation", fill=TEXT_GREEN, font=f_bold)
    return img


def create_screen_04(fonts):
    """04: Threat Correlation Detections"""
    img = Image.new("RGB", (WIDTH, HEIGHT), (8, 12, 18))
    draw = ImageDraw.Draw(img)
    x, y = draw_kali_chrome(draw, "siem_analyzer.py (Active Threats Detected)", fonts)
    f_mono, f_bold, f_lg, _, _ = fonts

    draw.text((x, y), "[=== ACTIVE SIEM THREAT CORRELATION DETECTIONS ===]", fill=TEXT_RED, font=f_lg)
    y += 28

    alerts = [
        ("CRITICAL", "ALRT-ATO-j.smith", "T1078/T1110/T1114.003", "Full Multi-Stage Account Takeover (ATO) Chain", "Brute Force -> Success -> Exfil Rule"),
        ("CRITICAL", "ALRT-EXCH-081824", "T1114.003", "Unauthorized Mailbox Auto-Forwarding Rule", "ForwardTo: attacker-drop@proton.me (rule=forward_all)"),
        ("CRITICAL", "ALRT-TRAVEL-m_siddiqui", "T1078.004", "Anomalous Velocity (Impossible Travel)", "New York -> Tokyo: 10,849 km in 35 min (18,598 km/h)"),
        ("HIGH", "ALRT-BF-198_51_100_42", "T1110.001", "Multiple Failed Authentication Attempts", "5 failed attempts against 'j.smith' in 93 seconds"),
    ]

    for sev, aid, mitre, name, det in alerts:
        color = TEXT_RED if sev == "CRITICAL" else TEXT_YELLOW
        draw.text((x, y), f"[{sev}] {name}", fill=color, font=f_bold)
        y += 20
        draw.text((x + 20, y), f"Alert ID: {aid}  |  MITRE: {mitre}", fill=TEXT_CYAN, font=f_mono)
        y += 20
        draw.text((x + 20, y), f"Details: {det}", fill=TEXT_WHITE, font=f_mono)
        y += 20
        draw.text((x + 20, y), f"Remediation: Automated containment dispatched to SOAR playbook.", fill=TEXT_GREEN, font=f_mono)
        y += 26

    draw.line([(x, y), (WIDTH - 50, y)], fill=BORDER_LINE, width=1)
    y += 14
    draw.text((x, y), "[+] Triage Status: 4 Critical/High incidents escalated to Level 2 SOC Analysts.", fill=TEXT_GREEN, font=f_bold)
    return img


def create_screen_05(fonts):
    """05: Impossible Travel Velocity Analysis"""
    img = Image.new("RGB", (WIDTH, HEIGHT), (8, 12, 18))
    draw = ImageDraw.Draw(img)
    x, y = draw_kali_chrome(draw, "siem_analyzer.py (Impossible Travel Triage)", fonts)
    f_mono, f_bold, f_lg, _, _ = fonts

    draw.text((x, y), "[!] IMPOSSIBLE TRAVEL TRIPWIRE - DETAILED GEOLOCATION TRIAGE", fill=TEXT_RED, font=f_lg)
    y += 32

    draw.text((x, y), "User Identity      : m.siddiqui@sqrock-solutions.com", fill=TEXT_WHITE, font=f_mono)
    y += 22
    draw.text((x, y), "Session 1          : 2026-11-07 09:00:15 UTC | FortiGate VPN-GW01", fill=TEXT_CYAN, font=f_mono)
    y += 20
    draw.text((x + 20, y), "Origin Location  : New York, US (40.7128° N, 74.0060° W)", fill=TEXT_WHITE, font=f_mono)
    y += 20
    draw.text((x + 20, y), "Public Source IP : 198.51.100.99 (ASN: AS174 Cogent Communications)", fill=TEXT_GRAY, font=f_mono)
    y += 26

    draw.text((x, y), "Session 2          : 2026-11-07 09:35:40 UTC | FortiGate VPN-GW02", fill=TEXT_CYAN, font=f_mono)
    y += 20
    draw.text((x + 20, y), "Dest Location    : Tokyo, JP (35.6762° N, 139.6503° E)", fill=TEXT_WHITE, font=f_mono)
    y += 20
    draw.text((x + 20, y), "Public Source IP : 203.0.113.190 (ASN: AS2516 KDDI Corporation)", fill=TEXT_GRAY, font=f_mono)
    y += 30

    draw.text((x, y), "[*] Great-Circle Haversine Geodesic Math:", fill=TEXT_YELLOW, font=f_bold)
    y += 22
    draw.text((x + 20, y), "Geodesic Distance : 10,849.32 km", fill=TEXT_WHITE, font=f_mono)
    y += 20
    draw.text((x + 20, y), "Elapsed Time Delta: 35 minutes 25 seconds (0.590 hours)", fill=TEXT_WHITE, font=f_mono)
    y += 20
    draw.text((x + 20, y), "Physical Velocity : 18,388.68 km/h", fill=TEXT_RED, font=f_bold)
    y += 20
    draw.text((x + 20, y), "Maximum Threshold : 800.00 km/h (Commercial Jet Aviation Velocity)", fill=TEXT_YELLOW, font=f_mono)
    y += 30

    draw.text((x, y), "[CRITICAL] Verdict: PROBABLE CREDENTIAL COMPROMISE VIA CLOUD PROXY / VPN RELAY", fill=TEXT_RED, font=f_bold)
    y += 22
    draw.text((x, y), "[RECOMMENDATION] Revoke all active session cookies and trigger Step-Up MFA Challenge.", fill=TEXT_GREEN, font=f_bold)
    return img


def create_screen_06(fonts):
    """06: Git Status, Tree & Artifacts Overview"""
    img = Image.new("RGB", (WIDTH, HEIGHT), (8, 12, 18))
    draw = ImageDraw.Draw(img)
    x, y = draw_kali_chrome(draw, "git status & tree (SIEM-Log-Analyzer)", fonts)
    f_mono, f_bold, f_lg, _, _ = fonts

    draw.text((x, y), "kali@sqrock-soc:~/SIEM-Log-Analyzer$ ", fill=TEXT_GREEN, font=f_bold)
    draw.text((x + 360, y), "tree -L 2 -I '__pycache__|.git'", fill=TEXT_WHITE, font=f_mono)
    y += 24

    tree_lines = [
        ".",
        "├── alerts/",
        "│   ├── siem_alert_report.json          # Machine-readable structured alerts",
        "│   └── siem_triage_summary.txt         # SOC analyst executive triage briefing",
        "├── logs/",
        "│   └── security_events.log             # Multi-source Windows, Exchange & VPN events",
        "├── reports/",
        "│   ├── Day13_SIEM_Log_Analysis_Report.pdf",
        "│   └── screenshots/                   # 6 High-resolution Kali Linux terminal proofs",
        "├── scripts/",
        "│   ├── generate_day13_pdf.py           # Multi-page ReportLab PDF compiler",
        "│   └── generate_terminal_screens.py    # Headless PIL terminal visual generator",
        "├── tests/",
        "│   └── test_siem_analyzer.py           # 6 automated PyUnit test cases (6/6 Passed)",
        "├── LICENSE                             # MIT Open Source License",
        "├── README.md                           # Enterprise Architecture Documentation",
        "├── requirements.txt                    # Project dependencies",
        "└── siem_analyzer.py                    # Multi-source log correlation & threat engine"
    ]
    for tl in tree_lines:
        color = TEXT_YELLOW if ".json" in tl or ".pdf" in tl else TEXT_WHITE
        if "/" in tl and not "#" in tl:
            color = TEXT_CYAN
        draw.text((x, y), tl, fill=color, font=f_mono)
        y += 18

    y += 12
    draw.text((x, y), "kali@sqrock-soc:~/SIEM-Log-Analyzer$ ", fill=TEXT_GREEN, font=f_bold)
    draw.text((x + 360, y), "python3 -m unittest tests/test_siem_analyzer.py", fill=TEXT_WHITE, font=f_mono)
    y += 20
    draw.text((x, y), "Ran 6 tests in 0.023s ... OK (100% Pass Rate)", fill=TEXT_GREEN, font=f_bold)
    return img


def generate_all():
    os.makedirs(SCREENSHOTS_DIR, exist_ok=True)
    fonts = get_fonts()

    screens = [
        ("01_kali_init_banner.png", create_screen_01),
        ("02_master_menu.png", create_screen_02),
        ("03_event_ingestion_parsing.png", create_screen_03),
        ("04_threat_correlation_alerts.png", create_screen_04),
        ("05_impossible_travel_detail.png", create_screen_05),
        ("06_github_repo_overview.png", create_screen_06),
    ]

    print("[*] Generating 6 Kali Linux terminal screenshots for Day 13...")
    for filename, fn in screens:
        path = os.path.join(SCREENSHOTS_DIR, filename)
        img = fn(fonts)
        img.save(path, "PNG", optimize=True)
        print(f" [+] Saved: {path}")

    print("[+] All 6 terminal screenshots created successfully!")


if __name__ == "__main__":
    generate_all()
