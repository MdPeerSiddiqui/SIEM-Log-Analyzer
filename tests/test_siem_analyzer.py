#!/usr/bin/env python3
"""
Unit Tests for PEER'S SIEM Log Analyzer
Sqrock IT Solutions - Cybersecurity Internship Phase 1 (Day 13)
"""

import os
import sys
import unittest
import json

# Add parent directory to path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE_DIR)

from siem_analyzer import SIEMLogAnalyzer, haversine_distance


class TestSIEMAnalyzer(unittest.TestCase):
    """Test suite for SIEM log parsing, correlation rules, and reporting."""

    def setUp(self):
        self.analyzer = SIEMLogAnalyzer()
        self.analyzer.load_logs()
        self.analyzer.parse_events()

    def test_log_ingestion(self):
        """Test that the log file is successfully loaded and non-empty."""
        self.assertGreater(len(self.analyzer.raw_events), 15)

    def test_multi_source_parsing(self):
        """Test normalization across Windows, Exchange, VPN, and Squid proxy logs."""
        sources = set([e["source"] for e in self.analyzer.parsed_events])
        self.assertIn("Windows-Security", sources)
        self.assertIn("MSExchange-Audit", sources)
        self.assertIn("VPN-Gateway", sources)
        self.assertIn("WebProxy-Squid", sources)

    def test_brute_force_detection(self):
        """Test brute force correlation rule for failed login clusters."""
        alerts = self.analyzer.detect_brute_force(threshold=3)
        self.assertGreaterEqual(len(alerts), 1)
        # Check IP or user in alert
        ips = [a["details"]["attacker_ip"] for a in alerts]
        self.assertTrue(any("198.51.100.42" in ip for ip in ips))

    def test_suspicious_forwarding_rules(self):
        """Test detection of malicious inbox auto-forwarding exfiltration rules."""
        alerts = self.analyzer.detect_suspicious_forwarding_rules()
        self.assertGreaterEqual(len(alerts), 1)
        rule_targets = [a["details"]["forward_destination"] for a in alerts]
        self.assertTrue(any("attacker-drop@proton.me" in t or "shadow-recon@darknet.org" in t for t in rule_targets))

    def test_impossible_travel_haversine(self):
        """Test Haversine distance math and impossible travel velocity alert."""
        # Distance NY to Tokyo is roughly 10,800 km
        dist = haversine_distance(40.7128, -74.0060, 35.6762, 139.6503)
        self.assertGreater(dist, 10000.0)
        self.assertLess(dist, 12000.0)

        travel_alerts = self.analyzer.detect_impossible_travel(max_speed_kmh=800.0)
        self.assertGreaterEqual(len(travel_alerts), 1)
        self.assertEqual(travel_alerts[0]["severity"], "CRITICAL")
        self.assertIn("m.siddiqui", travel_alerts[0]["details"]["user"])

    def test_account_takeover_chain_and_export(self):
        """Test full multi-stage ATO detection and JSON/TXT audit export."""
        ato_alerts = self.analyzer.detect_account_takeover()
        self.assertGreaterEqual(len(ato_alerts), 1)
        
        all_alerts = self.analyzer.correlate_all()
        self.assertGreaterEqual(len(all_alerts), 3)

        # Test export
        summary = self.analyzer.export_reports()
        self.assertIn("CRITICAL", summary["severity_counts"])
        self.assertGreaterEqual(summary["severity_counts"]["CRITICAL"], 1)

        json_path = os.path.join(BASE_DIR, "alerts", "siem_alert_report.json")
        txt_path = os.path.join(BASE_DIR, "alerts", "siem_triage_summary.txt")
        self.assertTrue(os.path.exists(json_path))
        self.assertTrue(os.path.exists(txt_path))


if __name__ == "__main__":
    unittest.main()
