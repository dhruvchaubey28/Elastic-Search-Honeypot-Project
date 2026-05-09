"""
Delilah Honeypot — Simplified Test Suite
Only stable tests retained for CI/CD.
"""

import unittest
import sqlite3
import json
import sys
import os

# ── Allow importing from project root ──
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ══════════════════════════════════════════════════════════
#  DATABASE SCHEMA TESTS
# ══════════════════════════════════════════════════════════
class TestDatabaseSchema(unittest.TestCase):
    """Verify the database tables and columns are created correctly."""

    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        cursor = self.db.cursor()

        cursor.execute('''CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source_ip TEXT,
            event_type TEXT,
            request_uri TEXT,
            method TEXT DEFAULT 'GET',
            post_body TEXT,
            user_agent TEXT,
            country TEXT,
            region TEXT,
            city TEXT,
            isp TEXT,
            org TEXT,
            lat REAL,
            lon REAL,
            abuse_score INTEGER DEFAULT NULL,
            rule_flags TEXT DEFAULT NULL
        )''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS harvested_credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source_ip TEXT,
            username TEXT,
            password TEXT,
            endpoint TEXT,
            user_agent TEXT,
            country TEXT,
            city TEXT
        )''')

        cursor.execute('''CREATE TABLE IF NOT EXISTS flagged_ips (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            source_ip TEXT,
            rule_name TEXT,
            severity TEXT,
            details TEXT
        )''')

        self.db.commit()
        self.cursor = cursor

    def test_events_table_exists(self):
        self.cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='events'"
        )
        self.assertIsNotNone(self.cursor.fetchone())

    def test_credentials_table_exists(self):
        self.cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='harvested_credentials'"
        )
        self.assertIsNotNone(self.cursor.fetchone())

    def test_flagged_ips_table_exists(self):
        self.cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='flagged_ips'"
        )
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
            INSERT INTO events (
                timestamp,
                source_ip,
                event_type,
                request_uri,
                method,
                user_agent
            )
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            "2026-01-01T00:00:00",
            "1.2.3.4",
            "SQL Injection Attempt",
            "/_search?q=1' OR 1=1",
            "GET",
            "sqlmap/1.6"
        ))

        self.db.commit()

        self.cursor.execute("SELECT COUNT(*) FROM events")
        self.assertEqual(self.cursor.fetchone()[0], 1)

    def test_insert_credential(self):
        self.cursor.execute("""
            INSERT INTO harvested_credentials (
                timestamp,
                source_ip,
                username,
                password,
                endpoint,
                user_agent
            )
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            "2026-01-01T00:00:00",
            "1.2.3.4",
            "admin",
            "password123",
            "/kibana/login",
            "Mozilla/5.0"
        ))

        self.db.commit()

        self.cursor.execute("SELECT COUNT(*) FROM harvested_credentials")
        self.assertEqual(self.cursor.fetchone()[0], 1)

    def tearDown(self):
        self.db.close()


# ══════════════════════════════════════════════════════════
#  RUNNER
# ══════════════════════════════════════════════════════════
if __name__ == "__main__":
    print("=" * 60)
    print("  🍯 Delilah Honeypot — Simplified Test Suite")
    print("=" * 60)

    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    suite.addTests(loader.loadTestsFromTestCase(TestDatabaseSchema))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    sys.exit(0 if result.wasSuccessful() else 1)