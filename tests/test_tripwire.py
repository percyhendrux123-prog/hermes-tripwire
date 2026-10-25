"""Tests for the pure logic and the notifier. Run: python3 -m unittest discover tests"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tripwire"))
import core  # noqa: E402


class CoreTests(unittest.TestCase):
    def test_allowed_tool_call_is_not_a_trip(self):
        self.assertIsNone(core.from_tool_call("ops", tool_name="terminal", status="ok"))

    def test_blocked_tool_call_is_a_trip(self):
        ev = core.from_tool_call("ops", tool_name="send_message", status="blocked",
                                 error_type="plugin_block", error_message="read-only profile",
                                 session_id="s1", now=100.0)
        self.assertEqual(ev["kind"], "tool_blocked")
        self.assertEqual(ev["tool"], "send_message")
        self.assertEqual(ev["ts"], 100.0)

    def test_housekeeping_blocks_are_ignored(self):
        self.assertIsNone(core.from_tool_call("ops", tool_name="x", status="blocked",
                                              error_type="suspected_pruned_tool_arguments"))

    def test_reason_is_cut_to_120_characters(self):
        ev = core.from_tool_call("ops", tool_name="t", status="blocked", error_message="a" * 500)
        self.assertEqual(len(ev["why"]), 120)

    def test_approval_allowed_is_not_a_trip(self):
        self.assertIsNone(core.from_approval("ops", choice="once"))

    def test_approval_denied_is_a_trip(self):
        ev = core.from_approval("ops", choice="deny", pattern_key="rm -rf", now=5.0)
        self.assertEqual(ev["kind"], "approval_refused")

    def test_write_event_appends_one_line(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "events.jsonl"
            core.write_event({"a": 1}, p)
            core.write_event({"a": 2}, p)
            self.assertEqual([json.loads(l)["a"] for l in p.read_text().splitlines()], [1, 2])


class NotifierTests(unittest.TestCase):
    def run_notify(self, d):
        env = dict(os.environ, TRIPWIRE_DIR=d)
        return subprocess.run([sys.executable, str(ROOT / "scripts" / "tripwire_notify.py")],
                              env=env, capture_output=True, text=True, check=True).stdout

    def test_silent_when_nothing_happened(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(self.run_notify(d), "")

    def test_alerts_once_then_goes_quiet(self):
        with tempfile.TemporaryDirectory() as d:
            src = (ROOT / "examples" / "events.sample.jsonl").read_text()
            (Path(d) / "events.jsonl").write_text(src)
            first = self.run_notify(d)
            self.assertIn("TRIPWIRE: 5 refused action(s)", first)
            self.assertEqual(self.run_notify(d), "")


if __name__ == "__main__":
    unittest.main()
