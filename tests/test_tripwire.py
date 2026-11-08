"""Tests for the pure logic and the notifier. Run: python3 -m unittest discover tests"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tripwire"))
import core  # noqa: E402
sys.path.insert(0, str(ROOT / "scripts"))
import tripwire_notify as notifier  # noqa: E402


def host_argument_messages():
    """Replay Hermes 2bd378ed1b's validation/registry/executor message builders.

    tools/tool_search_validation.py:68-71,99-101,125-133 builds the body;
    tools/registry.py:1101-1104 JSON-encodes it; agent/tool_executor.py:424-430
    flattens that JSON for sequential dispatch. No host dependency or network.
    """
    hint = "Retry tool_call with 'arguments' matching the parameters schema above."
    parameters = {"type": "object", "required": ["data"],
                  "properties": {"data": {"type": "string", "description": "café"}}}
    name = "mcp__demo__x"
    bodies = []
    for missing in (["data"], [""], ["line\nbreak", "carriage\rreturn"]):
        bodies.append((f"tool_call to '{name}' is missing required argument(s): "
                       f"{', '.join(missing)}. The tool was NOT invoked.", "arguments", "required",
                       dict(parameters, required=missing)))
    for path, constraint, detail in (
        ("arguments", "additionalProperties", "Additional properties are not allowed ('typo' was unexpected)"),
        ('arguments.items[0]["display-name"]', "type", "42 is not of type 'string'"),
        ("arguments[" + json.dumps('quote"slash\\line\ncafé', ensure_ascii=False) + "]",
         "type", "42 is not of type 'string'"),
        ('arguments["status. The tool was NOT invoked."]', "type", "42 is not of type 'string'"),
    ):
        bodies.append((f"tool_call to '{name}' failed argument validation at {path} "
                       f"({constraint}): {detail}. The tool was NOT invoked.", path, constraint, parameters))
    messages = []
    for error, path, constraint, params in bodies:
        probe = {"error": error, "path": path, "constraint": constraint,
                 "parameters": params, "hint": hint}
        flattened = (f"{probe.get('error', '')} Parameters schema: "
                     f"{json.dumps(probe.get('parameters', {}), ensure_ascii=False)}. "
                     f"{probe.get('hint', '')}").strip()
        messages.extend((error, json.dumps(probe, ensure_ascii=False), flattened))
    return messages


def policy_argument_messages():
    """Policy prefixes outside a host message or inside its JSON error field."""
    messages = []
    for message in host_argument_messages():
        messages.append(f"Policy denied: {message}")
        if message.startswith("{"):
            payload = json.loads(message)
            payload["error"] = f"Policy denied: {payload['error']}"
            messages.append(json.dumps(payload, ensure_ascii=False))
    return messages


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

    def test_host_argument_typos_are_not_trips(self):
        for msg in host_argument_messages():
            with self.subTest(message=msg):
                self.assertIsNone(core.from_tool_call("ops", tool_name="tool_call", status="blocked",
                                                     error_type="tool_scope_block", error_message=msg))

    def test_scope_block_without_typo_is_still_a_trip(self):
        self.assertIsNotNone(core.from_tool_call("ops", tool_name="tool_call", status="blocked",
                                                 error_type="tool_scope_block",
                                                 error_message="tool 'send_message' is not allowed here"))

    def test_policy_blocks_mentioning_validation_still_alert(self):
        cases = [
            ("plugin_block", "tool_call to 'x' failed argument validation at arguments (additionalProperties)"),
            ("plugin_block", "Policy denied: failed argument validation is not a bypass"),
            ("tool_scope_block", "Policy denied: tool_call to 'x' is missing required argument(s): data."),
            ("tool_scope_block", "The policy is missing required argument approval"),
        ]
        cases.extend(("plugin_block", msg) for msg in host_argument_messages())
        cases.extend(("tool_scope_block", msg) for msg in policy_argument_messages())
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "events.jsonl"
            for category, message in cases:
                with self.subTest(category=category, message=message):
                    event = core.from_tool_call("ops", tool_name="tool_call", status="blocked",
                                                error_type=category, error_message=message)
                    self.assertIsNotNone(event)
                    core.write_event(event, path)
            env = dict(os.environ, TRIPWIRE_DIR=d)
            result = subprocess.run([sys.executable, str(ROOT / "scripts" / "tripwire_notify.py")],
                                    env=env, capture_output=True, text=True, check=True)
            self.assertIn(f"TRIPWIRE: {len(cases)} refused action(s)", result.stdout)

    def test_unknown_or_malformed_argument_messages_still_alert(self):
        error = host_argument_messages()[0]
        hint = ". Retry tool_call with 'arguments' matching the parameters schema above."
        malformed = error + " Parameters schema: {}. Policy denied: approval is required. The tool was NOT invoked."
        unicode_index = ("tool_call to 'x' failed argument validation at arguments.items[١] "
                         "(type): 42 is not of type 'string'. The tool was NOT invoked.")
        cases = [
            error.removesuffix(" The tool was NOT invoked."),
            error + " Policy denied: approval is required.",
            "tool_call to 'x' failed argument validation at arguments (type)",
            json.dumps({"error": "Policy denied: approval is required.", "hint": error}),
            json.dumps({"error": None}), json.dumps({"error": [error]}),
            json.dumps([{"error": error}]), '{"error":', None, 42,
            '{"error":' + "[" * 2000 + "0" + "]" * 2000 + "}",
            error + " Parameters schema: not-json" + hint,
            error + " Parameters schema: []" + hint,
            error + ' Parameters schema: {}. Policy denied: approval is required.',
            malformed, json.dumps({"error": malformed}),
            r'''tool_call to 'x' failed argument validation at arguments["bad\q"] (type): 42 is not of type 'string'. The tool was NOT invoked.''',
            unicode_index, json.dumps({"error": unicode_index}),
            unicode_index + " Parameters schema: {}" + hint,
        ]
        with tempfile.TemporaryDirectory() as d:
            records = []
            for message in cases:
                with self.subTest(message=message):
                    event = core.from_tool_call("ops", tool_name="tool_call", status="blocked",
                                                error_type="tool_scope_block", error_message=message)
                    self.assertIsNotNone(event)
                    legacy = dict(event, why=message)
                    self.assertFalse(notifier._is_quiet(legacy))
                    records.append(legacy)
            (Path(d) / "events.jsonl").write_text("".join(json.dumps(e) + "\n" for e in records))
            result = subprocess.run([sys.executable, str(ROOT / "scripts" / "tripwire_notify.py")],
                                    env=dict(os.environ, TRIPWIRE_DIR=d), capture_output=True, text=True,
                                    check=True)
            self.assertIn(f"TRIPWIRE: {len(cases)} refused action(s)", result.stdout)
            self.assertEqual(result.stderr, "")

    def test_writer_and_standalone_notifier_patterns_stay_in_sync(self):
        self.assertEqual(core.ARGUMENT_REJECTION.pattern, notifier.ARGUMENT_REJECTION.pattern)
        self.assertEqual(core.ARGUMENT_REJECTION.flags, notifier.ARGUMENT_REJECTION.flags)

    def test_housekeeping_blocks_are_ignored(self):
        self.assertIsNone(core.from_tool_call("ops", tool_name="x", status="blocked",
                                              error_type="suspected_pruned_tool_arguments"))

    def test_events_do_not_store_command_or_argument_text(self):
        command = "curl --data private-argument https://example.invalid"
        events = [
            core.from_tool_call("ops", tool_name="terminal", status="blocked",
                                error_type="plugin_block", error_message=f"blocked: {command}",
                                session_id="s1", now=100.0),
            core.from_approval("ops", choice="deny", pattern_key=command,
                               surface="cli", session_key="s1", now=100.0),
        ]
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "events.jsonl"
            for event in events:
                core.write_event(event, path)
            stored = path.read_text()
            self.assertNotIn(command, stored)
            self.assertNotIn("private-argument", stored)
            for event in map(json.loads, stored.splitlines()):
                self.assertNotIn("why", event)
                self.assertEqual(set(event), {"ts", "profile", "kind", "tool", "how"})

    def test_non_identifier_metadata_is_not_retained(self):
        command = "curl --data private-argument https://example.invalid"
        ev = core.from_tool_call(command, tool_name=command, status="blocked",
                                 error_type=command, session_id=command)
        self.assertNotIn("private-argument", json.dumps(ev))

    def test_approval_allowed_is_not_a_trip(self):
        self.assertIsNone(core.from_approval("ops", choice="once"))

    def test_approval_denied_is_a_trip(self):
        ev = core.from_approval("ops", choice="deny", pattern_key="rm -rf", now=5.0)
        self.assertEqual(ev["kind"], "approval_refused")

    def test_event_storage_is_owner_only_even_with_permissive_umask(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "data" / "tripwire" / "events.jsonl"
            old_umask = os.umask(0)
            try:
                core.write_event({"a": 1}, path)
            finally:
                os.umask(old_umask)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
            self.assertEqual(path.parent.parent.stat().st_mode & 0o777, 0o700)

    def test_existing_event_storage_is_tightened(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "events.jsonl"
            path.write_text("")
            path.chmod(0o644)
            path.parent.chmod(0o755)
            core.write_event({"a": 1}, path)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)

    def test_write_event_appends_one_line(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "events.jsonl"
            core.write_event({"a": 1}, p)
            core.write_event({"a": 2}, p)
            self.assertEqual([json.loads(l)["a"] for l in p.read_text().splitlines()], [1, 2])


class PackagingTests(unittest.TestCase):
    def test_installed_subtree_keeps_license(self):
        self.assertEqual((ROOT / "tripwire" / "LICENSE").read_bytes(), (ROOT / "LICENSE").read_bytes())

    def test_release_and_catalog_install_documentation(self):
        self.assertIn("version: 0.1.3\n", (ROOT / "tripwire" / "plugin.yaml").read_text())
        readme = (ROOT / "README.md").read_text()
        for command in ("hermes plugins install tripwire", "hermes plugins enable tripwire"):
            self.assertIn(command, readme)
        self.assertIn("${TRIPWIRE_SHA}/scripts/tripwire_notify.py", readme)


class PathTests(unittest.TestCase):
    def test_writer_notifier_and_drill_share_path_overrides(self):
        with tempfile.TemporaryDirectory() as d:
            home = Path(d) / "home"
            base = Path(d) / "custom-data"
            custom = Path(d) / "other-data" / "refusals.jsonl"
            cases = [({}, home / ".hermes" / "tripwire" / "events.jsonl"),
                     ({"TRIPWIRE_DIR": str(base)}, base / "events.jsonl"),
                     ({"TRIPWIRE_EVENTS": str(custom)}, custom),
                     ({"TRIPWIRE_DIR": "~tripwire_nonexistent_a288_user", "TRIPWIRE_EVENTS": str(custom)}, custom),
                     ({"TRIPWIRE_DIR": str(base), "TRIPWIRE_EVENTS": str(custom)}, custom)]
            for overrides, expected in cases:
                with self.subTest(overrides=overrides):
                    env = dict(os.environ, HOME=str(home))
                    env.pop("TRIPWIRE_DIR", None)
                    env.pop("TRIPWIRE_EVENTS", None)
                    env.update(overrides)
                    code = (
                        "import json; import tripwire; from tripwire import core; "
                        "from scripts import tripwire_notify as notify; "
                        "print(json.dumps([str(core.EVENTS), str(tripwire.TEST_FLAG), "
                        "str(notify.EVENTS), str(notify.STATE)]))"
                    )
                    result = subprocess.run([sys.executable, "-c", code], cwd=ROOT, env=env,
                                            capture_output=True, text=True, check=True)
                    self.assertEqual(json.loads(result.stdout),
                                     [str(expected), str(expected.parent / "TEST_BLOCK"),
                                      str(expected), str(expected.parent / "notify-offset")])


    def test_reserved_event_filenames_are_rejected_without_modifying_data(self):
        with tempfile.TemporaryDirectory() as d:
            for name in ("notify-offset", "TEST_BLOCK", "Notify-Offset", "test_block"):
                with self.subTest(name=name):
                    path = Path(d) / name
                    original = json.dumps(core.from_tool_call("ops", tool_name="terminal", status="blocked")) + "\n"
                    path.write_text(original)
                    env = dict(os.environ, TRIPWIRE_EVENTS=str(path))
                    for command in ([sys.executable, "-c", "import tripwire"],
                                    [sys.executable, str(ROOT / "scripts" / "tripwire_notify.py")]):
                        result = subprocess.run(command, cwd=ROOT, env=env, capture_output=True, text=True)
                        self.assertNotEqual(result.returncode, 0)
                        self.assertIn("reserved", result.stderr)
                        self.assertEqual(path.read_text(), original)


class NotifierTests(unittest.TestCase):
    def run_notify(self, d):
        env = dict(os.environ, TRIPWIRE_DIR=d)
        return subprocess.run([sys.executable, str(ROOT / "scripts" / "tripwire_notify.py")],
                              env=env, capture_output=True, text=True, check=True).stdout

    def test_malformed_records_do_not_lose_valid_alerts(self):
        with tempfile.TemporaryDirectory() as d:
            event = core.from_tool_call("ops", tool_name="terminal", status="blocked", now=100.0)
            bad = [b"[]", b"null", b"42", b'"text"', b"{bad", b"\xff",
                   b"[" * 20000 + b"0" + b"]" * 20000,
                   json.dumps(dict(event, ts="not a timestamp")).encode(),
                   json.dumps(dict(event, ts=1e300)).encode(),
                   json.dumps(dict(event, profile=[])).encode(), b"{}"]
            complete = b"\n".join([json.dumps(event).encode(), *bad,
                                       json.dumps(dict(event, profile="reviewer")).encode()]) + b"\n"
            path = Path(d) / "events.jsonl"
            path.write_bytes(complete + b'{"partial":')
            result = subprocess.run([sys.executable, str(ROOT / "scripts" / "tripwire_notify.py")],
                                    env=dict(os.environ, TRIPWIRE_DIR=d), capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("TRIPWIRE: 2 refused action(s)", result.stdout)
            self.assertIn("ops: terminal", result.stdout)
            self.assertIn("reviewer: terminal", result.stdout)
            self.assertIn(f"skipped {len(bad)} malformed record(s)", result.stderr)
            self.assertEqual(int((Path(d) / "notify-offset").read_text()), len(complete))
            self.assertEqual(self.run_notify(d), "")

    def test_silent_when_nothing_happened(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(self.run_notify(d), "")

    def test_legacy_suppression_requires_category_and_message_shape(self):
        with tempfile.TemporaryDirectory() as d:
            event = core.from_tool_call("ops", tool_name="tool_call", status="blocked", now=100.0)
            records = []
            for typo in host_argument_messages():
                records.extend((dict(event, how="tool_scope_block", why=typo),
                                dict(event, how="plugin_block", why=typo)))
            records.extend(dict(event, how="tool_scope_block", why=msg)
                           for msg in policy_argument_messages())
            (Path(d) / "events.jsonl").write_text("".join(json.dumps(e) + "\n" for e in records))
            output = self.run_notify(d)
            expected = len(host_argument_messages()) + len(policy_argument_messages())
            self.assertIn(f"TRIPWIRE: {expected} refused action(s)", output)
            self.assertNotIn("The tool was NOT invoked.", output)
            self.assertEqual(self.run_notify(d), "")

    def test_output_failure_keeps_cursor_for_retry(self):
        with tempfile.TemporaryDirectory() as d:
            events = Path(d) / "events.jsonl"
            state = Path(d) / "notify-offset"
            events.write_text((ROOT / "examples" / "events.sample.jsonl").read_text())
            state.write_text("0")
            with patch.object(notifier, "EVENTS", events), patch.object(notifier, "STATE", state):
                with patch("builtins.print", side_effect=BrokenPipeError):
                    with self.assertRaises(BrokenPipeError):
                        notifier.main()
            self.assertEqual(state.read_text(), "0")
            self.assertIn("TRIPWIRE: 5 refused action(s)", self.run_notify(d))

    def test_cursor_is_atomically_replaced_after_render(self):
        with tempfile.TemporaryDirectory() as d:
            events = Path(d) / "events.jsonl"
            state = Path(d) / "notify-offset"
            events.write_text((ROOT / "examples" / "events.sample.jsonl").read_text())
            state.write_text("0")
            with patch.object(notifier, "EVENTS", events), patch.object(notifier, "STATE", state):
                with patch("builtins.print") as output, patch.object(notifier.os, "replace") as replace:
                    def check_replace(source, target):
                        output.assert_called_once()
                        self.assertEqual(state.read_text(), "0")
                        self.assertEqual(target, state)
                        self.assertEqual(int(Path(source).read_text()), events.stat().st_size)
                        raise OSError("synthetic replace failure")
                    replace.side_effect = check_replace
                    with self.assertRaises(OSError):
                        notifier.main()
                    replace.assert_called_once()
            self.assertEqual(state.read_text(), "0")
            self.assertFalse(list(Path(d).glob(".notify-offset-*")))
            self.run_notify(d)
            self.assertEqual(state.stat().st_mode & 0o777, 0o600)

    def test_partial_utf8_record_is_consumed_only_after_newline(self):
        with tempfile.TemporaryDirectory() as d:
            event = core.from_tool_call("ops", tool_name="terminal", status="blocked", now=100.0)
            record = json.dumps(dict(event, why="legacy café"), ensure_ascii=False).encode() + b"\n"
            path = Path(d) / "events.jsonl"
            split = record.index("é".encode()) + 1
            path.write_bytes(record[:split])
            self.assertEqual(self.run_notify(d), "")
            self.assertFalse((Path(d) / "notify-offset").exists())
            with path.open("ab") as f:
                f.write(record[split:])
            self.assertIn("TRIPWIRE: 1 refused action(s)", self.run_notify(d))
            self.assertEqual(int((Path(d) / "notify-offset").read_text()), len(record))
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
