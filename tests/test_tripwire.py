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
        self.assertIn("version: 0.2.0\n", (ROOT / "tripwire" / "plugin.yaml").read_text())
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
            for name in ("notify-offset", "TEST_BLOCK", "Notify-Offset", "test_block", "DETAIL", "allowed.jsonl"):
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


HOOK_DRIVER = r"""
import json, sys
import tripwire
class Ctx:
    profile_name = "ops"
    def __init__(self): self.hooks = {}
    def register_hook(self, name, fn): self.hooks[name] = fn
ctx = Ctx(); tripwire.register(ctx)
for name, kwargs in json.load(sys.stdin):
    ctx.hooks[name](**kwargs)
"""

COMMAND = "curl --data private-argument-value https://example.invalid/secret-path"


def run_hooks(d, calls, **env_extra):
    """Run hook calls in a fresh process (paths are fixed at import) against dir d."""
    env = {k: v for k, v in os.environ.items()
           if k not in ("TRIPWIRE_DETAIL", "TRIPWIRE_GATED_TOOLS", "TRIPWIRE_EVENTS")}
    env.update(TRIPWIRE_DIR=str(d), **env_extra)
    subprocess.run([sys.executable, "-c", HOOK_DRIVER], cwd=ROOT, env=env, check=True,
                   input=json.dumps(calls), text=True, capture_output=True)


def rows(path):
    return [json.loads(line) for line in Path(path).read_text().splitlines()]


def blocked_call(**over):
    kw = dict(tool_name="terminal", status="blocked", error_type="plugin_block", session_id="sess_1",
              args={"command": COMMAND, "nested": {"items": ["abcdefgh", "x"]}, "timeout": 30},
              error_message=f"Policy denied: cannot run `{COMMAND}` here")
    kw.update(over)
    return ("post_tool_call", kw)


class DetailModeTests(unittest.TestCase):
    def test_default_off_writes_only_the_original_fields_and_no_allowed_file(self):
        with tempfile.TemporaryDirectory() as d:
            run_hooks(d, [blocked_call(), ("post_tool_call", dict(tool_name="terminal", status="ok", args={"a": "bbbbbb"})),
                          ("post_approval_response", dict(choice="once", pattern_key="p", command=COMMAND)),
                          ("post_approval_response", dict(choice="deny", pattern_key="p", command=COMMAND))])
            out = rows(Path(d) / "events.jsonl")
            self.assertEqual(len(out), 2)
            for event in out:
                self.assertEqual(set(event), {"ts", "profile", "kind", "tool", "how"})
            self.assertFalse((Path(d) / "allowed.jsonl").exists())

    def test_core_off_output_is_byte_identical_to_before(self):
        with_kw = core.from_tool_call("ops", tool_name="terminal", status="blocked", error_type="plugin_block",
                                      error_message=COMMAND, session_id="s", now=1.0, args={"command": COMMAND})
        self.assertEqual(json.dumps(with_kw),
                         '{"ts": 1.0, "profile": "ops", "kind": "tool_blocked", "tool": "terminal", "how": "plugin_block"}')

    def test_switch_env_file_and_reserved_values(self):
        with tempfile.TemporaryDirectory() as d:
            events = Path(d) / "events.jsonl"
            with patch.dict(os.environ, {}, clear=False):
                os.environ.pop("TRIPWIRE_DETAIL", None)
                self.assertFalse(core.detail_enabled(events))
                (Path(d) / "DETAIL").write_text("")
                self.assertTrue(core.detail_enabled(events))
                (Path(d) / "DETAIL").unlink()
                for value, expected in (("1", True), ("0", False), ("", False), ("true", False)):
                    os.environ["TRIPWIRE_DETAIL"] = value
                    self.assertEqual(core.detail_enabled(events), expected, value)

    def test_detail_blocked_row_fields_and_no_raw_values(self):
        with tempfile.TemporaryDirectory() as d:
            run_hooks(d, [blocked_call()], TRIPWIRE_DETAIL="1")
            (event,) = rows(Path(d) / "events.jsonl")
            self.assertEqual(set(event), {"ts", "profile", "kind", "tool", "how", "reason", "args_sha256",
                                          "arg_keys", "session"})
            self.assertEqual(event["arg_keys"], ["command", "nested", "timeout"])
            self.assertEqual(event["session"], "sess_1")
            self.assertEqual(len(event["args_sha256"]), 64)
            self.assertEqual(event["reason"], "Policy denied: cannot run `<arg>` here")
            stored = (Path(d) / "events.jsonl").read_text()
            for raw in (COMMAND, "private-argument-value", "secret-path", "example.invalid", "abcdefgh"):
                self.assertNotIn(raw, stored)

    def test_detail_file_switch_without_env(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "DETAIL").write_text("")
            run_hooks(d, [blocked_call()])
            (event,) = rows(Path(d) / "events.jsonl")
            self.assertIn("reason", event)

    def test_hash_is_stable_across_key_order_and_matches_spec(self):
        a = {"b": 1, "a": {"y": "é", "x": [1, 2]}}
        b = {"a": {"x": [1, 2], "y": "é"}, "b": 1}
        self.assertEqual(core.args_sha256(a), core.args_sha256(b))
        blob = json.dumps(a, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
        import hashlib
        self.assertEqual(core.args_sha256(a), hashlib.sha256(blob.encode()).hexdigest())
        self.assertNotEqual(core.args_sha256(a), core.args_sha256({"b": 2, "a": a["a"]}))

    def test_redaction_cases(self):
        args = {"command": "rm -rf /tmp/some-long-directory/file.txt", "n": {"l": ["hunter2pw", "ab"]}, "k": 123456}
        cases = [
            "blocked: rm -rf /tmp/some-long-directory/file.txt",              # whole value
            "blocked: '/tmp/some-long-directory/file.txt' is protected",      # token
            "blocked path ...some-long-directory/file.t... (truncated)",      # 12+ char run, partial
            "json: " + json.dumps({"error": "x /tmp/some-long-directory/file.txt \"q\""}),
            "password hunter2pw rejected",                                    # nested list value
        ]
        for text in cases:
            out = core.redact(text, args)
            for raw in ("some-long-directory", "hunter2pw", "file.t"):
                self.assertNotIn(raw, out, text)
        self.assertIn("<arg>", core.redact(cases[4], args))
        # short values are left alone; non-str reason is tolerated; cap applies after redaction
        self.assertEqual(core.redact("ab is fine", args), "ab is fine")
        self.assertEqual(core.redact(None, args), "")
        long_text = "x" * 5000 + " hunter2pw"
        self.assertEqual(len(core.redact(long_text, args)), 2000)
        self.assertEqual(len(core.redact("y" * 3000, None)), 2000)

    def test_redaction_catches_json_escaped_multiline_command(self):
        command = 'echo "top secret line one"\nprintf \'second secret line\''
        message = json.dumps({"error": f"refused: {command}"})
        out = core.redact(message, {"command": command})
        for raw in ("top secret", "secret line", "second"):
            self.assertNotIn(raw, out)

    def test_detail_off_ignores_args_even_if_passed(self):
        ev = core.from_tool_call("ops", tool_name="t", status="blocked", args={"a": "abcdefgh"}, detail=False)
        self.assertEqual(set(ev), {"ts", "profile", "kind", "tool", "how"})

    def test_detail_files_are_owner_only(self):
        with tempfile.TemporaryDirectory() as d:
            old = os.umask(0)
            try:
                run_hooks(d, [blocked_call(),
                              ("post_tool_call", dict(tool_name="terminal", status="ok", args={"a": "bbbbbb"}))],
                          TRIPWIRE_DETAIL="1")
            finally:
                os.umask(old)
            for name in ("events.jsonl", "allowed.jsonl"):
                self.assertEqual((Path(d) / name).stat().st_mode & 0o777, 0o600, name)

    def test_allowed_tool_calls_only_for_gated_tools(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "events.jsonl").write_text(json.dumps(
                {"ts": 1, "profile": "ops", "kind": "tool_blocked", "tool": "terminal", "how": "plugin_block"}) + "\n")
            ok = dict(status="ok", session_id="s2", args={"command": COMMAND})
            run_hooks(d, [("post_tool_call", dict(ok, tool_name="terminal")),
                          ("post_tool_call", dict(ok, tool_name="read_file")),
                          ("post_tool_call", dict(ok, tool_name="env_tool")),
                          blocked_call(tool_name="env_tool")],
                      TRIPWIRE_DETAIL="1", TRIPWIRE_GATED_TOOLS="env_tool, ")
            allowed = rows(Path(d) / "allowed.jsonl")
            self.assertEqual([r["tool"] for r in allowed], ["terminal", "env_tool"])
            for r in allowed:
                self.assertEqual(set(r), {"ts", "profile", "kind", "tool", "args_sha256", "arg_keys", "session"})
                self.assertEqual((r["kind"], r["arg_keys"], r["session"]), ("allowed", ["command"], "s2"))
            self.assertNotIn("private-argument-value", (Path(d) / "allowed.jsonl").read_text())
            blocked = [r for r in rows(Path(d) / "events.jsonl") if "reason" in r]
            self.assertEqual(len(blocked), 1)  # the blocked call is a trip, not an allowed row

    def test_ignored_blocks_are_not_recorded_as_allowed(self):
        with tempfile.TemporaryDirectory() as d:
            run_hooks(d, [blocked_call(error_type="suspected_pruned_tool_arguments")],
                      TRIPWIRE_DETAIL="1", TRIPWIRE_GATED_TOOLS="terminal")
            self.assertFalse((Path(d) / "allowed.jsonl").exists())
            self.assertFalse((Path(d) / "events.jsonl").exists())

    def test_gated_set_refreshes_at_most_hourly(self):
        calls = []
        gated = core.GatedTools(loader=lambda events: calls.append(1) or {"t"})
        self.assertEqual(gated.get(now=1000.0), {"t"})
        gated.get(now=1000.0 + 3599)
        self.assertEqual(len(calls), 1)
        gated.get(now=1000.0 + 3600)
        self.assertEqual(len(calls), 2)

    def test_approval_grants_are_allowed_rows_and_refusals_are_not(self):
        with tempfile.TemporaryDirectory() as d:
            kw = dict(pattern_key="script execution via heredoc", command=COMMAND, session_id="s3",
                      session_key="agent:main:telegram:dm:1")
            run_hooks(d, [("post_approval_response", dict(kw, choice="once")),
                          ("post_approval_response", dict(kw, choice="always", pattern_key=COMMAND)),
                          ("post_approval_response", dict(kw, choice="smart_approve", pattern_key="rm_rf")),
                          ("post_approval_response", dict(kw, choice="notify_failed")),
                          ("post_approval_response", dict(kw, choice="deny"))],
                      TRIPWIRE_DETAIL="1")
            allowed = rows(Path(d) / "allowed.jsonl")
            self.assertEqual([r["choice"] for r in allowed], ["once", "always", "smart_approve"])
            for r in allowed:
                self.assertEqual(set(r), {"ts", "profile", "kind", "tool", "args_sha256", "arg_keys", "session",
                                          "choice", "pattern"})
                self.assertEqual((r["kind"], r["tool"], r["session"]), ("allowed", "terminal/approval", "s3"))
            self.assertEqual(allowed[0]["pattern"], "script execution via heredoc")
            self.assertEqual(allowed[1]["pattern"], "<arg>")
            self.assertEqual(allowed[2]["pattern"], "rm_rf")
            stored = (Path(d) / "allowed.jsonl").read_text()
            for raw in (COMMAND, "private-argument-value", "secret-path", "telegram"):
                self.assertNotIn(raw, stored)
            refused = rows(Path(d) / "events.jsonl")
            self.assertEqual([r["how"] for r in refused], ["deny"])
            self.assertEqual(set(refused[0]), {"ts", "profile", "kind", "tool", "how"})

    def test_notifier_parses_detail_rows_and_ignores_extra_fields(self):
        with tempfile.TemporaryDirectory() as d:
            run_hooks(d, [blocked_call(), ("post_tool_call", dict(tool_name="terminal", status="ok", args={}))],
                      TRIPWIRE_DETAIL="1")
            result = subprocess.run([sys.executable, str(ROOT / "scripts" / "tripwire_notify.py")],
                                    env=dict(os.environ, TRIPWIRE_DIR=d), capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stderr, "")
            self.assertIn("TRIPWIRE: 1 refused action(s)", result.stdout)
            self.assertIn("ops: terminal stopped (plugin_block).", result.stdout)
            self.assertNotIn("Policy denied", result.stdout)
            self.assertNotIn("private-argument-value", result.stdout)
            self.assertEqual(result.stdout.count("\n- "), 1)

    def test_hook_failures_fail_open_in_detail_mode(self):
        with tempfile.TemporaryDirectory() as d:
            run_hooks(d, [("post_tool_call", dict(tool_name="terminal", status="blocked", args=["x", 1.5, None],
                                                  error_message=123, session_id=5)),
                          ("post_approval_response", dict(choice=["x"], command=None))],
                      TRIPWIRE_DETAIL="1")


if __name__ == "__main__":
    unittest.main()
