"""Tests for the mod-record path of tripwire_hook.py, and the mod's own tests.

The mod (hooks/register.js) hands the script a small pre-classified record.
These tests send such records the way the mod does and check the written line,
that only the fixed labels can reach the log, and that bad input stays quiet.
The last class runs the node:test file that drives register.js end to end.
"""
import json
import os
import shutil
import subprocess
import unittest

from test_claude_hook import FIVE, HERE, SECRET, HookTestCase, slurp

MOD_TEST = os.path.join(HERE, "test_register.mjs")


def mod_record(**over):
    record = {"tripwire_mod": 1, "kind": "tool_blocked", "how": "deny_rule",
              "tool_name": "Bash", "agent_type": None}
    record.update(over)
    return record


class TestModRecords(HookTestCase):
    def test_each_kind_and_label_is_written(self):
        table = {
            "tool_blocked": ("deny_rule", "pretooluse_hook", "other_policy"),
            "permission_declined": ("user_declined", "no_approver", "dont_ask_mode"),
        }
        for kind, labels in table.items():
            for label in labels:
                os.path.exists(self.file) and os.remove(self.file)
                done = self.run_hook(mod_record(kind=kind, how=label))
                self.assertEqual((done.returncode, done.stdout, done.stderr), (0, b"", b""))
                (row,) = self.rows()
                self.assertEqual(sorted(row), sorted(FIVE))
                self.assertEqual((row["kind"], row["how"]), (kind, label))
                self.assertEqual((row["profile"], row["tool"]), ("main", "Bash"))

    def test_agent_type_becomes_profile(self):
        self.run_hook(mod_record(agent_type="security-reviewer"))
        self.assertEqual(self.rows()[0]["profile"], "security-reviewer")

    def test_unknown_kind_is_dropped(self):
        self.run_hook(mod_record(kind="permission_denied"))
        self.run_hook(mod_record(kind="anything " + SECRET))
        self.run_hook(mod_record(kind=["tool_blocked"]))
        self.assertFalse(os.path.exists(self.file))

    def test_label_must_belong_to_its_kind(self):
        self.run_hook(mod_record(kind="tool_blocked", how="user_declined"))
        self.run_hook(mod_record(kind="permission_declined", how="deny_rule"))
        self.run_hook(mod_record(how="free text " + SECRET))
        self.run_hook(mod_record(how=None))
        rows = self.rows()
        self.assertEqual([row["how"] for row in rows], ["unspecified"] * 4)
        self.assertNotIn(SECRET, slurp(self.file))

    def test_extra_fields_never_reach_the_log(self):
        self.run_hook(mod_record(command="echo " + SECRET, reason=SECRET, tool_input={"x": SECRET},
                                 cwd="/home/example/client-project", tool_use_id="toolu_01ABC"))
        raw = slurp(self.file)
        for forbidden in (SECRET, "client-project", "toolu_", "echo"):
            self.assertNotIn(forbidden, raw)
        self.assertEqual(sorted(self.rows()[0]), sorted(FIVE))

    def test_non_identifier_tool_and_agent_become_unknown(self):
        self.run_hook(mod_record(tool_name="run " + SECRET, agent_type="a b; " + SECRET))
        row = self.rows()[0]
        self.assertEqual((row["tool"], row["profile"]), ("unknown", "unknown"))
        self.assertNotIn(SECRET, slurp(self.file))

    def test_marker_must_be_exactly_one(self):
        for marker in (0, 2, True, 1.0, "1", None):
            self.run_hook(mod_record(tripwire_mod=marker))
        self.assertFalse(os.path.exists(self.file))

    def test_mod_record_without_marker_is_not_a_hook_event(self):
        payload = mod_record()
        del payload["tripwire_mod"]
        self.run_hook(payload)
        self.assertFalse(os.path.exists(self.file))

    def test_bad_mod_input_stays_quiet(self):
        for raw in (b"", b"{", b"[]", json.dumps(mod_record(kind={"a": 1})).encode(),
                    json.dumps(mod_record(how=[1, 2])).encode()):
            done = self.run_hook(raw)
            self.assertEqual((done.returncode, done.stdout, done.stderr), (0, b"", b""))

    def test_unwritable_log_fails_open(self):
        blocker = os.path.join(self.tmp, "blocker")
        open(blocker, "w").close()
        done = self.run_hook(mod_record(), file=os.path.join(blocker, "events.jsonl"))
        self.assertEqual((done.returncode, done.stdout, done.stderr), (0, b"", b""))

    def test_log_file_stays_private(self):
        self.run_hook(mod_record())
        self.assertEqual(os.stat(self.file).st_mode & 0o777, 0o600)
        self.assertEqual(os.stat(os.path.dirname(self.file)).st_mode & 0o777, 0o700)


class TestModManifest(unittest.TestCase):
    def test_hooks_json_lists_the_module_and_keeps_the_settings_hook(self):
        path = os.path.join(os.path.dirname(HERE), "tripwire", "hooks", "hooks.json")
        with open(path, encoding="utf-8") as handle:
            hooks = json.load(handle)
        self.assertEqual(hooks["modules"], ["./register.js"])
        self.assertEqual(list(hooks["hooks"]), ["PermissionDenied"])
        self.assertTrue(os.path.isfile(os.path.join(os.path.dirname(path), "register.js")))


@unittest.skipUnless(shutil.which("node"), "node is not installed")
class TestRegisterModule(unittest.TestCase):
    def test_node_suite_passes(self):
        done = subprocess.run(["node", "--test", MOD_TEST], capture_output=True, text=True, timeout=120)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)


if __name__ == "__main__":
    unittest.main()
