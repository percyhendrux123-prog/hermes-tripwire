#!/usr/bin/env python3
"""Tripwire for Claude Code: one log line per refused tool call.

Reads one JSON event on stdin and appends one line with exactly five fields
(ts, profile, kind, tool, how) to an owner-only file. Two senders exist: the
PermissionDenied settings hook (auto mode refusals), and the plugin's mod
(hooks/register.js), which sends a small pre-classified record for refusals the
settings hook cannot see. Tool arguments, commands, paths, denial text and
message text are never read into the record. Python 3 standard library only.

Fails open: whatever goes wrong, this script exits 0 and prints nothing, so it
can never block, delay-by-error or change a Claude Code session.

Ported from the Hermes Agent plugin's core (identifier rule, private
directory, locked append, symlink refusal).
"""
import json
import os
import re
import sys
import time

try:  # not available on Windows; the append below is then unlocked
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None

MAX_STDIN = 4 * 1024 * 1024  # bytes; tool input can be large, we only need names
DEFAULT_PARTS = (".claude", "tripwire", "events.jsonl")

# Claude Code hook event -> event kind. Only events that mean "a tool call was
# refused" belong here. PostToolUseFailure is not one of them: the docs say it
# does not fire for permission denials, only for calls that ran and failed.
KINDS = {"PermissionDenied": "permission_denied"}

# Records sent by the mod (hooks/register.js) carry "tripwire_mod": 1 and a
# kind/how pair that the mod already reduced to these fixed labels. Anything
# outside the table is dropped (kind) or written as "unspecified" (how), so the
# mod cannot put free text in the log even by mistake.
MOD_KINDS = {
    # decided without asking anyone: the verdict itself was "deny"
    "tool_blocked": ("deny_rule", "pretooluse_hook", "other_policy"),
    # asked, and the answer was no (or nobody could be asked)
    "permission_declined": ("user_declined", "no_approver", "dont_ask_mode"),
}


def identifier(value):
    """Keep host identifiers, not free-form messages or truncated content."""
    if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.:/-]{0,79}", value):
        return value
    return "unknown"


def how_category(reason):
    """Map the denial reason to a fixed label. The reason text is never stored."""
    if not isinstance(reason, str):
        return "unspecified"
    if reason.startswith("Auto mode could not evaluate this action"):
        return "no_verdict"
    if "Classifier unavailable" in reason:
        return "classifier_unavailable"
    if reason.startswith("["):
        return "policy_verdict"
    if "auto mode classifier" in reason:
        return "classifier_verdict"
    return "unspecified"


def events_path():
    override = os.environ.get("TRIPWIRE_FILE")
    if override:
        return os.path.expanduser(override)
    return os.path.join(os.path.expanduser("~"), *DEFAULT_PARTS)


def build_event(payload, now=None):
    """Hook payload -> the five-field event, or None when it is not a refusal."""
    if not isinstance(payload, dict):
        return None
    how = None
    marker = payload.get("tripwire_mod")
    if type(marker) is int and marker == 1:  # not True: bool is an int subclass
        kind = payload.get("kind")
        if not isinstance(kind, str) or kind not in MOD_KINDS:
            return None
        label = payload.get("how")
        how = label if isinstance(label, str) and label in MOD_KINDS[kind] else "unspecified"
    else:
        event_name = payload.get("hook_event_name")
        kind = KINDS.get(event_name) if isinstance(event_name, str) else None
        if kind is None:
            return None
        how = how_category(payload.get("reason"))
    # Profile is the subagent/agent type when the denial happened in one,
    # otherwise the main session. Claude Code has no profile concept.
    agent = payload.get("agent_type")
    return {
        "ts": now if now is not None else time.time(),
        "profile": identifier(agent) if agent else "main",
        "kind": kind,
        "tool": identifier(payload.get("tool_name")),
        "how": how,
    }


def private_directory(path):
    """Create missing directories as 0700 and tighten the data directory."""
    missing = []
    parent = path
    while not os.path.exists(parent):
        missing.append(parent)
        up = os.path.dirname(parent)
        if up == parent:
            break
        parent = up
    for directory in reversed(missing):
        os.makedirs(directory, mode=0o700, exist_ok=True)
        os.chmod(directory, 0o700)
    os.chmod(path, 0o700)


def write_event(event, path):
    private_directory(os.path.dirname(path))
    line = json.dumps(event, ensure_ascii=False) + "\n"
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as handle:
        os.fchmod(handle.fileno(), 0o600)
        if fcntl is not None:
            fcntl.flock(handle, fcntl.LOCK_EX)
        handle.write(line)
        handle.flush()
        if fcntl is not None:
            fcntl.flock(handle, fcntl.LOCK_UN)


def main():
    try:
        raw = sys.stdin.buffer.read(MAX_STDIN)
        event = build_event(json.loads(raw.decode("utf-8")))
        if event is not None:
            write_event(event, events_path())
    except BaseException:  # fail open, including odd input and storage errors
        pass
    return 0


if __name__ == "__main__":
    main()
    sys.exit(0)
