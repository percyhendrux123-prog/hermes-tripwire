"""Tripwire core: pure logic, no Hermes imports.

Records one line per refused action. Never stores tool arguments, commands,
results or message text: only who, which tool, how it was stopped, and when.
"""
import fcntl
import json
import os
import re
import time
from pathlib import Path

EVENTS = Path(os.environ.get("TRIPWIRE_EVENTS", str(Path.home() / ".hermes" / "tripwire" / "events.jsonl")))

# Blocks that are housekeeping, not security.
IGNORE_ERROR_TYPES = {"suspected_pruned_tool_arguments"}
# Typo-level rejections: the model sent a wrong or missing argument name and the
# call was bounced before running. Not a refused action; the agent retries.
IGNORE_MESSAGE_MARKERS = ("failed argument validation", "is missing required argument")
TRIP_CHOICES = {"deny", "denied", "smart_deny", "blocked", "cancelled", "timeout"}


def _identifier(value):
    """Keep host identifiers, not free-form messages or truncated content."""
    if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.:/-]{0,79}", value):
        return value
    return "unknown"


def write_event(event: dict, path: Path = EVENTS) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    line = json.dumps(event, ensure_ascii=False) + "\n"
    with open(path, "a") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        f.write(line)
        fcntl.flock(f, fcntl.LOCK_UN)


def from_tool_call(profile, *, tool_name, status, error_type=None, error_message=None,
                   session_id=None, now=None):
    """post_tool_call -> event, or None when this call is not a trip."""
    if status != "blocked":
        return None
    if error_type in IGNORE_ERROR_TYPES:
        return None
    msg = str(error_message or "").lower()
    if any(m in msg for m in IGNORE_MESSAGE_MARKERS):
        return None
    return {"ts": now if now is not None else time.time(),
            "profile": _identifier(profile), "kind": "tool_blocked",
            "tool": _identifier(tool_name), "how": _identifier(error_type)}


def from_approval(profile, *, choice, pattern_key=None, surface=None, session_key=None, now=None):
    """post_approval_response -> event, or None when the action was allowed."""
    if str(choice) not in TRIP_CHOICES:
        return None
    return {"ts": now if now is not None else time.time(),
            "profile": _identifier(profile), "kind": "approval_refused",
            "tool": "terminal/approval", "how": choice}
