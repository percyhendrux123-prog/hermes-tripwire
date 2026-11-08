#!/usr/bin/env python3
"""Tripwire notifier (Hermes cron, no agent). Prints an alert for new
refused-action events; prints nothing when there are none (= silent).
Reads ~/.hermes/tripwire/events.jsonl from a saved byte offset.
"""
import json
import math
import os
import re
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path

BASE = Path(os.environ.get("TRIPWIRE_DIR") or Path.home() / ".hermes" / "tripwire").expanduser()
EVENTS = Path(os.environ.get("TRIPWIRE_EVENTS") or BASE / "events.jsonl").expanduser()
STATE = EVENTS.parent / "notify-offset"
# Typo-level rejections (wrong/missing argument name, bounced before running).
# Kept in legacy events.jsonl files but not alerted. Mirrors tripwire/core.py.
ARGUMENT_REJECTION = re.compile(
    r"tool_call to '[A-Za-z0-9_.:/-]+' (?:"
    r"failed argument validation at arguments(?:\.[A-Za-z0-9_]+|\[\d+\])* \([A-Za-z]+\)"
    r"|is missing required argument\(s\): [A-Za-z0-9_]+(?:, [A-Za-z0-9_]+)*\.)"
)


def _is_quiet(e):
    why = e.get("why")
    return (e.get("kind") == "tool_blocked" and e.get("how") == "tool_scope_block"
            and isinstance(why, str) and ARGUMENT_REJECTION.fullmatch(why) is not None)


def _valid_event(e):
    if not isinstance(e, dict):
        return False
    if not isinstance(e.get("kind"), str) or e["kind"] not in {"tool_blocked", "approval_refused"}:
        return False
    for key in ("profile", "tool", "how"):
        value = e.get(key)
        if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.:/-]{0,79}", value):
            return False
    ts = e.get("ts")
    if type(ts) not in (int, float):
        return False
    try:
        if not math.isfinite(ts) or ts < 0:
            return False
        time.strftime("%-I:%M %p", time.localtime(ts))
    except (ValueError, OverflowError, OSError):
        return False
    return True


def _save_offset(offset):
    """Replace the cursor atomically; failed renders/writes leave it retryable."""
    STATE.parent.chmod(0o700)
    fd, name = tempfile.mkstemp(prefix=".notify-offset-", dir=STATE.parent)
    temporary = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="ascii") as f:
            os.fchmod(f.fileno(), 0o600)
            f.write(str(offset))
            f.flush()
            os.fsync(f.fileno())
        os.replace(temporary, STATE)
    finally:
        temporary.unlink(missing_ok=True)


def main():
    if not EVENTS.exists():
        return
    try:
        offset = int(STATE.read_text().strip() or 0) if STATE.exists() else 0
    except ValueError:
        offset = 0
    size = EVENTS.stat().st_size
    if offset < 0 or size < offset:  # file was rotated/cleared or cursor corrupt
        offset = 0
    if size == offset:
        return
    with open(EVENTS, "rb") as f:
        f.seek(offset)
        chunk = f.read()
    # Use byte offsets and only consume complete lines, even across UTF-8 writes.
    end = chunk.rfind(b"\n") + 1
    if not end:
        return
    events = []
    malformed = 0
    for line in chunk[:end].split(b"\n")[:-1]:
        try:
            event = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, ValueError, RecursionError):
            malformed += 1
            continue
        if not _valid_event(event):
            malformed += 1
            continue
        if not _is_quiet(event):
            events.append(event)
    if malformed:
        print(f"TRIPWIRE: skipped {malformed} malformed record(s)", file=sys.stderr, flush=True)
    if events:
        by_agent = Counter(e["profile"] for e in events)
        lines = [f"TRIPWIRE: {len(events)} refused action(s) since last check"]
        for e in events[-8:]:
            t = time.strftime("%-I:%M %p", time.localtime(e["ts"]))
            lines.append(f"- {t} {e['profile']}: {e['tool']} stopped ({e['how']}).")
        if len(events) > 8:
            lines.append(f"(+{len(events) - 8} more; by agent: {dict(by_agent)})")
        lines.append("Each of these was stopped. Say 'check the tripwire' to have your agent look into it.")
        print("\n".join(lines), flush=True)
    # Delivery beyond stdout is Hermes cron's responsibility. A crash before
    # this replace may repeat alerts, but must not silently consume them.
    _save_offset(offset + end)


if __name__ == "__main__":
    main()
