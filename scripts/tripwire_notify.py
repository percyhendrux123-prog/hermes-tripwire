#!/usr/bin/env python3
"""Tripwire notifier (Hermes cron, no agent). Prints an alert for new
refused-action events; prints nothing when there are none (= silent).
Reads ~/.hermes/tripwire/events.jsonl from a saved byte offset.
"""
import json
import os
import time
from collections import Counter
from pathlib import Path

BASE = Path(os.environ.get("TRIPWIRE_DIR", str(Path.home() / ".hermes" / "tripwire")))
EVENTS = BASE / "events.jsonl"
STATE = BASE / "notify-offset"


def main():
    if not EVENTS.exists():
        return
    offset = int(STATE.read_text().strip() or 0) if STATE.exists() else 0
    size = EVENTS.stat().st_size
    if size < offset:  # file was rotated/cleared
        offset = 0
    if size == offset:
        return
    with open(EVENTS) as f:
        f.seek(offset)
        chunk = f.read()
    # only consume complete lines
    end = chunk.rfind("\n") + 1
    events = []
    for line in chunk[:end].splitlines():
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            pass
    STATE.write_text(str(offset + len(chunk[:end].encode())))
    if not events:
        return
    by_agent = Counter(e.get("profile", "?") for e in events)
    lines = [f"TRIPWIRE: {len(events)} refused action(s) since last check"]
    for e in events[-8:]:
        t = time.strftime("%-I:%M %p", time.localtime(e.get("ts", 0)))
        lines.append(f"- {t} {e.get('profile')}: {e.get('tool')} stopped ({e.get('how')}). {e.get('why', '')}".rstrip())
    if len(events) > 8:
        lines.append(f"(+{len(events) - 8} more; by agent: {dict(by_agent)})")
    lines.append("Each of these was stopped. Say 'check the tripwire' to have your agent look into it.")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
