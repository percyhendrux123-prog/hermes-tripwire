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

BASE = Path(os.environ.get("TRIPWIRE_DIR") or Path.home() / ".hermes" / "tripwire")
EVENTS = Path(os.environ.get("TRIPWIRE_EVENTS") or BASE / "events.jsonl").expanduser()
if EVENTS.name.casefold() in {"notify-offset", "test_block"}:
    raise ValueError("TRIPWIRE_EVENTS uses a reserved cursor/drill filename")

# Blocks that are housekeeping, not security.
IGNORE_ERROR_TYPES = {"suspected_pruned_tool_arguments"}
# Typo-level rejections: the model sent a wrong or missing argument name and the
# call was bounced before running. Not a refused action; the agent retries.
# Match only the host's typo rejection category and complete message templates.
# Keep this pattern in sync with the optional standalone notifier.
ARGUMENT_REJECTION = re.compile(
    r"tool_call to '[A-Za-z0-9_.:/-]+' (?:"
    r'failed argument validation at arguments(?:\.[A-Za-z_][A-Za-z0-9_]*|\[(?:\d+|"(?:[^\x00-\x1f"\\]|\\(?:["\\/bfnrt]|u[0-9A-Fa-f]{4}))*")\])* '
    r"\([A-Za-z]+\): [^\r\n]+"
    r"|is missing required argument\(s\): [\s\S]*)\. The tool was NOT invoked\."
)
TRIP_CHOICES = {"deny", "denied", "smart_deny", "blocked", "cancelled", "timeout"}


def _is_argument_rejection(message):
    """Recognize bare, tool_error JSON and sequentially flattened host errors.

    Kept identical in the standalone notifier, which is downloaded separately.
    Unknown or malformed wrappers fail noisy rather than hiding a policy block.
    """
    if not isinstance(message, str):
        return False
    if message.lstrip().startswith("{"):
        try:
            payload = json.loads(message)
        except (ValueError, RecursionError):
            return False
        message = payload.get("error") if isinstance(payload, dict) else None
        if not isinstance(message, str):
            return False
    # Split before matching so a repeated marker cannot turn a malformed schema
    # trailer into validation detail and bypass wrapper checks.
    error, marker, trailer = message.partition(". The tool was NOT invoked.")
    if not marker or ARGUMENT_REJECTION.fullmatch(error + marker) is None:
        return False
    if not trailer:
        return True
    prefix = " Parameters schema: "
    if not trailer.startswith(prefix):
        return False
    schema = trailer[len(prefix):]
    try:
        parameters, end = json.JSONDecoder().raw_decode(schema)
    except (ValueError, RecursionError):
        return False
    return (isinstance(parameters, dict) and schema[end:] ==
            ". Retry tool_call with 'arguments' matching the parameters schema above.")


def _identifier(value):
    """Keep host identifiers, not free-form messages or truncated content."""
    if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.:/-]{0,79}", value):
        return value
    return "unknown"


def private_directory(path: Path) -> None:
    """Create missing data directories privately; tighten the data directory."""
    missing = []
    parent = path
    while not parent.exists():
        missing.append(parent)
        parent = parent.parent
    for directory in reversed(missing):
        directory.mkdir(mode=0o700, exist_ok=True)
        directory.chmod(0o700)
    path.chmod(0o700)


def write_event(event: dict, path: Path = EVENTS) -> None:
    private_directory(path.parent)
    line = json.dumps(event, ensure_ascii=False) + "\n"
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as f:
        os.fchmod(f.fileno(), 0o600)
        fcntl.flock(f, fcntl.LOCK_EX)
        f.write(line)
        f.flush()
        fcntl.flock(f, fcntl.LOCK_UN)


def from_tool_call(profile, *, tool_name, status, error_type=None, error_message=None,
                   session_id=None, now=None):
    """post_tool_call -> event, or None when this call is not a trip."""
    if status != "blocked":
        return None
    if error_type in IGNORE_ERROR_TYPES:
        return None
    if error_type == "tool_scope_block" and _is_argument_rejection(error_message):
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
