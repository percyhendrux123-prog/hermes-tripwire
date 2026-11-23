"""Tripwire core: pure logic, no Hermes imports.

Records one line per refused action. Never stores tool arguments, commands,
results or message text: only who, which tool, how it was stopped, and when.

Opt-in detail mode (OFF by default; env TRIPWIRE_DETAIL=1 or a file named
DETAIL beside the event file) adds a redacted refusal ``reason``, a hash and
the names of the arguments, and an ``allowed.jsonl`` log. Raw argument values
are never stored in either mode.
"""
import fcntl
import hashlib
import json
import os
import re
import time
from pathlib import Path

BASE = Path(os.environ.get("TRIPWIRE_DIR") or Path.home() / ".hermes" / "tripwire")
EVENTS = Path(os.environ.get("TRIPWIRE_EVENTS") or BASE / "events.jsonl").expanduser()
if EVENTS.name.casefold() in {"notify-offset", "test_block", "detail", "allowed.jsonl"}:
    raise ValueError("TRIPWIRE_EVENTS uses a reserved cursor/drill filename")

# Blocks that are housekeeping, not security.
IGNORE_ERROR_TYPES = {"suspected_pruned_tool_arguments"}
# Typo-level rejections: the model sent a wrong or missing argument name and the
# call was bounced before running. Not a refused action; the agent retries.
# Match only the host's typo rejection category and complete message templates.
# Keep this pattern in sync with the optional standalone notifier.
ARGUMENT_REJECTION = re.compile(
    r"tool_call to '[A-Za-z0-9_.:/-]+' (?:"
    r'failed argument validation at arguments(?:\.[A-Za-z_][A-Za-z0-9_]*|\[(?:[0-9]+|"(?:[^\x00-\x1f"\\]|\\(?:["\\/bfnrt]|u[0-9A-Fa-f]{4}))*")\])* '
    r"\([A-Za-z]+\): [^\r\n]+?"
    r"|is missing required argument\(s\): [\s\S]*?)\. The tool was NOT invoked\."
)
TRIP_CHOICES = {"deny", "denied", "smart_deny", "blocked", "cancelled", "timeout"}
# Approval outcomes that are neither a grant nor a refusal (delivery failed).
NOT_A_GRANT = {"notify_failed"}

REASON_CAP = 2000
MIN_SECRET = 4          # string argument values shorter than this are not redacted
LONG_VALUE = 12         # long values also have any 12+ char run redacted
GATED_REFRESH_SECONDS = 3600


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
    # Parse the header/path before finding the terminator (it can occur inside
    # a quoted property name). Lazy detail prevents swallowing a bad trailer.
    match = ARGUMENT_REJECTION.match(message)
    if match is None:
        return False
    trailer = message[match.end():]
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


# ---------------------------------------------------------------- detail mode

def detail_enabled(events: Path = None) -> bool:
    """Opt-in switch: env TRIPWIRE_DETAIL=1, or a DETAIL file beside the event file."""
    if os.environ.get("TRIPWIRE_DETAIL") == "1":
        return True
    try:
        return (Path(events or EVENTS).parent / "DETAIL").is_file()
    except OSError:
        return False


def allowed_path(events: Path = None) -> Path:
    return Path(events or EVENTS).parent / "allowed.jsonl"


def _walk_strings(value, depth=0):
    """Yield every string value (not key) in nested dicts/lists/tuples."""
    if depth > 50:
        return
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _walk_strings(item, depth + 1)
    elif isinstance(value, (list, tuple, set, frozenset)):
        for item in value:
            yield from _walk_strings(item, depth + 1)


def _variants(text):
    """The text as written, and as it would appear inside a JSON string."""
    out = {text}
    for ascii_only in (False, True):
        out.add(json.dumps(text, ensure_ascii=ascii_only)[1:-1])
    return out


def redact(text, args, cap=REASON_CAP):
    """Replace anything quoted from a string argument value with ``<arg>``, then cap.

    Every string value of length >= 4 (recursively), each whitespace-separated
    token of it of length >= 4, and any 12+ char run of a long value found in the
    text are replaced. Values are matched as written and JSON-escaped.
    """
    text = text if isinstance(text, str) else ("" if text is None else str(text))
    text = text[:20000]  # bound the work; the final cap is far below this
    needles = set()
    long_values = []
    for value in _walk_strings(args):
        if len(value) < MIN_SECRET:
            continue
        needles |= _variants(value)
        for token in value.split():
            if len(token) >= MIN_SECRET:
                needles |= _variants(token)
        if len(value) >= LONG_VALUE:
            long_values.append(value[:20000])
    for needle in sorted(needles, key=len, reverse=True):
        text = text.replace(needle, "<arg>")
    for value in long_values:
        for form in _variants(value):
            grams = {form[i:i + LONG_VALUE] for i in range(len(form) - LONG_VALUE + 1)}
            spans, run = [], None
            for i in range(len(text) - LONG_VALUE + 1):
                if text[i:i + LONG_VALUE] in grams:
                    run = [run[0], i + LONG_VALUE] if run else [i, i + LONG_VALUE]
                elif run:
                    spans.append(run)
                    run = None
            if run:
                spans.append(run)
            for start, end in reversed(spans):
                text = text[:start] + "<arg>" + text[end:]
    return text[:cap]


def args_sha256(args):
    try:
        blob = json.dumps(args, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
        return hashlib.sha256(blob.encode("utf-8", "surrogatepass")).hexdigest()
    except Exception:
        return None


def arg_keys(args):
    if not isinstance(args, dict):
        return []
    return sorted(_identifier(k) for k in args)


def _session(session_id):
    return _identifier(session_id) if session_id else "unknown"


def detail_fields(args, *, session_id=None):
    return {"args_sha256": args_sha256(args), "arg_keys": arg_keys(args), "session": _session(session_id)}


def load_gated_tools(events: Path = None):
    """Tool names seen in any event row, plus env TRIPWIRE_GATED_TOOLS (comma list)."""
    names = set()
    try:
        with open(events or EVENTS, "rb") as f:
            for line in f:
                try:
                    row = json.loads(line.decode("utf-8"))
                except (UnicodeDecodeError, ValueError, RecursionError):
                    continue
                if isinstance(row, dict) and isinstance(row.get("tool"), str):
                    tool = _identifier(row["tool"])
                    if tool != "unknown":
                        names.add(tool)
    except OSError:
        pass
    for tool in (os.environ.get("TRIPWIRE_GATED_TOOLS") or "").split(","):
        tool = tool.strip()
        if tool and _identifier(tool) != "unknown":
            names.add(tool)
    return names


class GatedTools:
    """Cached gated-tool set; re-read from the event file at most hourly."""

    def __init__(self, events: Path = None, loader=load_gated_tools):
        self.events, self.loader, self.loaded_at, self.names = events, loader, None, set()

    def get(self, now=None):
        now = now if now is not None else time.time()
        if self.loaded_at is None or now - self.loaded_at >= GATED_REFRESH_SECONDS:
            self.names, self.loaded_at = self.loader(self.events), now
        return self.names


def from_tool_call(profile, *, tool_name, status, error_type=None, error_message=None,
                   session_id=None, now=None, args=None, detail=False):
    """post_tool_call -> event, or None when this call is not a trip."""
    if status != "blocked":
        return None
    if error_type in IGNORE_ERROR_TYPES:
        return None
    if error_type == "tool_scope_block" and _is_argument_rejection(error_message):
        return None
    event = {"ts": now if now is not None else time.time(),
             "profile": _identifier(profile), "kind": "tool_blocked",
             "tool": _identifier(tool_name), "how": _identifier(error_type)}
    if detail:
        event["reason"] = redact(error_message, args)
        event.update(detail_fields(args, session_id=session_id))
    return event


def from_approval(profile, *, choice, pattern_key=None, surface=None, session_key=None, now=None):
    """post_approval_response -> event, or None when the action was allowed."""
    if str(choice) not in TRIP_CHOICES:
        return None
    return {"ts": now if now is not None else time.time(),
            "profile": _identifier(profile), "kind": "approval_refused",
            "tool": "terminal/approval", "how": choice}


def allowed_from_tool_call(profile, *, tool_name, status, args=None, session_id=None,
                           gated=(), now=None):
    """Detail mode: a non-blocked call to a gated tool -> allowed row, else None."""
    if status == "blocked" or _identifier(tool_name) not in gated:
        return None
    return dict({"ts": now if now is not None else time.time(),
                 "profile": _identifier(profile), "kind": "allowed",
                 "tool": _identifier(tool_name)}, **detail_fields(args, session_id=session_id))


def allowed_from_approval(profile, *, choice, pattern_key=None, command=None, session_id=None,
                          session_key=None, now=None):
    """Detail mode: an approval that was granted (once/session/always...) -> allowed row.

    ``command`` is only hashed and used for redaction; it is never stored.
    """
    if not isinstance(choice, str) or choice in TRIP_CHOICES or choice in NOT_A_GRANT:
        return None
    pattern = pattern_key if isinstance(pattern_key, str) else ""
    pattern = pattern if _identifier(pattern) != "unknown" else redact(pattern, {"c": command}, cap=120)
    args = {"command": command}
    event = {"ts": now if now is not None else time.time(),
             "profile": _identifier(profile), "kind": "allowed", "tool": "terminal/approval",
             "args_sha256": args_sha256(args), "arg_keys": ["command"],
             "session": _session(session_id or session_key),
             "choice": _identifier(choice), "pattern": pattern}
    return event
