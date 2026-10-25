"""Tripwire: record every refused agent action so the owner gets alerted.

Observer only (fails open). The single exception is the test switch file
~/.hermes/tripwire/TEST_BLOCK ("<profile> <tool>"), used to prove the alarm.
"""
import logging
from pathlib import Path

from .core import from_approval, from_tool_call, write_event

log = logging.getLogger(__name__)
TEST_FLAG = Path.home() / ".hermes" / "tripwire" / "TEST_BLOCK"


def register(ctx):
    profile = getattr(ctx, "profile_name", None) or "default"

    def post_tool_call(**kw):
        try:
            ev = from_tool_call(profile, tool_name=kw.get("tool_name"), status=kw.get("status"),
                                error_type=kw.get("error_type"), error_message=kw.get("error_message"),
                                session_id=kw.get("session_id"))
            if ev:
                write_event(ev)
        except Exception as exc:  # fail open
            log.debug("tripwire post_tool_call: %s", exc)

    def post_approval_response(**kw):
        try:
            ev = from_approval(profile, choice=kw.get("choice"), pattern_key=kw.get("pattern_key"),
                               surface=kw.get("surface"), session_key=kw.get("session_key"))
            if ev:
                write_event(ev)
        except Exception as exc:
            log.debug("tripwire post_approval_response: %s", exc)

    def pre_tool_call(**kw):
        # Test switch only: a file holding "<profile> <tool>" blocks that one tool
        # in that one profile, so the alarm can be proven end to end. Delete the
        # file to turn it off. No file = this hook does nothing.
        try:
            parts = TEST_FLAG.read_text().split() if TEST_FLAG.exists() else []
        except Exception:
            parts = []
        test = parts[1] if len(parts) == 2 and parts[0] == profile else None
        if test and kw.get("tool_name") == test:
            return {"action": "block", "message": f"tripwire test: {test} is not permitted"}
        return None

    ctx.register_hook("post_tool_call", post_tool_call)
    ctx.register_hook("post_approval_response", post_approval_response)
    ctx.register_hook("pre_tool_call", pre_tool_call)
