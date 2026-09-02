"""Client-side enforcement of the tenant's collection mode.

The mode has to be applied here, before the request is built. Sending a full
transcript and letting the server drop it means the content already crossed the
network and already sat in a request buffer on a machine the tenant chose not
to send it to — the contract calls that out explicitly
(`docs/contracts/transcript-data-modes.md` §9a). The server rejects a batch
that carries content it should not have (`ADR_MODE_FORBIDS_CONTENT`, 422); that
rejection is a backstop against a mis-built collector, not the control.

Fail-safe direction is toward privacy, not toward data: a collector that could
not learn its mode runs as `posture_only`.

What survives each mode is the table in that contract, §2:

  posture_only  how the session was configured, and which tools it called
  metadata      that, plus the inventory and counting fields
  full_session  everything the parser produced

Message and tool *content* — `content`, `arguments`, `result`, `error` — only
ever leaves this machine under `full_session`. The message skeleton stays in
the lower modes on purpose: `message_count`, `tool_call_count` and the tool and
MCP-server names are all derived from it server-side, and they are exactly what
posture detection runs on.
"""

from __future__ import annotations

from typing import Any, Dict, List

MODE_POSTURE_ONLY = "posture_only"
MODE_METADATA = "metadata"
MODE_FULL_SESSION = "full_session"

MODES = (MODE_POSTURE_ONLY, MODE_METADATA, MODE_FULL_SESSION)

# Per-message and per-tool fields that carry what was actually said or returned.
_MESSAGE_CONTENT_FIELDS = ("content",)
_TOOL_CONTENT_FIELDS = ("arguments", "result", "error")

# Kept only under `metadata` and above: these name the work rather than
# describe how it was configured. `title` is not a top-level field — only the
# Claude Desktop parser produces one, inside `session_context` — so it is
# handled there.
_INVENTORY_FIELDS = ("project_path",)


def normalize(mode: Any) -> str:
    """The mode to apply, defaulting to the most restrictive one.

    Anything unrecognised — absent, misspelled, a mode from a newer server this
    collector does not implement — resolves to `posture_only`.
    """
    candidate = str(mode or "").strip().lower()
    return candidate if candidate in MODES else MODE_POSTURE_ONLY


def _redact_tool(tool: Any) -> Any:
    if not isinstance(tool, dict):
        return tool
    stripped = {k: v for k, v in tool.items() if k not in _TOOL_CONTENT_FIELDS}
    # `arguments` is a dict upstream and `{}` reads as "no arguments" rather
    # than "arguments withheld"; the server's content check treats both as
    # empty, so the shape stays valid either way.
    if "arguments" in tool:
        stripped["arguments"] = {}
    return stripped


def _redact_message(message: Any) -> Any:
    if not isinstance(message, dict):
        return message
    stripped = {k: v for k, v in message.items() if k not in _MESSAGE_CONTENT_FIELDS}
    if "content" in message:
        stripped["content"] = ""
    if isinstance(message.get("tools"), list):
        stripped["tools"] = [_redact_tool(tool) for tool in message["tools"]]
    return stripped


def redact_for_mode(payload: Dict[str, Any], mode: str) -> Dict[str, Any]:
    """Return the session payload reduced to what `mode` permits.

    The input is left untouched: callers hold parsed sessions that are also
    used for local export and for the observed-source summary, and neither
    should change because ingest is configured.
    """
    resolved = normalize(mode)
    if resolved == MODE_FULL_SESSION:
        return payload

    reduced = dict(payload)

    history: List[Any] = payload.get("chat_history") or []
    if isinstance(history, list):
        reduced["chat_history"] = [_redact_message(message) for message in history]

    if resolved == MODE_POSTURE_ONLY:
        for field in _INVENTORY_FIELDS:
            reduced.pop(field, None)
        context = reduced.get("session_context")
        if isinstance(context, dict):
            reduced["session_context"] = {
                k: v for k, v in context.items() if k != "title"
            }

    return reduced
