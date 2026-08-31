"""Convert a collected session into the message shape ADR's detector expects.

ADR's detector was written against benchmark conversations where tool activity
is already flattened into the message text — its triage prompt looks for tool
usage, and its reasoning workflow instructs the model to "extract MCP tool names
from TOOL CALL and TOOL RESULT lines in the transcript".

Our collector keeps tools as structured fields on each message, so they have to
be rendered back into that convention. Without this the detector sees only prose
and loses the strongest signal in an agent transcript.
"""

from __future__ import annotations

import json
from typing import Any

# Tool arguments and results can be very large. Keep enough to characterise the
# call without letting one file read dominate the triage context window.
MAX_ARG_CHARS = 2000
MAX_RESULT_CHARS = 2000


def _clip(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return f"{text[:limit]}… [{len(text) - limit} more chars]"


def _render_arguments(arguments: Any) -> str:
    if arguments in (None, {}, ""):
        return ""
    try:
        rendered = json.dumps(arguments, ensure_ascii=False, sort_keys=True)
    except (TypeError, ValueError):
        rendered = str(arguments)
    return _clip(rendered, MAX_ARG_CHARS)


def _render_tool(tool: dict[str, Any]) -> list[str]:
    name = tool.get("tool_name") or "unknown"
    server = tool.get("server_name")
    qualified = f"{server}.{name}" if server else name

    lines = [f"TOOL CALL: {qualified}({_render_arguments(tool.get('arguments'))})"]

    result = tool.get("result")
    if result:
        lines.append(f"TOOL RESULT: {_clip(str(result), MAX_RESULT_CHARS)}")

    status = tool.get("status")
    error = tool.get("error")
    if error:
        lines.append(f"TOOL ERROR: {_clip(str(error), 400)}")
    elif status and status not in ("success", "unknown"):
        lines.append(f"TOOL STATUS: {status}")

    return lines


def to_adr_messages(session: dict[str, Any]) -> list[dict[str, str]]:
    """Flatten a collected session into ADR's `[{role, content}]` messages."""
    messages: list[dict[str, str]] = []

    for message in session.get("chat_history") or []:
        parts: list[str] = []

        content = (message.get("content") or "").strip()
        if content:
            parts.append(content)

        for tool in message.get("tools") or []:
            parts.extend(_render_tool(tool))

        if parts:
            messages.append(
                {"role": message.get("role") or "unknown", "content": "\n".join(parts)}
            )

    return messages


def posture_preamble(session: dict[str, Any]) -> str | None:
    """Describe the session's permissions so the detector can weigh them.

    A transcript alone does not say whether the agent was running with approval
    prompts disabled or which MCP servers it could reach — and that context
    changes how the same tool call should be read.
    """
    posture = (session.get("session_context") or {}).get("posture")
    if not posture:
        return None

    facts = []
    if posture.get("permission_mode"):
        facts.append(f"permission mode: {posture['permission_mode']}")
    if posture.get("chrome_permission_mode"):
        facts.append(f"browser permission mode: {posture['chrome_permission_mode']}")

    servers = posture.get("remote_mcp_servers") or []
    if servers:
        names = [s.get("name") if isinstance(s, dict) else str(s) for s in servers]
        facts.append(f"connected MCP servers: {', '.join(n for n in names if n)}")

    if not facts:
        return None
    return "SESSION CONFIGURATION — " + "; ".join(facts)
