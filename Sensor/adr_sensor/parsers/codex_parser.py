"""
Parser for OpenAI Codex CLI logs.
Reads JSONL files from $CODEX_HOME/sessions, else ~/.codex/sessions/
"""

import json
import traceback
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .. import platform_paths
from ..schemas.agent_event_schema import AgentEvent, ChatMessage, ToolUsage
from ..utils.string_utils import truncate_middle
from ..utils.timestamp_utils import normalize_timestamp
from .base_parser import BaseParser


class CodexParser(BaseParser):
    """Parser for OpenAI Codex CLI JSONL log files."""

    def __init__(self, max_age_days: Optional[int] = None, base_path: Optional[str] = None):
        super().__init__(max_age_days)
        # UMAI: honour CODEX_HOME. The ~/.codex default is kept for the
        # "No logs found" message when nothing exists.
        if base_path:
            self.base_path = Path(base_path)
        else:
            found = platform_paths.codex_sessions()
            self.base_path = found[0] if found else Path.home() / ".codex/sessions"

    def parse_all(self) -> List[AgentEvent]:
        """Parse all available Codex logs."""
        entries = []

        if not self.base_path.exists():
            print(f"[CODEX] No logs found at {self.base_path}")
            return entries

        jsonl_files = list(self.base_path.glob("**/*.jsonl"))
        print(f"[CODEX] Found {len(jsonl_files)} JSONL files")

        # UMAI: rollout files are appended while a session runs, so mtime is
        # the last-activity time.
        recent_files = [f for f in jsonl_files if self._is_recent_mtime(f)]
        self._report_skipped("CODEX", len(jsonl_files) - len(recent_files), "files")

        for jsonl_file in recent_files:
            try:
                entry = self.parse_jsonl_file(jsonl_file)
                if entry and entry.has_meaningful_content():
                    entries.append(entry)
            except Exception as e:
                print(f"[CODEX] Error parsing {jsonl_file}: {e}")

        return entries

    def parse_jsonl_file(self, file_path: Path) -> Optional[AgentEvent]:
        """Parse a single JSONL file."""
        try:
            session_data: Dict[str, Any] = {
                "id": None,
                "timestamp": None,
                "cwd": None,
                "model": None,
                "messages": [],
                "pending_tool_calls": {},
            }

            with open(file_path, encoding="utf-8") as file:
                for line in file:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                        self._process_event(event, session_data)
                    except json.JSONDecodeError:
                        continue

            if not session_data["id"]:
                return None

            chat_history = []
            for i, msg_dict in enumerate(session_data["messages"]):
                tools = [
                    ToolUsage(
                        tool_name=tool_dict["tool_name"],
                        tool_type=tool_dict["tool_type"],
                        arguments=tool_dict["arguments"],
                        result=tool_dict.get("result"),
                        status=tool_dict.get("status"),
                        error=tool_dict.get("error"),
                    )
                    for tool_dict in msg_dict["tools"]
                ]

                sequence_id = f"{session_data['id']}_msg_{i}"

                chat_history.append(
                    ChatMessage(
                        role=msg_dict["role"],
                        content=msg_dict["content"],
                        tools=tools,
                        sequence_id=sequence_id,
                    )
                )

            return AgentEvent(
                timestamp=session_data["timestamp"] or datetime.now(timezone.utc),
                source="codex",
                session_id=f"codex_{session_data['id']}",
                project_path=session_data["cwd"],
                model=session_data["model"],
                chat_history=chat_history,
                raw_log_path=str(file_path),
            )

        except Exception as e:
            print(f"[CODEX] Error reading {file_path}: {e}")
            traceback.print_exc()
            return None

    def _truncate_large_arguments(self, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Truncate large string values in tool arguments."""
        if not isinstance(arguments, dict):
            return arguments

        truncated = {}
        for key, value in arguments.items():
            if isinstance(value, str) and len(value) > 1000:
                truncated[key] = truncate_middle(value, max_length=1000, edge_chars=400)
            else:
                truncated[key] = value

        return truncated

    def _process_event(self, event: Dict[str, Any], session_data: Dict[str, Any]):
        """Process a single event."""
        evt_type = event.get("type")
        payload = event.get("payload", {})

        if evt_type == "session_meta":
            session_data["id"] = payload.get("id")
            if payload.get("timestamp"):
                session_data["timestamp"] = normalize_timestamp(payload.get("timestamp"))
            session_data["cwd"] = payload.get("cwd")

        elif evt_type == "turn_context":
            if payload.get("model"):
                session_data["model"] = payload.get("model")

        elif evt_type == "response_item":
            item_type = payload.get("type")

            if item_type == "message":
                role = payload.get("role")
                content_list = payload.get("content", [])
                text_content = ""
                for content_item in content_list:
                    if content_item.get("type") in ["input_text", "output_text"]:
                        text_content += content_item.get("text", "")

                if text_content:
                    session_data["messages"].append({"role": role, "content": text_content, "tools": []})

            elif item_type == "function_call":
                call_id = payload.get("call_id")
                tool_name = payload.get("name")
                arguments_str = payload.get("arguments", "{}")
                try:
                    arguments = json.loads(arguments_str)
                except json.JSONDecodeError:
                    arguments = {"raw": arguments_str}

                arguments = self._truncate_large_arguments(arguments)

                tool_dict = {
                    "tool_name": tool_name,
                    "tool_type": "function_call",
                    "arguments": arguments,
                    "status": "pending",
                    "result": None,
                }

                if not session_data["messages"] or session_data["messages"][-1]["role"] != "assistant":
                    session_data["messages"].append({"role": "assistant", "content": "", "tools": []})

                session_data["messages"][-1]["tools"].append(tool_dict)
                session_data["pending_tool_calls"][call_id] = tool_dict

            elif item_type == "function_call_output":
                call_id = payload.get("call_id")
                output = payload.get("output")

                if output and isinstance(output, str):
                    output = truncate_middle(output, max_length=1000, edge_chars=400)

                if call_id in session_data["pending_tool_calls"]:
                    tool_dict = session_data["pending_tool_calls"][call_id]
                    tool_dict["result"] = output
                    tool_dict["status"] = "success"

            elif item_type == "reasoning":
                summary_list = payload.get("summary", [])
                reasoning_text = ""
                for summary_item in summary_list:
                    if summary_item.get("type") == "summary_text":
                        reasoning_text += summary_item.get("text", "") + "\n"

                if reasoning_text:
                    if (
                        not session_data["messages"]
                        or session_data["messages"][-1]["role"] != "assistant"
                        or session_data["messages"][-1]["tools"]
                    ):
                        session_data["messages"].append({"role": "assistant", "content": "", "tools": []})

                    current_content = session_data["messages"][-1]["content"]
                    if current_content:
                        session_data["messages"][-1]["content"] = (
                            current_content + "\n\n[Reasoning]\n" + reasoning_text
                        )
                    else:
                        session_data["messages"][-1]["content"] = "[Reasoning]\n" + reasoning_text
