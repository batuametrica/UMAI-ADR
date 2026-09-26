"""
Parser for Warp Terminal logs.
Reads SQLite database from the Warp application data directory.

Supports macOS path. Linux support can be added when Warp provides Linux paths.
"""

import json
import sqlite3
import traceback
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..schemas.agent_event_schema import AgentEvent, ChatMessage, ToolUsage
from ..utils.timestamp_utils import normalize_timestamp
from .base_parser import BaseParser


class WarpParser(BaseParser):
    """Parser for Warp Terminal SQLite database."""

    def __init__(self, max_age_days: Optional[int] = None):
        super().__init__(max_age_days)
        # UMAI: macOS only. Windows (and Linux) are unsupported/unverified —
        # Warp's Windows data path has not been confirmed, so support is
        # deferred (go-live decision D5). On Windows this path never exists.
        self.base_path = Path.home() / "Library/Application Support/dev.warp.Warp-Stable"
        self.db_path = self.base_path / "warp.sqlite"

    def parse_all(self) -> List[AgentEvent]:
        """Parse all available Warp Terminal logs."""
        entries = []

        db_path = Path(self.db_path) if isinstance(self.db_path, str) else self.db_path

        if not db_path.exists():
            print(f"[WARP] No logs found at {db_path}")
            return entries

        print(f"[WARP] Reading logs from {db_path}")

        try:
            conn = sqlite3.connect(str(db_path))
            conn.row_factory = sqlite3.Row

            conversations = self._get_all_conversations(conn)
            print(f"[WARP] Found {len(conversations)} conversations")

            recent = [c for c in conversations if self._is_recent(self._last_modified(c))]
            self._report_skipped("WARP", len(conversations) - len(recent), "conversations")

            for conversation in recent:
                conversation_id = conversation["conversation_id"]
                try:
                    exchanges = self._get_conversation_exchanges(conn, conversation_id)
                    entry = self._create_entry_from_exchanges(conversation_id, exchanges)
                    if entry and entry.has_meaningful_content():
                        entries.append(entry)
                except Exception as e:
                    print(f"[WARP] Error processing conversation {conversation_id}: {e}")

            conn.close()

        except Exception as e:
            print(f"[WARP] Error reading database: {e}")
            traceback.print_exc()

        return entries

    @staticmethod
    def _last_modified(conversation: Dict) -> Optional[datetime]:
        """`last_modified_at` as UTC, or None when absent or unparseable."""
        value = conversation.get("last_modified_at")
        if value is None or value == "":
            return None
        try:
            return normalize_timestamp(value)
        except (ValueError, TypeError, OverflowError, OSError):
            return None

    def _get_all_conversations(self, conn) -> List[Dict]:
        """Get all conversations from the database."""
        cursor = conn.cursor()
        cursor.execute("""
            SELECT conversation_id, conversation_data, last_modified_at
            FROM agent_conversations
            ORDER BY last_modified_at DESC
        """)
        return [dict(row) for row in cursor.fetchall()]

    def _get_conversation_exchanges(self, conn, conversation_id: str) -> List[Dict]:
        """Get all exchanges for a conversation with LLM output."""
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT q.exchange_id, q.conversation_id, q.start_ts, q.input, q.working_directory,
                   q.output_status, q.model_id, b.output as llm_output
            FROM ai_queries q
            LEFT JOIN ai_blocks b ON q.exchange_id = b.exchange_id
            WHERE q.conversation_id = ?
            ORDER BY q.start_ts ASC
        """,
            (conversation_id,),
        )
        return [dict(row) for row in cursor.fetchall()]

    def _create_entry_from_exchanges(
        self, conversation_id: str, exchanges: List[Dict]
    ) -> Optional[AgentEvent]:
        """Create an AgentEvent from a conversation's exchanges."""
        if not exchanges:
            return None

        try:
            sorted_exchanges = sorted(exchanges, key=lambda x: x["start_ts"], reverse=True)
            most_recent = sorted_exchanges[0]
            timestamp = normalize_timestamp(most_recent["start_ts"])

            entry = AgentEvent(
                timestamp=timestamp,
                source="warp",
                session_id=f"warp_{conversation_id}",
                project_path=most_recent.get("working_directory"),
                model=most_recent.get("model_id"),
                raw_log_path=str(self.db_path),
            )

            for exchange in exchanges:
                exchange_id = exchange["exchange_id"]
                input_data = self._parse_json_safely(exchange["input"])
                llm_output = self._parse_json_safely(exchange.get("llm_output", "{}"))

                if not input_data or len(input_data) == 0:
                    continue

                sequence_id = exchange_id
                first_item = input_data[0]

                if "Query" in first_item:
                    query = first_item["Query"]
                    text = query.get("text", "")
                    if text:
                        msg = ChatMessage(role="user", content=text, tools=[], sequence_id=sequence_id)
                        entry.chat_history.append(msg)

                elif "ActionResult" in first_item:
                    action_result = first_item["ActionResult"]
                    tools = []

                    tool = self._parse_tool_usage(action_result)
                    if tool:
                        tools.append(tool)

                    content = self._extract_llm_text(llm_output) or self._extract_content_from_action(action_result)

                    msg = ChatMessage(
                        role="assistant",
                        content=content or "[Assistant used tools]",
                        tools=tools,
                        sequence_id=sequence_id,
                    )
                    entry.chat_history.append(msg)

            return entry

        except Exception as e:
            print(f"[WARP] Error creating entry for conversation {conversation_id}: {e}")
            traceback.print_exc()
            return None

    def _parse_json_safely(self, json_str: str) -> Optional[Any]:
        """Safely parse JSON string."""
        if not json_str:
            return None
        try:
            return json.loads(json_str)
        except json.JSONDecodeError:
            return None

    def _parse_tool_usage(self, action_result: Dict[str, Any]) -> Optional[ToolUsage]:
        """Parse tool usage from ActionResult."""
        try:
            if "result" in action_result and "RequestCommandOutput" in action_result["result"]:
                cmd_output = action_result["result"]["RequestCommandOutput"]["result"]

                if "Success" in cmd_output:
                    success = cmd_output["Success"]
                    command = success.get("command", "")
                    output = success.get("output", "")
                    exit_code = success.get("exit_code")

                    return ToolUsage(
                        tool_name="execute_command",
                        tool_type="terminal_command",
                        arguments={"command": command},
                        result=output,
                        status="success" if exit_code == 0 else "error",
                        error=None if exit_code == 0 else f"Exit code: {exit_code}",
                    )
                elif "Error" in cmd_output:
                    return ToolUsage(
                        tool_name="execute_command",
                        tool_type="terminal_command",
                        arguments={},
                        result=None,
                        status="error",
                        error=str(cmd_output["Error"]),
                    )

            tool_id = action_result.get("id", "unknown")
            return ToolUsage(
                tool_name=tool_id,
                tool_type="warp_tool",
                arguments=action_result.get("context", {}),
                result=str(action_result.get("result", {})),
            )

        except Exception:
            return None

    def _extract_content_from_action(self, action_result: Dict[str, Any]) -> str:
        """Extract meaningful content from action result."""
        if "result" in action_result and "RequestCommandOutput" in action_result["result"]:
            cmd_output = action_result["result"]["RequestCommandOutput"]["result"]
            if "Success" in cmd_output:
                command = cmd_output["Success"].get("command", "")
                return f"Executed: {command}"
        return ""

    def _extract_llm_text(self, llm_output: Optional[Dict[str, Any]]) -> str:
        """Extract LLM text response from ai_blocks output."""
        if not llm_output:
            return ""

        try:
            text_parts = []
            if "Received" in llm_output and "output" in llm_output["Received"]:
                for item in llm_output["Received"]["output"]:
                    if "Text" in item and "text" in item["Text"]:
                        text_parts.append(item["Text"]["text"])
                    elif "Code" in item and "code" in item["Code"]:
                        code = item["Code"]["code"]
                        language = ""
                        if "language" in item["Code"]:
                            lang_info = item["Code"]["language"]
                            if isinstance(lang_info, dict) and len(lang_info) > 0:
                                language = next(iter(lang_info.keys()), "")
                        if language:
                            text_parts.append(f"```{language.lower()}\n{code}\n```")
                        else:
                            text_parts.append(f"```\n{code}\n```")

            return "\n".join(text_parts)
        except Exception:
            return ""
