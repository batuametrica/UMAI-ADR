"""
Parser for Cline (Claude Dev) logs.
Reads JSON files from the Cline extension's task directories.

Scans every VS Code-family host (Cursor, VS Code, Insiders, VSCodium,
Windsurf) on Windows, macOS and Linux via platform_paths.
"""

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from .. import platform_paths
from ..schemas.agent_event_schema import AgentEvent, ChatMessage, ToolUsage
from ..utils.timestamp_utils import normalize_timestamp
from .base_parser import BaseParser


class ClineParser(BaseParser):
    """Parser for Cline (Claude Dev) logs."""

    def __init__(self, max_age_days: Optional[int] = None, base_path: Optional[str] = None):
        super().__init__(max_age_days)
        # UMAI: upstream only looked inside Cursor's globalStorage on macOS or
        # Linux. Cline installs into any VS Code-family host, so every host's
        # task store is scanned. An explicit base_path still wins.
        self.base_paths: List[Path] = (
            [Path(base_path)] if base_path else platform_paths.cline_task_roots()
        )

    @property
    def base_path(self) -> Optional[Path]:
        """First task root (single-root compatibility for upstream callers)."""
        return self.base_paths[0] if self.base_paths else None

    @base_path.setter
    def base_path(self, value) -> None:
        self.base_paths = [Path(value)] if value else []

    def parse_all(self) -> List[AgentEvent]:
        """Parse all available Cline logs."""
        entries = []

        roots = [root for root in self.base_paths if root.exists()]
        if not roots:
            where = ", ".join(str(p) for p in self.base_paths) or "any VS Code-family profile"
            print(f"[CLINE] No logs found at {where}")
            return entries

        task_dirs: List[Path] = []
        for root in roots:
            print(f"[CLINE] Scanning for logs in {root}")
            task_dirs.extend(d for d in root.iterdir() if d.is_dir())
        print(f"[CLINE] Found {len(task_dirs)} task directories")

        # UMAI: age by the conversation file's mtime — the same value
        # parse_cline_log reports as the session timestamp. A task without the
        # file is left to parse_cline_log, which ignores it.
        skipped_count = 0
        for task_dir in task_dirs:
            api_file = task_dir / "api_conversation_history.json"
            if api_file.exists() and not self._is_recent_mtime(api_file):
                skipped_count += 1
                continue
            try:
                entry = self.parse_cline_log(task_dir)
                if entry:
                    entries.append(entry)
            except Exception as e:
                print(f"[CLINE] Error parsing task {task_dir}: {e}")

        self._report_skipped("CLINE", skipped_count, "tasks")
        return entries

    def parse_cline_log(self, task_dir: Path) -> Optional[AgentEvent]:
        """Parse a single Cline task log."""
        try:
            api_file = task_dir / "api_conversation_history.json"
            if not api_file.exists():
                return None

            with open(api_file, encoding="utf-8") as f:
                conversation = json.load(f)

            if not conversation:
                return None

            # Use file modification time for timestamp
            file_mod_time = api_file.stat().st_mtime
            timestamp = datetime.fromtimestamp(file_mod_time, tz=timezone.utc)

            entry = AgentEvent(timestamp=timestamp, source="cline", session_id=f"cline_{task_dir.name}")

            for i, message in enumerate(conversation):
                role = message.get("role", "")
                content = message.get("content", [])
                sequence_id = f"msg_{i}"

                if role == "user":
                    prompt_text = self.extract_text_from_content(content)
                    if prompt_text:
                        msg = ChatMessage(role="user", content=prompt_text, tools=[], sequence_id=sequence_id)
                        entry.chat_history.append(msg)

                elif role == "assistant":
                    response_text = self.extract_text_from_content(content)
                    tool_usages = self.extract_mcp_tools(response_text) if response_text else []

                    if response_text or tool_usages:
                        msg = ChatMessage(
                            role="assistant",
                            content=response_text or "[Assistant used tools]",
                            tools=tool_usages,
                            sequence_id=sequence_id,
                        )
                        entry.chat_history.append(msg)

            return entry if entry.has_meaningful_content() else None

        except Exception as e:
            print(f"[CLINE] Error parsing task {task_dir}: {e}")
            return None

    def extract_text_from_content(self, content: List[Dict]) -> str:
        """Extract text from content array."""
        texts = []

        if isinstance(content, list):
            for item in content:
                if isinstance(item, dict) and item.get("type") == "text":
                    text = item.get("text", "")
                    if "<environment_details>" in text:
                        text = text.split("<environment_details>")[0].strip()
                    if "<task>" in text:
                        match = re.search(r"<task>(.*?)</task>", text, re.DOTALL)
                        if match:
                            text = match.group(1).strip()
                    texts.append(text)

        return " ".join(texts).strip()

    def extract_mcp_tools(self, text: str) -> List[ToolUsage]:
        """Extract MCP tool usage from text."""
        tools = []

        mcp_pattern = (
            r"<use_mcp_tool>\s*<server_name>([^<]+)</server_name>\s*"
            r"<tool_name>([^<]+)</tool_name>\s*"
            r"<arguments>\s*(\{.*?\})\s*</arguments>\s*</use_mcp_tool>"
        )
        matches = re.findall(mcp_pattern, text, re.DOTALL)

        for server_name, tool_name, arguments_str in matches:
            try:
                arguments = json.loads(arguments_str)
                tool = ToolUsage(
                    tool_name=tool_name,
                    tool_type="mcp_tool",
                    server_name=server_name,
                    arguments=arguments,
                )
                tools.append(tool)
            except json.JSONDecodeError:
                pass

        return tools
