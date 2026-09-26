"""
Parser for Claude Desktop Agent Mode (local agent mode) logs.

Two on-disk layouts exist, selected by platform:

* macOS   — `local-agent-mode-sessions/<user>/<org>/local_<uuid>/audit.jsonl`,
            a self-contained audit log per session.
* Windows — `claude-code-sessions/<user>/<org>/local_<uuid>.json`, a metadata
            sidecar whose `cliSessionId` points at a Claude Code transcript
            under `~/.claude/projects/`. Agent mode delegates to Claude Code
            there, so the transcript lives in the Claude Code store.

Memory-optimized: Streams audit.jsonl line-by-line, skips thinking blocks,
truncates large tool results, and filters by session age.

Performance-optimized: Skips sessions older than 2 weeks based on lastActivityAt.
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from .. import platform_paths
from ..schemas.agent_event_schema import AgentEvent, ChatMessage, ToolUsage
from ..utils.string_utils import truncate_middle
from ..utils.timestamp_utils import normalize_timestamp
from .base_parser import BaseParser
from .claude_parser import ClaudeParser

MAX_LOG_AGE_DAYS = 14

# Default base path for Claude Desktop agent mode sessions on macOS
DEFAULT_BASE_PATH = "~/Library/Application Support/Claude/local-agent-mode-sessions"


class ClaudeDesktopParser(BaseParser):
    """Parser for Claude Desktop Agent Mode sessions (both on-disk layouts)."""

    DEFAULT_MAX_AGE_DAYS = MAX_LOG_AGE_DAYS

    def __init__(self, max_age_days: Optional[int] = None, base_path: Optional[str] = None):
        super().__init__(max_age_days)
        # UMAI: layout and root now resolve per platform. An explicit base_path
        # still wins and is assumed to be the macOS audit.jsonl layout, which is
        # what upstream callers and the existing tests pass.
        if base_path:
            self.base_path = Path(base_path)
            self.layout = platform_paths.LAYOUT_AUDIT_JSONL
        else:
            located = platform_paths.agent_mode_session_root()
            if located:
                self.layout, self.base_path = located
            else:
                self.layout = platform_paths.LAYOUT_AUDIT_JSONL
                self.base_path = Path(DEFAULT_BASE_PATH).expanduser()

        # UMAI: Claude Code transcript files consumed by the sidecar layout.
        # The observer drops the duplicate `claude`-sourced copy of exactly
        # these files — matching on session id instead would also discard the
        # sub-agent (sidechain) runs, which share their parent's session id but
        # live in their own files.
        self.claimed_transcript_paths: Set[str] = set()
        self._transcript_index: Optional[Dict[str, Path]] = None

    def parse_all(self) -> List[AgentEvent]:
        """Parse all available Claude Desktop agent mode sessions."""
        self.claimed_transcript_paths = set()

        if not self.base_path.exists():
            print(f"[CLAUDE_DESKTOP] No sessions found at {self.base_path}")
            return []

        if self.layout == platform_paths.LAYOUT_SIDECAR:
            return self._parse_sidecar_layout()

        return self._parse_audit_jsonl_layout()

    def _parse_audit_jsonl_layout(self) -> List[AgentEvent]:
        """macOS layout: one audit.jsonl per session directory."""
        entries = []

        session_dirs = self._discover_sessions()
        print(f"[CLAUDE_DESKTOP] Found {len(session_dirs)} session directories")

        skipped_count = 0
        processed_count = 0

        for session_dir, metadata_path in session_dirs:
            try:
                metadata = self._read_session_metadata(metadata_path)
                if metadata is None:
                    continue

                last_activity = metadata.get("lastActivityAt")
                if last_activity is not None:
                    try:
                        activity_time = datetime.fromtimestamp(last_activity / 1000, tz=timezone.utc)
                        if not self._is_recent(activity_time):
                            skipped_count += 1
                            continue
                    except (ValueError, OSError, OverflowError):
                        pass

                audit_path = session_dir / "audit.jsonl"
                if not audit_path.exists():
                    continue

                entry = self._parse_session(audit_path, metadata)
                if entry and entry.has_meaningful_content():
                    entries.append(entry)
                    processed_count += 1

            except Exception as e:
                print(f"[CLAUDE_DESKTOP] Error parsing session {session_dir}: {e}")

        self._report_skipped("CLAUDE_DESKTOP", skipped_count, "sessions")
        print(f"[CLAUDE_DESKTOP] Processed {processed_count} sessions")

        return entries

    # ------------------------------------------------------------------
    # UMAI: sidecar layout (Windows)
    # ------------------------------------------------------------------

    def _parse_sidecar_layout(self) -> List[AgentEvent]:
        """Windows layout: metadata sidecar joined to a Claude Code transcript."""
        sidecars = sorted(self.base_path.glob("*/*/local_*.json"))
        print(f"[CLAUDE_DESKTOP] Found {len(sidecars)} session sidecars")

        entries = []
        skipped_count = 0
        unresolved_count = 0

        for sidecar_path in sidecars:
            metadata = self._read_session_metadata(sidecar_path)
            if not metadata:
                continue

            timestamp = self._sidecar_timestamp(metadata, sidecar_path)
            if not self._is_recent(timestamp):
                skipped_count += 1
                continue

            entry = self._parse_sidecar_session(metadata, timestamp)
            if entry is None:
                unresolved_count += 1
                continue

            if entry.has_meaningful_content():
                entries.append(entry)

        self._report_skipped("CLAUDE_DESKTOP", skipped_count, "sessions")
        if unresolved_count:
            print(f"[CLAUDE_DESKTOP] {unresolved_count} sidecars had no matching transcript")
        print(f"[CLAUDE_DESKTOP] Processed {len(entries)} sessions")

        return entries

    def _sidecar_timestamp(self, metadata: Dict[str, Any], sidecar_path: Path) -> datetime:
        """Best available activity time for a sidecar, newest signal first."""
        for key in ("lastActivityAt", "lastFocusedAt", "createdAt"):
            value = metadata.get(key)
            if value is None:
                continue
            try:
                return datetime.fromtimestamp(value / 1000, tz=timezone.utc)
            except (ValueError, OSError, OverflowError, TypeError):
                continue

        try:
            return datetime.fromtimestamp(sidecar_path.stat().st_mtime, tz=timezone.utc)
        except OSError:
            return datetime.now(timezone.utc)

    def _transcript_by_cli_session_id(self) -> Dict[str, Path]:
        """Index Claude Code transcripts by session id, built once per run."""
        if self._transcript_index is not None:
            return self._transcript_index

        index: Dict[str, Path] = {}
        for root in platform_paths.claude_code_projects():
            for transcript in root.glob("**/*.jsonl"):
                index.setdefault(transcript.stem, transcript)

        self._transcript_index = index
        return index

    def _parse_sidecar_session(
        self, metadata: Dict[str, Any], timestamp: datetime
    ) -> Optional[AgentEvent]:
        """Build one AgentEvent from a sidecar plus its Claude Code transcript."""
        cli_session_id = metadata.get("cliSessionId")
        if not cli_session_id:
            return None

        transcript_path = self._transcript_by_cli_session_id().get(cli_session_id)
        if transcript_path is None:
            return None

        try:
            # Age was already decided from the sidecar; don't re-filter here.
            transcript_events = ClaudeParser(max_age_days=10**6).parse_jsonl_file(transcript_path)
        except Exception as e:
            print(f"[CLAUDE_DESKTOP] Error reading transcript {transcript_path}: {e}")
            return None

        chat_history: List[ChatMessage] = []
        for event in transcript_events:
            if event.session_id == f"claude_{cli_session_id}":
                chat_history = list(event.chat_history)
                break
        else:
            if transcript_events:
                chat_history = list(transcript_events[0].chat_history)

        self.claimed_transcript_paths.add(str(transcript_path))

        session_id = metadata.get("sessionId", "")
        session_uuid = session_id[6:] if session_id.startswith("local_") else session_id

        session_context: Dict[str, Any] = {"posture": self._extract_posture(metadata)}
        if metadata.get("title"):
            session_context["title"] = metadata["title"]
        session_context["cli_session_id"] = cli_session_id

        return AgentEvent(
            timestamp=timestamp,
            source="claude_desktop",
            session_id=f"claude_desktop_{session_uuid}",
            project_path=metadata.get("cwd") or metadata.get("originCwd"),
            model=metadata.get("model"),
            chat_history=chat_history,
            raw_log_path=str(transcript_path),
            session_context=session_context,
        )

    def _extract_posture(self, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Security-relevant session configuration.

        These fields answer "what was this session allowed to do" without
        reading a single message, and drive detection independently of content.
        """
        return {
            "permission_mode": metadata.get("permissionMode"),
            "chrome_permission_mode": metadata.get("chromePermissionMode"),
            "remote_mcp_servers": metadata.get("remoteMcpServersConfig") or [],
            "always_allowed_reasons": metadata.get("alwaysAllowedReasons") or [],
            "session_permission_updates": metadata.get("sessionPermissionUpdates") or [],
            "effort": metadata.get("effort"),
            "completed_turns": metadata.get("completedTurns"),
        }

    def _discover_sessions(self) -> List[tuple]:
        """Discover session directories and their metadata files.

        Directory structure:
            base_path/<user_id>/<org_id>/local_<uuid>/audit.jsonl
            base_path/<user_id>/<org_id>/local_<uuid>.json  (metadata)
        """
        sessions = []

        try:
            for user_dir in self.base_path.iterdir():
                if not user_dir.is_dir() or user_dir.name.startswith("."):
                    continue

                for org_dir in user_dir.iterdir():
                    if not org_dir.is_dir() or org_dir.name.startswith("."):
                        continue

                    try:
                        for item in org_dir.iterdir():
                            if item.is_dir() and item.name.startswith("local_"):
                                audit_path = item / "audit.jsonl"
                                if audit_path.exists():
                                    metadata_path = org_dir / f"{item.name}.json"
                                    sessions.append((item, metadata_path))
                    except (PermissionError, OSError):
                        pass

        except (PermissionError, OSError) as e:
            print(f"[CLAUDE_DESKTOP] Error scanning base path {self.base_path}: {e}")

        return sessions

    def _read_session_metadata(self, metadata_path: Path) -> Optional[Dict[str, Any]]:
        """Read session metadata JSON file."""
        if not metadata_path.exists():
            return {}

        try:
            with open(metadata_path, encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, OSError, PermissionError):
            return {}

    def _normalize_result_content(self, result_content: Any) -> str:
        """Normalize result content which can be a string or list of content items."""
        if isinstance(result_content, str):
            return result_content

        if isinstance(result_content, list):
            text_parts = []
            for item in result_content:
                if isinstance(item, dict):
                    if item.get("type") == "text" and "text" in item:
                        text_parts.append(item["text"])
            return "\n".join(text_parts)

        return str(result_content) if result_content else ""

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

    def _parse_session(self, audit_path: Path, metadata: Dict[str, Any]) -> Optional[AgentEvent]:
        """Parse a single session's audit.jsonl file."""
        session_id_from_meta = metadata.get("sessionId", "")
        if session_id_from_meta.startswith("local_"):
            session_uuid = session_id_from_meta[6:]
        else:
            session_uuid = audit_path.parent.name
            if session_uuid.startswith("local_"):
                session_uuid = session_uuid[6:]

        model = metadata.get("model")
        project_path = metadata.get("cwd")
        title = metadata.get("title")

        # Determine timestamp
        timestamp = None
        last_activity_at = metadata.get("lastActivityAt")
        if last_activity_at is not None:
            try:
                timestamp = datetime.fromtimestamp(last_activity_at / 1000, tz=timezone.utc)
            except (ValueError, OSError, OverflowError):
                pass

        if timestamp is None:
            created_at = metadata.get("createdAt")
            if created_at is not None:
                try:
                    timestamp = datetime.fromtimestamp(created_at / 1000, tz=timezone.utc)
                except (ValueError, OSError, OverflowError):
                    pass

        if timestamp is None:
            try:
                timestamp = datetime.fromtimestamp(audit_path.stat().st_mtime, tz=timezone.utc)
            except OSError:
                timestamp = datetime.now(timezone.utc)

        # Extract messages
        messages = []
        init_data = None

        try:
            with open(audit_path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    extracted = self._extract_message_data(obj)
                    if extracted:
                        messages.append(extracted)
                    elif obj.get("type") == "system" and obj.get("subtype") == "init":
                        init_data = self._extract_init_data(obj)

                    del obj

        except (OSError, PermissionError):
            return None

        if not messages:
            return None

        # Build session context
        session_context: Dict[str, Any] = {}
        if title:
            session_context["title"] = title
        if init_data:
            session_context["init"] = init_data
            # UMAI: mirror the sidecar layout's posture shape so downstream
            # consumers read one key regardless of platform.
            session_context["posture"] = {
                "permission_mode": init_data.get("permission_mode"),
                "chrome_permission_mode": None,
                "remote_mcp_servers": init_data.get("mcp_servers") or [],
                "always_allowed_reasons": [],
                "session_permission_updates": [],
                "effort": None,
                "completed_turns": None,
            }

        entry = AgentEvent(
            timestamp=timestamp,
            source="claude_desktop",
            session_id=f"claude_desktop_{session_uuid}",
            project_path=project_path,
            model=model,
            raw_log_path=str(audit_path),
            session_context=session_context if session_context else None,
        )

        # Build chat history
        pending_tools: Dict[str, ToolUsage] = {}

        for i, msg_data in enumerate(messages):
            msg_type = msg_data["type"]
            sequence_id = msg_data.get("uuid") or f"msg_{i}"

            if msg_type == "user":
                tool_results = msg_data.get("tool_results", [])
                if tool_results:
                    for tool_result in tool_results:
                        tool_use_id = tool_result.get("tool_use_id")
                        result = tool_result.get("result")
                        if tool_use_id in pending_tools:
                            old_tool = pending_tools[tool_use_id]
                            updated_tool = ToolUsage(
                                tool_name=old_tool.tool_name,
                                tool_type=old_tool.tool_type,
                                arguments=old_tool.arguments,
                                result=result,
                                status="success" if result else "unknown",
                            )
                            for msg in entry.chat_history:
                                if msg.role == "assistant":
                                    for idx, t in enumerate(msg.tools):
                                        if t == old_tool:
                                            new_tools = list(msg.tools)
                                            new_tools[idx] = updated_tool
                                            object.__setattr__(msg, "tools", new_tools)
                                            break
                    continue

                content = msg_data.get("content", "")
                if content:
                    msg = ChatMessage(role="user", content=content, tools=[], sequence_id=sequence_id)
                    entry.chat_history.append(msg)

            elif msg_type == "assistant":
                content = msg_data.get("content", "")
                tools = []

                for tool_data in msg_data.get("tools", []):
                    tool = ToolUsage(
                        tool_name=tool_data.get("name", "unknown"),
                        tool_type="tool_use",
                        arguments=tool_data.get("input", {}),
                        result=None,
                    )
                    tools.append(tool)
                    tool_id = tool_data.get("id")
                    if tool_id:
                        pending_tools[tool_id] = tool

                if content or tools:
                    msg = ChatMessage(
                        role="assistant",
                        content=content or "[Assistant used tools]",
                        tools=tools,
                        sequence_id=sequence_id,
                    )
                    entry.chat_history.append(msg)

        return entry

    def _extract_init_data(self, obj: Dict[str, Any]) -> Dict[str, Any]:
        """Extract relevant data from a system:init event."""
        return {
            "tools": obj.get("tools", []),
            "mcp_servers": obj.get("mcp_servers", []),
            "permission_mode": obj.get("permissionMode"),
            "model": obj.get("model"),
        }

    def _extract_message_data(self, obj: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Extract only needed data from an audit.jsonl line."""
        msg_type = obj.get("type")
        if msg_type not in ("user", "assistant"):
            return None

        if "message" not in obj:
            return None

        extracted: Dict[str, Any] = {
            "type": msg_type,
            "uuid": obj.get("uuid"),
        }

        message = obj["message"]

        if msg_type == "user":
            content = message.get("content", "")

            tool_results = []
            if isinstance(content, list):
                for item in content:
                    if isinstance(item, dict) and item.get("type") == "tool_result":
                        tool_use_id = item.get("tool_use_id")
                        result_content = item.get("content", "")

                        if "tool_use_result" in obj and isinstance(obj["tool_use_result"], dict):
                            result_content = obj["tool_use_result"].get("result", result_content)

                        result_content = self._normalize_result_content(result_content)

                        if result_content and isinstance(result_content, str):
                            result_content = truncate_middle(result_content, max_length=1000, edge_chars=400)

                        tool_results.append({"tool_use_id": tool_use_id, "result": result_content})

            if tool_results:
                extracted["tool_results"] = tool_results
                extracted["content"] = ""
            elif isinstance(content, str):
                extracted["content"] = content
            else:
                extracted["content"] = ""

        elif msg_type == "assistant":
            content_items = message.get("content", [])
            text_parts = []
            tools = []

            if isinstance(content_items, list):
                for item in content_items:
                    if isinstance(item, dict):
                        item_type = item.get("type")
                        if item_type == "text":
                            text_parts.append(item.get("text", ""))
                        elif item_type == "tool_use":
                            raw_input = item.get("input", {})
                            truncated_input = self._truncate_large_arguments(raw_input)
                            tools.append({
                                "id": item.get("id"),
                                "name": item.get("name", "unknown"),
                                "input": truncated_input,
                            })
                        # Skip 'thinking' blocks entirely

            extracted["content"] = "".join(text_parts)
            extracted["tools"] = tools

        return extracted
