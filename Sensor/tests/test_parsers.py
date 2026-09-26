"""Tests for ADR Sensor parsers."""

import json
import os
import sqlite3
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

import pytest

from adr_sensor.parsers.base_parser import BaseParser
from adr_sensor.parsers.claude_desktop_parser import ClaudeDesktopParser
from adr_sensor.parsers.claude_parser import ClaudeParser
from adr_sensor.parsers.cline_parser import ClineParser
from adr_sensor.parsers.codex_parser import CodexParser
from adr_sensor.parsers.cursor_parser import CursorParser
from adr_sensor.parsers.warp_parser import WarpParser


class TestClaudeParser:
    def test_parse_jsonl_file(self, tmp_path):
        """Test parsing a JSONL file with Claude Code format."""
        jsonl_file = tmp_path / "test.jsonl"
        messages = [
            {
                "type": "user",
                "sessionId": "session1",
                "timestamp": "2025-06-15T10:00:00Z",
                "message": {"content": "Help me write a function"},
            },
            {
                "type": "assistant",
                "sessionId": "session1",
                "timestamp": "2025-06-15T10:00:01Z",
                "message": {
                    "model": "claude-sonnet-4-20250514",
                    "content": [
                        {"type": "text", "text": "Sure! Here's a function:"},
                        {
                            "type": "tool_use",
                            "id": "tool1",
                            "name": "write_file",
                            "input": {"path": "main.py", "content": "def hello(): pass"},
                        },
                    ],
                },
            },
            {
                "type": "user",
                "sessionId": "session1",
                "timestamp": "2025-06-15T10:00:02Z",
                "message": {
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": "tool1",
                            "content": "File written successfully",
                        }
                    ]
                },
            },
        ]
        with open(jsonl_file, "w") as f:
            for msg in messages:
                f.write(json.dumps(msg) + "\n")

        parser = ClaudeParser()
        entries = parser.parse_jsonl_file(jsonl_file)

        assert len(entries) == 1
        entry = entries[0]
        assert entry.source == "claude"
        assert entry.session_id == "claude_session1"
        assert entry.model == "claude-sonnet-4-20250514"
        assert len(entry.chat_history) >= 1

    def test_parse_empty_file(self, tmp_path):
        """Test parsing an empty file."""
        jsonl_file = tmp_path / "empty.jsonl"
        jsonl_file.write_text("")

        parser = ClaudeParser()
        entries = parser.parse_jsonl_file(jsonl_file)
        assert len(entries) == 0

    def test_parse_all_no_directory(self):
        """Test parse_all when directory doesn't exist."""
        parser = ClaudeParser()
        parser.base_path = Path("/nonexistent/path")
        entries = parser.parse_all()
        assert entries == []

    def test_truncate_large_arguments(self):
        """Test that large arguments are truncated."""
        parser = ClaudeParser()
        args = {"short": "hello", "long": "x" * 2000}
        result = parser._truncate_large_arguments(args)
        assert result["short"] == "hello"
        assert len(result["long"]) < 2000
        assert "[truncated" in result["long"]


class TestClineParser:
    def test_parse_cline_log(self, tmp_path):
        """Test parsing a Cline task directory."""
        task_dir = tmp_path / "1234567890"
        task_dir.mkdir()

        conversation = [
            {
                "role": "user",
                "content": [{"type": "text", "text": "Create a hello world script"}],
            },
            {
                "role": "assistant",
                "content": [
                    {"type": "text", "text": "I'll create that for you."},
                ],
            },
        ]

        api_file = task_dir / "api_conversation_history.json"
        with open(api_file, "w") as f:
            json.dump(conversation, f)

        parser = ClineParser()
        entry = parser.parse_cline_log(task_dir)

        assert entry is not None
        assert entry.source == "cline"
        assert len(entry.chat_history) == 2

    def test_extract_mcp_tools(self):
        """Test MCP tool extraction from text."""
        parser = ClineParser()
        text = """
        <use_mcp_tool>
        <server_name>my-server</server_name>
        <tool_name>query_database</tool_name>
        <arguments>{"query": "SELECT * FROM users"}</arguments>
        </use_mcp_tool>
        """
        tools = parser.extract_mcp_tools(text)
        assert len(tools) == 1
        assert tools[0].tool_name == "query_database"
        assert tools[0].server_name == "my-server"
        assert tools[0].tool_type == "mcp_tool"

    def test_parse_no_directory(self):
        """Test parse_all when directory doesn't exist."""
        parser = ClineParser()
        parser.base_path = Path("/nonexistent/path")
        entries = parser.parse_all()
        assert entries == []


class TestCodexParser:
    def test_parse_jsonl_file(self, tmp_path):
        """Test parsing a Codex CLI JSONL file."""
        jsonl_file = tmp_path / "rollout-001.jsonl"
        events = [
            {"type": "session_meta", "payload": {"id": "sess1", "timestamp": "2025-06-15T10:00:00Z", "cwd": "/tmp"}},
            {"type": "turn_context", "payload": {"model": "o3-mini"}},
            {
                "type": "response_item",
                "payload": {
                    "type": "message",
                    "role": "user",
                    "content": [{"type": "input_text", "text": "List all Python files"}],
                },
            },
            {
                "type": "response_item",
                "payload": {
                    "type": "function_call",
                    "call_id": "call1",
                    "name": "shell",
                    "arguments": '{"command": "find . -name \\"*.py\\""}',
                },
            },
            {
                "type": "response_item",
                "payload": {"type": "function_call_output", "call_id": "call1", "output": "main.py\ntest.py"},
            },
            {
                "type": "response_item",
                "payload": {
                    "type": "message",
                    "role": "assistant",
                    "content": [{"type": "output_text", "text": "Found 2 Python files."}],
                },
            },
        ]
        with open(jsonl_file, "w") as f:
            for event in events:
                f.write(json.dumps(event) + "\n")

        parser = CodexParser()
        entry = parser.parse_jsonl_file(jsonl_file)

        assert entry is not None
        assert entry.source == "codex"
        assert entry.session_id == "codex_sess1"
        assert entry.model == "o3-mini"
        assert len(entry.chat_history) >= 2

        # Check that tool was parsed
        assistant_msgs = [m for m in entry.chat_history if m.role == "assistant"]
        has_tools = any(len(m.tools) > 0 for m in assistant_msgs)
        assert has_tools

    def test_parse_no_directory(self):
        """Test parse_all when directory doesn't exist."""
        parser = CodexParser()
        parser.base_path = Path("/nonexistent/path")
        entries = parser.parse_all()
        assert entries == []


# ---------------------------------------------------------------------------
# UMAI: age filter (WS3.1)
# ---------------------------------------------------------------------------


def _age(path: Path, days: float) -> None:
    """Backdate a file's mtime by `days`."""
    stamp = time.time() - days * 86400
    os.utime(path, (stamp, stamp))


def _write_codex_rollout(path: Path, session_id: str) -> None:
    events = [
        {"type": "session_meta", "payload": {"id": session_id, "timestamp": "2025-06-15T10:00:00Z", "cwd": "/tmp"}},
        {
            "type": "response_item",
            "payload": {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "hello"}]},
        },
        {
            "type": "response_item",
            "payload": {"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "hi"}]},
        },
    ]
    path.write_text("\n".join(json.dumps(e) for e in events) + "\n", encoding="utf-8")


def _write_cline_task(root: Path, name: str) -> Path:
    task_dir = root / name
    task_dir.mkdir()
    api_file = task_dir / "api_conversation_history.json"
    api_file.write_text(
        json.dumps(
            [
                {"role": "user", "content": [{"type": "text", "text": "Create a hello world script"}]},
                {"role": "assistant", "content": [{"type": "text", "text": "Done."}]},
            ]
        ),
        encoding="utf-8",
    )
    return api_file


def _make_warp_db(path: Path, conversations) -> None:
    """`conversations`: iterable of (conversation_id, last_modified_at)."""
    conn = sqlite3.connect(str(path))
    conn.executescript(
        """
        CREATE TABLE agent_conversations (conversation_id TEXT, conversation_data TEXT, last_modified_at TEXT);
        CREATE TABLE ai_queries (exchange_id TEXT, conversation_id TEXT, start_ts TEXT, input TEXT,
                                 working_directory TEXT, output_status TEXT, model_id TEXT);
        CREATE TABLE ai_blocks (exchange_id TEXT, output TEXT);
        """
    )
    for conv_id, last_modified in conversations:
        conn.execute("INSERT INTO agent_conversations VALUES (?, '{}', ?)", (conv_id, last_modified))
        for i in range(2):
            conn.execute(
                "INSERT INTO ai_queries VALUES (?, ?, ?, ?, '/tmp', 'Finished', 'm')",
                (
                    f"{conv_id}-{i}",
                    conv_id,
                    f"2026-01-01T00:00:0{i}Z",
                    json.dumps([{"Query": {"text": f"question {i}"}}]),
                ),
            )
    conn.commit()
    conn.close()


class _Probe(BaseParser):
    def parse_all(self):
        return []


class TestBaseParserAgeWindow:
    def test_default_window_is_fourteen_days(self):
        assert _Probe().max_age_days == 14
        assert _Probe(max_age_days=None).max_age_days == 14
        assert _Probe(max_age_days=3).max_age_days == 3

    def test_unknown_timestamp_counts_as_recent(self):
        assert _Probe()._is_recent(None) is True

    def test_timestamp_boundaries(self):
        now = datetime.now(timezone.utc)
        parser = _Probe(max_age_days=14)
        assert parser._is_recent(now - timedelta(days=13))
        assert not parser._is_recent(now - timedelta(days=15))
        # a naive timestamp is read as UTC rather than raising
        assert parser._is_recent((now - timedelta(days=1)).replace(tzinfo=None))

    def test_unreadable_file_is_not_recent(self, tmp_path):
        assert _Probe()._is_recent_mtime(tmp_path / "missing.jsonl") is False

    def test_mtime_window(self, tmp_path):
        fresh = tmp_path / "fresh.jsonl"
        old = tmp_path / "old.jsonl"
        fresh.write_text("{}", encoding="utf-8")
        old.write_text("{}", encoding="utf-8")
        _age(old, 30)
        parser = _Probe()
        assert parser._is_recent_mtime(fresh)
        assert not parser._is_recent_mtime(old)

    def test_effectively_unbounded_window_does_not_overflow(self, tmp_path):
        old = tmp_path / "old.jsonl"
        old.write_text("{}", encoding="utf-8")
        _age(old, 3650)
        assert _Probe(max_age_days=10**6)._is_recent_mtime(old)

    @pytest.mark.parametrize(
        "parser_cls", [ClaudeParser, ClaudeDesktopParser, CursorParser, CodexParser, ClineParser, WarpParser]
    )
    def test_every_parser_shares_the_window(self, parser_cls):
        assert isinstance(parser_cls(), BaseParser)
        assert parser_cls().max_age_days == 14
        assert parser_cls(max_age_days=7).max_age_days == 7


class TestAgeFilterPerParser:
    def test_claude_skips_old_files(self, tmp_path, capsys):
        """Refactor guard: Claude's existing mtime filter behaves as before."""
        for name in ("fresh", "old"):
            (tmp_path / f"{name}.jsonl").write_text(
                json.dumps(
                    {
                        "type": "user",
                        "sessionId": name,
                        "timestamp": "2026-01-01T00:00:00Z",
                        "message": {"content": "hello there"},
                    }
                )
                + "\n",
                encoding="utf-8",
            )
        _age(tmp_path / "old.jsonl", 30)

        parser = ClaudeParser()
        parser.base_path = tmp_path
        parser.parse_all()

        out = capsys.readouterr().out
        assert "[CLAUDE] Skipped 1 files older than 14 days" in out
        assert "Processing 1 recent files" in out

    def test_codex_skips_old_rollouts(self, tmp_path, capsys):
        _write_codex_rollout(tmp_path / "rollout-fresh.jsonl", "fresh")
        _write_codex_rollout(tmp_path / "rollout-old.jsonl", "old")
        _age(tmp_path / "rollout-old.jsonl", 30)

        parser = CodexParser()
        parser.base_path = tmp_path
        entries = parser.parse_all()

        assert [e.session_id for e in entries] == ["codex_fresh"]
        assert "[CODEX] Skipped 1 files older than 14 days" in capsys.readouterr().out

    def test_codex_all_history_keeps_old_rollouts(self, tmp_path):
        _write_codex_rollout(tmp_path / "rollout-old.jsonl", "old")
        _age(tmp_path / "rollout-old.jsonl", 30)

        parser = CodexParser(max_age_days=10000)
        parser.base_path = tmp_path
        assert [e.session_id for e in parser.parse_all()] == ["codex_old"]

    def test_cline_skips_old_tasks(self, tmp_path, capsys):
        _write_cline_task(tmp_path, "fresh")
        _age(_write_cline_task(tmp_path, "old"), 30)

        parser = ClineParser()
        parser.base_path = tmp_path
        entries = parser.parse_all()

        assert [e.session_id for e in entries] == ["cline_fresh"]
        assert "[CLINE] Skipped 1 tasks older than 14 days" in capsys.readouterr().out

    def test_cline_custom_window(self, tmp_path):
        _age(_write_cline_task(tmp_path, "old"), 30)

        parser = ClineParser(max_age_days=60)
        parser.base_path = tmp_path
        assert [e.session_id for e in parser.parse_all()] == ["cline_old"]

    def test_warp_skips_old_conversations(self, tmp_path, capsys):
        now = datetime.now(timezone.utc)
        db = tmp_path / "warp.sqlite"
        _make_warp_db(
            db,
            [
                ("fresh", (now - timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S")),
                ("old", (now - timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S")),
                ("undated", None),
            ],
        )

        parser = WarpParser()
        parser.db_path = db
        entries = parser.parse_all()

        # a conversation without last_modified_at is kept, as Cursor does
        assert sorted(e.session_id for e in entries) == ["warp_fresh", "warp_undated"]
        assert "[WARP] Skipped 1 conversations older than 14 days" in capsys.readouterr().out

    def test_claude_desktop_audit_layout_skips_old_sessions(self, tmp_path, capsys):
        """Refactor guard: lastActivityAt (ms) still drives the audit layout."""
        now_ms = int(time.time() * 1000)
        org_dir = tmp_path / "user" / "org"
        for name, activity in (("local_fresh", now_ms), ("local_old", now_ms - 30 * 86400 * 1000)):
            (org_dir / name).mkdir(parents=True)
            (org_dir / name / "audit.jsonl").write_text("", encoding="utf-8")
            (org_dir / f"{name}.json").write_text(
                json.dumps({"sessionId": name, "lastActivityAt": activity}), encoding="utf-8"
            )

        parser = ClaudeDesktopParser(base_path=str(tmp_path))
        parser.parse_all()

        assert "[CLAUDE_DESKTOP] Skipped 1 sessions older than 14 days" in capsys.readouterr().out


def _make_cursor_db(path: Path, conversations) -> None:
    """Minimal Cursor state.vscdb: the cursorDiskKV table the parser reads.

    `conversations` is a list of (conv_id, lastUpdatedAt_ms, [(type, text), ...]).
    """
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE cursorDiskKV (key TEXT UNIQUE ON CONFLICT REPLACE, value BLOB)")
    for conv_id, updated_ms, bubbles in conversations:
        conn.execute(
            "INSERT INTO cursorDiskKV VALUES (?, ?)",
            (f"composerData:{conv_id}", json.dumps({"composerId": conv_id, "lastUpdatedAt": updated_ms})),
        )
        for i, (bubble_type, text) in enumerate(bubbles):
            conn.execute(
                "INSERT INTO cursorDiskKV VALUES (?, ?)",
                (f"bubbleId:{conv_id}:b{i}", json.dumps({"type": bubble_type, "text": text})),
            )
    conn.commit()
    conn.close()


class TestCursorParser:
    def test_parses_state_db_fixture(self, tmp_path, capsys):
        now_ms = int(time.time() * 1000)
        db = tmp_path / "state.vscdb"
        _make_cursor_db(
            db,
            [
                ("fresh", now_ms, [(1, "Refactor the billing module"), (2, "Here is the refactor.")]),
                ("old", now_ms - 30 * 86400 * 1000, [(1, "old question"), (2, "old answer")]),
            ],
        )

        entries = CursorParser(db_path=str(db)).parse_all()

        assert [e.session_id for e in entries] == ["cursor_fresh"]
        assert [m.role for m in entries[0].chat_history] == ["user", "assistant"]
        assert entries[0].chat_history[0].content == "Refactor the billing module"
        assert "[CURSOR] Skipped 1 conversations older than 14 days" in capsys.readouterr().out

    def test_missing_db(self, tmp_path):
        assert CursorParser(db_path=str(tmp_path / "absent.vscdb")).parse_all() == []
