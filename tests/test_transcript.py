"""Tests for the collected-session -> ADR message conversion."""

import pytest

from umai.worker.transcript import (
    MAX_ARG_CHARS,
    posture_preamble,
    to_adr_messages,
)


def session(chat_history, **extra):
    return {"source": "claude", "session_id": "s1", "chat_history": chat_history, **extra}


class TestToolRendering:
    def test_tool_calls_become_transcript_lines(self):
        """ADR's detector reads tool activity from TOOL CALL / TOOL RESULT lines.

        Our collector keeps tools as structured fields, so without this the
        detector sees only prose and loses the strongest signal in the session.
        """
        messages = to_adr_messages(
            session(
                [
                    {
                        "role": "assistant",
                        "content": "Reading config.",
                        "tools": [
                            {
                                "tool_name": "read_file",
                                "arguments": {"path": "/etc/passwd"},
                                "result": "root:x:0:0",
                                "status": "success",
                            }
                        ],
                    }
                ]
            )
        )

        content = messages[0]["content"]
        assert "TOOL CALL: read_file(" in content
        assert "/etc/passwd" in content
        assert "TOOL RESULT: root:x:0:0" in content

    def test_mcp_server_qualifies_the_tool_name(self):
        messages = to_adr_messages(
            session(
                [
                    {
                        "role": "assistant",
                        "content": "",
                        "tools": [{"tool_name": "query", "server_name": "supabase"}],
                    }
                ]
            )
        )
        assert "TOOL CALL: supabase.query(" in messages[0]["content"]

    def test_tool_errors_are_surfaced(self):
        messages = to_adr_messages(
            session(
                [
                    {
                        "role": "assistant",
                        "content": "",
                        "tools": [
                            {"tool_name": "write", "status": "error", "error": "permission denied"}
                        ],
                    }
                ]
            )
        )
        assert "TOOL ERROR: permission denied" in messages[0]["content"]

    def test_large_arguments_are_clipped_but_marked(self):
        """One large file read must not crowd out the rest of the session."""
        messages = to_adr_messages(
            session(
                [
                    {
                        "role": "assistant",
                        "content": "",
                        "tools": [{"tool_name": "write", "arguments": {"body": "x" * 50_000}}],
                    }
                ]
            )
        )
        content = messages[0]["content"]
        assert len(content) < MAX_ARG_CHARS + 500
        assert "more chars]" in content

    def test_a_tool_only_message_is_kept(self):
        """An assistant turn that only calls tools is the interesting case."""
        messages = to_adr_messages(
            session([{"role": "assistant", "content": "", "tools": [{"tool_name": "bash"}]}])
        )
        assert len(messages) == 1

    def test_empty_messages_are_dropped(self):
        messages = to_adr_messages(
            session([{"role": "user", "content": "   ", "tools": []}, {"role": "assistant"}])
        )
        assert messages == []

    def test_roles_and_order_are_preserved(self):
        messages = to_adr_messages(
            session(
                [
                    {"role": "user", "content": "one"},
                    {"role": "assistant", "content": "two"},
                    {"role": "user", "content": "three"},
                ]
            )
        )
        assert [m["role"] for m in messages] == ["user", "assistant", "user"]
        assert [m["content"] for m in messages] == ["one", "two", "three"]

    def test_missing_chat_history_is_not_an_error(self):
        assert to_adr_messages({"source": "claude"}) == []


class TestPosturePreamble:
    def test_permission_and_browser_modes_are_reported(self):
        preamble = posture_preamble(
            session(
                [],
                session_context={
                    "posture": {
                        "permission_mode": "bypassPermissions",
                        "chrome_permission_mode": "skip_all_permission_checks",
                    }
                },
            )
        )
        assert "bypassPermissions" in preamble
        assert "skip_all_permission_checks" in preamble

    def test_connected_mcp_servers_are_named(self):
        preamble = posture_preamble(
            session(
                [],
                session_context={
                    "posture": {
                        "permission_mode": "acceptEdits",
                        "remote_mcp_servers": [{"name": "Supabase"}, "Canva"],
                    }
                },
            )
        )
        assert "Supabase" in preamble and "Canva" in preamble

    def test_absent_posture_yields_nothing(self):
        assert posture_preamble(session([])) is None
        assert posture_preamble(session([], session_context={})) is None

    def test_empty_posture_fields_yield_nothing(self):
        assert posture_preamble(session([], session_context={"posture": {"effort": "high"}})) is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
