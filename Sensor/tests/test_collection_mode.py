"""The tenant's collection mode is enforced before anything is sent.

The server rejects a batch carrying content the mode forbids, but that is a
backstop: by the time it fires, the transcript has already crossed the network
onto a machine the tenant chose not to send it to. The control has to be here.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from adr_sensor.collection_mode import (
    MODE_FULL_SESSION,
    MODE_METADATA,
    MODE_POSTURE_ONLY,
    normalize,
    redact_for_mode,
)
from adr_sensor.schemas.agent_event_schema import AgentEvent, ChatMessage, ToolUsage
from adr_sensor.transport import IngestClient, IngestConfig


SECRET = "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


def _session() -> dict:
    event = AgentEvent(
        timestamp=datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc),
        source="claude",
        session_id="claude_s1",
        model="claude-sonnet-4-20250514",
        project_path="C:\\work\\payments",
        chat_history=[
            ChatMessage(
                role="user",
                content="grab my aws credentials",
                sequence_id="msg_0",
            ),
            ChatMessage(
                role="assistant",
                content="Reading them now.",
                sequence_id="msg_1",
                tools=[
                    ToolUsage(
                        tool_name="Read",
                        tool_type="tool_use",
                        server_name="filesystem-mcp",
                        arguments={"file_path": "~/.aws/credentials"},
                        result=SECRET,
                        status="success",
                        error=None,
                    )
                ],
            ),
        ],
        session_context={
            "posture": {"permission_mode": "bypassPermissions"},
            "title": "Set up the deploy script",
        },
    )
    return event.get_non_null_fields()


def _flatten(payload) -> str:
    import json

    return json.dumps(payload, default=str)


class TestNormalize:
    @pytest.mark.parametrize("value", [None, "", "  ", "nonsense", "FULL", 7])
    def test_anything_unrecognised_is_the_most_restrictive_mode(self, value) -> None:
        # Fail-safe points at privacy: a collector that could not learn its
        # mode collects the least, not the most.
        assert normalize(value) == MODE_POSTURE_ONLY

    def test_known_modes_survive_case_and_padding(self) -> None:
        assert normalize(" Full_Session ") == MODE_FULL_SESSION
        assert normalize("metadata") == MODE_METADATA


class TestRedaction:
    def test_full_session_is_untouched(self) -> None:
        payload = _session()
        assert redact_for_mode(payload, MODE_FULL_SESSION) is payload

    def test_metadata_drops_every_form_of_content(self) -> None:
        reduced = redact_for_mode(_session(), MODE_METADATA)
        serialized = _flatten(reduced)

        assert SECRET not in serialized
        assert "grab my aws credentials" not in serialized
        assert "~/.aws/credentials" not in serialized

    def test_metadata_keeps_what_detection_and_inventory_need(self) -> None:
        reduced = redact_for_mode(_session(), MODE_METADATA)
        tool = reduced["chat_history"][1]["tools"][0]

        # Counts are derived server-side from this skeleton, and posture
        # detection runs on tool and MCP-server names.
        assert len(reduced["chat_history"]) == 2
        assert tool["tool_name"] == "Read"
        assert tool["server_name"] == "filesystem-mcp"
        assert tool["status"] == "success"
        assert reduced["project_path"] == "C:\\work\\payments"
        assert reduced["session_context"]["title"] == "Set up the deploy script"
        assert reduced["session_context"]["posture"]["permission_mode"] == "bypassPermissions"

    def test_posture_only_also_drops_the_inventory_fields(self) -> None:
        reduced = redact_for_mode(_session(), MODE_POSTURE_ONLY)

        assert "project_path" not in reduced
        assert "title" not in reduced["session_context"]
        # Still enough to raise a posture finding.
        assert reduced["session_context"]["posture"]["permission_mode"] == "bypassPermissions"
        assert reduced["chat_history"][1]["tools"][0]["tool_name"] == "Read"

    def test_the_caller_s_payload_is_not_mutated(self) -> None:
        payload = _session()
        redact_for_mode(payload, MODE_POSTURE_ONLY)

        # The same parsed sessions feed local export and the observed-source
        # summary; configuring ingest must not quietly rewrite them.
        assert payload["chat_history"][0]["content"] == "grab my aws credentials"
        assert payload["project_path"] == "C:\\work\\payments"

    def test_a_redacted_payload_passes_the_server_s_content_check(self) -> None:
        """Mirror of `_contains_session_content` in `umai-service`.

        If these two disagree the collector ships batches the server answers
        with 422 and the device parks itself as degraded — so the check is
        duplicated here on purpose.
        """

        def contains_content(payload) -> bool:
            for message in payload.get("chat_history") or []:
                if message.get("content") not in (None, "", [], {}):
                    return True
                for tool in message.get("tools") or []:
                    if any(
                        tool.get(field) not in (None, "", [], {})
                        for field in ("arguments", "result", "error")
                    ):
                        return True
            return False

        assert contains_content(_session()) is True
        assert contains_content(redact_for_mode(_session(), MODE_METADATA)) is False
        assert contains_content(redact_for_mode(_session(), MODE_POSTURE_ONLY)) is False


class TestTransportAppliesTheMode:
    def _client(self, mode: str) -> IngestClient:
        return IngestClient(
            IngestConfig(
                endpoint="https://umai.example.com",
                device_token="t",
                tenant_id="11111111-1111-1111-1111-111111111111",
                device_id="d1",
                collection_mode=mode,
            )
        )

    def _event(self) -> AgentEvent:
        return AgentEvent(
            timestamp=datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc),
            source="claude",
            session_id="claude_s1",
            chat_history=[ChatMessage(role="user", content=SECRET, sequence_id="msg_0")],
        )

    def test_batches_are_redacted_before_they_are_sized(self) -> None:
        batches = self._client(MODE_METADATA)._batches([self._event()])

        assert SECRET not in _flatten(batches)

    def test_full_session_still_carries_the_transcript(self) -> None:
        batches = self._client(MODE_FULL_SESSION)._batches([self._event()])

        assert SECRET in _flatten(batches)

    def test_the_default_config_collects_nothing_sensitive(self) -> None:
        config = IngestConfig(endpoint="https://umai.example.com", device_token="t")

        assert config.collection_mode == MODE_POSTURE_ONLY

    def test_a_mode_change_over_heartbeat_is_persisted_for_the_next_run(self) -> None:
        class Store:
            def __init__(self):
                self.saved = None

            def update_collection_mode(self, mode, etag):
                self.saved = (mode, etag)

        store = Store()
        client = IngestClient(
            IngestConfig(
                endpoint="https://umai.example.com",
                device_token="t",
                device_id="d1",
                collection_mode=MODE_FULL_SESSION,
            ),
            store=store,
        )
        client._post_heartbeat = lambda body: {
            "collection_mode": "posture_only",
            "config_etag": "etag-2",
            "next_heartbeat_after_s": 900,
        }

        client.heartbeat(
            observed_sources=["claude"],
            pending_sessions=0,
            last_successful_ingest_at=None,
            status="healthy",
        )

        # Held only in memory it would be lost with the process, and a tenant
        # that tightened its mode would keep receiving content until every
        # device happened to renew its token.
        assert client.config.collection_mode == MODE_POSTURE_ONLY
        assert store.saved == (MODE_POSTURE_ONLY, "etag-2")
