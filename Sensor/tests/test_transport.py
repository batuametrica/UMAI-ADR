"""Tests for the UMAI ingest transport."""

from datetime import datetime, timezone

import pytest

from adr_sensor.schemas.agent_event_schema import AgentEvent, ChatMessage
from adr_sensor.transport import (
    IngestClient,
    IngestConfig,
    SessionState,
    state_key,
)


def make_event(session_id, *, source="claude", raw_log_path=None, messages=1):
    return AgentEvent(
        timestamp=datetime(2026, 8, 1, 12, 0, tzinfo=timezone.utc),
        source=source,
        session_id=session_id,
        chat_history=[
            ChatMessage(role="user", content=f"message {i}") for i in range(messages)
        ],
        raw_log_path=raw_log_path,
        hostname="test-host",
        username="tester",
    )


class TestStateKey:
    def test_sidechains_sharing_a_session_id_stay_distinct(self):
        """Sub-agent runs carry the parent's session id in their own files.

        Keying state on session_id alone collapses them, which both under-counts
        state and re-ships the collapsed entries on every run.
        """
        parent = make_event("claude_abc", raw_log_path="/logs/abc.jsonl")
        sidechain_a = make_event("claude_abc", raw_log_path="/logs/side-a.jsonl")
        sidechain_b = make_event("claude_abc", raw_log_path="/logs/side-b.jsonl")

        keys = {state_key(parent), state_key(sidechain_a), state_key(sidechain_b)}
        assert len(keys) == 3

    def test_same_session_id_across_sources_stays_distinct(self):
        a = make_event("s1", source="claude")
        b = make_event("s1", source="claude_desktop")
        assert state_key(a) != state_key(b)


class TestSessionState:
    def test_unchanged_sessions_are_skipped_on_the_next_run(self, tmp_path):
        state = SessionState(path=tmp_path / "state.json")
        events = [make_event("s1", raw_log_path="/a.jsonl")]

        pending, skipped = state.pending(events)
        assert len(pending) == 1 and skipped == 0

        state.mark_sent(pending)
        state.save()

        reloaded = SessionState(path=tmp_path / "state.json")
        pending, skipped = reloaded.pending(events)
        assert pending == [] and skipped == 1

    def test_a_growing_session_is_resent(self, tmp_path):
        """Upstream compares an export-filename timestamp, and Claude Code
        reports a session's *earliest* timestamp — so an append-only session is
        exported once and never updated. Hashing the content catches growth.
        """
        state = SessionState(path=tmp_path / "state.json")
        before = make_event("s1", raw_log_path="/a.jsonl", messages=2)
        state.mark_sent([before])
        state.save()

        after = make_event("s1", raw_log_path="/a.jsonl", messages=5)
        pending, skipped = SessionState(path=tmp_path / "state.json").pending([after])

        assert len(pending) == 1 and skipped == 0

    def test_all_sidechains_are_tracked_independently(self, tmp_path):
        state = SessionState(path=tmp_path / "state.json")
        events = [
            make_event("claude_abc", raw_log_path=f"/logs/{name}.jsonl")
            for name in ("main", "side-a", "side-b")
        ]

        state.mark_sent(events)
        state.save()

        _, skipped = SessionState(path=tmp_path / "state.json").pending(events)
        assert skipped == 3

    def test_corrupt_state_file_is_ignored(self, tmp_path):
        path = tmp_path / "state.json"
        path.write_text("{not json", encoding="utf-8")

        pending, skipped = SessionState(path=path).pending([make_event("s1")])
        assert len(pending) == 1 and skipped == 0

    def test_last_successful_ingest_is_persisted_separately(self, tmp_path):
        path = tmp_path / "state.json"
        state = SessionState(path=path)
        state.last_successful_ingest_at = "2026-08-31T12:00:00+00:00"
        state.save()

        reloaded = SessionState(path=path)
        assert reloaded.last_successful_ingest_at == "2026-08-31T12:00:00+00:00"


class TestBatching:
    def _client(self, max_batch_bytes):
        return IngestClient(
            IngestConfig(
                endpoint="https://example.invalid",
                device_token="t",
                max_batch_bytes=max_batch_bytes,
            )
        )

    def test_oversized_sessions_split_across_batches(self):
        events = [make_event(f"s{i}", messages=40) for i in range(6)]
        batches = self._client(max_batch_bytes=2000)._batches(events)

        assert len(batches) > 1
        assert sum(len(b) for b in batches) == len(events)

    def test_a_single_oversized_session_still_ships(self):
        """A transcript larger than the batch budget must not be dropped."""
        events = [make_event("s1", messages=500)]
        batches = self._client(max_batch_bytes=10)._batches(events)

        assert len(batches) == 1 and len(batches[0]) == 1

    def test_small_sessions_share_one_batch(self):
        events = [make_event(f"s{i}") for i in range(5)]
        batches = self._client(max_batch_bytes=8 * 1024 * 1024)._batches(events)

        assert len(batches) == 1 and len(batches[0]) == 5


class TestConfig:
    def test_absent_configuration_returns_none(self, monkeypatch):
        monkeypatch.delenv("UMAI_INGEST_ENDPOINT", raising=False)
        monkeypatch.delenv("UMAI_DEVICE_TOKEN", raising=False)
        assert IngestConfig.from_env() is None

    def test_endpoint_trailing_slash_is_normalized(self, monkeypatch):
        monkeypatch.setenv("UMAI_INGEST_ENDPOINT", "https://umai.example.com/")
        monkeypatch.setenv("UMAI_DEVICE_TOKEN", "token")

        config = IngestConfig.from_env()
        assert IngestClient(config).url == "https://umai.example.com/api/v1/adr/sessions"

    def test_device_header_is_sent_when_enrolled(self):
        client = IngestClient(
            IngestConfig(
                endpoint="https://umai.example.com",
                device_token="token",
                tenant_id="11111111-1111-1111-1111-111111111111",
                device_id="collector-01",
            )
        )
        assert client._headers()["X-Device-Id"] == "collector-01"

    def test_heartbeat_reports_version_os_capabilities_and_health(self, monkeypatch):
        client = IngestClient(
            IngestConfig(
                endpoint="https://umai.example.com",
                device_token="token",
                tenant_id="11111111-1111-1111-1111-111111111111",
                device_id="collector-01",
                config_etag='"adr-old"',
            )
        )
        captured = {}

        def fake_post(body):
            captured.update(body)
            return {"config_etag": '"adr-new"', "collection_mode": "metadata"}

        monkeypatch.setattr(client, "_post_heartbeat", fake_post)
        client.heartbeat(
            observed_sources=["codex", "claude", "codex"],
            pending_sessions=3,
            last_successful_ingest_at="2026-08-31T12:00:00+00:00",
            status="degraded",
            status_detail="PARTIAL_INGEST",
        )

        assert captured["collector_version"]
        assert captured["os"] and captured["os_version"]
        assert captured["supported_sources"]
        assert captured["observed_sources"] == ["claude", "codex"]
        assert captured["status_detail"] == "PARTIAL_INGEST"
        assert client.config.config_etag == '"adr-new"'

    def test_malformed_numeric_setting_falls_back_to_default(self, monkeypatch):
        monkeypatch.setenv("UMAI_INGEST_ENDPOINT", "https://umai.example.com")
        monkeypatch.setenv("UMAI_DEVICE_TOKEN", "token")
        monkeypatch.setenv("UMAI_INGEST_TIMEOUT_SECONDS", "not-a-number")

        assert IngestConfig.from_env().timeout == 60


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
