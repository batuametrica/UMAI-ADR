import datetime as dt
import logging
import threading
import urllib.error
import urllib.request

import pytest

from umai.worker.__main__ import (
    BudgetExceeded,
    DailySpend,
    _check_batch_budget,
    _run_triage_batch,
    _wait_for_daily_budget,
)
from umai.worker.client import PlatformError
from umai.worker.config import BudgetConfig, StageConfig, WorkerConfig
from umai.worker.operations import RuntimeState, start_operations_server


def test_operations_endpoints_report_liveness_readiness_and_metrics():
    state = RuntimeState(
        stage="triage",
        claimed_total=4,
        processed_total=3,
        queue_claim_batch_size=4,
        active_leases=1,
    )
    server = start_operations_server(state, "127.0.0.1", 0)
    port = server.server_address[1]
    try:
        assert urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz").status == 200
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/readyz")
            raise AssertionError("not-ready endpoint must return 503")
        except urllib.error.HTTPError as error:
            assert error.code == 503
        state.ready = True
        assert urllib.request.urlopen(f"http://127.0.0.1:{port}/readyz").status == 200
        metrics = urllib.request.urlopen(f"http://127.0.0.1:{port}/metrics").read().decode()
        assert 'umai_worker_claimed_total{stage="triage"} 4' in metrics
        assert 'umai_worker_processed_total{stage="triage"} 3' in metrics
        assert 'umai_worker_queue_claim_batch_size{stage="triage"} 4' in metrics
        assert 'umai_worker_active_leases{stage="triage"} 1' in metrics
    finally:
        server.shutdown()
        server.server_close()


def test_client_release_payload_uses_worker_identity(monkeypatch):
    from umai.worker.client import PlatformClient, PlatformConfig

    client = PlatformClient(PlatformConfig("https://platform", "token", worker_id="worker-1"))
    captured = {}

    def request(method, path, body=None):
        captured.update(method=method, path=path, body=body)
        return b'{"released":2}'

    monkeypatch.setattr(client, "_request", request)
    released = client.release(
        "triage",
        [
            {"tenant_id": "t1", "session_key": "s1"},
            {"tenant_id": "t1", "session_key": "s2"},
        ],
    )
    assert released == 2
    assert captured["body"]["worker_id"] == "worker-1"
    assert captured["path"] == "/internal/analysis/release"


# --- cost budgets in the batch loop ------------------------------------------

class _Clock:
    def __init__(self, now: dt.datetime):
        self.now = now

    def __call__(self) -> dt.datetime:
        return self.now


def _stage(name: str) -> StageConfig:
    return StageConfig(
        stage=name,
        model=f"{name}-model",
        base_url=None,
        api_key="k",
        timeout_s=60,
        cost_per_1m_input=1.0,
        cost_per_1m_output=1.0,
    )


def _config(**budget) -> WorkerConfig:
    return WorkerConfig(
        triage=_stage("triage"), reasoning=_stage("reasoning"), budget=BudgetConfig(**budget)
    )


class _FakeClient:
    """Serves a queue of sessions and records what the batch did with them."""

    def __init__(self, count: int, *, release_fails: bool = False):
        self.queue = [{"tenant_id": "t1", "session_key": f"s{i:03d}"} for i in range(count)]
        self.submitted: list[dict] = []
        self.released: list[str] = []
        self.claims = 0
        self.release_fails = release_fails

    def claim(self, stage, limit=10, tenant_id=None):
        self.claims += 1
        batch, self.queue = self.queue[:limit], self.queue[limit:]
        return batch

    def transcript(self, tenant, key):
        return {"session_key": key}

    def submit(self, result):
        self.submitted.append(result)
        return {}

    def release(self, stage, sessions):
        if self.release_fails:
            raise PlatformError("release unavailable")
        self.released.extend(item["session_key"] for item in sessions)
        # Released work goes back to the front of the queue.
        self.queue = list(sessions) + self.queue
        return len(sessions)


class _Outcome:
    def __init__(self, cost: float):
        self.cost_usd = cost
        self.input_tokens = 0
        self.output_tokens = 0
        self.verdict = "benign"
        self.threat_tactic = None

    def to_result(self, tenant, key):
        return {"tenant_id": tenant, "session_key": key, "stage": "triage", "verdict": "benign"}


@pytest.fixture
def fixed_cost_triage(monkeypatch):
    """Every triaged session costs $1.00; no model or Detection import."""

    class Runner:
        def __init__(self, stage=None):
            pass

        def run(self, transcript):
            return _Outcome(1.0)

    monkeypatch.setattr("umai.worker.triage.TriageRunner", Runner)


def test_daily_spend_persists_across_batches_and_resets_at_utc_midnight(fixed_cost_triage):
    clock = _Clock(dt.datetime(2026, 9, 26, 23, 0, tzinfo=dt.timezone.utc))
    daily = DailySpend(5.0, clock=clock)
    client = _FakeClient(20)
    config = _config(max_cost_per_batch_usd=3.0, max_cost_per_day_usd=5.0)
    runtime = RuntimeState(stage="triage")

    # The batch cap resets per batch; the daily cap does not.
    assert _run_triage_batch(client, 4, None, config, runtime=runtime, daily=daily) == 3
    assert _run_triage_batch(client, 4, None, config, runtime=runtime, daily=daily) == 2
    assert daily.spent_usd == 5.0
    assert daily.exhausted()
    assert runtime.daily_spend_usd == 5.0

    claims = client.claims
    assert _run_triage_batch(client, 4, None, config, runtime=runtime, daily=daily) == 0
    assert client.claims == claims, "an exhausted day must not take new leases"
    assert daily.seconds_until_reset() == 3600

    clock.now = dt.datetime(2026, 9, 27, 0, 0, 1, tzinfo=dt.timezone.utc)
    assert not daily.exhausted()
    assert daily.spent_usd == 0.0
    assert _run_triage_batch(client, 4, None, config, runtime=runtime, daily=daily) == 3
    assert len(client.submitted) == 8


def test_budget_stop_releases_the_unprocessed_sessions(fixed_cost_triage):
    client = _FakeClient(6)
    config = _config(max_cost_per_batch_usd=2.0)
    runtime = RuntimeState(stage="triage")

    processed = _run_triage_batch(client, 6, None, config, runtime=runtime)

    assert processed == 2
    assert client.released == ["s002", "s003", "s004", "s005"]
    # Released, not reported as failed: nothing about the sessions was wrong.
    assert [r["session_key"] for r in client.submitted] == ["s000", "s001"]
    assert all(r["verdict"] != "error" for r in client.submitted)
    assert runtime.released_total == 4
    assert runtime.active_leases == 0
    assert runtime.budget_stops_total == 1
    assert runtime.failed_total == 0


def test_a_failed_release_leaves_the_leases_to_expire(fixed_cost_triage, caplog):
    client = _FakeClient(4, release_fails=True)
    runtime = RuntimeState(stage="triage")

    with caplog.at_level(logging.WARNING, logger="umai.worker"):
        processed = _run_triage_batch(
            client, 4, None, _config(max_cost_per_batch_usd=1.0), runtime=runtime
        )

    assert processed == 1
    assert runtime.active_leases == 3
    assert any("leases will expire" in r.getMessage() for r in caplog.records)


def test_the_per_session_cap_still_only_logs(fixed_cost_triage, caplog):
    """Unchanged: an overrun is recorded, the batch carries on."""
    client = _FakeClient(3)
    with caplog.at_level(logging.WARNING, logger="umai.worker"):
        processed = _run_triage_batch(
            client, 3, None, _config(max_cost_per_session_usd=0.5), runtime=None
        )

    assert processed == 3
    assert client.released == []
    overruns = [r for r in caplog.records if "exceeded the per-session cap" in r.getMessage()]
    assert len(overruns) == 3


def test_the_daily_check_raises_with_a_clear_reason():
    daily = DailySpend(2.0, clock=_Clock(dt.datetime(2026, 9, 26, 12, tzinfo=dt.timezone.utc)))
    config = _config(max_cost_per_day_usd=2.0)
    _check_batch_budget(config, 0.0, daily)
    daily.add(2.0)
    with pytest.raises(BudgetExceeded) as exc:
        _check_batch_budget(config, 0.0, daily)
    assert "Daily budget of $2.0000" in str(exc.value)
    assert "2026-09-26" in str(exc.value)


def test_an_unset_daily_cap_never_pauses():
    daily = DailySpend(0.0)
    daily.add(10_000.0)
    assert not daily.exhausted()


def test_the_loop_pauses_and_resumes_once_each(caplog):
    clock = _Clock(dt.datetime(2026, 9, 26, 23, 59, 30, tzinfo=dt.timezone.utc))
    daily = DailySpend(1.0, clock=clock)
    daily.add(1.0)
    runtime = RuntimeState(stage="triage", ready=True)
    waits: list[float] = []

    class Stop:
        def wait(self, seconds):
            waits.append(seconds)

    with caplog.at_level(logging.INFO, logger="umai.worker"):
        assert _wait_for_daily_budget(daily, runtime, Stop(), 60) is True
        assert _wait_for_daily_budget(daily, runtime, Stop(), 60) is True
        assert runtime.budget_paused is True
        clock.now = dt.datetime(2026, 9, 27, 0, 0, 5, tzinfo=dt.timezone.utc)
        assert _wait_for_daily_budget(daily, runtime, Stop(), 60) is False

    assert runtime.budget_paused is False
    # The idle wait is capped at the UTC reset.
    assert waits == [31.0, 31.0]
    messages = [r.getMessage() for r in caplog.records]
    assert sum("claiming paused" in m for m in messages) == 1
    assert sum("claiming resumed" in m for m in messages) == 1


def test_readiness_stays_up_but_reports_the_budget_pause():
    state = RuntimeState(
        stage="triage", ready=True, budget_paused=True, daily_budget_usd=5.0, daily_spend_usd=5.0
    )
    server = start_operations_server(state, "127.0.0.1", 0)
    port = server.server_address[1]
    try:
        response = urllib.request.urlopen(f"http://127.0.0.1:{port}/readyz")
        assert response.status == 200
        assert b'"paused":"daily_budget"' in response.read()
        metrics = urllib.request.urlopen(f"http://127.0.0.1:{port}/metrics").read().decode()
        assert 'umai_worker_budget_paused{stage="triage"} 1' in metrics
        assert 'umai_worker_daily_budget_usd{stage="triage"} 5.0' in metrics
        assert 'umai_worker_daily_spend_usd{stage="triage"} 5.0' in metrics
        assert 'umai_worker_budget_stops_total{stage="triage"} 0' in metrics
    finally:
        server.shutdown()
        server.server_close()
