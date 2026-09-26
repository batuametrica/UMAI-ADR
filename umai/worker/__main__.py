"""Analysis worker entrypoint.

    python -m umai.worker --stage triage --once

Claims sessions from the platform, runs a detection stage, posts results back.
Outbound connections only.
"""

from __future__ import annotations

import argparse
import datetime as dt
import logging
import os
import random
import signal
import sys
import threading
import time
from collections.abc import Callable

from .client import PlatformClient, PlatformConfig, PlatformError
from .config import ConfigError, WorkerConfig, load_worker_config
from .operations import RuntimeState, start_operations_server

logger = logging.getLogger("umai.worker")


class BudgetExceeded(RuntimeError):
    """The batch (or the day) has spent what it was allowed to spend.

    Raised rather than returned so it unwinds the batch loop: continuing to
    claim sessions once the budget is gone just marks them all failed. The
    sessions still held are released back to the queue, unanalysed.
    """


def _utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


class DailySpend:
    """Cumulative spend for this worker process in the current UTC day.

    The batch cap resets every time a batch is claimed, so on its own it bounds
    nothing across a backfill. This accumulator survives batches and is only
    reset when the UTC date changes. It is per process and in memory: a
    restarted worker starts the day at $0 again, and N replicas may each spend
    the cap.
    """

    def __init__(self, cap_usd: float, clock: Callable[[], dt.datetime] = _utc_now):
        self.cap_usd = cap_usd
        self._clock = clock
        self.day = clock().date()
        self.spent_usd = 0.0

    def _roll(self) -> None:
        today = self._clock().date()
        if today != self.day:
            self.day = today
            self.spent_usd = 0.0

    def add(self, cost: float) -> None:
        self._roll()
        self.spent_usd += cost or 0.0

    def exhausted(self) -> bool:
        self._roll()
        return bool(self.cap_usd) and self.spent_usd >= self.cap_usd

    def seconds_until_reset(self) -> float:
        now = self._clock()
        midnight = dt.datetime.combine(
            now.date() + dt.timedelta(days=1), dt.time(0), tzinfo=dt.timezone.utc
        )
        return max((midnight - now).total_seconds(), 0.0)


def _failure_result(
    tenant_id: str, session_key: str, stage: str, model: str, reason: str
) -> dict:
    """A result that says the analysis did not happen.

    Without this the platform sees no result at all and the lease expires, so
    the session is retried forever; worse, at the triage stage any verdict
    other than `suspicious` marks it benign. Either way nobody learns that the
    model timed out.
    """
    return {
        "tenant_id": tenant_id,
        "session_key": session_key,
        "stage": stage,
        "verdict": "error",
        "reason": reason,
        "model": model,
    }


def _is_timeout(error: BaseException) -> bool:
    if isinstance(error, TimeoutError):
        return True
    return "timeout" in type(error).__name__.lower() or "timed out" in str(error).lower()


def _describe_failure(error: BaseException) -> str:
    """A one-line reason an operator can act on."""
    name = type(error).__name__
    text = str(error).strip()
    if _is_timeout(error):
        return f"Model call timed out: {text or name}"
    return f"{name}: {text}" if text else name


def _check_batch_budget(
    config: WorkerConfig, spent: float, daily: DailySpend | None = None
) -> None:
    cap = config.budget.max_cost_per_batch_usd
    if cap and spent >= cap:
        raise BudgetExceeded(
            f"Batch budget of ${cap:.4f} is spent (${spent:.4f} used). "
            "Raise UMAI_MAX_COST_PER_BATCH_USD or run more batches."
        )
    if daily is not None and daily.exhausted():
        raise BudgetExceeded(
            f"Daily budget of ${daily.cap_usd:.4f} is spent "
            f"(${daily.spent_usd:.4f} used on {daily.day.isoformat()} UTC). "
            "Claiming resumes at 00:00 UTC; raise UMAI_MAX_COST_PER_DAY_USD to "
            "resume sooner."
        )


def _release_unprocessed(
    client: PlatformClient,
    stage_name: str,
    sessions: list[dict],
    runtime: RuntimeState | None,
) -> None:
    """Hand claimed-but-unanalysed sessions back to the queue.

    Best effort: if the release call fails, the leases expire and the platform
    reclaims the sessions, which is slower but loses nothing.
    """
    try:
        released = client.release(stage_name, sessions)
    except PlatformError as e:
        logger.warning(
            "%s could not release %s session(s); their leases will expire: %s",
            stage_name,
            len(sessions),
            e,
        )
        return
    if runtime:
        runtime.released_total += released
        runtime.active_leases = max(runtime.active_leases - released, 0)


def _record_spend(
    cost: float, daily: DailySpend | None, runtime: RuntimeState | None
) -> None:
    if daily is not None:
        daily.add(cost)
        if runtime:
            runtime.daily_spend_usd = daily.spent_usd


def _account(config: WorkerConfig, stage, outcome, session_key: str) -> float:
    """Price one session and complain if it blew the per-session cap.

    The session has already been analysed by the time this runs, so the money
    is spent whether or not it was allowed. Recording the overrun is the useful
    part: a cap that keeps being hit means either the cap or the model is wrong.
    """
    cost = outcome.cost_usd
    if cost is None:
        cost = stage.price(
            getattr(outcome, "input_tokens", 0) or 0,
            getattr(outcome, "output_tokens", 0) or 0,
        )
    cap = config.budget.max_cost_per_session_usd
    if cap and cost > cap:
        logger.warning(
            "%s session=%s cost $%.5f exceeded the per-session cap of $%.5f",
            stage.stage,
            session_key[:12],
            cost,
            cap,
        )
    return cost or 0.0


def _report_failure(
    client: PlatformClient,
    tenant: str,
    key: str,
    stage_name: str,
    model: str,
    reason: str,
) -> None:
    """Tell the platform the analysis failed, and why.

    Best effort: if this call fails too, the lease expires and the session is
    reclaimed, which is the behaviour there was before.
    """
    try:
        client.submit(_failure_result(tenant, key, stage_name, model, reason))
    except PlatformError as e:
        logger.warning("could not report failure for session=%s: %s", key[:12], e)


def _run_triage_batch(
    client: PlatformClient,
    limit: int,
    tenant_id: str | None,
    config: WorkerConfig,
    stop: threading.Event | None = None,
    runtime: RuntimeState | None = None,
    daily: DailySpend | None = None,
) -> int:
    from .triage import TriageRunner

    if daily is not None and daily.exhausted():
        # Do not take leases that could not be worked.
        return 0
    sessions = client.claim("triage", limit=limit, tenant_id=tenant_id)
    if runtime:
        runtime.queue_claim_batch_size = len(sessions)
    if not sessions:
        return 0
    if runtime:
        runtime.claimed_total += len(sessions)
        runtime.active_leases += len(sessions)
        runtime.queue_age_seconds = _oldest_queue_age(sessions)

    stage = config.triage
    runner = TriageRunner(stage=stage)
    processed = 0
    spent = 0.0

    for index, session in enumerate(sessions):
        if stop and stop.is_set():
            released = client.release("triage", sessions[index:])
            if runtime:
                runtime.released_total += released
                runtime.active_leases = max(runtime.active_leases - released, 0)
            break
        tenant = str(session["tenant_id"])
        key = session["session_key"]
        try:
            _check_batch_budget(config, spent, daily)
            transcript = client.transcript(tenant, key)
            outcome = runner.run(transcript)
            cost = _account(config, stage, outcome, key)
            spent += cost
            _record_spend(cost, daily, runtime)
            client.submit(outcome.to_result(tenant, key))
            processed += 1
            if runtime:
                runtime.processed_total += 1
                runtime.active_leases = max(runtime.active_leases - 1, 0)
                runtime.last_success_at = time.time()
            logger.info(
                "triage session=%s verdict=%s tactic=%s cost=%s",
                key[:12],
                outcome.verdict,
                outcome.threat_tactic,
                f"${outcome.cost_usd:.5f}" if outcome.cost_usd else "n/a",
            )
        except PlatformError as e:
            # Leave the lease to expire; the session is reclaimed and retried.
            logger.warning("triage session=%s platform error: %s", key[:12], e)
            if runtime:
                runtime.failed_total += 1
        except BudgetExceeded as e:
            # Nothing from this session on was analysed. Released rather than
            # reported as failed: running out of budget says nothing about the
            # session, and a released session is picked up again once there is
            # budget instead of waiting out its lease.
            logger.warning("triage batch stopped: %s", e)
            _release_unprocessed(client, "triage", sessions[index:], runtime)
            if runtime:
                runtime.budget_stops_total += 1
            break
        except Exception as e:  # noqa: BLE001 - one bad session must not stop the batch
            _report_failure(
                client, tenant, key, "triage", stage.model, _describe_failure(e)
            )
            if _is_timeout(e):
                logger.warning(
                    "triage session=%s timed out after %ss", key[:12], stage.timeout_s
                )
            else:
                logger.exception("triage session=%s failed: %s", key[:12], e)
            if runtime:
                runtime.failed_total += 1

    return processed


def _build_reasoning_runner(config: WorkerConfig):
    """A reasoning runner bound to the endpoint configured for that stage."""
    from .config import build_client
    from .reasoning import ReasoningRunner
    from .triage import _ensure_detection_importable

    _ensure_detection_importable()
    stage = config.reasoning

    return ReasoningRunner(
        build_client(stage),
        model=stage.model,
        max_turns=config.reasoning_max_turns,
        max_tokens=config.reasoning_max_tokens,
        use_tools=config.reasoning_use_tools,
        cost_rates=(stage.cost_per_1m_input, stage.cost_per_1m_output),
    )


def _run_reason_batch(
    client: PlatformClient,
    limit: int,
    tenant_id: str | None,
    config: WorkerConfig,
    stop: threading.Event | None = None,
    runtime: RuntimeState | None = None,
    daily: DailySpend | None = None,
) -> int:
    if daily is not None and daily.exhausted():
        return 0
    sessions = client.claim("reason", limit=limit, tenant_id=tenant_id)
    if runtime:
        runtime.queue_claim_batch_size = len(sessions)
    if not sessions:
        return 0
    if runtime:
        runtime.claimed_total += len(sessions)
        runtime.active_leases += len(sessions)
        runtime.queue_age_seconds = _oldest_queue_age(sessions)

    stage = config.reasoning
    runner = _build_reasoning_runner(config)
    processed = 0
    spent = 0.0

    for index, session in enumerate(sessions):
        if stop and stop.is_set():
            released = client.release("reason", sessions[index:])
            if runtime:
                runtime.released_total += released
                runtime.active_leases = max(runtime.active_leases - released, 0)
            break
        tenant = str(session["tenant_id"])
        key = session["session_key"]
        try:
            _check_batch_budget(config, spent, daily)
            transcript = client.transcript(tenant, key)
            outcome = runner.run(transcript, triage_tactic=session.get("threat_tactic"))
            cost = _account(config, stage, outcome, key)
            spent += cost
            _record_spend(cost, daily, runtime)
            client.submit(outcome.to_result(tenant, key, session.get("threat_tactic")))
            processed += 1
            if runtime:
                runtime.processed_total += 1
                runtime.active_leases = max(runtime.active_leases - 1, 0)
                runtime.last_success_at = time.time()
            logger.info(
                "reason session=%s verdict=%s technique=%s tools=%s cost=%s",
                key[:12],
                outcome.verdict,
                outcome.technique_id,
                outcome.tool_calls,
                f"${outcome.cost_usd:.5f}" if outcome.cost_usd else "n/a",
            )
        except PlatformError as e:
            logger.warning("reason session=%s platform error: %s", key[:12], e)
            if runtime:
                runtime.failed_total += 1
        except BudgetExceeded as e:
            # Nothing from this session on was analysed. Released rather than
            # reported as failed: running out of budget says nothing about the
            # session, and a released session is picked up again once there is
            # budget instead of waiting out its lease.
            logger.warning("reason batch stopped: %s", e)
            _release_unprocessed(client, "reason", sessions[index:], runtime)
            if runtime:
                runtime.budget_stops_total += 1
            break
        except Exception as e:  # noqa: BLE001
            _report_failure(
                client, tenant, key, "reason", stage.model, _describe_failure(e)
            )
            if _is_timeout(e):
                logger.warning(
                    "reason session=%s timed out after %ss", key[:12], stage.timeout_s
                )
            else:
                logger.exception("reason session=%s failed: %s", key[:12], e)
            if runtime:
                runtime.failed_total += 1

    return processed


STAGE_RUNNERS = {"triage": _run_triage_batch, "reason": _run_reason_batch}


def _oldest_queue_age(sessions: list[dict]) -> float:
    now = dt.datetime.now(dt.timezone.utc)
    ages = []
    for item in sessions:
        value = item.get("observed_at")
        if not value:
            continue
        try:
            observed = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
            if observed.tzinfo is None:
                observed = observed.replace(tzinfo=dt.timezone.utc)
            ages.append(max((now - observed).total_seconds(), 0.0))
        except ValueError:
            continue
    return max(ages, default=0.0)


def _wait_for_daily_budget(
    daily: DailySpend,
    runtime: RuntimeState,
    stop: threading.Event,
    idle_seconds: float,
    wait: bool = True,
) -> bool:
    """Pause claiming while the daily budget is spent.

    Returns True when the budget is spent (after one idle wait, capped at the
    UTC reset so the new day starts on time), False when claiming may go on.
    The pause is logged once when it starts and once when it ends, not on
    every wake.
    """
    if not daily.exhausted():
        if runtime.budget_paused:
            runtime.budget_paused = False
            runtime.daily_spend_usd = daily.spent_usd
            logger.info(
                "new UTC day %s; daily budget reset, claiming resumed",
                daily.day.isoformat(),
            )
        return False

    if not runtime.budget_paused:
        runtime.budget_paused = True
        logger.warning(
            "daily budget of $%.4f spent ($%.4f on %s UTC); claiming paused "
            "for %.0fs until 00:00 UTC",
            daily.cap_usd,
            daily.spent_usd,
            daily.day.isoformat(),
            daily.seconds_until_reset(),
        )
    if wait:
        stop.wait(min(idle_seconds, daily.seconds_until_reset() + 1))
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="UMAI analysis worker")
    parser.add_argument("--stage", choices=["triage", "reason"], default="triage")
    parser.add_argument("--limit", type=int, default=10, help="Sessions claimed per batch")
    parser.add_argument("--once", action="store_true", help="Drain the queue and exit")
    parser.add_argument("--tenant-id", default=None, help="Restrict to one tenant")
    parser.add_argument(
        "--idle-seconds", type=int, default=60, help="Pause when there is no work"
    )
    parser.add_argument("--log-level", default="INFO")
    parser.add_argument("--metrics-host", default=os.environ.get("UMAI_WORKER_METRICS_HOST", "0.0.0.0"))
    parser.add_argument("--metrics-port", type=int, default=int(os.environ.get("UMAI_WORKER_METRICS_PORT", "9100")))
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )

    # Both configurations are resolved before a single session is claimed. A
    # worker that will fail on a bad model name or a missing endpoint should
    # say so now, not after it has taken a lease on ten sessions.
    try:
        client = PlatformClient(PlatformConfig.from_env())
        worker_config = load_worker_config()
    except (PlatformError, ConfigError) as e:
        print(f"Configuration error: {e}", file=sys.stderr)
        return 2

    for line in worker_config.describe():
        logger.info("config %s", line)

    stop = threading.Event()
    # Readiness stays false until the platform accepts the first claim request.
    # This keeps a configured-but-disconnected worker out of service discovery.
    runtime = RuntimeState(stage=args.stage)
    operations = start_operations_server(runtime, args.metrics_host, args.metrics_port)

    def request_stop(signum, _frame):
        logger.info("shutdown requested signal=%s; finishing current session", signum)
        runtime.ready = False
        stop.set()

    signal.signal(signal.SIGTERM, request_stop)
    signal.signal(signal.SIGINT, request_stop)

    daily = DailySpend(worker_config.budget.max_cost_per_day_usd)
    runtime.daily_budget_usd = daily.cap_usd

    total = 0
    while not stop.is_set():
        if _wait_for_daily_budget(
            daily, runtime, stop, args.idle_seconds, wait=not args.once
        ):
            if args.once:
                break
            continue

        started = time.monotonic()
        try:
            processed = STAGE_RUNNERS[args.stage](
                client, args.limit, args.tenant_id, worker_config, stop, runtime, daily
            )
            runtime.ready = True
        except PlatformError as e:
            logger.warning("claim failed: %s", e)
            runtime.ready = False
            runtime.claim_errors_total += 1
            processed = 0
        finally:
            runtime.batch_duration_seconds = time.monotonic() - started

        total += processed

        if args.once and processed == 0:
            break
        if processed == 0:
            # Jitter so several workers do not wake together.
            stop.wait(args.idle_seconds + random.uniform(0, args.idle_seconds * 0.1))

    runtime.ready = False
    operations.shutdown()
    operations.server_close()
    logger.info("worker finished, %s session(s) processed", total)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
