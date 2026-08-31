"""Analysis worker entrypoint.

    python -m umai.worker --stage triage --once

Claims sessions from the platform, runs a detection stage, posts results back.
Outbound connections only.
"""

from __future__ import annotations

import argparse
import logging
import random
import sys
import time

from .client import PlatformClient, PlatformConfig, PlatformError
from .config import ConfigError, WorkerConfig, load_worker_config

logger = logging.getLogger("umai.worker")


class BudgetExceeded(RuntimeError):
    """The batch has spent what it was allowed to spend.

    Raised rather than returned so it unwinds the batch loop: continuing to
    claim sessions once the budget is gone just marks them all failed.
    """


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


def _check_batch_budget(config: WorkerConfig, spent: float) -> None:
    cap = config.budget.max_cost_per_batch_usd
    if cap and spent >= cap:
        raise BudgetExceeded(
            f"Batch budget of ${cap:.4f} is spent (${spent:.4f} used). "
            "Raise UMAI_MAX_COST_PER_BATCH_USD or run more batches."
        )


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
    client: PlatformClient, limit: int, tenant_id: str | None, config: WorkerConfig
) -> int:
    from .triage import TriageRunner

    sessions = client.claim("triage", limit=limit, tenant_id=tenant_id)
    if not sessions:
        return 0

    stage = config.triage
    runner = TriageRunner(stage=stage)
    processed = 0
    spent = 0.0

    for session in sessions:
        tenant = str(session["tenant_id"])
        key = session["session_key"]
        try:
            _check_batch_budget(config, spent)
            transcript = client.transcript(tenant, key)
            outcome = runner.run(transcript)
            spent += _account(config, stage, outcome, key)
            client.submit(outcome.to_result(tenant, key))
            processed += 1
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
        except BudgetExceeded as e:
            _report_failure(client, tenant, key, "triage", stage.model, str(e))
            logger.warning("triage batch stopped: %s", e)
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
    client: PlatformClient, limit: int, tenant_id: str | None, config: WorkerConfig
) -> int:
    sessions = client.claim("reason", limit=limit, tenant_id=tenant_id)
    if not sessions:
        return 0

    stage = config.reasoning
    runner = _build_reasoning_runner(config)
    processed = 0
    spent = 0.0

    for session in sessions:
        tenant = str(session["tenant_id"])
        key = session["session_key"]
        try:
            _check_batch_budget(config, spent)
            transcript = client.transcript(tenant, key)
            outcome = runner.run(transcript, triage_tactic=session.get("threat_tactic"))
            spent += _account(config, stage, outcome, key)
            client.submit(outcome.to_result(tenant, key, session.get("threat_tactic")))
            processed += 1
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
        except BudgetExceeded as e:
            _report_failure(client, tenant, key, "reason", stage.model, str(e))
            logger.warning("reason batch stopped: %s", e)
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

    return processed


STAGE_RUNNERS = {"triage": _run_triage_batch, "reason": _run_reason_batch}


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

    total = 0
    while True:
        try:
            processed = STAGE_RUNNERS[args.stage](
                client, args.limit, args.tenant_id, worker_config
            )
        except PlatformError as e:
            logger.warning("claim failed: %s", e)
            processed = 0

        total += processed

        if args.once and processed == 0:
            break
        if processed == 0:
            # Jitter so several workers do not wake together.
            time.sleep(args.idle_seconds + random.uniform(0, args.idle_seconds * 0.1))

    logger.info("worker finished, %s session(s) processed", total)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
