"""Analysis worker entrypoint.

    python -m umai.worker --stage triage --once

Claims sessions from the platform, runs a detection stage, posts results back.
Outbound connections only.
"""

from __future__ import annotations

import argparse
import logging
import os
import random
import sys
import time

from .client import PlatformClient, PlatformConfig, PlatformError

logger = logging.getLogger("umai.worker")


def _run_triage_batch(client: PlatformClient, limit: int, tenant_id: str | None) -> int:
    from .triage import TriageRunner

    sessions = client.claim("triage", limit=limit, tenant_id=tenant_id)
    if not sessions:
        return 0

    runner = TriageRunner()
    processed = 0

    for session in sessions:
        tenant = str(session["tenant_id"])
        key = session["session_key"]
        try:
            transcript = client.transcript(tenant, key)
            outcome = runner.run(transcript)
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
        except Exception as e:  # noqa: BLE001 - one bad session must not stop the batch
            logger.exception("triage session=%s failed: %s", key[:12], e)

    return processed


def _build_reasoning_runner():
    """Reuse the detector config so both stages read one source of truth."""
    from .triage import _ensure_detection_importable, load_detector_config
    from .reasoning import ReasoningRunner

    _ensure_detection_importable()
    from openai_config import get_openai_client  # noqa: E402

    config = load_detector_config()
    agent = (config.get("adr_framework") or {}).get("reasoning_agent") or {}
    model = os.environ.get("UMAI_REASONING_MODEL", "").strip() or agent.get(
        "model", "claude-sonnet-4-6"
    )
    rates = (
        float(agent.get("cost_per_1m_input", 0) or 0),
        float(agent.get("cost_per_1m_output", 0) or 0),
    )

    return ReasoningRunner(
        get_openai_client(),
        model=model,
        max_turns=int(agent.get("max_turns", 12) or 12),
        max_tokens=int(agent.get("max_tokens", 4000) or 4000),
        use_tools=os.environ.get("UMAI_REASONING_TOOLS", "1") != "0",
        cost_rates=rates,
    )


def _run_reason_batch(client: PlatformClient, limit: int, tenant_id: str | None) -> int:
    sessions = client.claim("reason", limit=limit, tenant_id=tenant_id)
    if not sessions:
        return 0

    runner = _build_reasoning_runner()
    processed = 0

    for session in sessions:
        tenant = str(session["tenant_id"])
        key = session["session_key"]
        try:
            transcript = client.transcript(tenant, key)
            outcome = runner.run(transcript, triage_tactic=session.get("threat_tactic"))
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
        except Exception as e:  # noqa: BLE001
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

    try:
        client = PlatformClient(PlatformConfig.from_env())
    except PlatformError as e:
        print(f"Configuration error: {e}", file=sys.stderr)
        return 2

    total = 0
    while True:
        try:
            processed = STAGE_RUNNERS[args.stage](client, args.limit, args.tenant_id)
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
