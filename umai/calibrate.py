"""Measure how well a triage model filters a real session corpus.

The number that decides whether this product is affordable is the elimination
rate: what share of sessions triage clears without paying for the reasoning
stage. Upstream reports roughly 3,950 of 4,000 cleared at tier one. If a model
escalates everything, the two-tier design collapses into one expensive tier.

Runs against session files on disk rather than the platform queue, so a
calibration pass neither consumes work nor mutates state, and the same corpus
can be replayed across candidate models.

    python -m umai.calibrate --sessions ./out --model gpt-oss-safeguard-20b

Produces a per-session CSV alongside the summary so two models can be diffed
session by session, not just on headline rates.
"""

from __future__ import annotations

import argparse
import csv
import json
import statistics
import sys
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterator, Optional


@dataclass
class SessionResult:
    session_id: str
    source: str
    messages: int
    tool_calls: int
    verdict: str
    tactic: Optional[str]
    confidence: Optional[float]
    latency_ms: float
    input_tokens: int
    output_tokens: int
    cost_usd: Optional[float]
    error: Optional[str] = None


@dataclass
class Calibration:
    model: str
    results: list[SessionResult] = field(default_factory=list)
    ground_truth: dict[str, str] = field(default_factory=dict)

    @property
    def scored(self) -> list[SessionResult]:
        return [r for r in self.results if r.error is None]

    @property
    def elimination_rate(self) -> float:
        """Share of sessions triage clears without escalating."""
        scored = self.scored
        if not scored:
            return 0.0
        return sum(1 for r in scored if r.verdict == "benign") / len(scored)

    def recall(self) -> dict[str, Any] | None:
        """How triage performs against labels, when the corpus has them.

        Triage recall is the number that matters most: a malicious session it
        clears is never seen again. Escalating a benign one only costs money.
        """
        if not self.ground_truth:
            return None

        labelled = [r for r in self.scored if r.session_id in self.ground_truth]
        if not labelled:
            return None

        malicious = [r for r in labelled if self.ground_truth[r.session_id] == "malicious"]
        benign = [r for r in labelled if self.ground_truth[r.session_id] == "benign"]

        caught = sum(1 for r in malicious if r.verdict == "suspicious")
        escalated_benign = sum(1 for r in benign if r.verdict == "suspicious")

        return {
            "labelled": len(labelled),
            "malicious": len(malicious),
            "malicious_escalated": caught,
            "malicious_missed": len(malicious) - caught,
            "triage_recall": round(caught / len(malicious), 4) if malicious else None,
            "benign": len(benign),
            "benign_escalated": escalated_benign,
            "benign_escalation_rate": round(escalated_benign / len(benign), 4) if benign else None,
        }

    def summary(self) -> dict[str, Any]:
        scored = self.scored
        latencies = sorted(r.latency_ms for r in scored)
        costs = [r.cost_usd for r in scored if r.cost_usd is not None]

        def pct(values: list[float], fraction: float) -> float:
            if not values:
                return 0.0
            return values[min(int(len(values) * fraction), len(values) - 1)]

        return {
            "model": self.model,
            "sessions": len(self.results),
            "scored": len(scored),
            "errors": len(self.results) - len(scored),
            "eliminated": sum(1 for r in scored if r.verdict == "benign"),
            "escalated": sum(1 for r in scored if r.verdict == "suspicious"),
            "elimination_rate": round(self.elimination_rate, 4),
            "tactics": dict(Counter(r.tactic for r in scored if r.tactic)),
            "input_tokens": sum(r.input_tokens for r in scored),
            "output_tokens": sum(r.output_tokens for r in scored),
            "cost_usd_total": round(sum(costs), 4) if costs else None,
            "cost_usd_per_session": round(statistics.mean(costs), 6) if costs else None,
            "latency_ms_p50": round(pct(latencies, 0.5), 1),
            "latency_ms_p95": round(pct(latencies, 0.95), 1),
            "against_ground_truth": self.recall(),
        }

    def write_csv(self, path: Path) -> None:
        with open(path, "w", encoding="utf-8", newline="") as f:
            writer = csv.writer(f)
            writer.writerow(
                [
                    "session_id", "source", "messages", "tool_calls", "verdict",
                    "tactic", "confidence", "latency_ms", "input_tokens",
                    "output_tokens", "cost_usd", "error",
                ]
            )
            for r in self.results:
                writer.writerow(
                    [
                        r.session_id, r.source, r.messages, r.tool_calls, r.verdict,
                        r.tactic or "", r.confidence if r.confidence is not None else "",
                        round(r.latency_ms, 1), r.input_tokens, r.output_tokens,
                        r.cost_usd if r.cost_usd is not None else "", r.error or "",
                    ]
                )


BENCHMARK_ROOT = Path(__file__).resolve().parents[1] / "Detection"


def load_benchmark(
    packed: Optional[Path] = None, tasks_json: Optional[Path] = None
) -> tuple[list[dict[str, Any]], dict[str, str]]:
    """Load ADR-Bench conversations with their ground-truth labels.

    Calibrating on this corpus rather than on customer transcripts has two
    advantages: it is synthetic by construction, so it can be sent to a
    candidate model without exposing anyone's source code; and it is labelled,
    so triage can be measured on what it *misses*, not just on how much it
    clears. A session triage clears is one the reasoning stage never sees, so a
    missed malicious task is a permanent miss.
    """
    packed = packed or BENCHMARK_ROOT / "benchmark" / "adr_bench_20251017_151604.jsonl"
    tasks_json = tasks_json or BENCHMARK_ROOT / "tasks.json"

    with open(tasks_json, encoding="utf-8") as f:
        raw = json.load(f)
    task_list = raw["tasks"] if isinstance(raw, dict) else raw

    # The packed run identifies tasks as `task_001`; tasks.json uses the bare
    # integer. Index both forms so the labels attach either way.
    ground_truth: dict[str, str] = {}
    for task in task_list:
        label = task.get("ground_truth", "unknown")
        raw_id = str(task["task_id"])
        ground_truth[raw_id] = label
        if raw_id.isdigit():
            ground_truth[f"task_{int(raw_id):03d}"] = label

    sessions: list[dict[str, Any]] = []
    with open(packed, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            if record.get("type") == "manifest":
                continue

            chat_history = []
            for message in record.get("conversation") or []:
                tools = [
                    {"tool_name": call.get("name", "unknown"), "arguments": {}}
                    for call in message.get("tool_calls") or []
                ]
                chat_history.append(
                    {
                        "role": message.get("role", "unknown"),
                        "content": message.get("content") or "",
                        "tools": tools,
                    }
                )

            sessions.append(
                {
                    "source": "adr_bench",
                    "session_id": str(record.get("task_id")),
                    "chat_history": chat_history,
                }
            )

    return sessions, ground_truth


def load_sessions(root: Path) -> Iterator[dict[str, Any]]:
    """Read collected sessions from `adr-sensor --save-sessions` output."""
    for path in sorted(root.rglob("*.json")):
        try:
            with open(path, encoding="utf-8") as f:
                payload = json.load(f)
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(payload, dict) and payload.get("chat_history"):
            yield payload
        elif isinstance(payload, dict) and isinstance(payload.get("entries"), list):
            # The combined export format.
            for entry in payload["entries"]:
                if entry.get("chat_history"):
                    yield entry


def run(
    sessions: list[dict[str, Any]],
    model_override: Optional[str] = None,
    ground_truth: Optional[dict[str, str]] = None,
) -> Calibration:
    from .worker.triage import TriageRunner, load_detector_config

    config = load_detector_config()
    if model_override:
        config.setdefault("adr_framework", {}).setdefault("triage_llm", {})["model"] = model_override

    runner = TriageRunner(config)
    calibration = Calibration(model=runner.model, ground_truth=ground_truth or {})

    for index, session in enumerate(sessions, 1):
        chat = session.get("chat_history") or []
        tools = sum(len(m.get("tools") or []) for m in chat)
        started = time.perf_counter()

        try:
            outcome = runner.run(session)
            calibration.results.append(
                SessionResult(
                    session_id=session.get("session_id", f"session-{index}"),
                    source=session.get("source", "unknown"),
                    messages=len(chat),
                    tool_calls=tools,
                    verdict=outcome.verdict,
                    tactic=outcome.threat_tactic,
                    confidence=outcome.confidence,
                    latency_ms=(time.perf_counter() - started) * 1000,
                    input_tokens=outcome.input_tokens,
                    output_tokens=outcome.output_tokens,
                    cost_usd=outcome.cost_usd,
                )
            )
        except Exception as e:  # noqa: BLE001 - a bad session must not end the run
            calibration.results.append(
                SessionResult(
                    session_id=session.get("session_id", f"session-{index}"),
                    source=session.get("source", "unknown"),
                    messages=len(chat),
                    tool_calls=tools,
                    verdict="error",
                    tactic=None,
                    confidence=None,
                    latency_ms=(time.perf_counter() - started) * 1000,
                    input_tokens=0,
                    output_tokens=0,
                    cost_usd=None,
                    error=f"{e.__class__.__name__}: {e}",
                )
            )

        print(f"  [{index}/{len(sessions)}] {calibration.results[-1].verdict}", flush=True)

    return calibration


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Calibrate the triage stage")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--sessions", type=Path, help="Directory of collected session JSON")
    source.add_argument(
        "--benchmark",
        action="store_true",
        help="Use ADR-Bench's recorded conversations and ground-truth labels",
    )
    parser.add_argument("--limit", type=int, default=0, help="Cap the corpus size")
    parser.add_argument("--model", default=None, help="Override the configured triage model")
    parser.add_argument("--csv", type=Path, default=None, help="Write per-session results here")
    args = parser.parse_args(argv)

    if args.benchmark:
        sessions, ground_truth = load_benchmark()
    else:
        sessions, ground_truth = list(load_sessions(args.sessions)), {}

    if args.limit:
        sessions = sessions[: args.limit]

    if not sessions:
        print(f"No sessions found under {args.sessions}", file=sys.stderr)
        return 1

    print(f"Calibrating on {len(sessions)} session(s)…")
    calibration = run(sessions, args.model, ground_truth)

    summary = calibration.summary()
    print("\n" + json.dumps(summary, indent=2, ensure_ascii=False))

    if args.csv:
        calibration.write_csv(args.csv)
        print(f"\nPer-session results: {args.csv}")

    # An elimination rate this low means the second tier pays for everything,
    # which is the failure mode the two-tier design exists to avoid.
    if summary["scored"] and summary["elimination_rate"] < 0.5:
        print(
            f"\nWARNING: only {summary['elimination_rate']:.0%} of sessions were cleared. "
            "The reasoning stage will run on most of the corpus.",
            file=sys.stderr,
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
