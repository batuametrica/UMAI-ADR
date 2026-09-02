"""Triage stage: cheap, high-recall filter over collected sessions.

Wraps ADR's `TriageLLM` — the prompt and threat-tactic taxonomy are upstream IP
and are used unchanged. What this module adds is the plumbing: making the
upstream package importable, pointing the client at a sovereign model, and
turning a collected session into the message shape the prompt expects.

Triage is deliberately tuned to over-escalate. Its verdict never raises a
finding on its own; it decides what is worth the reasoning stage's time.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional

import yaml

from .transcript import posture_preamble, to_adr_messages

if TYPE_CHECKING:  # pragma: no cover
    from .config import StageConfig

DETECTION_ROOT = Path(__file__).resolve().parents[2] / "Detection"

# Upstream's `TriageLLM.analyze` catches every exception and returns a
# synthetic `is_suspicious=True, confidence=0.9` result tagged with this
# `analysis_method`, on a "high recall: escalate on error" argument
# (`Detection/guardrail/adr_agent/adr_baseline.py`). That argument holds for a
# benchmark run and fails for a product: a provider outage then produces a
# fleet-wide wave of high-confidence "suspicious" verdicts that are not
# detections, and escalates every one of them to the expensive reasoning
# stage. The session was never examined, so the only honest result is the
# `error` verdict the worker contract defines for exactly this case.
#
# `test_triage.py::test_upstream_still_marks_errors_with_known_method` pins
# this literal against the vendored upstream, so a rename fails a test instead
# of silently restoring the fabricated verdicts.
UPSTREAM_ERROR_METHOD = "Fast Triage (Error)"


class TriageUnavailable(RuntimeError):
    """Triage could not be performed, so no verdict exists for this session.

    Raised in place of upstream's fail-open result. The batch loop reports it
    as `verdict: error`, which the platform records as `analysis_failed` with
    the reason attached — an unexamined session stays visibly unexamined.
    """


def _ensure_detection_importable() -> None:
    """Put upstream `Detection/` on the path.

    It is a directory of scripts rather than an installed package — `openai_config`
    and `base_detector` are imported as top-level modules by upstream code — so
    the directory itself has to be importable.
    """
    root = str(DETECTION_ROOT)
    if root not in sys.path:
        sys.path.insert(0, root)


def load_detector_config(path: Optional[Path] = None) -> dict[str, Any]:
    config_path = path or DETECTION_ROOT / "config_detector.yaml"
    try:
        with open(config_path, encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except OSError:
        return {}


def _with_triage_model(config: dict[str, Any], model: str) -> dict[str, Any]:
    """A copy of the detector config with the triage model replaced.

    Copied rather than mutated: the same dict is handed to the reasoning stage,
    and one stage must not be able to change the other's model.
    """
    updated = dict(config)
    framework = dict(updated.get("adr_framework") or {})
    key = "triage_llm" if "triage_llm" in framework else "triage_agent"
    section = dict(framework.get(key) or {})
    section["model"] = model
    framework[key] = section
    updated["adr_framework"] = framework
    return updated


@dataclass
class TriageOutcome:
    verdict: str  # "suspicious" | "benign"
    threat_tactic: Optional[str]
    reason: Optional[str]
    confidence: Optional[float]
    model: Optional[str]
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: Optional[float] = None

    def to_result(self, tenant_id: str, session_key: str) -> dict[str, Any]:
        return {
            "tenant_id": tenant_id,
            "session_key": session_key,
            "stage": "triage",
            "verdict": self.verdict,
            "threat_tactic": self.threat_tactic,
            "confidence": self.confidence,
            "reason": self.reason,
            "model": self.model,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cost_usd": self.cost_usd,
        }


class TriageRunner:
    """Runs ADR's triage stage against collected sessions.

    `stage` carries the model, endpoint and timeout for triage specifically.
    Passing it is what lets a regulated customer run this stage on a model in
    their own network while the reasoning stage runs elsewhere.
    """

    def __init__(
        self,
        config: Optional[dict[str, Any]] = None,
        *,
        stage: Optional["StageConfig"] = None,
    ):
        _ensure_detection_importable()

        from guardrail.adr_agent.adr_baseline import ADSConfig, TriageLLM  # noqa: E402
        from openai_config import calculate_cost, get_openai_client  # noqa: E402

        from .config import build_client  # noqa: PLC0415

        self._calculate_cost = calculate_cost
        detector_config = config or load_detector_config()
        if stage is not None:
            # `TriageLLM` reads the model from the config, not from the client,
            # so a per-stage model has to be written in here or it is ignored.
            detector_config = _with_triage_model(detector_config, stage.model)
        self._config = ADSConfig(detector_config)
        self._stage = stage
        # No stage config means the shared client, which is how the standalone
        # scripts in `Detection/` still call this.
        client = build_client(stage) if stage is not None else get_openai_client()
        self._triage = TriageLLM(client, self._config)

    @property
    def model(self) -> str:
        if self._stage is not None:
            return self._stage.model
        return self._config.get_triage_model()

    def run(self, session: dict[str, Any]) -> TriageOutcome:
        messages = to_adr_messages(session)

        preamble = posture_preamble(session)
        if preamble:
            # Prepend as a system-role line so the permissions the session ran
            # under are part of what triage weighs, not invisible context.
            messages.insert(0, {"role": "system", "content": preamble})

        if not messages:
            return TriageOutcome(
                verdict="benign",
                threat_tactic=None,
                reason="Session has no readable content",
                confidence=1.0,
                model=self.model,
            )

        result = self._triage.analyze(messages)

        if getattr(result, "analysis_method", None) == UPSTREAM_ERROR_METHOD:
            raise TriageUnavailable(
                getattr(result, "reason", None) or "Triage failed without a reason"
            )

        tactic = getattr(result, "threat_tactic", None)
        if tactic in ("N/A", "", None):
            tactic = None

        cost = None
        try:
            rates = self._config.get_triage_rates()
            cost = self._calculate_cost(*rates, result.input_tokens, result.output_tokens)
        except Exception:
            pass

        return TriageOutcome(
            verdict="suspicious" if result.is_suspicious else "benign",
            threat_tactic=tactic,
            reason=getattr(result, "reason", None),
            confidence=getattr(result, "confidence", None),
            model=self.model,
            input_tokens=getattr(result, "input_tokens", 0) or 0,
            output_tokens=getattr(result, "output_tokens", 0) or 0,
            cost_usd=cost,
        )
