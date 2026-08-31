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
from typing import Any, Optional

import yaml

from .transcript import posture_preamble, to_adr_messages

DETECTION_ROOT = Path(__file__).resolve().parents[2] / "Detection"


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
    """Runs ADR's triage stage against collected sessions."""

    def __init__(self, config: Optional[dict[str, Any]] = None):
        _ensure_detection_importable()

        from guardrail.adr_agent.adr_baseline import ADSConfig, TriageLLM  # noqa: E402
        from openai_config import calculate_cost, get_openai_client  # noqa: E402

        self._calculate_cost = calculate_cost
        self._config = ADSConfig(config or load_detector_config())
        self._triage = TriageLLM(get_openai_client(), self._config)

    @property
    def model(self) -> str:
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
