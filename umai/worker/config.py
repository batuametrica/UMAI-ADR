"""Worker configuration: one place, validated once, at startup.

The two stages are not the same workload. Triage is a cheap high-recall filter
that a regulated customer runs on a model inside their own network; reasoning
is an expensive multi-turn agent that may run somewhere else entirely. Sharing
one model, one endpoint and one timeout between them meant a customer could
not have that, and it meant a hung reasoning call had nothing to hit but the
platform's lease expiry.

Everything is resolved and checked before the first session is claimed. A
worker that will fail on a bad model name should say so in the first second,
not after it has taken a lease on ten sessions.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Optional

# The defaults are deliberately different per stage. Triage runs per session,
# in bulk, and a slow one blocks the queue. Reasoning is a multi-turn agent
# with tool calls and legitimately takes longer.
DEFAULT_TRIAGE_TIMEOUT_S = 60.0
DEFAULT_REASONING_TIMEOUT_S = 300.0

# Off by default. A cap that silently stops analysing is worse than no cap
# for a customer who did not ask for one.
DEFAULT_MAX_COST_PER_SESSION_USD = 0.0
DEFAULT_MAX_COST_PER_BATCH_USD = 0.0


class ConfigError(RuntimeError):
    """The worker cannot start with the configuration it was given."""


@dataclass(frozen=True)
class StageConfig:
    """Model, endpoint and timeout for one analysis stage."""

    stage: str
    model: str
    base_url: Optional[str]
    api_key: str
    timeout_s: float
    # Per-1M-token rates, used to price a session and enforce the budget.
    cost_per_1m_input: float = 0.0
    cost_per_1m_output: float = 0.0

    def price(self, input_tokens: int, output_tokens: int) -> float:
        return (
            input_tokens * self.cost_per_1m_input
            + output_tokens * self.cost_per_1m_output
        ) / 1_000_000

    def describe(self) -> str:
        """A line safe to log: endpoint and model, never the key."""
        where = self.base_url or "api.openai.com"
        return f"{self.stage}: model={self.model} endpoint={where} timeout={self.timeout_s}s"


@dataclass(frozen=True)
class BudgetConfig:
    max_cost_per_session_usd: float = DEFAULT_MAX_COST_PER_SESSION_USD
    max_cost_per_batch_usd: float = DEFAULT_MAX_COST_PER_BATCH_USD

    @property
    def enforced(self) -> bool:
        return bool(self.max_cost_per_session_usd or self.max_cost_per_batch_usd)


@dataclass(frozen=True)
class WorkerConfig:
    triage: StageConfig
    reasoning: StageConfig
    budget: BudgetConfig
    # Reasoning-only agent limits, kept here so every knob has one home.
    reasoning_max_turns: int = 12
    reasoning_max_tokens: int = 4000
    reasoning_use_tools: bool = True

    def for_stage(self, stage: str) -> StageConfig:
        if stage == "triage":
            return self.triage
        if stage in ("reason", "reasoning"):
            return self.reasoning
        raise ConfigError(f"Unknown analysis stage: {stage!r}")

    def describe(self) -> list[str]:
        lines = [self.triage.describe(), self.reasoning.describe()]
        if self.budget.enforced:
            lines.append(
                "budget: "
                f"session=${self.budget.max_cost_per_session_usd:.4f} "
                f"batch=${self.budget.max_cost_per_batch_usd:.4f}"
            )
        return lines


# --- parsing ----------------------------------------------------------------


def _env(name: str) -> str:
    return os.environ.get(name, "").strip()


def _float(name: str, default: float, *, minimum: float | None = 0.0) -> float:
    raw = _env(name)
    if not raw:
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be a number, got {raw!r}") from exc
    if minimum is not None and value < minimum:
        raise ConfigError(f"{name} must be at least {minimum}, got {value}")
    return value


def _int(name: str, default: int, *, minimum: int = 1) -> int:
    raw = _env(name)
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ConfigError(f"{name} must be a whole number, got {raw!r}") from exc
    if value < minimum:
        raise ConfigError(f"{name} must be at least {minimum}, got {value}")
    return value


def _positive_timeout(name: str, default: float) -> float:
    # No minimum here: a negative and a zero timeout are the same mistake and
    # deserve the same explanation.
    value = _float(name, default, minimum=None)
    if value <= 0:
        # A zero timeout is almost always a typo for "no timeout", and "no
        # timeout" is the behaviour this card exists to remove.
        raise ConfigError(
            f"{name} must be greater than zero. A worker with no timeout hangs "
            "on the model instead of failing, and the session sits claimed "
            "until its lease expires."
        )
    return value


def _stage_config(
    stage: str,
    *,
    env_prefix: str,
    default_model: str,
    default_timeout: float,
    default_rates: tuple[float, float],
) -> StageConfig:
    """Resolve one stage, falling back to the shared OpenAI settings.

    Per-stage variables win. The shared ones stay supported so a single-model
    deployment does not have to set everything twice.
    """
    model = _env(f"{env_prefix}_MODEL") or default_model
    if not model:
        raise ConfigError(
            f"No model configured for the {stage} stage. "
            f"Set {env_prefix}_MODEL, or give the stage a model in "
            "Detection/config_detector.yaml."
        )

    base_url = _env(f"{env_prefix}_BASE_URL") or _env("OPENAI_BASE_URL") or None
    if base_url and not base_url.startswith(("http://", "https://")):
        raise ConfigError(
            f"{env_prefix}_BASE_URL must start with http:// or https://, got {base_url!r}"
        )

    api_key = _env(f"{env_prefix}_API_KEY") or _env("OPENAI_API_KEY")
    if not api_key:
        if not base_url:
            raise ConfigError(
                f"No API key for the {stage} stage. Set {env_prefix}_API_KEY or "
                "OPENAI_API_KEY, or point the stage at a local endpoint with "
                f"{env_prefix}_BASE_URL."
            )
        # A self-hosted OpenAI-compatible server usually ignores the key but
        # still requires the header to be present.
        api_key = "local"

    return StageConfig(
        stage=stage,
        model=model,
        base_url=base_url,
        api_key=api_key,
        timeout_s=_positive_timeout(f"{env_prefix}_TIMEOUT_SECONDS", default_timeout),
        cost_per_1m_input=default_rates[0],
        cost_per_1m_output=default_rates[1],
    )


def _section_timeout(section: dict[str, Any], fallback: float) -> float:
    """The stage timeout declared in the detector config, if it declares one.

    Upstream already writes `timeout:` next to each model; taking it from there
    means the two files do not disagree about the same number.
    """
    raw = section.get("timeout")
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return fallback
    return value if value > 0 else fallback


def _rates(section: dict[str, Any]) -> tuple[float, float]:
    try:
        return (
            float(section.get("cost_per_1m_input", 0) or 0),
            float(section.get("cost_per_1m_output", 0) or 0),
        )
    except (TypeError, ValueError):
        # Bad pricing must not stop analysis; it only makes the cost figure
        # wrong, and the budget check below notices a zero rate.
        return (0.0, 0.0)


def load_worker_config(detector_config: Optional[dict[str, Any]] = None) -> WorkerConfig:
    """Build and validate the whole worker configuration.

    Raises ConfigError with a message aimed at whoever has to fix it.
    """
    if detector_config is None:
        from .triage import load_detector_config  # noqa: PLC0415 - avoids a cycle

        detector_config = load_detector_config()

    framework = (detector_config or {}).get("adr_framework") or {}
    # `triage_llm` is what upstream's config_detector.yaml calls it.
    triage_section = framework.get("triage_llm") or framework.get("triage_agent") or {}
    reasoning_section = framework.get("reasoning_agent") or {}

    triage = _stage_config(
        "triage",
        env_prefix="UMAI_TRIAGE",
        default_model=str(triage_section.get("model", "") or ""),
        default_timeout=_section_timeout(triage_section, DEFAULT_TRIAGE_TIMEOUT_S),
        default_rates=_rates(triage_section),
    )
    reasoning = _stage_config(
        "reasoning",
        # The old name for the reasoning model. Kept working so an existing
        # deployment does not break on upgrade.
        env_prefix="UMAI_REASONING",
        default_model=_env("UMAI_REASONING_MODEL")
        or str(reasoning_section.get("model", "") or ""),
        default_timeout=_section_timeout(reasoning_section, DEFAULT_REASONING_TIMEOUT_S),
        default_rates=_rates(reasoning_section),
    )

    budget = BudgetConfig(
        max_cost_per_session_usd=_float(
            "UMAI_MAX_COST_PER_SESSION_USD", DEFAULT_MAX_COST_PER_SESSION_USD
        ),
        max_cost_per_batch_usd=_float(
            "UMAI_MAX_COST_PER_BATCH_USD", DEFAULT_MAX_COST_PER_BATCH_USD
        ),
    )
    if (
        budget.max_cost_per_batch_usd
        and budget.max_cost_per_session_usd
        and budget.max_cost_per_batch_usd < budget.max_cost_per_session_usd
    ):
        raise ConfigError(
            "UMAI_MAX_COST_PER_BATCH_USD is below UMAI_MAX_COST_PER_SESSION_USD, "
            "so the batch budget would be exhausted before a single session could "
            "complete."
        )

    return WorkerConfig(
        triage=triage,
        reasoning=reasoning,
        budget=budget,
        reasoning_max_turns=_int(
            "UMAI_REASONING_MAX_TURNS", int(reasoning_section.get("max_turns", 12) or 12)
        ),
        reasoning_max_tokens=_int(
            "UMAI_REASONING_MAX_TOKENS",
            int(reasoning_section.get("max_tokens", 4000) or 4000),
        ),
        reasoning_use_tools=_env("UMAI_REASONING_TOOLS") != "0",
    )


def build_client(stage: StageConfig):
    """An OpenAI-compatible client bound to one stage's endpoint and timeout.

    The timeout is set on the client rather than around the call: the SDK
    applies it per HTTP request, so a multi-turn agent gets it on every turn
    instead of once for the whole conversation.
    """
    from openai import OpenAI  # noqa: PLC0415 - optional at import time

    kwargs: dict[str, Any] = {"api_key": stage.api_key, "timeout": stage.timeout_s}
    if stage.base_url:
        kwargs["base_url"] = stage.base_url
    return OpenAI(**kwargs)
