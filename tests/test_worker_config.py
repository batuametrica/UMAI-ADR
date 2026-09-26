"""Per-stage worker configuration, validated at startup (UMA-53).

Two stages, two models, two endpoints, two timeouts — and a worker that
refuses to start rather than discovering a bad setting after it has taken
leases on ten sessions.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from umai.worker.config import (  # noqa: E402
    DEFAULT_REASONING_TIMEOUT_S,
    DEFAULT_TRIAGE_TIMEOUT_S,
    BudgetConfig,
    ConfigError,
    StageConfig,
    WorkerConfig,
    load_worker_config,
)

DETECTOR_CONFIG = {
    "adr_framework": {
        "triage_llm": {
            "model": "gpt-4o",
            "cost_per_1m_input": 2.50,
            "cost_per_1m_output": 10.00,
        },
        "reasoning_agent": {
            "model": "claude-sonnet-4-6",
            "cost_per_1m_input": 3.00,
            "cost_per_1m_output": 15.00,
            "max_turns": 60,
            "max_tokens": 10000,
            "timeout": 300,
        },
    }
}

# Every variable this module reads, cleared before each test so a developer
# machine with a real key set does not change what is being tested.
ENV_VARS = [
    "OPENAI_API_KEY",
    "OPENAI_BASE_URL",
    "UMAI_TRIAGE_MODEL",
    "UMAI_TRIAGE_BASE_URL",
    "UMAI_TRIAGE_API_KEY",
    "UMAI_TRIAGE_TIMEOUT_SECONDS",
    "UMAI_REASONING_MODEL",
    "UMAI_REASONING_BASE_URL",
    "UMAI_REASONING_API_KEY",
    "UMAI_REASONING_TIMEOUT_SECONDS",
    "UMAI_REASONING_MAX_TURNS",
    "UMAI_REASONING_MAX_TOKENS",
    "UMAI_REASONING_TOOLS",
    "UMAI_MAX_COST_PER_SESSION_USD",
    "UMAI_MAX_COST_PER_BATCH_USD",
    "UMAI_MAX_COST_PER_DAY_USD",
    "UMAI_TRIAGE_COST_PER_1M_INPUT",
    "UMAI_TRIAGE_COST_PER_1M_OUTPUT",
    "UMAI_REASONING_COST_PER_1M_INPUT",
    "UMAI_REASONING_COST_PER_1M_OUTPUT",
]


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for name in ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    # A key by default: most tests are about something other than auth.
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")


def _load(**env) -> WorkerConfig:
    import os

    for key, value in env.items():
        os.environ[key] = value
    return load_worker_config(DETECTOR_CONFIG)


class TestStageSeparation:
    def test_each_stage_gets_its_own_model_from_the_detector_config(self) -> None:
        config = _load()
        assert config.triage.model == "gpt-4o"
        assert config.reasoning.model == "claude-sonnet-4-6"

    def test_the_two_stages_can_point_at_different_endpoints(self) -> None:
        """The whole point: cheap filtering locally, reasoning elsewhere."""
        config = _load(
            UMAI_TRIAGE_BASE_URL="http://gpu-01.internal:8000/v1",
            UMAI_REASONING_BASE_URL="https://api.vendor.example/v1",
        )
        assert config.triage.base_url == "http://gpu-01.internal:8000/v1"
        assert config.reasoning.base_url == "https://api.vendor.example/v1"

    def test_the_two_stages_can_use_different_keys(self) -> None:
        config = _load(UMAI_TRIAGE_API_KEY="local-key", UMAI_REASONING_API_KEY="vendor-key")
        assert config.triage.api_key == "local-key"
        assert config.reasoning.api_key == "vendor-key"

    def test_a_shared_endpoint_still_works_without_setting_it_twice(self) -> None:
        config = _load(OPENAI_BASE_URL="http://one-model.internal:8000/v1")
        assert config.triage.base_url == config.reasoning.base_url

    def test_a_per_stage_setting_beats_the_shared_one(self) -> None:
        config = _load(
            OPENAI_BASE_URL="http://shared:8000/v1",
            UMAI_TRIAGE_BASE_URL="http://triage-only:8000/v1",
        )
        assert config.triage.base_url == "http://triage-only:8000/v1"
        assert config.reasoning.base_url == "http://shared:8000/v1"

    def test_the_stage_lookup_accepts_the_name_the_platform_uses(self) -> None:
        """The claim endpoint calls it `reason`, the config calls it reasoning."""
        config = _load()
        assert config.for_stage("reason") is config.reasoning
        assert config.for_stage("reasoning") is config.reasoning
        assert config.for_stage("triage") is config.triage

    def test_an_unknown_stage_is_rejected(self) -> None:
        with pytest.raises(ConfigError):
            _load().for_stage("guessing")


class TestTimeouts:
    def test_triage_and_reasoning_get_different_defaults(self) -> None:
        """A bulk filter and a multi-turn agent are not the same workload."""
        config = _load()
        assert config.triage.timeout_s == DEFAULT_TRIAGE_TIMEOUT_S
        # Taken from `timeout: 300` in the detector config, which happens to
        # match the default.
        assert config.reasoning.timeout_s == 300.0

    def test_the_detector_config_timeout_is_honoured(self) -> None:
        detector = {
            "adr_framework": {
                "triage_llm": {"model": "m", "timeout": 15},
                "reasoning_agent": {"model": "m2"},
            }
        }
        config = load_worker_config(detector)
        assert config.triage.timeout_s == 15.0
        assert config.reasoning.timeout_s == DEFAULT_REASONING_TIMEOUT_S

    def test_the_environment_overrides_the_detector_config(self) -> None:
        config = _load(UMAI_REASONING_TIMEOUT_SECONDS="45.5")
        assert config.reasoning.timeout_s == 45.5

    @pytest.mark.parametrize("value", ["0", "-1", "0.0"])
    def test_a_zero_or_negative_timeout_is_refused(self, value: str) -> None:
        """It reads as "no timeout", which is the behaviour being removed."""
        with pytest.raises(ConfigError) as exc:
            _load(UMAI_TRIAGE_TIMEOUT_SECONDS=value)
        assert "greater than zero" in str(exc.value)

    def test_a_non_numeric_timeout_is_refused(self) -> None:
        with pytest.raises(ConfigError) as exc:
            _load(UMAI_REASONING_TIMEOUT_SECONDS="soon")
        assert "must be a number" in str(exc.value)


class TestFailFast:
    def test_a_missing_model_is_refused_and_says_what_to_set(self) -> None:
        detector = {"adr_framework": {"reasoning_agent": {"model": "m"}}}
        with pytest.raises(ConfigError) as exc:
            load_worker_config(detector)
        assert "UMAI_TRIAGE_MODEL" in str(exc.value)

    def test_a_missing_key_with_no_local_endpoint_is_refused(self, monkeypatch) -> None:
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        with pytest.raises(ConfigError) as exc:
            load_worker_config(DETECTOR_CONFIG)
        assert "API key" in str(exc.value)

    def test_a_local_endpoint_needs_no_key(self, monkeypatch) -> None:
        """A self-hosted server usually ignores it but wants the header."""
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        config = _load(OPENAI_BASE_URL="http://gpu-01.internal:8000/v1")
        assert config.triage.api_key == "local"

    @pytest.mark.parametrize("bad", ["gpu-01.internal:8000", "ftp://host/v1", "/v1"])
    def test_an_endpoint_that_is_not_a_url_is_refused(self, bad: str) -> None:
        with pytest.raises(ConfigError) as exc:
            _load(UMAI_TRIAGE_BASE_URL=bad)
        assert "http://" in str(exc.value)

    @pytest.mark.parametrize("bad", ["lots", "-3"])
    def test_a_bad_turn_limit_is_refused(self, bad: str) -> None:
        with pytest.raises(ConfigError):
            _load(UMAI_REASONING_MAX_TURNS=bad)


class TestBudget:
    def test_no_budget_is_configured_by_default(self) -> None:
        """A cap nobody asked for silently stopping analysis is worse."""
        assert _load().budget.enforced is False

    def test_caps_are_read_from_the_environment(self) -> None:
        budget = _load(
            UMAI_MAX_COST_PER_SESSION_USD="0.25", UMAI_MAX_COST_PER_BATCH_USD="5"
        ).budget
        assert budget.max_cost_per_session_usd == 0.25
        assert budget.max_cost_per_batch_usd == 5.0
        assert budget.enforced is True

    def test_a_batch_cap_below_the_session_cap_is_refused(self) -> None:
        """It could never let a single session finish."""
        with pytest.raises(ConfigError) as exc:
            _load(
                UMAI_MAX_COST_PER_SESSION_USD="1.00", UMAI_MAX_COST_PER_BATCH_USD="0.50"
            )
        assert "below" in str(exc.value)

    def test_a_negative_cap_is_refused(self) -> None:
        with pytest.raises(ConfigError):
            _load(UMAI_MAX_COST_PER_SESSION_USD="-1")


class TestDailyBudget:
    def test_the_daily_cap_is_read_and_enforced(self) -> None:
        budget = _load(UMAI_MAX_COST_PER_DAY_USD="20").budget
        assert budget.max_cost_per_day_usd == 20.0
        assert budget.enforced is True

    def test_it_is_off_by_default(self) -> None:
        assert _load().budget.max_cost_per_day_usd == 0.0

    @pytest.mark.parametrize(
        "other", ["UMAI_MAX_COST_PER_SESSION_USD", "UMAI_MAX_COST_PER_BATCH_USD"]
    )
    def test_a_daily_cap_below_a_smaller_cap_is_refused(self, other: str) -> None:
        with pytest.raises(ConfigError) as exc:
            _load(UMAI_MAX_COST_PER_DAY_USD="1", **{other: "5"})
        assert "UMAI_MAX_COST_PER_DAY_USD is below" in str(exc.value)

    def test_all_three_caps_can_be_combined(self) -> None:
        budget = _load(
            UMAI_MAX_COST_PER_SESSION_USD="0.25",
            UMAI_MAX_COST_PER_BATCH_USD="5",
            UMAI_MAX_COST_PER_DAY_USD="50",
        ).budget
        assert (
            budget.max_cost_per_session_usd,
            budget.max_cost_per_batch_usd,
            budget.max_cost_per_day_usd,
        ) == (0.25, 5.0, 50.0)

    def test_a_negative_daily_cap_is_refused(self) -> None:
        with pytest.raises(ConfigError):
            _load(UMAI_MAX_COST_PER_DAY_USD="-1")

    def test_the_daily_cap_is_in_the_startup_lines(self) -> None:
        assert "day=$50.0000" in _load(UMAI_MAX_COST_PER_DAY_USD="50").describe()[-1]


class TestRateOverrides:
    def test_env_rates_override_the_detector_config(self) -> None:
        config = _load(
            UMAI_TRIAGE_COST_PER_1M_INPUT="0.10",
            UMAI_TRIAGE_COST_PER_1M_OUTPUT="0.40",
            UMAI_REASONING_COST_PER_1M_INPUT="1.25",
            UMAI_REASONING_COST_PER_1M_OUTPUT="10",
        )
        assert (config.triage.cost_per_1m_input, config.triage.cost_per_1m_output) == (
            0.10,
            0.40,
        )
        assert (
            config.reasoning.cost_per_1m_input,
            config.reasoning.cost_per_1m_output,
        ) == (1.25, 10.0)

    def test_one_override_leaves_the_other_rate_from_the_yaml(self) -> None:
        config = _load(UMAI_TRIAGE_COST_PER_1M_OUTPUT="0.40")
        assert config.triage.cost_per_1m_input == 2.50
        assert config.triage.cost_per_1m_output == 0.40
        # The other stage is untouched.
        assert config.reasoning.cost_per_1m_output == 15.00

    @pytest.mark.parametrize("bad", ["cheap", "-0.5"])
    def test_a_bad_rate_is_refused(self, bad: str) -> None:
        with pytest.raises(ConfigError) as exc:
            _load(UMAI_REASONING_COST_PER_1M_INPUT=bad)
        assert "UMAI_REASONING_COST_PER_1M_INPUT" in str(exc.value)

    def test_the_override_prices_the_session(self) -> None:
        from umai.worker.__main__ import _account

        class Outcome:
            cost_usd = None
            input_tokens = 1_000_000
            output_tokens = 1_000_000

        config = _load(
            UMAI_TRIAGE_COST_PER_1M_INPUT="0.10", UMAI_TRIAGE_COST_PER_1M_OUTPUT="0.40"
        )
        assert _account(config, config.triage, Outcome(), "sess-1") == pytest.approx(0.50)


ZERO_RATES = {
    "adr_framework": {
        "triage_llm": {"model": "local-triage"},
        "reasoning_agent": {"model": "local-reasoning"},
    }
}


class TestBudgetNeedsRates:
    """A budget priced at $0 can never be reached, which is worse than none."""

    @pytest.mark.parametrize(
        "cap",
        [
            "UMAI_MAX_COST_PER_SESSION_USD",
            "UMAI_MAX_COST_PER_BATCH_USD",
            "UMAI_MAX_COST_PER_DAY_USD",
        ],
    )
    def test_any_budget_with_zero_rates_is_refused(self, monkeypatch, cap: str) -> None:
        monkeypatch.setenv(cap, "5")
        with pytest.raises(ConfigError) as exc:
            load_worker_config(ZERO_RATES)
        assert "UMAI_TRIAGE_COST_PER_1M_INPUT" in str(exc.value)

    def test_zero_rates_without_a_budget_are_fine(self) -> None:
        config = load_worker_config(ZERO_RATES)
        assert config.triage.cost_per_1m_input == 0.0

    def test_one_zero_rate_is_refused(self) -> None:
        with pytest.raises(ConfigError) as exc:
            _load(UMAI_MAX_COST_PER_DAY_USD="5", UMAI_REASONING_COST_PER_1M_OUTPUT="0")
        assert "reasoning" in str(exc.value)

    def test_env_rates_satisfy_the_check(self, monkeypatch) -> None:
        for name in (
            "UMAI_TRIAGE_COST_PER_1M_INPUT",
            "UMAI_TRIAGE_COST_PER_1M_OUTPUT",
            "UMAI_REASONING_COST_PER_1M_INPUT",
            "UMAI_REASONING_COST_PER_1M_OUTPUT",
        ):
            monkeypatch.setenv(name, "0.5")
        monkeypatch.setenv("UMAI_MAX_COST_PER_DAY_USD", "5")
        assert load_worker_config(ZERO_RATES).budget.enforced is True

    def test_only_the_running_stage_needs_rates(self, monkeypatch) -> None:
        """A triage worker is not refused over the reasoning stage's pricing."""
        monkeypatch.setenv("UMAI_TRIAGE_COST_PER_1M_INPUT", "0.1")
        monkeypatch.setenv("UMAI_TRIAGE_COST_PER_1M_OUTPUT", "0.4")
        monkeypatch.setenv("UMAI_MAX_COST_PER_DAY_USD", "5")

        assert load_worker_config(ZERO_RATES, stage="triage").budget.enforced
        with pytest.raises(ConfigError):
            load_worker_config(ZERO_RATES, stage="reason")
        with pytest.raises(ConfigError):
            load_worker_config(ZERO_RATES)

    def test_the_worker_exits_2_on_an_unmeasurable_budget(self, monkeypatch, capsys) -> None:
        from umai.worker.__main__ import main

        monkeypatch.setenv("UMAI_PLATFORM_ENDPOINT", "http://platform.invalid")
        monkeypatch.setenv("UMAI_ANALYSIS_WORKER_TOKEN", "token")
        monkeypatch.setenv("UMAI_MAX_COST_PER_DAY_USD", "5")
        monkeypatch.setenv("UMAI_TRIAGE_COST_PER_1M_INPUT", "0")

        assert main(["--stage", "triage", "--once"]) == 2
        assert "Configuration error" in capsys.readouterr().err


class TestPricing:
    def test_rates_come_from_the_detector_config_per_stage(self) -> None:
        config = _load()
        assert (config.triage.cost_per_1m_input, config.triage.cost_per_1m_output) == (
            2.50,
            10.00,
        )
        assert config.reasoning.cost_per_1m_input == 3.00

    def test_a_session_is_priced_from_its_token_counts(self) -> None:
        stage = StageConfig(
            stage="triage",
            model="m",
            base_url=None,
            api_key="k",
            timeout_s=60,
            cost_per_1m_input=2.0,
            cost_per_1m_output=10.0,
        )
        # 1M input at $2 plus 100k output at $10.
        assert stage.price(1_000_000, 100_000) == pytest.approx(3.0)

    def test_broken_pricing_does_not_stop_the_worker(self) -> None:
        detector = {
            "adr_framework": {
                "triage_llm": {"model": "m", "cost_per_1m_input": "free"},
                "reasoning_agent": {"model": "m2"},
            }
        }
        config = load_worker_config(detector)
        assert config.triage.cost_per_1m_input == 0.0


class TestDescribe:
    def test_the_startup_lines_never_include_the_key(self) -> None:
        config = _load(
            UMAI_TRIAGE_API_KEY="sk-secret-triage",
            UMAI_REASONING_API_KEY="sk-secret-reasoning",
        )
        rendered = "\n".join(config.describe())
        assert "sk-secret" not in rendered
        assert "gpt-4o" in rendered and "claude-sonnet-4-6" in rendered

    def test_the_budget_is_only_mentioned_when_it_is_set(self) -> None:
        assert len(_load().describe()) == 2
        assert len(_load(UMAI_MAX_COST_PER_BATCH_USD="5").describe()) == 3


class TestBudgetExceededSignal:
    """The batch loop stops rather than marking the rest of the queue failed."""

    def test_the_batch_cap_trips_once_it_is_spent(self) -> None:
        from umai.worker.__main__ import BudgetExceeded, _check_batch_budget

        config = WorkerConfig(
            triage=_load().triage,
            reasoning=_load().reasoning,
            budget=BudgetConfig(max_cost_per_batch_usd=1.0),
        )
        _check_batch_budget(config, 0.5)
        with pytest.raises(BudgetExceeded):
            _check_batch_budget(config, 1.0)

    def test_an_unset_cap_never_trips(self) -> None:
        from umai.worker.__main__ import _check_batch_budget

        _check_batch_budget(_load(), 10_000.0)


class TestFailureReporting:
    def test_a_failure_result_marks_the_session_as_an_error(self) -> None:
        from umai.worker.__main__ import _failure_result

        result = _failure_result("t1", "s1", "triage", "gpt-4o", "Model call timed out")
        # Not `benign`: the platform must not be able to read this as cleared.
        assert result["verdict"] == "error"
        assert result["reason"] == "Model call timed out"
        assert result["stage"] == "triage"
        assert result["model"] == "gpt-4o"

    def test_a_timeout_is_described_as_one(self) -> None:
        from umai.worker.__main__ import _describe_failure

        assert "timed out" in _describe_failure(TimeoutError("after 60s"))

    def test_a_vendor_timeout_class_is_recognised_by_name(self) -> None:
        from umai.worker.__main__ import _describe_failure, _is_timeout

        class APITimeoutError(Exception):
            pass

        error = APITimeoutError("Request timed out.")
        assert _is_timeout(error) is True
        assert "timed out" in _describe_failure(error)

    def test_other_failures_keep_their_own_description(self) -> None:
        from umai.worker.__main__ import _describe_failure

        assert _describe_failure(ValueError("bad json")) == "ValueError: bad json"

    def test_a_failure_with_no_message_still_names_its_type(self) -> None:
        from umai.worker.__main__ import _describe_failure

        assert _describe_failure(RuntimeError()) == "RuntimeError"


class TestSessionCostAccounting:
    def test_an_overrun_is_logged_but_the_cost_is_still_counted(self, caplog) -> None:
        from umai.worker.__main__ import _account

        class Outcome:
            cost_usd = 0.9
            input_tokens = 0
            output_tokens = 0

        config = WorkerConfig(
            triage=_load().triage,
            reasoning=_load().reasoning,
            budget=BudgetConfig(max_cost_per_session_usd=0.1),
        )
        with caplog.at_level("WARNING", logger="umai.worker"):
            spent = _account(config, config.triage, Outcome(), "sess-1")

        assert spent == 0.9
        assert any("exceeded the per-session cap" in r.getMessage() for r in caplog.records)

    def test_a_missing_cost_is_derived_from_the_token_counts(self) -> None:
        from umai.worker.__main__ import _account

        class Outcome:
            cost_usd = None
            input_tokens = 1_000_000
            output_tokens = 0

        config = _load()
        # $2.50 per 1M input tokens, from the detector config.
        assert _account(config, config.triage, Outcome(), "sess-1") == pytest.approx(2.50)


class TestBlankSdkEnvironment:
    """An empty `OPENAI_BASE_URL` is worse than an absent one.

    Compose renders `OPENAI_BASE_URL: ${OPENAI_BASE_URL:-}` as an empty string
    rather than omitting the variable. When a stage has no explicit base URL
    the worker deliberately passes none, and the OpenAI SDK then reads the
    environment itself — an empty value is not None, so it becomes the base
    URL and every request dies with `httpx.UnsupportedProtocol`. Both analysis
    stages were down this way with no configuration visibly wrong.
    """

    def test_blank_values_are_removed_from_the_environment(self, monkeypatch) -> None:
        from umai.worker.config import clear_blank_sdk_env

        monkeypatch.setenv("OPENAI_BASE_URL", "")
        monkeypatch.setenv("OPENAI_API_KEY", "   ")

        clear_blank_sdk_env()

        import os

        assert "OPENAI_BASE_URL" not in os.environ
        assert "OPENAI_API_KEY" not in os.environ

    def test_real_values_are_left_alone(self, monkeypatch) -> None:
        from umai.worker.config import clear_blank_sdk_env

        monkeypatch.setenv("OPENAI_BASE_URL", "https://llm.internal.example.com/v1")
        monkeypatch.setenv("OPENAI_API_KEY", "sk-real")

        clear_blank_sdk_env()

        import os

        assert os.environ["OPENAI_BASE_URL"] == "https://llm.internal.example.com/v1"
        assert os.environ["OPENAI_API_KEY"] == "sk-real"

    def test_loading_the_config_clears_them_before_any_client_is_built(
        self, monkeypatch
    ) -> None:
        import os

        monkeypatch.setenv("OPENAI_BASE_URL", "")
        monkeypatch.setenv("UMAI_TRIAGE_API_KEY", "sk-triage")
        monkeypatch.setenv("UMAI_REASONING_API_KEY", "sk-reason")

        config = load_worker_config(DETECTOR_CONFIG)

        assert "OPENAI_BASE_URL" not in os.environ
        # No base URL configured anywhere means the SDK's own default, which is
        # only reachable once the blank variable is gone.
        assert config.triage.base_url is None
        assert config.reasoning.base_url is None
