"""
Base parser interface for ADR Sensor.

All parsers should inherit from BaseParser and implement the parse_all() method.
This enables easy extension with new AI agent log formats.
"""

from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional

from ..schemas.agent_event_schema import AgentEvent


class BaseParser(ABC):
    """Abstract base class for all ADR parsers.

    To add support for a new AI agent, create a new parser class that inherits
    from BaseParser and implements the parse_all() method.

    Example:
        class MyAgentParser(BaseParser):
            def parse_all(self) -> List[AgentEvent]:
                # Parse logs from your agent and return AgentEvent objects
                ...

    UMAI: every parser shares one age window. The Windows collector runs every
    source on every device, so a parser without a window uploads its entire
    history on the first run — and each session costs a triage LLM call.
    """

    DEFAULT_MAX_AGE_DAYS = 14

    def __init__(self, max_age_days: Optional[int] = None):
        self.max_age_days = self.DEFAULT_MAX_AGE_DAYS if max_age_days is None else max_age_days

    def _cutoff(self) -> datetime:
        try:
            return datetime.now(timezone.utc) - timedelta(days=self.max_age_days)
        except OverflowError:
            # An effectively unbounded window (e.g. 10**6 days) predates year 1.
            return datetime.min.replace(tzinfo=timezone.utc)

    def _is_recent(self, ts: Optional[datetime]) -> bool:
        """True when `ts` falls inside the age window.

        An unknown timestamp counts as recent: dropping data we cannot date is
        worse than processing it once.
        """
        if ts is None:
            return True
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return ts >= self._cutoff()

    def _is_recent_mtime(self, path: Path) -> bool:
        """True when the file at `path` was modified inside the age window.

        A file that cannot be stat'ed counts as not recent — it could not be
        read either.
        """
        try:
            mtime = datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc)
        except (OSError, ValueError, OverflowError):
            return False
        return mtime >= self._cutoff()

    def _report_skipped(self, tag: str, skipped_count: int, noun: str) -> None:
        """Print the age-filter summary in the shared `[TAG] Skipped ...` style."""
        if skipped_count > 0:
            print(f"[{tag}] Skipped {skipped_count} {noun} older than {self.max_age_days} days")

    @abstractmethod
    def parse_all(self) -> List[AgentEvent]:
        """Parse all available logs and return a list of AgentEvent objects.

        Returns:
            List of AgentEvent objects representing parsed telemetry data.
        """
        ...
