"""Ship collected sessions to a UMAI ingest endpoint.

UMAI: added. Upstream writes JSON to disk and stops there; this module is the
missing transport.

Deliberately stdlib-only (urllib, gzip, hashlib). `adr-sensor` ships to employee
endpoints, where "what does this package pull in" is a question that has to have
a one-line answer, so the dependency list stays at `tabulate`.

Incremental state is a content hash per session, not a filename timestamp.
Upstream's `filter_entries_by_existing_files` compares a timestamp parsed out of
the export filename, and Claude Code reports a session's *earliest* timestamp —
so a session that keeps growing is exported once and never updated again.
Hashing the conversation catches append-only growth correctly.
"""

import gzip
import json
import os
import platform
import random
import socket
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from . import __version__
from .enrollment import SUPPORTED_SOURCES
from .network import urlopen
from .schemas.agent_event_schema import AgentEvent

DEFAULT_TIMEOUT_SECONDS = 60
DEFAULT_MAX_BATCH_BYTES = 8 * 1024 * 1024  # keep a single request modest
DEFAULT_MAX_ATTEMPTS = 4
RETRYABLE_STATUS = {408, 425, 429, 500, 502, 503, 504}


class TransportError(RuntimeError):
    """Raised when a batch could not be delivered after retries."""


@dataclass
class SendResult:
    sessions_sent: int = 0
    batches_sent: int = 0
    sessions_skipped: int = 0
    errors: List[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass
class IngestConfig:
    endpoint: str
    device_token: str
    tenant_id: Optional[str] = None
    device_id: Optional[str] = None
    config_etag: Optional[str] = None
    timeout: int = DEFAULT_TIMEOUT_SECONDS
    max_batch_bytes: int = DEFAULT_MAX_BATCH_BYTES
    max_attempts: int = DEFAULT_MAX_ATTEMPTS

    @classmethod
    def from_env(cls) -> Optional["IngestConfig"]:
        """Build config from UMAI_* environment variables.

        The device token normally comes from the enrolment store, not from the
        environment — a deployment ships a single-use bootstrap token and the
        sensor manages the device token itself from there. `UMAI_DEVICE_TOKEN`
        stays supported for tests and for operators pinning a token by hand.

        Returns None when no endpoint is configured, so a sensor deployed
        without ingest keeps working as a local-export tool.
        """
        endpoint = os.environ.get("UMAI_INGEST_ENDPOINT", "").strip().rstrip("/")
        if not endpoint:
            return None

        def _int(name: str, default: int) -> int:
            try:
                return int(os.environ.get(name, "") or default)
            except ValueError:
                return default

        timeout = _int("UMAI_INGEST_TIMEOUT_SECONDS", DEFAULT_TIMEOUT_SECONDS)
        token = os.environ.get("UMAI_DEVICE_TOKEN", "").strip()
        tenant_id = os.environ.get("UMAI_TENANT_ID", "").strip() or None
        device_id = os.environ.get("UMAI_DEVICE_ID", "").strip() or None
        config_etag = os.environ.get("UMAI_CONFIG_ETAG", "").strip() or None

        if not token:
            from .enrollment import ensure_credentials

            credentials = ensure_credentials(
                endpoint,
                bootstrap_token=os.environ.get("UMAI_BOOTSTRAP_TOKEN", "").strip() or None,
                tenant_id=tenant_id,
                timeout=timeout,
            )
            token = credentials.device_token
            tenant_id = credentials.tenant_id
            device_id = credentials.device_id
            config_etag = credentials.config_etag or None

        return cls(
            endpoint=endpoint,
            device_token=token,
            tenant_id=tenant_id,
            device_id=device_id,
            config_etag=config_etag,
            timeout=timeout,
            max_batch_bytes=_int("UMAI_INGEST_MAX_BATCH_BYTES", DEFAULT_MAX_BATCH_BYTES),
            max_attempts=_int("UMAI_INGEST_MAX_ATTEMPTS", DEFAULT_MAX_ATTEMPTS),
        )


# ---------------------------------------------------------------------------
# Incremental state
# ---------------------------------------------------------------------------


def state_key(session: AgentEvent) -> str:
    """Stable identity for incremental state.

    `session_id` alone is not unique: sub-agent (sidechain) runs carry their
    parent's session id in files of their own, so keying on it collapses them
    into one entry and re-ships the rest on every run. The source log path is
    the discriminator where a parser records it.
    """
    return f"{session.source}|{session.session_id}|{session.raw_log_path or ''}"


class SessionState:
    """Content hash per session, persisted between runs."""

    def __init__(self, path: Optional[Path] = None):
        self.path = path or self._default_path()
        self._hashes: Dict[str, str] = {}
        self.last_successful_ingest_at: Optional[str] = None
        self._load()

    @staticmethod
    def _default_path() -> Path:
        override = os.environ.get("UMAI_ADR_STATE_DIR")
        if override:
            return Path(override) / "state.json"
        if os.name == "nt":
            program_data = os.environ.get("PROGRAMDATA", r"C:\ProgramData")
            return Path(program_data) / "UMAI" / "ADR Collector" / "state" / "state.json"
        cache_home = os.environ.get("XDG_CACHE_HOME")
        base = Path(cache_home) if cache_home else Path.home() / ".cache"
        return base / "adr_sensor" / "state.json"

    def _load(self) -> None:
        try:
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
            sent = data.get("sent")
            if isinstance(sent, dict):
                self._hashes = {str(k): str(v) for k, v in sent.items()}
            last_ingest = data.get("last_successful_ingest_at")
            if isinstance(last_ingest, str) and last_ingest:
                self.last_successful_ingest_at = last_ingest
        except (OSError, ValueError):
            self._hashes = {}

    def pending(self, sessions: List[AgentEvent]) -> Tuple[List[AgentEvent], int]:
        """Split sessions into (changed-or-new, skipped_count)."""
        pending = []
        skipped = 0
        for session in sessions:
            if self._hashes.get(state_key(session)) == session.get_content_hash():
                skipped += 1
            else:
                pending.append(session)
        return pending, skipped

    def mark_sent(self, sessions: List[AgentEvent]) -> None:
        for session in sessions:
            self._hashes[state_key(session)] = session.get_content_hash()

    def save(self) -> None:
        """Write atomically so a crash mid-write cannot corrupt the state."""
        payload = {
            "version": 2,
            "sent": self._hashes,
            "last_successful_ingest_at": self.last_successful_ingest_at,
        }
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".json.tmp")
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(payload, f, separators=(",", ":"))
            os.replace(tmp, self.path)
        except OSError as e:
            print(f"[TRANSPORT] Could not persist state to {self.path}: {e}")


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


class IngestClient:
    """Minimal HTTP client for POSTing session bundles."""

    def __init__(self, config: IngestConfig):
        self.config = config

    @property
    def url(self) -> str:
        return f"{self.config.endpoint}/api/v1/adr/sessions"

    @property
    def heartbeat_url(self) -> str:
        return f"{self.config.endpoint}/api/v1/adr/heartbeat"

    def _batches(self, sessions: List[AgentEvent]) -> List[List[Dict[str, Any]]]:
        """Group serialized sessions into request-sized chunks.

        A single transcript can be megabytes, so batching by count alone would
        produce wildly uneven requests.
        """
        batches: List[List[Dict[str, Any]]] = []
        current: List[Dict[str, Any]] = []
        current_bytes = 0

        for session in sessions:
            payload = session.get_non_null_fields()
            size = len(json.dumps(payload, ensure_ascii=False).encode("utf-8"))

            if current and current_bytes + size > self.config.max_batch_bytes:
                batches.append(current)
                current, current_bytes = [], 0

            current.append(payload)
            current_bytes += size

        if current:
            batches.append(current)

        return batches

    def _headers(self) -> Dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Content-Encoding": "gzip",
            "Authorization": f"Bearer {self.config.device_token}",
            "User-Agent": f"adr-sensor/{__version__}",
        }
        if self.config.tenant_id:
            headers["X-Tenant-Id"] = self.config.tenant_id
        if self.config.device_id:
            headers["X-Device-Id"] = self.config.device_id
        return headers

    def _post(self, body: Dict[str, Any]) -> None:
        raw = json.dumps(body, ensure_ascii=False).encode("utf-8")
        compressed = gzip.compress(raw)

        last_error: Optional[str] = None
        for attempt in range(1, self.config.max_attempts + 1):
            request = urllib.request.Request(
                self.url,
                data=compressed,
                method="POST",
                headers=self._headers(),
            )

            try:
                with urlopen(request, timeout=self.config.timeout) as response:
                    if 200 <= response.status < 300:
                        return
                    last_error = f"HTTP {response.status}"
                    retryable = response.status in RETRYABLE_STATUS
            except urllib.error.HTTPError as e:
                last_error = f"HTTP {e.code}"
                retryable = e.code in RETRYABLE_STATUS
            except (urllib.error.URLError, socket.timeout, OSError) as e:
                last_error = f"{e.__class__.__name__}: {e}"
                retryable = True

            if not retryable or attempt == self.config.max_attempts:
                break

            delay = min(30.0, 2 ** (attempt - 1)) + random.uniform(0, 0.5)
            time.sleep(delay)

        raise TransportError(f"{last_error} after {self.config.max_attempts} attempt(s)")

    def _post_heartbeat(self, body: Dict[str, Any]) -> Dict[str, Any]:
        raw = json.dumps(body, ensure_ascii=False).encode("utf-8")
        headers = self._headers()
        headers.pop("Content-Encoding", None)
        request = urllib.request.Request(
            self.heartbeat_url,
            data=raw,
            method="POST",
            headers=headers,
        )
        try:
            with urlopen(request, timeout=self.config.timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            raise TransportError(f"Heartbeat HTTP {e.code}") from e
        except (urllib.error.URLError, socket.timeout, OSError) as e:
            raise TransportError(f"Heartbeat {e.__class__.__name__}: {e}") from e

    def heartbeat(
        self,
        *,
        observed_sources: List[str],
        pending_sessions: int,
        last_successful_ingest_at: Optional[str],
        status: str,
        status_detail: Optional[str] = None,
    ) -> Dict[str, Any]:
        if not self.config.device_id:
            raise TransportError("Heartbeat requires an enrolled device_id")
        body: Dict[str, Any] = {
            "device_id": self.config.device_id,
            "collector_version": __version__,
            "hostname": socket.gethostname(),
            "os": platform.system(),
            "os_version": platform.release(),
            "config_etag": self.config.config_etag,
            "supported_sources": list(SUPPORTED_SOURCES),
            "observed_sources": sorted(set(observed_sources)),
            "last_successful_ingest_at": last_successful_ingest_at,
            "pending_sessions": max(pending_sessions, 0),
            "status": status,
        }
        if status_detail:
            body["status_detail"] = status_detail
        response = self._post_heartbeat(body)
        returned_etag = response.get("config_etag")
        if isinstance(returned_etag, str):
            self.config.config_etag = returned_etag
        return response

    def send(self, sessions: List[AgentEvent]) -> SendResult:
        result = SendResult()
        if not sessions:
            return result

        for batch in self._batches(sessions):
            body = {
                "collector": {"name": "adr-sensor", "version": __version__},
                "sessions": batch,
            }
            try:
                self._post(body)
                result.batches_sent += 1
                result.sessions_sent += len(batch)
            except TransportError as e:
                result.errors.append(str(e))
                break  # stop on first failure; state is only advanced for what landed

        return result


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def ship(sessions: List[AgentEvent], config: Optional[IngestConfig] = None) -> SendResult:
    """Send sessions that changed since the last successful run."""
    config = config or IngestConfig.from_env()
    if config is None:
        raise TransportError("Ingest is not configured. Set UMAI_INGEST_ENDPOINT.")

    state = SessionState()
    pending, skipped = state.pending(sessions)

    client = IngestClient(config)
    result = client.send(pending)
    result.sessions_skipped = skipped

    # Only record what actually landed. A partial failure re-sends the tail next
    # run; the ingest side dedupes on session id + content hash.
    if result.sessions_sent:
        state.mark_sent(pending[: result.sessions_sent])
        state.last_successful_ingest_at = datetime.now(timezone.utc).isoformat()

    state.save()

    pending_count = max(len(pending) - result.sessions_sent, 0)
    if result.errors and result.sessions_sent:
        health_status, detail = "degraded", "PARTIAL_INGEST"
    elif result.errors:
        health_status, detail = "error", "INGEST_FAILED"
    else:
        health_status, detail = "healthy", None
    try:
        client.heartbeat(
            observed_sources=[session.source for session in sessions],
            pending_sessions=pending_count,
            last_successful_ingest_at=state.last_successful_ingest_at,
            status=health_status,
            status_detail=detail,
        )
    except TransportError as e:
        result.errors.append(str(e))

    return result
