"""HTTP client for the platform's analysis endpoints.

The worker only ever makes outbound calls: it claims work, fetches a transcript,
posts a result. Nothing listens on this side, which is what lets it run inside a
customer network without an inbound firewall rule.
"""

from __future__ import annotations

import json
import os
import socket
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Optional

DEFAULT_TIMEOUT_SECONDS = 120


class PlatformError(RuntimeError):
    """Raised when the platform cannot be reached or refuses a request."""


@dataclass
class PlatformConfig:
    endpoint: str
    worker_token: str
    worker_id: str = field(default_factory=lambda: f"analyzer-{socket.gethostname()}")
    timeout: int = DEFAULT_TIMEOUT_SECONDS

    @classmethod
    def from_env(cls) -> "PlatformConfig":
        endpoint = os.environ.get("UMAI_PLATFORM_ENDPOINT", "").strip().rstrip("/")
        token = os.environ.get("UMAI_ANALYSIS_WORKER_TOKEN", "").strip()
        if not endpoint or not token:
            raise PlatformError(
                "Set UMAI_PLATFORM_ENDPOINT and UMAI_ANALYSIS_WORKER_TOKEN."
            )
        try:
            timeout = int(os.environ.get("UMAI_PLATFORM_TIMEOUT_SECONDS", "") or DEFAULT_TIMEOUT_SECONDS)
        except ValueError:
            timeout = DEFAULT_TIMEOUT_SECONDS

        worker_id = os.environ.get("UMAI_WORKER_ID", "").strip()
        return cls(
            endpoint=endpoint,
            worker_token=token,
            worker_id=worker_id or f"analyzer-{socket.gethostname()}",
            timeout=timeout,
        )


class PlatformClient:
    def __init__(self, config: PlatformConfig):
        self.config = config

    def _request(self, method: str, path: str, body: Optional[dict[str, Any]] = None) -> bytes:
        url = f"{self.config.endpoint}{path}"
        data = json.dumps(body).encode("utf-8") if body is not None else None
        request = urllib.request.Request(
            url,
            data=data,
            method=method,
            headers={
                "Authorization": f"Bearer {self.config.worker_token}",
                **({"Content-Type": "application/json"} if data else {}),
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=self.config.timeout) as response:
                return response.read()
        except urllib.error.HTTPError as e:
            detail = e.read().decode("utf-8", "replace")[:200]
            raise PlatformError(f"{method} {path} -> HTTP {e.code}: {detail}") from e
        except (urllib.error.URLError, socket.timeout, OSError) as e:
            raise PlatformError(f"{method} {path} -> {e.__class__.__name__}: {e}") from e

    def claim(self, stage: str, limit: int = 10, tenant_id: Optional[str] = None) -> list[dict[str, Any]]:
        body: dict[str, Any] = {
            "stage": stage,
            "worker_id": self.config.worker_id,
            "limit": limit,
        }
        if tenant_id:
            body["tenant_id"] = tenant_id
        payload = json.loads(self._request("POST", "/internal/analysis/claim", body))
        return payload.get("sessions") or []

    def transcript(self, tenant_id: str, session_key: str) -> dict[str, Any]:
        raw = self._request(
            "GET", f"/internal/analysis/transcript/{tenant_id}/{session_key}"
        )
        return json.loads(raw.decode("utf-8"))

    def submit(self, result: dict[str, Any]) -> dict[str, Any]:
        return json.loads(self._request("POST", "/internal/analysis/result", result))
