"""Device enrolment and token lifecycle.

UMAI: added. The sensor runs as a scheduled task, so each invocation is a fresh
process — the device identity and its token have to survive on disk between
runs, and the token has to renew itself without anyone visiting the machine.

The lifecycle:

    first run    bootstrap token (baked into the deployment) -> device token
    later runs   device token -> renewed device token, before it expires
    revoked      renewal is refused, and the sensor stops reporting

Bootstrap tokens are single-use, so the device token is what persists. It is
stored with owner-only permissions where the platform supports it.
"""

import json
import os
import platform
import socket
import stat
import time
import urllib.error
import urllib.request
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from . import __version__

# Renew this far ahead of expiry, so a run that starts just before the deadline
# does not race it.
RENEW_BEFORE_SECONDS = 60 * 60 * 6


class EnrollmentError(RuntimeError):
    """Raised when the sensor cannot obtain a usable device token."""


@dataclass
class DeviceCredentials:
    tenant_id: str
    device_id: str
    device_token: str
    expires_at: int

    @property
    def expired(self) -> bool:
        return time.time() >= self.expires_at

    @property
    def due_for_renewal(self) -> bool:
        return time.time() >= self.expires_at - RENEW_BEFORE_SECONDS


class CredentialStore:
    """Device identity and token, persisted between scheduled runs."""

    def __init__(self, path: Optional[Path] = None):
        self.path = path or self._default_path()

    @staticmethod
    def _default_path() -> Path:
        override = os.environ.get("UMAI_SENSOR_STATE_DIR")
        if override:
            return Path(override) / "device.json"
        cache_home = os.environ.get("XDG_CACHE_HOME")
        base = Path(cache_home) if cache_home else Path.home() / ".cache"
        return base / "adr_sensor" / "device.json"

    def load(self) -> Optional[DeviceCredentials]:
        try:
            with open(self.path, encoding="utf-8") as f:
                data = json.load(f)
            return DeviceCredentials(
                tenant_id=str(data["tenant_id"]),
                device_id=str(data["device_id"]),
                device_token=str(data["device_token"]),
                expires_at=int(data["expires_at"]),
            )
        except (OSError, ValueError, KeyError):
            return None

    def save(self, credentials: DeviceCredentials) -> None:
        payload = {
            "version": 1,
            "tenant_id": credentials.tenant_id,
            "device_id": credentials.device_id,
            "device_token": credentials.device_token,
            "expires_at": credentials.expires_at,
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.parent / f".device.{os.getpid()}.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f, separators=(",", ":"))
        try:
            os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            # Windows ignores POSIX modes; NTFS ACLs are the deployment's job.
            pass
        os.replace(tmp, self.path)

    def device_id(self) -> str:
        """Stable identifier for this machine, minted once and reused."""
        existing = self.load()
        if existing:
            return existing.device_id

        try:
            hostname = socket.gethostname()
        except Exception:
            hostname = "unknown"
        return f"{hostname}-{uuid.uuid4().hex[:12]}"


def _post_json(
    url: str, *, token: str, body: Optional[dict[str, Any]], timeout: int, tenant_id: Optional[str]
) -> dict[str, Any]:
    data = json.dumps(body).encode("utf-8") if body is not None else b"{}"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {token}",
        "User-Agent": f"adr-sensor/{__version__}",
    }
    if tenant_id:
        headers["X-Tenant-Id"] = tenant_id

    request = urllib.request.Request(url, data=data, method="POST", headers=headers)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")[:200]
        raise EnrollmentError(f"HTTP {e.code}: {detail}") from e
    except (urllib.error.URLError, socket.timeout, OSError) as e:
        raise EnrollmentError(f"{e.__class__.__name__}: {e}") from e


def _credentials_from_response(data: dict[str, Any]) -> DeviceCredentials:
    try:
        return DeviceCredentials(
            tenant_id=str(data["tenant_id"]),
            device_id=str(data["device_id"]),
            device_token=str(data["device_token"]),
            expires_at=int(data["expires_at"]),
        )
    except (KeyError, TypeError, ValueError) as e:
        raise EnrollmentError(f"Malformed enrolment response: {e}") from e


def bootstrap(endpoint: str, *, bootstrap_token: str, tenant_id: str, timeout: int = 30,
              store: Optional[CredentialStore] = None) -> DeviceCredentials:
    """Enrol this device and obtain its first token."""
    store = store or CredentialStore()
    device_id = store.device_id()

    body = {
        "tenant_id": tenant_id,
        "device_id": device_id,
        "hostname": socket.gethostname(),
        "os": platform.system(),
        "os_version": platform.release(),
        "agent_version": __version__,
    }
    data = _post_json(
        f"{endpoint}/api/v1/sensor/bootstrap",
        token=bootstrap_token,
        body=body,
        timeout=timeout,
        tenant_id=tenant_id,
    )

    credentials = _credentials_from_response(data)
    store.save(credentials)
    return credentials


def renew(endpoint: str, credentials: DeviceCredentials, *, timeout: int = 30,
          store: Optional[CredentialStore] = None) -> DeviceCredentials:
    """Exchange the current device token for a fresh one."""
    store = store or CredentialStore()
    data = _post_json(
        f"{endpoint}/api/v1/sensor/renew",
        token=credentials.device_token,
        body=None,
        timeout=timeout,
        tenant_id=credentials.tenant_id,
    )

    renewed = _credentials_from_response(data)
    store.save(renewed)
    return renewed


def ensure_credentials(
    endpoint: str,
    *,
    bootstrap_token: Optional[str] = None,
    tenant_id: Optional[str] = None,
    timeout: int = 30,
    store: Optional[CredentialStore] = None,
) -> DeviceCredentials:
    """Return usable device credentials, enrolling or renewing as needed."""
    store = store or CredentialStore()
    credentials = store.load()

    if credentials is None:
        if not bootstrap_token or not tenant_id:
            raise EnrollmentError(
                "This device is not enrolled. Set UMAI_BOOTSTRAP_TOKEN and UMAI_TENANT_ID "
                "for the first run."
            )
        return bootstrap(
            endpoint, bootstrap_token=bootstrap_token, tenant_id=tenant_id,
            timeout=timeout, store=store,
        )

    if not credentials.due_for_renewal:
        return credentials

    try:
        return renew(endpoint, credentials, timeout=timeout, store=store)
    except EnrollmentError as e:
        # A renewal failure is only fatal once the current token is actually
        # dead — a transient outage should not stop a still-valid run.
        if credentials.expired:
            raise EnrollmentError(f"Device token expired and renewal failed: {e}") from e
        print(f"[ENROLLMENT] Renewal deferred, current token still valid: {e}")
        return credentials
