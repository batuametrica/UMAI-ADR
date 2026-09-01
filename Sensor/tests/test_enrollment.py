"""Tests for device enrolment and token lifecycle."""

import time

import pytest

from adr_sensor import enrollment
from adr_sensor.enrollment import (
    CredentialStore,
    DeviceCredentials,
    EnrollmentError,
    ensure_credentials,
)


def creds(expires_in: int) -> DeviceCredentials:
    return DeviceCredentials(
        tenant_id="11111111-1111-1111-1111-111111111111",
        device_id="HOST-abc123",
        device_token="token",
        expires_at=int(time.time()) + expires_in,
    )


class TestCredentialStore:
    def test_round_trip(self, tmp_path):
        store = CredentialStore(path=tmp_path / "device.json")
        original = creds(3600)
        store.save(original)

        loaded = CredentialStore(path=tmp_path / "device.json").load()
        assert loaded == original

    def test_missing_file_loads_as_none(self, tmp_path):
        assert CredentialStore(path=tmp_path / "nothing.json").load() is None

    def test_corrupt_file_loads_as_none(self, tmp_path):
        path = tmp_path / "device.json"
        path.write_text("{not json", encoding="utf-8")
        assert CredentialStore(path=path).load() is None

    def test_device_id_is_stable_once_enrolled(self, tmp_path):
        store = CredentialStore(path=tmp_path / "device.json")
        store.save(creds(3600))
        assert store.device_id() == "HOST-abc123"

    def test_device_id_is_minted_before_enrolment(self, tmp_path):
        store = CredentialStore(path=tmp_path / "device.json")
        assert store.device_id()  # hostname + random suffix


class TestRenewalWindow:
    def test_fresh_token_is_not_due(self):
        assert creds(enrollment.RENEW_BEFORE_SECONDS + 600).due_for_renewal is False

    def test_token_inside_the_window_is_due(self):
        assert creds(enrollment.RENEW_BEFORE_SECONDS - 600).due_for_renewal is True

    def test_expired_token_reports_expired(self):
        assert creds(-60).expired is True


class TestEnsureCredentials:
    def test_unenrolled_device_without_a_bootstrap_token_fails_clearly(self, tmp_path):
        store = CredentialStore(path=tmp_path / "device.json")
        with pytest.raises(EnrollmentError, match="not enrolled"):
            ensure_credentials("https://umai.example.com", store=store)

    def test_valid_token_is_returned_without_a_network_call(self, tmp_path, monkeypatch):
        store = CredentialStore(path=tmp_path / "device.json")
        store.save(creds(enrollment.RENEW_BEFORE_SECONDS + 600))

        def fail(*args, **kwargs):
            raise AssertionError("should not have called the service")

        monkeypatch.setattr(enrollment, "renew", fail)
        assert ensure_credentials("https://umai.example.com", store=store).device_token == "token"

    def test_renewal_failure_is_tolerated_while_the_token_is_still_valid(
        self, tmp_path, monkeypatch
    ):
        """A transient outage must not stop a run that could still report."""
        store = CredentialStore(path=tmp_path / "device.json")
        store.save(creds(60))  # due for renewal, not yet expired

        monkeypatch.setattr(
            enrollment,
            "renew",
            lambda *a, **k: (_ for _ in ()).throw(EnrollmentError("service down")),
        )

        assert ensure_credentials("https://umai.example.com", store=store).device_token == "token"

    def test_renewal_failure_on_an_expired_token_is_fatal(self, tmp_path, monkeypatch):
        store = CredentialStore(path=tmp_path / "device.json")
        store.save(creds(-60))

        monkeypatch.setattr(
            enrollment,
            "renew",
            lambda *a, **k: (_ for _ in ()).throw(EnrollmentError("service down")),
        )

        with pytest.raises(EnrollmentError, match="expired and renewal failed"):
            ensure_credentials("https://umai.example.com", store=store)

    def test_a_due_token_is_renewed_and_persisted(self, tmp_path, monkeypatch):
        path = tmp_path / "device.json"
        store = CredentialStore(path=path)
        store.save(creds(60))

        renewed = creds(86400)
        renewed.device_token = "fresh-token"

        def fake_renew(endpoint, credentials, *, timeout=30, store=None):
            store.save(renewed)
            return renewed

        monkeypatch.setattr(enrollment, "renew", fake_renew)

        result = ensure_credentials("https://umai.example.com", store=store)
        assert result.device_token == "fresh-token"
        assert CredentialStore(path=path).load().device_token == "fresh-token"


class TestAdrApiMigration:
    def test_bootstrap_uses_adr_contract_and_collector_fields(self, tmp_path, monkeypatch):
        calls = []

        def fake_post(url, *, token, body, timeout, tenant_id):
            calls.append((url, body))
            return {
                "tenant_id": tenant_id,
                "device_id": body["device_id"],
                "device_token": "device-token",
                "expires_at": int(time.time()) + 3600,
                "collection_mode": "metadata",
                "config_etag": '"adr-config"',
            }

        monkeypatch.setattr(enrollment, "_post_json", fake_post)
        result = enrollment.bootstrap(
            "https://umai.example.com",
            bootstrap_token="bootstrap",
            tenant_id="11111111-1111-1111-1111-111111111111",
            store=CredentialStore(path=tmp_path / "device.json"),
        )

        assert calls[0][0].endswith("/api/v1/adr/bootstrap")
        assert "collector_version" in calls[0][1]
        assert "agent_version" not in calls[0][1]
        assert calls[0][1]["supported_sources"]
        assert result.collection_mode == "metadata"

    def test_renew_uses_adr_contract(self, tmp_path, monkeypatch):
        urls = []

        def fake_post(url, *, token, body, timeout, tenant_id):
            urls.append(url)
            return {
                "tenant_id": tenant_id,
                "device_id": "HOST-abc123",
                "device_token": "fresh-token",
                "expires_at": int(time.time()) + 3600,
                "collection_mode": "full_session",
                "config_etag": '"adr-config"',
            }

        monkeypatch.setattr(enrollment, "_post_json", fake_post)
        enrollment.renew(
            "https://umai.example.com",
            creds(60),
            store=CredentialStore(path=tmp_path / "device.json"),
        )
        assert urls == ["https://umai.example.com/api/v1/adr/renew"]
