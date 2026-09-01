import json
import zipfile
from pathlib import Path

from adr_sensor import enrollment
from adr_sensor.enrollment import CredentialStore
from adr_sensor.network import ca_bundle_path, proxy_url
from adr_sensor.support_bundle import create_support_bundle


def test_windows_dpapi_store_never_writes_plaintext_token(tmp_path, monkeypatch):
    monkeypatch.setattr(enrollment.os, "name", "nt")
    monkeypatch.setattr(enrollment, "_dpapi_protect", lambda value: b"encrypted:" + value[::-1])
    monkeypatch.setattr(enrollment, "_dpapi_unprotect", lambda value: value.removeprefix(b"encrypted:")[::-1])
    credentials = enrollment.DeviceCredentials("tenant", "device", "super-secret-token", 9999999999)
    store = CredentialStore(tmp_path / "device.json")

    store.save(credentials)

    metadata = (tmp_path / "device.json").read_text(encoding="utf-8")
    assert "super-secret-token" not in metadata
    assert json.loads(metadata)["token_protection"] == "dpapi-local-machine"
    assert store.load() == credentials


def test_enterprise_proxy_and_ca_environment(monkeypatch):
    monkeypatch.setenv("UMAI_HTTPS_PROXY", "http://proxy.example:8080")
    monkeypatch.setenv("UMAI_CA_BUNDLE", r"C:\certs\private.pem")
    assert proxy_url() == "http://proxy.example:8080"
    assert ca_bundle_path() == r"C:\certs\private.pem"


def test_support_bundle_redacts_and_excludes_credentials(tmp_path, monkeypatch):
    root = tmp_path / "data"
    (root / "state").mkdir(parents=True)
    (root / "config").mkdir()
    (root / "logs").mkdir()
    (root / "state" / "device-token.dpapi").write_bytes(b"secret-binary")
    (root / "state" / "device.json").write_text(
        json.dumps({"device_id": "d1", "device_token": "secret"}), encoding="utf-8"
    )
    (root / "config" / "collector.json").write_text(
        json.dumps({"endpoint": "https://example", "bootstrap_token": "secret"}), encoding="utf-8"
    )
    (root / "logs" / "collector.log").write_text(
        "Authorization: Bearer abc.def\nbootstrap_token=secret-two", encoding="utf-8"
    )
    monkeypatch.setenv("UMAI_ADR_DATA_DIR", str(root))
    output = tmp_path / "support.zip"

    create_support_bundle(output)

    with zipfile.ZipFile(output) as archive:
        names = archive.namelist()
        all_text = "\n".join(archive.read(name).decode("utf-8") for name in names)
    assert not any(name.endswith(".dpapi") for name in names)
    assert "abc.def" not in all_text
    assert "secret-two" not in all_text
    assert '"bootstrap_token": "[REDACTED]"' in all_text


def test_wix_contract_has_silent_msi_upgrade_task_and_permanent_state():
    wix = Path(__file__).parents[1] / "packaging" / "windows" / "Product.wxs"
    text = wix.read_text(encoding="utf-8")
    assert "MajorUpgrade" in text
    assert "RegisterCollectorTask" in text and "RemoveCollectorTask" in text
    assert 'Id="StateDirectory"' in text and 'Permanent="yes"' in text
    assert "NT AUTHORITY" not in text  # principal is defined in the installed task script
