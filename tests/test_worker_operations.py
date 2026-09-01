import threading
import urllib.error
import urllib.request

from umai.worker.operations import RuntimeState, start_operations_server


def test_operations_endpoints_report_liveness_readiness_and_metrics():
    state = RuntimeState(
        stage="triage",
        claimed_total=4,
        processed_total=3,
        queue_claim_batch_size=4,
        active_leases=1,
    )
    server = start_operations_server(state, "127.0.0.1", 0)
    port = server.server_address[1]
    try:
        assert urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz").status == 200
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{port}/readyz")
            raise AssertionError("not-ready endpoint must return 503")
        except urllib.error.HTTPError as error:
            assert error.code == 503
        state.ready = True
        assert urllib.request.urlopen(f"http://127.0.0.1:{port}/readyz").status == 200
        metrics = urllib.request.urlopen(f"http://127.0.0.1:{port}/metrics").read().decode()
        assert 'umai_worker_claimed_total{stage="triage"} 4' in metrics
        assert 'umai_worker_processed_total{stage="triage"} 3' in metrics
        assert 'umai_worker_queue_claim_batch_size{stage="triage"} 4' in metrics
        assert 'umai_worker_active_leases{stage="triage"} 1' in metrics
    finally:
        server.shutdown()
        server.server_close()


def test_client_release_payload_uses_worker_identity(monkeypatch):
    from umai.worker.client import PlatformClient, PlatformConfig

    client = PlatformClient(PlatformConfig("https://platform", "token", worker_id="worker-1"))
    captured = {}

    def request(method, path, body=None):
        captured.update(method=method, path=path, body=body)
        return b'{"released":2}'

    monkeypatch.setattr(client, "_request", request)
    released = client.release(
        "triage",
        [
            {"tenant_id": "t1", "session_key": "s1"},
            {"tenant_id": "t1", "session_key": "s2"},
        ],
    )
    assert released == 2
    assert captured["body"]["worker_id"] == "worker-1"
    assert captured["path"] == "/internal/analysis/release"
