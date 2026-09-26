"""Dependency-free health, readiness and Prometheus metrics endpoint."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread


@dataclass
class RuntimeState:
    stage: str
    ready: bool = False
    started_at: float = field(default_factory=time.time)
    claimed_total: int = 0
    processed_total: int = 0
    failed_total: int = 0
    released_total: int = 0
    claim_errors_total: int = 0
    queue_claim_batch_size: int = 0
    active_leases: int = 0
    queue_age_seconds: float = 0.0
    last_success_at: float = 0.0
    batch_duration_seconds: float = 0.0
    # Daily cost budget (UMAI_MAX_COST_PER_DAY_USD). Paused is not unready:
    # the worker is healthy and connected, it has just stopped claiming.
    budget_paused: bool = False
    daily_budget_usd: float = 0.0
    daily_spend_usd: float = 0.0
    budget_stops_total: int = 0

    def prometheus(self) -> str:
        labels = f'stage="{self.stage}"'
        values = [
            ("umai_worker_up", 1),
            ("umai_worker_ready", int(self.ready)),
            ("umai_worker_claimed_total", self.claimed_total),
            ("umai_worker_processed_total", self.processed_total),
            ("umai_worker_failures_total", self.failed_total),
            ("umai_worker_released_leases_total", self.released_total),
            ("umai_worker_claim_errors_total", self.claim_errors_total),
            ("umai_worker_queue_claim_batch_size", self.queue_claim_batch_size),
            ("umai_worker_active_leases", self.active_leases),
            ("umai_worker_queue_age_seconds", self.queue_age_seconds),
            ("umai_worker_last_success_timestamp_seconds", self.last_success_at),
            ("umai_worker_batch_duration_seconds", self.batch_duration_seconds),
            ("umai_worker_budget_paused", int(self.budget_paused)),
            ("umai_worker_daily_budget_usd", self.daily_budget_usd),
            ("umai_worker_daily_spend_usd", self.daily_spend_usd),
            ("umai_worker_budget_stops_total", self.budget_stops_total),
        ]
        return "\n".join(f"{name}{{{labels}}} {value}" for name, value in values) + "\n"


def start_operations_server(state: RuntimeState, host: str, port: int) -> ThreadingHTTPServer:
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler API
            if self.path == "/healthz":
                self._reply(200, b'{"status":"ok"}\n', "application/json")
            elif self.path == "/readyz":
                code = 200 if state.ready else 503
                if not state.ready:
                    body = b'{"status":"not_ready"}\n'
                elif state.budget_paused:
                    body = b'{"status":"ready","paused":"daily_budget"}\n'
                else:
                    body = b'{"status":"ready"}\n'
                self._reply(code, body, "application/json")
            elif self.path == "/metrics":
                self._reply(200, state.prometheus().encode("utf-8"), "text/plain; version=0.0.4")
            else:
                self._reply(404, b"not found\n", "text/plain")

        def _reply(self, code: int, body: bytes, content_type: str):
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format, *_args):
            return

    server = ThreadingHTTPServer((host, port), Handler)
    Thread(target=server.serve_forever, name="worker-operations", daemon=True).start()
    return server
