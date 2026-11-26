from __future__ import annotations

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any


class _FakeMailHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self,
        response_status: int,
        delay_seconds: float,
    ) -> None:
        super().__init__(("127.0.0.1", 0), _FakeMailHandler)
        self.response_status = response_status
        self.delay_seconds = delay_seconds
        self.messages: list[dict[str, Any]] = []
        self.messages_lock = threading.Lock()


class _FakeMailHandler(BaseHTTPRequestHandler):
    server: _FakeMailHTTPServer

    def do_POST(self) -> None:
        if self.path != "/send":
            self.send_error(404)
            return

        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.send_error(400)
            return

        if content_length < 1 or content_length > 100_000:
            self.send_error(400)
            return

        try:
            payload = json.loads(self.rfile.read(content_length))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self.send_error(400)
            return

        if not isinstance(payload, dict):
            self.send_error(400)
            return

        with self.server.messages_lock:
            self.server.messages.append(
                {
                    "authorization": self.headers.get("Authorization"),
                    "payload": payload,
                }
            )
            message_count = len(self.server.messages)

        if self.server.delay_seconds:
            time.sleep(self.server.delay_seconds)

        accepted = 200 <= self.server.response_status < 300
        response = json.dumps(
            {
                "accepted": accepted,
                "message_id": f"fake-{message_count}" if accepted else None,
            }
        ).encode("utf-8")

        self.send_response(self.server.response_status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, format: str, *args: object) -> None:
        return


class FakeMailServer:
    """Context-managed HTTP fake for the EmailAdapter."""

    def __init__(
        self,
        *,
        response_status: int = 202,
        delay_seconds: float = 0.0,
    ) -> None:
        self._server = _FakeMailHTTPServer(response_status, delay_seconds)
        self._thread: threading.Thread | None = None

    @property
    def endpoint_url(self) -> str:
        address = self._server.server_address
        host = address[0]
        if isinstance(host, bytes):
            host = host.decode("ascii")
        port = address[1]
        return f"http://{host}:{port}/send"

    @property
    def messages(self) -> list[dict[str, Any]]:
        with self._server.messages_lock:
            return list(self._server.messages)

    def __enter__(self) -> FakeMailServer:
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            daemon=True,
        )
        self._thread.start()
        return self

    def __exit__(self, *_: object) -> None:
        self._server.shutdown()
        self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=2)
