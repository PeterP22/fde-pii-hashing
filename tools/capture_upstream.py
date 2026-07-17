#!/usr/bin/env python3
"""Privacy-safe in-memory OpenAI-compatible capture upstream."""

from __future__ import annotations

import argparse
import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Lock
from typing import Any
from urllib.parse import urlsplit

MAX_REQUEST_BYTES = 1_048_576
JsonObject = dict[str, Any]


class CaptureState:
    """Thread-safe request state which is never persisted to disk."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._last_request: JsonObject | None = None
        self._request_count = 0

    def record(self, payload: JsonObject) -> None:
        with self._lock:
            self._last_request = payload
            self._request_count += 1

    def snapshot(self) -> tuple[int, JsonObject | None]:
        with self._lock:
            return self._request_count, self._last_request

    def reset(self) -> None:
        with self._lock:
            self._last_request = None
            self._request_count = 0


class CaptureHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, server_address: tuple[str, int]) -> None:
        super().__init__(server_address, CaptureHandler)
        self.state = CaptureState()


class InvalidRequestError(ValueError):
    """Raised for malformed requests without retaining sensitive input."""


class CaptureHandler(BaseHTTPRequestHandler):
    server: CaptureHTTPServer

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        path = urlsplit(self.path).path
        if path == "/health":
            self._send_json(HTTPStatus.OK, {"status": "ok"})
            return

        request_count, last_request = self.server.state.snapshot()
        if path == "/request-count":
            self._send_json(HTTPStatus.OK, {"count": request_count})
        elif path == "/last-request":
            self._send_json(HTTPStatus.OK, last_request)
        else:
            self._send_error(HTTPStatus.NOT_FOUND, "not found")

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
        path = urlsplit(self.path).path
        if path == "/reset":
            self.server.state.reset()
            self._send_json(HTTPStatus.OK, {"status": "reset"})
            return
        if path != "/v1/chat/completions":
            self._send_error(HTTPStatus.NOT_FOUND, "not found")
            return

        try:
            payload = self._read_json_object()
        except InvalidRequestError:
            self._send_error(HTTPStatus.BAD_REQUEST, "invalid JSON request")
            return

        self.server.state.record(payload)
        model = payload.get("model")
        response_model = model if isinstance(model, str) else "capture-model"
        self._send_json(
            HTTPStatus.OK,
            {
                "id": "chatcmpl-capture",
                "object": "chat.completion",
                "created": 0,
                "model": response_model,
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "captured"},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
            },
        )

    def _read_json_object(self) -> JsonObject:
        raw_length = self.headers.get("Content-Length")
        try:
            content_length = int(raw_length) if raw_length is not None else -1
        except ValueError as error:
            raise InvalidRequestError from error
        if content_length <= 0 or content_length > MAX_REQUEST_BYTES:
            raise InvalidRequestError

        raw_body = self.rfile.read(content_length)
        if len(raw_body) != content_length:
            raise InvalidRequestError
        try:
            payload = json.loads(raw_body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise InvalidRequestError from error
        if not isinstance(payload, dict):
            raise InvalidRequestError
        return payload

    def _send_error(self, status: HTTPStatus, message: str) -> None:
        self._send_json(
            status,
            {"error": {"message": message, "type": "invalid_request_error"}},
        )

    def _send_json(self, status: HTTPStatus, payload: Any) -> None:
        encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, format: str, *args: object) -> None:
        """Disable request logging so prompts are not written to stdout or disk."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the in-memory capture upstream")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    server = CaptureHTTPServer((args.host, args.port))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
