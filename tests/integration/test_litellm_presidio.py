from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

import pytest

pytestmark = pytest.mark.integration

ROOT = Path(__file__).resolve().parents[2]
LITELLM_BASE_URL = os.environ.get("LITELLM_BASE_URL", "http://127.0.0.1:4000")
CAPTURE_BASE_URL = os.environ.get("CAPTURE_BASE_URL", "http://127.0.0.1:8080")
JSON = dict[str, Any] | list[Any] | str | int | float | bool | None


def _json_request(
    method: str,
    url: str,
    payload: JSON = None,
    *,
    timeout: float = 5.0,
) -> tuple[int, JSON]:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    request = Request(
        url,
        data=data,
        method=method,
        headers={"Content-Type": "application/json"} if data is not None else {},
    )
    try:
        with urlopen(request, timeout=timeout) as response:  # noqa: S310 - local test service
            body = json.loads(response.read().decode("utf-8"))
            return response.status, body
    except HTTPError as error:
        raw_body = error.read().decode("utf-8")
        try:
            body = json.loads(raw_body)
        except json.JSONDecodeError:
            body = {"error": "non-json response"}
        return error.code, body


def _find_free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_until_healthy(base_url: str, process: subprocess.Popen[bytes]) -> None:
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if process.poll() is not None:
            pytest.fail("capture upstream exited before becoming healthy")
        try:
            status, body = _json_request("GET", f"{base_url}/health", timeout=0.25)
        except URLError:
            time.sleep(0.05)
            continue
        if status == 200 and body == {"status": "ok"}:
            return
    pytest.fail("capture upstream did not become healthy")


@pytest.fixture
def capture_process() -> Iterator[str]:
    port = _find_free_port()
    process = subprocess.Popen(
        [
            sys.executable,
            str(ROOT / "tools" / "capture_upstream.py"),
            "--host",
            "127.0.0.1",
            "--port",
            str(port),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    base_url = f"http://127.0.0.1:{port}"
    try:
        _wait_until_healthy(base_url, process)
        yield base_url
    finally:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)


def test_capture_upstream_keeps_request_state_in_memory(capture_process: str) -> None:
    request_payload = {
        "model": "capture-model",
        "messages": [{"role": "user", "content": "fictional test prompt"}],
    }

    status, response = _json_request(
        "POST", f"{capture_process}/v1/chat/completions", request_payload
    )

    assert status == 200
    assert isinstance(response, dict)
    assert response["object"] == "chat.completion"
    assert response["choices"][0]["message"]["content"] == "captured"
    assert _json_request("GET", f"{capture_process}/request-count") == (200, {"count": 1})
    assert _json_request("GET", f"{capture_process}/last-request") == (200, request_payload)

    assert _json_request("POST", f"{capture_process}/reset", {}) == (
        200,
        {"status": "reset"},
    )
    assert _json_request("GET", f"{capture_process}/request-count") == (200, {"count": 0})
    assert _json_request("GET", f"{capture_process}/last-request") == (200, None)


@pytest.fixture
def local_services() -> None:
    checks = (
        (f"{LITELLM_BASE_URL}/health/liveliness", "I'm alive!"),
        (f"{CAPTURE_BASE_URL}/health", {"status": "ok"}),
    )
    for url, expected in checks:
        try:
            status, body = _json_request("GET", url, timeout=1)
        except URLError:
            pytest.skip(
                "local LiteLLM/Presidio capture services are absent; "
                "run `docker compose up --wait` before integration tests"
            )
        assert status == 200, f"local service health check failed for {url}"
        assert body == expected, f"unexpected local service health response for {url}"


@pytest.fixture
def reset_capture(local_services: None) -> Iterator[None]:
    status, body = _json_request("POST", f"{CAPTURE_BASE_URL}/reset", {})
    assert (status, body) == (200, {"status": "reset"})
    yield
    status, body = _json_request("POST", f"{CAPTURE_BASE_URL}/reset", {})
    assert (status, body) == (200, {"status": "reset"})


def test_low_risk_fictional_pii_is_masked_before_capture(reset_capture: None) -> None:
    originals = ("Jane Doe", "jane.doe@example.com", "+1 202-555-0147")
    request_payload = {
        "model": "capture-model",
        "messages": [
            {
                "role": "user",
                "content": (
                    "Fictional contact Jane Doe can be reached at "
                    "jane.doe@example.com or +1 202-555-0147."
                ),
            }
        ],
    }

    status, response = _json_request(
        "POST", f"{LITELLM_BASE_URL}/v1/chat/completions", request_payload, timeout=15
    )

    assert status == 200
    assert isinstance(response, dict)
    assert response["choices"][0]["message"]["content"] == "captured"
    assert _json_request("GET", f"{CAPTURE_BASE_URL}/request-count") == (
        200,
        {"count": 1},
    )
    capture_status, captured = _json_request("GET", f"{CAPTURE_BASE_URL}/last-request")
    assert capture_status == 200
    serialized_capture = json.dumps(captured)
    for original in originals:
        assert original not in serialized_capture
    for placeholder in ("<PERSON>", "<EMAIL_ADDRESS>", "<PHONE_NUMBER>"):
        assert placeholder in serialized_capture


def test_high_risk_credit_card_is_blocked_before_capture(reset_capture: None) -> None:
    standard_test_card = "4111111111111111"
    count_before = _json_request("GET", f"{CAPTURE_BASE_URL}/request-count")
    payload_before = _json_request("GET", f"{CAPTURE_BASE_URL}/last-request")

    status, response = _json_request(
        "POST",
        f"{LITELLM_BASE_URL}/v1/chat/completions",
        {
            "model": "capture-model",
            "messages": [
                {
                    "role": "user",
                    "content": f"This is a standard test credit-card number: {standard_test_card}.",
                }
            ],
        },
        timeout=15,
    )

    assert 400 <= status < 500
    assert standard_test_card not in json.dumps(response)
    assert _json_request("GET", f"{CAPTURE_BASE_URL}/request-count") == count_before
    assert _json_request("GET", f"{CAPTURE_BASE_URL}/last-request") == payload_before
