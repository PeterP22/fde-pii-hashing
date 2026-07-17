import json
from collections.abc import Mapping
from datetime import UTC, datetime
from traceback import format_exception

import pytest

from fde_privacy.contracts import InboundUserRequest, SafeModelRequest, SessionContext
from fde_privacy.model_adapters import (
    LiteLLMAdapter,
    ProviderConfigurationError,
    ProviderDisabled,
    ProviderUnavailable,
)
from fde_privacy.pii_demo import main


class FakeTransport:
    def __init__(self, response: bytes | Exception) -> None:
        self.response = response
        self.calls: list[tuple[str, bytes, Mapping[str, str], float]] = []

    def __call__(
        self,
        url: str,
        body: bytes,
        headers: Mapping[str, str],
        timeout: float,
    ) -> bytes:
        self.calls.append((url, body, headers, timeout))
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


def _enable(
    monkeypatch: pytest.MonkeyPatch,
    *,
    base_url: str = "http://localhost:4000",
    model: str = "capture-model",
    api_key: str | None = None,
) -> None:
    monkeypatch.setenv("ENABLE_EXTERNAL_MODEL", "true")
    monkeypatch.setenv("LITELLM_BASE_URL", base_url)
    monkeypatch.setenv("LITELLM_MODEL", model)
    if api_key is None:
        monkeypatch.delenv("LITELLM_API_KEY", raising=False)
    else:
        monkeypatch.setenv("LITELLM_API_KEY", api_key)


def _safe_request() -> SafeModelRequest:
    return SafeModelRequest(
        system_instruction="Use only transformed values and approved facts.",
        safe_text="Summarize account {{PERSON:abcdefghijklmnopqrstuvwx}} without exact totals.",
    )


def _response(content: object = "safe completion") -> bytes:
    return json.dumps({"choices": [{"message": {"content": content}}]}).encode()


@pytest.mark.parametrize("setting", [None, "", "false", "False", "TRUE", " true", "true "])
def test_environment_gate_requires_exact_lowercase_true(
    setting: str | None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if setting is None:
        monkeypatch.delenv("ENABLE_EXTERNAL_MODEL", raising=False)
    else:
        monkeypatch.setenv("ENABLE_EXTERNAL_MODEL", setting)

    with pytest.raises(ProviderDisabled, match="^external model provider is disabled$"):
        LiteLLMAdapter.from_environment(transport=FakeTransport(_response()))


def test_direct_construction_cannot_bypass_the_environment_gate() -> None:
    with pytest.raises(ProviderDisabled):
        LiteLLMAdapter(
            endpoint="https://gateway.example/v1/chat/completions",
            model="capture-model",
            api_key="",
            transport=FakeTransport(_response()),
        )


@pytest.mark.parametrize(
    ("base_url", "model"),
    [(None, "capture-model"), ("", "capture-model"), ("http://localhost:4000", None), ("http://localhost:4000", "")],
)
def test_enabled_provider_requires_base_url_and_model(
    base_url: str | None,
    model: str | None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ENABLE_EXTERNAL_MODEL", "true")
    if base_url is None:
        monkeypatch.delenv("LITELLM_BASE_URL", raising=False)
    else:
        monkeypatch.setenv("LITELLM_BASE_URL", base_url)
    if model is None:
        monkeypatch.delenv("LITELLM_MODEL", raising=False)
    else:
        monkeypatch.setenv("LITELLM_MODEL", model)

    with pytest.raises(
        ProviderConfigurationError,
        match="^external model provider configuration is invalid$",
    ):
        LiteLLMAdapter.from_environment(transport=FakeTransport(_response()))


@pytest.mark.parametrize(
    "base_url",
    [
        "http://example.com",
        "http://10.0.0.1:4000",
        "http://192.168.1.12:4000",
        "http://172.16.0.5:4000",
        "ftp://localhost:4000",
        "https://user:super-secret@example.com",
        "https://example.com/path#fragment",
        "https://example.com/path?token=super-secret",
        "https://",
    ],
)
def test_enabled_provider_rejects_unsafe_base_urls(
    base_url: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable(monkeypatch, base_url=base_url)

    with pytest.raises(ProviderConfigurationError) as error:
        LiteLLMAdapter.from_environment(transport=FakeTransport(_response()))

    formatted = "".join(format_exception(error.value))
    assert str(error.value) == "external model provider configuration is invalid"
    assert "super-secret" not in formatted
    assert error.value.__cause__ is None
    assert error.value.__context__ is None


@pytest.mark.parametrize(
    ("base_url", "expected_url"),
    [
        ("http://localhost:4000", "http://localhost:4000/v1/chat/completions"),
        ("http://127.0.0.1:4000/", "http://127.0.0.1:4000/v1/chat/completions"),
        ("http://[::1]:4000/v1", "http://[::1]:4000/v1/chat/completions"),
        ("https://gateway.example/v1/chat/completions", "https://gateway.example/v1/chat/completions"),
    ],
)
def test_provider_normalizes_only_the_chat_completions_endpoint(
    base_url: str,
    expected_url: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = FakeTransport(_response())
    _enable(monkeypatch, base_url=base_url)
    adapter = LiteLLMAdapter.from_environment(transport=transport)

    assert adapter.complete(_safe_request()) == "safe completion"
    assert transport.calls[0][0] == expected_url


def test_provider_builds_exact_openai_body_from_safe_request_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw_pii = "alice.johnson@example.com"
    exact_total = "987654321"
    database_url = "postgresql://admin:password@10.0.0.8/private"
    api_key = "local-test-credential"
    transport = FakeTransport(_response())
    _enable(monkeypatch, api_key=api_key)
    request = _safe_request()

    adapter = LiteLLMAdapter.from_environment(transport=transport)

    assert adapter.complete(request) == "safe completion"
    assert len(transport.calls) == 1
    url, body, headers, timeout = transport.calls[0]
    assert url == "http://localhost:4000/v1/chat/completions"
    assert json.loads(body) == {
        "model": "capture-model",
        "messages": [
            {"role": "system", "content": request.system_instruction},
            {"role": "user", "content": request.safe_text},
        ],
    }
    assert headers == {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }
    assert 0 < timeout <= 10
    serialized = body.decode()
    for forbidden in (raw_pii, exact_total, database_url, api_key, "rows", "sql"):
        assert forbidden not in serialized.casefold()


@pytest.mark.parametrize("api_key", [None, ""])
def test_provider_omits_authorization_when_api_key_is_empty(
    api_key: str | None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = FakeTransport(_response())
    _enable(monkeypatch, api_key=api_key)
    adapter = LiteLLMAdapter.from_environment(transport=transport)

    adapter.complete(_safe_request())

    assert "Authorization" not in transport.calls[0][2]


def test_provider_rejects_arbitrary_inbound_and_subclass_requests(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class SafeRequestSubclass(SafeModelRequest):
        unsafe_metadata: str = "database-password"

    transport = FakeTransport(_response())
    _enable(monkeypatch)
    adapter = LiteLLMAdapter.from_environment(transport=transport)
    inbound = InboundUserRequest(
        text="alice.johnson@example.com",
        session=SessionContext(
            owner_id="owner",
            session_id="session",
            issued_at=datetime(2026, 7, 17, tzinfo=UTC),
        ),
    )
    subclass = SafeRequestSubclass(
        system_instruction="safe",
        safe_text="<PERSON>",
        unsafe_metadata="database-password",
    )

    for unsafe in ({"safe_text": "<PERSON>"}, inbound, subclass):
        with pytest.raises(TypeError, match="^request must be a SafeModelRequest$"):
            adapter.complete(unsafe)  # type: ignore[arg-type]

    assert transport.calls == []


@pytest.mark.parametrize(
    "response",
    [
        RuntimeError("HTTP body contained alice.johnson@example.com and local-test-credential"),
        b"not-json alice.johnson@example.com",
        b"{}",
        _response(None),
        _response({"unsafe": "alice.johnson@example.com"}),
    ],
)
def test_provider_failures_are_typed_and_privacy_safe(
    response: bytes | Exception,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _enable(monkeypatch, api_key="local-test-credential")
    adapter = LiteLLMAdapter.from_environment(transport=FakeTransport(response))

    with pytest.raises(ProviderUnavailable) as error:
        adapter.complete(_safe_request())

    formatted = "".join(format_exception(error.value))
    assert str(error.value) == "external model provider is unavailable"
    assert "alice.johnson@example.com" not in formatted
    assert "local-test-credential" not in formatted
    assert error.value.__cause__ is None
    assert error.value.__context__ is None


def test_cli_rejects_litellm_before_processing_or_printing_input(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setenv("PII_HASH_SALT", "fictional-dev-salt-32-bytes-long")
    monkeypatch.delenv("ENABLE_EXTERNAL_MODEL", raising=False)

    assert main(["--provider", "litellm"]) == 2

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "external model provider is disabled\n"
    assert "alice.johnson@example.com" not in captured.err
