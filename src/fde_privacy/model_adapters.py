"""Typed model adapters for provider-safe requests."""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from typing import Final, Protocol, runtime_checkable
from urllib.parse import unquote, urlsplit, urlunsplit
from urllib.request import Request, urlopen

from fde_privacy.contracts import SafeModelRequest

_PROVIDER_TIMEOUT_SECONDS: Final = 5.0
_CHAT_COMPLETIONS_PATH: Final = "/v1/chat/completions"
_PROVIDER_CONSTRUCTION_TOKEN: Final = object()


class ProviderDisabled(RuntimeError):
    """Raised when external provider access has not been explicitly enabled."""

    def __init__(self) -> None:
        super().__init__("external model provider is disabled")


class ProviderConfigurationError(RuntimeError):
    """Raised when enabled provider configuration is absent or unsafe."""

    def __init__(self) -> None:
        super().__init__("external model provider configuration is invalid")


class ProviderUnavailable(RuntimeError):
    """Raised when a provider response cannot be safely used."""

    def __init__(self) -> None:
        super().__init__("external model provider is unavailable")


class ProviderTransport(Protocol):
    """Small injectable HTTP boundary used by the optional provider."""

    def __call__(
        self,
        url: str,
        body: bytes,
        headers: Mapping[str, str],
        timeout: float,
    ) -> bytes:
        """POST one JSON body and return the response bytes."""


@runtime_checkable
class ModelAdapter(Protocol):
    """Minimal completion interface shared by model providers."""

    def complete(self, request: SafeModelRequest) -> str:
        """Complete a validated provider request."""


class CapturingMockAdapter:
    """Capture deterministic serialized payloads without contacting a provider."""

    def __init__(self, response: str | None = None) -> None:
        if response is not None and not isinstance(response, str):
            raise TypeError("response must be a string or None")
        self._response = response
        self.last_payload: str | None = None

    def complete(self, request: SafeModelRequest) -> str:
        """Serialize exactly once and return a deterministic response."""

        if type(request) is not SafeModelRequest:
            raise TypeError("request must be a SafeModelRequest")
        self.last_payload = request.model_dump_json()
        return request.safe_text if self._response is None else self._response


class LiteLLMAdapter:
    """Disabled-by-default OpenAI-compatible adapter for a configured LiteLLM gateway."""

    def __init__(
        self,
        *,
        endpoint: str,
        model: str,
        api_key: str,
        transport: ProviderTransport,
        _construction_token: object | None = None,
    ) -> None:
        if _construction_token is not _PROVIDER_CONSTRUCTION_TOKEN:
            raise ProviderDisabled()
        self._endpoint = endpoint
        self._model = model
        self._api_key = api_key
        self._transport = transport

    @classmethod
    def from_environment(
        cls,
        *,
        transport: ProviderTransport | None = None,
    ) -> LiteLLMAdapter:
        """Construct only after the exact opt-in gate and safe configuration validate."""

        if os.environ.get("ENABLE_EXTERNAL_MODEL") != "true":
            raise ProviderDisabled()

        base_url = os.environ.get("LITELLM_BASE_URL")
        model = os.environ.get("LITELLM_MODEL")
        if base_url is None or not base_url.strip() or model is None or not model.strip():
            raise ProviderConfigurationError()

        endpoint: str | None = None
        try:
            endpoint = _normalize_endpoint(base_url)
        except Exception:
            pass
        if endpoint is None:
            raise ProviderConfigurationError()

        return cls(
            endpoint=endpoint,
            model=model.strip(),
            api_key=os.environ.get("LITELLM_API_KEY", ""),
            transport=_urllib_transport if transport is None else transport,
            _construction_token=_PROVIDER_CONSTRUCTION_TOKEN,
        )

    def complete(self, request: SafeModelRequest) -> str:
        """Send only the closed safe-request fields and parse one deterministic completion."""

        if type(request) is not SafeModelRequest:
            raise TypeError("request must be a SafeModelRequest")

        messages: list[dict[str, str]] = [
            {"role": "system", "content": request.system_instruction},
            {"role": "user", "content": request.safe_text},
        ]
        if request.automotive_facts is not None:
            facts_json = json.dumps(
                request.automotive_facts.model_dump(mode="json"),
                separators=(",", ":"),
                sort_keys=True,
            )
            messages.append({"role": "user", "content": facts_json})

        body = json.dumps(
            {"model": self._model, "messages": messages},
            separators=(",", ":"),
        ).encode("utf-8")
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        content: object | None = None
        failed = False
        try:
            response = self._transport(
                self._endpoint,
                body,
                headers,
                _PROVIDER_TIMEOUT_SECONDS,
            )
            if not isinstance(response, bytes):
                failed = True
            else:
                parsed = json.loads(response)
                content = parsed["choices"][0]["message"]["content"]
        except Exception:
            failed = True
        if failed or not isinstance(content, str):
            raise ProviderUnavailable()
        return content


def _normalize_endpoint(base_url: str) -> str:
    if base_url != base_url.strip() or any(ord(character) < 32 for character in base_url):
        raise ValueError
    parsed = urlsplit(base_url)
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError
    if parsed.scheme == "http" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise ValueError
    _ = parsed.port

    decoded_path = unquote(parsed.path)
    if "\\" in decoded_path or any(segment in {".", ".."} for segment in decoded_path.split("/")):
        raise ValueError
    path = parsed.path.rstrip("/")
    if path.endswith(_CHAT_COMPLETIONS_PATH):
        endpoint_path = path
    elif path.endswith("/v1"):
        endpoint_path = f"{path}/chat/completions"
    else:
        endpoint_path = f"{path}{_CHAT_COMPLETIONS_PATH}"
    return urlunsplit((parsed.scheme, parsed.netloc, endpoint_path, "", ""))


def _urllib_transport(
    url: str,
    body: bytes,
    headers: Mapping[str, str],
    timeout: float,
) -> bytes:
    request = Request(url, data=body, headers=dict(headers), method="POST")
    with urlopen(request, timeout=timeout) as response:  # noqa: S310 - URL is validated above.
        data = response.read()
    if not isinstance(data, bytes):
        raise TypeError
    return data
