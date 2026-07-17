"""Typed model adapters for provider-safe requests."""

from typing import Protocol, runtime_checkable

from fde_privacy.contracts import SafeModelRequest


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

        if not isinstance(request, SafeModelRequest):
            raise TypeError("request must be a SafeModelRequest")
        self.last_payload = request.model_dump_json()
        return request.safe_text if self._response is None else self._response
