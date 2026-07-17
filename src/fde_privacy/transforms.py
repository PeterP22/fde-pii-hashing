"""Local, fail-closed PII value transformations."""

from collections.abc import Iterable
from dataclasses import dataclass
from re import fullmatch
from typing import Final

from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig, RecognizerResult

_ENGINE: Final = AnonymizerEngine()  # type: ignore[no-untyped-call]
_ENTITY_TYPE_PATTERN: Final = r"[A-Z][A-Z0-9_]*"
_MINIMUM_SALT_BYTES: Final = 16


class TransformValidationError(ValueError):
    """Raised when transformation inputs cannot be handled safely."""


@dataclass(frozen=True, slots=True)
class SpanReplacement:
    """A policy-approved replacement for a span in the original text."""

    start: int
    end: int
    value: str


def hash_value(value: str, *, salt: str | None = None) -> str:
    """Hash one complete value with Presidio's SHA-256 operator."""

    _validate_value(value)
    if salt is not None and (
        not isinstance(salt, str) or len(salt.encode("utf-8")) < _MINIMUM_SALT_BYTES
    ):
        raise TransformValidationError("salt must be a string containing at least 16 UTF-8 bytes")

    params: dict[str, str] = {"hash_type": "sha256"}
    if salt is not None:
        params["salt"] = salt
    result = _ENGINE.anonymize(
        text=value,
        analyzer_results=[RecognizerResult("VALUE", 0, len(value), 1.0)],
        operators={"VALUE": OperatorConfig("hash", params)},
    )
    return result.text


def mask_value(value: str, entity_type: str) -> str:
    """Replace one complete value with a repository-owned entity placeholder."""

    _validate_value(value)
    if not isinstance(entity_type, str) or fullmatch(_ENTITY_TYPE_PATTERN, entity_type) is None:
        raise TransformValidationError("entity type must be a non-empty uppercase identifier")

    replacement = f"<{entity_type}>"
    result = _ENGINE.anonymize(
        text=value,
        analyzer_results=[RecognizerResult(entity_type, 0, len(value), 1.0)],
        operators={entity_type: OperatorConfig("replace", {"new_value": replacement})},
    )
    return result.text


def transform_text(text: str, replacements: Iterable[SpanReplacement]) -> str:
    """Apply approved, non-overlapping replacements against original text offsets."""

    if not isinstance(text, str):
        raise TransformValidationError("text must be a string")

    try:
        ordered = sorted(replacements, key=lambda replacement: (replacement.start, replacement.end))
    except (AttributeError, TypeError) as error:
        raise TransformValidationError("replacements must contain valid spans") from error

    previous_end = -1
    for replacement in ordered:
        if (
            not isinstance(replacement, SpanReplacement)
            or type(replacement.start) is not int
            or type(replacement.end) is not int
            or not isinstance(replacement.value, str)
            or replacement.start < 0
            or replacement.start >= replacement.end
            or replacement.end > len(text)
        ):
            raise TransformValidationError("replacement span is invalid")
        if replacement.start < previous_end:
            raise TransformValidationError("replacement spans must not overlap")
        previous_end = replacement.end

    transformed = text
    for replacement in reversed(ordered):
        transformed = (
            transformed[: replacement.start] + replacement.value + transformed[replacement.end :]
        )
    return transformed


def _validate_value(value: str) -> None:
    if not isinstance(value, str) or not value:
        raise TransformValidationError("value must be a non-empty string")
