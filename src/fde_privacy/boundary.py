"""Provider-facing request construction with fail-closed local leakage checks."""

from collections.abc import Collection, Mapping, Sequence
from dataclasses import dataclass
from decimal import Decimal
from enum import StrEnum
from ipaddress import IPv4Address
from math import isfinite
from re import IGNORECASE, Pattern, escape, finditer
from re import compile as compile_regex
from types import MappingProxyType
from typing import Final

from fde_privacy.contracts import SafeModelRequest
from fde_privacy.detector import DetectedEntity, detect_pii
from fde_privacy.policy import PolicyDecision, decide_policy


class BoundaryViolation(ValueError):
    """Raised when a provider request cannot be proven safe."""


class SystemPromptId(StrEnum):
    """Closed identifiers for repository-owned provider instructions."""

    PII_SUMMARY = "pii_summary"
    AUTOMOTIVE_NARRATIVE = "automotive_narrative"


SYSTEM_PROMPTS: Final[Mapping[SystemPromptId, str]] = MappingProxyType(
    {
        SystemPromptId.PII_SUMMARY: (
            "Summarize only the transformed user text. Do not infer or reconstruct protected "
            "values."
        ),
        SystemPromptId.AUTOMOTIVE_NARRATIVE: (
            "Write an automotive narrative using only the transformed user text and approved facts."
        ),
    }
)

MAX_SAFE_TEXT_LENGTH: Final = 20_000
_TOKEN_PATTERN: Final[Pattern[str]] = compile_regex(r"\{\{[A-Z][A-Z0-9_]*:[A-Za-z0-9_-]{24}\}\}")
_MASK_PATTERN: Final[Pattern[str]] = compile_regex(r"<[A-Z][A-Z0-9_]*>")
_HASH_PATTERN: Final[Pattern[str]] = compile_regex(r"(?<![0-9A-Za-z])[0-9a-f]{64}(?![0-9A-Za-z])")
_PROTECTED_LOOKING_PATTERNS: Final[tuple[Pattern[str], ...]] = (
    compile_regex(r"\{\{[^{}\n]*\}\}"),
    compile_regex(r"<[^<>\n]+>"),
    compile_regex(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{64,}(?![0-9A-Fa-f])"),
)
_MONTH_PATTERNS: Final[tuple[Pattern[str], ...]] = (
    compile_regex(r"\b(?:19|20)\d{2}[-/](?:0[1-9]|1[0-2])\b"),
    compile_regex(
        r"\b(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|Jun(?:e)?|"
        r"Jul(?:y)?|Aug(?:ust)?|Sep(?:tember)?|Oct(?:ober)?|Nov(?:ember)?|"
        r"Dec(?:ember)?)\s+(?:19|20)\d{2}\b",
        IGNORECASE,
    ),
)
_ENTITY_TYPE_PATTERN: Final[Pattern[str]] = compile_regex(r"[A-Z][A-Z0-9_]*")
_EMAIL_PATTERN: Final[Pattern[str]] = compile_regex(
    r"\b[A-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?"
    r"(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+\b",
    IGNORECASE,
)
_PHONE_PATTERN: Final[Pattern[str]] = compile_regex(
    r"\b(?:phone|mobile|call|contact|tel(?:ephone)?)\b[^\n]{0,32}?"
    r"(?<!\w)(?:\+?\d[\d ()-]{7,}\d)\b",
    IGNORECASE,
)
_CUSTOMER_ID_PATTERN: Final[Pattern[str]] = compile_regex(r"\bCUST-[0-9]{6}\b")
_CREDIT_CARD_PATTERN: Final[Pattern[str]] = compile_regex(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")
_IPV4_CANDIDATE_PATTERN: Final[Pattern[str]] = compile_regex(
    r"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])"
)
_DATABASE_SCHEME_PATTERNS: Final[tuple[Pattern[str], ...]] = (
    compile_regex(
        r"(?<![A-Za-z0-9])(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|"
        r"sqlite)://\S+",
        IGNORECASE,
    ),
    compile_regex(r"(?<![A-Za-z0-9])jdbc:[a-z0-9]+://\S+", IGNORECASE),
)
_DATABASE_FILE_EXTENSION_PATTERN: Final[Pattern[str]] = compile_regex(
    r"\.(?:db|sqlite(?:3)?)(?![A-Za-z0-9])",
    IGNORECASE,
)
_ASCII_ALNUM_WORD_PATTERN: Final[Pattern[str]] = compile_regex(r"[A-Za-z0-9]+")
_DATABASE_DIRECTORY_NAMES: Final[frozenset[str]] = frozenset({"mysql", "postgresql"})
_NUMERIC_TOKEN_PATTERN: Final[Pattern[str]] = compile_regex(
    r"(?<![A-Za-z0-9_])(?P<open>\()?(?P<sign_before>[+-])?\$?(?P<sign_after>[+-])?"
    r"(?P<number>(?:[0-9]{1,3}(?:,[0-9]{3})+|[0-9]+)(?:\.[0-9]+)?)"
    r"(?P<close>\))?(?![A-Za-z0-9_])"
)
_MALFORMED_NUMERIC_CANDIDATE_PATTERN: Final[Pattern[str]] = compile_regex(
    r"(?<![A-Za-z0-9_])(?P<prefix>[()$+\- \t]*)"
    r"(?P<number>(?:[0-9]{1,3}(?:,[0-9]{3})+|[0-9]+)(?:\.[0-9]+)?)"
    r"(?P<suffix>[()$+\- \t]*)(?![A-Za-z0-9_])"
)
_REPEATED_CURRENCY_CODE_PATTERN: Final[Pattern[str]] = compile_regex(
    r"(?<![A-Za-z0-9_])(?P<code>[A-Z]{3})(?:[ \t]+(?P=code))+[ \t]+[+$\- \t]*"
    r"(?P<number>(?:[0-9]{1,3}(?:,[0-9]{3})+|[0-9]+)(?:\.[0-9]+)?)"
    r"(?![A-Za-z0-9_])"
)
_NUMERIC_LITERAL_PATTERN: Final[Pattern[str]] = compile_regex(
    r"(?P<open>\()?(?P<sign_before>[+-])?"
    r"(?:(?:[A-Z]{3})[ \t]+)?\$?(?P<sign_after>[+-])?"
    r"(?P<number>(?:[0-9]{1,3}(?:,[0-9]{3})+|[0-9]+)(?:\.[0-9]+)?)"
    r"(?P<close>\))?",
    IGNORECASE,
)
_FORBIDDEN_FIELD_NAMES: Final[tuple[str, ...]] = (
    "database_url",
    "host",
    "port",
    "credentials",
    "connection_string",
    "sql",
    "schema",
    "rows",
)

Span = tuple[int, int]


@dataclass(frozen=True, slots=True)
class _ExactValues:
    string_literals: tuple[str, ...]
    numeric_values: frozenset[Decimal]


_EMPTY_EXACT_VALUES: Final = _ExactValues((), frozenset())


def build_safe_request(
    *,
    safe_text: str,
    system_prompt_id: SystemPromptId,
    automotive_facts: None = None,
    forbidden_exact_values: Collection[str | int] = (),
) -> SafeModelRequest:
    """Build an immutable request only after local, fail-closed inspection."""

    if not isinstance(safe_text, str) or not safe_text:
        raise BoundaryViolation("safe text must be a non-empty string")
    if len(safe_text) > MAX_SAFE_TEXT_LENGTH:
        raise BoundaryViolation("safe text exceeds maximum length")
    if not isinstance(system_prompt_id, SystemPromptId):
        raise BoundaryViolation("system prompt must use a repository-owned identifier")
    if automotive_facts is not None:
        raise BoundaryViolation("automotive facts are not accepted by this boundary version")

    exact_values = _normalize_exact_values(forbidden_exact_values)
    protected_spans = _protected_spans(safe_text)

    detections = _run_detector(safe_text)

    visible_text = _blank_spans(safe_text, protected_spans)
    manual_violation = _find_manual_violation(visible_text)
    if manual_violation is not None:
        kind, category = manual_violation
        raise BoundaryViolation(f"request contains forbidden {kind}: {category}")

    _reject_exact_values(safe_text, exact_values, protected_spans)
    _reject_unprotected_detections(detections, protected_spans, len(safe_text))
    visible_detections = _run_detector(visible_text)
    _reject_unprotected_detections(visible_detections, (), len(safe_text))

    request: SafeModelRequest | None = None
    try:
        request = SafeModelRequest(
            system_instruction=SYSTEM_PROMPTS[system_prompt_id],
            safe_text=safe_text,
            automotive_facts=None,
        )
    except Exception:
        pass
    if request is None:
        raise BoundaryViolation("safe request contract validation failed")

    serialized = request.model_dump(mode="json")
    serialized_violation = _inspect_serialized(serialized, exact_values)
    if serialized_violation is not None:
        kind, category = serialized_violation
        raise BoundaryViolation(f"serialized request contains forbidden {kind}: {category}")
    return request


def _normalize_exact_values(values: Collection[str | int]) -> _ExactValues:
    normalized: tuple[object, ...] | None = None
    if isinstance(values, (str, bytes, bytearray)):
        raise BoundaryViolation("forbidden exact values collection is invalid")
    try:
        normalized = tuple(values)
    except Exception:
        pass
    if normalized is None:
        raise BoundaryViolation("forbidden exact values collection is invalid")

    string_literals: list[str] = []
    numeric_values: set[Decimal] = set()
    for value in normalized:
        if type(value) is int:
            numeric_values.add(Decimal(value))
        elif isinstance(value, str) and value:
            string_literals.append(value)
            match = _NUMERIC_LITERAL_PATTERN.fullmatch(value)
            if match is not None:
                has_open_parenthesis = match.group("open") is not None
                has_close_parenthesis = match.group("close") is not None
                sign_before = match.group("sign_before")
                sign_after = match.group("sign_after")
                if has_open_parenthesis == has_close_parenthesis and not (
                    sign_before is not None and sign_after is not None
                ):
                    numeric_value = Decimal(match.group("number").replace(",", ""))
                    explicit_sign = sign_before or sign_after
                    if has_open_parenthesis or explicit_sign == "-":
                        numeric_value = -numeric_value
                    numeric_values.add(numeric_value)
        else:
            raise BoundaryViolation("forbidden exact values collection is invalid")
    return _ExactValues(tuple(string_literals), frozenset(numeric_values))


def _protected_spans(text: str) -> tuple[Span, ...]:
    spans = [
        match.span()
        for pattern in (_TOKEN_PATTERN, _MASK_PATTERN, _HASH_PATTERN)
        for match in pattern.finditer(text)
    ]
    return tuple(sorted(spans))


def _month_spans(text: str) -> tuple[Span, ...]:
    return tuple(
        sorted(match.span() for pattern in _MONTH_PATTERNS for match in pattern.finditer(text))
    )


def _blank_spans(text: str, spans: Sequence[Span]) -> str:
    characters = list(text)
    for start, end in spans:
        characters[start:end] = " " * (end - start)
    return "".join(characters)


def _find_manual_violation(text: str) -> tuple[str, str] | None:
    if any(pattern.search(text) is not None for pattern in _PROTECTED_LOOKING_PATTERNS):
        return "category", "protected value format"
    field_name = _find_forbidden_field_name(text)
    if field_name is not None:
        return "field name", field_name
    if _contains_database_location(text):
        return "category", "database location"
    if _contains_private_ipv4(text):
        return "category", "private network address"
    if _EMAIL_PATTERN.search(text) is not None:
        return "entity type", "EMAIL_ADDRESS"
    if _PHONE_PATTERN.search(text) is not None:
        return "entity type", "PHONE_NUMBER"
    if _CUSTOMER_ID_PATTERN.search(text) is not None:
        return "entity type", "CUSTOMER_ID"
    if _CREDIT_CARD_PATTERN.search(text) is not None:
        return "entity type", "CREDIT_CARD"
    return None


def _find_forbidden_field_name(text: str) -> str | None:
    for field_name in _FORBIDDEN_FIELD_NAMES:
        pattern = compile_regex(
            rf"(?<![A-Za-z0-9]){escape(field_name)}(?![A-Za-z0-9])",
            IGNORECASE,
        )
        if pattern.search(text) is not None:
            return field_name
    return None


def _contains_database_location(text: str) -> bool:
    for chunk in text.split():
        if any(pattern.search(chunk) is not None for pattern in _DATABASE_SCHEME_PATTERNS):
            return True
        if _DATABASE_FILE_EXTENSION_PATTERN.search(chunk) is not None:
            return True
        if "/" not in chunk and "\\" not in chunk:
            continue
        for segment in chunk.replace("\\", "/").split("/"):
            if any(
                match.group().casefold() in _DATABASE_DIRECTORY_NAMES
                for match in _ASCII_ALNUM_WORD_PATTERN.finditer(segment)
            ):
                return True
    return False


def _contains_private_ipv4(text: str) -> bool:
    for match in _IPV4_CANDIDATE_PATTERN.finditer(text):
        address: IPv4Address | None = None
        try:
            address = IPv4Address(match.group())
        except ValueError:
            pass
        if address is not None and address.is_private:
            return True
    return False


def _run_detector(text: str) -> tuple[object, ...]:
    detections: tuple[object, ...] | None = None
    try:
        detections = tuple(detect_pii(text))
    except Exception:
        pass
    if detections is None:
        raise BoundaryViolation("local privacy detection failed")
    return detections


def _reject_unprotected_detections(
    detections: Sequence[object], protected_spans: Sequence[Span], text_length: int
) -> None:
    for detection in detections:
        if (
            not isinstance(detection, DetectedEntity)
            or not isinstance(detection.entity_type, str)
            or type(detection.start) is not int
            or type(detection.end) is not int
            or not 0 <= detection.start < detection.end <= text_length
        ):
            raise BoundaryViolation("local privacy detection returned an invalid category")
        if any(start <= detection.start and detection.end <= end for start, end in protected_spans):
            continue

        decision: PolicyDecision | None = None
        try:
            decision = decide_policy(detection.entity_type, detection.score)
        except Exception:
            pass
        if decision is None:
            raise BoundaryViolation("local privacy detection returned an invalid category")
        category = (
            detection.entity_type
            if _ENTITY_TYPE_PATTERN.fullmatch(detection.entity_type) is not None
            else "detected entity"
        )
        disposition = "review-required" if decision.needs_review else "disallowed"
        raise BoundaryViolation(f"request contains {disposition} entity type: {category}")


def _reject_exact_values(
    text: str, exact_values: _ExactValues, protected_spans: Sequence[Span]
) -> None:
    if _contains_exact_value(text, exact_values, protected_spans):
        raise BoundaryViolation("request contains an exact confidential value")


def _contains_exact_value(
    text: str, exact_values: _ExactValues, protected_spans: Sequence[Span]
) -> bool:
    locally_exempt = (*protected_spans, *_month_spans(text))
    inspectable = _blank_spans(text, locally_exempt)
    for value in exact_values.string_literals:
        for match in finditer(escape(value), inspectable):
            if _is_standalone_match(inspectable, match.start(), match.end(), value):
                return True
    return _contains_forbidden_numeric_value(inspectable, exact_values.numeric_values)


def _contains_forbidden_numeric_value(text: str, forbidden_values: frozenset[Decimal]) -> bool:
    if not forbidden_values:
        return False
    forbidden_magnitudes = frozenset(abs(value) for value in forbidden_values)
    for match in _MALFORMED_NUMERIC_CANDIDATE_PATTERN.finditer(text):
        wrappers = match.group("prefix") + match.group("suffix")
        parenthesis_depth = 0
        has_unmatched_parentheses = False
        for character in wrappers:
            if character == "(":
                parenthesis_depth += 1
            elif character == ")":
                if parenthesis_depth == 0:
                    has_unmatched_parentheses = True
                    break
                parenthesis_depth -= 1
        has_unmatched_parentheses = has_unmatched_parentheses or parenthesis_depth != 0
        has_repeated_signs = wrappers.count("+") + wrappers.count("-") > 1
        has_repeated_currency_markers = wrappers.count("$") > 1
        if has_unmatched_parentheses or has_repeated_signs or has_repeated_currency_markers:
            magnitude = Decimal(match.group("number").replace(",", ""))
            if magnitude in forbidden_magnitudes:
                return True
    for match in _REPEATED_CURRENCY_CODE_PATTERN.finditer(text):
        magnitude = Decimal(match.group("number").replace(",", ""))
        if magnitude in forbidden_magnitudes:
            return True
    for match in _NUMERIC_TOKEN_PATTERN.finditer(text):
        has_open_parenthesis = match.group("open") is not None
        has_close_parenthesis = match.group("close") is not None
        sign_before = match.group("sign_before")
        sign_after = match.group("sign_after")
        if sign_before is not None and sign_after is not None:
            continue

        numeric_value = Decimal(match.group("number").replace(",", ""))
        explicit_sign = sign_before or sign_after
        if (has_open_parenthesis and has_close_parenthesis) or explicit_sign == "-":
            numeric_value = -numeric_value
        if numeric_value in forbidden_values:
            return True
    return False


def _is_standalone_match(text: str, start: int, end: int, value: str) -> bool:
    left = text[start - 1] if start else ""
    right = text[end] if end < len(text) else ""
    if left and (left.isalnum() or left == "_"):
        return False
    if right and (right.isalnum() or right == "_"):
        return False
    if value.lstrip("-").isdigit():
        if left in ".," and start >= 2 and text[start - 2].isdigit():
            return False
        if right in ".," and end + 1 < len(text) and text[end + 1].isdigit():
            return False
    return True


def _inspect_serialized(
    value: object, exact_values: _ExactValues = _EMPTY_EXACT_VALUES
) -> tuple[str, str] | None:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if not isinstance(key, str):
                return "field name", "non-string field"
            normalized_key = key.casefold()
            if normalized_key in _FORBIDDEN_FIELD_NAMES:
                return "field name", normalized_key
            violation = _inspect_serialized(nested, exact_values)
            if violation is not None:
                return violation
        return None
    if isinstance(value, list):
        for nested in value:
            violation = _inspect_serialized(nested, exact_values)
            if violation is not None:
                return violation
        return None
    if isinstance(value, str):
        visible = _blank_spans(value, _protected_spans(value))
        field_name = _find_forbidden_field_name(visible)
        if field_name is not None:
            return "field name", field_name
        if _contains_database_location(visible):
            return "category", "database location"
        if _contains_exact_value(value, exact_values, _protected_spans(value)):
            return "category", "exact confidential value"
        return None
    numeric_value: Decimal | None = None
    if type(value) is int:
        numeric_value = Decimal(value)
    elif type(value) is float:
        if not isfinite(value):
            return "category", "invalid numeric value"
        numeric_value = Decimal(str(value))
    elif isinstance(value, Decimal):
        if not value.is_finite():
            return "category", "invalid numeric value"
        numeric_value = value
    if numeric_value is not None and numeric_value in exact_values.numeric_values:
        return "category", "exact confidential value"
    return None
