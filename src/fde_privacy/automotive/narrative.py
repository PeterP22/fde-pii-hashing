"""Validate model templates and insert confidential exact values only locally."""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Final

from pydantic import ValidationError

from fde_privacy.automotive.analytics import derive_narrative_facts
from fde_privacy.automotive.contracts import (
    AutomotiveNarrativeFacts,
    DataQualityFlag,
    Placeholder,
)
from fde_privacy.automotive.database import MonthlyTotal
from fde_privacy.contracts import NarrativeTemplate

_DIGIT_PATTERN: Final = re.compile(r"[0-9]")
_PLACEHOLDER_PATTERN: Final = re.compile(r"\{\{[^{}]+\}\}")


class NarrativeValidationError(ValueError):
    """A privacy-safe failure raised before local value composition."""


def _texts(template: NarrativeTemplate) -> tuple[str, ...]:
    caveat = () if template.caveat is None else (template.caveat,)
    return (template.headline, *template.observations, *caveat)


def _extract_placeholders(text: str) -> tuple[str, ...]:
    found = tuple(match.group() for match in _PLACEHOLDER_PATTERN.finditer(text))
    without_known_shapes = _PLACEHOLDER_PATTERN.sub("", text)
    if "{{" in without_known_shapes or "}}" in without_known_shapes:
        raise NarrativeValidationError("model narrative contains an unknown placeholder")
    return found


def _validate_template_content(
    template: NarrativeTemplate,
    *,
    allowed_placeholders: frozenset[Placeholder],
    caveat_allowed: bool,
) -> None:
    if any(_DIGIT_PATTERN.search(text) is not None for text in _texts(template)):
        raise NarrativeValidationError("model narrative contains digits")
    if _extract_placeholders(template.headline):
        raise NarrativeValidationError("model narrative headline cannot contain placeholders")
    if template.caveat is not None and _extract_placeholders(template.caveat):
        raise NarrativeValidationError("model narrative caveat cannot contain placeholders")
    if template.caveat is not None and not caveat_allowed:
        raise NarrativeValidationError("model narrative caveat requires a data quality warning")

    for observation in template.observations:
        for raw_placeholder in _extract_placeholders(observation):
            try:
                placeholder = Placeholder(raw_placeholder)
            except ValueError:
                raise NarrativeValidationError(
                    "model narrative contains an unknown placeholder"
                ) from None
            if placeholder not in allowed_placeholders:
                raise NarrativeValidationError(
                    "model narrative contains an unrequested placeholder"
                )


def validate_model_response(
    model_output: str,
    facts: AutomotiveNarrativeFacts,
) -> NarrativeTemplate:
    """Parse and fail-closed validate the model's JSON narrative grammar."""

    if not isinstance(model_output, str) or type(facts) is not AutomotiveNarrativeFacts:
        raise NarrativeValidationError("model narrative contract validation failed")
    try:
        template = NarrativeTemplate.model_validate_json(model_output)
    except (ValidationError, ValueError, TypeError):
        raise NarrativeValidationError("model narrative contract validation failed") from None

    caveat_allowed = any(
        flag is not DataQualityFlag.NONE for flag in facts.data_quality_flags
    )
    _validate_template_content(
        template,
        allowed_placeholders=frozenset(facts.allowed_placeholders),
        caveat_allowed=caveat_allowed,
    )
    return template


def validate_narrative_template(
    model_output: str,
    facts: AutomotiveNarrativeFacts,
) -> NarrativeTemplate:
    """Named alias for callers that describe validation by artifact type."""

    return validate_model_response(model_output, facts)


def render_monthly_table(monthly_totals: Sequence[MonthlyTotal]) -> str:
    """Render the trusted exact local result as a deterministic Markdown table."""

    totals = tuple(monthly_totals)
    derive_narrative_facts(totals)
    rows = ["Month | Vehicle sales", "--- | ---:"]
    rows.extend(f"{item.month} | {item.total}" for item in totals)
    return "\n".join(rows)


def _substitution_map(monthly_totals: tuple[MonthlyTotal, ...]) -> dict[Placeholder, str]:
    peak = max(monthly_totals, key=lambda item: item.total)
    trough = min(monthly_totals, key=lambda item: item.total)
    return {
        Placeholder.PEAK_MONTH_TOTAL: str(peak.total),
        Placeholder.TROUGH_MONTH_TOTAL: str(trough.total),
        Placeholder.PERIOD_START_TOTAL: str(monthly_totals[0].total),
        Placeholder.PERIOD_END_TOTAL: str(monthly_totals[-1].total),
    }


def compose_user_response(
    monthly_totals: Sequence[MonthlyTotal],
    template: NarrativeTemplate,
) -> str:
    """Render the exact table and substitute only registered values in first-party code."""

    if type(template) is not NarrativeTemplate:
        raise NarrativeValidationError("model narrative contract validation failed")
    totals = tuple(monthly_totals)
    table = render_monthly_table(totals)
    _validate_template_content(
        template,
        allowed_placeholders=frozenset(Placeholder),
        caveat_allowed=True,
    )

    mapping = _substitution_map(totals)
    narrative_parts = [template.headline, *(f"- {item}" for item in template.observations)]
    if template.caveat is not None:
        narrative_parts.append(f"Caveat: {template.caveat}")
    narrative = "\n".join(narrative_parts)
    for placeholder, exact_value in mapping.items():
        narrative = narrative.replace(placeholder.value, exact_value)
    if "{{" in narrative or "}}" in narrative:
        raise NarrativeValidationError("model narrative contains an unresolved placeholder")
    return f"{table}\n\n{narrative}"


def compose_local_fallback(monthly_totals: Sequence[MonthlyTotal]) -> str:
    """Return an explicitly local deterministic summary when no model is available."""

    template = NarrativeTemplate(
        headline="LOCAL FALLBACK NARRATIVE",
        observations=(
            "The strongest month recorded {{PEAK_MONTH_TOTAL}} vehicle sales.",
            "The period ended with {{PERIOD_END_TOTAL}} vehicle sales.",
        ),
    )
    return compose_user_response(monthly_totals, template)
