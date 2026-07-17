import json
from traceback import format_exception

import pytest

from fde_privacy.automotive.analytics import derive_narrative_facts
from fde_privacy.automotive.contracts import DataQualityFlag, Placeholder
from fde_privacy.automotive.database import MonthlyTotal
from fde_privacy.automotive.narrative import (
    NarrativeValidationError,
    compose_local_fallback,
    compose_user_response,
    render_monthly_table,
    validate_model_response,
)
from fde_privacy.contracts import NarrativeTemplate

TOTALS = (
    MonthlyTotal("2025-07", 8),
    MonthlyTotal("2025-08", 10),
    MonthlyTotal("2025-09", 9),
    MonthlyTotal("2025-10", 12),
    MonthlyTotal("2025-11", 12),
    MonthlyTotal("2025-12", 15),
    MonthlyTotal("2026-01", 11),
    MonthlyTotal("2026-02", 10),
    MonthlyTotal("2026-03", 13),
    MonthlyTotal("2026-04", 14),
    MonthlyTotal("2026-05", 16),
    MonthlyTotal("2026-06", 18),
)


def model_json(
    *,
    headline: str = "Sales strengthened across the period",
    observations: tuple[str, ...] = (
        "The strongest month reached {{PEAK_MONTH_TOTAL}} vehicle sales.",
        "The period ended at {{PERIOD_END_TOTAL}} vehicle sales.",
    ),
    caveat: str | None = None,
) -> str:
    return json.dumps(
        {"headline": headline, "observations": observations, "caveat": caveat}
    )


def test_valid_model_json_becomes_existing_narrative_template() -> None:
    facts = derive_narrative_facts(TOTALS)

    template = validate_model_response(model_json(), facts)

    assert type(template) is NarrativeTemplate
    assert template.headline == "Sales strengthened across the period"
    assert template.observations[0].endswith("{{PEAK_MONTH_TOTAL}} vehicle sales.")


@pytest.mark.parametrize(
    "output",
    [
        model_json(headline="Sales rose in 2 waves"),
        model_json(observations=("Sales rose by five then 2.",)),
        model_json(caveat="One month has 1 warning"),
    ],
)
def test_model_narrative_rejects_digits_anywhere(output: str) -> None:
    with pytest.raises(NarrativeValidationError, match="digits"):
        validate_model_response(output, derive_narrative_facts(TOTALS))


def test_headline_rejects_placeholders() -> None:
    with pytest.raises(NarrativeValidationError, match="headline"):
        validate_model_response(
            model_json(headline="Peak reached {{PEAK_MONTH_TOTAL}}"),
            derive_narrative_facts(TOTALS),
        )


def test_unknown_placeholder_is_rejected_without_echoing_model_text() -> None:
    secret = "{{CUSTOMER_SECRET}}"
    output = model_json(observations=(f"The result included {secret}.",))

    with pytest.raises(NarrativeValidationError, match="unknown placeholder") as error:
        validate_model_response(output, derive_narrative_facts(TOTALS))

    assert output not in "".join(format_exception(error.value))
    assert secret not in "".join(format_exception(error.value))


def test_registered_but_unrequested_placeholder_is_rejected() -> None:
    facts = derive_narrative_facts(TOTALS).model_copy(
        update={"allowed_placeholders": (Placeholder.PEAK_MONTH_TOTAL,)}
    )

    with pytest.raises(NarrativeValidationError, match="unrequested placeholder"):
        validate_model_response(
            model_json(observations=("The end reached {{PERIOD_END_TOTAL}} sales.",)),
            facts,
        )


def test_model_contract_rejects_more_than_four_observations_privately() -> None:
    output = model_json(observations=("safe",) * 5)

    with pytest.raises(NarrativeValidationError, match="contract") as error:
        validate_model_response(output, derive_narrative_facts(TOTALS))

    assert output not in "".join(format_exception(error.value))


def test_clean_facts_reject_caveat() -> None:
    with pytest.raises(NarrativeValidationError, match="quality warning"):
        validate_model_response(
            model_json(caveat="The source has a quality warning."),
            derive_narrative_facts(TOTALS),
        )


def test_nonclean_facts_allow_plain_text_caveat() -> None:
    clean = derive_narrative_facts(TOTALS)
    payload = clean.model_dump()
    payload["data_quality_flags"] = (DataQualityFlag.DUPLICATE_RECORDS,)
    facts = type(clean).model_validate(payload)

    template = validate_model_response(
        model_json(caveat="Duplicate source records were detected locally."),
        facts,
    )

    assert template.caveat == "Duplicate source records were detected locally."


def test_composer_renders_exact_table_and_substitutes_registered_values_locally() -> None:
    template = validate_model_response(model_json(), derive_narrative_facts(TOTALS))

    response = compose_user_response(TOTALS, template)

    assert response.startswith(render_monthly_table(TOTALS))
    assert "2025-07 | 8" in response
    assert "2026-06 | 18" in response
    assert "The strongest month reached 18 vehicle sales." in response
    assert "The period ended at 18 vehicle sales." in response
    assert "{{" not in response
    assert "}}" not in response


def test_composer_revalidates_before_replacing() -> None:
    unvalidated = NarrativeTemplate(
        headline="Unsafe template",
        observations=("Use {{UNKNOWN_TOTAL}} here.",),
    )

    with pytest.raises(NarrativeValidationError, match="unknown placeholder"):
        compose_user_response(TOTALS, unvalidated)


def test_local_fallback_is_deterministic_and_explicitly_local() -> None:
    first = compose_local_fallback(TOTALS)
    second = compose_local_fallback(TOTALS)

    assert first == second
    assert "LOCAL FALLBACK NARRATIVE" in first
    assert "LLM" not in first
    assert "2026-06 | 18" in first
