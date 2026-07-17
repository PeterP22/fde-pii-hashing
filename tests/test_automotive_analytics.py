from typing import Any

import pytest
from pydantic import ValidationError

from fde_privacy.automotive.analytics import IncompletePeriodError, derive_narrative_facts
from fde_privacy.automotive.contracts import (
    AutomotiveNarrativeFacts,
    DataQualityFlag,
    Direction,
    Placeholder,
    Trend,
    Volatility,
)
from fde_privacy.automotive.database import MonthlyTotal
from fde_privacy.contracts import SafeModelRequest

FIXED_TOTALS = (
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


def valid_payload() -> dict[str, Any]:
    return {
        "period_start": "2025-07",
        "period_end": "2026-06",
        "monthly_direction_sequence": (
            Direction.UP,
            Direction.DOWN,
            Direction.UP,
            Direction.FLAT,
            Direction.UP,
            Direction.DOWN,
            Direction.DOWN,
            Direction.UP,
            Direction.UP,
            Direction.UP,
            Direction.UP,
        ),
        "peak_month": "2026-06",
        "trough_month": "2025-07",
        "quarter_direction_sequence": (Direction.UP, Direction.DOWN, Direction.UP),
        "volatility_band": Volatility.MODERATE,
        "overall_trend": Trend.GROWING,
        "data_quality_flags": (DataQualityFlag.NONE,),
        "allowed_placeholders": tuple(Placeholder),
    }


def test_fixed_totals_derive_only_closed_qualitative_facts() -> None:
    facts = derive_narrative_facts(FIXED_TOTALS)

    assert facts.period_start == "2025-07"
    assert facts.period_end == "2026-06"
    assert facts.monthly_direction_sequence == (
        Direction.UP,
        Direction.DOWN,
        Direction.UP,
        Direction.FLAT,
        Direction.UP,
        Direction.DOWN,
        Direction.DOWN,
        Direction.UP,
        Direction.UP,
        Direction.UP,
        Direction.UP,
    )
    assert facts.quarter_direction_sequence == (
        Direction.UP,
        Direction.DOWN,
        Direction.UP,
    )
    assert facts.peak_month == "2026-06"
    assert facts.trough_month == "2025-07"
    assert facts.volatility_band is Volatility.MODERATE
    assert facts.overall_trend is Trend.GROWING
    assert facts.data_quality_flags == (DataQualityFlag.NONE,)
    assert facts.allowed_placeholders == tuple(Placeholder)

    serialized = facts.model_dump_json()
    for forbidden_field in (
        '"total"',
        "percent",
        "revenue",
        "margin",
        "sale_id",
        "dealer_id",
        "customer_id",
        "salesperson_id",
        "rows",
    ):
        assert forbidden_field not in serialized


def test_facts_are_frozen_and_forbid_extra_fields() -> None:
    facts = AutomotiveNarrativeFacts.model_validate(valid_payload())

    with pytest.raises(ValidationError):
        facts.period_start = "2025-08"
    with pytest.raises(ValidationError):
        AutomotiveNarrativeFacts.model_validate({**valid_payload(), "total": 148})


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("monthly_direction_sequence", (Direction.UP,) * 10),
        ("monthly_direction_sequence", (Direction.UP,) * 12),
        ("quarter_direction_sequence", (Direction.UP,) * 2),
        ("quarter_direction_sequence", (Direction.UP,) * 4),
    ],
)
def test_facts_require_exact_direction_lengths(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        AutomotiveNarrativeFacts.model_validate({**valid_payload(), field: value})


@pytest.mark.parametrize(
    "updates",
    [
        {"period_start": "2025-13"},
        {"period_start": "2025-08"},
        {"peak_month": "2026-07"},
        {"trough_month": "2025-06"},
    ],
)
def test_facts_require_valid_twelve_month_period_and_months_inside_it(
    updates: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        AutomotiveNarrativeFacts.model_validate({**valid_payload(), **updates})


def test_none_quality_flag_cannot_be_combined() -> None:
    with pytest.raises(ValidationError):
        AutomotiveNarrativeFacts.model_validate(
            {
                **valid_payload(),
                "data_quality_flags": (
                    DataQualityFlag.NONE,
                    DataQualityFlag.DUPLICATE_RECORDS,
                ),
            }
        )


def test_missing_month_raises_without_producing_facts() -> None:
    with pytest.raises(IncompletePeriodError, match="complete twelve-month period"):
        derive_narrative_facts(FIXED_TOTALS[:4] + FIXED_TOTALS[5:])


def test_thresholds_use_strict_low_and_moderate_cv_boundaries() -> None:
    low = derive_narrative_facts(
        tuple(MonthlyTotal(f"2025-{month:02d}", 10) for month in range(1, 13))
    )
    high = derive_narrative_facts(
        tuple(
            MonthlyTotal(f"2025-{month:02d}", total)
            for month, total in enumerate((1, 1, 1, 1, 1, 1, 9, 9, 9, 9, 9, 9), 1)
        )
    )

    assert low.volatility_band is Volatility.LOW
    assert low.overall_trend is Trend.MIXED
    assert high.volatility_band is Volatility.HIGH
    assert high.overall_trend is Trend.GROWING


def test_safe_model_request_accepts_typed_facts_directly() -> None:
    facts = derive_narrative_facts(FIXED_TOTALS)

    request = SafeModelRequest(
        system_instruction="Use approved qualitative facts only",
        safe_text="Describe the sales pattern qualitatively.",
        automotive_facts=facts,
    )

    assert request.automotive_facts is facts
