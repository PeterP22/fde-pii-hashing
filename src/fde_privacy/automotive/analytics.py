"""Derive a minimal qualitative automotive fact set entirely in first-party code."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import date
from statistics import mean, pstdev
from typing import cast

from fde_privacy.automotive.contracts import (
    AutomotiveNarrativeFacts,
    DataQualityFlag,
    Direction,
    MonthlyDirections,
    Placeholder,
    QuarterDirections,
    Trend,
    Volatility,
)
from fde_privacy.automotive.database import MonthlyTotal


class IncompletePeriodError(ValueError):
    """Raised when exact input cannot prove a complete twelve-month period."""


def _direction(previous: int, current: int) -> Direction:
    if current > previous:
        return Direction.UP
    if current < previous:
        return Direction.DOWN
    return Direction.FLAT


def _parse_month(value: str) -> date:
    try:
        if len(value) != 7 or value[4] != "-":
            raise ValueError
        return date(int(value[:4]), int(value[5:]), 1)
    except (TypeError, ValueError):
        raise IncompletePeriodError("input is not a complete twelve-month period") from None


def _month_number(value: date) -> int:
    return value.year * 12 + value.month - 1


def _validate_period(monthly_totals: Sequence[MonthlyTotal]) -> tuple[MonthlyTotal, ...]:
    totals = tuple(monthly_totals)
    if len(totals) != 12 or any(type(item) is not MonthlyTotal for item in totals):
        raise IncompletePeriodError("input is not a complete twelve-month period")
    months = tuple(_parse_month(item.month) for item in totals)
    if len(set(months)) != 12:
        raise IncompletePeriodError("input is not a complete twelve-month period")
    first = _month_number(months[0])
    if tuple(_month_number(month) for month in months) != tuple(range(first, first + 12)):
        raise IncompletePeriodError("input is not a complete twelve-month period")
    if any(type(item.total) is not int or item.total < 0 for item in totals):
        raise IncompletePeriodError("input is not a complete twelve-month period")
    return totals


def _volatility(values: tuple[int, ...]) -> Volatility:
    average = mean(values)
    coefficient = 0.0 if average == 0 else pstdev(values) / average
    if coefficient < 0.10:
        return Volatility.LOW
    if coefficient < 0.25:
        return Volatility.MODERATE
    return Volatility.HIGH


def _trend(values: tuple[int, ...]) -> Trend:
    first_mean = mean(values[:3])
    final_mean = mean(values[-3:])
    if first_mean == 0:
        change = 0.0 if final_mean == 0 else float("inf")
    else:
        change = (final_mean - first_mean) / first_mean
    if change > 0.05:
        return Trend.GROWING
    if change < -0.05:
        return Trend.DECLINING
    return Trend.MIXED


def derive_narrative_facts(
    monthly_totals: Sequence[MonthlyTotal],
) -> AutomotiveNarrativeFacts:
    """Convert exact local totals to the closed model-facing qualitative schema."""

    totals = _validate_period(monthly_totals)
    values = tuple(item.total for item in totals)
    monthly_directions = cast(
        MonthlyDirections,
        tuple(
            _direction(previous, current)
            for previous, current in zip(values, values[1:], strict=False)
        ),
    )
    quarterly_values = tuple(sum(values[index : index + 3]) for index in range(0, 12, 3))
    quarter_directions = cast(
        QuarterDirections,
        tuple(
            _direction(previous, current)
            for previous, current in zip(
                quarterly_values, quarterly_values[1:], strict=False
            )
        ),
    )

    return AutomotiveNarrativeFacts(
        period_start=totals[0].month,
        period_end=totals[-1].month,
        monthly_direction_sequence=monthly_directions,
        peak_month=max(totals, key=lambda item: item.total).month,
        trough_month=min(totals, key=lambda item: item.total).month,
        quarter_direction_sequence=quarter_directions,
        volatility_band=_volatility(values),
        overall_trend=_trend(values),
        data_quality_flags=(DataQualityFlag.NONE,),
        allowed_placeholders=tuple(Placeholder),
    )
