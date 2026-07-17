"""Closed qualitative contracts permitted at the automotive model boundary."""

from __future__ import annotations

from datetime import date
from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, model_validator


class Direction(StrEnum):
    UP = "UP"
    DOWN = "DOWN"
    FLAT = "FLAT"


class Volatility(StrEnum):
    LOW = "LOW"
    MODERATE = "MODERATE"
    HIGH = "HIGH"


class Trend(StrEnum):
    GROWING = "GROWING"
    DECLINING = "DECLINING"
    MIXED = "MIXED"


class DataQualityFlag(StrEnum):
    NONE = "NONE"
    MISSING_MONTH = "MISSING_MONTH"
    DUPLICATE_RECORDS = "DUPLICATE_RECORDS"


class Placeholder(StrEnum):
    PEAK_MONTH_TOTAL = "{{PEAK_MONTH_TOTAL}}"
    TROUGH_MONTH_TOTAL = "{{TROUGH_MONTH_TOTAL}}"
    PERIOD_START_TOTAL = "{{PERIOD_START_TOTAL}}"
    PERIOD_END_TOTAL = "{{PERIOD_END_TOTAL}}"


# Compatibility names used by the approved design document.
VolatilityBand = Volatility
OverallTrend = Trend

MonthlyDirections = tuple[
    Direction,
    Direction,
    Direction,
    Direction,
    Direction,
    Direction,
    Direction,
    Direction,
    Direction,
    Direction,
    Direction,
]
QuarterDirections = tuple[Direction, Direction, Direction]
QualityFlags = Annotated[tuple[DataQualityFlag, ...], Field(min_length=1, max_length=2)]
AllowedPlaceholders = Annotated[tuple[Placeholder, ...], Field(min_length=1, max_length=4)]


def _parse_month(value: str) -> date:
    if len(value) != 7 or value[4] != "-":
        raise ValueError("month must use YYYY-MM")
    try:
        return date(int(value[:4]), int(value[5:]), 1)
    except (TypeError, ValueError):
        raise ValueError("month must use YYYY-MM") from None


def _month_number(value: date) -> int:
    return value.year * 12 + value.month - 1


class AutomotiveNarrativeFacts(BaseModel):
    """Immutable, extra-forbid facts containing no confidential exact measures."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    period_start: str
    period_end: str
    monthly_direction_sequence: MonthlyDirections
    peak_month: str
    trough_month: str
    quarter_direction_sequence: QuarterDirections
    volatility_band: Volatility
    overall_trend: Trend
    data_quality_flags: QualityFlags
    allowed_placeholders: AllowedPlaceholders

    @model_validator(mode="after")
    def validate_closed_period(self) -> AutomotiveNarrativeFacts:
        start = _parse_month(self.period_start)
        end = _parse_month(self.period_end)
        if _month_number(end) - _month_number(start) != 11:
            raise ValueError("period must contain twelve consecutive months")

        for label in (self.peak_month, self.trough_month):
            month = _parse_month(label)
            if not start <= month <= end:
                raise ValueError("peak and trough months must fall inside the period")

        flags = self.data_quality_flags
        if len(set(flags)) != len(flags):
            raise ValueError("data quality flags must be unique")
        if DataQualityFlag.NONE in flags and flags != (DataQualityFlag.NONE,):
            raise ValueError("NONE cannot be combined with another data quality flag")
        if len(set(self.allowed_placeholders)) != len(self.allowed_placeholders):
            raise ValueError("allowed placeholders must be unique")
        return self
