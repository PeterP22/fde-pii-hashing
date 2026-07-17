"""First-party loading and aggregation for the synthetic automotive fixture."""

from __future__ import annotations

import csv
import sqlite3
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Final
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

_SYNTHETIC_MARKER: Final = "SYNTHETIC_FICTIONAL_DATA"
_FIELDNAMES: Final = (
    "synthetic_marker",
    "sale_id",
    "sale_date",
    "dealer_id",
    "salesperson_id",
    "customer_id",
    "vin_like",
    "make",
    "model",
    "sale_price",
    "margin",
)

_CREATE_TABLE: Final = """
CREATE TABLE automotive_sales (
    synthetic_marker TEXT NOT NULL,
    sale_id TEXT PRIMARY KEY,
    sale_date TEXT NOT NULL,
    dealer_id TEXT NOT NULL,
    salesperson_id TEXT NOT NULL,
    customer_id TEXT NOT NULL,
    vin_like TEXT NOT NULL,
    make TEXT NOT NULL,
    model TEXT NOT NULL,
    sale_price INTEGER NOT NULL,
    margin INTEGER NOT NULL
)
"""
_INSERT_ROW: Final = """
INSERT INTO automotive_sales (
    synthetic_marker, sale_id, sale_date, dealer_id, salesperson_id,
    customer_id, vin_like, make, model, sale_price, margin
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""
_MONTHLY_QUERY: Final = """
SELECT substr(sale_date, 1, 7) AS month, count(*) AS total
FROM automotive_sales
WHERE sale_date >= ? AND sale_date < ?
GROUP BY substr(sale_date, 1, 7)
ORDER BY month
"""


@dataclass(frozen=True, slots=True)
class MonthlyTotal:
    """An immutable local exact monthly unit total."""

    month: str
    total: int


def load_synthetic_database(csv_path: str | Path, db_path: str | Path) -> sqlite3.Connection:
    """Load the explicitly marked fictional CSV into a fresh local SQLite table."""

    source = Path(csv_path)
    database = str(db_path)
    if database != ":memory:":
        Path(database).parent.mkdir(parents=True, exist_ok=True)

    rows: list[tuple[str, str, str, str, str, str, str, str, str, int, int]] = []
    with source.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        if tuple(reader.fieldnames or ()) != _FIELDNAMES:
            raise ValueError("synthetic CSV format is invalid")
        for row in reader:
            if row["synthetic_marker"] != _SYNTHETIC_MARKER:
                raise ValueError("CSV contains a row without the synthetic marker")
            rows.append(
                (
                    row["synthetic_marker"],
                    row["sale_id"],
                    row["sale_date"],
                    row["dealer_id"],
                    row["salesperson_id"],
                    row["customer_id"],
                    row["vin_like"],
                    row["make"],
                    row["model"],
                    int(row["sale_price"]),
                    int(row["margin"]),
                )
            )

    connection = sqlite3.connect(database)
    try:
        with connection:
            connection.execute("DROP TABLE IF EXISTS automotive_sales")
            connection.execute(_CREATE_TABLE)
            connection.executemany(_INSERT_ROW, rows)
    except Exception:
        connection.close()
        raise
    return connection


def _shift_month(value: date, delta: int) -> date:
    absolute_month = value.year * 12 + value.month - 1 + delta
    return date(absolute_month // 12, absolute_month % 12 + 1, 1)


def query_monthly_sales(
    connection: sqlite3.Connection,
    *,
    as_of: date = date(2026, 7, 17),
    timezone: str = "Australia/Sydney",
) -> tuple[MonthlyTotal, ...]:
    """Return ordered totals for the twelve complete months before ``as_of``."""

    try:
        ZoneInfo(timezone)
    except (ZoneInfoNotFoundError, ValueError, TypeError):
        raise ValueError("timezone is invalid") from None
    if not isinstance(as_of, date):
        raise TypeError("as_of must be a date")

    current_month = date(as_of.year, as_of.month, 1)
    period_start = _shift_month(current_month, -12)
    cursor = connection.execute(
        _MONTHLY_QUERY,
        (period_start.isoformat(), current_month.isoformat()),
    )
    return tuple(MonthlyTotal(str(month), int(total)) for month, total in cursor.fetchall())
