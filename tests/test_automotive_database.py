import runpy
import sqlite3
from collections import Counter
from collections.abc import Callable
from csv import DictReader
from datetime import date
from pathlib import Path
from typing import cast

import pytest

from fde_privacy.automotive.database import (
    MonthlyTotal,
    load_synthetic_database,
    query_monthly_sales,
)

EXPECTED = {
    "2025-07": 8,
    "2025-08": 10,
    "2025-09": 9,
    "2025-10": 12,
    "2025-11": 12,
    "2025-12": 15,
    "2026-01": 11,
    "2026-02": 10,
    "2026-03": 13,
    "2026-04": 14,
    "2026-05": 16,
    "2026-06": 18,
}

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CSV_PATH = PROJECT_ROOT / "data" / "synthetic_automotive_sales.csv"
GENERATOR = runpy.run_path(str(PROJECT_ROOT / "scripts" / "generate_synthetic_sales.py"))
SYNTHETIC_MARKER = cast(str, GENERATOR["SYNTHETIC_MARKER"])
generate = cast(Callable[[Path], int], GENERATOR["generate"])


def test_committed_fixture_is_explicitly_synthetic_and_has_fixed_distribution() -> None:
    with CSV_PATH.open(newline="", encoding="utf-8") as handle:
        rows = list(DictReader(handle))

    assert len(rows) == 148
    assert {row["synthetic_marker"] for row in rows} == {SYNTHETIC_MARKER}
    assert Counter(row["sale_date"][:7] for row in rows) == EXPECTED
    assert all(row["sale_id"].startswith("SYN-SALE-") for row in rows)
    assert all(row["vin_like"].startswith("SYNVIN") for row in rows)


def test_generator_is_deterministic(tmp_path: Path) -> None:
    first = tmp_path / "first.csv"
    second = tmp_path / "second.csv"

    assert generate(first) == 148
    assert generate(second) == 148

    assert first.read_bytes() == second.read_bytes()


def test_generator_refuses_to_overwrite_unrecognized_file(tmp_path: Path) -> None:
    output = tmp_path / "existing.csv"
    output.write_text("customer,secret\nreal,private\n", encoding="utf-8")

    with pytest.raises(ValueError, match="refusing to overwrite"):
        generate(output)

    assert output.read_text(encoding="utf-8") == "customer,secret\nreal,private\n"


def test_query_returns_previous_twelve_complete_months_in_order(tmp_path: Path) -> None:
    connection = load_synthetic_database(CSV_PATH, tmp_path / "sales.db")
    try:
        connection.execute(
            """INSERT INTO automotive_sales VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                SYNTHETIC_MARKER,
                "SYN-SALE-OUTSIDE",
                "2026-07-01",
                "SYN-DEALER-ONE",
                "SYN-REP-ONE",
                "SYN-CUSTOMER-ONE",
                "SYNVINOUTSIDE00001",
                "Fiction",
                "Example",
                1,
                1,
            ),
        )

        totals = query_monthly_sales(
            connection,
            as_of=date(2026, 7, 17),
            timezone="Australia/Sydney",
        )
    finally:
        connection.close()

    assert totals == tuple(MonthlyTotal(month, total) for month, total in EXPECTED.items())
    assert len(totals) == 12
    assert all(total.month != "2026-07" for total in totals)


def test_monthly_total_is_immutable() -> None:
    total = MonthlyTotal("2025-07", 8)

    with pytest.raises((AttributeError, TypeError)):
        total.total = 9  # type: ignore[misc]


def test_query_rejects_unknown_timezone() -> None:
    connection = sqlite3.connect(":memory:")
    try:
        with pytest.raises(ValueError, match="timezone"):
            query_monthly_sales(connection, as_of=date(2026, 7, 17), timezone="Mars/Base")
    finally:
        connection.close()
