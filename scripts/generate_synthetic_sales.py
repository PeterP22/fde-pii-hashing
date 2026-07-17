"""Generate a deterministic, explicitly synthetic automotive-sales fixture."""

from __future__ import annotations

import argparse
import csv
import random
from datetime import date
from pathlib import Path
from typing import Final

SEED: Final = 20260717
SYNTHETIC_MARKER: Final = "SYNTHETIC_FICTIONAL_DATA"
MONTHLY_COUNTS: Final[tuple[tuple[str, int], ...]] = (
    ("2025-07", 8),
    ("2025-08", 10),
    ("2025-09", 9),
    ("2025-10", 12),
    ("2025-11", 12),
    ("2025-12", 15),
    ("2026-01", 11),
    ("2026-02", 10),
    ("2026-03", 13),
    ("2026-04", 14),
    ("2026-05", 16),
    ("2026-06", 18),
)
FIELDNAMES: Final[tuple[str, ...]] = (
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

_DEALERS: Final = ("SYN-DEALER-NORTH", "SYN-DEALER-CENTRAL", "SYN-DEALER-COAST")
_SALESPEOPLE: Final = tuple(f"SYN-REP-{number:02d}" for number in range(1, 9))
_MAKES_AND_MODELS: Final = (
    ("Fiction Motors", "Comet"),
    ("Example Automotive", "Harbour"),
    ("Imaginary Vehicles", "Wattle"),
    ("Sample Mobility", "Banksia"),
)


def _default_output() -> Path:
    return Path(__file__).resolve().parents[1] / "data" / "synthetic_automotive_sales.csv"


def _recognized_generated_file(path: Path) -> bool:
    try:
        with path.open(newline="", encoding="utf-8") as handle:
            reader = csv.DictReader(handle)
            if tuple(reader.fieldnames or ()) != FIELDNAMES:
                return False
            return all(row.get("synthetic_marker") == SYNTHETIC_MARKER for row in reader)
    except (OSError, csv.Error, UnicodeError):
        return False


def _days_in_month(year: int, month: int) -> int:
    if month == 12:
        following = date(year + 1, 1, 1)
    else:
        following = date(year, month + 1, 1)
    return (following - date(year, month, 1)).days


def generate(output_path: str | Path | None = None) -> int:
    """Write the owned fixture and return its deterministic row count."""

    output = _default_output() if output_path is None else Path(output_path)
    if output.exists() and not _recognized_generated_file(output):
        raise ValueError("refusing to overwrite a file not recognized as generated synthetic data")

    rng = random.Random(SEED)
    output.parent.mkdir(parents=True, exist_ok=True)
    row_number = 0
    with output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDNAMES)
        writer.writeheader()
        for month_label, count in MONTHLY_COUNTS:
            year, month = (int(part) for part in month_label.split("-"))
            for _ in range(count):
                row_number += 1
                day = rng.randint(1, _days_in_month(year, month))
                sale_price = rng.randrange(28_000, 86_001, 500)
                make, model = rng.choice(_MAKES_AND_MODELS)
                writer.writerow(
                    {
                        "synthetic_marker": SYNTHETIC_MARKER,
                        "sale_id": f"SYN-SALE-{row_number:04d}",
                        "sale_date": date(year, month, day).isoformat(),
                        "dealer_id": rng.choice(_DEALERS),
                        "salesperson_id": rng.choice(_SALESPEOPLE),
                        "customer_id": f"SYN-CUSTOMER-{row_number:04d}",
                        "vin_like": f"SYNVIN{row_number:011d}",
                        "make": make,
                        "model": model,
                        "sale_price": sale_price,
                        "margin": rng.randrange(1_500, 9_001, 250),
                    }
                )
    return row_number


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", nargs="?", type=Path, default=_default_output())
    args = parser.parse_args()
    count = generate(args.output)
    print(f"Wrote {count} explicitly synthetic fictional rows to {args.output}")


if __name__ == "__main__":
    main()
