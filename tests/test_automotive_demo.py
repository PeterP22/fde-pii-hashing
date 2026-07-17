import csv
import json
from datetime import date
from pathlib import Path

import pytest

import fde_privacy.automotive_demo as demo_module
from fde_privacy.automotive_demo import format_demo_stages, run_automotive_demo
from fde_privacy.model_adapters import CapturingMockAdapter

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CSV_PATH = PROJECT_ROOT / "data" / "synthetic_automotive_sales.csv"
MODEL_OUTPUT = json.dumps(
    {
        "headline": "Sales strengthened across the period",
        "observations": [
            "The strongest month reached {{PEAK_MONTH_TOTAL}} vehicle sales.",
            "The period ended at {{PERIOD_END_TOTAL}} vehicle sales.",
        ],
        "caveat": None,
    }
)
EXACT_TOTALS = (8, 10, 9, 12, 12, 15, 11, 10, 13, 14, 16, 18)


def test_demo_keeps_exact_values_local_and_returns_useful_narrative() -> None:
    adapter = CapturingMockAdapter(response=MODEL_OUTPUT)

    result = run_automotive_demo(
        adapter,
        csv_path=CSV_PATH,
        as_of=date(2026, 7, 17),
        timezone="Australia/Sydney",
    )

    assert result.error is None
    assert result.local_database_result is not None
    assert result.local_facts is not None
    assert result.model_facing_payload is not None
    assert result.model_narrative is not None
    assert result.final_response is not None
    assert adapter.last_payload == result.model_facing_payload
    assert "2025-07 | 8" in result.local_database_result
    assert "2026-06 | 18" in result.local_database_result
    assert "The strongest month reached 18 vehicle sales." in result.final_response
    assert "The period ended at 18 vehicle sales." in result.final_response

    payload = result.model_facing_payload
    parsed = json.loads(payload)
    assert set(parsed) == {"system_instruction", "safe_text", "automotive_facts"}
    assert parsed["automotive_facts"] == result.local_facts.model_dump(mode="json")
    assert not _contains_exact_numeric_value(parsed, set(EXACT_TOTALS))

    with CSV_PATH.open(newline="", encoding="utf-8") as handle:
        first_row = next(csv.DictReader(handle))
    for forbidden in (
        first_row["sale_id"],
        first_row["dealer_id"],
        first_row["salesperson_id"],
        first_row["customer_id"],
        first_row["vin_like"],
        first_row["sale_price"],
        first_row["margin"],
        "SELECT substr(sale_date",
        "192.168.1.44",
        "db.internal",
        str(CSV_PATH),
    ):
        assert forbidden not in payload
    for forbidden_word in (
        "sale_id",
        "dealer_id",
        "salesperson_id",
        "customer_id",
        "vin_like",
        "sale_price",
        "margin",
        "sql",
        "rows",
    ):
        assert forbidden_word not in payload.casefold()


def _contains_exact_numeric_value(value: object, forbidden: set[int]) -> bool:
    if type(value) is int:
        return value in forbidden
    if isinstance(value, dict):
        return any(_contains_exact_numeric_value(item, forbidden) for item in value.values())
    if isinstance(value, list):
        return any(_contains_exact_numeric_value(item, forbidden) for item in value)
    return False


def test_formatted_stages_put_exact_totals_only_in_first_and_fourth_stages() -> None:
    result = run_automotive_demo(CapturingMockAdapter(response=MODEL_OUTPUT), csv_path=CSV_PATH)

    formatted = format_demo_stages(result)
    local_result, remainder = formatted.split("\n\nLOCAL DERIVED FACTS\n", 1)
    local_facts, remainder = remainder.split("\n\nMODEL-FACING PAYLOAD\n", 1)
    payload, final = remainder.split("\n\nFINAL FIRST-PARTY RESPONSE\n", 1)

    assert local_result.startswith("LOCAL DATABASE RESULT\n")
    assert "2025-07 | 8" in local_result
    assert "2026-06 | 18" in local_result
    assert " | 8" not in local_facts
    assert " | 18" not in local_facts
    assert " | 8" not in payload
    assert " | 18" not in payload
    assert "2025-07 | 8" in final
    assert "2026-06 | 18" in final


def test_database_failure_never_calls_model_or_returns_model_narrative(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adapter = CapturingMockAdapter(response=MODEL_OUTPUT)

    def fail_query(*args: object, **kwargs: object) -> object:
        raise RuntimeError("private database details")

    monkeypatch.setattr(demo_module, "query_monthly_sales", fail_query)

    result = run_automotive_demo(adapter, csv_path=CSV_PATH)

    assert adapter.last_payload is None
    assert result.model_narrative is None
    assert result.model_facing_payload is None
    assert result.final_response is None
    assert result.error == "local database processing failed"
    assert "private database details" not in repr(result)


def test_model_failure_returns_explicit_local_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    adapter = CapturingMockAdapter(response=MODEL_OUTPUT)

    def fail_completion(request: object) -> str:
        raise RuntimeError("provider secret")

    monkeypatch.setattr(adapter, "complete", fail_completion)

    result = run_automotive_demo(adapter, csv_path=CSV_PATH)

    assert result.model_narrative is None
    assert result.used_local_fallback is True
    assert result.final_response is not None
    assert "LOCAL FALLBACK NARRATIVE" in result.final_response
    assert "provider secret" not in repr(result)
