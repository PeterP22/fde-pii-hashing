"""End-to-end proof that exact automotive values remain in first-party code."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import date
from pathlib import Path

from fde_privacy.automotive.analytics import derive_narrative_facts
from fde_privacy.automotive.contracts import AutomotiveNarrativeFacts
from fde_privacy.automotive.database import load_synthetic_database, query_monthly_sales
from fde_privacy.automotive.narrative import (
    compose_local_fallback,
    compose_user_response,
    render_monthly_table,
    validate_model_response,
)
from fde_privacy.boundary import SystemPromptId, build_safe_request
from fde_privacy.contracts import NarrativeTemplate
from fde_privacy.model_adapters import CapturingMockAdapter, ModelAdapter

_SAFE_TEXT = (
    "Write a concise narrative from the approved qualitative automotive facts. "
    "Use only requested placeholders."
)
_DEFAULT_MODEL_OUTPUT = json.dumps(
    {
        "headline": "Sales strengthened across the period",
        "observations": [
            "The strongest month reached {{PEAK_MONTH_TOTAL}} vehicle sales.",
            "The period ended at {{PERIOD_END_TOTAL}} vehicle sales.",
        ],
        "caveat": None,
    }
)


@dataclass(frozen=True, slots=True)
class AutomotiveDemoResult:
    """The four inspectable trust-boundary stages plus sanitized outcome metadata."""

    local_database_result: str | None
    local_facts: AutomotiveNarrativeFacts | None
    model_facing_payload: str | None
    final_response: str | None
    model_narrative: NarrativeTemplate | None
    error: str | None = None
    used_local_fallback: bool = False


def _default_csv_path() -> Path:
    return Path(__file__).resolve().parents[2] / "data" / "synthetic_automotive_sales.csv"


def run_automotive_demo(
    adapter: ModelAdapter | None = None,
    *,
    csv_path: str | Path | None = None,
    db_path: str | Path = ":memory:",
    as_of: date = date(2026, 7, 17),
    timezone: str = "Australia/Sydney",
) -> AutomotiveDemoResult:
    """Run local query, minimization, model templating, and local exact composition."""

    model_adapter = (
        CapturingMockAdapter(response=_DEFAULT_MODEL_OUTPUT) if adapter is None else adapter
    )
    source = _default_csv_path() if csv_path is None else Path(csv_path)
    connection: sqlite3.Connection | None = None
    try:
        connection = load_synthetic_database(source, db_path)
        monthly_totals = query_monthly_sales(
            connection,
            as_of=as_of,
            timezone=timezone,
        )
        local_database_result = render_monthly_table(monthly_totals)
        facts = derive_narrative_facts(monthly_totals)
    except Exception:
        return AutomotiveDemoResult(
            local_database_result=None,
            local_facts=None,
            model_facing_payload=None,
            final_response=None,
            model_narrative=None,
            error="local database processing failed",
        )
    finally:
        if connection is not None:
            connection.close()

    try:
        request = build_safe_request(
            safe_text=_SAFE_TEXT,
            system_prompt_id=SystemPromptId.AUTOMOTIVE_NARRATIVE,
            automotive_facts=facts,
            forbidden_exact_values=tuple(item.total for item in monthly_totals),
        )
    except Exception:
        return AutomotiveDemoResult(
            local_database_result=local_database_result,
            local_facts=facts,
            model_facing_payload=None,
            final_response=compose_local_fallback(monthly_totals),
            model_narrative=None,
            error="model boundary processing failed",
            used_local_fallback=True,
        )

    payload = request.model_dump_json()
    try:
        model_output = model_adapter.complete(request)
        template = validate_model_response(model_output, facts)
        final_response = compose_user_response(monthly_totals, template)
    except Exception:
        return AutomotiveDemoResult(
            local_database_result=local_database_result,
            local_facts=facts,
            model_facing_payload=payload,
            final_response=compose_local_fallback(monthly_totals),
            model_narrative=None,
            error="model narrative unavailable",
            used_local_fallback=True,
        )

    return AutomotiveDemoResult(
        local_database_result=local_database_result,
        local_facts=facts,
        model_facing_payload=payload,
        final_response=final_response,
        model_narrative=template,
    )


def format_demo_stages(result: AutomotiveDemoResult) -> str:
    """Format the four required stages without exposing exception detail."""

    local_result = result.local_database_result or "Unavailable"
    local_facts = (
        "Unavailable" if result.local_facts is None else result.local_facts.model_dump_json(indent=2)
    )
    payload = result.model_facing_payload or "Unavailable"
    final_response = result.final_response or "Unavailable"
    return (
        f"LOCAL DATABASE RESULT\n{local_result}\n\n"
        f"LOCAL DERIVED FACTS\n{local_facts}\n\n"
        f"MODEL-FACING PAYLOAD\n{payload}\n\n"
        f"FINAL FIRST-PARTY RESPONSE\n{final_response}"
    )


def main() -> None:
    """Run the key-free in-memory demonstration."""

    print(format_demo_stages(run_automotive_demo()))


if __name__ == "__main__":
    main()
