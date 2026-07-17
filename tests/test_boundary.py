from decimal import Decimal
from inspect import signature
from time import perf_counter
from traceback import format_exception

import pytest
from pydantic import ValidationError

import fde_privacy.boundary as boundary_module
from fde_privacy.boundary import BoundaryViolation, SystemPromptId, build_safe_request
from fde_privacy.contracts import SafeModelRequest
from fde_privacy.detector import DetectedEntity
from fde_privacy.model_adapters import CapturingMockAdapter, ModelAdapter

SAFE_HASH = "a" * 20 + "12345" + "a" * 39
SAFE_TOKEN = "{{EMAIL_ADDRESS:123456789012345678901234}}"
DATABASE_FILE_PROBES = (
    "customer.db",
    "customer.sqlite",
    "customer.sqlite3",
    "data/customer.db",
    "data/customer.sqlite",
    r"data\customer.sqlite3",
    "<PERSON>_customer.db",
    "<PERSON>_data/customer.sqlite3",
    r"<PERSON>_data\customer.sqlite",
)


def safe_request_text() -> str:
    return (
        f"Customer {SAFE_TOKEN} had identifier {SAFE_HASH}; "
        "contact is <PHONE_NUMBER>. The vehicle needs routine service."
    )


def test_safe_text_length_limit_accepts_exactly_twenty_thousand_and_rejects_one_over(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    detector_inputs: list[str] = []

    def record_detector_input(value: str) -> tuple[DetectedEntity, ...]:
        detector_inputs.append(value)
        return ()

    monkeypatch.setattr(boundary_module, "detect_pii", record_detector_input)
    at_limit = "z" * 20_000
    over_limit = "z" * 20_001

    request = build_safe_request(
        safe_text=at_limit,
        system_prompt_id=SystemPromptId.PII_SUMMARY,
    )

    assert request.safe_text == at_limit
    assert detector_inputs == [at_limit, at_limit]

    with pytest.raises(BoundaryViolation, match="maximum length") as error:
        build_safe_request(
            safe_text=over_limit,
            system_prompt_id=SystemPromptId.PII_SUMMARY,
        )

    assert detector_inputs == [at_limit, at_limit]
    assert over_limit not in "".join(format_exception(error.value))


def test_long_nonmatching_slash_input_has_bounded_database_scan_time() -> None:
    text = "segment/" * 2_000 + "terminal.txt"

    started_at = perf_counter()
    violation = boundary_module._find_manual_violation(text)
    elapsed = perf_counter() - started_at

    assert violation is None
    assert elapsed < 0.5


def test_build_safe_request_accepts_representative_composed_output() -> None:
    request = build_safe_request(
        safe_text=safe_request_text(),
        system_prompt_id=SystemPromptId.PII_SUMMARY,
        automotive_facts=None,
        forbidden_exact_values=(12345, 2025),
    )

    assert isinstance(request, SafeModelRequest)
    assert request.safe_text == safe_request_text()
    assert request.automotive_facts is None
    assert request.system_instruction
    assert "12345" not in request.system_instruction


@pytest.mark.parametrize(
    ("unsafe_text", "category"),
    [
        ("Email alice@example.com about the vehicle.", "EMAIL_ADDRESS"),
        ("Call the customer on 0400 123 456.", "PHONE_NUMBER"),
        ("Customer CUST-123456 needs a summary.", "CUSTOMER_ID"),
        ("Charge card 4111 1111 1111 1111.", "CREDIT_CARD"),
        ("The internal address is 192.168.10.44.", "private network address"),
        ("Connect with postgresql://admin:secret@db.internal/app.", "database location"),
        ("Read /var/lib/postgresql/customer.db for details.", "database location"),
        ("Pass database_url to the model.", "database_url"),
        ("The connection uses host and port.", "host"),
        ("Return the SQL rows.", "sql"),
    ],
)
def test_build_safe_request_rejects_leakage_without_echoing_it(
    unsafe_text: str, category: str
) -> None:
    with pytest.raises(BoundaryViolation) as error:
        build_safe_request(
            safe_text=unsafe_text,
            system_prompt_id=SystemPromptId.PII_SUMMARY,
        )

    formatted = "".join(format_exception(error.value))
    assert category in str(error.value)
    assert unsafe_text not in formatted
    for secret in ("alice@example.com", "192.168.10.44", "admin:secret", "4111 1111"):
        assert secret not in formatted
    assert error.value.__cause__ is None
    assert error.value.__context__ is None


@pytest.mark.parametrize(
    ("unsafe_text", "category"),
    [
        ("<PERSON>_postgresql://db/app", "database location"),
        ("<PERSON>_/var/lib/postgresql/customer.db", "database location"),
        (r"<PERSON>_C:\data\customer.db", "database location"),
        ("<PERSON>_database_url", "database_url"),
        ("<PERSON>_host", "host"),
        ("<PERSON>_sql", "sql"),
        ("<PERSON>_rows", "rows"),
    ],
)
def test_database_checks_reject_underscore_adjacency_after_protected_atom(
    unsafe_text: str, category: str
) -> None:
    with pytest.raises(BoundaryViolation, match=category) as error:
        build_safe_request(
            safe_text=unsafe_text,
            system_prompt_id=SystemPromptId.PII_SUMMARY,
        )

    assert unsafe_text not in "".join(format_exception(error.value))


@pytest.mark.parametrize(
    "unsafe_value",
    [
        "<PERSON>_postgresql://db/app",
        "<PERSON>_/var/lib/postgresql/customer.db",
        r"<PERSON>_C:\data\customer.db",
        "<PERSON>_database_url",
        "<PERSON>_host",
        "<PERSON>_sql",
        "<PERSON>_rows",
    ],
)
def test_recursive_serialized_value_checks_use_same_database_boundaries(
    unsafe_value: str,
) -> None:
    assert boundary_module._inspect_serialized({"allowed": [{"content": unsafe_value}]}) is not None


@pytest.mark.parametrize("unsafe_path", DATABASE_FILE_PROBES)
def test_database_checks_reject_bare_and_relative_database_files(unsafe_path: str) -> None:
    with pytest.raises(BoundaryViolation, match="database location") as error:
        build_safe_request(
            safe_text=unsafe_path,
            system_prompt_id=SystemPromptId.PII_SUMMARY,
        )

    assert unsafe_path not in "".join(format_exception(error.value))


@pytest.mark.parametrize("unsafe_path", DATABASE_FILE_PROBES)
def test_recursive_checks_reject_bare_and_relative_database_files(unsafe_path: str) -> None:
    assert boundary_module._inspect_serialized({"allowed": [{"content": unsafe_path}]}) == (
        "category",
        "database location",
    )


def test_database_checks_do_not_match_substrings_inside_alphanumeric_words(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    text = (
        "ghost hostage airport transport database_urlish credentialsmith "
        "connection_strings nosql schemas browsing"
    )
    monkeypatch.setattr(boundary_module, "detect_pii", lambda _: ())

    request = build_safe_request(
        safe_text=text,
        system_prompt_id=SystemPromptId.PII_SUMMARY,
    )

    assert request.safe_text == text
    assert boundary_module._inspect_serialized({"allowed": [{"content": text}]}) is None


@pytest.mark.parametrize(
    "safe_text",
    [
        "customer.dbexample",
        "data/customer.sqlitebackup",
        r"data\customer.sqlite3example",
        "The customer discussed report.txt, image.jpeg, and archive.tar.gz.",
    ],
)
def test_database_file_checks_allow_extension_superstrings_and_unrelated_files(
    safe_text: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(boundary_module, "detect_pii", lambda _: ())

    request = build_safe_request(
        safe_text=safe_text,
        system_prompt_id=SystemPromptId.PII_SUMMARY,
    )

    assert request.safe_text == safe_text
    assert boundary_module._inspect_serialized({"allowed": [{"content": safe_text}]}) is None


@pytest.mark.parametrize(
    "safe_prefix",
    [
        "<EMAIL_ADDRESS>",
        SAFE_TOKEN,
        SAFE_HASH,
    ],
)
def test_protected_value_does_not_hide_adjacent_raw_sensitive_text(safe_prefix: str) -> None:
    raw_email = "alice@example.com"

    with pytest.raises(BoundaryViolation) as error:
        build_safe_request(
            safe_text=f"{safe_prefix}{raw_email}",
            system_prompt_id=SystemPromptId.PII_SUMMARY,
        )

    assert raw_email not in "".join(format_exception(error.value))


@pytest.mark.parametrize(
    "malformed_value",
    [
        "{{EMAIL_ADDRESS:short}}",
        "<email_address>",
        "A" * 64,
        "a" * 65,
    ],
)
def test_protected_looking_value_must_match_an_entire_repository_format(
    malformed_value: str,
) -> None:
    with pytest.raises(BoundaryViolation, match="protected value format") as error:
        build_safe_request(
            safe_text=f"Transformed value {malformed_value}.",
            system_prompt_id=SystemPromptId.PII_SUMMARY,
        )

    assert malformed_value not in "".join(format_exception(error.value))


def test_every_unprotected_presidio_detection_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        boundary_module,
        "detect_pii",
        lambda text: (DetectedEntity("UNRECOGNIZED_SECRET", 0, len(text), 0.01),),
    )

    with pytest.raises(BoundaryViolation, match="UNRECOGNIZED_SECRET"):
        build_safe_request(
            safe_text="ordinary words",
            system_prompt_id=SystemPromptId.PII_SUMMARY,
        )


def test_detector_iteration_failure_is_sanitized(monkeypatch: pytest.MonkeyPatch) -> None:
    fictional_secret = "alice@example.com"

    class FailingDetections:
        def __iter__(self) -> object:
            raise RuntimeError(fictional_secret)

    monkeypatch.setattr(boundary_module, "detect_pii", lambda _: FailingDetections())

    with pytest.raises(BoundaryViolation, match="privacy detection failed") as error:
        build_safe_request(
            safe_text="ordinary words",
            system_prompt_id=SystemPromptId.PII_SUMMARY,
        )

    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    assert fictional_secret not in "".join(format_exception(error.value))


def test_invalid_detection_score_fails_with_a_sanitized_boundary_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fictional_secret = "alice@example.com"
    monkeypatch.setattr(
        boundary_module,
        "detect_pii",
        lambda text: (
            DetectedEntity(
                entity_type="EMAIL_ADDRESS",
                start=0,
                end=len(text),
                score=fictional_secret,  # type: ignore[arg-type]
            ),
        ),
    )

    with pytest.raises(BoundaryViolation, match="invalid category") as error:
        build_safe_request(
            safe_text="ordinary words",
            system_prompt_id=SystemPromptId.PII_SUMMARY,
        )

    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    assert fictional_secret not in "".join(format_exception(error.value))


def test_detection_wholly_inside_a_valid_repository_token_is_allowed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    text = f"Contact {SAFE_TOKEN}."
    start = text.index("123456")
    detector_inputs: list[str] = []

    def detect_token_then_nothing(value: str) -> tuple[DetectedEntity, ...]:
        detector_inputs.append(value)
        if len(detector_inputs) == 1:
            return (DetectedEntity("PHONE_NUMBER", start, start + 6, 0.2),)
        return ()

    monkeypatch.setattr(
        boundary_module,
        "detect_pii",
        detect_token_then_nothing,
    )

    request = build_safe_request(
        safe_text=text,
        system_prompt_id=SystemPromptId.PII_SUMMARY,
    )

    assert request.safe_text == text
    assert detector_inputs == [text, f"Contact {' ' * len(SAFE_TOKEN)}."]


def test_second_detector_pass_always_checks_outside_valid_protected_atoms(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw_tfn = "876 543 210"
    text = f"<PERSON> reference {raw_tfn}"
    tfn_start = text.index(raw_tfn)
    detector_inputs: list[str] = []

    def staged_detector(value: str) -> tuple[DetectedEntity, ...]:
        detector_inputs.append(value)
        if len(detector_inputs) == 1:
            return (DetectedEntity("PERSON", 1, 7, 0.95),)
        return (DetectedEntity("AU_TFN", tfn_start, tfn_start + len(raw_tfn), 1.0),)

    monkeypatch.setattr(boundary_module, "detect_pii", staged_detector)

    with pytest.raises(BoundaryViolation, match="AU_TFN") as error:
        build_safe_request(
            safe_text=text,
            system_prompt_id=SystemPromptId.PII_SUMMARY,
        )

    assert detector_inputs == [text, f"{' ' * len('<PERSON>')} reference {raw_tfn}"]
    assert raw_tfn not in "".join(format_exception(error.value))


def test_first_pass_detection_partially_overlapping_protected_atom_blocks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    text = "<PERSON>suffix"
    detector_inputs: list[str] = []

    def detect_partial_overlap(value: str) -> tuple[DetectedEntity, ...]:
        detector_inputs.append(value)
        return (DetectedEntity("PERSON", 1, len(text), 0.95),)

    monkeypatch.setattr(
        boundary_module,
        "detect_pii",
        detect_partial_overlap,
    )

    with pytest.raises(BoundaryViolation, match="PERSON"):
        build_safe_request(
            safe_text=text,
            system_prompt_id=SystemPromptId.PII_SUMMARY,
        )

    assert detector_inputs == [text]


def test_exact_confidential_value_is_checked_locally_but_not_serialized() -> None:
    confidential_total = 125000

    with pytest.raises(BoundaryViolation) as error:
        build_safe_request(
            safe_text="The confidential total is 125000.",
            system_prompt_id=SystemPromptId.PII_SUMMARY,
            forbidden_exact_values=(confidential_total,),
        )

    formatted = "".join(format_exception(error.value))
    assert str(confidential_total) not in formatted
    assert "exact confidential value" in str(error.value)


@pytest.mark.parametrize(
    ("forbidden_total", "formatted_total"),
    [
        (125000, "125000"),
        (125000, "125000.00"),
        (125000, "$125,000"),
        (125000, "$125,000.00"),
        (125000, "AUD 125,000"),
        (-125000, "-125000"),
        (-125000, "-125000.00"),
        (-125000, "-$125,000"),
        (-125000, "$-125,000.00"),
        (-125000, "AUD -125,000"),
        (-125000, "(125,000.00)"),
    ],
)
def test_numeric_exact_values_reject_equivalent_formatted_totals(
    forbidden_total: int,
    formatted_total: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(boundary_module, "detect_pii", lambda _: ())

    with pytest.raises(BoundaryViolation, match="exact confidential value") as error:
        build_safe_request(
            safe_text=f"The total is {formatted_total}.",
            system_prompt_id=SystemPromptId.PII_SUMMARY,
            forbidden_exact_values=(forbidden_total,),
        )

    assert formatted_total not in "".join(format_exception(error.value))


@pytest.mark.parametrize(
    "unmatched_total",
    [
        "125000)",
        "(125000",
        "$125,000)",
        "($125,000.00",
        "AUD 125,000)",
    ],
)
def test_numeric_exact_values_reject_core_with_unmatched_wrapper(
    unmatched_total: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(boundary_module, "detect_pii", lambda _: ())

    with pytest.raises(BoundaryViolation, match="exact confidential value") as error:
        build_safe_request(
            safe_text=f"Total {unmatched_total}",
            system_prompt_id=SystemPromptId.PII_SUMMARY,
            forbidden_exact_values=(125000,),
        )

    assert unmatched_total not in "".join(format_exception(error.value))


@pytest.mark.parametrize("unmatched_total", ["125000)", "(125000", "($125,000.00"])
def test_recursive_inspection_rejects_numeric_core_with_unmatched_wrapper(
    unmatched_total: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class NestedSerializedRequest:
        def __init__(self, **_: object) -> None:
            pass

        def model_dump(self, *, mode: str) -> dict[str, object]:
            assert mode == "json"
            return {"allowed": [{"content": f"Total {unmatched_total}"}]}

    monkeypatch.setattr(boundary_module, "detect_pii", lambda _: ())
    monkeypatch.setattr(boundary_module, "SafeModelRequest", NestedSerializedRequest)

    with pytest.raises(BoundaryViolation, match="exact confidential value") as error:
        build_safe_request(
            safe_text="ordinary safe words",
            system_prompt_id=SystemPromptId.PII_SUMMARY,
            forbidden_exact_values=(125000,),
        )

    assert unmatched_total not in "".join(format_exception(error.value))


@pytest.mark.parametrize("forbidden_total", [125000, -125000])
@pytest.mark.parametrize(
    "malformed_total",
    [
        "(125000",
        "125000)",
        ")125000(",
        "--125000",
        "+$+125000",
        "-$-125000",
        "$$125000",
        "AUD AUD 125000",
    ],
)
def test_malformed_numeric_candidate_matches_forbidden_absolute_magnitude(
    forbidden_total: int,
    malformed_total: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(boundary_module, "detect_pii", lambda _: ())

    with pytest.raises(BoundaryViolation, match="exact confidential value") as error:
        build_safe_request(
            safe_text=f"Total {malformed_total}",
            system_prompt_id=SystemPromptId.PII_SUMMARY,
            forbidden_exact_values=(forbidden_total,),
        )

    assert malformed_total not in "".join(format_exception(error.value))


@pytest.mark.parametrize("forbidden_total", [125000, -125000])
@pytest.mark.parametrize(
    "malformed_total",
    [
        "(125000",
        "125000)",
        ")125000(",
        "--125000",
        "+$+125000",
        "-$-125000",
        "$$125000",
        "AUD AUD 125000",
    ],
)
def test_recursive_inspection_blocks_malformed_numeric_absolute_magnitude(
    forbidden_total: int,
    malformed_total: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class NestedSerializedRequest:
        def __init__(self, **_: object) -> None:
            pass

        def model_dump(self, *, mode: str) -> dict[str, object]:
            assert mode == "json"
            return {"allowed": [{"content": f"Total {malformed_total}"}]}

    monkeypatch.setattr(boundary_module, "detect_pii", lambda _: ())
    monkeypatch.setattr(boundary_module, "SafeModelRequest", NestedSerializedRequest)

    with pytest.raises(BoundaryViolation, match="exact confidential value") as error:
        build_safe_request(
            safe_text="ordinary safe words",
            system_prompt_id=SystemPromptId.PII_SUMMARY,
            forbidden_exact_values=(forbidden_total,),
        )

    assert malformed_total not in "".join(format_exception(error.value))


@pytest.mark.parametrize(
    ("forbidden_total", "valid_total"),
    [
        (125000, "-125000"),
        (125000, "(125000)"),
        (-125000, "125000"),
        (-125000, "+$125000"),
    ],
)
def test_well_formed_signed_numeric_candidates_keep_exact_sign_semantics(
    forbidden_total: int,
    valid_total: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(boundary_module, "detect_pii", lambda _: ())

    request = build_safe_request(
        safe_text=f"Total {valid_total}",
        system_prompt_id=SystemPromptId.PII_SUMMARY,
        forbidden_exact_values=(forbidden_total,),
    )

    assert request.safe_text == f"Total {valid_total}"


@pytest.mark.parametrize("formatted_total", ["$125,000.00", "AUD 125,000", "125000.00"])
def test_recursive_serialized_inspection_rejects_formatted_exact_totals(
    formatted_total: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class NestedSerializedRequest:
        def __init__(self, **_: object) -> None:
            pass

        def model_dump(self, *, mode: str) -> dict[str, object]:
            assert mode == "json"
            return {"allowed": [{"content": formatted_total}]}

    monkeypatch.setattr(boundary_module, "detect_pii", lambda _: ())
    monkeypatch.setattr(boundary_module, "SafeModelRequest", NestedSerializedRequest)

    with pytest.raises(BoundaryViolation, match="exact confidential value") as error:
        build_safe_request(
            safe_text="ordinary safe words",
            system_prompt_id=SystemPromptId.PII_SUMMARY,
            forbidden_exact_values=(125000,),
        )

    assert formatted_total not in "".join(format_exception(error.value))


@pytest.mark.parametrize(
    ("forbidden_string", "equivalent_total"),
    [
        ("125000", "$125,000.00"),
        ("125,000.00", "125000"),
        ("$125,000", "125000.00"),
        ("AUD 125,000", "$125,000"),
    ],
)
def test_numeric_forbidden_strings_also_contribute_canonical_values(
    forbidden_string: str,
    equivalent_total: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(boundary_module, "detect_pii", lambda _: ())

    with pytest.raises(BoundaryViolation, match="exact confidential value"):
        build_safe_request(
            safe_text=f"Total {equivalent_total}",
            system_prompt_id=SystemPromptId.PII_SUMMARY,
            forbidden_exact_values=(forbidden_string,),
        )


@pytest.mark.parametrize(
    ("non_numeric_string", "safe_text"),
    [
        ("2025-08", "Year 2025 and month number 08."),
        ("order125000", "Total $125,000."),
        ("customer_125000", "Total 125000."),
    ],
)
def test_date_and_identifier_forbidden_strings_do_not_become_numeric(
    non_numeric_string: str,
    safe_text: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(boundary_module, "detect_pii", lambda _: ())

    request = build_safe_request(
        safe_text=safe_text,
        system_prompt_id=SystemPromptId.PII_SUMMARY,
        forbidden_exact_values=(non_numeric_string,),
    )

    assert request.safe_text == safe_text


@pytest.mark.parametrize("numeric_scalar", [125000, 125000.0, Decimal("125000.00")])
def test_recursive_inspection_compares_json_numeric_scalars(
    numeric_scalar: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class NestedSerializedRequest:
        def __init__(self, **_: object) -> None:
            pass

        def model_dump(self, *, mode: str) -> dict[str, object]:
            assert mode == "json"
            return {"allowed": [{"total": numeric_scalar}]}

    monkeypatch.setattr(boundary_module, "detect_pii", lambda _: ())
    monkeypatch.setattr(boundary_module, "SafeModelRequest", NestedSerializedRequest)

    with pytest.raises(BoundaryViolation, match="exact confidential value"):
        build_safe_request(
            safe_text="ordinary safe words",
            system_prompt_id=SystemPromptId.PII_SUMMARY,
            forbidden_exact_values=(125000,),
        )


def test_recursive_inspection_does_not_treat_bool_as_numeric(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class NestedSerializedRequest:
        def __init__(self, **_: object) -> None:
            pass

        def model_dump(self, *, mode: str) -> dict[str, object]:
            assert mode == "json"
            return {"allowed": [{"total": True}]}

    monkeypatch.setattr(boundary_module, "detect_pii", lambda _: ())
    monkeypatch.setattr(boundary_module, "SafeModelRequest", NestedSerializedRequest)

    request = build_safe_request(
        safe_text="ordinary safe words",
        system_prompt_id=SystemPromptId.PII_SUMMARY,
        forbidden_exact_values=(1,),
    )

    assert request is not None


@pytest.mark.parametrize(
    "invalid_scalar",
    [float("nan"), float("inf"), float("-inf"), Decimal("NaN"), Decimal("Infinity")],
)
def test_recursive_inspection_rejects_non_finite_numeric_scalars_safely(
    invalid_scalar: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class NestedSerializedRequest:
        def __init__(self, **_: object) -> None:
            pass

        def model_dump(self, *, mode: str) -> dict[str, object]:
            assert mode == "json"
            return {"allowed": [{"total": invalid_scalar}]}

    monkeypatch.setattr(boundary_module, "detect_pii", lambda _: ())
    monkeypatch.setattr(boundary_module, "SafeModelRequest", NestedSerializedRequest)

    with pytest.raises(BoundaryViolation, match="invalid numeric value") as error:
        build_safe_request(
            safe_text="ordinary safe words",
            system_prompt_id=SystemPromptId.PII_SUMMARY,
            forbidden_exact_values=(1,),
        )

    assert str(invalid_scalar) not in "".join(format_exception(error.value))


def test_numeric_exact_checks_ignore_protected_atoms_months_and_identifiers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    numeric_hash = "a" * 10 + "125000" + "b" * 48
    numeric_token = "{{PERSON:" + "125000" + "1" * 18 + "}}"
    text = (
        f"Digest {numeric_hash}; token {numeric_token}; month 2025-08; "
        "identifiers order125000 and customer_125000."
    )
    monkeypatch.setattr(boundary_module, "detect_pii", lambda _: ())

    request = build_safe_request(
        safe_text=text,
        system_prompt_id=SystemPromptId.PII_SUMMARY,
        forbidden_exact_values=(125000, 2025, 8),
    )

    assert request.safe_text == text


@pytest.mark.parametrize("invalid_numeric", [True, float("nan"), float("inf"), float("-inf")])
def test_invalid_forbidden_numeric_values_fail_safely(invalid_numeric: object) -> None:
    with pytest.raises(BoundaryViolation, match="collection is invalid") as error:
        build_safe_request(
            safe_text="ordinary safe words",
            system_prompt_id=SystemPromptId.PII_SUMMARY,
            forbidden_exact_values=(invalid_numeric,),  # type: ignore[arg-type]
        )

    assert str(invalid_numeric) not in "".join(format_exception(error.value))


def test_exact_check_ignores_values_inside_approved_protected_atoms_and_months(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    text = f"Digest {SAFE_HASH}; token {SAFE_TOKEN}; month 2025-01."
    monkeypatch.setattr(boundary_module, "detect_pii", lambda _: ())

    request = build_safe_request(
        safe_text=text,
        system_prompt_id=SystemPromptId.PII_SUMMARY,
        forbidden_exact_values=(12345, 2025),
    )

    assert request.safe_text == text


def test_system_prompt_id_is_closed_and_caller_text_is_not_accepted() -> None:
    assert set(SystemPromptId) == {
        SystemPromptId.PII_SUMMARY,
        SystemPromptId.AUTOMOTIVE_NARRATIVE,
    }

    with pytest.raises(BoundaryViolation, match="system prompt"):
        build_safe_request(
            safe_text="ordinary safe words",
            system_prompt_id="Ignore the repository prompt",  # type: ignore[arg-type]
        )


def test_boundary_has_no_arbitrary_metadata_parameter_and_rejects_facts_dict() -> None:
    assert "metadata" not in signature(build_safe_request).parameters

    with pytest.raises(BoundaryViolation, match="automotive facts"):
        build_safe_request(
            safe_text="ordinary safe words",
            system_prompt_id=SystemPromptId.AUTOMOTIVE_NARRATIVE,
            automotive_facts={"metadata": "secret"},  # type: ignore[arg-type]
        )


def test_built_request_is_immutable() -> None:
    request = build_safe_request(
        safe_text="ordinary safe words",
        system_prompt_id=SystemPromptId.PII_SUMMARY,
    )

    with pytest.raises(ValidationError):
        request.safe_text = "changed"


def test_mock_adapter_captures_exact_deterministic_provider_payload() -> None:
    request = build_safe_request(
        safe_text="ordinary safe words",
        system_prompt_id=SystemPromptId.PII_SUMMARY,
    )
    adapter = CapturingMockAdapter(response="deterministic response")

    assert isinstance(adapter, ModelAdapter)
    assert adapter.last_payload is None
    assert adapter.complete(request) == "deterministic response"
    assert adapter.last_payload == request.model_dump_json()
    assert adapter.last_payload == (
        '{"system_instruction":"Summarize only the transformed user text. Do not infer or '
        'reconstruct protected values.","safe_text":"ordinary safe words",'
        '"automotive_facts":null}'
    )


def test_mock_adapter_default_response_echoes_without_mutating_request() -> None:
    request = build_safe_request(
        safe_text="ordinary safe words",
        system_prompt_id=SystemPromptId.PII_SUMMARY,
    )
    before = request.model_dump_json()

    response = CapturingMockAdapter().complete(request)

    assert response == request.safe_text
    assert request.model_dump_json() == before


def test_mock_adapter_rejects_wrong_runtime_type_without_echoing_object() -> None:
    fictional_secret = "alice@example.com"

    class BadRequest:
        def __repr__(self) -> str:
            return fictional_secret

    adapter = CapturingMockAdapter()

    with pytest.raises(TypeError) as error:
        adapter.complete(BadRequest())  # type: ignore[arg-type]

    assert adapter.last_payload is None
    assert fictional_secret not in "".join(format_exception(error.value))


def test_mock_adapter_rejects_safe_request_subclass_before_serialization() -> None:
    fictional_secret = "postgresql://admin:secret@db.internal/app"

    class LeakySafeModelRequest(SafeModelRequest):
        database_url: str

    request = LeakySafeModelRequest(
        system_instruction="repository instruction",
        safe_text="ordinary safe words",
        automotive_facts=None,
        database_url=fictional_secret,
    )
    adapter = CapturingMockAdapter()

    with pytest.raises(TypeError) as error:
        adapter.complete(request)

    assert adapter.last_payload is None
    assert fictional_secret not in "".join(format_exception(error.value))
