"""Adversarial leak tests: a curious provider must not recover raw PII from payloads."""

import hashlib
from datetime import UTC, datetime

import pytest

from fde_privacy.contracts import SessionContext
from fde_privacy.leak_eval import make_population, naive_hash, run_eval
from fde_privacy.model_adapters import CapturingMockAdapter
from fde_privacy.pii_demo import FICTIONAL_REQUEST, PiiDemoError, run_pii_demo
from fde_privacy.token_vault import TokenOwnershipError, TokenVault
from fde_privacy.transforms import hash_value

SALT = "synthetic-test-salt-0123456789"
RAW = ("Alice Johnson", "alice.johnson@example.com", "+61 412 345 678", "CUST-000123")


def _session(name: str) -> SessionContext:
    return SessionContext(owner_id="owner", session_id=name, issued_at=datetime.now(UTC))


@pytest.fixture(scope="module")
def results() -> dict[str, object]:
    return run_eval(size=30, salt_known_attack=False)


def _pipeline(results: dict[str, object], name: str) -> dict[str, object]:
    pipelines = results["pipelines"]
    assert isinstance(pipelines, list)
    return next(p for p in pipelines if p["name"] == name)


def test_dictionary_attack_recovers_naive_hashes(results: dict[str, object]) -> None:
    naive = _pipeline(results, "naive_sha256")
    assert naive["dictionary_reidentified"] > 0
    assert naive["leak_rate"] > 0.8
    assert naive["linkage_rate"] == 1.0


def test_boundary_leaks_nothing_to_provider(results: dict[str, object]) -> None:
    fde = _pipeline(results, "fde_boundary")
    assert fde["raw_leaks"] == 0
    assert fde["dictionary_reidentified"] == 0
    assert fde["leak_rate"] == 0.0
    assert fde["requests"] > fde["blocked"]


def test_logs_and_errors_never_contain_raw_pii(results: dict[str, object]) -> None:
    assert results["log_records_scanned"] > 0
    assert _pipeline(results, "fde_boundary")["log_leaks"] == 0


def test_salt_leak_attack_matches_presidio_hash() -> None:
    expected = hashlib.sha256(b"CUST-000123" + SALT.encode()).hexdigest()
    assert hash_value("CUST-000123", salt=SALT) == expected
    assert hash_value("CUST-000123", salt=SALT) != naive_hash("CUST-000123")


def test_demo_payload_resists_dictionary_attack() -> None:
    adapter = CapturingMockAdapter()
    run_pii_demo(_session("s1"), adapter, SALT)
    payload = adapter.last_payload
    assert payload is not None
    assert not any(value in payload for value in RAW)
    assert not any(naive_hash(value) in payload for value in RAW)


def test_model_echoing_raw_pii_fails_closed() -> None:
    adapter = CapturingMockAdapter(response=f"Leaked {RAW[1]}")
    with pytest.raises(PiiDemoError) as error:
        run_pii_demo(_session("s1"), adapter, SALT)
    assert not any(value in str(error.value) for value in RAW)


def test_forged_token_fails_closed() -> None:
    adapter = CapturingMockAdapter(response="{{PERSON:AAAAAAAAAAAAAAAAAAAAAAAA}}")
    with pytest.raises(PiiDemoError):
        run_pii_demo(_session("s1"), adapter, SALT)


def test_tokens_do_not_rehydrate_or_link_across_sessions() -> None:
    vault = TokenVault()
    first = vault.tokenize(RAW[0], "PERSON", _session("a"))
    second = vault.tokenize(RAW[0], "PERSON", _session("b"))
    assert first != second
    with pytest.raises(TokenOwnershipError):
        vault.rehydrate(first, _session("b"))


def test_demo_payload_differs_per_session() -> None:
    payloads = []
    for name in ("a", "b"):
        adapter = CapturingMockAdapter()
        run_pii_demo(_session(name), adapter, SALT, request=FICTIONAL_REQUEST)
        payloads.append(adapter.last_payload)
    assert payloads[0] != payloads[1]


def test_population_is_synthetic_and_deterministic() -> None:
    people = make_population(10, 1)
    assert people == make_population(10, 1)
    assert all(p.email.endswith("@example.com") for p in people)
