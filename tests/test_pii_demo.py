import json
from dataclasses import asdict, fields
from datetime import UTC, datetime
from traceback import format_exception

import pytest

from fde_privacy.contracts import SafeModelRequest, SessionContext
from fde_privacy.detector import DetectedEntity
from fde_privacy.model_adapters import CapturingMockAdapter
from fde_privacy.pii_demo import (
    FICTIONAL_REQUEST,
    PiiDemoError,
    PiiDetectionMetadata,
    main,
    rehydrate_tokens,
    run_pii_demo,
)
from fde_privacy.policy import PiiAction, PolicyDecision, decide_policy
from fde_privacy.token_vault import TokenNotFound, TokenOwnershipError, TokenVault

NOW = datetime(2026, 7, 17, 12, 0, tzinfo=UTC)
SALT = "fictional-dev-salt-32-bytes-long"


def session(owner_id: str = "owner-1", session_id: str = "session-1") -> SessionContext:
    return SessionContext(owner_id=owner_id, session_id=session_id, issued_at=NOW)


def test_end_to_end_demo_keeps_provider_payload_safe_and_rehydrates_tokens() -> None:
    adapter = CapturingMockAdapter()
    vault = TokenVault()

    result = run_pii_demo(session(), adapter, SALT, vault=vault)

    assert result.trusted_input == FICTIONAL_REQUEST
    assert tuple(field.name for field in fields(PiiDetectionMetadata)) == (
        "type",
        "start",
        "end",
        "score",
    )
    assert {detection.type for detection in result.local_detections} == {
        "PERSON",
        "EMAIL_ADDRESS",
        "PHONE_NUMBER",
        "CUSTOMER_ID",
    }
    assert all(set(asdict(detection)) == {"type", "start", "end", "score"} for detection in result.local_detections)

    assert result.model_facing_request.safe_text == result.transformed_text
    assert adapter.last_payload == result.model_facing_request.model_dump_json()
    assert result.model_response == result.transformed_text
    for restored in (
        "Alice Johnson",
        "alice.johnson@example.com",
        "+61 412 345 678",
    ):
        assert restored in result.final_local_response

    customer_hash = next(
        word.strip(".,")
        for word in result.transformed_text.split()
        if len(word.strip(".,")) == 64
    )
    assert len(customer_hash) == 64
    assert all(character in "0123456789abcdef" for character in customer_hash)
    for entity_type in ("PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER"):
        assert f"{{{{{entity_type}:" in result.transformed_text

    protected_values = (
        "Alice Johnson",
        "alice.johnson@example.com",
        "+61 412 345 678",
        "CUST-000123",
    )
    for protected in protected_values:
        assert protected not in adapter.last_payload
        assert protected not in result.transformed_text
        assert protected not in result.model_response
    assert "CUST-000123" not in result.final_local_response
    assert customer_hash in result.final_local_response


def test_adapter_receives_the_exact_safe_request_instance() -> None:
    class IdentityAdapter:
        def __init__(self) -> None:
            self.request: SafeModelRequest | None = None

        def complete(self, request: SafeModelRequest) -> str:
            self.request = request
            return request.safe_text

    adapter = IdentityAdapter()

    result = run_pii_demo(session(), adapter, SALT)

    assert adapter.request is result.model_facing_request


def test_all_policy_decisions_are_evaluated_before_blocking_and_before_adapter() -> None:
    adapter = CapturingMockAdapter()
    calls: list[str] = []
    request = "Alice has secret data."

    def detector(_: str) -> tuple[DetectedEntity, ...]:
        return (
            DetectedEntity("PERSON", 0, 5, 0.95),
            DetectedEntity("UNRECOGNIZED_SECRET", 10, 16, 0.95),
        )

    def policy(entity_type: str, score: float) -> PolicyDecision:
        calls.append(entity_type)
        return decide_policy(entity_type, score)

    with pytest.raises(PiiDemoError, match="privacy policy blocked the request") as error:
        run_pii_demo(
            session(),
            adapter,
            SALT,
            request=request,
            detector=detector,
            policy=policy,
        )

    assert calls == ["PERSON", "UNRECOGNIZED_SECRET"]
    assert adapter.last_payload is None
    assert request not in "".join(format_exception(error.value))


def test_future_mask_policy_is_composed_without_leaking_the_value() -> None:
    request = "Secret nickname is Sparrow."
    start = request.index("Sparrow")

    result = run_pii_demo(
        session(),
        CapturingMockAdapter(),
        SALT,
        request=request,
        detector=lambda _: (DetectedEntity("NICKNAME", start, start + 7, 0.99),),
        policy=lambda _entity_type, _score: PolicyDecision(PiiAction.MASK, False),
    )

    assert result.transformed_text == "Secret nickname is <NICKNAME>."
    assert result.final_local_response == result.transformed_text


def test_rehydrate_tokens_enforces_owner_and_session_and_ignores_hashes() -> None:
    vault = TokenVault()
    owner = session()
    token = vault.tokenize("Alice Johnson", "PERSON", owner)
    irreversible_hash = "a" * 64

    assert rehydrate_tokens(f"Hello {token} {irreversible_hash}", owner, vault) == (
        f"Hello Alice Johnson {irreversible_hash}"
    )
    with pytest.raises(TokenOwnershipError):
        rehydrate_tokens(token, session(owner_id="owner-2"), vault)
    with pytest.raises(TokenOwnershipError):
        rehydrate_tokens(token, session(session_id="session-2"), vault)
    with pytest.raises(TokenNotFound):
        vault.rehydrate(irreversible_hash, owner)


def test_detector_failure_is_sanitized_and_never_calls_adapter() -> None:
    adapter = CapturingMockAdapter()
    raw_pii = "alice.johnson@example.com"

    def broken_detector(_: str) -> tuple[DetectedEntity, ...]:
        raise RuntimeError(f"detector unavailable for {raw_pii} with {SALT}")

    with pytest.raises(PiiDemoError, match="local privacy detection failed") as error:
        run_pii_demo(
            session(),
            adapter,
            SALT,
            request=f"Email {raw_pii}",
            detector=broken_detector,
        )

    formatted = "".join(format_exception(error.value))
    assert adapter.last_payload is None
    assert raw_pii not in formatted
    assert SALT not in formatted
    assert error.value.__cause__ is None
    assert error.value.__context__ is None


@pytest.mark.parametrize("salt", [None, "short"])
def test_cli_exits_clearly_without_a_valid_environment_salt(
    salt: str | None, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    if salt is None:
        monkeypatch.delenv("PII_HASH_SALT", raising=False)
    else:
        monkeypatch.setenv("PII_HASH_SALT", salt)

    exit_code = main()
    captured = capsys.readouterr()

    assert exit_code == 2
    assert "PII_HASH_SALT must contain at least 16 UTF-8 bytes" in captured.err
    assert captured.out == ""
    if salt is not None:
        assert salt not in captured.err


def test_cli_prints_labelled_stages_without_printing_salt(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setenv("PII_HASH_SALT", SALT)

    exit_code = main()
    captured = capsys.readouterr()

    assert exit_code == 0
    assert captured.err == ""
    for label in (
        "TRUSTED LOCAL INPUT",
        "LOCAL DETECTIONS",
        "MODEL-FACING PAYLOAD",
        "FINAL LOCAL RESPONSE",
    ):
        assert f"=== {label} ===" in captured.out
    assert SALT not in captured.out
    detections_json = captured.out.split("=== LOCAL DETECTIONS ===\n", 1)[1].split(
        "\n=== MODEL-FACING PAYLOAD ===", 1
    )[0]
    assert isinstance(json.loads(detections_json), list)
