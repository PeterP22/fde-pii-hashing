from dataclasses import FrozenInstanceError

import pytest

from fde_privacy.policy import PiiAction, PolicyDecision, decide_policy


@pytest.mark.parametrize(
    ("entity_type", "expected_action"),
    [
        ("PERSON", PiiAction.TOKENIZE),
        ("EMAIL_ADDRESS", PiiAction.TOKENIZE),
        ("PHONE_NUMBER", PiiAction.TOKENIZE),
        ("CUSTOMER_ID", PiiAction.HASH),
        ("CREDIT_CARD", PiiAction.BLOCK),
    ],
)
def test_default_policy_assigns_only_listed_actions(
    entity_type: str, expected_action: PiiAction
) -> None:
    decision = decide_policy(entity_type, score=0.95)

    assert decision == PolicyDecision(action=expected_action, needs_review=False)


def test_pii_actions_are_strings() -> None:
    assert {action.value for action in PiiAction} == {
        "BLOCK",
        "MASK",
        "HASH",
        "TOKENIZE",
    }
    assert all(isinstance(action, str) for action in PiiAction)


@pytest.mark.parametrize(
    "entity_type",
    [
        "CREDIT_CARD",
        "IBAN_CODE",
        "US_BANK_NUMBER",
        "ABA_ROUTING_NUMBER",
        "AU_TFN",
        "AU_MEDICARE",
        "US_SSN",
        "US_ITIN",
        "US_MBI",
        "DE_TAX_ID",
        "US_DRIVER_LICENSE",
        "UK_DRIVING_LICENCE",
        "IT_DRIVER_LICENSE",
        "DE_FUEHRERSCHEIN",
        "US_PASSPORT",
        "UK_PASSPORT",
        "IN_PASSPORT",
        "BANK_ACCOUNT",
        "TAX_ID",
        "MEDICARE_NUMBER",
        "DRIVER_LICENSE",
        "PASSPORT_NUMBER",
    ],
)
def test_high_risk_entities_are_blocked(entity_type: str) -> None:
    assert decide_policy(entity_type, score=0.95) == PolicyDecision(
        action=PiiAction.BLOCK,
        needs_review=False,
    )


def test_unknown_entities_fail_closed() -> None:
    assert decide_policy("UNRECOGNIZED_SECRET", score=0.95) == PolicyDecision(
        action=PiiAction.BLOCK,
        needs_review=False,
    )


def test_unlisted_location_fails_closed() -> None:
    assert decide_policy("LOCATION", score=0.95) == PolicyDecision(
        action=PiiAction.BLOCK,
        needs_review=False,
    )


@pytest.mark.parametrize("entity_type", ["PERSON", "CUSTOMER_ID", "LOCATION"])
def test_general_confidence_at_exact_threshold_uses_normal_action(entity_type: str) -> None:
    assert decide_policy(entity_type, score=0.60).needs_review is False


@pytest.mark.parametrize("entity_type", ["PERSON", "CUSTOMER_ID", "LOCATION"])
def test_general_confidence_below_threshold_blocks_for_review(entity_type: str) -> None:
    assert decide_policy(entity_type, score=0.599999) == PolicyDecision(
        action=PiiAction.BLOCK,
        needs_review=True,
    )


def test_high_risk_confidence_at_exact_threshold_is_normal_policy_block() -> None:
    assert decide_policy("CREDIT_CARD", score=0.80) == PolicyDecision(
        action=PiiAction.BLOCK,
        needs_review=False,
    )


def test_high_risk_confidence_below_threshold_blocks_for_review() -> None:
    assert decide_policy("CREDIT_CARD", score=0.799999) == PolicyDecision(
        action=PiiAction.BLOCK,
        needs_review=True,
    )


def test_policy_decision_is_immutable() -> None:
    decision = PolicyDecision(action=PiiAction.HASH, needs_review=False)

    with pytest.raises(FrozenInstanceError):
        decision.needs_review = True  # type: ignore[misc]
