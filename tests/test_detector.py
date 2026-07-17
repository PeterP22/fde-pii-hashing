from dataclasses import FrozenInstanceError, fields

import pytest
from presidio_analyzer import RecognizerResult

from fde_privacy.detector import DetectedEntity, detect_pii, get_analyzer
from fde_privacy.policy import PiiAction, PolicyDecision, decide_policy


def test_detects_fictional_person_email_phone_and_customer_id() -> None:
    text = (
        "Alice Johnson can be reached at alice.johnson@example.com or "
        "+1 202-555-0199. Customer CUST-123456."
    )

    detections = detect_pii(text)

    assert isinstance(detections, tuple)
    assert {detection.entity_type for detection in detections} >= {
        "PERSON",
        "EMAIL_ADDRESS",
        "PHONE_NUMBER",
        "CUSTOMER_ID",
    }


def test_customer_id_detection_uses_expected_span_and_score() -> None:
    text = "Fictional customer CUST-654321 requested a callback."

    detection = next(
        detection for detection in detect_pii(text) if detection.entity_type == "CUSTOMER_ID"
    )

    assert (detection.start, detection.end) == (19, 30)
    assert detection.score == pytest.approx(0.95)


def test_detected_entity_is_immutable_and_carries_no_source_text() -> None:
    entity = DetectedEntity(entity_type="PERSON", start=0, end=13, score=0.85)

    assert tuple(field.name for field in fields(entity)) == (
        "entity_type",
        "start",
        "end",
        "score",
    )
    with pytest.raises(FrozenInstanceError):
        entity.score = 1.0  # type: ignore[misc]


def test_analyzer_is_cached_and_uses_installed_small_english_model() -> None:
    analyzer = get_analyzer()

    assert get_analyzer() is analyzer
    assert analyzer.nlp_engine.models == [
        {"lang_code": "en", "model_name": "en_core_web_sm"}
    ]


def test_detects_presidio_upstream_test_only_australian_tfn_fixture() -> None:
    # Test-only fixture copied from Presidio 2.2.363's AuTfnRecognizer tests:
    # presidio-analyzer/tests/test_au_tfn_recognizer.py. It is published test data,
    # not an identifier attributed to a real person.
    text = "Test-only Australian TFN fixture: 876 543 210."

    detections = detect_pii(text)

    assert any(detection.entity_type == "AU_TFN" for detection in detections)


def test_contextual_fictional_australian_phone_is_safe_to_tokenize() -> None:
    text = "The customer's phone number is +61 412 345 678."

    phone = next(
        detection for detection in detect_pii(text) if detection.entity_type == "PHONE_NUMBER"
    )

    assert phone.score >= 0.60
    assert decide_policy(phone.entity_type, phone.score) == PolicyDecision(
        action=PiiAction.TOKENIZE,
        needs_review=False,
    )


def test_exact_customer_id_owns_its_span_without_weak_overlap_blocks() -> None:
    text = "Customer CUST-000123 requested a callback."

    detections = detect_pii(text)
    customer_id = next(
        detection for detection in detections if detection.entity_type == "CUSTOMER_ID"
    )
    overlapping = tuple(
        detection
        for detection in detections
        if detection.start < customer_id.end and customer_id.start < detection.end
    )

    assert text[customer_id.start : customer_id.end] == "CUST-000123"
    assert customer_id.score == pytest.approx(0.95)
    assert tuple(
        (detection, decide_policy(detection.entity_type, detection.score))
        for detection in overlapping
    ) == (
        (
            customer_id,
            PolicyDecision(action=PiiAction.HASH, needs_review=False),
        ),
    )


def test_detector_orders_results_by_text_then_specificity() -> None:
    text = (
        "The customer's phone number is +61 412 345 678. "
        "Email alice.johnson@example.com and customer CUST-000123."
    )

    detections = detect_pii(text)

    assert detections == tuple(
        sorted(
            detections,
            key=lambda detection: (
                detection.start,
                detection.end,
                -detection.score,
                detection.entity_type,
            ),
        )
    )


def test_representative_fictional_text_reaches_intended_policy_actions() -> None:
    text = (
        "Alice Johnson has email alice.johnson@example.com. "
        "The customer's phone number is +61 412 345 678. "
        "Customer record CUST-000123."
    )

    detections = detect_pii(text)
    intended = {
        entity_type: next(
            detection for detection in detections if detection.entity_type == entity_type
        )
        for entity_type in ("PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "CUSTOMER_ID")
    }

    assert {
        entity_type: decide_policy(detection.entity_type, detection.score)
        for entity_type, detection in intended.items()
    } == {
        "PERSON": PolicyDecision(PiiAction.TOKENIZE, needs_review=False),
        "EMAIL_ADDRESS": PolicyDecision(PiiAction.TOKENIZE, needs_review=False),
        "PHONE_NUMBER": PolicyDecision(PiiAction.TOKENIZE, needs_review=False),
        "CUSTOMER_ID": PolicyDecision(PiiAction.HASH, needs_review=False),
    }
    customer_id = intended["CUSTOMER_ID"]
    assert not any(
        detection.entity_type == "US_DRIVER_LICENSE"
        and detection.start < customer_id.end
        and customer_id.start < detection.end
        for detection in detections
    )


def test_non_customer_ambiguous_overlaps_remain_fail_closed() -> None:
    text = "Email alice.johnson@example.com."

    detections = detect_pii(text)
    email = next(
        detection for detection in detections if detection.entity_type == "EMAIL_ADDRESS"
    )
    overlapping_urls = tuple(
        detection
        for detection in detections
        if detection.entity_type == "URL"
        and detection.start < email.end
        and email.start < detection.end
    )

    assert overlapping_urls
    assert all(
        decide_policy(detection.entity_type, detection.score)
        == PolicyDecision(PiiAction.BLOCK, needs_review=True)
        for detection in overlapping_urls
    )


def test_customer_id_suppresses_only_fully_contained_overlaps(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    text = "Alice CUST-000123 Bob"

    class StubAnalyzer:
        def analyze(self, *, text: str, language: str) -> list[RecognizerResult]:
            assert text == "Alice CUST-000123 Bob"
            assert language == "en"
            return [
                RecognizerResult("PERSON", 0, 17, 0.85),
                RecognizerResult("CUSTOMER_ID", 6, 17, 0.95),
                RecognizerResult("US_DRIVER_LICENSE", 11, 17, 0.01),
                RecognizerResult("PERSON", 18, 21, 0.85),
            ]

    monkeypatch.setattr("fde_privacy.detector.get_analyzer", lambda: StubAnalyzer())

    detections = detect_pii(text)

    assert tuple(
        (detection.entity_type, detection.start, detection.end) for detection in detections
    ) == (
        ("PERSON", 0, 17),
        ("CUSTOMER_ID", 6, 17),
        ("PERSON", 18, 21),
    )
