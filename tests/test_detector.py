from dataclasses import FrozenInstanceError, fields

import pytest

from fde_privacy.detector import DetectedEntity, detect_pii, get_analyzer


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
