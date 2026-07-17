"""Local PII detection that exposes offset-only metadata."""

from dataclasses import dataclass
from functools import cache
from re import fullmatch
from typing import Final

from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_analyzer.predefined_recognizers import AuTfnRecognizer

from fde_privacy.policy import GENERAL_MIN_CONFIDENCE

CUSTOMER_ID_REGEX: Final = r"\bCUST-[0-9]{6}\b"
CUSTOMER_ID_SCORE: Final = 0.95


@dataclass(frozen=True, slots=True)
class DetectedEntity:
    """A detected span without the sensitive source text."""

    entity_type: str
    start: int
    end: int
    score: float


@cache
def get_analyzer() -> AnalyzerEngine:
    """Build and cache the local English Presidio analyzer."""

    nlp_engine = NlpEngineProvider(
        nlp_configuration={
            "nlp_engine_name": "spacy",
            "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}],
        }
    ).create_engine()
    analyzer = AnalyzerEngine(nlp_engine=nlp_engine, supported_languages=["en"])
    analyzer.registry.add_recognizer(
        PatternRecognizer(
            supported_entity="CUSTOMER_ID",
            patterns=[
                Pattern(
                    name="customer-id",
                    regex=CUSTOMER_ID_REGEX,
                    score=CUSTOMER_ID_SCORE,
                )
            ],
        )
    )
    analyzer.registry.add_recognizer(AuTfnRecognizer())
    return analyzer


def detect_pii(text: str) -> tuple[DetectedEntity, ...]:
    """Analyze text locally and return only entity type, offsets, and score."""

    detections = tuple(
        DetectedEntity(
            entity_type=result.entity_type,
            start=result.start,
            end=result.end,
            score=result.score,
        )
        for result in get_analyzer().analyze(text=text, language="en")
    )
    owned_customer_ids = tuple(
        detection
        for detection in detections
        if detection.entity_type == "CUSTOMER_ID"
        and detection.score == CUSTOMER_ID_SCORE
        and fullmatch(CUSTOMER_ID_REGEX, text[detection.start : detection.end]) is not None
    )
    owned_emails = tuple(
        detection
        for detection in detections
        if detection.entity_type == "EMAIL_ADDRESS"
        and GENERAL_MIN_CONFIDENCE <= detection.score <= 1
    )
    arbitrated = (
        detection
        for detection in detections
        if (
            detection in owned_customer_ids
            or not any(
                customer_id.start <= detection.start and detection.end <= customer_id.end
                for customer_id in owned_customer_ids
            )
        )
        and (
            detection.entity_type != "URL"
            or not any(
                email.start <= detection.start and detection.end <= email.end
                for email in owned_emails
            )
        )
    )
    return tuple(
        sorted(
            arbitrated,
            key=lambda detection: (
                detection.start,
                detection.end,
                -detection.score,
                detection.entity_type,
            ),
        )
    )
