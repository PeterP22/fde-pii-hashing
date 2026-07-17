"""Local PII detection that exposes offset-only metadata."""

from dataclasses import dataclass
from functools import cache

from presidio_analyzer import AnalyzerEngine, Pattern, PatternRecognizer
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_analyzer.predefined_recognizers import AuTfnRecognizer


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
                    regex=r"\bCUST-[0-9]{6}\b",
                    score=0.95,
                )
            ],
        )
    )
    analyzer.registry.add_recognizer(AuTfnRecognizer())
    return analyzer


def detect_pii(text: str) -> tuple[DetectedEntity, ...]:
    """Analyze text locally and return only entity type, offsets, and score."""

    return tuple(
        DetectedEntity(
            entity_type=result.entity_type,
            start=result.start,
            end=result.end,
            score=result.score,
        )
        for result in get_analyzer().analyze(text=text, language="en")
    )
