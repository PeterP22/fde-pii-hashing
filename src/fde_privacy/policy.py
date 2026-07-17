"""Closed local policy for actions applied to detected PII."""

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Final


class PiiAction(StrEnum):
    BLOCK = "BLOCK"
    MASK = "MASK"
    HASH = "HASH"
    TOKENIZE = "TOKENIZE"


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    action: PiiAction
    needs_review: bool


GENERAL_MIN_CONFIDENCE: Final = 0.60
HIGH_RISK_MIN_CONFIDENCE: Final = 0.80

DEFAULT_ACTIONS: Final[Mapping[str, PiiAction]] = MappingProxyType(
    {
        "PERSON": PiiAction.TOKENIZE,
        "EMAIL_ADDRESS": PiiAction.TOKENIZE,
        "PHONE_NUMBER": PiiAction.TOKENIZE,
        "CUSTOMER_ID": PiiAction.HASH,
    }
)

HIGH_RISK_ENTITIES: Final[frozenset[str]] = frozenset(
    {
        # Credit card and bank identifiers.
        "CREDIT_CARD",
        "IBAN_CODE",
        "US_BANK_NUMBER",
        "ABA_ROUTING_NUMBER",
        "BANK_ACCOUNT",
        "BANK_ACCOUNT_NUMBER",
        "BANK_NUMBER",
        "ROUTING_NUMBER",
        # Tax and closely related government identifiers.
        "AU_TFN",
        "AU_ABN",
        "AU_ACN",
        "US_ITIN",
        "US_SSN",
        "UK_NINO",
        "DE_TAX_ID",
        "DE_TAX_NUMBER",
        "DE_VAT_ID",
        "IT_FISCAL_CODE",
        "IT_VAT_CODE",
        "ES_NIF",
        "ES_NIE",
        "IN_PAN",
        "IN_GSTIN",
        "PH_TIN",
        "TH_TNIN",
        "TAX_FILE_NUMBER",
        "TAX_ID",
        "TAX_NUMBER",
        # Medicare and equivalent health-benefit identifiers.
        "AU_MEDICARE",
        "US_MBI",
        "UK_NHS",
        "MEDICARE",
        "MEDICARE_NUMBER",
        # Driver licences.
        "US_DRIVER_LICENSE",
        "UK_DRIVING_LICENCE",
        "IT_DRIVER_LICENSE",
        "KR_DRIVER_LICENSE",
        "DE_FUEHRERSCHEIN",
        "DRIVER_LICENCE",
        "DRIVER_LICENSE",
        "DRIVING_LICENCE",
        "DRIVING_LICENSE",
        # Passports.
        "US_PASSPORT",
        "UK_PASSPORT",
        "IN_PASSPORT",
        "IT_PASSPORT",
        "DE_PASSPORT",
        "ES_PASSPORT",
        "KR_PASSPORT",
        "PASSPORT",
        "PASSPORT_NUMBER",
    }
)


def decide_policy(entity_type: str, score: float) -> PolicyDecision:
    """Choose an action, failing closed when confidence is below policy minimum."""

    threshold = (
        HIGH_RISK_MIN_CONFIDENCE
        if entity_type in HIGH_RISK_ENTITIES
        else GENERAL_MIN_CONFIDENCE
    )
    if score < threshold:
        return PolicyDecision(action=PiiAction.BLOCK, needs_review=True)

    action = (
        PiiAction.BLOCK
        if entity_type in HIGH_RISK_ENTITIES
        else DEFAULT_ACTIONS.get(entity_type, PiiAction.BLOCK)
    )
    return PolicyDecision(action=action, needs_review=False)
