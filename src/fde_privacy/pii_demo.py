"""Inspectable local-first PII transformation demonstration."""

import json
import os
import re
import sys
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from typing import Final

from fde_privacy.boundary import SystemPromptId, build_safe_request
from fde_privacy.contracts import SafeModelRequest, SessionContext
from fde_privacy.detector import DetectedEntity, detect_pii
from fde_privacy.model_adapters import CapturingMockAdapter, ModelAdapter
from fde_privacy.policy import PiiAction, PolicyDecision, decide_policy
from fde_privacy.token_vault import TokenVault
from fde_privacy.transforms import SpanReplacement, hash_value, mask_value, transform_text

FICTIONAL_REQUEST: Final = (
    "Alice Johnson has email alice.johnson@example.com. "
    "The customer's phone number is +61 412 345 678. "
    "Customer record CUST-000123."
)
_TOKEN_PATTERN: Final = re.compile(r"\{\{[A-Z][A-Z0-9_]*:[A-Za-z0-9_-]{24}\}\}")
_MINIMUM_SALT_BYTES: Final = 16

Detector = Callable[[str], tuple[DetectedEntity, ...]]
PolicyEvaluator = Callable[[str, float], PolicyDecision]


class PiiDemoError(RuntimeError):
    """Raised when the local-first demo cannot prove a request safe."""


@dataclass(frozen=True, slots=True)
class PiiDetectionMetadata:
    """Safe-to-inspect detection metadata without the detected substring."""

    type: str
    start: int
    end: int
    score: float


@dataclass(frozen=True, slots=True)
class PiiDemoResult:
    """Explicit trust-boundary stages produced by the PII demo."""

    trusted_input: str
    local_detections: tuple[PiiDetectionMetadata, ...]
    transformed_text: str
    model_facing_request: SafeModelRequest
    model_response: str
    final_local_response: str


def rehydrate_tokens(text: str, session: SessionContext, vault: TokenVault) -> str:
    """Restore only complete repository token patterns for their owning session."""

    return _TOKEN_PATTERN.sub(lambda match: vault.rehydrate(match.group(), session), text)


def run_pii_demo(
    session: SessionContext,
    adapter: ModelAdapter,
    fixed_salt: str,
    request: str = FICTIONAL_REQUEST,
    detector: Detector = detect_pii,
    vault: TokenVault | None = None,
    policy: PolicyEvaluator = decide_policy,
) -> PiiDemoResult:
    """Run detection, policy, transformation, model capture, and local rehydration."""

    if not isinstance(fixed_salt, str) or len(fixed_salt.encode("utf-8")) < _MINIMUM_SALT_BYTES:
        raise PiiDemoError("hash salt must contain at least 16 UTF-8 bytes")
    if not isinstance(request, str) or not request:
        raise PiiDemoError("trusted input must be a non-empty string")
    if not isinstance(session, SessionContext):
        raise PiiDemoError("session must be a SessionContext")

    detected: tuple[object, ...] | None = None
    try:
        detected = tuple(detector(request))
    except Exception:
        pass
    if detected is None:
        raise PiiDemoError("local privacy detection failed")

    detections = _validate_detections(detected, len(request))
    decisions = _evaluate_all_policies(detections, policy)
    if any(decision.needs_review or decision.action is PiiAction.BLOCK for decision in decisions):
        raise PiiDemoError("privacy policy blocked the request")

    active_vault = vault if vault is not None else TokenVault()
    replacements: list[SpanReplacement] = []
    originals: list[str] = []
    for detection, decision in zip(detections, decisions, strict=True):
        original = request[detection.start : detection.end]
        originals.append(original)
        replacement: str
        if decision.action is PiiAction.TOKENIZE:
            replacement = active_vault.tokenize(original, detection.entity_type, session)
        elif decision.action is PiiAction.HASH:
            replacement = hash_value(original, salt=fixed_salt)
        elif decision.action is PiiAction.MASK:
            replacement = mask_value(original, detection.entity_type)
        else:
            raise PiiDemoError("privacy policy returned an unsupported action")
        replacements.append(SpanReplacement(detection.start, detection.end, replacement))

    transformed = transform_text(request, replacements)
    safe_request = build_safe_request(
        safe_text=transformed,
        system_prompt_id=SystemPromptId.PII_SUMMARY,
        forbidden_exact_values=tuple(originals),
    )

    model_response: object | None = None
    try:
        model_response = adapter.complete(safe_request)
    except Exception:
        pass
    if not isinstance(model_response, str):
        raise PiiDemoError("model adapter failed safely")
    if any(original in model_response for original in originals):
        raise PiiDemoError("model response failed local privacy validation")

    final_response: str | None = None
    try:
        final_response = rehydrate_tokens(model_response, session, active_vault)
    except Exception:
        pass
    if final_response is None:
        raise PiiDemoError("local token rehydration failed")

    metadata = tuple(
        PiiDetectionMetadata(
            type=detection.entity_type,
            start=detection.start,
            end=detection.end,
            score=detection.score,
        )
        for detection in detections
    )
    return PiiDemoResult(
        trusted_input=request,
        local_detections=metadata,
        transformed_text=transformed,
        model_facing_request=safe_request,
        model_response=model_response,
        final_local_response=final_response,
    )


def _validate_detections(
    detected: tuple[object, ...], text_length: int
) -> tuple[DetectedEntity, ...]:
    validated: list[DetectedEntity] = []
    previous_end = -1
    for item in detected:
        if (
            not isinstance(item, DetectedEntity)
            or not isinstance(item.entity_type, str)
            or type(item.start) is not int
            or type(item.end) is not int
            or not 0 <= item.start < item.end <= text_length
            or item.start < previous_end
        ):
            raise PiiDemoError("local privacy detection returned invalid metadata")
        validated.append(item)
        previous_end = item.end
    return tuple(validated)


def _evaluate_all_policies(
    detections: tuple[DetectedEntity, ...], policy: PolicyEvaluator
) -> tuple[PolicyDecision, ...]:
    decisions: list[PolicyDecision] = []
    failed = False
    for detection in detections:
        decision: object | None = None
        try:
            decision = policy(detection.entity_type, detection.score)
        except Exception:
            failed = True
        if not isinstance(decision, PolicyDecision):
            failed = True
        else:
            decisions.append(decision)
    if failed or len(decisions) != len(detections):
        raise PiiDemoError("local privacy policy evaluation failed")
    return tuple(decisions)


def main() -> int:
    """Print the four inspectable demo stages using only local components."""

    salt = os.environ.get("PII_HASH_SALT")
    if salt is None or len(salt.encode("utf-8")) < _MINIMUM_SALT_BYTES:
        print("PII_HASH_SALT must contain at least 16 UTF-8 bytes", file=sys.stderr)
        return 2

    result: PiiDemoResult | None = None
    try:
        result = run_pii_demo(
            SessionContext(
                owner_id="fictional-demo-owner",
                session_id="fictional-demo-session",
                issued_at=datetime.now(UTC),
            ),
            CapturingMockAdapter(),
            salt,
        )
    except Exception:
        pass
    if result is None:
        print("PII demo failed closed locally", file=sys.stderr)
        return 1

    print("=== TRUSTED LOCAL INPUT ===")
    print(result.trusted_input)
    print("=== LOCAL DETECTIONS ===")
    print(json.dumps([asdict(detection) for detection in result.local_detections], indent=2))
    print("=== MODEL-FACING PAYLOAD ===")
    print(result.model_facing_request.model_dump_json(indent=2))
    print("=== FINAL LOCAL RESPONSE ===")
    print(result.final_local_response)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
