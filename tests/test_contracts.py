from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import BaseModel, ValidationError

from fde_privacy.contracts import (
    InboundUserRequest,
    NarrativeTemplate,
    SafeMessage,
    SafeModelRequest,
    SessionContext,
)

NOW = datetime(2026, 7, 17, tzinfo=UTC)


def valid_session() -> SessionContext:
    return SessionContext(owner_id="owner-1", session_id="session-1", issued_at=NOW)


def boundary_examples() -> tuple[BaseModel, ...]:
    return (
        valid_session(),
        InboundUserRequest(text="Call Alice", session=valid_session()),
        SafeModelRequest(system_instruction="Summarise", safe_text="Call <PERSON>"),
        SafeMessage(role="user", content="Call <PERSON>"),
        NarrativeTemplate(headline="Vehicle summary", observations=("Mileage increased",)),
    )


@pytest.mark.parametrize(
    ("model", "expected_fields"),
    [
        (SessionContext, {"owner_id", "session_id", "issued_at"}),
        (InboundUserRequest, {"text", "session"}),
        (
            SafeModelRequest,
            {"system_instruction", "safe_text", "automotive_facts"},
        ),
        (SafeMessage, {"role", "content"}),
        (NarrativeTemplate, {"headline", "observations", "caveat"}),
    ],
)
def test_boundary_models_have_only_their_public_fields(
    model: type[BaseModel], expected_fields: set[str]
) -> None:
    assert set(model.model_fields) == expected_fields


@pytest.mark.parametrize(
    ("model", "payload"),
    [
        (
            SessionContext,
            {"owner_id": "owner-1", "session_id": "session-1", "issued_at": NOW},
        ),
        (InboundUserRequest, {"text": "Call Alice", "session": valid_session()}),
        (
            SafeModelRequest,
            {"system_instruction": "Summarise", "safe_text": "Call <PERSON>"},
        ),
        (SafeMessage, {"role": "user", "content": "Call <PERSON>"}),
        (
            NarrativeTemplate,
            {"headline": "Vehicle summary", "observations": ("Mileage increased",)},
        ),
    ],
)
def test_boundary_models_reject_extra_fields(
    model: type[BaseModel], payload: dict[str, Any]
) -> None:
    with pytest.raises(ValidationError):
        model.model_validate({**payload, "unexpected": "private"})


def test_safe_request_rejects_extra_fields() -> None:
    with pytest.raises(ValidationError):
        SafeModelRequest.model_validate(
            {
                "system_instruction": "Summarise",
                "safe_text": "<PERSON>",
                "database_url": "private",
            }
        )


@pytest.mark.parametrize("instance", boundary_examples())
def test_boundary_models_are_immutable(instance: BaseModel) -> None:
    field_name = next(iter(type(instance).model_fields))
    with pytest.raises(ValidationError):
        setattr(instance, field_name, getattr(instance, field_name))


def test_session_context_is_immutable() -> None:
    context = SessionContext(owner_id="owner-1", session_id="session-1", issued_at=NOW)
    with pytest.raises(ValidationError):
        context.owner_id = "owner-2"


@pytest.mark.parametrize(
    ("model", "payload"),
    [
        (SessionContext, {"owner_id": "", "session_id": "session-1", "issued_at": NOW}),
        (SessionContext, {"owner_id": "owner-1", "session_id": "", "issued_at": NOW}),
        (InboundUserRequest, {"text": "", "session": valid_session()}),
        (SafeModelRequest, {"system_instruction": "", "safe_text": "<PERSON>"}),
        (SafeModelRequest, {"system_instruction": "Summarise", "safe_text": ""}),
        (SafeMessage, {"role": "user", "content": ""}),
        (NarrativeTemplate, {"headline": "", "observations": ("Mileage increased",)}),
        (
            NarrativeTemplate,
            {"headline": "Vehicle summary", "observations": ("",)},
        ),
        (
            NarrativeTemplate,
            {"headline": "Vehicle summary", "observations": ("Mileage increased",), "caveat": ""},
        ),
    ],
)
def test_boundary_models_reject_empty_required_strings(
    model: type[BaseModel], payload: dict[str, Any]
) -> None:
    with pytest.raises(ValidationError):
        model.model_validate(payload)


@pytest.mark.parametrize("role", ["assistant", "tool"])
def test_safe_message_rejects_non_boundary_roles(role: str) -> None:
    with pytest.raises(ValidationError):
        SafeMessage.model_validate({"role": role, "content": "Call <PERSON>"})


@pytest.mark.parametrize(
    "observations",
    [(), ("one", "two", "three", "four", "five")],
)
def test_narrative_template_requires_one_to_four_observations(
    observations: tuple[str, ...],
) -> None:
    with pytest.raises(ValidationError):
        NarrativeTemplate(headline="Vehicle summary", observations=observations)


def test_safe_model_request_accepts_only_none_for_automotive_facts() -> None:
    request = SafeModelRequest(
        system_instruction="Summarise",
        safe_text="Call <PERSON>",
        automotive_facts=None,
    )

    assert request.automotive_facts is None
    with pytest.raises(ValidationError):
        SafeModelRequest.model_validate(
            {
                "system_instruction": "Summarise",
                "safe_text": "Call <PERSON>",
                "automotive_facts": {"vin": "private"},
            }
        )
