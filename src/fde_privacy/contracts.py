"""Strict request and session contracts for privacy boundaries."""

from datetime import datetime
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from fde_privacy.automotive.contracts import AutomotiveNarrativeFacts

NonEmptyString = Annotated[str, Field(min_length=1)]


class StrictModel(BaseModel):
    """Immutable model that rejects fields outside its declared contract."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class SessionContext(StrictModel):
    owner_id: str = Field(min_length=1)
    session_id: str = Field(min_length=1)
    issued_at: datetime


class InboundUserRequest(StrictModel):
    text: str = Field(min_length=1)
    session: SessionContext


class SafeModelRequest(StrictModel):
    system_instruction: str = Field(min_length=1)
    safe_text: str = Field(min_length=1)
    automotive_facts: AutomotiveNarrativeFacts | None = None


class SafeMessage(StrictModel):
    role: Literal["system", "user"]
    content: str = Field(min_length=1)


class NarrativeTemplate(StrictModel):
    headline: str = Field(min_length=1)
    observations: tuple[NonEmptyString, ...] = Field(min_length=1, max_length=4)
    caveat: str | None = Field(default=None, min_length=1)
