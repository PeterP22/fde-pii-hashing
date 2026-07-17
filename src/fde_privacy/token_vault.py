"""Session-bound, expiring, reversible PII tokenization."""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from re import fullmatch
from secrets import token_urlsafe
from threading import Lock
from typing import Final

from fde_privacy.contracts import SessionContext

Clock = Callable[[], datetime]

_DEFAULT_TTL: Final = timedelta(seconds=300)
_ENTITY_TYPE_PATTERN: Final = r"[A-Z][A-Z0-9_]*"
_TOKEN_PATTERN: Final = r"\{\{[A-Z][A-Z0-9_]*:[A-Za-z0-9_-]{24}\}\}"


class TokenNotFound(Exception):
    """Raised when a supplied value is not a known vault token."""


class TokenExpired(Exception):
    """Raised when a known token has reached its expiry timestamp."""


class TokenOwnershipError(Exception):
    """Raised when a token belongs to a different owner or session."""


class TokenValidationError(ValueError):
    """Raised when vault configuration or tokenization input is invalid."""


@dataclass(frozen=True, slots=True)
class VaultEntry:
    """One original value and its absolute expiry time."""

    original: str
    expires_at: datetime


def utc_now() -> datetime:
    """Return the current timezone-aware UTC timestamp."""

    return datetime.now(UTC)


class TokenVault:
    """Keep opaque PII tokens reversible only within their owning session."""

    def __init__(self, *, ttl: timedelta = _DEFAULT_TTL, clock: Clock = utc_now) -> None:
        if not isinstance(ttl, timedelta) or ttl <= timedelta(0):
            raise TokenValidationError("ttl must be positive")
        if not callable(clock):
            raise TokenValidationError("clock must be callable")

        self._ttl = ttl
        self._clock = clock
        self._entries: dict[tuple[str, str, str], VaultEntry] = {}
        self._ownership_by_token: dict[str, tuple[str, str]] = {}
        self._lock = Lock()

    def tokenize(self, value: str, entity_type: str, session: SessionContext) -> str:
        """Create a fresh opaque token owned by one user session."""

        self._validate_value(value)
        self._validate_entity_type(entity_type)
        self._validate_session(session)
        expires_at = self._current_time() + self._ttl

        with self._lock:
            token = self._new_token(entity_type)
            while token in self._ownership_by_token:
                token = self._new_token(entity_type)

            ownership = (session.owner_id, session.session_id)
            key = (*ownership, token)
            self._entries[key] = VaultEntry(original=value, expires_at=expires_at)
            self._ownership_by_token[token] = ownership

        return token

    def rehydrate(self, token: str, session: SessionContext) -> str:
        """Restore a known, unexpired token for its owning user session."""

        self._validate_session(session)
        if not isinstance(token, str) or fullmatch(_TOKEN_PATTERN, token) is None:
            raise TokenNotFound("token was not found")

        with self._lock:
            ownership = self._ownership_by_token.get(token)
            if ownership is None:
                raise TokenNotFound("token was not found")
            if ownership != (session.owner_id, session.session_id):
                raise TokenOwnershipError("token does not belong to this session")

            key = (*ownership, token)
            entry = self._entries.get(key)
            if entry is None:
                self._ownership_by_token.pop(token, None)
                raise TokenNotFound("token was not found")

            if self._current_time() >= entry.expires_at:
                self._entries.pop(key, None)
                self._ownership_by_token.pop(token, None)
                raise TokenExpired("token has expired")

            return entry.original

    @staticmethod
    def _new_token(entity_type: str) -> str:
        return f"{{{{{entity_type}:{token_urlsafe(18)}}}}}"

    def _current_time(self) -> datetime:
        timestamp: object | None = None
        try:
            timestamp = self._clock()
        except Exception:
            pass

        normalized: datetime | None = None
        if isinstance(timestamp, datetime):
            try:
                if timestamp.utcoffset() is not None:
                    normalized = timestamp.astimezone(UTC)
            except Exception:
                pass

        if normalized is None:
            raise TokenValidationError("clock must return a timezone-aware datetime")
        return normalized

    @staticmethod
    def _validate_value(value: object) -> None:
        if not isinstance(value, str) or not value:
            raise TokenValidationError("value must be a non-empty string")

    @staticmethod
    def _validate_entity_type(entity_type: object) -> None:
        if not isinstance(entity_type, str) or fullmatch(_ENTITY_TYPE_PATTERN, entity_type) is None:
            raise TokenValidationError("entity type must be a non-empty uppercase identifier")

    @staticmethod
    def _validate_session(session: object) -> None:
        if not isinstance(session, SessionContext):
            raise TokenValidationError("session must be a SessionContext")
