from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from itertools import count
from re import fullmatch
from threading import Barrier
from traceback import format_exception

import pytest

import fde_privacy.token_vault as token_vault_module
from fde_privacy.contracts import SessionContext
from fde_privacy.token_vault import (
    TokenExpired,
    TokenNotFound,
    TokenOwnershipError,
    TokenValidationError,
    TokenVault,
)

NOW = datetime(2026, 7, 17, 12, 0, tzinfo=UTC)


class MutableClock:
    def __init__(self, now: datetime = NOW) -> None:
        self.now = now

    def __call__(self) -> datetime:
        return self.now


def session(owner_id: str = "owner-1", session_id: str = "session-1") -> SessionContext:
    return SessionContext(owner_id=owner_id, session_id=session_id, issued_at=NOW)


def assert_token_absent(vault: TokenVault, token: str) -> None:
    assert token not in vault._ownership_by_token
    assert all(stored_token != token for _, _, stored_token in vault._entries)


def test_tokenize_creates_opaque_token_that_rehydrates_in_same_session() -> None:
    vault = TokenVault(clock=MutableClock())
    context = session()

    token = vault.tokenize("alice@example.com", "EMAIL_ADDRESS", context)

    assert fullmatch(r"\{\{EMAIL_ADDRESS:[A-Za-z0-9_-]{24}\}\}", token) is not None
    assert vault.rehydrate(token, context) == "alice@example.com"


@pytest.mark.parametrize(
    "other_session",
    [
        session(owner_id="owner-2"),
        session(session_id="session-2"),
    ],
)
def test_rehydrate_rejects_wrong_owner_or_session_with_ownership_error(
    other_session: SessionContext,
) -> None:
    original = "alice@example.com"
    vault = TokenVault(clock=MutableClock())
    token = vault.tokenize(original, "EMAIL_ADDRESS", session())

    with pytest.raises(TokenOwnershipError) as error:
        vault.rehydrate(token, other_session)

    assert original not in str(error.value)
    assert original not in "".join(format_exception(error.value))


def test_token_expires_at_exactly_the_default_three_hundred_seconds() -> None:
    original = "alice@example.com"
    clock = MutableClock()
    vault = TokenVault(clock=clock)
    context = session()
    token = vault.tokenize(original, "EMAIL_ADDRESS", context)
    clock.now += timedelta(seconds=300)

    with pytest.raises(TokenExpired) as error:
        vault.rehydrate(token, context)

    assert original not in str(error.value)
    assert original not in "".join(format_exception(error.value))
    with pytest.raises(TokenNotFound):
        vault.rehydrate(token, context)


def test_tokenize_prunes_expired_entries_and_ownership_rows() -> None:
    clock = MutableClock()
    vault = TokenVault(clock=clock)
    context = session()
    expired_token = vault.tokenize("first@example.com", "EMAIL_ADDRESS", context)
    clock.now += timedelta(seconds=301)

    live_token = vault.tokenize("second@example.com", "EMAIL_ADDRESS", context)

    assert_token_absent(vault, expired_token)
    assert live_token in vault._ownership_by_token
    assert len(vault._entries) == len(vault._ownership_by_token) == 1


def test_rehydrate_prunes_other_expired_entries_and_ownership_rows() -> None:
    clock = MutableClock()
    vault = TokenVault(clock=clock)
    context = session()
    expired_token = vault.tokenize("first@example.com", "EMAIL_ADDRESS", context)
    clock.now += timedelta(seconds=100)
    live_token = vault.tokenize("second@example.com", "EMAIL_ADDRESS", context)
    clock.now += timedelta(seconds=201)

    vault.rehydrate(live_token, context)

    assert_token_absent(vault, expired_token)
    assert live_token in vault._ownership_by_token
    assert len(vault._entries) == len(vault._ownership_by_token) == 1


def test_wrong_owner_of_expired_token_gets_ownership_error_without_retaining_token() -> None:
    clock = MutableClock()
    vault = TokenVault(clock=clock)
    owner = session()
    token = vault.tokenize("alice@example.com", "EMAIL_ADDRESS", owner)
    clock.now += timedelta(seconds=300)

    with pytest.raises(TokenOwnershipError):
        vault.rehydrate(token, session(owner_id="owner-2"))

    assert_token_absent(vault, token)
    with pytest.raises(TokenNotFound):
        vault.rehydrate(token, owner)


@pytest.mark.parametrize(
    "token",
    [
        "not-a-token",
        "{{EMAIL_ADDRESS:short}}",
        "{{lowercase:abcdefghijklmnopqrstuvwx}}",
        "{{EMAIL_ADDRESS:abcdefghijklmnopqrstuvwx}}",
    ],
)
def test_unknown_or_malformed_token_raises_not_found(token: str) -> None:
    with pytest.raises(TokenNotFound):
        TokenVault(clock=MutableClock()).rehydrate(token, session())


def test_presidio_hash_cannot_be_rehydrated_through_vault() -> None:
    presidio_hash = "a" * 64

    with pytest.raises(TokenNotFound):
        TokenVault(clock=MutableClock()).rehydrate(presidio_hash, session())


def test_token_never_contains_original_and_repeated_values_get_distinct_tokens() -> None:
    original = "CUST-123456"
    vault = TokenVault(clock=MutableClock())
    context = session()

    first = vault.tokenize(original, "CUSTOMER_ID", context)
    second = vault.tokenize(original, "CUSTOMER_ID", context)

    assert original not in first
    assert original not in second
    assert first != second
    assert vault.rehydrate(first, context) == original
    assert vault.rehydrate(second, context) == original


def test_tokenize_retries_one_time_collision_without_overwriting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    first_opaque = "a" * 24
    second_opaque = "b" * 24
    generated = iter((first_opaque, first_opaque, second_opaque))
    monkeypatch.setattr(token_vault_module, "token_urlsafe", lambda _: next(generated))
    vault = TokenVault(clock=MutableClock())
    context = session()

    first_token = vault.tokenize("first@example.com", "EMAIL_ADDRESS", context)
    second_token = vault.tokenize("second@example.com", "EMAIL_ADDRESS", context)

    assert first_token == f"{{{{EMAIL_ADDRESS:{first_opaque}}}}}"
    assert second_token == f"{{{{EMAIL_ADDRESS:{second_opaque}}}}}"
    assert vault.rehydrate(first_token, context) == "first@example.com"
    assert vault.rehydrate(second_token, context) == "second@example.com"


def test_concurrent_tokenization_is_distinct_and_rehydrates_correctly(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker_count = 8
    barrier = Barrier(worker_count)
    generated = count()

    def deterministic_token_urlsafe(byte_count: int) -> str:
        assert byte_count == 18
        return f"{next(generated):024d}"

    monkeypatch.setattr(token_vault_module, "token_urlsafe", deterministic_token_urlsafe)
    vault = TokenVault(clock=MutableClock())
    context = session()

    def tokenize_after_barrier(worker_id: int) -> tuple[str, str]:
        value = f"person-{worker_id}@example.com"
        barrier.wait(timeout=5)
        return value, vault.tokenize(value, "EMAIL_ADDRESS", context)

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = [
            executor.submit(tokenize_after_barrier, worker_id)
            for worker_id in range(worker_count)
        ]
        results = [future.result(timeout=5) for future in futures]

    tokens = [token for _, token in results]
    assert len(tokens) == len(set(tokens)) == worker_count
    for value, token in results:
        assert vault.rehydrate(token, context) == value


@pytest.mark.parametrize("value", ["", 123])
def test_tokenize_rejects_invalid_values_with_sanitized_error(value: object) -> None:
    with pytest.raises(TokenValidationError) as error:
        TokenVault(clock=MutableClock()).tokenize(value, "PERSON", session())  # type: ignore[arg-type]

    assert str(error.value) == "value must be a non-empty string"


@pytest.mark.parametrize(
    "entity_type",
    ["", "lowercase_label", "EMAIL><alice@example.com", "_PERSON"],
)
def test_tokenize_rejects_invalid_entity_labels_with_sanitized_error(entity_type: str) -> None:
    original = "alice@example.com"

    with pytest.raises(TokenValidationError) as error:
        TokenVault(clock=MutableClock()).tokenize(original, entity_type, session())

    message = str(error.value)
    assert message == "entity type must be a non-empty uppercase identifier"
    assert original not in message


@pytest.mark.parametrize("ttl", [timedelta(0), timedelta(seconds=-1)])
def test_ttl_must_be_positive(ttl: timedelta) -> None:
    with pytest.raises(TokenValidationError, match="ttl must be positive"):
        TokenVault(ttl=ttl)


def test_clock_must_return_timezone_aware_datetime() -> None:
    naive_clock = MutableClock(datetime(2026, 7, 17, 12, 0))
    vault = TokenVault(clock=naive_clock)

    with pytest.raises(TokenValidationError, match="timezone-aware"):
        vault.tokenize("alice@example.com", "EMAIL_ADDRESS", session())


def test_clock_failure_is_sanitized_without_exception_chaining() -> None:
    original = "alice@example.com"

    def unsafe_clock() -> datetime:
        raise ValueError(original)

    vault = TokenVault(clock=unsafe_clock)

    with pytest.raises(TokenValidationError) as error:
        vault.tokenize(original, "EMAIL_ADDRESS", session())

    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    assert original not in str(error.value)
    assert original not in "".join(format_exception(error.value))
