from collections.abc import Iterator
from dataclasses import FrozenInstanceError
from hashlib import sha256
from re import fullmatch
from traceback import format_exception

import pytest

from fde_privacy.transforms import (
    SpanReplacement,
    TransformValidationError,
    hash_value,
    mask_value,
    transform_text,
)


def test_hash_value_with_fixed_salt_is_deterministic_sha256() -> None:
    value = "CUST-123456"
    salt = "0123456789abcdef"

    first = hash_value(value, salt=salt)
    second = hash_value(value, salt=salt)

    assert first == second
    assert first == sha256((value + salt).encode()).hexdigest()


def test_hash_value_without_salt_uses_fresh_random_salt() -> None:
    value = "CUST-123456"

    assert hash_value(value) != hash_value(value)


@pytest.mark.parametrize("salt", [None, "0123456789abcdef"])
def test_hash_value_is_exactly_lowercase_sha256_hex(salt: str | None) -> None:
    digest = hash_value("CUST-123456", salt=salt)

    assert fullmatch(r"[0-9a-f]{64}", digest) is not None


def test_hash_value_rejects_salt_shorter_than_sixteen_utf8_bytes() -> None:
    with pytest.raises(TransformValidationError, match="salt"):
        hash_value("CUST-123456", salt="1234567890abcde")


def test_hash_value_accepts_salt_with_sixteen_utf8_bytes() -> None:
    salt = "é" * 8

    assert (
        hash_value("CUST-123456", salt=salt) == sha256(("CUST-123456" + salt).encode()).hexdigest()
    )


def test_mask_value_uses_repository_owned_entity_placeholder() -> None:
    assert mask_value("alice@example.com", "EMAIL_ADDRESS") == "<EMAIL_ADDRESS>"


@pytest.mark.parametrize(
    ("call", "sensitive_inputs"),
    [
        (lambda: hash_value(""), ()),
        (lambda: mask_value("", "EMAIL_ADDRESS"), ()),
        (lambda: mask_value("alice@example.com", ""), ("alice@example.com",)),
        (
            lambda: mask_value("alice@example.com", "EMAIL><SECRET"),
            ("alice@example.com", "EMAIL><SECRET"),
        ),
        (
            lambda: mask_value("alice@example.com", "lowercase_label"),
            ("alice@example.com", "lowercase_label"),
        ),
    ],
)
def test_invalid_hash_or_mask_inputs_fail_without_echoing_sensitive_values(
    call: object, sensitive_inputs: tuple[str, ...]
) -> None:
    with pytest.raises(TransformValidationError) as error:
        call()  # type: ignore[operator]

    for sensitive_input in sensitive_inputs:
        assert sensitive_input not in str(error.value)


def test_span_replacement_is_immutable() -> None:
    replacement = SpanReplacement(start=0, end=1, value="<PERSON>")

    with pytest.raises(FrozenInstanceError):
        replacement.end = 2  # type: ignore[misc]


def test_transform_text_applies_multiple_original_spans_right_to_left() -> None:
    text = "Email alice@example.com for customer CUST-123456."
    email = "alice@example.com"
    customer_id = "CUST-123456"

    transformed = transform_text(
        text,
        [
            SpanReplacement(
                start=text.index(email),
                end=text.index(email) + len(email),
                value="<EMAIL_ADDRESS>",
            ),
            SpanReplacement(
                start=text.index(customer_id),
                end=text.index(customer_id) + len(customer_id),
                value="a" * 64,
            ),
        ],
    )

    assert transformed == f"Email <EMAIL_ADDRESS> for customer {'a' * 64}."


def test_transform_text_applies_unordered_adjacent_unicode_spans() -> None:
    text = "A🙂漢B"

    transformed = transform_text(
        text,
        [
            SpanReplacement(start=2, end=4, value="<SECOND>"),
            SpanReplacement(start=0, end=2, value="<FIRST>"),
        ],
    )

    assert transformed == "<FIRST><SECOND>"


def test_invalid_replacements_iterable_does_not_survive_in_traceback() -> None:
    fictional_secret = "alice@example.com"

    class SecretBearingIterable:
        def __iter__(self) -> Iterator[SpanReplacement]:
            raise TypeError(fictional_secret)

    with pytest.raises(TransformValidationError) as error:
        transform_text("safe text", SecretBearingIterable())

    formatted_traceback = "".join(format_exception(error.value))
    assert error.value.__cause__ is None
    assert error.value.__context__ is None
    assert fictional_secret not in formatted_traceback


@pytest.mark.parametrize(
    "replacement",
    [
        SpanReplacement(start=-1, end=2, value="replacement-secret"),
        SpanReplacement(start=0, end=99, value="replacement-secret"),
        SpanReplacement(start=2, end=2, value="replacement-secret"),
        SpanReplacement(start=3, end=2, value="replacement-secret"),
    ],
)
def test_transform_text_rejects_invalid_spans_without_echoing_inputs(
    replacement: SpanReplacement,
) -> None:
    original = "original-sensitive-text"

    with pytest.raises(TransformValidationError) as error:
        transform_text(original, [replacement])

    assert original not in str(error.value)
    assert replacement.value not in str(error.value)


def test_transform_text_rejects_overlapping_spans_without_echoing_inputs() -> None:
    original = "original-sensitive-text"
    replacements = [
        SpanReplacement(start=0, end=8, value="first-secret-replacement"),
        SpanReplacement(start=7, end=12, value="second-secret-replacement"),
    ]

    with pytest.raises(TransformValidationError) as error:
        transform_text(original, replacements)

    message = str(error.value)
    assert original not in message
    assert all(replacement.value not in message for replacement in replacements)
