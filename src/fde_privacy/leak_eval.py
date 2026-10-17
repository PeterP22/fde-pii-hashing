"""Adversarial leak evaluation: what a curious provider can recover from model-facing payloads.

Every record is synthetic. The attacker sees only serialized provider payloads and holds a
candidate dictionary that contains every true value plus distractors.
"""

import argparse
import hashlib
import json
import logging
import random
import re
import secrets
import time
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Final

from fde_privacy.boundary import BoundaryViolation
from fde_privacy.contracts import SessionContext
from fde_privacy.detector import DetectedEntity, detect_pii
from fde_privacy.model_adapters import CapturingMockAdapter
from fde_privacy.pii_demo import PiiDemoError, run_pii_demo
from fde_privacy.token_vault import TokenVault

SEED: Final = 20261017
CUSTOMER_ID_SPACE: Final = 1_000_000
_DIGEST: Final = re.compile(r"\b[0-9a-f]{64}\b")
_FIRST: Final = (
    "Priya", "Daniel", "Mei", "Tom", "Aisha", "Lucas", "Sofia", "Kenji", "Amara", "Oliver",
    "Zara", "Mateo", "Hannah", "Ravi", "Chloe", "Samuel", "Leila", "Noah", "Ingrid", "Omar",
)
_LAST: Final = (
    "Raman", "Okafor", "Chen", "Nguyen", "Haddad", "Silva", "Rossi", "Tanaka", "Mensah",
    "Walsh", "Khan", "Garcia", "Muller", "Patel", "Dubois", "Cohen", "Novak", "Jensen",
    "Ali", "Brennan",
)
TEMPLATES: Final = (
    "{name} has email {email}. The customer's phone number is {phone}. Customer record {cid}.",
    "Follow up with {name}: {email}, mobile {phone}, account {cid}.",
    "Please call {name} on {phone} about order {cid}; the email is {email}.",
    "Refund request from {name} ({email}). Phone {phone}. Record {cid}.",
)


@dataclass(frozen=True, slots=True)
class Person:
    name: str
    email: str
    phone: str
    cid: str

    def values(self) -> tuple[str, ...]:
        return (self.name, self.email, self.phone, self.cid)


@dataclass(slots=True)
class PipelineReport:
    name: str
    requests: int = 0
    blocked: int = 0
    pii_values: int = 0
    raw_leaks: int = 0
    dictionary_reidentified: int = 0
    linkable_pairs: int = 0
    customer_pairs: int = 0
    salt_known_recovered: int = 0
    hashed_customer_ids: int = 0
    log_leaks: int = 0
    served_rate: float = 0.0
    leak_rate: float = 0.0
    linkage_rate: float = 0.0
    seconds: float = 0.0
    leaked_types: dict[str, int] = field(default_factory=dict)


def make_population(size: int, seed: int) -> list[Person]:
    """Deterministic fictional people with unique values."""

    rng = random.Random(seed)
    people: list[Person] = []
    seen: set[str] = set()
    while len(people) < size:
        first, last = rng.choice(_FIRST), rng.choice(_LAST)
        tag = rng.randrange(100, 1000)
        email = f"{first.lower()}.{last.lower()}{tag}@example.com"
        if email in seen:
            continue
        seen.add(email)
        digits = f"{rng.randrange(0, 1000):03d} {rng.randrange(0, 1000):03d}"
        people.append(
            Person(
                name=f"{first} {last}",
                email=email,
                phone=f"+61 4{rng.randrange(10, 100)} {digits}",
                cid=f"CUST-{rng.randrange(CUSTOMER_ID_SPACE):06d}",
            )
        )
    return people


def make_requests(people: Sequence[Person]) -> list[tuple[int, str]]:
    """Each person appears twice, in two different templates, for the linkage attack."""

    requests: list[tuple[int, str]] = []
    for index, person in enumerate(people):
        for offset in (0, 1):
            template = TEMPLATES[(index + offset) % len(TEMPLATES)]
            fields = dict(name=person.name, email=person.email, phone=person.phone, cid=person.cid)
            requests.append((index, template.format(**fields)))
    return requests


def naive_hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def naive_pipeline(text: str, detections: Sequence[DetectedEntity]) -> str:
    """Baseline: hash every detected span with unsalted SHA-256, no policy, no fail-closed."""

    chosen: list[DetectedEntity] = []
    for detection in sorted(detections, key=lambda d: (d.start, -(d.end - d.start))):
        if not chosen or detection.start >= chosen[-1].end:
            chosen.append(detection)
    out = text
    for detection in reversed(chosen):
        out = out[: detection.start] + naive_hash(text[detection.start : detection.end]) + out[
            detection.end :
        ]
    return json.dumps({"safe_text": out})


class _Capture(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(record.getMessage())


def _attack(
    report: PipelineReport,
    people: Sequence[Person],
    requests: Sequence[tuple[int, str]],
    payloads: Sequence[str | None],
    dictionary: dict[str, str],
    salt: str | None,
) -> None:
    labels = ("PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "CUSTOMER_ID")
    pseudonyms: dict[int, list[set[str]]] = {}
    for (owner, _), payload in zip(requests, payloads, strict=True):
        person = people[owner]
        report.requests += 1
        report.pii_values += 4
        if payload is None:
            report.blocked += 1
            continue
        digests = set(_DIGEST.findall(payload))
        recovered = {dictionary[d] for d in digests if d in dictionary}
        report.dictionary_reidentified += len(recovered & set(person.values()))
        for label, value in zip(labels, person.values(), strict=True):
            raw = value in payload or (
                label == "PHONE_NUMBER" and re.sub(r"\D", "", value) in re.sub(r"\D", "", payload)
            )
            report.raw_leaks += raw
            if raw or value in recovered:
                report.leaked_types[label] = report.leaked_types.get(label, 0) + 1
        opaque = digests | set(re.findall(r"\{\{[A-Z_]+:[A-Za-z0-9_-]{24}\}\}", payload))
        pseudonyms.setdefault(owner, []).append(opaque)
        if salt is not None:
            for digest in digests:
                report.hashed_customer_ids += 1
                report.salt_known_recovered += _brute_force_customer_id(digest, salt) == person.cid
    for sets in pseudonyms.values():
        if len(sets) == 2:
            report.customer_pairs += 1
            report.linkable_pairs += bool(sets[0] & sets[1])
    report.served_rate = (report.requests - report.blocked) / report.requests
    report.leak_rate = sum(report.leaked_types.values()) / report.pii_values
    report.linkage_rate = report.linkable_pairs / max(report.customer_pairs, 1)


_SALTED_TABLE: dict[str, dict[str, str]] = {}


def _brute_force_customer_id(digest: str, salt: str) -> str | None:
    """Enumerate the full CUST-000000..999999 space under a leaked salt."""

    if salt not in _SALTED_TABLE:
        salt_bytes = salt.encode()
        _SALTED_TABLE[salt] = {
            hashlib.sha256(f"CUST-{i:06d}".encode() + salt_bytes).hexdigest(): f"CUST-{i:06d}"
            for i in range(CUSTOMER_ID_SPACE)
        }
    return _SALTED_TABLE[salt].get(digest)


def run_eval(size: int = 200, seed: int = SEED, salt_known_attack: bool = True) -> dict[str, object]:
    people = make_population(size, seed)
    distractors = make_population(size * 4, seed + 1)
    requests = make_requests(people)
    dictionary = {naive_hash(v): v for p in [*people, *distractors] for v in p.values()}
    dictionary.update(
        {naive_hash(f"CUST-{i:06d}"): f"CUST-{i:06d}" for i in range(CUSTOMER_ID_SPACE)}
    )

    started = time.perf_counter()
    detections = {text: detect_pii(text) for _, text in requests}
    detect_seconds = time.perf_counter() - started

    capture = _Capture()
    root = logging.getLogger()
    previous_level = root.level
    root.addHandler(capture)
    root.setLevel(logging.DEBUG)
    try:
        naive_start = time.perf_counter()
        naive_payloads: list[str | None] = [
            naive_pipeline(text, detections[text]) for _, text in requests
        ]
        naive = PipelineReport("naive_sha256")
        naive.seconds = time.perf_counter() - naive_start

        salt = secrets.token_hex(16)
        vault = TokenVault()
        fde_payloads: list[str | None] = []
        errors: list[str] = []
        fde_start = time.perf_counter()
        lookup: Callable[[str], tuple[DetectedEntity, ...]] = lambda text: detections[text]  # noqa: E731
        for number, (_, text) in enumerate(requests):
            adapter = CapturingMockAdapter()
            session = SessionContext(
                owner_id="synthetic-owner",
                session_id=f"synthetic-session-{number}",
                issued_at=datetime.now(UTC),
            )
            try:
                run_pii_demo(session, adapter, salt, request=text, detector=lookup, vault=vault)
            except (PiiDemoError, BoundaryViolation) as error:
                errors.append(str(error))
            fde_payloads.append(adapter.last_payload)
        fde = PipelineReport("fde_boundary")
        fde.seconds = time.perf_counter() - fde_start
    finally:
        root.removeHandler(capture)
        root.setLevel(previous_level)

    _attack(naive, people, requests, naive_payloads, dictionary, None)
    _attack(fde, people, requests, fde_payloads, dictionary, salt if salt_known_attack else None)
    all_values = [v for p in people for v in p.values()]
    surfaced = [*capture.messages, *errors]
    fde.log_leaks = sum(any(v in m for v in all_values) for m in surfaced)
    return {
        "seed": seed,
        "people": size,
        "requests": len(requests),
        "attacker_dictionary_size": len(dictionary),
        "detection_seconds": round(detect_seconds, 3),
        "log_records_scanned": len(surfaced),
        "fde_block_reasons": {reason: errors.count(reason) for reason in sorted(set(errors))},
        "pipelines": [asdict(naive), asdict(fde)],
    }


def render_svg(results: dict[str, object]) -> str:
    """Tiny dependency-free grouped bar chart."""

    pipelines = results["pipelines"]
    assert isinstance(pipelines, list)
    naive, fde = pipelines
    rows = (
        ("Re-identified (raw or dictionary)", naive["leak_rate"], fde["leak_rate"]),
        ("Linkable across sessions", naive["linkage_rate"], fde["linkage_rate"]),
        (
            "Customer IDs enumerated",
            naive["leaked_types"].get("CUSTOMER_ID", 0) / max(naive["requests"], 1),
            fde["salt_known_recovered"] / max(fde["hashed_customer_ids"], 1),
        ),
    )
    bar_w, height = 360, 48 + 70 * len(rows)
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="680" height="{height}" '
        'font-family="Helvetica,Arial,sans-serif" font-size="13">',
        '<rect width="100%" height="100%" fill="white"/>',
        '<rect x="250" y="12" width="12" height="12" fill="#9ca3af"/>'
        '<text x="268" y="23">naive SHA-256</text>',
        '<rect x="380" y="12" width="12" height="12" fill="#4f46e5"/>'
        '<text x="398" y="23">fde boundary</text>',
    ]
    for i, (label, a, b) in enumerate(rows):
        y = 48 + 70 * i
        parts.append(f'<text x="10" y="{y + 22}">{label}</text>')
        for j, (value, colour) in enumerate(((a, "#9ca3af"), (b, "#4f46e5"))):
            yy = y + j * 24
            parts.append(
                f'<rect x="250" y="{yy}" width="{max(value * bar_w, 1):.1f}" height="20" '
                f'fill="{colour}"/><text x="{256 + value * bar_w:.1f}" y="{yy + 15}">'
                f"{value:.1%}</text>"
            )
    parts.append("</svg>")
    return "\n".join(parts) + "\n"


def main(argv: Sequence[str] = ()) -> int:
    parser = argparse.ArgumentParser(description="Run the adversarial leak evaluation.")
    parser.add_argument("--people", type=int, default=200)
    parser.add_argument("--out", type=Path, default=Path("results/leak_eval.json"))
    parser.add_argument("--chart", type=Path, default=Path("docs/img/leak_rate.svg"))
    args = parser.parse_args(tuple(argv))
    results = run_eval(args.people)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    args.chart.parent.mkdir(parents=True, exist_ok=True)
    args.chart.write_text(render_svg(results), encoding="utf-8")
    print(json.dumps(results["pipelines"], indent=2))
    return 0


if __name__ == "__main__":
    import sys

    raise SystemExit(main(sys.argv[1:]))
