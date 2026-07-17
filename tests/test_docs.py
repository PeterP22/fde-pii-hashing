import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
ACHIEVEMENT_DOC = ROOT / "docs" / "what-we-are-achieving.md"
THREAT_MODEL = ROOT / "docs" / "threat-model.md"
DOCS = (README, ACHIEVEMENT_DOC, THREAT_MODEL)


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_readme_has_required_learning_headings() -> None:
    readme = _read(README)
    headings = (
        "What the LLM sees",
        "Masking vs hashing vs tokenization",
        "PII is not the same as confidential business data",
        "Automotive database example",
        "Run without an API key",
        "Optional LiteLLM gateway",
        "Optional real provider",
        "Limitations",
    )

    for heading in headings:
        assert re.search(rf"^#+ {re.escape(heading)}$", readme, re.MULTILINE)


def test_readme_documents_runnable_paths_and_provider_gate() -> None:
    readme = _read(README)
    commands = (
        "uv sync",
        "uv run python -m fde_privacy.pii_demo",
        "uv run python -m fde_privacy.automotive_demo",
        "docker compose up -d --wait",
        "uv run pytest tests/integration/test_litellm_presidio.py -v -m integration",
        "docker compose down",
        "ENABLE_EXTERNAL_MODEL=true",
        "uv run python -m fde_privacy.pii_demo --provider litellm",
    )

    for command in commands:
        assert command in readme

    assert "ENABLE_EXTERNAL_MODEL=false" in readme
    assert "LiteLLM 1.92.0" in readme
    assert "MASK" in readme
    assert "BLOCK" in readme
    assert "not HASH" in readme


def test_docs_include_required_security_warnings() -> None:
    combined = "\n".join(_read(path) for path in DOCS)
    phrases = (
        "ordinary pip/wheel install is unsupported",
        "Presidio 2.2.363",
        "cryptography<47",
        "cryptography 48.0.1",
        "uv override",
        "false negatives",
        "process isolation",
        "300-second",
        "activity-pruned",
        "synthetic-only",
        "1.82.7",
        "1.82.8",
        "cosign verify",
        "0112e53046018d726492c814b3644b7d376029d0",
    )

    for phrase in phrases:
        assert phrase in combined


def test_docs_do_not_describe_the_project_as_a_lab_or_expose_local_paths_or_secrets() -> None:
    combined = "\n".join(_read(path) for path in DOCS)

    assert re.search(r"\blab\b", combined, re.IGNORECASE) is None
    assert "/Users/" not in combined
    assert "C:\\Users\\" not in combined
    assert re.search(r"\bsk-[A-Za-z0-9_-]{16,}\b", combined) is None
    assert "peterpreketes" not in combined.casefold()


def test_docs_links_and_relative_paths_resolve() -> None:
    readme = _read(README)
    assert "[What we are achieving](docs/what-we-are-achieving.md)" in readme
    assert "[Threat model](docs/threat-model.md)" in readme
    assert ACHIEVEMENT_DOC.is_file()
    assert THREAT_MODEL.is_file()
