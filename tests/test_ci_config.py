import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = ROOT / ".github" / "workflows" / "tests.yml"
DEPENDABOT_PATH = ROOT / ".github" / "dependabot.yml"
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")


def read_required(path: Path) -> str:
    assert path.is_file(), f"required CI configuration is missing: {path.relative_to(ROOT)}"
    return path.read_text(encoding="utf-8")


def action_uses(workflow: str) -> list[tuple[str, str]]:
    uses_lines = re.findall(r"^\s+uses:\s*([^\s#]+)(?:\s+#\s*(.+))?$", workflow, re.MULTILINE)
    assert uses_lines, "workflow must use pinned actions"
    return uses_lines


def test_workflow_is_secret_free_and_least_privilege() -> None:
    workflow = read_required(WORKFLOW_PATH)

    assert re.search(r"^on:\s*\n\s+push:\s*\n\s+pull_request:\s*$", workflow, re.MULTILINE)
    assert re.search(r"^permissions:\s*\n\s+contents:\s+read\s*$", workflow, re.MULTILINE)
    assert "${{ secrets." not in workflow
    assert not re.search(r"^\s+\w[\w-]*:\s+write\s*$", workflow, re.MULTILINE)
    assert "services:" not in workflow


def test_every_action_is_pinned_to_a_full_sha_with_version_comment() -> None:
    workflow = read_required(WORKFLOW_PATH)
    uses = action_uses(workflow)

    assert len(uses) == len(re.findall(r"^\s+uses:", workflow, re.MULTILINE))
    for action_ref, version_comment in uses:
        action, separator, ref = action_ref.partition("@")
        assert action and separator == "@"
        assert FULL_SHA.fullmatch(ref), f"action is not pinned to a full SHA: {action_ref}"
        assert re.search(r"\bv\d+(?:\.\d+){0,2}\b", version_comment or ""), (
            f"action pin lacks a human-readable version comment: {action_ref}"
        )


def test_quality_job_uses_locked_uv_checks_without_integration_or_audit_exemptions() -> None:
    workflow = read_required(WORKFLOW_PATH)

    assert 'python-version: "3.12"' in workflow
    assert "enable-cache: true" in workflow
    expected_commands = (
        "uv sync --locked --all-groups",
        "uv run ruff check .",
        "uv run mypy src",
        'uv run pytest -m "not integration" '
        "--cov=src/fde_privacy --cov-report=term-missing",
        "uv run pip-audit",
    )
    for command in expected_commands:
        assert command in workflow
    assert "--ignore-vuln" not in workflow


def test_gitleaks_job_scans_full_history_with_verified_binary() -> None:
    workflow = read_required(WORKFLOW_PATH)
    gitleaks_job = re.search(r"^  gitleaks:\s*$(.*)\Z", workflow, re.MULTILINE | re.DOTALL)

    assert gitleaks_job is not None
    job = gitleaks_job.group(1)
    assert "fetch-depth: 0" in job
    assert re.search(r"GITLEAKS_VERSION:\s*\"?\d+\.\d+\.\d+\"?", job)
    assert re.search(r"GITLEAKS_SHA256:\s*[0-9a-f]{64}", job)
    assert "sha256sum --check" in job
    assert 'archive_name="gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"' in job
    assert "/${archive_name}" in job
    assert "releases/download/v${GITLEAKS_VERSION}/${archive}" not in job
    assert 'gitleaks git --redact --verbose --log-opts="--all" .' in job


def test_dependabot_checks_actions_and_uv_weekly() -> None:
    dependabot = read_required(DEPENDABOT_PATH)

    assert re.search(r"^version:\s*2\s*$", dependabot, re.MULTILINE)
    assert dependabot.count('directory: "/"') == 2
    assert dependabot.count('interval: "weekly"') == 2
    assert set(re.findall(r'package-ecosystem:\s*"([^"]+)"', dependabot)) == {
        "github-actions",
        "uv",
    }
    limits = [int(value) for value in re.findall(r"open-pull-requests-limit:\s*(\d+)", dependabot)]
    assert len(limits) == 2
    assert all(1 <= limit <= 10 for limit in limits)
