# FDE PII and Hashing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and publish `PeterP22/fde-pii-hashing`, a test-first FDE learning repository that proves how local PII transformation and confidential-data minimization keep sensitive values out of external LLM payloads.

**Architecture:** A Python 3.12 application owns two trust-boundary paths. The PII path converts `InboundUserRequest` into `SafeModelRequest` using local Presidio detection plus mask, hash, block, or session tokenization policies. The automotive path queries a synthetic SQLite database locally, returns exact totals directly to the user, sends only a closed qualitative fact schema and approved placeholders to a mock or optional provider, then inserts exact values locally after response validation.

**Tech Stack:** Python 3.12, uv, Presidio Analyzer/Anonymizer 2.2.363, spaCy `en_core_web_sm` 3.8.0, Pydantic 2, SQLite, pytest, Ruff, mypy, Docker Compose, LiteLLM Gateway 1.92.0, GitHub Actions.

**Required skills during execution:** `@superpowers:test-driven-development` for every behavior change, `@verifying-changes` before completion, and `@github:yeet` for the final public publish workflow.

---

## File map

| Path | Responsibility |
|---|---|
| `pyproject.toml` | Python metadata, runtime dependencies, dev tools, test/lint configuration |
| `uv.lock` | Exact resolved Python dependency graph |
| `.python-version` | Select Python 3.12 |
| `.gitignore` | Exclude secrets, local databases, captures, logs, caches, and build output |
| `.env.example` | Document variable names without usable credentials or salts |
| `src/fde_privacy/contracts.py` | Strict inbound, session, safe-model, and response Pydantic contracts |
| `src/fde_privacy/detector.py` | Local Presidio engine and custom automotive identifiers |
| `src/fde_privacy/policy.py` | Entity-to-action rules and high-risk block defaults |
| `src/fde_privacy/transforms.py` | Masking and Presidio hash operations |
| `src/fde_privacy/token_vault.py` | Session-bound, expiring in-memory tokenization |
| `src/fde_privacy/boundary.py` | Construct and validate the only provider-facing request type |
| `src/fde_privacy/model_adapters.py` | Model protocol plus request-capturing mock adapter |
| `src/fde_privacy/pii_demo.py` | Readable end-to-end PII command-line demonstration |
| `src/fde_privacy/automotive/database.py` | Synthetic CSV import and fixed parameterized SQLite query |
| `src/fde_privacy/automotive/analytics.py` | Local totals-to-qualitative-features conversion |
| `src/fde_privacy/automotive/narrative.py` | Response validation, placeholder registry, and local composition |
| `src/fde_privacy/automotive_demo.py` | End-to-end private automotive analytics command |
| `scripts/generate_synthetic_sales.py` | Deterministically create fictional row-level sales data |
| `data/synthetic_automotive_sales.csv` | Public fictional input covering 2025-07 through 2026-06 |
| `tools/capture_upstream.py` | Local OpenAI-compatible capture server for LiteLLM integration proof |
| `config/litellm.yaml` | Local Presidio pre-call mask/block policy and capture upstream model |
| `docker-compose.yml` | Pinned Presidio, LiteLLM, and capture services |
| `tests/` | Unit, integration, leakage, and end-to-end proofs |
| `README.md` | Numbered learning path and exact commands |
| `docs/what-we-are-achieving.md` | Plain-language explanation of each privacy primitive |
| `docs/threat-model.md` | Trust boundaries, assets, threats, and non-guarantees |
| `.github/workflows/tests.yml` | Secret-free unit test, lint, type-check, and dependency-audit CI |

## Fixed defaults

- Token TTL: 300 seconds.
- Presidio minimum confidence: `0.60` for general PII and `0.80` for high-risk identifiers.
- High-risk entities are blocked: credit card, bank number, tax identifiers, Medicare, driver licence, passport.
- Demo clock: `as_of=2026-07-17`, timezone `Australia/Sydney`.
- Automotive period: 2025-07 through 2026-06 inclusive.
- Direction: `UP` when current > previous, `DOWN` when current < previous, otherwise `FLAT`.
- Volatility: coefficient of variation `<0.10` is `LOW`, `<0.25` is `MODERATE`, otherwise `HIGH`.
- Overall trend: compare first three-month mean with final three-month mean; more than +5% is `GROWING`, below -5% is `DECLINING`, otherwise `MIXED`.
- Missing any required month prevents `AutomotiveNarrativeFacts` construction and skips model narration.
- Clean automotive data uses `data_quality_flags=(DataQualityFlag.NONE,)`; `NONE` never enables a model caveat.

### Task 1: Bootstrap the safe Python project

**Files:**
- Create: `pyproject.toml`
- Create: `.python-version`
- Create: `.gitignore`
- Create: `.env.example`
- Create: `src/fde_privacy/__init__.py`
- Create: `src/fde_privacy/automotive/__init__.py`
- Create: `tests/test_smoke.py`

- [ ] **Step 1: Write the failing import test**

```python
def test_package_has_public_version() -> None:
    import fde_privacy

    assert fde_privacy.__version__ == "0.1.0"
```

- [ ] **Step 2: Add project metadata and dependencies**

Create `pyproject.toml` with a `src` layout and these direct dependencies:

```toml
[project]
name = "fde-pii-hashing"
version = "0.1.0"
requires-python = ">=3.12,<3.13"
dependencies = [
  "presidio-analyzer==2.2.363",
  "presidio-anonymizer==2.2.363",
  "pydantic>=2.12.5,<3",
  "python-dotenv>=1.2.2,<2",
  "en-core-web-sm @ https://github.com/explosion/spacy-models/releases/download/en_core_web_sm-3.8.0/en_core_web_sm-3.8.0-py3-none-any.whl",
]

[dependency-groups]
dev = [
  "mypy>=1.17,<2",
  "pip-audit>=2.9,<3",
  "pytest>=8.4,<9",
  "pytest-cov>=6.2,<7",
  "ruff>=0.12,<1",
]

[tool.pytest.ini_options]
testpaths = ["tests"]
markers = ["integration: requires local Docker services"]

[tool.ruff]
line-length = 100
target-version = "py312"

[tool.mypy]
python_version = "3.12"
strict = true
packages = ["fde_privacy"]
```

Create `.python-version` containing `3.12`. Ignore `.env`, `*.db`, `captures/`, `.venv/`, caches, logs, coverage, and build output. `.env.example` contains only `PII_HASH_SALT=replace-with-at-least-16-bytes` and optional provider variable names.

- [ ] **Step 3: Resolve and lock dependencies**

Run: `uv lock`

Expected: `uv.lock` is created; neither LiteLLM 1.82.7 nor 1.82.8 appears.

- [ ] **Step 4: Run the smoke test to verify it fails**

Run: `uv run pytest tests/test_smoke.py -v`

Expected: FAIL because `fde_privacy.__version__` does not exist.

- [ ] **Step 5: Add the minimal package**

```python
"""FDE examples for PII and confidential-data boundaries."""

__version__ = "0.1.0"
```

- [ ] **Step 6: Run quality checks**

Run: `uv run pytest tests/test_smoke.py -v`

Expected: PASS.

Run: `uv run ruff check .`

Expected: `All checks passed!`

- [ ] **Step 7: Commit**

```bash
git add pyproject.toml uv.lock .python-version .gitignore .env.example src tests/test_smoke.py
git commit -m "build: bootstrap fde pii privacy project"
```

### Task 2: Define strict request and session contracts

**Files:**
- Create: `src/fde_privacy/contracts.py`
- Create: `tests/test_contracts.py`

- [ ] **Step 1: Write failing contract tests**

Cover these requirements:

```python
def test_safe_request_rejects_extra_fields() -> None:
    with pytest.raises(ValidationError):
        SafeModelRequest.model_validate(
            {"system_instruction": "Summarise", "safe_text": "<PERSON>", "database_url": "private"}
        )


def test_session_context_is_immutable() -> None:
    context = SessionContext(owner_id="owner-1", session_id="session-1", issued_at=NOW)
    with pytest.raises(ValidationError):
        context.owner_id = "owner-2"
```

- [ ] **Step 2: Run tests to verify failure**

Run: `uv run pytest tests/test_contracts.py -v`

Expected: FAIL with missing imports/classes.

- [ ] **Step 3: Implement Pydantic contracts**

Create immutable `SessionContext`, `InboundUserRequest`, `SafeModelRequest`, `SafeMessage`, and `NarrativeTemplate` models. Set `ConfigDict(extra="forbid", frozen=True)` on every boundary object. `SafeModelRequest` contains only `system_instruction`, `safe_text`, and optional `automotive_facts`.

```python
class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class SessionContext(StrictModel):
    owner_id: str = Field(min_length=1)
    session_id: str = Field(min_length=1)
    issued_at: datetime


class InboundUserRequest(StrictModel):
    text: str = Field(min_length=1)
    session: SessionContext


class SafeModelRequest(StrictModel):
    system_instruction: str
    safe_text: str
    automotive_facts: AutomotiveNarrativeFacts | None = None
```

Use a forward import or separate `automotive/contracts.py` in Task 9 to avoid circular imports; until then type the field as `None` and add it when Task 9 lands.

- [ ] **Step 4: Run tests and type check**

Run: `uv run pytest tests/test_contracts.py -v`

Expected: PASS.

Run: `uv run mypy src/fde_privacy/contracts.py`

Expected: success with no issues.

- [ ] **Step 5: Commit**

```bash
git add src/fde_privacy/contracts.py tests/test_contracts.py
git commit -m "feat: add strict privacy boundary contracts"
```

### Task 3: Detect PII and assign policy actions locally

**Files:**
- Create: `src/fde_privacy/detector.py`
- Create: `src/fde_privacy/policy.py`
- Create: `tests/test_detector.py`
- Create: `tests/test_policy.py`

- [ ] **Step 1: Write failing detection tests**

Use fictional text and assert detections for `PERSON`, `EMAIL_ADDRESS`, `PHONE_NUMBER`, and a custom `CUSTOMER_ID` matching `CUST-[0-9]{6}`. Add an Australian identifier test using a fictional format accepted by the relevant recognizer; never use a real person's value.

- [ ] **Step 2: Run tests to verify failure**

Run: `uv run pytest tests/test_detector.py tests/test_policy.py -v`

Expected: FAIL because the detector and policy do not exist.

- [ ] **Step 3: Implement the detector**

Build `AnalyzerEngine` with `en_core_web_sm`, register a `PatternRecognizer` for `CUSTOMER_ID`, and return a tuple of simple immutable `DetectedEntity` objects rather than leaking Presidio internals through the rest of the application.

```python
@dataclass(frozen=True)
class DetectedEntity:
    entity_type: str
    start: int
    end: int
    score: float


CUSTOMER_ID = PatternRecognizer(
    supported_entity="CUSTOMER_ID",
    patterns=[Pattern(name="customer-id", regex=r"\bCUST-[0-9]{6}\b", score=0.95)],
)
```

- [ ] **Step 4: Implement the closed policy**

Define `PiiAction = BLOCK | MASK | HASH | TOKENIZE`. Default actions:

- `PERSON`, `EMAIL_ADDRESS`, `PHONE_NUMBER`: `TOKENIZE`.
- `CUSTOMER_ID`: `HASH`.
- `CREDIT_CARD`, bank, tax, Medicare, licence, passport: `BLOCK`.
- Unknown detected entities: `BLOCK`.

Reject general detections below 0.60 and high-risk detections below 0.80 from automatic transformation; treat them as blocked/needs-review rather than silently safe.

- [ ] **Step 5: Run tests**

Run: `uv run pytest tests/test_detector.py tests/test_policy.py -v`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add src/fde_privacy/detector.py src/fde_privacy/policy.py tests/test_detector.py tests/test_policy.py
git commit -m "feat: detect pii and apply closed privacy policy"
```

### Task 4: Implement masking and Presidio hashing

**Files:**
- Create: `src/fde_privacy/transforms.py`
- Create: `tests/test_transforms.py`

- [ ] **Step 1: Write failing transformation tests**

Required proofs:

```python
def test_fixed_salt_hash_is_deterministic() -> None:
    assert hash_value("CUST-000123", salt=FIXED_SALT) == hash_value(
        "CUST-000123", salt=FIXED_SALT
    )


def test_random_salt_hash_changes() -> None:
    assert hash_value("CUST-000123") != hash_value("CUST-000123")


def test_mask_uses_entity_label() -> None:
    assert mask_value("alice@example.com", "EMAIL_ADDRESS") == "<EMAIL_ADDRESS>"
```

Also test that fixed salts shorter than 16 bytes fail and that hashes are 64 lowercase hexadecimal characters.

- [ ] **Step 2: Run tests to verify failure**

Run: `uv run pytest tests/test_transforms.py -v`

Expected: FAIL with missing functions.

- [ ] **Step 3: Implement minimal Presidio wrappers**

Use `AnonymizerEngine`, one full-span `RecognizerResult`, and `OperatorConfig`.

```python
def hash_value(value: str, *, salt: str | None = None) -> str:
    params: dict[str, str] = {"hash_type": "sha256"}
    if salt is not None:
        params["salt"] = salt
    result = _ENGINE.anonymize(
        text=value,
        analyzer_results=[RecognizerResult("VALUE", 0, len(value), 1.0)],
        operators={"VALUE": OperatorConfig("hash", params)},
    )
    return result.text
```

Add `mask_value` and a span-safe `transform_text` that applies transformations from right to left so offsets remain valid.

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/test_transforms.py -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/fde_privacy/transforms.py tests/test_transforms.py
git commit -m "feat: demonstrate presidio masking and hashing"
```

### Task 5: Add reversible session tokenization

**Files:**
- Create: `src/fde_privacy/token_vault.py`
- Create: `tests/test_token_vault.py`

- [ ] **Step 1: Write failing vault tests**

Test creation, same-session restoration, wrong-owner denial, wrong-session denial, expiry at 300 seconds, unknown token denial, and that the original value never appears inside the token. Pass a 64-character Presidio hash to `rehydrate` and prove it raises `TokenNotFound`: hashing is not tokenization and cannot use the vault to recover an original.

- [ ] **Step 2: Run tests to verify failure**

Run: `uv run pytest tests/test_token_vault.py -v`

Expected: FAIL with missing vault.

- [ ] **Step 3: Implement the in-memory teaching vault**

Inject a clock for deterministic tests. Store entries under `(owner_id, session_id, token)` and create tokens with `secrets.token_urlsafe(18)` wrapped as `{{ENTITY:<opaque>}}`.

```python
@dataclass(frozen=True)
class VaultEntry:
    original: str
    expires_at: datetime


class TokenVault:
    def __init__(self, *, ttl: timedelta = timedelta(seconds=300), clock: Clock = utc_now): ...
    def tokenize(self, value: str, entity_type: str, session: SessionContext) -> str: ...
    def rehydrate(self, token: str, session: SessionContext) -> str: ...
```

Raise dedicated `TokenNotFound`, `TokenExpired`, and `TokenOwnershipError` exceptions without including original values.

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/test_token_vault.py -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/fde_privacy/token_vault.py tests/test_token_vault.py
git commit -m "feat: add session-bound pii tokenization"
```

### Task 6: Enforce the provider-facing model boundary

**Files:**
- Create: `src/fde_privacy/boundary.py`
- Create: `src/fde_privacy/model_adapters.py`
- Create: `tests/test_boundary.py`

- [ ] **Step 1: Write failing leakage tests**

Assert that raw email, phone, customer ID, database keys (`database_url`, `host`, `sql`, `rows`), IPv4 private addresses, and known exact totals are rejected. Assert that tokens, hashes, entity masks, and approved empty facts pass.

- [ ] **Step 2: Run tests to verify failure**

Run: `uv run pytest tests/test_boundary.py -v`

Expected: FAIL with missing boundary.

- [ ] **Step 3: Implement fail-closed request construction**

`build_safe_request` accepts transformed text, a repository-owned system prompt ID, and optional typed facts. It runs Presidio a second time for prohibited raw PII and recursively checks serialized field names/values against the forbidden contract. It never accepts arbitrary `dict` metadata.

Create a `ModelAdapter` protocol and `CapturingMockAdapter` whose `complete` method stores the exact serialized `SafeModelRequest` and returns a deterministic response.

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/test_boundary.py -v`

Expected: PASS, including assertions against `adapter.last_payload`.

- [ ] **Step 5: Commit**

```bash
git add src/fde_privacy/boundary.py src/fde_privacy/model_adapters.py tests/test_boundary.py
git commit -m "feat: enforce provider-facing safe request boundary"
```

### Task 7: Build the inspectable PII demonstration

**Files:**
- Create: `src/fde_privacy/pii_demo.py`
- Create: `tests/test_pii_demo.py`

- [ ] **Step 1: Write a failing end-to-end test**

Use one fictional request containing a person, email, phone, and `CUST-000123`. Assert the returned demonstration object contains:

- Original input only in the trusted `input` stage.
- Presidio detections without logging original substrings in metadata.
- A 64-character customer hash.
- Session tokens for name/email/phone.
- A model payload with none of the originals.
- A locally rehydrated final response for the same session.
- Rehydration failure for another session.
- No model invocation when local PII analysis raises or cannot initialize.

- [ ] **Step 2: Run the test to verify failure**

Run: `uv run pytest tests/test_pii_demo.py -v`

Expected: FAIL because orchestration is missing.

- [ ] **Step 3: Implement orchestration and CLI**

Expose `run_pii_demo(session, adapter, fixed_salt)` for tests and `main()` for humans. Print labelled JSON stages with explicit `TRUSTED LOCAL` and `MODEL-FACING` headings. Never print the usable fixed salt.

Fail closed around the local analyzer: if detection fails or Presidio cannot initialize, return a safe local error and leave `CapturingMockAdapter.last_payload` unset. Do not treat an analyzer failure as "no PII found."

Run command: `PII_HASH_SALT='development-only-32-byte-salt' uv run python -m fde_privacy.pii_demo`

Expected: the model-facing stage contains tokens/hash only; final local output contains rehydrated fictional values.

- [ ] **Step 4: Run tests and CLI**

Run: `uv run pytest tests/test_pii_demo.py -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/fde_privacy/pii_demo.py tests/test_pii_demo.py
git commit -m "feat: add inspectable pii boundary demo"
```

### Task 8: Create deterministic synthetic automotive data and local query

**Files:**
- Create: `scripts/generate_synthetic_sales.py`
- Create: `data/synthetic_automotive_sales.csv`
- Create: `src/fde_privacy/automotive/database.py`
- Create: `tests/test_automotive_database.py`

- [ ] **Step 1: Define fixed fixture totals in a failing test**

Use these exact monthly sale counts:

```python
EXPECTED = {
    "2025-07": 8,
    "2025-08": 10,
    "2025-09": 9,
    "2025-10": 12,
    "2025-11": 12,
    "2025-12": 15,
    "2026-01": 11,
    "2026-02": 10,
    "2026-03": 13,
    "2026-04": 14,
    "2026-05": 16,
    "2026-06": 18,
}
```

Assert query ordering, exactly twelve months, and no rows outside the requested range.

- [ ] **Step 2: Run tests to verify failure**

Run: `uv run pytest tests/test_automotive_database.py -v`

Expected: FAIL because data/query code is missing.

- [ ] **Step 3: Generate fictional row-level data**

Use a fixed random seed and create one row per sale with fictional `sale_id`, `sale_date`, `dealer_id`, `salesperson_id`, `customer_id`, VIN-like identifier, make/model, `sale_price`, and `margin`. The generator must refuse to overwrite a non-generated file and must write a header noting that all values are synthetic.

Run: `uv run python scripts/generate_synthetic_sales.py`

Expected: 148 fictional rows and the exact monthly distribution above.

- [ ] **Step 4: Implement SQLite loading and parameterized aggregation**

`load_synthetic_database(csv_path, db_path)` creates the table. `query_monthly_sales(connection, as_of=date(2026, 7, 17), timezone="Australia/Sydney")` calculates the previous twelve complete months using parameters, not string interpolation, and returns immutable `MonthlyTotal(month, total)` objects.

- [ ] **Step 5: Run tests**

Run: `uv run pytest tests/test_automotive_database.py -v`

Expected: PASS with the fixed totals.

- [ ] **Step 6: Commit**

```bash
git add scripts/generate_synthetic_sales.py data/synthetic_automotive_sales.csv src/fde_privacy/automotive/database.py tests/test_automotive_database.py
git commit -m "feat: add synthetic automotive sales database"
```

### Task 9: Convert exact totals into a closed qualitative fact schema

**Files:**
- Create: `src/fde_privacy/automotive/contracts.py`
- Create: `src/fde_privacy/automotive/analytics.py`
- Modify: `src/fde_privacy/contracts.py`
- Create: `tests/test_automotive_analytics.py`

- [ ] **Step 1: Write failing analytics and schema tests**

Test the exact enums and array lengths from the design. Test `extra="forbid"`. Verify the fixed dataset yields:

- `period_start="2025-07"`, `period_end="2026-06"`.
- Eleven monthly directions.
- Three quarter directions.
- Peak month `2026-06`; trough month `2025-07`.
- Only registered placeholders.

Assert that a missing month raises `IncompletePeriodError` and no facts object is returned.

- [ ] **Step 2: Run tests to verify failure**

Run: `uv run pytest tests/test_automotive_analytics.py -v`

Expected: FAIL with missing contracts.

- [ ] **Step 3: Implement typed closed facts**

Create string enums `Direction`, `VolatilityBand`, `OverallTrend`, `DataQualityFlag`, and `Placeholder`. Define `AutomotiveNarrativeFacts` with exact tuple lengths where Pydantic supports them, `extra="forbid"`, and validators that months lie inside the period.

Represent clean data as exactly `(DataQualityFlag.NONE,)`. Reject combinations where `NONE` appears with another flag.

- [ ] **Step 4: Implement local feature extraction**

Use only exact totals as local input. Apply the fixed defaults at the top of this plan. Do not include totals, percentages, revenue, margin, dealer identifiers, or source rows in the returned object.

- [ ] **Step 5: Connect facts to `SafeModelRequest`**

Replace the temporary `None` field in `contracts.py` with `AutomotiveNarrativeFacts | None` using a direct import that does not create a cycle.

- [ ] **Step 6: Run tests and inspect serialized output**

Run: `uv run pytest tests/test_automotive_analytics.py tests/test_boundary.py -v`

Expected: PASS; serialized facts contain no numeric totals from `EXPECTED`.

- [ ] **Step 7: Commit**

```bash
git add src/fde_privacy/contracts.py src/fde_privacy/automotive/contracts.py src/fde_privacy/automotive/analytics.py tests/test_automotive_analytics.py tests/test_boundary.py
git commit -m "feat: derive safe automotive narrative facts"
```

### Task 10: Validate model templates and compose exact results locally

**Files:**
- Create: `src/fde_privacy/automotive/narrative.py`
- Create: `tests/test_narrative.py`

- [ ] **Step 1: Write failing response-validation tests**

Test rejection of:

- Any digit in model-generated headline, observations, or caveat.
- Unknown placeholders.
- Registered placeholders not listed in request `allowed_placeholders`.
- More than four observations.
- Exact fixture totals or identifiers.
- A `caveat` when the request facts have no data-quality flags.

Test acceptance of a template such as:

```python
NarrativeTemplate(
    headline="Sales strengthened across the period",
    observations=(
        "The strongest month reached {{PEAK_MONTH_TOTAL}} vehicle sales.",
        "The period ended at {{PERIOD_END_TOTAL}} vehicle sales.",
    ),
)
```

- [ ] **Step 2: Run tests to verify failure**

Run: `uv run pytest tests/test_narrative.py -v`

Expected: FAIL with missing validator/composer.

- [ ] **Step 3: Implement response validation**

Parse model output into `NarrativeTemplate`, scan all strings for `[0-9]`, extract every `{{...}}`, compare with the request's enum registry, and reject before composition. Accept `caveat` only when the associated `AutomotiveNarrativeFacts.data_quality_flags` contains at least one flag other than `DataQualityFlag.NONE`; reject it for the clean `(NONE,)` state.

- [ ] **Step 4: Implement local composition**

`compose_user_response(monthly_totals, template)` renders the exact local table and substitutes only the four registered placeholders from a local mapping. Use `str.replace` only after validating the complete placeholder set. Assert no unresolved `{{` remains.

- [ ] **Step 5: Add deterministic fallback narrative**

When the model is unavailable, generate a local summary directly from totals without pretending it came from an LLM.

- [ ] **Step 6: Run tests**

Run: `uv run pytest tests/test_narrative.py -v`

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/fde_privacy/automotive/narrative.py tests/test_narrative.py
git commit -m "feat: compose confidential sales results locally"
```

### Task 11: Build the end-to-end automotive privacy demonstration

**Files:**
- Create: `src/fde_privacy/automotive_demo.py`
- Create: `tests/test_automotive_demo.py`

- [ ] **Step 1: Write a failing end-to-end leakage test**

Run the complete flow with `CapturingMockAdapter`. Assert:

- Exact totals appear in the trusted local result table.
- None of the twelve exact totals appears as a standalone numeric field in `last_payload`.
- No CSV row, SQL, VIN, customer ID, salesperson ID, dealer ID, private IPv4 address, hostname, database path, price, or margin appears in `last_payload`.
- The final response contains exact peak/end totals after local composition.
- The model payload remains useful enough to produce the expected template.
- A database exception leaves `CapturingMockAdapter.last_payload` unset and returns no model narrative.

- [ ] **Step 2: Run the test to verify failure**

Run: `uv run pytest tests/test_automotive_demo.py -v`

Expected: FAIL because orchestration is missing.

- [ ] **Step 3: Implement orchestration and CLI**

The CLI prints four stages:

1. `LOCAL DATABASE RESULT` - exact monthly table.
2. `LOCAL DERIVED FACTS` - typed qualitative facts.
3. `MODEL-FACING PAYLOAD` - exact serialized safe request.
4. `FINAL FIRST-PARTY RESPONSE` - table plus locally composed narrative.

Run: `uv run python -m fde_privacy.automotive_demo`

Expected: exact totals occur in stages 1 and 4 only.

- [ ] **Step 4: Run all non-Docker tests**

Run: `uv run pytest -m "not integration" -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/fde_privacy/automotive_demo.py tests/test_automotive_demo.py
git commit -m "feat: add private automotive analytics demo"
```

### Task 12: Prove local LiteLLM masking with a capture upstream

**Files:**
- Create: `tools/capture_upstream.py`
- Create: `config/litellm.yaml`
- Create: `docker-compose.yml`
- Create: `tests/integration/test_litellm_presidio.py`

- [ ] **Step 1: Write the skipped/failing integration test**

The first test posts fictional low-risk PII to local LiteLLM, then requests the capture server's last payload. Assert the capture contains `<PERSON>`, `<EMAIL_ADDRESS>`, and `<PHONE_NUMBER>` but not original values.

The second test records the capture server request count, posts a standard fictional/test credit-card value, and asserts LiteLLM returns a guardrail rejection without forwarding the request: the capture count and last payload remain unchanged. Mark both tests `integration` and skip with a clear message when services are absent.

- [ ] **Step 2: Implement the capture upstream**

Use only `http.server`. Support:

- `POST /v1/chat/completions`: record the JSON body in memory and return an OpenAI-compatible deterministic completion.
- `GET /last-request`: return the captured body.
- `GET /request-count`: return the number of captured completion requests.
- `POST /reset`: clear the in-memory capture and counter between tests.
- `GET /health`: return success.

Do not write captured prompts to disk.

- [ ] **Step 3: Configure local services**

Pin:

- `ghcr.io/data-privacy-stack/presidio-analyzer:2.2.363`
- `ghcr.io/data-privacy-stack/presidio-anonymizer:2.2.363`
- `ghcr.io/berriai/litellm:v1.92.0`
- `python:3.12-slim` by digest after resolving the current official digest.

`litellm.yaml` defines one capture model and a `pre_call` Presidio guardrail with `MASK` for person/email/phone and `BLOCK` for credit card and high-risk identifiers. Use service DNS names, never host private IPs.

- [ ] **Step 4: Validate configuration before starting**

Run: `docker compose config`

Expected: valid resolved Compose configuration with no missing variables.

- [ ] **Step 5: Start and test services**

Run: `docker compose up -d --wait`

Expected: all services healthy.

Run: `uv run pytest tests/integration/test_litellm_presidio.py -v -m integration`

Expected: PASS; the low-risk request reaches the capture upstream with masked values only, while the high-risk request is blocked before the capture count can increase.

- [ ] **Step 6: Verify LiteLLM image signature where cosign is available**

Run:

```bash
cosign verify \
  --key https://raw.githubusercontent.com/BerriAI/litellm/0112e53046018d726492c814b3644b7d376029d0/cosign.pub \
  ghcr.io/berriai/litellm:v1.92.0
```

Expected: signature and claims validation succeed. Record the result in `docs/threat-model.md`; do not fail local development only because cosign is not installed.

- [ ] **Step 7: Stop services**

Run: `docker compose down --volumes`

Expected: containers and ephemeral volumes removed.

- [ ] **Step 8: Commit**

```bash
git add tools/capture_upstream.py config/litellm.yaml docker-compose.yml tests/integration/test_litellm_presidio.py
git commit -m "feat: prove litellm presidio mask and block"
```

### Task 13: Add the disabled-by-default optional provider path

**Files:**
- Modify: `src/fde_privacy/model_adapters.py`
- Modify: `src/fde_privacy/pii_demo.py`
- Create: `tests/test_optional_provider.py`
- Modify: `.env.example`

- [ ] **Step 1: Write failing provider-gate tests**

Test that:

- The adapter cannot be constructed when `ENABLE_EXTERNAL_MODEL` is absent or not exactly `true`.
- `LITELLM_BASE_URL` and `LITELLM_MODEL` are required only after explicit enablement.
- The adapter accepts only a validated `SafeModelRequest`, not arbitrary dictionaries or raw inbound requests.
- A fake local HTTP transport receives exactly the serialized safe request and authorization metadata, with no raw PII, exact automotive totals, SQL, rows, database address, or credentials inside the JSON body.
- Provider HTTP errors return a typed unavailable result and never trigger local placeholder composition from unvalidated text.
- The PII CLI keeps the mock adapter as its default and rejects `--provider litellm` unless the environment gate is enabled.

- [ ] **Step 2: Run tests to verify failure**

Run: `uv run pytest tests/test_optional_provider.py -v`

Expected: FAIL because the optional adapter is missing.

- [ ] **Step 3: Implement the explicit environment gate**

Add `LiteLLMAdapter.from_environment()` using the standard library HTTP client or a small injected transport. It must require all of:

- `ENABLE_EXTERNAL_MODEL=true`.
- `LITELLM_BASE_URL` using `http://localhost` or `https://`.
- `LITELLM_MODEL`.
- `LITELLM_API_KEY` when the configured gateway requires one.

The adapter receives a `SafeModelRequest`, builds an OpenAI-compatible request internally, applies a short timeout, and returns text for the existing response validator. It must not accept generic metadata or log request bodies. The mock adapter remains the default everywhere.

Add `--provider mock|litellm` to `pii_demo.py`. Default to `mock`; selecting `litellm` calls `LiteLLMAdapter.from_environment()` and fails with a clear local message before processing input when the gate is disabled.

Update `.env.example` with disabled placeholder values only; keep `ENABLE_EXTERNAL_MODEL=false`.

- [ ] **Step 4: Run the unit proof and optional local capture proof**

Run: `uv run pytest tests/test_optional_provider.py tests/test_boundary.py -v`

Expected: PASS with no network access.

After Task 12's local services are healthy, optionally run:

```bash
ENABLE_EXTERNAL_MODEL=true \
LITELLM_BASE_URL=http://localhost:4000 \
LITELLM_MODEL=capture-model \
uv run python -m fde_privacy.pii_demo --provider litellm
```

Expected: the local capture upstream sees only the already validated safe payload. Do not configure a paid or external provider during automated tests.

- [ ] **Step 5: Commit**

```bash
git add src/fde_privacy/model_adapters.py src/fde_privacy/pii_demo.py tests/test_optional_provider.py .env.example
git commit -m "feat: gate optional litellm provider access"
```

### Task 14: Write the FDE-focused explanation and walkthrough

**Files:**
- Create: `README.md`
- Create: `docs/what-we-are-achieving.md`
- Create: `docs/threat-model.md`
- Modify: `.env.example`

- [ ] **Step 1: Write README acceptance assertions**

Create `tests/test_docs.py` that asserts the README contains the exact headings:

- `What the LLM sees`
- `Masking vs hashing vs tokenization`
- `PII is not the same as confidential business data`
- `Automotive database example`
- `Run without an API key`
- `Optional LiteLLM gateway`
- `Optional real provider`
- `Limitations`

- [ ] **Step 2: Run the test to verify failure**

Run: `uv run pytest tests/test_docs.py -v`

Expected: FAIL because README is absent.

- [ ] **Step 3: Write the documentation**

README order:

1. FDE problem statement.
2. One architecture diagram.
3. Quickstart with mock model.
4. PII demo with before/model-facing/final payloads.
5. Automotive demo with exact local table and reduced model payload.
6. LiteLLM Docker path.
7. Disabled-by-default `--provider litellm` workflow, required environment variables, and the exact local capture command from Task 13.
8. Security and supply-chain notes.
9. Limitations and production substitutions.

`what-we-are-achieving.md` explains each code file and why hashing cannot rehydrate. `threat-model.md` separates PII, pseudonymous identifiers, confidential business data, database infrastructure, model providers, logs, and CI.

- [ ] **Step 4: Run documentation tests**

Run: `uv run pytest tests/test_docs.py -v`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add README.md docs/what-we-are-achieving.md docs/threat-model.md .env.example tests/test_docs.py
git commit -m "docs: explain pii hashing for fde workflows"
```

### Task 15: Add secret-free CI and dependency checks

**Files:**
- Create: `.github/workflows/tests.yml`
- Create: `.github/dependabot.yml`

- [ ] **Step 1: Add the CI workflow**

Use Python 3.12 and uv. CI runs no Docker integration and requires no secrets:

```yaml
name: tests
on:
  push:
  pull_request:

permissions:
  contents: read

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: astral-sh/setup-uv@v6
        with:
          enable-cache: true
      - run: uv sync --locked --all-groups
      - run: uv run ruff check .
      - run: uv run mypy src
      - run: uv run pytest -m "not integration" --cov=src/fde_privacy --cov-report=term-missing
      - run: uv run pip-audit
```

Add a separate least-privilege `gitleaks` job that scans the repository history on both pushes and pull requests. During implementation, replace every action tag, including the Gitleaks action, with the current full commit SHA after verifying it against the official action repository. Add weekly Dependabot checks for GitHub Actions and uv dependencies.

- [ ] **Step 2: Validate the workflow locally**

Run: `uv run ruff check .`

Expected: PASS.

Run: `uv run mypy src`

Expected: PASS.

Run: `uv run pytest -m "not integration" --cov=src/fde_privacy --cov-report=term-missing`

Expected: PASS with meaningful coverage across every boundary module.

Run: `uv run pip-audit`

Expected: no known vulnerabilities in the locked environment. Any finding must be resolved or documented before publication.

Validate the Gitleaks configuration locally when the CLI is available; otherwise inspect the pinned CI job and require its first public run to pass before calling publication complete.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/tests.yml .github/dependabot.yml
git commit -m "ci: add secret-free privacy checks"
```

### Task 16: Final verification and public GitHub publication

**Files:**
- Modify only if verification exposes a defect.

- [ ] **Step 1: Run the complete local verification suite**

Run each command separately:

```bash
uv lock --check
uv run ruff check .
uv run mypy src
uv run pytest -m "not integration" -v
docker compose config
docker compose up -d --wait
uv run pytest tests/integration/test_litellm_presidio.py -v -m integration
docker compose down --volumes
uv run pip-audit
git diff --check
git status --short
```

Expected: every check passes; final `git status --short` is empty.

- [ ] **Step 2: Perform a public-repository leakage review**

Search tracked files for real home paths, API-key prefixes, connection strings, private IP examples, `.env` values, database files, prompt captures, and non-fictional identities. Confirm `git ls-files` contains no `.db`, `.env`, capture, log, or secret file.

- [ ] **Step 3: Review the final diff and history**

Run: `git log --oneline --decorate --reverse`

Expected: small, understandable commits matching the tasks above.

- [ ] **Step 4: Publish using the GitHub workflow**

Invoke `@github:yeet`. Create the public repository `PeterP22/fde-pii-hashing` with description:

> Curious FDE examples for PII detection, hashing, tokenization, and keeping private business data outside LLM prompts.

Do not initialize the remote with a README because the local repository already has history. Add the remote, push `main`, and verify the repository visibility is public.

The local `gh` token was stale during planning. Prefer authenticated SSH if already configured; otherwise complete `gh auth login` interactively immediately before publishing. Never place a token in a command, file, or chat message.

- [ ] **Step 5: Verify the public result**

Confirm:

- Default branch is `main`.
- README renders correctly.
- CI starts and passes.
- The Gitleaks history scan passes.
- No secret scanning alert or dependency alert is present.
- Clone instructions work from a clean temporary directory.

- [ ] **Step 6: Final handoff**

Provide the public repository URL, the two primary run commands, a concise explanation of what the model does and does not see, and any intentionally deferred production improvements.
