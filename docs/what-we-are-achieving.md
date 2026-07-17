# What we are achieving

`fde-pii-hashing` demonstrates two complementary FDE patterns:

1. Transform PII locally before a provider-facing request is constructible.
2. Keep confidential database results local while asking a model to write only a constrained
   narrative template from qualitative facts.

The result is useful because the learner can inspect the trusted input, local work, exact serialized
model payload, model response, and local final response as separate artifacts.

## File map

| File | Responsibility |
|---|---|
| `src/fde_privacy/contracts.py` | Immutable, extra-forbid inbound, session, `SafeModelRequest`, and narrative contracts |
| `src/fde_privacy/detector.py` | Local Presidio analyzer and synthetic customer-ID recognizer |
| `src/fde_privacy/policy.py` | Closed action policy: tokenize common PII, hash customer IDs, block high-risk or unknown entities |
| `src/fde_privacy/transforms.py` | Presidio masking and salted SHA-256 wrappers plus safe span replacement |
| `src/fde_privacy/token_vault.py` | Owning-session tokenization with a 300-second TTL and activity-pruned in-memory entries |
| `src/fde_privacy/boundary.py` | Builds `SafeModelRequest` only after fail-closed checks for PII, exact values, database details, and malformed placeholders |
| `src/fde_privacy/model_adapters.py` | Deterministic capture mock and disabled-by-default LiteLLM-compatible adapter |
| `src/fde_privacy/pii_demo.py` | End-to-end detect → policy → transform → model → local rehydration walkthrough |
| `src/fde_privacy/automotive/database.py` | Loads synthetic CSV data and runs a fixed parameterized 12-month SQLite query |
| `src/fde_privacy/automotive/contracts.py` | Closed enums, qualitative fact schema, and approved placeholder registry |
| `src/fde_privacy/automotive/analytics.py` | Converts exact totals into directions, month labels, volatility band, trend, and quality flags locally |
| `src/fde_privacy/automotive/narrative.py` | Rejects response digits/unknown placeholders, renders exact tables, and inserts values locally |
| `src/fde_privacy/automotive_demo.py` | End-to-end private analytics walkthrough and deterministic fallback |
| `scripts/generate_synthetic_sales.py` | Reproduces the fictional source dataset deterministically |
| `data/synthetic_automotive_sales.csv` | Synthetic-only row data for 2025-07 through 2026-06 |
| `config/litellm.yaml` | LiteLLM 1.92.0 pre-call Presidio policy: `MASK` common PII and `BLOCK` high-risk entities, not `HASH` |
| `tools/capture_upstream.py` | Local OpenAI-compatible server that keeps captured test state in memory |
| `docker-compose.yml` | Digest-pinned capture, Presidio, and LiteLLM services bound to localhost |
| `tests/` | Contract, leakage, transformation, session, analytics, response, provider-gate, and integration proofs |
| `pyproject.toml` / `uv.lock` | Supported Python graph, deliberate uv override, and exact resolution |

## PII data flow

1. The trusted first-party application receives an `InboundUserRequest` containing raw fictional
   PII and a simulated `SessionContext`.
2. Presidio detects spans locally. Detection metadata can be inspected without printing detected
   substrings.
3. A closed policy assigns `MASK`, `HASH`, `TOKENIZE`, or `BLOCK`. A detection or policy failure
   stops the request.
4. Masking replaces identity with an entity label. Hashing uses the Presidio Anonymizer. Tokenizing
   stores the original only in a session-bound in-memory vault and emits an opaque token.
5. `boundary.py` checks the transformed text and constructs the only type accepted by a model
   adapter: `SafeModelRequest`.
6. The mock or enabled adapter receives only that contract. The response is checked locally for
   original values.
7. Complete, known tokens are rehydrated locally for the owning, unexpired session. Hashes remain
   hashes.

### Before, model payload, final

Before local processing:

```text
Alice Johnson has email alice.johnson@example.com. Customer record CUST-000123.
```

Representative model payload (opaque values vary per run):

```json
{
  "system_instruction": "Summarize only the transformed user text. Do not infer or reconstruct protected values.",
  "safe_text": "{{PERSON:opaque-session-token}} has email {{EMAIL_ADDRESS:opaque-session-token}}. Customer record <64-character-sha256-digest>.",
  "automotive_facts": null
}
```

After the mock response returns and token authorization succeeds locally:

```text
Alice Johnson has email alice.johnson@example.com. Customer record <64-character-sha256-digest>.
```

The provider never receives the name or email. The final response can contain them because local
code restores authorized tokens; the customer ID cannot be restored from its hash.

## Why hashes cannot rehydrate

A cryptographic hash maps an input to a fixed-size digest and does not store a reverse mapping.
`hash_value()` returns only the digest, so there is no vault entry for rehydration. Guessing remains
possible for low-entropy inputs: an attacker can hash candidates with a known salt and compare.

- A random salt makes the same input produce a different digest on each call. This prevents stable
  correlation but also prevents deterministic matching.
- A fixed secret salt makes repeat inputs stable. That creates linkable pseudonyms; disclosure of the
  salt enables offline guessing and the salt must not be committed.
- When production needs deterministic pseudonyms, use HMAC with a managed secret key, explicit key
  identifiers, rotation, access control, and collision/domain separation rules. Presidio hashing is
  retained here to explain its operator, not as a universal identity design.

## Automotive data flow

1. `database.py` imports fictional rows into first-party SQLite and runs fixed, parameterized SQL.
2. The exact 12 monthly totals are rendered directly for the authenticated user. Rows, SQL, database
   host, and exact measures remain local.
3. `analytics.py` derives a closed fact set: month labels, directional sequences, volatility band,
   trend, data-quality flags, and registered placeholders.
4. `boundary.py` rejects exact totals and unexpected fields, then serializes `SafeModelRequest`.
5. The model returns a digit-free JSON template. Local validation rejects digits, unknown or
   unrequested placeholders, and an unapproved caveat.
6. `narrative.py` inserts exact values only after validation and joins the narrative to the exact
   local table. Failure produces a deterministic local fallback.

### Local result, model payload, final

The first-party exact result includes:

```text
2025-07 | 8
2025-12 | 15
2026-06 | 18
```

The model-facing facts include no totals:

```json
{
  "period_start": "2025-07",
  "period_end": "2026-06",
  "peak_month": "2026-06",
  "trough_month": "2025-07",
  "volatility_band": "MODERATE",
  "overall_trend": "GROWING",
  "allowed_placeholders": ["{{PEAK_MONTH_TOTAL}}", "{{TROUGH_MONTH_TOTAL}}", "{{PERIOD_START_TOTAL}}", "{{PERIOD_END_TOTAL}}"]
}
```

The accepted model template contains no digits:

```text
The strongest month reached {{PEAK_MONTH_TOTAL}} vehicle sales.
```

The first-party final response contains the exact table and locally rendered sentence:

```text
The strongest month reached 18 vehicle sales.
```

This is data minimization rather than obfuscation: the model receives only facts needed for its
narrow language task.

## Dependency and runtime choices

uv is canonical. An ordinary pip/wheel install is unsupported while Presidio 2.2.363 declares
`cryptography<47` but the patched dependency is cryptography 48.0.1. The deliberate uv override is
verified by import, initialization, mask/hash, and test coverage; remove it when Presidio supports
the patched range.

The mock path needs no API key. The LiteLLM Docker path proves built-in `MASK` and `BLOCK`; application
hashing happens before the Python model boundary. Real-provider use requires an explicit environment
gate and an approved deployment review.
