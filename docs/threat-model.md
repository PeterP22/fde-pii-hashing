# Threat model

This document scopes the demonstration in `fde-pii-hashing`. It is not a compliance assessment.
Every supplied identifier, row, and total is fictional, synthetic-only data.

## Assets

| Asset | Sensitivity | Intended location |
|---|---|---|
| Raw PII | Directly identifying | Trusted first-party input and authorized local processing only |
| Pseudonyms: hashes and tokens | Linkable sensitive data | Minimize; model-facing only when explicitly allowed by policy |
| Confidential business data | Rows, exact totals, prices, margins, performance | Database and first-party response composer only |
| Database infrastructure | SQL, schema, host, IP, credentials, connection string | Database adapter and secret manager only |
| Model request/response | Potential disclosure channel | Closed contracts, validation, approved provider |
| Logs, traces, captures | Durable secondary disclosure channel | Sanitized metadata only; local test capture is ephemeral |
| CI state and secrets | Supply-chain and credential target | Secret-free tests; no provider calls |

## Trust boundaries

1. **Trusted local process:** accepts raw input, runs Presidio, owns policy, token vault, database
   connection, exact totals, response validation, and final composition.
2. **First-party LiteLLM gateway:** an optional named local processor. It may receive raw inbound text
   only so its local pre-call Presidio guardrail can `MASK` or `BLOCK` before capture/upstream.
3. **External model/provider:** untrusted for raw PII, exact business measures, database access, SQL,
   infrastructure details, and secrets. It receives only serialized `SafeModelRequest` fields.
4. **Logs and observability:** separate sinks that can outlive a request. Payloads and exception
   details are not safe by default.
5. **CI and dependency supply chain:** code executes with repository context and can become a
   credential-exfiltration route. Automated tests require no external key or provider.

Authentication is simulated. The command constructs a `SessionContext` directly; it does not verify
an identity token or browser session. The ownership check demonstrates where verified identity would
bind to local token state, not real authentication.

## Threats and controls

| Threat | Current control | Residual risk |
|---|---|---|
| Raw PII reaches a provider | Local detection/policy, span transforms, strict `SafeModelRequest`, exact-value leakage checks | Presidio automated detection has false negatives and false positives |
| High-risk identifier is merely obscured | Credit card, bank, tax, medical, licence, passport, unknown, and low-confidence cases fail closed or need review | Recognizer coverage varies by locale and input quality |
| Token is used by another session | Random token, owner/session binding, expiry, complete-token grammar | Demo session auth is simulated; token theft inside the same process is not solved |
| Hash is treated as anonymous | Documentation calls hashes linkable pseudonyms; fixed salt is not committed | Low-entropy values can be guessed; a stable digest enables correlation |
| Confidential rows or totals enter a prompt | Fixed local query, local aggregation, extra-forbid qualitative schema, forbidden exact-value scan | Policy must evolve when new fields or analyses are added |
| Model smuggles exact values into output | Digit-free response grammar, placeholder allowlist, local substitution only after validation | Qualitative facts and month labels still disclose bounded information |
| Prompt exposes database or network details | Boundary rejects SQL, row fields, connection schemes, database files, and private IPs | Pattern checks are defense-in-depth, not a general information-flow proof |
| Model outage corrupts the user response | Validate before composition; return exact local table plus deterministic fallback | Fallback language is intentionally limited |
| Logs or exceptions retain sensitive values | Privacy-safe errors; no request-body logging; capture server uses memory and test resets | Third-party runtime or platform logs require independent configuration |
| CI sends or stores secrets | Mock/synthetic unit suite; integration path is local; no provider key required | Future workflows must preserve secret-free defaults |
| Dependency or image is malicious | uv lock, version floors, digest-pinned containers, advisory review, optional signature verification | Pins freeze known artifacts but do not prove they are benign |

Automated PII detection is only one layer. Production needs structured-field classification,
outbound allowlists, deterministic policy, contextual deny rules, human review for ambiguous cases,
response validation, monitoring, retention controls, and appropriate data-loss-prevention tooling.

## Local memory and zeroization limitation

“Local” describes the trust boundary, not guaranteed erasure. spaCy/Python local memory does not
guarantee zeroization: immutable strings can be copied, garbage collection is nondeterministic, and
spaCy cached vocabulary may retain tokens in first-party memory after a request. Deleting a Python
reference or expiring a vault entry is not proof that every byte was overwritten.

The token vault is in-memory only. Entries expire 300 seconds after creation and are activity-pruned
during later tokenize or rehydrate operations; there is no background eraser and activity does not
refresh the TTL. If memory zeroization is in the threat model, use process isolation with a short-lived
worker, minimize loaded text, disable core dumps/swapping where appropriate, terminate and restart the
worker after the request, and use an architecture/runtime designed for verifiable secret handling.

## Supply-chain posture

- Presidio 2.2.363 declares `cryptography<47`, while
  [GHSA-537c-gmf6-5ccf](https://github.com/advisories/GHSA-537c-gmf6-5ccf) is patched in cryptography
  48.0.1. Therefore ordinary pip/wheel install is unsupported; the deliberate uv override selects the
  patched version and is covered by Presidio initialization and transformation tests. Remove the uv
  override when upstream supports the patched range.
- pytest is constrained above the patched floor for
  [GHSA-6w46-j5rx-g56g](https://github.com/advisories/GHSA-6w46-j5rx-g56g).
- LiteLLM `1.82.7` and `1.82.8` were compromised and are excluded; the
  [incident record](https://github.com/BerriAI/litellm/issues/24518) describes the event. The current
  LiteLLM 1.92.0 image is pinned by digest.
- [Presidio's anonymizer documentation](https://data-privacy-stack.github.io/presidio/anonymizer/),
  [repository](https://github.com/data-privacy-stack/presidio), and
  [hash operator](https://github.com/data-privacy-stack/presidio/blob/517d13eee659794ed3a55d188752d014be574c2a/presidio-anonymizer/presidio_anonymizer/operators/hash.py)
  define the local primitives. LiteLLM's
  [tutorial](https://docs.litellm.ai/docs/tutorials/presidio_pii_masking) and
  [current guardrail types](https://github.com/BerriAI/litellm/blob/4d339648981ceb8c45df3081b388680084a2206d/litellm/types/guardrails.py)
  show built-in `MASK`/`BLOCK`, not `HASH`.

Cosign verification was not run for this documentation task because Cosign was unavailable. It is an
optional independent check, not an assertion made by this change:

```bash
cosign verify \
  --key https://raw.githubusercontent.com/BerriAI/litellm/0112e53046018d726492c814b3644b7d376029d0/cosign.pub \
  ghcr.io/berriai/litellm:v1.92.0
```

## Non-goals

- Perfect PII detection, anonymization, memory zeroization, or regulatory certification.
- Letting a model generate unrestricted SQL or connect to the database.
- Sending real identifiers, commercial data, credentials, or provider keys.
- Treating a hash, token, mask, or aggregate as automatically anonymous.
- Building a durable token service, real authentication system, or complete observability stack.

## Production replacements

| Demonstration component | Production replacement |
|---|---|
| Injected `SessionContext` | Verified identity/session middleware and authorization policy |
| In-process token vault | Encrypted, access-controlled token service with audit, revocation, and explicit retention |
| Presidio-only free-text scan | Layered structured classification, locale-tuned recognizers, DLP, review, and red-team tests |
| Presidio salted hash | HMAC with managed key, domain separation, rotation, and access policy when deterministic pseudonyms are needed |
| SQLite and CSV | Restricted database role, fixed audited query/service, row/column controls, and approved aggregates |
| Regex/value boundary checks | Typed information-flow boundaries, policy engine, egress proxy, and tested schemas |
| Mock/capture model | Approved provider contract, regional/retention controls, private networking where required, and provider monitoring |
| In-process memory handling | Isolated short-lived workers and restart-based lifecycle when zeroization matters |
| Manual dependency review | Automated SBOM, signature/provenance verification, secret scanning, dependency audit, and incident response |
