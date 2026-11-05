# Module 11 — Proof-Carrying Findings & Chain of Custody

**Module ID:** `proof-carrying-findings`  
**Document type:** Proposed innovation specification  
**Status:** Proposed — not yet implemented  
**Priority:** P0 for the hackathon differentiator; additive and non-breaking  
**Audience:** Implementing engineer, demo owner, submission reviewer  
**Dependencies:** `core/evidence/evidence_vault.py`, `core/findings/finding_verifier.py`, `engine/graph.py`, `core/reporting/report_generator.py`, `apps/api/`, `integrations/bifrost/`, `integrations/tavily/`  
**Last reviewed:** 2026-11-05

---

## 1. Purpose

This document specifies an additive capability for ARGUS: **Proof-Carrying Findings** backed by a **tamper-evident Chain of Custody**.

ARGUS already stores SHA-256 hashes of evidence artifacts. That proves an artifact was not changed after capture. It does **not** prove:

- that the executor actually ran the action,
- that the evidence was not inserted, removed, or reordered,
- that a finding was derived from that evidence,
- which model decision and research sources produced the action.

The Chain of Custody closes that gap. Every confirmed finding ships with a **Proof Capsule** — a self-contained bundle containing the finding, executor-attested ledger records, Merkle inclusion proofs, artifact hashes, Bifrost model provenance, and Tavily research citations. A judge can verify the capsule offline with a standalone verifier and a verdict of `PROVEN`, `UNPROVEN`, or `FAILED`.

The one-line thesis:

> **ARGUS does not just report findings. It gives you a court-admissible receipt for every action the agent took.**

This is the hackathon differentiator. Most autonomous pentesting demos say “the AI found a bug.” ARGUS says “the AI found a bug, and here is cryptographic proof you can verify without trusting the AI.”

---

## 2. Why Now — Research and Market Context

The 2026 state of the art in agent security has moved from autonomy to **verifiable agent behaviour**.

| Source | Key finding | Implication for ARGUS |
|---|---|---|
| **PCM: Proof-Carrying Messages** (arXiv, Oct 2026) | On 926 real agent messages containing 712 lies, models of six deployed agent protocols accepted **70.8–100%**; proof-carrying messages accepted **1.4%**. A claim resting only on the agent’s own report is never proven. | Adopt the T1/T2 distinction and Merkle-backed inclusion proofs for findings. |
| **Agent Flight Recorder** (2026) | Merkle proofs make agent audit trails tamper-evident and verifiable without trusting the operator. | Store an append-only Merkle ledger per assessment. |
| **IETF Agent Audit Trail draft** | Standard logging format includes a Merkle audit path proving record inclusion. | Use a canonical record format with `seq`, `hash`, and `audit_path`. |
| **OWASP Top 10 for Agentic Applications 2026** | Agent goal hijacking and tool misuse are top risks. | Only executor-attested `T2` records may support a confirmed finding. |
| **Bifrost MCP Gateway** (2026) | Bifrost supports MCP client/server modes, tool filtering, and audit trails. | Record Bifrost model/provider/fallback metadata in the capsule; optional MCP exposure later. |
| **MCP tool-poisoning research** (2026) | Tool descriptions and indirect prompt injection can steer agents without executing a malicious tool. | Reinforces the need for executor-attested evidence, not agent self-report. |
| **Tavily** | Real-time search and extraction for AI agents with cited sources. | Record source URLs and snippet hashes as research provenance in the capsule. |

The hackathon timeline (per the official event page): problem statements live **1 Nov 2026**, prototypes due **15 Nov 2026**, judging **29 Nov 2026**. Bifrost is the title partner; Tavily is the track partner. This feature uses both meaningfully and can be shipped in 3–4 focused days.

---

## 3. Problem Statement

Autonomous pentesting has a trust problem:

1. **The agent can hallucinate.** An LLM may claim a port is open, a service version is vulnerable, or a tool returned a proof that never existed.
2. **The agent can be prompt-injected.** Target content or tool descriptions can steer the planner toward out-of-scope or fabricated actions.
3. **The agent’s own logs are not evidence.** A log written by the same process that made the claim can be edited, reordered, or fabricated.
4. **Judges and clients cannot verify after the demo.** They have to trust the demo machine, the agent, and the report.

ARGUS’s existing zero-hallucination invariant is a strong start: a finding is not confirmed without an evidence artifact and a verification method. But the evidence chain is still local, mutable, and not independently verifiable.

The missing primitive is a **chain of custody**: an append-only, executor-written record of every action, with short cryptographic proofs that a finding is included in that record.

---

## 4. Goals and Non-Goals

### 4.1 Goals

- G1: Record every executed tool action in an append-only Merkle ledger.
- G2: Distinguish `T2` executor-attested records from `T1` agent-reported claims.
- G3: Require a valid `T2` ledger proof before a finding can be `CONFIRMED`.
- G4: Produce a self-contained Proof Capsule for every confirmed finding.
- G5: Verify a capsule offline with no ARGUS runtime and no trust in the agent.
- G6: Include Bifrost model provenance and Tavily research provenance in the capsule.
- G7: Detect tampering with any artifact, record, order, or root.
- G8: Keep the existing 215-test suite green and preserve current behaviour when the feature is disabled.

### 4.2 Non-Goals

- N1: Do not prove that the agent’s intent was benign. A compromised agent can still request any action the scope allows.
- N2: Do not replace the existing SHA-256 evidence vault. This is an additive layer.
- N3: Do not provide confidentiality. Capsules contain redacted evidence only.
- N4: Do not implement a public transparency log or external timestamp anchor in the MVP.
- N5: Do not require a blockchain, a new database, or a new runtime dependency.
- N6: Do not make every historical test depend on the new layer. The feature must be optional and additive.

---

## 5. Threat Model and Trust Boundaries

### 5.1 Adversary

The adversary may:

- control the LLM planner through prompt injection,
- fabricate tool results or findings in the agent’s own report,
- edit, delete, reorder, or insert ledger records,
- modify artifacts on disk,
- replay a capsule with altered fields,
- claim a `T1` record is `T2`.

### 5.2 Trusted components

- **The executor** that runs the tool and writes the ledger record.
- **The ledger append path** that assigns `seq` and timestamps.
- **The verifier** that recomputes hashes and inclusion proofs.
- **The scope policy engine** that authorizes the action before execution.

The agent/planner is **untrusted**. Its own claims are `T1` and never sufficient for a confirmed finding.

### 5.3 What this does not solve

- A compromised executor can lie. The executor is the trusted computing base for this feature.
- A compromised verifier can lie. The verifier is intentionally small and stdlib-only for auditability.
- A stolen private key can forge signatures if Ed25519 signing is enabled. The MVP uses Merkle proofs plus local trust; signatures are a future extension.
- A capsule proves that a record existed at verification time, not that the target is still vulnerable.

---

## 6. Core Concepts

### 6.1 T1 vs T2 records

| Tier | Writer | Meaning | May support a confirmed finding? |
|---|---|---|---|
| `T1` | Planner/agent | “The agent says it ran this.” | **No** |
| `T2` | Executor | “The executor actually ran this and observed this output.” | **Yes** |

The executor writes the ledger after the subprocess completes. The planner never writes ledger records. This is the central invariant.

### 6.2 Append-only Merkle ledger

Each assessment has one ledger, stored as `artifacts/{assessment_id}/ledger.jsonl`. Each line is a canonical JSON record with a monotonically increasing `seq`.

A Merkle tree is built over the leaf hashes. The tree head is:

```json
{
  "tree_size": 8,
  "root_hash": "sha256:...",
  "head_timestamp": "2026-11-05T12:00:00Z"
}
```

An inclusion proof for record `seq` contains the sibling hashes from the leaf to the root. Changing any record changes the root, and the proof fails.

### 6.3 Proof Capsule

A `.argusproof` file is a ZIP archive:

```
manifest.json          # finding, tree head, proofs, Bifrost/Tavily provenance, verdict
ledger.jsonl           # full canonical ledger (optional but recommended)
artifacts/             # redacted raw evidence files named by evidence_id
  ev-....raw
```

`manifest.json` is the signed/verifiable core. `ledger.jsonl` allows the verifier to reconstruct the tree and check that the claimed `tree_size` is consistent.

### 6.4 Offline verifier

`scripts/verify_proof.py` is a standalone, stdlib-only verifier. It:

1. Opens the capsule ZIP.
2. Validates `manifest.json` shape and version.
3. Rebuilds the Merkle tree from `ledger.jsonl`.
4. Checks the recomputed root against the manifest root.
5. For each evidence item, recomputes the artifact SHA-256 and compares it to the manifest and the ledger record.
6. Verifies each inclusion proof against the recomputed root.
7. Checks that every required evidence record is `tier == "T2"`.
8. Prints `PROVEN`, `UNPROVEN`, or `FAILED` with reasons.

The verifier does not import ARGUS, does not need network access, and does not trust the agent.

---

## 7. Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│ UnTrusted Planner (LLM via Bifrost)                                  │
│  - proposes actions                                                  │
│  - may hallucinate or be prompt-injected                             │
└───────────────────────────────┬──────────────────────────────────────┘
                                │ ActionProposal
                                ▼
┌──────────────────────────────────────────────────────────────────────┐
│ Deterministic Policy Engine                                          │
│  - scope, port, action-category, redirect, embedded-URL checks       │
└───────────────────────────────┬──────────────────────────────────────┘
                                │ approved action
                                ▼
┌──────────────────────────────────────────────────────────────────────┐
│ Tool Executor (trusted for T2 attestation)                           │
│  - runs argv, captures stdout/stderr/exit code                       │
│  - writes redacted artifact to EvidenceVault                         │
│  - appends T2 record to Merkle ledger                                │
└───────────────────────────────┬──────────────────────────────────────┘
                                │ evidence_id + ledger record + proof
                                ▼
┌──────────────────────────────────────────────────────────────────────┐
│ Finding Verifier                                                     │
│  - requires valid artifact hash + valid ledger inclusion proof        │
│  - refuses CONFIRMED for T1-only claims                              │
└───────────────────────────────┬──────────────────────────────────────┘
                                │ confirmed finding
                                ▼
┌──────────────────────────────────────────────────────────────────────┐
│ Proof Capsule Builder                                                │
│  - finding + ledger head + inclusion proofs + artifacts              │
│  - Bifrost model trace + Tavily research citations                   │
└───────────────────────────────┬──────────────────────────────────────┘
                                │ .argusproof
                                ▼
┌──────────────────────────────────────────────────────────────────────┐
│ Offline Verifier (stdlib only)                                       │
│  - recomputes hashes/root/proofs                                     │
│  - verdict: PROVEN | UNPROVEN | FAILED                               │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 8. Data Contracts

### 8.1 Ledger record

```json
{
  "version": "argus.ledger.v1",
  "seq": 7,
  "assessment_id": "asm-20261105-abc123",
  "timestamp": "2026-11-05T12:00:00Z",
  "tier": "T2",
  "event": "tool_result",
  "action_id": "act-007",
  "tool": "nuclei",
  "target_host": "192.168.100.5",
  "target_port": 8080,
  "arguments_sha256": "sha256:...",
  "exit_code": 0,
  "stdout_sha256": "sha256:...",
  "stderr_sha256": "sha256:...",
  "evidence_ids": ["ev-20261105120000-abc12345"],
  "bifrost": {
    "provider": "anthropic",
    "model": "claude-3-5-sonnet-20241022",
    "fallback_used": false,
    "latency_ms": 812,
    "prompt_tokens": 1420,
    "completion_tokens": 210
  },
  "research": [
    {
      "source_id": "tavily-cve-2021-41773-0",
      "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
      "snippet_sha256": "sha256:..."
    }
  ]
}
```

Rules:

- `seq` is assigned by the ledger append path, not the caller.
- `tier` must be `T2` for executor-written records.
- `arguments_sha256` hashes the canonical approved arguments, not raw secrets.
- `stdout_sha256` and `stderr_sha256` hash the redacted output actually stored in the vault.
- `evidence_ids` must reference artifacts stored by the same executor action.
- `bifrost` and `research` are optional and may be empty for non-model actions.

### 8.2 Tree head

```json
{
  "tree_size": 8,
  "root_hash": "sha256:...",
  "head_timestamp": "2026-11-05T12:00:00Z"
}
```

### 8.3 Inclusion proof

```json
{
  "leaf_index": 7,
  "tree_size": 8,
  "audit_path": [
    "sha256:...",
    "sha256:...",
    "sha256:..."
  ]
}
```

### 8.4 Capsule manifest

```json
{
  "capsule_version": "argus.proof.v1",
  "created_at": "2026-11-05T12:00:00Z",
  "assessment_id": "asm-20261105-abc123",
  "finding": {
    "finding_id": "F-001",
    "title": "CVE-2021-41773 path traversal",
    "severity": "HIGH",
    "confidence": "CONFIRMED",
    "affected_asset": "192.168.100.5:8080",
    "evidence_ids": ["ev-20261105120000-abc12345"]
  },
  "ledger": {
    "tree_size": 8,
    "root_hash": "sha256:...",
    "head_timestamp": "2026-11-05T12:00:00Z"
  },
  "proofs": [
    {
      "evidence_id": "ev-20261105120000-abc12345",
      "leaf_index": 7,
      "tree_size": 8,
      "audit_path": ["sha256:...", "sha256:...", "sha256:..."]
    }
  ],
  "artifacts": [
    {
      "evidence_id": "ev-20261105120000-abc12345",
      "path": "artifacts/ev-20261105120000-abc12345.raw",
      "sha256": "sha256:..."
    }
  ],
  "bifrost": {
    "provider": "anthropic",
    "model": "claude-3-5-sonnet-20241022",
    "fallback_used": false,
    "latency_ms": 812
  },
  "research": [
    {
      "source_id": "tavily-cve-2021-41773-0",
      "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
      "snippet_sha256": "sha256:..."
    }
  ]
}
```

### 8.5 Verdict

```json
{
  "verdict": "PROVEN",
  "checks": [
    {"name": "capsule_schema", "ok": true},
    {"name": "ledger_root", "ok": true},
    {"name": "inclusion_proofs", "ok": true},
    {"name": "artifact_hashes", "ok": true},
    {"name": "t2_attestation", "ok": true}
  ],
  "reasons": []
}
```

Verdict semantics:

| Verdict | Meaning | Judge action |
|---|---|---|
| `PROVEN` | All required checks pass; every required record is `T2`. | Accept the finding. |
| `UNPROVEN` | Missing proof, `T1`-only evidence, or a check could not be performed. | Treat as testimony, not proof. |
| `FAILED` | Malformed capsule, hash mismatch, invalid proof, missing artifact, or altered root. | Reject the finding. |

---

## 9. Merkle Specification

### 9.1 Canonical JSON

Records are canonicalized with:

```python
json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
```

No whitespace, no trailing newline, no NaN/Infinity. Reject non-finite numbers and duplicate keys at the verifier boundary.

### 9.2 Hashing

Domain-separated hashing prevents leaf/internal-node confusion:

```python
LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


def leaf_hash(canonical_bytes: bytes) -> bytes:
    return hashlib.sha256(LEAF_PREFIX + canonical_bytes).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(NODE_PREFIX + left + right).digest()
```

Hashes in JSON are lowercase hex with a `sha256:` prefix.

### 9.3 Tree construction

- Leaves are ordered by `seq`, starting at 0.
- Build pairwise; when a level has an odd number of nodes, **promote the last node unchanged** to the next level.
- The root is the single node at the top.
- The empty tree root is `sha256(b"")`; an empty ledger cannot produce a confirmed finding.

The implementation must use the same construction for proof generation and verification. Tests must cover tree sizes 1, 2, 3, 5, 8, 16, and 17.

### 9.4 Inclusion proof generation

For leaf index `i` in a tree of size `n`:

1. Start at the leaf level.
2. At each level, if the sibling exists, append the sibling hash to the proof.
3. Move to the parent; for odd promotion, a promoted node has no sibling at that level.
4. Stop at the root.

The proof records `leaf_index`, `tree_size`, and the ordered `audit_path`.

### 9.5 Inclusion proof verification

The `audit_path` contains **only levels where a sibling exists**. A promoted node has no sibling, so the verifier must skip that level rather than consume a proof element.

```python
def verify_inclusion(
    leaf: bytes,
    index: int,
    tree_size: int,
    audit_path: list[bytes],
    root: bytes,
) -> bool:
    if index < 0 or index >= tree_size:
        return False

    h = leaf
    idx = index
    level_size = tree_size
    siblings = iter(audit_path)

    while level_size > 1:
        if idx % 2 == 0 and idx + 1 < level_size:
            sibling = next(siblings)
            h = node_hash(h, sibling)
        elif idx % 2 == 1:
            sibling = next(siblings)
            h = node_hash(sibling, h)
        # else: last node promoted, no sibling at this level

        idx //= 2
        level_size = (level_size + 1) // 2

    return next(siblings, None) is None and h == root
```

The exact implementation must match the tree construction; the test suite is the authority.

### 9.6 Replay and ordering

- `seq` must be contiguous and match the ledger line index.
- Duplicate `seq` values must be rejected.
- A missing `seq` must be rejected.
- Reordering records changes the root and fails verification.
- The verifier must not accept a proof whose `tree_size` differs from the reconstructed ledger size.

---

## 10. Integration Plan

### 10.1 New files

| File | Responsibility |
|---|---|
| `core/evidence/merkle_log.py` | Canonicalization, leaf/node hashes, tree build, proof generation/verification. |
| `core/evidence/ledger.py` | Append-only JSONL ledger per assessment, `append()`, `head()`, `proof()`, `records()`. |
| `core/evidence/proof_capsule.py` | Build and verify capsules; ZIP packaging. |
| `scripts/verify_proof.py` | Standalone stdlib-only offline verifier CLI. |
| `tests/unit/test_merkle_log.py` | Tree/proof/tamper unit tests. |
| `tests/unit/test_proof_capsule.py` | Capsule build/verify/tamper tests. |
| `tests/integration/test_proof_api.py` | API proof endpoint tests. |

### 10.2 Modified files

| File | Change |
|---|---|
| `core/evidence/evidence_vault.py` | No breaking change; expose stable artifact path/content lookup for the capsule builder. |
| `engine/graph.py` (`execute_tool_node`) | After `store_artifact`, append a `T2` ledger record with the artifact hash, action, exit code, Bifrost metadata (if available), and research refs (if available). |
| `engine/graph.py` (`verify_finding_node`) | Require a valid ledger proof for the evidence ID before confirming. Keep the existing vault integrity check. |
| `core/findings/finding_verifier.py` | Accept an optional proof reference and expose `proof_id` / `ledger_root` on the finding. |
| `core/reporting/report_generator.py` | Add a “Chain of Custody” section with root, proof IDs, and capsule filename. |
| `apps/api/routers/assessments.py` | Add `GET /api/v1/assessments/{id}/proof?finding_id=...` returning the capsule (JSON or ZIP). |
| `apps/api/static/index.html` | Show a “Proof Verified” badge, “Download Proof Capsule” link, and a “Tamper test” result panel. |
| `packages/contracts/findings.py` | Add optional `proof` fields; do not make them mandatory for existing tests. |
| `core/config.py` | Add `ENABLE_PROOF_LEDGER` (default `true` in new code, overridable for tests) and `PROOF_VERIFIER_PATH`. |

### 10.3 Execution flow

1. Planner proposes an action.
2. Policy engine approves or denies.
3. Executor runs the action.
4. Executor stores the redacted artifact in the vault.
5. Executor appends a `T2` record to the ledger with the artifact hash and action metadata.
6. The ledger returns `seq`, `leaf_hash`, and `inclusion_proof`.
7. The state stores `evidence_id`, `ledger_seq`, `ledger_root`, and `inclusion_proof`.
8. Finding verification requires both the vault integrity check and the ledger inclusion proof.
9. The report/API builds a capsule for every confirmed finding.

### 10.4 Backward compatibility

- The ledger is created lazily per assessment.
- If `ENABLE_PROOF_LEDGER=false`, behaviour is unchanged and capsules are not produced.
- Existing tests that construct findings without ledger proofs continue to pass when the flag is off.
- New tests enable the flag and assert the stronger invariant.
- Do not make `proof` a required field in the shared `Finding` contract until the feature is fully adopted.

---

## 11. Sponsor Provenance

### 11.1 Bifrost

The capsule records the model path that produced the action:

- provider and model,
- fallback used (boolean),
- latency in milliseconds,
- prompt/completion/total tokens,
- request timestamp.

This turns Bifrost from “we called an LLM” into “here is the exact model decision path behind the finding.” The existing `BifrostTelemetry` model in `integrations/bifrost/telemetry.py` is the source of truth.

### 11.2 Tavily

The capsule records research provenance:

- source ID,
- URL,
- title,
- snippet SHA-256,
- query,
- retrieval timestamp.

This turns Tavily from “we searched the web” into “here is the exact advisory that justified the finding, and it is included in the proof.”

### 11.3 Scope attestation

The capsule may also include the normalized scope document hash and the policy decision ID for the executed action. This lets a verifier confirm the action was authorized under the same scope that was presented to the judge.

---

## 12. API Contracts

### 12.1 Build a capsule

```
POST /api/v1/assessments/{assessment_id}/proof
Content-Type: application/json

{"finding_id": "F-001"}
```

Response: `202` with `{"proof_id": "...", "status": "BUILDING"}` or `200` with the capsule if built synchronously for the MVP.

### 12.2 Download a capsule

```
GET /api/v1/assessments/{assessment_id}/proof/{proof_id}
Accept: application/zip
```

Response: `200` with `application/zip`, filename `{assessment_id}-{finding_id}.argusproof`.

### 12.3 Verify a capsule

```
POST /api/v1/proof/verify
Content-Type: application/zip
```

Response:

```json
{
  "verdict": "PROVEN",
  "checks": [{"name": "ledger_root", "ok": true}],
  "reasons": []
}
```

The API verification is a convenience for the dashboard. The authoritative verifier is `scripts/verify_proof.py`, which works offline.

### 12.4 Report integration

`GET /api/v1/assessments/{id}/report?format=md|html|pdf` includes:

- the ledger root,
- the proof IDs for each confirmed finding,
- the capsule filename,
- a “Verify offline” command.

---

## 13. Dashboard Integration

Add a compact “Chain of Custody” panel to `apps/api/static/index.html`:

- **Ledger root** (short hash + copy button).
- **Records** count and last append time.
- **Per-finding proof badge**: `PROVEN`, `UNPROVEN`, `FAILED`.
- **Download Proof Capsule** button.
- **Tamper test** button: creates a copy of the capsule, flips one byte, runs the verifier, and displays the red failure. This is a demo-only action and must never modify the original capsule.

Optional visual: a small Merkle tree diagram with the finding's leaf highlighted and the audit path in a different colour. Keep it CSS/SVG-only; no new JS dependency.

---

## 14. Three-Minute Demo Script

1. **Setup (20s).** Start the compose stack, open the dashboard, show the authorized mock lab and the simulation badge.
2. **Run (60s).** Launch an assessment; show the planner, policy gate, executor, evidence vault, and confirmed finding.
3. **Proof (40s).** Open the finding, show the ledger root and proof badge, click **Download Proof Capsule**.
4. **Verify (30s).**
   ```bash
   python scripts/verify_proof.py F-001.argusproof
   # VERIFIED — finding F-001 is backed by 3 T2 executor records
   # Ledger root: sha256:...
   # Bifrost: claude-3-5-sonnet, fallback=false, 812ms
   # Tavily: nvd.nist.gov CVE-2021-41773
   ```
5. **Tamper (30s).**
   ```bash
   python scripts/verify_proof.py tampered.argusproof
   # FAILED — leaf 2 hash mismatch; ledger root changed
   ```
6. **Close (10s).** “Don’t trust the agent. Verify the proof.”

The demo must work fully in simulation mode and must never claim a live assessment when simulation is enabled.

---

## 15. Implementation Plan

### Day 1 — Merkle ledger

- [ ] Implement `core/evidence/merkle_log.py` with canonical JSON, leaf/node hashing, tree build, inclusion proof, and verification.
- [ ] Implement `core/evidence/ledger.py` with append-only JSONL, contiguous `seq`, head, and proof lookup.
- [ ] Add unit tests for tree sizes 1, 2, 3, 5, 8, 16, 17.
- [ ] Add tamper tests: modified leaf, missing leaf, reordered records, invalid proof, wrong root.

### Day 2 — Capsule and verifier

- [ ] Implement `core/evidence/proof_capsule.py`.
- [ ] Implement `scripts/verify_proof.py` with no ARGUS imports and no network.
- [ ] Add capsule tests: valid, missing artifact, tampered artifact, `T1`-only evidence, malformed manifest.
- [ ] Add a fixture capsule generated from a real assessment.

### Day 3 — Integration and demo

- [ ] Append `T2` records in `execute_tool_node`.
- [ ] Require ledger proof in `verify_finding_node`.
- [ ] Add proof fields to the finding/report contracts.
- [ ] Add the API proof endpoints.
- [ ] Add the dashboard panel and tamper-test button.
- [ ] Add the report “Chain of Custody” section.
- [ ] Update `README.md` and `docs/`.

### Day 4 — Buffer and polish

- [ ] Record the 3-minute demo.
- [ ] Add `tests/integration/test_proof_api.py`.
- [ ] Run the full suite, `ruff`, and `mypy`.
- [ ] Write the submission blurb and judge instructions.

**Minimum viable version (1 day):** a hash chain + `verify_proof.py` + CLI demo.  
**Recommended version (3–4 days):** Merkle ledger + capsule + dashboard + report integration.

---

## 16. Test Plan

### 16.1 Unit tests — Merkle

- `test_single_leaf_root`
- `test_even_tree_proof`
- `test_odd_tree_promotion`
- `test_inclusion_proof_all_leaves`
- `test_tampered_leaf_fails`
- `test_missing_leaf_fails`
- `test_reordered_records_fail`
- `test_wrong_tree_size_fails`
- `test_invalid_index_rejected`
- `test_canonical_json_is_stable`

### 16.2 Unit tests — capsule

- `test_capsule_round_trip`
- `test_capsule_verifies_all_artifacts`
- `test_capsule_rejects_tampered_artifact`
- `test_capsule_rejects_tampered_record`
- `test_capsule_rejects_t1_only_evidence`
- `test_capsule_rejects_missing_artifact`
- `test_capsule_rejects_malformed_manifest`
- `test_capsule_rejects_wrong_root`

### 16.3 Integration tests

- `test_confirmed_finding_has_ledger_proof`
- `test_finding_without_proof_is_not_confirmed`
- `test_report_contains_ledger_root_and_proof_ids`
- `test_api_returns_capsule`
- `test_api_verify_returns_proven`
- `test_e2e_lab_capsule_verifies_offline`
- `test_tamper_demo_returns_failed`

### 16.4 Regression tests

- The existing 215 tests must pass with `ENABLE_PROOF_LEDGER=false`.
- The full suite must pass with `ENABLE_PROOF_LEDGER=true`.
- `ruff check .` and `mypy core engine integrations packages apps` must remain clean.

---

## 17. Acceptance Criteria

- [ ] Every executed tool action produces a `T2` ledger record.
- [ ] Every confirmed finding has at least one valid inclusion proof.
- [ ] A finding with only `T1` evidence cannot be `CONFIRMED`.
- [ ] A proof capsule verifies offline with `scripts/verify_proof.py`.
- [ ] Editing any artifact, record, or proof causes `FAILED`.
- [ ] The report includes the ledger root and proof IDs.
- [ ] The dashboard exposes a download link and a proof badge.
- [ ] The demo runs in simulation mode and is labelled as simulation.
- [ ] The existing test suite, lint, and type checks remain green.
- [ ] The capsule includes Bifrost and Tavily provenance when available.

---

## 18. Security Considerations

- **Never let the planner write ledger records.** The append path is executor-only.
- **Redact before hashing.** Hash the redacted artifact, not raw secrets.
- **Reject non-canonical JSON.** Duplicate keys, NaN/Infinity, and trailing whitespace must fail.
- **Reject path traversal.** Artifact paths inside the capsule must be relative and must not contain `..`.
- **Bound capsule size.** Enforce a maximum number of records/artifacts and a maximum decompressed size to prevent zip bombs.
- **Do not trust zip metadata.** Verify `path` against the manifest and the artifact hash.
- **Use constant-time comparison** for digest equality where practical.
- **Do not log private keys or secrets.** The MVP does not require signing keys.
- **Clearly label simulation.** A capsule from a simulated run must contain `simulation: true` and the verifier must display it.
- **Fail closed.** If the ledger is missing or inconsistent, do not confirm the finding.

---

## 19. Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Merkle proof implementation bug | Medium | High | Property tests for many tree sizes; compare against a naive reference implementation. |
| Integration breaks existing tests | Medium | High | Feature flag off by default for legacy paths; add new tests with the flag on. |
| Capsule too large | Low | Medium | Include only finding-linked artifacts; enforce size limits; redact. |
| Judge cannot run the verifier | Low | High | Stdlib-only CLI; include a prebuilt demo capsule and a one-line command. |
| Agent still fabricates a `T2` record | Low | High | Ledger append path is executor-only; planner has no ledger handle. |
| Time overrun | Medium | High | Ship the 1-day hash-chain MVP first; upgrade to Merkle if time permits. |
| Scope creep into MCP/Next.js | Medium | High | Do not start secondary ideas until the capsule demo is green. |

---

## 20. Backward Compatibility

- `ENABLE_PROOF_LEDGER` defaults to `true` for new assessments and can be disabled for legacy tests.
- Existing `EvidenceArtifact` and `Finding` contracts gain optional fields only.
- Existing report formats remain valid; the Chain of Custody section is additive.
- Existing API endpoints are unchanged; new proof endpoints are additive.
- The ledger lives beside the existing `metadata.jsonl` and does not replace it.

---

## 21. Future Extensions

1. **Ed25519 signatures** over the tree head, with a public key pinned in the report. Adds non-repudiation at the cost of one dependency.
2. **ARGUS MCP server** exposing `launch_assessment`, `get_findings`, and `verify_proof` as MCP tools; connect through Bifrost’s MCP gateway.
3. **MCP tool-poisoning scanner** as a new target adapter, using the same T2 evidence path.
4. **External transparency anchor** (e.g., a public log or timestamp service) for the tree head.
5. **Capsule diffing** to compare two assessments and show what changed.
6. **Judge-facing verification page** that accepts a `.argusproof` upload and verifies it in the browser.

---

## 22. Open Questions

- Should the MVP include Ed25519 signing, or is Merkle + SHA-256 sufficient for the demo?
- Should the capsule include the full ledger or only the finding-linked records?
- Should the ledger be per assessment or global with an assessment prefix?
- How should Bifrost telemetry be threaded into the executor when the model call happens in the planner rather than the tool?
- Should the dashboard tamper test run server-side or client-side?

---

## 23. References

- **Hackathon event page:** <https://www.geekroom.co.in/event/global-ai-hackathon>
- **PCM: A Proof-Carrying Message Protocol for Verifiable Multi-Agent Communication** (arXiv, Oct 2026): <https://arxiv.org/html/2610.39109v1>
- **Agent Flight Recorder: Tamper-Evident Audit Trails** (2026): <https://binds.ch/papers/flightrecorder2026.pdf>
- **IETF Agent Audit Trail draft:** <https://datatracker.ietf.org/doc/draft-sharif-agent-audit-trail/>
- **OWASP Top 10 for Agentic Applications 2026:** <https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/>
- **Bifrost MCP overview:** <https://docs.getbifrost.ai/mcp/overview>
- **Bifrost AI Gateway:** <https://www.getmaxim.ai/>
- **Tavily:** <https://tavily.com/>
- **MCP tool poisoning:** <https://invariantlabs.ai/blog/mcp-security-notification-tool-poisoning-attacks>
- **OWASP MCP tool poisoning:** <https://community.owasp.org/attacks/MCP_Tool_Poisoning>

---

## 24. Summary

Proof-Carrying Findings turn ARGUS’s strongest existing property — evidence over hallucination — into a visible, portable, offline-verifiable artifact.

The implementation is small enough to ship in 3–4 days, uses only the Python standard library for the core proof layer, reinforces Bifrost and Tavily usage, and gives judges a memorable 30-second tamper test.

**Do not trust the agent. Verify the proof.**
