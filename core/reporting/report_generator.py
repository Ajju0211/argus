"""Markdown, HTML, and PDF report generation for ARGUS assessments.

The generator is intentionally state-driven: it never invents findings or services.
Every claim in the report traces back to the assessment state, a parsed observation,
or an evidence ID whose SHA-256 is re-verified against the evidence vault.
"""

import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from core.evidence.evidence_vault import EvidenceVault
from core.evidence.redactor import SecretRedactor
from core.reporting.pdf_exporter import export_markdown_to_pdf, render_styled_html
from packages.contracts.scope import ScopeDocument

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_SEVERITY_RANK = {
    "INFORMATIONAL": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def _text(value: Any, default: str = "") -> str:
    """Converts arbitrary state values into a safe single-line string."""
    if value is None:
        return default
    return str(value).strip() or default


def _cell(value: Any, default: str = "—") -> str:
    """Escapes a value for a Markdown table cell."""
    rendered = _text(value, default).replace("|", "\\|").replace("\n", " ")
    return rendered or default


def _confidence(finding: dict[str, Any]) -> str:
    """Reads the confidence value from either the canonical or legacy field."""
    return _text(finding.get("confidence") or finding.get("status"), "UNKNOWN").upper()


def _summary(state: dict[str, Any]) -> dict[str, Any]:
    completion = state.get("completion") or {}
    return completion if isinstance(completion, dict) else {}


def _duration_seconds(state: dict[str, Any]) -> str:
    started_raw = _text(state.get("started_at"))
    if not started_raw:
        return "N/A"
    try:
        started = datetime.fromisoformat(started_raw)
        if started.tzinfo is None:
            started = started.replace(tzinfo=UTC)
        elapsed = max(0.0, (datetime.now(UTC) - started).total_seconds())
        return f"{elapsed:.1f}s"
    except ValueError:
        return "N/A"


class ReportGenerator:
    """Builds client-ready assessment reports from verified state."""

    def __init__(self, redactor: SecretRedactor | None = None) -> None:
        self._redactor = redactor or SecretRedactor()

    # ------------------------------------------------------------------
    # Evidence integrity
    # ------------------------------------------------------------------
    def _evidence_record(
        self,
        state: dict[str, Any],
        evidence_id: str,
        vault: EvidenceVault | None,
        cache: dict[str, tuple[str, str, str]],
    ) -> tuple[str, str, str]:
        """Returns ``(integrity_status, sha256, detail)`` for an evidence ID."""
        if evidence_id in cache:
            return cache[evidence_id]

        ref: dict[str, Any] = next(
            (
                item
                for item in state.get("evidence_refs", [])
                if item.get("evidence_id") == evidence_id
            ),
            {},
        )
        recorded_sha = _text(ref.get("sha256"), "unknown")

        if vault is None:
            result = (
                "UNVERIFIED",
                recorded_sha,
                "No evidence vault was available for verification",
            )
        else:
            try:
                artifact = vault.get_artifact(_text(state.get("assessment_id")), evidence_id)
            except (ValueError, OSError, TypeError):
                artifact = None

            if artifact is None:
                result = (
                    "MISSING",
                    recorded_sha,
                    "No matching artifact metadata was found in the evidence vault",
                )
            else:
                try:
                    valid, detail = vault.verify_integrity(
                        _text(state.get("assessment_id")), evidence_id
                    )
                except (ValueError, OSError, TypeError) as exc:
                    valid, detail = False, f"Integrity check failed: {exc}"
                status = "VERIFIED" if valid else "INTEGRITY FAILURE"
                result = (status, artifact.sha256, detail)

        cache[evidence_id] = result
        return result

    @staticmethod
    def _all_evidence_ids(findings: list[dict[str, Any]], state: dict[str, Any]) -> list[str]:
        ids: list[str] = []
        for finding in findings:
            ids.extend(str(eid) for eid in finding.get("evidence_ids", []) if eid)
        ids.extend(
            str(ref["evidence_id"])
            for ref in state.get("evidence_refs", [])
            if ref.get("evidence_id")
        )
        return list(dict.fromkeys(ids))

    # ------------------------------------------------------------------
    # Report sections
    # ------------------------------------------------------------------
    def _render_header(self, state: dict[str, Any], simulated: bool) -> list[str]:
        assessment_id = _text(state.get("assessment_id"), "unknown-assessment")
        outcome = _text(_summary(state).get("outcome"), _text(state.get("status"), "UNKNOWN"))
        generated = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
        lines = [
            "# ARGUS Security Assessment Report",
            "",
            f"> **Assessment ID:** `{assessment_id}`  ",
            f"> **Outcome:** **{outcome}**  ",
            f"> **Generated:** {generated}  ",
            f"> **Report mode:** **{'SIMULATED' if simulated else 'LIVE'}**",
            "",
        ]
        if simulated:
            lines.extend(
                [
                    "> [!WARNING]",
                    (
                        "> **SIMULATION MODE:** This report contains simulated tool output. "
                        "It must not be presented as a live security assessment."
                    ),
                    "",
                ]
            )
        return lines

    def _render_executive_summary(
        self,
        state: dict[str, Any],
        findings: list[dict[str, Any]],
        statuses: dict[str, tuple[str, str, str]],
    ) -> list[str]:
        confirmed = [f for f in findings if _confidence(f) == "CONFIRMED"]
        verified_confirmed = [
            f
            for f in confirmed
            if any(
                statuses.get(str(eid), ("", "", ""))[0] == "VERIFIED"
                for eid in f.get("evidence_ids", [])
            )
        ]
        severity_counts = {name: 0 for name in _SEVERITY_RANK}
        for finding in confirmed:
            severity = _text(finding.get("severity"), "INFORMATIONAL").upper()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        if confirmed:
            overall = max(
                (_text(f.get("severity"), "INFORMATIONAL").upper() for f in confirmed),
                key=lambda sev: _SEVERITY_RANK.get(sev, 0),
            )
        else:
            overall = "NONE (no confirmed findings)"

        summary = _text(_summary(state).get("summary"), "No completion summary was produced.")
        lines = [
            "## 1. Executive Summary",
            "",
            f"**Overall risk posture:** **{overall}**",
            "",
            (
                f"- Confirmed findings: **{len(confirmed)}** "
                f"({len(verified_confirmed)} with vault-verified evidence)"
            ),
            f"- Potential / other findings: **{len(findings) - len(confirmed)}**",
            f"- Discovered assets: **{len(state.get('discovered_assets', []))}**",
            f"- Discovered services: **{len(state.get('discovered_services', []))}**",
            f"- Assessment summary: {summary}",
            "",
            "| Severity | Confirmed findings |",
            "|---|---:|",
        ]
        for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"):
            lines.append(f"| {severity} | {severity_counts.get(severity, 0)} |")
        lines.append("")
        return lines

    def _render_scope(self, state: dict[str, Any], scope: ScopeDocument | None) -> list[str]:
        lines = [
            "## 2. Assessment Scope & Authorization",
            "",
            f"- Scope ID: `{_text(state.get('scope_id'), 'unknown')}`",
            f"- Scope schema version: `{_text(state.get('scope_version'), 'unknown')}`",
            f"- Scope snapshot SHA-256: `{_text(state.get('scope_snapshot_hash'), 'unknown')}`",
        ]
        if scope is None:
            lines.extend(
                [
                    "- Full normalized scope document was not supplied to the report generator.",
                    "",
                ]
            )
            return lines

        lines.extend(
            [
                f"- Authorized hosts: {', '.join(f'`{h}`' for h in scope.targets.allowed_hosts) or '—'}",
                f"- Authorized subnets: {', '.join(f'`{s}`' for s in scope.targets.allowed_subnets) or '—'}",
                f"- Denied hosts: {', '.join(f'`{h}`' for h in scope.targets.denied_hosts) or '—'}",
                f"- Allowed ports: {', '.join(f'`{p}`' for p in scope.ports.allowed_ports) or '—'}",
                f"- Denied ports: {', '.join(f'`{p}`' for p in scope.ports.denied_ports) or '—'}",
                f"- Allowed protocols: {', '.join(scope.protocols.allowed) or '—'}",
                f"- Denied protocols: {', '.join(scope.protocols.denied) or '—'}",
                f"- Allowed action categories: {', '.join(scope.actions.allowed_categories) or '—'}",
                f"- Prohibited action categories: {', '.join(scope.actions.prohibited_categories) or '—'}",
                f"- Redirect policy: `{scope.network_policy.redirect_policy}`",
            ]
        )

        chain = scope.authorized_chain
        if chain.enabled:
            lines.append(f"- Multi-step chain: **AUTHORIZED** (maximum {chain.max_steps} steps)")
            for index, step in enumerate(chain.allowed_steps, start=1):
                lines.append(
                    f"  {index}. `{step.action_category}` on "
                    f"hosts {', '.join(step.allowed_hosts) or 'any in-scope host'} / "
                    f"ports {', '.join(str(p) for p in step.allowed_ports) or 'any allowed port'}"
                )
        else:
            lines.append("- Multi-step chain: **NOT AUTHORIZED**")
        lines.append("")
        return lines

    def _render_methodology(self, state: dict[str, Any]) -> list[str]:
        lines = [
            "## 3. Methodology",
            "",
            "1. The scope document was validated and its SHA-256 snapshot recorded.",
            "2. Every proposed action passed the deterministic policy gate before execution.",
            "3. Tool commands were dispatched as validated argv arrays, never through a shell.",
            "4. Raw output was redacted, stored in the evidence vault, and hashed with SHA-256.",
            "5. Findings were promoted only after independent evidence integrity verification.",
            "6. Completion was evaluated deterministically against the declared objective.",
            "",
            "### Executed Actions",
            "",
        ]
        actions = state.get("executed_actions", [])
        if not actions:
            lines.append("No tool actions were executed.")
        else:
            lines.extend(
                [
                    "| Action ID | Tool | Category | Target | Port | Step |",
                    "|---|---|---|---|---:|---:|",
                ]
            )
            for action in actions:
                lines.append(
                    "| "
                    + " | ".join(
                        [
                            f"`{_cell(action.get('action_id'))}`",
                            _cell(action.get("tool_name")),
                            _cell(action.get("action_category")),
                            _cell(action.get("target_host")),
                            _cell(action.get("target_port")),
                            _cell(action.get("step_index")),
                        ]
                    )
                    + " |"
                )
        lines.append("")
        return lines

    def _render_attack_surface(self, state: dict[str, Any]) -> list[str]:
        lines = ["## 4. Discovered Attack Surface", "", "### Assets", ""]
        assets = state.get("discovered_assets", [])
        if assets:
            lines.extend(f"- `{_text(asset)}`" for asset in assets)
        else:
            lines.append("No assets were discovered.")

        lines.extend(["", "### Services", ""])
        services = state.get("discovered_services", [])
        if services:
            lines.extend(
                [
                    "| Port | Protocol | Service | Product | Version |",
                    "|---:|---|---|---|---|",
                ]
            )
            for service in services:
                lines.append(
                    "| "
                    + " | ".join(
                        [
                            _cell(service.get("port")),
                            _cell(service.get("protocol"), "tcp"),
                            _cell(service.get("service")),
                            _cell(service.get("product")),
                            _cell(service.get("version")),
                        ]
                    )
                    + " |"
                )
        else:
            lines.append("No services were discovered.")
        lines.append("")
        return lines

    def _render_findings_table(
        self,
        findings: list[dict[str, Any]],
        statuses: dict[str, tuple[str, str, str]],
    ) -> list[str]:
        lines = [
            "## 5. Verified Findings",
            "",
        ]
        if not findings:
            lines.extend(
                [
                    (
                        "No security findings were recorded. A negative scan is **not** proof "
                        "that the target is free of vulnerabilities; see the limitations section."
                    ),
                    "",
                ]
            )
            return lines

        lines.extend(
            [
                "| # | Severity | Confidence | Title | CVE | CVSS | Verification method | Evidence SHA-256 |",
                "|---:|---|---|---|---|---|---|---|",
            ]
        )
        for index, finding in enumerate(findings, start=1):
            text_blob = f"{_text(finding.get('title'))} {_text(finding.get('description'))}"
            cves = ", ".join(dict.fromkeys(match.upper() for match in _CVE_RE.findall(text_blob)))
            evidence_ids = [str(eid) for eid in finding.get("evidence_ids", []) if eid]
            hashes = ", ".join(
                statuses.get(eid, ("", "unknown", ""))[1][:16] for eid in evidence_ids
            )
            lines.append(
                "| "
                + " | ".join(
                    [
                        str(index),
                        f"**{_cell(finding.get('severity'))}**",
                        _cell(_confidence(finding)),
                        _cell(finding.get("title")),
                        _cell(cves or None),
                        _cell(finding.get("cvss") or finding.get("cvss_score")),
                        _cell(finding.get("verification_method")),
                        f"`{_cell(hashes or '—')}`",
                    ]
                )
                + " |"
            )
        lines.append("")
        return lines

    def _render_finding_details(
        self,
        findings: list[dict[str, Any]],
        statuses: dict[str, tuple[str, str, str]],
    ) -> list[str]:
        lines = ["## 6. Detailed Findings", ""]
        if not findings:
            lines.extend(["No detailed findings to report.", ""])
            return lines

        for index, finding in enumerate(findings, start=1):
            severity = _text(finding.get("severity"), "INFORMATIONAL").upper()
            confidence = _confidence(finding)
            title = _text(finding.get("title"), "Untitled finding")
            lines.extend(
                [
                    f"### 6.{index} [{severity}] {title}",
                    "",
                    f"- Finding ID: `{_text(finding.get('finding_id'), 'unknown')}`",
                    f"- Confidence: **{confidence}**",
                    f"- Affected asset: `{_text(finding.get('affected_asset'), 'unknown')}`",
                    f"- Affected service: {_text(finding.get('affected_service'), 'unknown')}",
                    f"- Description: {_text(finding.get('description'), '—')}",
                    f"- Verification method: {_text(finding.get('verification_method'), '—')}",
                    f"- Impact: {_text(finding.get('impact'), '—')}",
                    f"- Remediation: {_text(finding.get('remediation'), '—')}",
                    "- Reproduction steps:",
                    "",
                    "```text",
                    _text(finding.get("reproduction_steps"), "No reproduction steps recorded."),
                    "```",
                    "",
                    "**Cryptographic evidence:**",
                    "",
                    "| Evidence ID | SHA-256 | Integrity | Artifact |",
                    "|---|---|---|---|",
                ]
            )
            evidence_ids = [str(eid) for eid in finding.get("evidence_ids", []) if eid]
            if not evidence_ids:
                lines.append("| — | — | MISSING | No evidence referenced |")
            for evidence_id in evidence_ids:
                status, sha256, _detail = statuses.get(evidence_id, ("UNKNOWN", "unknown", ""))
                lines.append(
                    f"| `{_cell(evidence_id)}` | `{_cell(sha256)}` | **{_cell(status)}** | "
                    f"`artifacts/{_cell(_text(finding.get('assessment_id'), 'assessment'))}/"
                    f"{_cell(evidence_id)}.raw` |"
                )
            lines.append("")
        return lines

    def _render_research(self, state: dict[str, Any]) -> list[str]:
        lines = ["## 7. External Intelligence (Tavily)", ""]
        refs = state.get("research_refs", [])
        if not refs:
            lines.extend(
                [
                    (
                        "No external intelligence was retrieved for this assessment. External "
                        "intelligence never confirms a finding on its own."
                    ),
                    "",
                ]
            )
            return lines

        lines.extend(
            [
                "| Source ID | Title | URL | Relevance |",
                "|---|---|---|---:|",
            ]
        )
        for ref in refs:
            lines.append(
                "| "
                + " | ".join(
                    [
                        _cell(ref.get("source_id") or ref.get("source")),
                        _cell(ref.get("title") or ref.get("advisory")),
                        _cell(ref.get("url")),
                        _cell(ref.get("score")),
                    ]
                )
                + " |"
            )
        lines.extend(
            [
                "",
                (
                    "> External intelligence is advisory context only. It is never used to "
                    "promote a finding to `CONFIRMED`."
                ),
                "",
            ]
        )
        return lines

    def _render_audit(
        self,
        state: dict[str, Any],
        statuses: dict[str, tuple[str, str, str]],
    ) -> list[str]:
        budget = state.get("budget") or {}
        lines = [
            "## 8. Audit Trail & Telemetry",
            "",
            "### Execution Budget",
            "",
            (
                f"- Iterations used: {_text(budget.get('iterations_used'), '0')} "
                f"of {_text(budget.get('max_iterations'), 'unknown')}"
            ),
            (
                f"- Model calls used: {_text(budget.get('model_calls_used'), '0')} "
                f"of {_text(budget.get('max_model_calls'), 'unknown')}"
            ),
            f"- Total tokens: {_text(budget.get('total_tokens_used'), '0')}",
            f"- Elapsed duration: {_duration_seconds(state)}",
            "",
            "### Blocked Actions",
            "",
        ]
        blocked = state.get("blocked_actions", [])
        if not blocked:
            lines.append("No actions were blocked by the policy engine.")
        else:
            lines.extend(
                [
                    "| Tool | Category | Target | Reason |",
                    "|---|---|---|---|",
                ]
            )
            for action in blocked:
                reason = (
                    action.get("denied_reason")
                    or action.get("reject_reason")
                    or action.get("reason")
                    or "Blocked by policy"
                )
                lines.append(
                    "| "
                    + " | ".join(
                        [
                            _cell(action.get("tool_name")),
                            _cell(action.get("action_category")),
                            _cell(action.get("target_host")),
                            _cell(reason),
                        ]
                    )
                    + " |"
                )

        chain = state.get("chain_summary") or {}
        lines.extend(["", "### Multi-Step Authorization", ""])
        if chain:
            lines.append(f"- Authorized: **{bool(chain.get('authorized'))}**")
            lines.append(f"- Maximum allowed steps: {_cell(chain.get('max_steps'))}")
            executed_steps = chain.get("executed_steps", [])
            if executed_steps:
                lines.extend(
                    [
                        "",
                        "| Step | Action ID | Tool | Target | Evidence | Status |",
                        "|---:|---|---|---|---|---|",
                    ]
                )
                for step in executed_steps:
                    lines.append(
                        "| "
                        + " | ".join(
                            [
                                _cell(step.get("step_index")),
                                f"`{_cell(step.get('action_id'))}`",
                                _cell(step.get("tool_name")),
                                _cell(step.get("target_host")),
                                f"`{_cell(step.get('evidence_id'))}`",
                                _cell(step.get("status")),
                            ]
                        )
                        + " |"
                    )
            else:
                lines.append("- No chain steps were executed.")
        else:
            lines.append("- No chain authorization metadata was recorded.")

        telemetry = state.get("telemetry") or []
        lines.extend(["", "### Bifrost Telemetry", ""])
        if telemetry:
            lines.extend(
                [
                    "| Provider | Model | Prompt tokens | Completion tokens | Latency (ms) | Fallback |",
                    "|---|---|---:|---:|---:|---|",
                ]
            )
            for event in telemetry:
                lines.append(
                    "| "
                    + " | ".join(
                        [
                            _cell(event.get("provider_used")),
                            _cell(event.get("model_used")),
                            _cell(event.get("prompt_tokens")),
                            _cell(event.get("completion_tokens")),
                            _cell(event.get("latency_ms")),
                            _cell(event.get("fallback_triggered")),
                        ]
                    )
                    + " |"
                )
        else:
            lines.append("No Bifrost telemetry was captured for this run.")

        # Spec 11: Chain of Custody & Merkle Proof Capsules
        findings_with_proof = [
            f for f in state.get("findings", []) if isinstance(f, dict) and f.get("proof_id")
        ]
        lines.extend(["", "### Chain of Custody & Proof Capsules", ""])
        if findings_with_proof:
            lines.extend(
                [
                    "| Finding ID | Title | Proof Capsule ID | Ledger Root | Attestation |",
                    "|---|---|---|---|---|",
                ]
            )
            for f in findings_with_proof:
                lines.append(
                    "| "
                    + " | ".join(
                        [
                            f"`{_cell(f.get('finding_id'))}`",
                            _cell(f.get("title")),
                            f"`{_cell(f.get('proof_id'))}`",
                            f"`{_cell(f.get('ledger_root') or 'unknown')[:18]}...`",
                            "**T2 (Executor)**",
                        ]
                    )
                    + " |"
                )
            lines.append("")
            lines.append("To independently verify proof capsules offline without trusting the AI:")
            lines.append("```bash")
            lines.append("python scripts/verify_proof.py <path-to-capsule.argusproof>")
            lines.append("```")
        else:
            lines.append("No cryptographic proof capsules were bound to findings in this run.")

        lines.append("")
        return lines

    def _render_limitations(
        self, state: dict[str, Any], simulated: bool, statuses: dict[str, tuple[str, str, str]]
    ) -> list[str]:
        outcome = _text(_summary(state).get("outcome"), _text(state.get("status"), ""))
        lines = [
            "## 9. Limitations & False Positives",
            "",
            (
                "- A scanner's negative result is not proof of absence. Only confirmed findings "
                "are asserted as vulnerabilities."
            ),
            "- External intelligence is advisory and never sufficient to confirm a finding.",
            "- Reproduction steps are provided for authorized re-testing only.",
        ]
        if simulated:
            lines.append(
                "- **This assessment ran in simulation mode.** Tool output was simulated and "
                "the report must not be treated as a real penetration test."
            )
        if outcome in {"PARTIAL_SUCCESS", "FAILED", "CANCELLED", "BLOCKED"}:
            lines.append(
                f"- The assessment terminated with outcome `{outcome}`. Coverage may be "
                "incomplete and findings must be interpreted with that limitation."
            )
        tampered = [eid for eid, (status, _, _) in statuses.items() if status != "VERIFIED"]
        if tampered:
            lines.append(
                "- The following evidence IDs could not be cryptographically verified: "
                + ", ".join(f"`{eid}`" for eid in tampered)
                + ". Claims relying on them should be reviewed manually."
            )
        blocked_count = len(state.get("blocked_actions", []))
        if blocked_count:
            lines.append(
                f"- {blocked_count} proposed action(s) were blocked by the deterministic policy "
                "engine, which may have reduced coverage."
            )
        lines.append("")
        return lines

    def _render_evidence_appendix(
        self, state: dict[str, Any], statuses: dict[str, tuple[str, str, str]]
    ) -> list[str]:
        lines = [
            "## 10. Evidence Appendix",
            "",
            "| Evidence ID | Tool | SHA-256 | Integrity |",
            "|---|---|---|---|",
        ]
        refs = state.get("evidence_refs", [])
        if not refs:
            lines.append("| — | — | — | No evidence was stored |")
        for ref in refs:
            evidence_id = _text(ref.get("evidence_id"))
            status, sha256, _detail = statuses.get(evidence_id, ("UNKNOWN", "unknown", ""))
            lines.append(
                f"| `{_cell(evidence_id)}` | {_cell(ref.get('tool'))} | "
                f"`{_cell(sha256)}` | **{_cell(status)}** |"
            )
        lines.append("")
        return lines

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def generate_markdown_report(
        self,
        state: dict[str, Any],
        scope: ScopeDocument | None = None,
        evidence_vault: EvidenceVault | None = None,
        simulation_mode: bool | None = None,
    ) -> str:
        """Generates a complete Markdown assessment report."""
        findings = [f for f in state.get("findings", []) if isinstance(f, dict)]
        simulated = bool(
            simulation_mode if simulation_mode is not None else state.get("simulation_mode", False)
        )

        cache: dict[str, tuple[str, str, str]] = {}
        evidence_ids = self._all_evidence_ids(findings, state)
        statuses = {
            evidence_id: self._evidence_record(state, evidence_id, evidence_vault, cache)
            for evidence_id in evidence_ids
        }

        sections: list[str] = []
        sections.extend(self._render_header(state, simulated))
        sections.extend(self._render_executive_summary(state, findings, statuses))
        sections.extend(self._render_scope(state, scope))
        sections.extend(self._render_methodology(state))
        sections.extend(self._render_attack_surface(state))
        sections.extend(self._render_findings_table(findings, statuses))
        sections.extend(self._render_finding_details(findings, statuses))
        sections.extend(self._render_research(state))
        sections.extend(self._render_audit(state, statuses))
        sections.extend(self._render_limitations(state, simulated, statuses))
        sections.extend(self._render_evidence_appendix(state, statuses))

        markdown = "\n".join(sections).rstrip() + "\n"
        redacted, _was_redacted = self._redactor.redact(markdown)
        return redacted

    def write_markdown_report(
        self,
        state: dict[str, Any],
        output_path: Path | str,
        scope: ScopeDocument | None = None,
        evidence_vault: EvidenceVault | None = None,
        simulation_mode: bool | None = None,
    ) -> Path:
        """Writes the Markdown report to ``output_path`` and returns the path."""
        markdown = self.generate_markdown_report(
            state,
            scope=scope,
            evidence_vault=evidence_vault,
            simulation_mode=simulation_mode,
        )
        destination = Path(output_path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(markdown, encoding="utf-8")
        return destination

    def generate_html_report(
        self,
        state: dict[str, Any],
        scope: ScopeDocument | None = None,
        evidence_vault: EvidenceVault | None = None,
        simulation_mode: bool | None = None,
    ) -> str:
        """Generates a styled, print-friendly HTML report."""
        markdown = self.generate_markdown_report(
            state,
            scope=scope,
            evidence_vault=evidence_vault,
            simulation_mode=simulation_mode,
        )
        assessment_id = _text(state.get("assessment_id"), "unknown-assessment")
        outcome = _text(_summary(state).get("outcome"), _text(state.get("status"), "UNKNOWN"))
        return render_styled_html(
            markdown,
            title="ARGUS Security Assessment Report",
            subtitle=f"Assessment {assessment_id} — Outcome {outcome}",
        )

    def write_html_report(
        self,
        state: dict[str, Any],
        output_path: Path | str,
        scope: ScopeDocument | None = None,
        evidence_vault: EvidenceVault | None = None,
        simulation_mode: bool | None = None,
    ) -> Path:
        """Writes the styled HTML report to ``output_path`` and returns the path."""
        destination = Path(output_path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(
            self.generate_html_report(
                state,
                scope=scope,
                evidence_vault=evidence_vault,
                simulation_mode=simulation_mode,
            ),
            encoding="utf-8",
        )
        return destination

    def generate_pdf_report(
        self,
        state: dict[str, Any],
        output_path: Path | str,
        scope: ScopeDocument | None = None,
        evidence_vault: EvidenceVault | None = None,
        simulation_mode: bool | None = None,
    ) -> Path:
        """Generates a paginated PDF report without native dependencies."""
        markdown = self.generate_markdown_report(
            state,
            scope=scope,
            evidence_vault=evidence_vault,
            simulation_mode=simulation_mode,
        )
        assessment_id = _text(state.get("assessment_id"), "assessment")
        return export_markdown_to_pdf(
            markdown,
            output_path,
            title=f"ARGUS Security Assessment Report — {assessment_id}",
        )
