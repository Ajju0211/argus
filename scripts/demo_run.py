"""Lab-agnostic ARGUS demonstration runner.

This script no longer assumes Apache 2.4.49, CVE-2021-41773, or port 8080.
The target, scope, and objective are supplied explicitly (or derived from the
scope document). Simulation is opt-in and every simulated artifact is labelled.

Examples:
    # Fully offline, clearly simulated pipeline demonstration
    python scripts/demo_run.py --simulated --objective discover_services

    # Live assessment through Bifrost + the configured tool executor
    python scripts/demo_run.py --scope scope.yaml --target http://lab:3000

    # Generate Markdown, HTML, and PDF deliverables
    python scripts/demo_run.py --simulated --output-dir artifacts/demo
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.config import get_settings
from core.reporting.report_generator import ReportGenerator
from core.scope.validator import ScopeValidator
from engine.graph import AssessmentOrchestrator, create_initial_state, extract_target_spec
from packages.contracts.actions import (
    ActionProposal,
    AssessmentDecision,
    DecisionType,
)
from packages.contracts.scope import ScopeDocument

DEFAULT_SCOPE = Path(__file__).parent.parent / "tests" / "fixtures" / "valid_scope.yaml"

SUPPORTED_OBJECTIVES = {
    "discover_services": "Service and host discovery only",
    "severity_threshold": "Confirm a finding at or above --min-severity",
    "find_cve": "Confirm a vulnerability finding (legacy objective name)",
}


def _banner(mode: str) -> None:
    print("\n" + "=" * 68)
    print("🛡️   ARGUS — Autonomous Penetration Testing Platform")
    print(f"    Mode: {mode}")
    print("=" * 68 + "\n")


def _resolve_target(scope: ScopeDocument, target_arg: str | None) -> str:
    """Chooses an explicit target or derives one from the authorized scope."""
    if target_arg:
        return target_arg

    hosts = scope.targets.allowed_hosts
    if not hosts:
        raise ValueError(
            "No --target supplied and the scope has no allowed_hosts. "
            "Provide an explicit --target within the authorized scope."
        )

    host = hosts[0]
    preferred = 8080 if 8080 in scope.ports.allowed_ports else None
    port = preferred or (scope.ports.allowed_ports[0] if scope.ports.allowed_ports else None)
    scheme = "https" if port in (443, 8443) else "http"
    return f"{scheme}://{host}" + (f":{port}" if port else "")


def _build_objective(args: argparse.Namespace) -> dict[str, Any]:
    if args.objective == "severity_threshold":
        return {"type": "severity_threshold", "min_severity": args.min_severity.upper()}
    if args.objective == "find_cve":
        return {"find_cve": True, "required_hosts": 1}
    return {"type": "discover_services", "required_hosts": 1}


def _simulated_nmap_xml(host: str, port: int | None) -> str:
    """Synthetic Nmap XML with no vendor/CVE claims, used only in simulation."""
    port_block = ""
    if port is not None:
        port_block = (
            "<ports>"
            f'<port protocol="tcp" portid="{port}">'
            '<state state="open"/>'
            '<service name="http" method="probed"/>'
            "</port>"
            "</ports>"
        )
    return (
        '<?xml version="1.0"?>\n'
        "<nmaprun>"
        "<host>"
        '<status state="up"/>'
        f'<address addr="{host}" addrtype="ipv4"/>'
        f"{port_block}"
        "</host>"
        "</nmaprun>"
    )


def _simulated_nuclei_jsonl(url: str) -> str:
    """Synthetic Nuclei JSONL for pipeline demonstration only."""
    record = {
        "template-id": "simulated-lab-check",
        "info": {
            "name": "Simulated Lab Check",
            "severity": "high",
            "description": "[SIMULATION_MODE] Synthetic observation for pipeline demonstration.",
        },
        "host": url,
        "matched-at": url,
        "curl-command": f"curl -sS {url}",
        "extracted-results": ["SIMULATED_MARKER"],
    }
    return json.dumps(record)


def _simulated_model_gateway(objective: dict[str, Any], target_spec: dict[str, Any]) -> Any:
    """Builds a deterministic, clearly-labelled planner for offline demos."""
    objective_type = str(
        objective.get("type") or ("find_cve" if objective.get("find_cve") else "")
    ).lower()
    iteration = {"count": 0}

    def gateway(prompt: str) -> AssessmentDecision:
        iteration["count"] += 1
        if objective_type in ("severity_threshold", "find_cve") and iteration["count"] == 1:
            host = target_spec["host"]
            port = target_spec["port"]
            scheme = "https" if port in (443, 8443) else "http"
            url = f"{scheme}://{host}" + (f":{port}" if port else "")
            proposal = ActionProposal(
                action_id="act-sim-verify-001",
                target_host=host,
                target_port=port,
                tool_name="nuclei",
                action_category="active_template_check",
                arguments={"target": url, "template": "simulated-lab-check.yaml"},
                rationale="[SIMULATION_MODE] Demonstrate the verification pipeline.",
                expected_evidence="[SIMULATION_MODE] Synthetic template result.",
            )
            return AssessmentDecision(
                decision_type=DecisionType.EXECUTE_ACTION,
                proposed_action=proposal,
                rationale="[SIMULATION_MODE] Running a synthetic verification check.",
            )
        return AssessmentDecision(
            decision_type=DecisionType.OBJECTIVE_ACHIEVED,
            rationale="[SIMULATION_MODE] Demonstration objective reached.",
            completion_summary="[SIMULATION_MODE] Offline pipeline demonstration complete.",
        )

    return gateway


def _simulated_tool_executor(
    target_spec: dict[str, Any],
) -> Any:
    def executor(proposal: ActionProposal) -> tuple[int, str, str]:
        if proposal.tool_name == "nmap":
            return 0, _simulated_nmap_xml(target_spec["host"], target_spec["port"]), ""
        if proposal.tool_name == "nuclei":
            url = str(
                proposal.arguments.get("target")
                or proposal.arguments.get("target_url")
                or f"http://{proposal.target_host}:{proposal.target_port}"
            )
            return 0, _simulated_nuclei_jsonl(url), ""
        return 0, f"[SIMULATION_MODE] No synthetic output for {proposal.tool_name}", ""

    return executor


def _print_summary(state: dict[str, Any], report_paths: dict[str, str]) -> None:
    print("\n📊 Assessment Result")
    print("=" * 68)
    print(f"      • Final status:        {state.get('status')}")
    print(f"      • Outcome:             {state.get('completion', {}).get('outcome')}")
    print(f"      • Discovered assets:   {state.get('discovered_assets', [])}")
    print(f"      • Services discovered: {len(state.get('discovered_services', []))}")
    print(f"      • Findings:            {len(state.get('findings', []))}")
    for finding in state.get("findings", []):
        print(
            f"        - [{finding.get('severity')}] {finding.get('title')} "
            f"({finding.get('confidence') or finding.get('status')})"
        )
    print(f"      • Evidence artifacts:  {len(state.get('evidence_refs', []))}")
    print(f"      • Report:              {state.get('report_path') or 'not written'}")
    for kind, path in report_paths.items():
        print(f"      • {kind.upper()} deliverable:     {path}")
    if state.get("simulation_mode"):
        print("\n⚠️  SIMULATION_MODE: results are synthetic and are not a live assessment.")
    print("=" * 68 + "\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run an authorized ARGUS assessment demo.")
    parser.add_argument(
        "--scope",
        type=Path,
        default=DEFAULT_SCOPE,
        help=f"Path to the authorized scope YAML (default: {DEFAULT_SCOPE})",
    )
    parser.add_argument(
        "--target",
        default=None,
        help="Target URL or host:port. Defaults to the first authorized host/port in scope.",
    )
    parser.add_argument(
        "--objective",
        choices=sorted(SUPPORTED_OBJECTIVES),
        default="discover_services",
        help="Assessment objective type",
    )
    parser.add_argument(
        "--min-severity",
        default="HIGH",
        help="Minimum severity for the severity_threshold objective",
    )
    parser.add_argument(
        "--simulated",
        action="store_true",
        help="Opt in to clearly-labelled synthetic tool output (offline demo)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Directory for Markdown/HTML/PDF deliverables",
    )
    parser.add_argument("--max-iterations", type=int, default=5, help="Maximum planning iterations")
    args = parser.parse_args(argv)

    settings = get_settings()
    if not args.simulated and not settings.BIFROST_API_KEY:
        print(
            "ERROR: Live mode requires ARGUS_BIFROST_API_KEY (Bifrost model gateway).\n"
            "       Pass --simulated for a clearly-labelled offline pipeline demonstration.",
            file=sys.stderr,
        )
        return 2

    mode = "SIMULATION (explicit)" if args.simulated else "LIVE"
    _banner(mode)

    try:
        scope_raw = args.scope.read_text(encoding="utf-8")
        scope = ScopeValidator.parse_yaml_string(scope_raw)
        target_value = _resolve_target(scope, args.target)
        target_spec = extract_target_spec(target_value)
    except (OSError, ValueError, TypeError) as exc:
        print(f"ERROR: Could not load scope/target: {exc}", file=sys.stderr)
        return 2

    objective = _build_objective(args)

    print("[1/4] 📋 Scope")
    print(f"      • Scope ID:       {scope.assessment_id}")
    print(f"      • Target:         {target_value}")
    print(f"      • Allowed hosts:  {scope.targets.allowed_hosts}")
    print(f"      • Allowed ports:  {scope.ports.allowed_ports}")
    print(f"      • Objective:      {objective}")

    if args.simulated:
        orchestrator = AssessmentOrchestrator(
            scope=scope,
            model_gateway=_simulated_model_gateway(objective, target_spec),
            tool_executor=_simulated_tool_executor(target_spec),
            simulation_mode=True,
        )
    else:
        orchestrator = AssessmentOrchestrator(scope=scope, simulation_mode=False)

    print("\n[2/4] 🧱 Policy Firewall")
    from core.policy.policy_engine import PolicyEngine

    policy = PolicyEngine(scope)
    probe = ActionProposal(
        action_id="act-demo-probe",
        tool_name="nmap",
        action_category="network_recon",
        target_host=target_spec["host"],
        target_port=target_spec["port"],
        arguments={"target": target_spec["host"], "ports": str(target_spec["port"] or 80)},
        rationale="Demonstrate the deterministic policy gate",
        expected_evidence="Port state",
    )
    decision = policy.evaluate(probe)
    print(f"      • Authorized probe: {'APPROVED' if decision.approved else 'DENIED'}")
    if not decision.approved:
        print(f"        Reason: {decision.reason}")

    print("\n[3/4] 🤖 Running assessment graph")
    initial_state = create_initial_state(
        assessment_id="demo-assessment",
        target={"type": "web", "value": target_value},
        objective=objective,
        scope=scope,
        scope_yaml_raw=scope_raw,
        max_iterations=args.max_iterations,
    )
    final_state = orchestrator.run(initial_state)

    print("\n[4/4] 📄 Generating deliverables")
    output_dir = args.output_dir or (Path(settings.ARTIFACTS_DIR) / "demo-assessment")
    output_dir.mkdir(parents=True, exist_ok=True)
    generator = ReportGenerator()
    state_dict: dict[str, Any] = dict(final_state)
    report_paths = {
        "html": str(
            generator.write_html_report(
                state_dict,
                output_dir / "report.html",
                scope=scope,
                evidence_vault=orchestrator.evidence_vault,
                simulation_mode=orchestrator.simulation_mode,
            )
        ),
        "pdf": str(
            generator.generate_pdf_report(
                state_dict,
                output_dir / "report.pdf",
                scope=scope,
                evidence_vault=orchestrator.evidence_vault,
                simulation_mode=orchestrator.simulation_mode,
            )
        ),
    }

    _print_summary(state_dict, report_paths)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
