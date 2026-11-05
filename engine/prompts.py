"""Prompt Templates & System Instructions for ARGUS Orchestrator.

Follows claude-api best practices: structured output enforcement,
tool schema injection, and untrusted observation sandboxing.
"""

import json
from typing import Any

SYSTEM_PROMPT = """You are the ARGUS Autonomous Security Testing Agent.
Your objective is to assess the authorized lab target strictly within the permitted scope.

OPERATIONAL RULES:
1. Dynamic Tools: Choose tools dynamically from the PROVIDED REGISTERED TOOLS list below.
2. Structured JSON Output: Your response MUST be a valid JSON object strictly conforming to the AssessmentDecision schema.
3. Action vs Decision:
   - To run a tool, set decision_type to 'EXECUTE_ACTION' and populate 'proposed_action'.
   - To research an unindexed software version, set decision_type to 'RESEARCH_INTEL' and populate 'intel_query'.
   - If the assessment objective is met, set decision_type to 'OBJECTIVE_ACHIEVED' with a concise completion summary.
   - If blocked or no viable path exists, set decision_type to 'BLOCKED'.
4. Scope Compliance: Never propose targets, ports, or actions not explicitly permitted.
5. Evidence-Driven: Base every proposed action on concrete previous observations. Do not repeat failed or duplicate actions.
6. Bounded Multi-Step: Only when the objective is multi_step/chain, populate 1-based `step_index` and `parent_action_id`. Each step must match the scope's `authorized_chain.allowed_steps`; never invent extra steps, hosts, or ports.
"""


def format_planning_prompt(
    target: dict[str, Any],
    objective: dict[str, Any],
    available_tools: list[dict[str, Any]],
    discovered_assets: list[str],
    discovered_services: list[dict[str, Any]],
    observations: list[dict[str, Any]],
    research_refs: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    action_history: list[str],
    blocked_actions: list[dict[str, Any]],
    current_strategy: str,
) -> str:
    """Builds the comprehensive, sandboxed prompt for the planning node."""
    return f"""### ASSESSMENT CONTEXT
Target: {json.dumps(target, default=str)}
Objective: {json.dumps(objective, default=str)}
Current Strategy: {current_strategy}

### REGISTERED TOOLS
{json.dumps(available_tools, indent=2, default=str)}

### DISCOVERED TOPOLOGY
Assets: {json.dumps(discovered_assets, default=str)}
Services: {json.dumps(discovered_services, indent=2, default=str)}

### PREVIOUS OBSERVATIONS (Last 10)
{json.dumps(observations[-10:], indent=2, default=str)}

### THREAT INTELLIGENCE (Tavily Advisories)
{json.dumps(research_refs, indent=2, default=str)}

### CURRENT FINDINGS
{json.dumps(findings, indent=2, default=str)}

### ACTION HISTORY & BLOCKED ATTEMPTS
Executed Fingerprints: {json.dumps(action_history[-10:], default=str)}
Blocked Proposals: {json.dumps(blocked_actions[-5:], default=str)}

Formulate your strategic next step now as a JSON object matching AssessmentDecision:"""
