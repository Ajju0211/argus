"use client";

import { useEffect, useMemo, useState } from "react";
import {
  Activity,
  CheckCircle2,
  Circle,
  Crosshair,
  FileSearch,
  Radar,
  ShieldCheck,
  Wrench,
  AlertTriangle,
} from "lucide-react";
import { AssessmentDetail, AssessmentEvent } from "@/lib/types";
import { ConnectionStatus } from "@/lib/useAssessmentStream";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

interface LiveAgentPanelProps {
  assessment: AssessmentDetail;
  events: AssessmentEvent[];
  connectionStatus: ConnectionStatus;
}

const PIPELINE = [
  { key: "validate_scope", label: "Scope", icon: ShieldCheck },
  { key: "recon", label: "Recon", icon: Radar },
  { key: "plan_action", label: "Plan", icon: Crosshair },
  { key: "policy_gate", label: "Policy", icon: ShieldCheck },
  { key: "execute_tool", label: "Execute", icon: Wrench },
  { key: "verify_finding", label: "Verify", icon: FileSearch },
  { key: "report", label: "Report", icon: FileSearch },
];

const ACTIVE_STEP: Record<string, string> = {
  recon_started: "recon",
  recon_completed: "recon",
  planning_started: "plan_action",
  action_proposed: "plan_action",
  action_approved: "execute_tool",
  tool_started: "execute_tool",
  tool_completed: "verify_finding",
  verification_started: "verify_finding",
  recovery_started: "verify_finding",
  finding_verified: "evaluate_completion",
  completion_check: "evaluate_completion",
  report_generated: "report",
  assessment_completed: "report",
};

function asString(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function actionTarget(action?: Record<string, unknown>): string {
  if (!action) return "";
  const host = asString(action.target_host);
  const port = action.target_port;
  if (host && port) return `${host}:${port}`;
  return host || "";
}

function describeEvent(
  evt: AssessmentEvent | undefined,
  assessment: AssessmentDetail,
): string {
  if (!evt) {
    return assessment.status === "COMPLETED" || assessment.status === "SUCCESS"
      ? "Assessment finished. Review the findings and report below."
      : "Connecting to the agent telemetry stream...";
  }
  const data = evt.data || {};
  const action = (data.action as Record<string, unknown>) || undefined;
  const finding = (data.finding as Record<string, unknown>) || undefined;

  switch (evt.eventType) {
    case "assessment_created":
      return "Assessment registered and scope boundaries loaded.";
    case "assessment_started":
      return `Autonomous loop started in ${data.simulation ? "simulated" : "live"} mode.`;
    case "scope_validated":
      return "Scope validated. The agent is preparing reconnaissance.";
    case "recon_started":
      return `Running service discovery against ${assessment.target?.value || "the target"}...`;
    case "recon_completed":
      return `Reconnaissance complete: ${
        (data.assets as unknown[])?.length || 0
      } asset(s), ${(data.services as unknown[])?.length || 0} open service(s).`;
    case "planning_started":
      return "Analyzing observations and deciding the next action.";
    case "action_proposed":
      return `Planner proposed ${asString(action?.tool_name) || asString(data.tool_name) || "an action"}${
        actionTarget(action) ? ` against ${actionTarget(action)}` : ""
      }.`;
    case "action_approved":
      return `Policy firewall approved ${asString(action?.tool_name) || "the action"}.`;
    case "action_blocked":
      return `Policy firewall blocked ${asString(action?.tool_name) || "an out-of-scope action"}.`;
    case "tool_started":
      return `Executing ${asString(action?.tool_name) || "tool"}${
        actionTarget(action) ? ` against ${actionTarget(action)}` : ""
      }...`;
    case "tool_completed":
      return `Tool execution finished${
        asString(action?.tool_name) ? ` (${asString(action?.tool_name)})` : ""
      }. Parsing observations.`;
    case "verification_started":
      return "Verifying observations and attaching cryptographic evidence.";
    case "recovery_started":
      return "Tool failed. The agent is selecting a recovery strategy.";
    case "finding_verified":
      return `Confirmed finding: ${asString(finding?.title) || "vulnerability verified"}.`;
    case "completion_check":
      return data.is_completed
        ? "Objective satisfied. Preparing the final report."
        : "Objective not yet satisfied. Continuing the agent loop.";
    case "report_generated":
      return "Signed assessment report generated.";
    case "assessment_paused":
      return "Assessment paused by the operator.";
    case "assessment_resumed":
      return "Assessment resumed.";
    case "assessment_completed":
      return `Assessment completed${
        asString(data.outcome) ? ` (${asString(data.outcome)})` : ""
      }.`;
    case "assessment_failed":
      return `Assessment failed: ${asString(data.error) || "unknown error"}.`;
    case "node_transition":
      return `Pipeline step completed: ${evt.node || asString(data.node) || "unknown"}.`;
    case "stream_closed":
      return "Telemetry stream closed.";
    default:
      return evt.eventType.replace(/_/g, " ");
  }
}

function formatElapsed(start: string, end?: string | null): string {
  const startMs = new Date(start).getTime();
  const endMs = end ? new Date(end).getTime() : Date.now();
  if (!Number.isFinite(startMs) || !Number.isFinite(endMs)) return "—";
  const seconds = Math.max(0, Math.floor((endMs - startMs) / 1000));
  const mins = Math.floor(seconds / 60);
  const secs = seconds % 60;
  return mins > 0 ? `${mins}m ${secs}s` : `${secs}s`;
}

export function LiveAgentPanel({
  assessment,
  events,
  connectionStatus,
}: LiveAgentPanelProps) {
  const [, setClock] = useState(0);

  useEffect(() => {
    if (assessment.is_terminal) return;
    const timer = setInterval(() => setClock((n) => n + 1), 1000);
    return () => clearInterval(timer);
  }, [assessment.is_terminal]);

  const derived = useMemo(() => {
    const latest = events[events.length - 1];
    const latestAction = [...events]
      .reverse()
      .map((evt) => evt.data?.action as Record<string, unknown> | undefined)
      .find((action) => action && asString(action.tool_name));
    const latestFinding = [...events]
      .reverse()
      .map((evt) => evt.data?.finding as Record<string, unknown> | undefined)
      .find((finding) => finding && asString(finding.title));
    const snapshot = [...events]
      .reverse()
      .find((evt) => evt.eventType === "node_transition")?.data;

    const visited = new Set<string>();
    events.forEach((evt) => {
      const node = evt.node || asString(evt.data?.node);
      if (node) visited.add(node);
      const mapped = ACTIVE_STEP[evt.eventType];
      if (mapped) visited.add(mapped === "execute_tool" ? "execute_tool" : mapped);
    });

    const activeStep =
      (latest && ACTIVE_STEP[latest.eventType]) ||
      latest?.node ||
      asString(latest?.data?.node) ||
      (assessment.is_terminal ? "report" : "validate_scope");

    return {
      latest,
      latestAction,
      latestFinding,
      activeStep,
      visited,
      counts: {
        assets:
          (snapshot?.assets as number | undefined) ??
          assessment.discovered_assets?.length ??
          0,
        services:
          (snapshot?.services as number | undefined) ??
          assessment.discovered_services?.length ??
          0,
        findings:
          (snapshot?.findings as number | undefined) ??
          assessment.findings?.length ??
          0,
        evidence:
          (snapshot?.evidence as number | undefined) ??
          assessment.evidence_refs?.length ??
          0,
        iterations:
          (snapshot?.iterations_used as number | undefined) ??
          assessment.budget?.iterations_used ??
          0,
      },
    };
  }, [events, assessment]);

  const activeIndex = PIPELINE.findIndex(
    (step) => step.key === derived.activeStep,
  );
  const isLive =
    connectionStatus === "LIVE" || connectionStatus === "CONNECTING";

  return (
    <Card className="border-border/70 bg-card overflow-hidden">
      <CardContent className="p-4 sm:p-5 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center gap-2.5 min-w-0">
            <span
              className={`relative flex h-2.5 w-2.5 shrink-0 ${
                isLive ? "" : "opacity-60"
              }`}
            >
              {isLive && (
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-emerald-400 opacity-60" />
              )}
              <span
                className={`relative inline-flex h-2.5 w-2.5 rounded-full ${
                  connectionStatus === "COMPLETED"
                    ? "bg-muted-foreground"
                    : connectionStatus === "PAUSED"
                      ? "bg-amber-500"
                      : connectionStatus === "DISCONNECTED"
                        ? "bg-rose-500"
                        : "bg-emerald-500"
                }`}
              />
            </span>
            <Activity className="h-4 w-4 text-muted-foreground/70 shrink-0" />
            <span className="text-xs uppercase tracking-wider font-semibold text-foreground">
              Agent Live Status
            </span>
            <Badge
              variant="outline"
              className={`text-[10px] font-mono ${
                connectionStatus === "LIVE"
                  ? "text-emerald-500 border-emerald-500/40"
                  : connectionStatus === "DISCONNECTED"
                    ? "text-rose-500 border-rose-500/40"
                    : "text-muted-foreground"
              }`}
            >
              {connectionStatus}
            </Badge>
            <Badge
              variant="outline"
              className="text-[10px] font-mono text-muted-foreground"
            >
              {formatElapsed(
                assessment.created_at,
                assessment.is_terminal ? assessment.completed_at : null,
              )}
            </Badge>
          </div>

          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-muted-foreground font-mono">
            <span>
              assets <b className="text-foreground">{derived.counts.assets}</b>
            </span>
            <span>
              services <b className="text-foreground">{derived.counts.services}</b>
            </span>
            <span>
              findings <b className="text-foreground">{derived.counts.findings}</b>
            </span>
            <span>
              evidence <b className="text-foreground">{derived.counts.evidence}</b>
            </span>
            <span>
              iter <b className="text-foreground">{derived.counts.iterations}</b>
            </span>
          </div>
        </div>

        {/* Pipeline stepper */}
        <div className="flex items-center gap-1 overflow-x-auto pb-1 custom-scrollbar">
          {PIPELINE.map((step, idx) => {
            const done = derived.visited.has(step.key) && idx < activeIndex;
            const active =
              idx === activeIndex ||
              (activeIndex === -1 &&
                idx === 0 &&
                !assessment.is_terminal);
            const Icon = step.icon;
            return (
              <div key={step.key} className="flex items-center gap-1 shrink-0">
                <div
                  className={`flex items-center gap-1.5 rounded-md border px-2 py-1 text-[10px] font-mono transition-colors ${
                    active
                      ? "border-primary/50 bg-primary/10 text-foreground"
                      : done
                        ? "border-emerald-500/30 bg-emerald-500/5 text-muted-foreground"
                        : "border-border/50 text-muted-foreground/60"
                  }`}
                >
                  {done ? (
                    <CheckCircle2 className="h-3 w-3 text-emerald-500" />
                  ) : active ? (
                    <Icon className="h-3 w-3 animate-pulse text-primary" />
                  ) : (
                    <Circle className="h-3 w-3 opacity-40" />
                  )}
                  {step.label}
                </div>
                {idx < PIPELINE.length - 1 && (
                  <span className="text-border/60 text-[9px]">›</span>
                )}
              </div>
            );
          })}
        </div>

        <div className="rounded-md border border-border/60 bg-muted/30 p-3 space-y-2">
          <p className="text-xs sm:text-[13px] text-foreground leading-relaxed font-sans">
            {describeEvent(derived.latest, assessment)}
          </p>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px] font-mono">
            <div className="flex items-start gap-1.5 min-w-0">
              <Wrench className="h-3 w-3 mt-0.5 text-muted-foreground/60 shrink-0" />
              <span className="text-muted-foreground shrink-0">action</span>
              <span className="text-foreground truncate">
                {asString(derived.latestAction?.tool_name) || "—"}
                {actionTarget(derived.latestAction)
                  ? ` @ ${actionTarget(derived.latestAction)}`
                  : ""}
              </span>
            </div>
            <div className="flex items-start gap-1.5 min-w-0">
              {derived.latestFinding ? (
                <AlertTriangle className="h-3 w-3 mt-0.5 text-rose-500 shrink-0" />
              ) : (
                <FileSearch className="h-3 w-3 mt-0.5 text-muted-foreground/60 shrink-0" />
              )}
              <span className="text-muted-foreground shrink-0">finding</span>
              <span className="text-foreground truncate">
                {asString(derived.latestFinding?.title) || "none confirmed yet"}
              </span>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
