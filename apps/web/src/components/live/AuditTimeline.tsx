"use client";

import { useEffect, useMemo, useRef } from "react";
import {
  Terminal,
  CheckCircle,
  AlertOctagon,
  Radar,
  Crosshair,
  Wrench,
  ShieldCheck,
  FileSearch,
  Activity,
} from "lucide-react";
import { AssessmentEvent } from "@/lib/types";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

interface AuditTimelineProps {
  events: AssessmentEvent[];
}

function asString(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function targetOf(action?: Record<string, unknown>): string {
  if (!action) return "";
  const host = asString(action.target_host);
  const port = action.target_port;
  if (host && port) return `${host}:${port}`;
  return host || "";
}

export function AuditTimeline({ events }: AuditTimelineProps) {
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [events]);

  const startMs = useMemo(() => {
    if (events.length === 0) return null;
    const ms = new Date(events[0].timestamp).getTime();
    return Number.isFinite(ms) ? ms : null;
  }, [events]);

  const getEventIcon = (type: string) => {
    switch (type) {
      case "assessment_created":
      case "scope_validated":
      case "action_approved":
      case "assessment_resumed":
      case "assessment_completed":
      case "tool_completed":
        return <CheckCircle className="h-3.5 w-3.5 text-emerald-500" />;
      case "action_blocked":
      case "finding_verified":
      case "assessment_failed":
        return <AlertOctagon className="h-3.5 w-3.5 text-rose-500" />;
      case "action_proposed":
      case "planning_started":
        return <Crosshair className="h-3.5 w-3.5 text-blue-400" />;
      case "recon_started":
      case "recon_completed":
        return <Radar className="h-3.5 w-3.5 text-cyan-400" />;
      case "tool_started":
        return <Wrench className="h-3.5 w-3.5 text-amber-400" />;
      case "verification_started":
      case "completion_check":
        return <FileSearch className="h-3.5 w-3.5 text-violet-400" />;
      case "recovery_started":
        return <Activity className="h-3.5 w-3.5 text-amber-500" />;
      case "policy_gate":
        return <ShieldCheck className="h-3.5 w-3.5 text-muted-foreground/60" />;
      case "report_generated":
        return <FileSearch className="h-3.5 w-3.5 text-foreground/70" />;
      default:
        return <Terminal className="h-3.5 w-3.5 text-muted-foreground/60" />;
    }
  };

  const getEventLabel = (evt: AssessmentEvent) => {
    const data = evt.data || {};
    const action = data.action as Record<string, unknown> | undefined;
    const finding = data.finding as Record<string, unknown> | undefined;
    switch (evt.eventType) {
      case "assessment_created":
        return "Assessment initialized and validated against scope boundaries";
      case "assessment_started":
        return `Assessment execution started in ${data.simulation ? "simulated" : "live"} mode`;
      case "scope_validated":
        return "Scope certified: target allowed, no IP rebinding conflicts";
      case "recon_started":
        return `Running service discovery against ${asString((data.target as Record<string, unknown>)?.value) || "the target"}`;
      case "recon_completed":
        return `Reconnaissance finished. Discovered ${
          (data.assets as unknown[])?.length || 0
        } assets and ${(data.services as unknown[])?.length || 0} open services`;
      case "planning_started":
        return "Planner is analyzing observations and choosing the next action";
      case "action_proposed":
        return `AI Planner proposed ${asString(action?.tool_name) || asString(data.tool_name) || "action"}${
          targetOf(action) ? ` against ${targetOf(action)}` : ""
        }`;
      case "action_approved":
        return `Policy Firewall: APPROVED ${asString(action?.tool_name) || "action"}`;
      case "action_blocked":
        return `Policy Firewall: BLOCKED ${asString(action?.tool_name) || "action"} (out of scope)`;
      case "tool_started":
        return `Executing ${asString(action?.tool_name) || "tool"}${
          targetOf(action) ? ` against ${targetOf(action)}` : ""
        }`;
      case "tool_completed":
        return `Tool completed: ${asString(action?.tool_name) || "scan"} — parsing observations`;
      case "verification_started":
        return "Verifying observations and attaching cryptographic evidence";
      case "recovery_started":
        return "Recovery strategy engaged after a tool failure";
      case "finding_verified":
        return `VERIFIED VULNERABILITY: ${asString(finding?.title) || "CVE identified"}${
          asString(finding?.severity) ? ` (${asString(finding?.severity)})` : ""
        }`;
      case "completion_check":
        return data.is_completed
          ? "Completion check: objective satisfied"
          : "Completion check: objective not yet satisfied, continuing";
      case "node_transition":
        return `Pipeline step: ${evt.node || asString(data.node) || "in progress"}`;
      case "assessment_paused":
        return "Assessment execution paused by operator";
      case "assessment_resumed":
        return "Assessment execution resumed";
      case "report_generated":
        return "Cryptographic audit report generated & signed";
      case "assessment_completed":
        return "Assessment objectives fully completed";
      case "assessment_failed":
        return "Assessment terminated with error";
      case "stream_closed":
        return "Telemetry stream closed";
      default:
        return evt.message || evt.eventType;
    }
  };

  return (
    <Card className="flex flex-col h-[520px] border-border/70">
      <CardHeader className="border-b border-border/50 py-3 px-4 flex flex-row items-center justify-between">
        <div className="flex items-center gap-2">
          <Terminal className="h-4 w-4 text-muted-foreground/60" />
          <CardTitle className="text-xs uppercase tracking-wider font-semibold">
            Live Monologue & Audit Log
          </CardTitle>
        </div>
        <Badge variant="outline" className="text-[10px] font-mono font-normal">
          {events.length} Events
        </Badge>
      </CardHeader>

      <CardContent
        ref={scrollRef}
        className="flex-1 overflow-y-auto p-4 space-y-2.5 font-mono text-xs custom-scrollbar"
      >
        {events.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-muted-foreground space-y-2 font-sans">
            <Terminal className="h-6 w-6 opacity-30" />
            <p className="text-xs">Awaiting agent execution telemetry...</p>
          </div>
        ) : (
          events.map((evt, idx) => {
            const eventMs = new Date(evt.timestamp).getTime();
            const elapsed =
              startMs !== null && Number.isFinite(eventMs)
                ? Math.max(0, Math.round((eventMs - startMs) / 1000))
                : null;
            return (
              <div
                key={`${evt.id}-${idx}`}
                className="flex items-start gap-2.5 p-2 rounded hover:bg-muted/30 transition-colors"
              >
                <div className="mt-0.5 shrink-0">{getEventIcon(evt.eventType)}</div>
                <div className="flex-1 space-y-1 min-w-0">
                  <div className="flex items-baseline justify-between gap-2">
                    <span className="text-[11px] font-medium text-foreground truncate">
                      {evt.eventType.replace(/_/g, " ").toUpperCase()}
                      {evt.node ? (
                        <span className="ml-1.5 text-[10px] font-normal text-muted-foreground">
                          [{evt.node}]
                        </span>
                      ) : null}
                    </span>
                    <span className="text-[10px] text-muted-foreground shrink-0">
                      {elapsed !== null ? `+${elapsed}s · ` : ""}
                      {new Date(evt.timestamp).toLocaleTimeString()}
                    </span>
                  </div>
                  <p className="text-xs text-muted-foreground leading-relaxed break-words font-sans">
                    {getEventLabel(evt)}
                  </p>
                  {Boolean(evt.data?.rationale) && (
                    <p className="text-[11px] text-foreground/80 bg-muted/40 p-2 rounded border border-border/50 font-sans">
                      <span className="font-medium text-foreground">Reasoning: </span>
                      {String(evt.data.rationale)}
                    </p>
                  )}
                </div>
              </div>
            );
          })
        )}
      </CardContent>
    </Card>
  );
}
