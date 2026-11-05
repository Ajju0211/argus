"use client";

import { useEffect, useRef } from "react";
import {
  Terminal,
  ShieldCheck,
  Search,
  CheckCircle,
  AlertTriangle,
  Bug,
  Pause,
  Play,
  FileText,
  CheckCheck,
  AlertOctagon,
} from "lucide-react";
import { AssessmentEvent } from "@/lib/types";

interface AuditTimelineProps {
  events: AssessmentEvent[];
}

export function AuditTimeline({ events }: AuditTimelineProps) {
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [events]);

  const getEventIcon = (type: string) => {
    switch (type) {
      case "assessment_created":
        return <ShieldCheck className="h-3.5 w-3.5 text-indigo-400" />;
      case "scope_validated":
        return <CheckCircle className="h-3.5 w-3.5 text-emerald-400" />;
      case "recon_completed":
        return <Search className="h-3.5 w-3.5 text-cyan-400" />;
      case "action_approved":
        return <CheckCircle className="h-3.5 w-3.5 text-emerald-400" />;
      case "action_blocked":
        return <AlertTriangle className="h-3.5 w-3.5 text-amber-400" />;
      case "tool_completed":
        return <Terminal className="h-3.5 w-3.5 text-cyan-400" />;
      case "finding_verified":
        return <Bug className="h-3.5 w-3.5 text-rose-400" />;
      case "assessment_paused":
        return <Pause className="h-3.5 w-3.5 text-amber-400" />;
      case "assessment_resumed":
        return <Play className="h-3.5 w-3.5 text-emerald-400" />;
      case "report_generated":
        return <FileText className="h-3.5 w-3.5 text-indigo-400" />;
      case "assessment_completed":
        return <CheckCheck className="h-3.5 w-3.5 text-emerald-400" />;
      case "assessment_failed":
        return <AlertOctagon className="h-3.5 w-3.5 text-rose-400" />;
      default:
        return <Terminal className="h-3.5 w-3.5 text-cyber-muted" />;
    }
  };

  const getEventLabel = (evt: AssessmentEvent) => {
    const data = evt.data || {};
    switch (evt.eventType) {
      case "assessment_created":
        return "Assessment created and validated against scope boundaries";
      case "scope_validated":
        return "Scope certified: target allowed, no IP rebinding conflicts";
      case "recon_completed":
        return `Reconnaissance finished. Discovered ${
          (data.assets as any[])?.length || 1
        } assets and ${(data.services as any[])?.length || 0} open services`;
      case "action_approved":
        return `Policy Firewall: APPROVED action ${(data.action as any)?.tool_name || "probe"}`;
      case "action_blocked":
        return `Policy Firewall: BLOCKED action ${(data.action as any)?.tool_name || "probe"} (Out of scope)`;
      case "tool_completed":
        return `Tool completed: ${(data.action as any)?.tool_name || "scan"}`;
      case "finding_verified":
        return `Finding Verified: ${(data.finding as any)?.title || "Vulnerability confirmed"}`;
      case "assessment_paused":
        return `Assessment paused cleanly. Graph checkpoint saved (${data.checkpoint_id || "chk"})`;
      case "assessment_resumed":
        return "Assessment resumed from latest checkpoint state";
      case "report_generated":
        return "Executive report and client PDF deliverables generated";
      case "assessment_completed":
        return `Assessment finished. Outcome: ${data.outcome || data.status || "COMPLETED"}`;
      case "assessment_failed":
        return `Assessment failed: ${data.error || "Unknown error"}`;
      case "node_transition":
        return `Node transition: ${evt.node || (data as any)?.node || "state machine step"}`;
      default:
        return `${evt.eventType}: ${JSON.stringify(data)}`;
    }
  };

  return (
    <div className="glass-panel rounded-2xl border border-cyber-border overflow-hidden flex flex-col h-[520px]">
      <div className="p-4 border-b border-cyber-border bg-cyber-bg/40 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Terminal className="h-4 w-4 text-cyan-400" />
          <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-white">
            Audit Timeline (Live SSE Feed)
          </h3>
        </div>
        <span className="text-[11px] font-mono text-cyber-muted">
          {events.length} events logged
        </span>
      </div>

      <div ref={scrollRef} className="p-4 overflow-y-auto space-y-3 font-mono text-xs flex-1">
        {events.length === 0 ? (
          <div className="h-full flex items-center justify-center text-cyber-muted">
            Waiting for agent execution events...
          </div>
        ) : (
          events.map((evt, idx) => (
            <div
              key={`${evt.id}-${idx}`}
              className="flex items-start gap-3 rounded-lg border border-cyber-border/40 bg-cyber-bg/40 p-2.5 hover:border-cyber-border transition-colors"
            >
              <div className="mt-0.5 rounded p-1 bg-cyber-panel border border-cyber-border/60">
                {getEventIcon(evt.eventType)}
              </div>
              <div className="flex-1 space-y-1 overflow-hidden">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-semibold text-white text-[11px]">
                    {evt.eventType}
                  </span>
                  <span className="text-[10px] text-cyber-muted shrink-0">
                    {new Date(evt.timestamp).toLocaleTimeString()}
                  </span>
                </div>
                <p className="text-cyber-text text-[11.5px] leading-relaxed break-words">
                  {getEventLabel(evt)}
                </p>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

