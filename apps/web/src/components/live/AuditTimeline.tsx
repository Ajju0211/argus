"use client";

import { useEffect, useRef } from "react";
import {
  Terminal,
  CheckCircle,
  AlertOctagon,
} from "lucide-react";
import { AssessmentEvent } from "@/lib/types";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

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
      case "scope_validated":
      case "action_approved":
      case "assessment_resumed":
      case "assessment_completed":
        return <CheckCircle className="h-3.5 w-3.5 text-foreground/70" />;
      case "action_blocked":
      case "finding_verified":
      case "assessment_failed":
        return <AlertOctagon className="h-3.5 w-3.5 text-rose-500" />;
      case "recon_completed":
      case "tool_completed":
      case "report_generated":
      default:
        return <Terminal className="h-3.5 w-3.5 text-muted-foreground/60" />;
    }
  };

  const getEventLabel = (evt: AssessmentEvent) => {
    const data = evt.data || {};
    switch (evt.eventType) {
      case "assessment_created":
        return "Assessment initialized and validated against scope boundaries";
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
        return `VERIFIED VULNERABILITY: ${(data.finding as any)?.title || "CVE identified"}`;
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
          events.map((evt, idx) => (
            <div
              key={`${evt.timestamp}-${idx}`}
              className="flex items-start gap-2.5 p-2 rounded hover:bg-muted/30 transition-colors"
            >
              <div className="mt-0.5 shrink-0">{getEventIcon(evt.eventType)}</div>
              <div className="flex-1 space-y-1 min-w-0">
                <div className="flex items-baseline justify-between gap-2">
                  <span className="text-[11px] font-medium text-foreground truncate">
                    {evt.eventType.replace(/_/g, " ").toUpperCase()}
                  </span>
                  <span className="text-[10px] text-muted-foreground shrink-0">
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
          ))
        )}
      </CardContent>
    </Card>
  );
}
