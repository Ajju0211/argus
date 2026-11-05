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
        return <CheckCircle className="h-3.5 w-3.5 text-primary" />;
      case "action_blocked":
      case "finding_verified":
      case "assessment_failed":
        return <AlertOctagon className="h-3.5 w-3.5 text-destructive" />;
      case "recon_completed":
      case "tool_completed":
      case "report_generated":
      default:
        return <Terminal className="h-3.5 w-3.5 text-muted-foreground" />;
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
    <Card className="flex flex-col h-[520px]">
      <CardHeader className="border-b border-border py-3 px-4 flex flex-row items-center justify-between">
        <div className="flex items-center gap-2">
          <Terminal className="h-4 w-4 text-primary" />
          <CardTitle className="text-xs uppercase tracking-wider">
            Live ReAct Monologue & Audit Log
          </CardTitle>
        </div>
        <Badge variant="outline" className="text-[10px]">
          {events.length} Telemetry Events
        </Badge>
      </CardHeader>

      <CardContent
        ref={scrollRef}
        className="flex-1 overflow-y-auto p-4 space-y-3 font-mono text-xs"
      >
        {events.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-muted-foreground space-y-2">
            <Terminal className="h-6 w-6 opacity-40" />
            <p className="text-xs">Awaiting agent execution telemetry...</p>
          </div>
        ) : (
          events.map((evt, idx) => (
            <div
              key={`${evt.timestamp}-${idx}`}
              className="flex items-start gap-2.5 p-2 rounded hover:bg-muted/40 transition-colors"
            >
              <div className="mt-0.5 shrink-0">{getEventIcon(evt.eventType)}</div>
              <div className="flex-1 space-y-1 min-w-0">
                <div className="flex items-baseline justify-between gap-2">
                  <span className="text-[11px] font-semibold text-foreground truncate">
                    {evt.eventType.replace(/_/g, " ").toUpperCase()}
                  </span>
                  <span className="text-[10px] text-muted-foreground shrink-0">
                    {new Date(evt.timestamp).toLocaleTimeString()}
                  </span>
                </div>
                <p className="text-xs text-muted-foreground leading-relaxed break-words">
                  {getEventLabel(evt)}
                </p>
                {Boolean(evt.data?.rationale) && (
                  <p className="text-[11px] text-primary/90 bg-primary/5 p-1.5 rounded border border-primary/20">
                    <span className="font-semibold text-primary">Reasoning: </span>
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
