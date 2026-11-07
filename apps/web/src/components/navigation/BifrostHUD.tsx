"use client";

import { useState } from "react";
import { Shield, Clock, Layers, Pause, Play, Square, FileText, Check, Copy, Trash2 } from "lucide-react";
import { AssessmentDetail } from "@/lib/types";
import { getStatusColor } from "@/lib/utils";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";

interface BifrostHUDProps {
  assessment: AssessmentDetail;
  onPause?: () => void;
  onResume?: () => void;
  onCancel?: () => void;
  onDelete?: () => void;
  onDownloadPdf?: () => void;
  isActionLoading?: boolean;
}

export function BifrostHUD({
  assessment,
  onPause,
  onResume,
  onCancel,
  onDelete,
  onDownloadPdf,
  isActionLoading = false,
}: BifrostHUDProps) {
  const statusInfo = getStatusColor(assessment.status);
  const [copiedField, setCopiedField] = useState<"target" | "trace" | "session" | null>(null);

  const isDev =
    process.env.NODE_ENV === "development" ||
    process.env.NEXT_PUBLIC_DEV_MODE === "true";

  const targetValue = assessment.target?.value || "Target Unset";
  const assetsCount = assessment.discovered_assets?.length || 0;
  const servicesCount = assessment.discovered_services?.length || 0;
  const findingsCount = assessment.findings?.length || 0;

  const handleCopy = (text: string, field: "target" | "trace" | "session") => {
    if (typeof navigator !== "undefined" && navigator.clipboard) {
      navigator.clipboard.writeText(text);
      setCopiedField(field);
      setTimeout(() => setCopiedField(null), 2000);
    }
  };

  return (
    <Card className="mb-6 border-border/70 bg-card">
      <CardContent className="p-4 sm:p-5">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          {/* Left: Target & Status */}
          <div className="flex flex-wrap items-center gap-3">
            <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-mono font-medium border ${statusInfo.badge}`}>
              <span className={`h-1.5 w-1.5 rounded-full ${statusInfo.dot}`}></span>
              {assessment.status}
            </span>

            <span className="text-border/60">|</span>

            <div className="flex items-center gap-2">
              <span className="font-mono text-sm sm:text-base font-semibold text-foreground tracking-tight">
                {targetValue}
              </span>
              <button
                onClick={() => handleCopy(targetValue, "target")}
                className="text-muted-foreground hover:text-foreground transition-colors p-1 rounded hover:bg-muted/50"
                title="Copy Target"
              >
                {copiedField === "target" ? (
                  <Check className="h-3.5 w-3.5 text-emerald-500" />
                ) : (
                  <Copy className="h-3.5 w-3.5 opacity-60" />
                )}
              </button>
            </div>

            {assessment.simulation && (
              <Badge variant="outline" className="text-[10px] text-muted-foreground border-border/60 font-normal">
                Simulation Mode
              </Badge>
            )}
          </div>

          {/* Center: Real Assessment Telemetry */}
          <div className="flex flex-wrap items-center gap-3 bg-muted/30 rounded-md px-3.5 py-1.5 border border-border/60 text-xs">
            <div className="flex items-center gap-1.5 text-muted-foreground">
              <Shield className="h-3.5 w-3.5 text-muted-foreground/60" />
              <span>Targets:</span>
              <span className="text-foreground font-mono font-medium">{assetsCount}</span>
            </div>

            <span className="text-border/60">|</span>

            <div className="flex items-center gap-1.5 text-muted-foreground">
              <Layers className="h-3.5 w-3.5 text-muted-foreground/60" />
              <span>Services:</span>
              <span className="text-foreground font-mono font-medium">{servicesCount}</span>
            </div>

            <span className="text-border/60">|</span>

            <div className="flex items-center gap-1.5 text-muted-foreground">
              <Clock className="h-3.5 w-3.5 text-muted-foreground/60" />
              <span>Findings:</span>
              <span className="text-foreground font-mono font-medium">{findingsCount}</span>
            </div>
          </div>

          {/* Right: Lifecycle Controls */}
          <div className="flex items-center gap-2">
            {assessment.status === "RUNNING" && (
              <Button
                variant="outline"
                size="sm"
                onClick={onPause}
                disabled={isActionLoading}
                className="gap-1.5 text-xs h-7.5 px-2.5"
              >
                <Pause className="h-3.5 w-3.5" />
                <span>Pause</span>
              </Button>
            )}

            {assessment.status === "PAUSED" && (
              <Button
                variant="outline"
                size="sm"
                onClick={onResume}
                disabled={isActionLoading}
                className="gap-1.5 text-xs h-7.5 px-2.5"
              >
                <Play className="h-3.5 w-3.5" />
                <span>Resume</span>
              </Button>
            )}

            {["RUNNING", "PAUSED", "QUEUED", "READY"].includes(assessment.status) && (
              <Button
                variant="destructive"
                size="sm"
                onClick={onCancel}
                disabled={isActionLoading}
                className="gap-1.5 text-xs h-7.5 px-2.5"
              >
                <Square className="h-3.5 w-3.5 fill-current" />
                <span>Abort</span>
              </Button>
            )}

            <Button
              variant="outline"
              size="sm"
              onClick={onDownloadPdf}
              className="gap-1.5 text-xs h-7.5 px-2.5"
            >
              <FileText className="h-3.5 w-3.5" />
              <span>PDF Report</span>
            </Button>

            {onDelete && (
              <Button
                variant="ghost"
                size="sm"
                onClick={onDelete}
                disabled={isActionLoading}
                className="gap-1.5 text-xs h-7.5 px-2.5 text-rose-600 hover:bg-rose-500/10 hover:text-rose-600 dark:text-rose-400 dark:hover:text-rose-400"
              >
                <Trash2 className="h-3.5 w-3.5" />
                <span>Delete</span>
              </Button>
            )}
          </div>
        </div>

        {/* Dev Mode Only: Langfuse Trace ID & Session ID with Copy */}
        {isDev && (
          <div className="mt-3 pt-3 border-t border-border/50 flex flex-wrap items-center justify-between gap-2.5">
            <div className="flex items-center gap-2">
              <Badge
                variant="outline"
                className="font-mono text-[10px] uppercase font-semibold bg-amber-500/10 text-amber-500 border-amber-500/30 px-1.5 py-0.5"
              >
                Dev Mode
              </Badge>
              <span className="text-[11px] font-mono text-muted-foreground">Langfuse Observability</span>
            </div>

            {assessment.langfuse_trace_id ? (
              <div className="flex flex-wrap items-center gap-2.5">
                {/* Langfuse Trace ID */}
                <div className="flex items-center gap-1.5 bg-muted/30 border border-border/60 rounded px-2.5 py-1 text-xs font-mono">
                  <span className="text-muted-foreground text-[11px]">Trace ID:</span>
                  <span className="text-foreground text-[11px] font-medium tracking-tight">
                    {assessment.langfuse_trace_id}
                  </span>
                  <button
                    onClick={() => handleCopy(assessment.langfuse_trace_id!, "trace")}
                    className="text-muted-foreground hover:text-foreground transition-colors p-0.5 rounded hover:bg-muted/60"
                    title="Copy Langfuse Trace ID"
                  >
                    {copiedField === "trace" ? (
                      <Check className="h-3 w-3 text-emerald-500" />
                    ) : (
                      <Copy className="h-3 w-3 opacity-60" />
                    )}
                  </button>
                </div>

                {/* Session ID */}
                <div className="flex items-center gap-1.5 bg-muted/30 border border-border/60 rounded px-2.5 py-1 text-xs font-mono">
                  <span className="text-muted-foreground text-[11px]">Session ID:</span>
                  <span className="text-foreground text-[11px] font-medium tracking-tight">
                    {assessment.langfuse_session_id || assessment.id}
                  </span>
                  <button
                    onClick={() =>
                      handleCopy(assessment.langfuse_session_id || assessment.id, "session")
                    }
                    className="text-muted-foreground hover:text-foreground transition-colors p-0.5 rounded hover:bg-muted/60"
                    title="Copy Langfuse Session ID"
                  >
                    {copiedField === "session" ? (
                      <Check className="h-3 w-3 text-emerald-500" />
                    ) : (
                      <Copy className="h-3 w-3 opacity-60" />
                    )}
                  </button>
                </div>
              </div>
            ) : assessment.langfuse_configured ? (
              <div className="flex items-center gap-1.5 text-[11px] font-mono text-emerald-600 dark:text-emerald-400 bg-emerald-500/10 border border-emerald-500/30 rounded px-2.5 py-1">
                <span className="h-1.5 w-1.5 rounded-full bg-emerald-500 animate-pulse" />
                <span>Langfuse Active on Server (Historical run prior to setup — start a new assessment to see live trace)</span>
              </div>
            ) : (
              <div className="flex items-center gap-1.5 text-[11px] font-mono text-muted-foreground bg-muted/20 border border-border/40 rounded px-2 py-1">
                <span className="h-1.5 w-1.5 rounded-full bg-muted-foreground/40" />
                <span>Langfuse: Inactive (Credentials not set)</span>
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
