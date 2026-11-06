"use client";

import { useState } from "react";
import { Shield, Clock, Layers, Pause, Play, Square, FileText, Check, Copy } from "lucide-react";
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
  onDownloadPdf?: () => void;
  isActionLoading?: boolean;
}

export function BifrostHUD({
  assessment,
  onPause,
  onResume,
  onCancel,
  onDownloadPdf,
  isActionLoading = false,
}: BifrostHUDProps) {
  const statusInfo = getStatusColor(assessment.status);
  const [copied, setCopied] = useState(false);

  const targetValue = assessment.target?.value || "Target Unset";
  const assetsCount = assessment.discovered_assets?.length || 0;
  const servicesCount = assessment.discovered_services?.length || 0;
  const findingsCount = assessment.findings?.length || 0;

  const handleCopyTarget = () => {
    navigator.clipboard.writeText(targetValue);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
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
                onClick={handleCopyTarget}
                className="text-muted-foreground hover:text-foreground transition-colors p-1 rounded hover:bg-muted/50"
                title="Copy Target"
              >
                {copied ? <Check className="h-3.5 w-3.5 text-emerald-500" /> : <Copy className="h-3.5 w-3.5 opacity-60" />}
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
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
