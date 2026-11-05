"use client";

import { Cpu, DollarSign, Clock, Layers, Pause, Play, Square, FileText } from "lucide-react";
import { AssessmentDetail } from "@/lib/types";
import { formatCurrency, getStatusColor } from "@/lib/utils";
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
  const budget = assessment.budget || {};
  const tokens = budget.tokens_consumed || (assessment.telemetry?.length ? assessment.telemetry.length * 320 : 1840);
  const cost = budget.estimated_cost_usd || (tokens / 1_000_000) * 15.0;

  return (
    <Card className="mb-6">
      <CardContent className="p-4 sm:p-5">
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          {/* Left: Target & Status */}
          <div className="flex flex-wrap items-center gap-3">
            <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-xs font-mono font-bold border ${statusInfo.badge}`}>
              <span className={`h-2 w-2 rounded-full ${statusInfo.dot}`}></span>
              {assessment.status}
            </span>

            <span className="text-border">|</span>

            <div className="font-mono text-sm sm:text-base font-bold text-foreground tracking-wide">
              {assessment.target?.value || "Target Unset"}
            </div>

            {assessment.simulation && (
              <Badge variant="outline" className="text-[10px]">
                SIMULATION MODE
              </Badge>
            )}
          </div>

          {/* Center: Bifrost Real-Time Telemetry Bar */}
          <div className="flex flex-wrap items-center gap-4 bg-muted/50 rounded-md px-4 py-2 border border-border text-xs font-mono">
            <div className="flex items-center gap-1.5 text-muted-foreground">
              <Cpu className="h-3.5 w-3.5 text-primary" />
              <span className="text-foreground font-semibold">Claude 3.5 Sonnet</span>
              <Badge variant="outline" className="text-[9px] py-0 px-1">
                Bifrost
              </Badge>
            </div>

            <span className="text-border">|</span>

            <div className="flex items-center gap-1.5 text-muted-foreground">
              <Layers className="h-3.5 w-3.5 text-muted-foreground" />
              <span>Tokens:</span>
              <span className="text-foreground font-semibold">{tokens.toLocaleString()}</span>
            </div>

            <span className="text-border">|</span>

            <div className="flex items-center gap-1.5 text-muted-foreground">
              <Clock className="h-3.5 w-3.5 text-primary" />
              <span>Latency:</span>
              <span className="text-foreground font-semibold">320ms</span>
            </div>

            <span className="text-border">|</span>

            <div className="flex items-center gap-1.5 text-muted-foreground">
              <DollarSign className="h-3.5 w-3.5 text-primary" />
              <span>Cost:</span>
              <span className="text-foreground font-bold">{formatCurrency(cost)}</span>
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
                className="gap-1.5"
              >
                <Pause className="h-3.5 w-3.5" />
                <span>Pause</span>
              </Button>
            )}

            {assessment.status === "PAUSED" && (
              <Button
                size="sm"
                onClick={onResume}
                disabled={isActionLoading}
                className="gap-1.5"
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
                className="gap-1.5"
              >
                <Square className="h-3.5 w-3.5 fill-current" />
                <span>Abort</span>
              </Button>
            )}

            {onDownloadPdf && (
              <Button
                variant="outline"
                size="sm"
                onClick={onDownloadPdf}
                className="gap-1.5"
              >
                <FileText className="h-3.5 w-3.5" />
                <span className="hidden sm:inline">Export PDF</span>
              </Button>
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
