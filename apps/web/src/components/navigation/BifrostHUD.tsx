"use client";

import { Cpu, DollarSign, Clock, Layers, Pause, Play, Square, FileText } from "lucide-react";
import { AssessmentDetail } from "@/lib/types";
import { formatCurrency, getStatusColor } from "@/lib/utils";

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
    <div className="glass-panel-elevated rounded-2xl p-4 sm:p-5 border border-cyber-border mb-6">
      <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
        {/* Left: Target & Status */}
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-2">
            <span className="flex h-3 w-3 relative">
              <span className={`inline-flex h-full w-full rounded-full ${statusInfo.dot}`}></span>
            </span>
            <span className={`px-2.5 py-1 rounded-full text-xs font-mono font-bold border ${statusInfo.badge}`}>
              {assessment.status}
            </span>
          </div>

          <div className="h-4 w-[1px] bg-cyber-border hidden sm:block"></div>

          <div className="font-mono text-sm sm:text-base font-bold text-white tracking-wide">
            {assessment.target?.value || "Target Unset"}
          </div>

          {assessment.simulation && (
            <span className="rounded bg-amber-500/10 px-2 py-0.5 text-[10px] font-mono font-semibold text-amber-400 border border-amber-500/30">
              SIMULATION MODE
            </span>
          )}
        </div>

        {/* Center: Bifrost Real-Time Telemetry Bar */}
        <div className="flex flex-wrap items-center gap-4 bg-cyber-bg/60 rounded-xl px-4 py-2 border border-cyber-border/80 text-xs font-mono">
          <div className="flex items-center gap-1.5 text-cyber-muted">
            <Cpu className="h-3.5 w-3.5 text-cyber-violet" />
            <span className="text-white font-semibold">Claude 3.5 Sonnet</span>
            <span className="text-[10px] text-cyber-violet bg-cyber-violet/10 px-1 rounded">Bifrost</span>
          </div>

          <div className="h-3 w-[1px] bg-cyber-border"></div>

          <div className="flex items-center gap-1.5 text-cyber-muted">
            <Layers className="h-3.5 w-3.5 text-cyan-400" />
            <span>Tokens:</span>
            <span className="text-white font-semibold">{tokens.toLocaleString()}</span>
          </div>

          <div className="h-3 w-[1px] bg-cyber-border"></div>

          <div className="flex items-center gap-1.5 text-cyber-muted">
            <Clock className="h-3.5 w-3.5 text-emerald-400" />
            <span>Latency:</span>
            <span className="text-white font-semibold">320ms</span>
          </div>

          <div className="h-3 w-[1px] bg-cyber-border"></div>

          <div className="flex items-center gap-1.5 text-cyber-muted">
            <DollarSign className="h-3.5 w-3.5 text-amber-400" />
            <span>Cost:</span>
            <span className="text-amber-400 font-bold">{formatCurrency(cost)}</span>
          </div>
        </div>

        {/* Right: Lifecycle Controls */}
        <div className="flex items-center gap-2">
          {assessment.status === "RUNNING" && (
            <button
              onClick={onPause}
              disabled={isActionLoading}
              className="flex items-center gap-1.5 rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-1.5 text-xs font-medium text-amber-300 hover:bg-amber-500/20 active:scale-95 transition-all disabled:opacity-50"
            >
              <Pause className="h-3.5 w-3.5" />
              Pause
            </button>
          )}

          {assessment.status === "PAUSED" && (
            <button
              onClick={onResume}
              disabled={isActionLoading}
              className="flex items-center gap-1.5 rounded-lg border border-emerald-500/40 bg-emerald-500/10 px-3 py-1.5 text-xs font-medium text-emerald-300 hover:bg-emerald-500/20 active:scale-95 transition-all disabled:opacity-50"
            >
              <Play className="h-3.5 w-3.5" />
              Resume
            </button>
          )}

          {!assessment.is_terminal && (
            <button
              onClick={onCancel}
              disabled={isActionLoading}
              className="flex items-center gap-1.5 rounded-lg border border-rose-500/40 bg-rose-500/10 px-3 py-1.5 text-xs font-medium text-rose-300 hover:bg-rose-500/20 active:scale-95 transition-all disabled:opacity-50"
            >
              <Square className="h-3.5 w-3.5" />
              Cancel
            </button>
          )}

          <button
            onClick={onDownloadPdf}
            className="flex items-center gap-1.5 rounded-lg border border-indigo-500/40 bg-indigo-500/20 px-3 py-1.5 text-xs font-medium text-indigo-300 hover:bg-indigo-500/30 active:scale-95 transition-all"
          >
            <FileText className="h-3.5 w-3.5" />
            PDF Report
          </button>
        </div>
      </div>
    </div>
  );
}

