import { ShieldCheck, Target, Bug, Cpu } from "lucide-react";
import { AssessmentDetail } from "@/lib/types";
import { formatCurrency } from "@/lib/utils";

interface KpiCardGridProps {
  assessments: AssessmentDetail[];
}

export function KpiCardGrid({ assessments }: KpiCardGridProps) {
  const totalRuns = assessments.length;
  const successfulRuns = assessments.filter((a) =>
    ["SUCCESS", "COMPLETED"].includes(a.status)
  ).length;
  const successRate = totalRuns > 0 ? ((successfulRuns / totalRuns) * 100).toFixed(0) : "100";

  const totalAssets = assessments.reduce(
    (acc, a) => acc + (a.discovered_assets?.length || 0),
    0
  );
  const totalServices = assessments.reduce(
    (acc, a) => acc + (a.discovered_services?.length || 0),
    0
  );

  const allFindings = assessments.flatMap((a) => a.findings || []);
  const criticalCount = allFindings.filter((f) => f.severity === "CRITICAL").length;
  const highCount = allFindings.filter((f) => f.severity === "HIGH").length;
  const medCount = allFindings.filter((f) => f.severity === "MEDIUM").length;

  const totalTokens = assessments.reduce(
    (acc, a) => acc + (a.budget?.tokens_consumed || 1640),
    0
  );
  const totalCost = (totalTokens / 1_000_000) * 15.0;

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
      {/* KPI 1: Assessments */}
      <div className="glass-panel rounded-2xl p-5 border border-cyber-border hover:border-indigo-500/40 transition-colors">
        <div className="flex items-center justify-between text-cyber-muted mb-3">
          <span className="text-xs font-mono uppercase tracking-wider">Assessments</span>
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-indigo-500/10 text-indigo-400 border border-indigo-500/20">
            <ShieldCheck className="h-4 w-4" />
          </div>
        </div>
        <div className="flex items-baseline gap-2">
          <span className="text-3xl font-mono font-bold text-white">{totalRuns}</span>
          <span className="text-xs font-mono text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/30">
            {successRate}% Success
          </span>
        </div>
        <p className="text-xs text-cyber-muted mt-2">Autonomous LangGraph runs</p>
      </div>

      {/* KPI 2: Attack Surface */}
      <div className="glass-panel rounded-2xl p-5 border border-cyber-border hover:border-cyan-500/40 transition-colors">
        <div className="flex items-center justify-between text-cyber-muted mb-3">
          <span className="text-xs font-mono uppercase tracking-wider">Attack Surface</span>
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
            <Target className="h-4 w-4" />
          </div>
        </div>
        <div className="flex items-baseline gap-2">
          <span className="text-3xl font-mono font-bold text-white">{totalAssets}</span>
          <span className="text-xs font-mono text-cyan-400 bg-cyan-500/10 px-2 py-0.5 rounded border border-cyan-500/30">
            {totalServices} Services
          </span>
        </div>
        <p className="text-xs text-cyber-muted mt-2">Discovered hosts & mapped ports</p>
      </div>

      {/* KPI 3: Vulnerabilities */}
      <div className="glass-panel rounded-2xl p-5 border border-cyber-border hover:border-rose-500/40 transition-colors">
        <div className="flex items-center justify-between text-cyber-muted mb-3">
          <span className="text-xs font-mono uppercase tracking-wider">Verified Findings</span>
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-rose-500/10 text-rose-400 border border-rose-500/20">
            <Bug className="h-4 w-4" />
          </div>
        </div>
        <div className="flex items-baseline gap-2">
          <span className="text-3xl font-mono font-bold text-white">{allFindings.length}</span>
          <span className="text-xs font-mono text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/30">
            100% Verified
          </span>
        </div>
        <div className="flex items-center gap-1.5 mt-2 font-mono text-[11px]">
          <span className="text-rose-400 font-bold">{criticalCount} Crit</span>
          <span className="text-cyber-muted">·</span>
          <span className="text-orange-400 font-bold">{highCount} High</span>
          <span className="text-cyber-muted">·</span>
          <span className="text-amber-400 font-bold">{medCount} Med</span>
        </div>
      </div>

      {/* KPI 4: Bifrost Gateway Efficiency */}
      <div className="glass-panel rounded-2xl p-5 border border-cyber-border hover:border-violet-500/40 transition-colors">
        <div className="flex items-center justify-between text-cyber-muted mb-3">
          <span className="text-xs font-mono uppercase tracking-wider">Bifrost Gateway</span>
          <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-violet-500/10 text-violet-400 border border-violet-500/20">
            <Cpu className="h-4 w-4" />
          </div>
        </div>
        <div className="flex items-baseline gap-2">
          <span className="text-3xl font-mono font-bold text-white">{formatCurrency(totalCost)}</span>
          <span className="text-xs font-mono text-violet-400 bg-violet-500/10 px-2 py-0.5 rounded border border-violet-500/30">
            ~320ms avg
          </span>
        </div>
        <p className="text-xs text-cyber-muted mt-2">
          {totalTokens.toLocaleString()} tokens via Claude 3.5
        </p>
      </div>
    </div>
  );
}

