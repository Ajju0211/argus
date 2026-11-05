import Link from "next/link";
import { Bug, ShieldCheck, ExternalLink, Terminal } from "lucide-react";
import { Finding } from "@/lib/types";
import { getSeverityColor } from "@/lib/utils";

interface FindingsBoardProps {
  findings: Finding[];
  assessmentId: string;
}

export function FindingsBoard({ findings, assessmentId }: FindingsBoardProps) {
  return (
    <div className="glass-panel rounded-2xl border border-cyber-border p-4 sm:p-5 space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Bug className="h-4 w-4 text-rose-400" />
          <h3 className="text-xs font-mono font-bold uppercase tracking-wider text-white">
            Verified Security Findings
          </h3>
        </div>
        <span className="text-[11px] font-mono text-emerald-400 bg-emerald-500/10 border border-emerald-500/30 px-2 py-0.5 rounded">
          {findings.length} Evidence-Backed
        </span>
      </div>

      <div className="space-y-3 font-mono">
        {findings.length === 0 ? (
          <div className="rounded-xl border border-cyber-border/40 bg-cyber-bg/30 p-8 text-center text-xs text-cyber-muted">
            No confirmed findings yet. Only findings with verifiable cryptographic proof are promoted.
          </div>
        ) : (
          findings.map((finding) => {
            const sev = getSeverityColor(finding.severity);
            return (
              <div
                key={finding.finding_id}
                className={`rounded-xl border ${sev.border} ${sev.bg} p-3.5 space-y-2.5 transition-all`}
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold border ${sev.badge}`}
                      >
                        {finding.severity}
                      </span>
                      <span className="text-xs font-bold text-white tracking-wide">
                        {finding.title}
                      </span>
                    </div>
                    <p className="text-[11px] text-cyber-text leading-relaxed">
                      {finding.description}
                    </p>
                  </div>

                  <span className="inline-flex items-center gap-1 rounded bg-emerald-500/10 border border-emerald-500/30 px-2 py-0.5 text-[10px] font-bold text-emerald-300 shrink-0">
                    <ShieldCheck className="h-3 w-3 text-emerald-400" />
                    CONFIRMED
                  </span>
                </div>

                {finding.reproduction_steps && (
                  <div className="rounded-lg bg-cyber-bg/80 border border-cyber-border/80 p-2 text-[10px] text-cyan-300 overflow-x-auto">
                    <span className="text-cyber-muted">$ </span>
                    {finding.reproduction_steps}
                  </div>
                )}

                {/* Evidence Links */}
                {finding.evidence_ids && finding.evidence_ids.length > 0 && (
                  <div className="flex items-center gap-2 pt-1 border-t border-cyber-border/40 text-[10px] text-cyber-muted">
                    <span>Evidence Vault:</span>
                    {finding.evidence_ids.map((evId) => (
                      <Link
                        key={evId}
                        href={`/assessments/${assessmentId}/evidence?focus=${evId}`}
                        className="inline-flex items-center gap-1 rounded bg-indigo-500/10 border border-indigo-500/30 px-2 py-0.5 text-indigo-300 hover:text-white transition-colors"
                      >
                        {evId}
                        <ExternalLink className="h-2.5 w-2.5" />
                      </Link>
                    ))}
                  </div>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}

