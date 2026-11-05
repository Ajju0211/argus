import Link from "next/link";
import { Bug, ShieldCheck, ExternalLink } from "lucide-react";
import { Finding } from "@/lib/types";
import { getSeverityColor } from "@/lib/utils";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

interface FindingsBoardProps {
  findings: Finding[];
  assessmentId: string;
}

export function FindingsBoard({ findings, assessmentId }: FindingsBoardProps) {
  return (
    <Card className="space-y-4">
      <CardHeader className="border-b border-border py-3 px-4 flex flex-row items-center justify-between">
        <div className="flex items-center gap-2">
          <Bug className="h-4 w-4 text-destructive" />
          <CardTitle className="text-xs uppercase tracking-wider">
            Verified Security Findings
          </CardTitle>
        </div>
        <Badge variant="success">
          {findings.length} Evidence-Backed
        </Badge>
      </CardHeader>

      <CardContent className="space-y-3 font-mono p-4">
        {findings.length === 0 ? (
          <div className="rounded-md border border-border bg-muted/20 p-8 text-center text-xs text-muted-foreground">
            No confirmed findings yet. Only findings with verifiable cryptographic proof are promoted.
          </div>
        ) : (
          findings.map((finding) => {
            const sev = getSeverityColor(finding.severity);
            return (
              <div
                key={finding.finding_id}
                className={`rounded-md border ${sev.border} ${sev.bg} p-3.5 space-y-2.5 transition-all`}
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold border ${sev.badge}`}
                      >
                        {finding.severity}
                      </span>
                      <span className="text-xs font-bold text-foreground tracking-wide">
                        {finding.title}
                      </span>
                    </div>
                    <p className="text-[11px] text-muted-foreground leading-relaxed">
                      {finding.description}
                    </p>
                  </div>

                  <Badge variant="success" className="gap-1 shrink-0">
                    <ShieldCheck className="h-3 w-3" />
                    VERIFIED
                  </Badge>
                </div>

                {finding.reproduction_steps && (
                  <div className="rounded bg-muted/60 border border-border p-2 text-[10px] text-foreground overflow-x-auto">
                    <span className="text-primary font-bold">$ </span>
                    {finding.reproduction_steps}
                  </div>
                )}

                {/* Evidence Links */}
                {finding.evidence_ids && finding.evidence_ids.length > 0 && (
                  <div className="flex items-center gap-2 pt-1 border-t border-border text-[10px] text-muted-foreground">
                    <span>Evidence Vault:</span>
                    {finding.evidence_ids.map((evId) => (
                      <Link
                        key={evId}
                        href={`/assessments/${assessmentId}/evidence?focus=${evId}`}
                        className="inline-flex items-center gap-1 rounded bg-secondary px-2 py-0.5 text-foreground hover:text-primary transition-colors border border-border"
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
      </CardContent>
    </Card>
  );
}
