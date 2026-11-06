import { ShieldCheck, Target, Bug, Lock } from "lucide-react";
import { AssessmentDetail } from "@/lib/types";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

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
  const otherCount = allFindings.length - criticalCount - highCount;

  const totalEvidence = assessments.reduce(
    (acc, a) => acc + (a.evidence_refs?.length || 0),
    0
  );

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5 mb-6">
      {/* KPI 1: Assessments */}
      <Card className="hover:border-border transition-colors">
        <CardContent className="p-4 sm:p-5">
          <div className="flex items-center justify-between text-muted-foreground mb-3">
            <span className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground/70">
              Assessments
            </span>
            <ShieldCheck className="h-4 w-4 text-muted-foreground/50" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl sm:text-3xl font-mono font-semibold text-foreground">
              {totalRuns}
            </span>
            <Badge variant="secondary" className="font-normal text-[10px]">
              {successRate}% Success
            </Badge>
          </div>
          <p className="text-xs text-muted-foreground mt-2">Autonomous pentest runs</p>
        </CardContent>
      </Card>

      {/* KPI 2: Attack Surface */}
      <Card className="hover:border-border transition-colors">
        <CardContent className="p-4 sm:p-5">
          <div className="flex items-center justify-between text-muted-foreground mb-3">
            <span className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground/70">
              Attack Surface
            </span>
            <Target className="h-4 w-4 text-muted-foreground/50" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl sm:text-3xl font-mono font-semibold text-foreground">
              {totalAssets}
            </span>
            <Badge variant="outline" className="font-normal text-[10px]">
              {totalServices} Services
            </Badge>
          </div>
          <p className="text-xs text-muted-foreground mt-2">Discovered hosts & mapped ports</p>
        </CardContent>
      </Card>

      {/* KPI 3: Vulnerabilities */}
      <Card className="hover:border-border transition-colors">
        <CardContent className="p-4 sm:p-5">
          <div className="flex items-center justify-between text-muted-foreground mb-3">
            <span className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground/70">
              Verified Findings
            </span>
            <Bug className="h-4 w-4 text-muted-foreground/50" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl sm:text-3xl font-mono font-semibold text-foreground">
              {allFindings.length}
            </span>
            {criticalCount > 0 ? (
              <Badge variant="destructive" className="font-medium text-[10px]">
                {criticalCount} Critical
              </Badge>
            ) : (
              <Badge variant="outline" className="font-normal text-[10px]">
                {highCount} High
              </Badge>
            )}
          </div>
          <div className="flex items-center gap-1.5 mt-2 text-xs text-muted-foreground">
            <span>{highCount} High</span>
            <span>·</span>
            <span>{otherCount} Other</span>
          </div>
        </CardContent>
      </Card>

      {/* KPI 4: Evidence Vault & Merkle Audit Trail */}
      <Card className="hover:border-border transition-colors">
        <CardContent className="p-4 sm:p-5">
          <div className="flex items-center justify-between text-muted-foreground mb-3">
            <span className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground/70">
              Evidence Vault
            </span>
            <Lock className="h-4 w-4 text-muted-foreground/50" />
          </div>
          <div className="flex items-baseline gap-2">
            <span className="text-2xl sm:text-3xl font-mono font-semibold text-foreground">
              {totalEvidence}
            </span>
            <Badge variant="secondary" className="font-normal text-[10px]">
              Merkle Tree
            </Badge>
          </div>
          <p className="text-xs text-muted-foreground mt-2">Cryptographic SHA-256 chain</p>
        </CardContent>
      </Card>
    </div>
  );
}
