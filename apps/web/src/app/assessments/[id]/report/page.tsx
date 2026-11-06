"use client";

import { use, useEffect, useState } from "react";
import Link from "next/link";
import {
  ArrowLeft,
  Download,
  ExternalLink,
  Copy,
  Check,
} from "lucide-react";
import { getAssessment, getReport } from "@/lib/api";
import { AssessmentDetail } from "@/lib/types";
import { getSeverityColor } from "@/lib/utils";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

interface PageProps {
  params: Promise<{ id: string }>;
}

export default function ReportDeliverablePage({ params }: PageProps) {
  const resolvedParams = use(params);
  const assessmentId = resolvedParams.id;

  const [assessment, setAssessment] = useState<AssessmentDetail | null>(null);
  const [reportMarkdown, setReportMarkdown] = useState<string>("");
  const [isLoading, setIsLoading] = useState(true);
  const [hasCopied, setHasCopied] = useState(false);

  useEffect(() => {
    setIsLoading(true);
    Promise.all([
      getAssessment(assessmentId),
      getReport(assessmentId, "json").catch(() => ({ markdown: "" })),
    ])
      .then(([asmData, repData]) => {
        setAssessment(asmData);
        setReportMarkdown(repData.markdown || "");
      })
      .finally(() => setIsLoading(false));
  }, [assessmentId]);

  const handleCopyMd = () => {
    navigator.clipboard.writeText(reportMarkdown);
    setHasCopied(true);
    setTimeout(() => setHasCopied(false), 2000);
  };

  const handleDownloadPdf = () => {
    window.open(`/api/v1/assessments/${assessmentId}/report/pdf`, "_blank");
  };

  const handleOpenHtml = () => {
    window.open(`/api/v1/assessments/${assessmentId}/report?format=html`, "_blank");
  };

  if (isLoading || !assessment) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] space-y-3">
        <div className="h-6 w-6 animate-spin rounded-full border-2 border-primary border-t-transparent"></div>
        <p className="text-xs text-muted-foreground">Preparing Executive Report...</p>
      </div>
    );
  }

  const findings = assessment.findings || [];
  const criticalCount = findings.filter((f) => f.severity === "CRITICAL").length;
  const highCount = findings.filter((f) => f.severity === "HIGH").length;

  return (
    <div className="max-w-5xl mx-auto space-y-6">
      {/* Navigation Breadcrumb */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 text-xs">
        <div className="flex items-center gap-2 text-muted-foreground">
          <Link href={`/assessments/${assessmentId}`} className="hover:text-foreground flex items-center gap-1 transition-colors">
            <ArrowLeft className="h-3 w-3" />
            Back to Assessment
          </Link>
          <span>/</span>
          <span className="text-foreground font-medium">Executive Report</span>
        </div>

        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={handleCopyMd}
            disabled={!reportMarkdown}
            className="text-xs gap-1.5"
          >
            {hasCopied ? <Check className="h-3.5 w-3.5 text-emerald-500" /> : <Copy className="h-3.5 w-3.5 opacity-60" />}
            <span>{hasCopied ? "Copied" : "Copy Markdown"}</span>
          </Button>

          <Button
            variant="outline"
            size="sm"
            onClick={handleOpenHtml}
            className="text-xs gap-1.5"
          >
            <ExternalLink className="h-3.5 w-3.5" />
            <span>HTML Report</span>
          </Button>

          <Button
            size="sm"
            onClick={handleDownloadPdf}
            className="text-xs gap-1.5"
          >
            <Download className="h-3.5 w-3.5" />
            <span>Download PDF</span>
          </Button>
        </div>
      </div>

      {/* Deliverable Document Card */}
      <Card className="p-6 sm:p-8 space-y-8 border-border/80">
        {/* Report Header */}
        <div className="border-b border-border/60 pb-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-1.5">
              <Badge variant="outline" className="text-xs">
                CISO Security Deliverable
              </Badge>
              {assessment.simulation && (
                <Badge variant="outline" className="text-[10px]">
                  Simulation Audit
                </Badge>
              )}
            </div>
            <h1 className="text-xl sm:text-2xl font-semibold tracking-tight text-foreground">
              Security Assessment: {assessment.name || assessment.id}
            </h1>
            <p className="text-xs text-muted-foreground mt-1 font-mono">
              Target: {assessment.target?.value} · Generated: {new Date().toLocaleDateString()}
            </p>
          </div>

          <div className="flex items-center gap-4 bg-muted/40 border border-border p-3.5 rounded-lg shrink-0">
            <div className="text-center">
              <div className="text-[10px] text-muted-foreground uppercase tracking-wider font-medium">Risk Score</div>
              <div className="text-2xl font-mono font-bold text-destructive">
                {criticalCount > 0 ? "9.8" : highCount > 0 ? "7.5" : "3.0"}
                <span className="text-xs text-muted-foreground font-normal"> / 10</span>
              </div>
            </div>
          </div>
        </div>

        {/* Findings Summary Matrix */}
        <div className="space-y-3">
          <h2 className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
            Verified Vulnerability Summary
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {findings.length === 0 ? (
              <div className="col-span-2 p-6 rounded-md border border-border bg-muted/20 text-center text-xs text-muted-foreground">
                No vulnerabilities verified during this run.
              </div>
            ) : (
              findings.map((f) => {
                const sev = getSeverityColor(f.severity);
                return (
                  <div
                    key={f.finding_id}
                    className={`p-3.5 rounded-md border ${sev.border} ${sev.bg} space-y-2`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold border ${sev.badge}`}>
                        {f.severity}
                      </span>
                      <span className="text-[11px] font-mono text-muted-foreground">{f.finding_id}</span>
                    </div>
                    <div className="text-xs font-semibold text-foreground tracking-tight">
                      {f.title}
                    </div>
                    <p className="text-xs text-muted-foreground line-clamp-2 leading-relaxed">
                      {f.description}
                    </p>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Markdown Narrative Body */}
        {reportMarkdown && (
          <div className="border-t border-border/60 pt-6 space-y-4">
            <h2 className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
              Technical Narrative
            </h2>
            <div className="prose prose-sm dark:prose-invert max-w-none bg-muted/20 p-5 rounded-md border border-border text-xs leading-relaxed custom-scrollbar overflow-x-auto whitespace-pre-wrap font-mono">
              {reportMarkdown}
            </div>
          </div>
        )}
      </Card>
    </div>
  );
}
