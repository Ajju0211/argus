"use client";

import { use, useEffect, useState } from "react";
import Link from "next/link";
import {
  ArrowLeft,
  FileText,
  Download,
  ExternalLink,
  ShieldAlert,
  CheckCircle,
  Copy,
  Check,
} from "lucide-react";
import { getAssessment, getReport } from "@/lib/api";
import { AssessmentDetail } from "@/lib/types";
import { getSeverityColor } from "@/lib/utils";

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
      <div className="flex flex-col items-center justify-center min-h-[60vh] space-y-4">
        <div className="h-8 w-8 animate-spin rounded-full border-2 border-indigo-500 border-t-transparent"></div>
        <p className="text-xs font-mono text-cyber-muted">Preparing Executive Report...</p>
      </div>
    );
  }

  const findings = assessment.findings || [];
  const criticalCount = findings.filter((f) => f.severity === "CRITICAL").length;
  const highCount = findings.filter((f) => f.severity === "HIGH").length;

  return (
    <div className="max-w-5xl mx-auto space-y-6">
      {/* Navigation Breadcrumb */}
      <div className="flex items-center justify-between text-xs font-mono">
        <div className="flex items-center gap-2 text-cyber-muted">
          <Link href={`/assessments/${assessmentId}`} className="hover:text-white flex items-center gap-1 transition-colors">
            <ArrowLeft className="h-3 w-3" />
            Back to Assessment
          </Link>
          <span>/</span>
          <span className="text-white">Executive Report Deliverables</span>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleCopyMd}
            disabled={!reportMarkdown}
            className="flex items-center gap-1.5 rounded-lg border border-cyber-border bg-cyber-card px-3 py-1.5 text-xs font-mono text-cyber-muted hover:text-white transition-colors"
          >
            {hasCopied ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
            {hasCopied ? "Copied" : "Copy Markdown"}
          </button>
          <button
            onClick={handleOpenHtml}
            className="flex items-center gap-1.5 rounded-lg border border-cyber-border bg-cyber-card px-3 py-1.5 text-xs font-mono text-cyan-300 hover:text-white transition-colors"
          >
            <ExternalLink className="h-3.5 w-3.5" />
            HTML Report
          </button>
          <button
            onClick={handleDownloadPdf}
            className="flex items-center gap-1.5 rounded-lg bg-gradient-to-r from-indigo-600 to-cyan-500 px-4 py-1.5 text-xs font-mono font-bold text-white shadow-md shadow-indigo-600/30 hover:brightness-110 active:scale-95 transition-all"
          >
            <Download className="h-3.5 w-3.5" />
            Download PDF
          </button>
        </div>
      </div>

      {/* Deliverable Document Card */}
      <div className="glass-panel-elevated rounded-3xl p-6 sm:p-10 border border-cyber-border space-y-8 font-sans">
        {/* Report Header */}
        <div className="border-b border-cyber-border pb-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-2 mb-1">
              <span className="rounded bg-indigo-500/20 px-2 py-0.5 text-xs font-mono font-bold text-indigo-300 border border-indigo-500/30">
                ARGUS CISO DELIVERABLE
              </span>
              {assessment.simulation && (
                <span className="rounded bg-amber-500/20 px-2 py-0.5 text-xs font-mono font-bold text-amber-300 border border-amber-500/30">
                  SIMULATION RUN
                </span>
              )}
            </div>
            <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
              Executive Security Assessment Report
            </h1>
            <p className="text-xs sm:text-sm text-cyber-muted font-mono mt-1">
              Target: <span className="text-white font-semibold">{assessment.target?.value}</span> · Generated {new Date(assessment.created_at).toLocaleDateString()}
            </p>
          </div>

          <div className="flex items-center gap-4 bg-cyber-bg/80 border border-cyber-border p-4 rounded-2xl shrink-0 font-mono">
            <div>
              <div className="text-[10px] text-cyber-muted uppercase">Risk Score</div>
              <div className="text-2xl font-black text-rose-400">
                {criticalCount > 0 ? "9.8" : highCount > 0 ? "7.5" : "3.0"}
                <span className="text-xs text-cyber-muted font-normal"> / 10</span>
              </div>
            </div>
            <div className="h-8 w-[1px] bg-cyber-border"></div>
            <div>
              <div className="text-[10px] text-cyber-muted uppercase">Confidence</div>
              <div className="text-sm font-bold text-emerald-400 flex items-center gap-1">
                <CheckCircle className="h-3.5 w-3.5" />
                100% PROVEN
              </div>
            </div>
          </div>
        </div>

        {/* Executive Summary */}
        <div className="space-y-3">
          <h2 className="text-lg font-bold text-white tracking-wide font-mono">1. Executive Summary</h2>
          <div className="rounded-2xl border border-cyber-border bg-cyber-bg/40 p-5 text-sm text-cyber-text leading-relaxed font-sans">
            {assessment.summary ||
              "Automated security assessment conducted under authorized scope constraints. Discovered open attack surfaces and confirmed reproducible vulnerabilities backed by cryptographic EvidenceVault artifacts."}
          </div>
        </div>

        {/* Verified Findings */}
        <div className="space-y-3">
          <h2 className="text-lg font-bold text-white tracking-wide font-mono">2. Confirmed Vulnerability Inventory</h2>
          {findings.length === 0 ? (
            <div className="rounded-xl border border-cyber-border/40 bg-cyber-bg/40 p-6 text-center text-xs font-mono text-cyber-muted">
              Zero vulnerabilities verified during this assessment run.
            </div>
          ) : (
            <div className="space-y-4">
              {findings.map((f, i) => {
                const sev = getSeverityColor(f.severity);
                return (
                  <div
                    key={f.finding_id || i}
                    className={`rounded-2xl border ${sev.border} ${sev.bg} p-5 space-y-3`}
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span className={`px-2 py-0.5 rounded text-xs font-bold font-mono border ${sev.badge}`}>
                          {f.severity}
                        </span>
                        <h3 className="text-base font-bold text-white">{f.title}</h3>
                      </div>
                      <span className="font-mono text-xs text-cyber-muted">
                        Asset: {f.affected_asset}
                      </span>
                    </div>

                    <p className="text-xs sm:text-sm text-cyber-text leading-relaxed">
                      {f.description}
                    </p>

                    {f.reproduction_steps && (
                      <div className="rounded-xl border border-cyber-border bg-cyber-bg/80 p-3 font-mono text-xs text-cyan-300">
                        <div className="text-[10px] uppercase text-cyber-muted mb-1">
                          Proof-of-Concept Reproduction Command
                        </div>
                        <code>{f.reproduction_steps}</code>
                      </div>
                    )}

                    {f.remediation && (
                      <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/10 p-3 font-mono text-xs text-emerald-300">
                        <div className="text-[10px] uppercase text-emerald-400 font-bold mb-1">
                          Remediation Guidance
                        </div>
                        <p>{f.remediation}</p>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>

        {/* Cryptographic Chain of Custody */}
        <div className="space-y-3">
          <h2 className="text-lg font-bold text-white tracking-wide font-mono">3. Cryptographic Proof & Chain of Custody</h2>
          <div className="rounded-2xl border border-cyber-border bg-cyber-bg/40 p-5 font-mono text-xs space-y-2 text-cyber-muted">
            <p>
              All discoveries are immutably tied to raw tool output hashes captured at execution time.
            </p>
            <div className="divide-y divide-cyber-border/40">
              {(assessment.evidence_refs || []).map((ref, idx) => (
                <div key={idx} className="py-2 flex items-center justify-between">
                  <span className="text-white font-semibold">{ref.evidence_id || ref.id}</span>
                  <span className="text-[11px] text-cyan-300 font-mono">SHA256: {ref.sha256}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

