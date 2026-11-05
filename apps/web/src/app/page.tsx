"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { PlusCircle, ShieldAlert, RefreshCw } from "lucide-react";
import { KpiCardGrid } from "@/components/dashboard/KpiCardGrid";
import { AssessmentsTable } from "@/components/dashboard/AssessmentsTable";
import { AssessmentDetail } from "@/lib/types";
import { listAssessments } from "@/lib/api";

export default function DashboardPage() {
  const [assessments, setAssessments] = useState<AssessmentDetail[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadAssessments = async (showLoading = true) => {
    if (showLoading) setIsLoading(true);
    setIsRefreshing(true);
    setError(null);
    try {
      const data = await listAssessments(50);
      setAssessments(data);
    } catch (err: any) {
      console.error("Failed to load assessments:", err);
      setError(err?.message || "Failed to connect to ARGUS API backend.");
    } finally {
      setIsLoading(false);
      setIsRefreshing(false);
    }
  };

  useEffect(() => {
    loadAssessments();
    const interval = setInterval(() => loadAssessments(false), 5000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="space-y-8">
      {/* Hero Welcome Banner */}
      <div className="relative overflow-hidden rounded-3xl glass-panel-elevated p-6 sm:p-8 border border-cyber-border">
        <div className="relative z-10 flex flex-col md:flex-row md:items-center justify-between gap-6">
          <div className="space-y-2">
            <div className="inline-flex items-center gap-2 rounded-full border border-indigo-500/30 bg-indigo-500/10 px-3 py-1 text-xs font-mono font-semibold text-indigo-300">
              <span className="flex h-1.5 w-1.5 rounded-full bg-indigo-400"></span>
              Autonomous Agent Orchestrator Active
            </div>
            <h1 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-white">
              Security Operations Center
            </h1>
            <p className="max-w-2xl text-xs sm:text-sm text-cyber-muted">
              Live proof-carrying assessment console. Every finding is verified by cryptographic evidence
              before promotion to prevent LLM hallucination.
            </p>
          </div>

          <div className="flex items-center gap-3">
            <button
              onClick={() => loadAssessments(false)}
              disabled={isRefreshing}
              className="flex items-center gap-2 rounded-xl border border-cyber-border bg-cyber-panel/80 px-4 py-2.5 text-xs font-mono text-cyber-muted hover:text-white hover:bg-cyber-card transition-all disabled:opacity-50"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${isRefreshing ? "animate-spin" : ""}`} />
              Refresh
            </button>

            <Link
              href="/new"
              className="flex items-center gap-2 rounded-xl bg-gradient-to-r from-indigo-600 via-indigo-500 to-cyan-500 px-5 py-2.5 text-xs font-mono font-bold text-white shadow-lg shadow-indigo-500/25 hover:brightness-110 active:scale-95 transition-all"
            >
              <PlusCircle className="h-4 w-4" />
              Launch Assessment
            </Link>
          </div>
        </div>
      </div>

      {/* Error Alert */}
      {error && (
        <div className="rounded-xl border border-rose-500/40 bg-rose-500/10 p-4 text-xs font-mono text-rose-300 flex items-center gap-3">
          <ShieldAlert className="h-5 w-5 text-rose-400 shrink-0" />
          <span>{error} Please ensure the backend is running at <code className="text-white">http://localhost:8000</code>.</span>
        </div>
      )}

      {/* KPI Cards */}
      <KpiCardGrid assessments={assessments} />

      {/* Historical Assessments Table */}
      <AssessmentsTable assessments={assessments} />
    </div>
  );
}

