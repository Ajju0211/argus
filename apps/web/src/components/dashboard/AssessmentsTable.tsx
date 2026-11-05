"use client";

import { useState } from "react";
import Link from "next/link";
import { Search, ExternalLink, FileText, ArrowRight } from "lucide-react";
import { AssessmentDetail } from "@/lib/types";
import { formatTimeAgo, getStatusColor } from "@/lib/utils";

interface AssessmentsTableProps {
  assessments: AssessmentDetail[];
}

export function AssessmentsTable({ assessments }: AssessmentsTableProps) {
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("ALL");

  const filtered = assessments.filter((a) => {
    const matchesSearch =
      a.id.toLowerCase().includes(search.toLowerCase()) ||
      a.name.toLowerCase().includes(search.toLowerCase()) ||
      a.target.value.toLowerCase().includes(search.toLowerCase());

    if (!matchesSearch) return false;
    if (statusFilter === "ALL") return true;
    if (statusFilter === "ACTIVE") return ["RUNNING", "QUEUED", "READY", "PAUSED"].includes(a.status);
    if (statusFilter === "COMPLETED") return ["SUCCESS", "COMPLETED"].includes(a.status);
    if (statusFilter === "FAILED") return ["FAILED", "CANCELLED"].includes(a.status);
    return true;
  });

  return (
    <div className="glass-panel rounded-2xl border border-cyber-border overflow-hidden">
      {/* Header & Controls */}
      <div className="p-4 sm:p-5 border-b border-cyber-border flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-base font-bold text-white tracking-wide">Historical Assessments</h2>
          <p className="text-xs text-cyber-muted mt-0.5">
            Audit logs and real-time execution records
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          {/* Search Input */}
          <div className="relative">
            <Search className="absolute left-3 top-2.5 h-3.5 w-3.5 text-cyber-muted" />
            <input
              type="text"
              placeholder="Search target, ID, or name..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="h-8 rounded-lg border border-cyber-border bg-cyber-bg/80 pl-9 pr-3 text-xs font-mono text-white placeholder-cyber-muted focus:border-indigo-500 focus:outline-none w-48 sm:w-64"
            />
          </div>

          {/* Status Filter Tabs */}
          <div className="flex items-center rounded-lg border border-cyber-border bg-cyber-bg/80 p-0.5 text-xs font-mono">
            {["ALL", "ACTIVE", "COMPLETED", "FAILED"].map((status) => (
              <button
                key={status}
                onClick={() => setStatusFilter(status)}
                className={`px-2.5 py-1 rounded-md text-[11px] font-medium transition-colors ${
                  statusFilter === status
                    ? "bg-indigo-600 text-white"
                    : "text-cyber-muted hover:text-white"
                }`}
              >
                {status}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left text-xs font-mono">
          <thead className="bg-cyber-bg/50 border-b border-cyber-border text-cyber-muted">
            <tr>
              <th className="py-3 px-4 font-semibold">Assessment</th>
              <th className="py-3 px-4 font-semibold">Target</th>
              <th className="py-3 px-4 font-semibold">Status</th>
              <th className="py-3 px-4 font-semibold">Findings</th>
              <th className="py-3 px-4 font-semibold">Started</th>
              <th className="py-3 px-4 font-semibold text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-cyber-border/40">
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={6} className="py-8 text-center text-cyber-muted">
                  No assessments found matching your filter criteria.
                </td>
              </tr>
            ) : (
              filtered.map((a) => {
                const statusInfo = getStatusColor(a.status);
                const findingsCount = a.findings?.length || a.total_findings || 0;
                return (
                  <tr
                    key={a.id}
                    className="hover:bg-cyber-card/50 transition-colors group cursor-pointer"
                  >
                    <td className="py-3.5 px-4">
                      <div className="font-bold text-white group-hover:text-cyan-400 transition-colors">
                        {a.name || a.id}
                      </div>
                      <div className="text-[11px] text-cyber-muted">{a.id}</div>
                    </td>

                    <td className="py-3.5 px-4 font-medium text-cyber-text">
                      {a.target?.value}
                    </td>

                    <td className="py-3.5 px-4">
                      <span
                        className={`inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11px] font-semibold border ${statusInfo.badge}`}
                      >
                        <span className={`h-1.5 w-1.5 rounded-full ${statusInfo.dot}`}></span>
                        {a.status}
                      </span>
                    </td>

                    <td className="py-3.5 px-4">
                      {findingsCount > 0 ? (
                        <span className="font-bold text-rose-400 bg-rose-500/10 border border-rose-500/30 px-2 py-0.5 rounded">
                          {findingsCount} Findings
                        </span>
                      ) : (
                        <span className="text-cyber-muted">0 Findings</span>
                      )}
                    </td>

                    <td className="py-3.5 px-4 text-cyber-muted">
                      {formatTimeAgo(a.created_at)}
                    </td>

                    <td className="py-3.5 px-4 text-right">
                      <div className="flex items-center justify-end gap-2">
                        <Link
                          href={`/assessments/${a.id}`}
                          className="flex items-center gap-1 rounded bg-indigo-500/20 px-2.5 py-1 text-[11px] font-bold text-indigo-300 hover:bg-indigo-500/30 transition-colors"
                        >
                          View Live
                          <ArrowRight className="h-3 w-3" />
                        </Link>
                        {a.report_pdf_url && (
                          <a
                            href={a.report_pdf_url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="flex items-center gap-1 rounded bg-cyber-bg px-2 py-1 text-[11px] text-cyber-muted hover:text-white border border-cyber-border hover:border-indigo-500 transition-colors"
                          >
                            <FileText className="h-3 w-3 text-indigo-400" />
                            PDF
                          </a>
                        )}
                      </div>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

