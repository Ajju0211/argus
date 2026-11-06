"use client";

import { useState } from "react";
import Link from "next/link";
import { Search, ArrowRight } from "lucide-react";
import { AssessmentDetail } from "@/lib/types";
import { formatTimeAgo, getStatusColor } from "@/lib/utils";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";

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
      (a.target?.value || "").toLowerCase().includes(search.toLowerCase());

    if (!matchesSearch) return false;
    if (statusFilter === "ALL") return true;
    if (statusFilter === "ACTIVE") return ["RUNNING", "QUEUED", "READY", "PAUSED"].includes(a.status);
    if (statusFilter === "COMPLETED") return ["SUCCESS", "COMPLETED"].includes(a.status);
    if (statusFilter === "FAILED") return ["FAILED", "CANCELLED"].includes(a.status);
    return true;
  });

  return (
    <Card className="overflow-hidden border-border/70">
      {/* Header & Controls */}
      <CardHeader className="border-b border-border/50 p-4 sm:p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <CardTitle>Historical Assessments</CardTitle>
          <CardDescription>
            Audit logs and verified execution records
          </CardDescription>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          {/* Search Input */}
          <div className="relative w-48 sm:w-60">
            <Search className="absolute left-2.5 top-2.5 h-3.5 w-3.5 text-muted-foreground/60" />
            <Input
              type="text"
              placeholder="Filter assessments..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-8 h-8 text-xs font-sans border-border/60"
            />
          </div>

          {/* Status Filter Tabs */}
          <div className="flex items-center rounded-md border border-border/60 bg-muted/40 p-0.5 text-xs">
            {["ALL", "ACTIVE", "COMPLETED", "FAILED"].map((status) => (
              <button
                key={status}
                onClick={() => setStatusFilter(status)}
                className={`px-2.5 py-1 rounded text-[11px] font-medium transition-colors ${
                  statusFilter === status
                    ? "bg-foreground text-background font-medium shadow-2xs"
                    : "text-muted-foreground hover:text-foreground"
                }`}
              >
                {status}
              </button>
            ))}
          </div>
        </div>
      </CardHeader>

      {/* Table */}
      <CardContent className="p-0 overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead className="bg-muted/30 border-b border-border/50 text-[11px] font-medium uppercase tracking-wider text-muted-foreground">
            <tr>
              <th className="py-2.5 px-4">Assessment</th>
              <th className="py-2.5 px-4">Target</th>
              <th className="py-2.5 px-4">Status</th>
              <th className="py-2.5 px-4">Findings</th>
              <th className="py-2.5 px-4">Started</th>
              <th className="py-2.5 px-4 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border/50">
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={6} className="py-12 text-center text-muted-foreground text-xs">
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
                    className="hover:bg-muted/30 transition-colors group"
                  >
                    <td className="py-3 px-4">
                      <div className="font-medium text-foreground group-hover:text-muted-foreground transition-colors">
                        {a.name || a.id}
                      </div>
                      <div className="text-[11px] font-mono text-muted-foreground/70">{a.id}</div>
                    </td>

                    <td className="py-3 px-4 font-mono text-xs text-foreground/90">
                      {a.target?.value}
                    </td>

                    <td className="py-3 px-4">
                      <span
                        className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-mono font-medium border ${statusInfo.badge}`}
                      >
                        <span className={`h-1.5 w-1.5 rounded-full ${statusInfo.dot}`}></span>
                        {a.status}
                      </span>
                    </td>

                    <td className="py-3 px-4">
                      {findingsCount > 0 ? (
                        <Badge variant="destructive" className="font-mono text-[10px]">
                          {findingsCount} Findings
                        </Badge>
                      ) : (
                        <Badge variant="secondary" className="font-mono text-[10px]">
                          0 Findings
                        </Badge>
                      )}
                    </td>

                    <td className="py-3 px-4 text-muted-foreground text-[11px] font-mono">
                      {formatTimeAgo(a.created_at)}
                    </td>

                    <td className="py-3 px-4 text-right">
                      <Link href={`/assessments/${a.id}`}>
                        <Button variant="ghost" size="sm" className="h-7 px-2.5 text-xs gap-1 text-muted-foreground hover:text-foreground">
                          <span>Inspect</span>
                          <ArrowRight className="h-3 w-3 opacity-60" />
                        </Button>
                      </Link>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </CardContent>
    </Card>
  );
}
