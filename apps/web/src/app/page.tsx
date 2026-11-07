"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { PlusCircle, ShieldAlert, RefreshCw } from "lucide-react";
import { KpiCardGrid } from "@/components/dashboard/KpiCardGrid";
import { AssessmentsTable } from "@/components/dashboard/AssessmentsTable";
import { DeleteAssessmentDialog } from "@/components/assessments/DeleteAssessmentDialog";
import { AssessmentDetail } from "@/lib/types";
import { deleteAssessment, listAssessments } from "@/lib/api";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";

export default function DashboardPage() {
  const [assessments, setAssessments] = useState<AssessmentDetail[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [deleteTarget, setDeleteTarget] = useState<AssessmentDetail | null>(null);
  const [isDeleting, setIsDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);

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

  const handleDeleteAssessment = async () => {
    if (!deleteTarget) return;

    setIsDeleting(true);
    setDeleteError(null);
    try {
      await deleteAssessment(deleteTarget.id);
      setDeleteTarget(null);
      await loadAssessments(false);
    } catch (err: any) {
      setDeleteError(err?.message || "Failed to delete assessment.");
    } finally {
      setIsDeleting(false);
    }
  };

  const requestDelete = (assessment: AssessmentDetail) => {
    setDeleteError(null);
    setDeleteTarget(assessment);
  };

  const closeDeleteDialog = () => {
    if (isDeleting) return;
    setDeleteTarget(null);
    setDeleteError(null);
  };

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl sm:text-2xl font-semibold tracking-tight text-foreground">
            Command Center
          </h1>
          <p className="text-xs text-muted-foreground mt-1">
            Autonomous security testing operations verified by cryptographic evidence.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => loadAssessments(false)}
            disabled={isRefreshing}
            className="gap-1.5 text-xs"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${isRefreshing ? "animate-spin" : ""}`} />
            <span>Refresh</span>
          </Button>

          <Link href="/new">
            <Button size="sm" className="gap-1.5 text-xs">
              <PlusCircle className="h-3.5 w-3.5" />
              <span>Launch Assessment</span>
            </Button>
          </Link>
        </div>
      </div>

      {/* Error Alert */}
      {error && (
        <Card className="border-destructive/30 bg-destructive/10 text-destructive">
          <CardContent className="p-3.5 flex items-center gap-2.5 text-xs font-mono">
            <ShieldAlert className="h-4 w-4 shrink-0" />
            <span>
              {error} Please ensure the backend is running at{" "}
              <code className="font-semibold underline">http://localhost:8000</code>.
            </span>
          </CardContent>
        </Card>
      )}

      {/* KPI Stats Grid */}
      <KpiCardGrid assessments={assessments} />

      {/* Historical Runs Table */}
      <AssessmentsTable
        assessments={assessments}
        onDeleteRequest={requestDelete}
        deletingId={isDeleting ? deleteTarget?.id ?? null : null}
      />

      <DeleteAssessmentDialog
        open={deleteTarget !== null}
        assessment={deleteTarget}
        isDeleting={isDeleting}
        error={deleteError}
        onClose={closeDeleteDialog}
        onConfirm={handleDeleteAssessment}
      />
    </div>
  );
}
