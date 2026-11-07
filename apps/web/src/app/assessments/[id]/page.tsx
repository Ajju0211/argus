"use client";

import { use, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { ArrowLeft } from "lucide-react";
import { useAssessmentStream } from "@/lib/useAssessmentStream";
import { BifrostHUD } from "@/components/navigation/BifrostHUD";
import { DeleteAssessmentDialog } from "@/components/assessments/DeleteAssessmentDialog";
import { LiveAgentPanel } from "@/components/live/LiveAgentPanel";
import { AuditTimeline } from "@/components/live/AuditTimeline";
import { TopologyGrid } from "@/components/live/TopologyGrid";
import { FindingsBoard } from "@/components/live/FindingsBoard";
import {
  cancelAssessment,
  deleteAssessment,
  pauseAssessment,
  resumeAssessment,
} from "@/lib/api";

interface PageProps {
  params: Promise<{ id: string }>;
}

export default function AssessmentLivePage({ params }: PageProps) {
  const resolvedParams = use(params);
  const assessmentId = resolvedParams.id;
  const router = useRouter();
  const { assessment, events, connectionStatus, refresh } =
    useAssessmentStream(assessmentId);
  const [isActionLoading, setIsActionLoading] = useState(false);
  const [isDeleteDialogOpen, setIsDeleteDialogOpen] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);

  const handlePause = async () => {
    setIsActionLoading(true);
    try {
      await pauseAssessment(assessmentId);
      await refresh();
    } catch (err) {
      console.error("Failed to pause:", err);
    } finally {
      setIsActionLoading(false);
    }
  };

  const handleResume = async () => {
    setIsActionLoading(true);
    try {
      await resumeAssessment(assessmentId);
      await refresh();
    } catch (err) {
      console.error("Failed to resume:", err);
    } finally {
      setIsActionLoading(false);
    }
  };

  const handleCancel = async () => {
    setIsActionLoading(true);
    try {
      await cancelAssessment(assessmentId);
      await refresh();
    } catch (err) {
      console.error("Failed to cancel:", err);
    } finally {
      setIsActionLoading(false);
    }
  };

  const handleDelete = async () => {
    setIsDeleting(true);
    setDeleteError(null);
    try {
      await deleteAssessment(assessmentId);
      setIsDeleteDialogOpen(false);
      router.push("/");
      router.refresh();
    } catch (err: any) {
      setDeleteError(err?.message || "Failed to delete assessment.");
    } finally {
      setIsDeleting(false);
    }
  };

  const closeDeleteDialog = () => {
    if (isDeleting) return;
    setIsDeleteDialogOpen(false);
    setDeleteError(null);
  };

  const handleDownloadPdf = () => {
    window.open(`/api/v1/assessments/${assessmentId}/report/pdf`, "_blank");
  };

  if (!assessment) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] space-y-3">
        <div className="h-6 w-6 animate-spin rounded-full border-2 border-primary border-t-transparent"></div>
        <p className="text-xs text-muted-foreground">Connecting to Assessment Stream...</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Breadcrumb Nav */}
      <div className="flex items-center justify-between text-xs">
        <div className="flex items-center gap-2 text-muted-foreground">
          <Link href="/" className="hover:text-foreground flex items-center gap-1 transition-colors">
            <ArrowLeft className="h-3 w-3" />
            Command Center
          </Link>
          <span>/</span>
          <span className="text-foreground font-medium">{assessment.name || assessment.id}</span>
        </div>

        <div className="flex items-center gap-3">
          <Link
            href={`/assessments/${assessmentId}/evidence`}
            className="text-muted-foreground hover:text-foreground transition-colors font-medium text-xs"
          >
            Evidence Vault →
          </Link>
          <Link
            href={`/assessments/${assessmentId}/report`}
            className="text-muted-foreground hover:text-foreground transition-colors font-medium text-xs"
          >
            Executive Report →
          </Link>
        </div>
      </div>

      {/* Assessment Header & Status Controls */}
      <BifrostHUD
        assessment={assessment}
        onPause={handlePause}
        onResume={handleResume}
        onCancel={handleCancel}
        onDelete={() => {
          setDeleteError(null);
          setIsDeleteDialogOpen(true);
        }}
        onDownloadPdf={handleDownloadPdf}
        isActionLoading={isActionLoading}
      />

      <LiveAgentPanel
        assessment={assessment}
        events={events}
        connectionStatus={connectionStatus}
      />

      {/* Main Dual-Pane Live Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5 items-start">
        {/* Left: Audit Timeline */}
        <AuditTimeline events={events} />

        {/* Right: Topology & Findings */}
        <div className="space-y-5">
          <TopologyGrid assessment={assessment} />
          <FindingsBoard
            findings={assessment.findings || []}
            assessmentId={assessmentId}
          />
        </div>
      </div>

      <DeleteAssessmentDialog
        open={isDeleteDialogOpen}
        assessment={assessment}
        isDeleting={isDeleting}
        error={deleteError}
        onClose={closeDeleteDialog}
        onConfirm={handleDelete}
      />
    </div>
  );
}
