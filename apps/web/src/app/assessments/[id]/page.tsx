"use client";

import { use, useState } from "react";
import Link from "next/link";
import { ArrowLeft, ShieldAlert } from "lucide-react";
import { useAssessmentStream } from "@/lib/useAssessmentStream";
import { BifrostHUD } from "@/components/navigation/BifrostHUD";
import { AuditTimeline } from "@/components/live/AuditTimeline";
import { TopologyGrid } from "@/components/live/TopologyGrid";
import { FindingsBoard } from "@/components/live/FindingsBoard";
import { pauseAssessment, resumeAssessment, cancelAssessment } from "@/lib/api";
import { Button } from "@/components/ui/button";

interface PageProps {
  params: Promise<{ id: string }>;
}

export default function AssessmentLivePage({ params }: PageProps) {
  const resolvedParams = use(params);
  const assessmentId = resolvedParams.id;
  const { assessment, events, refresh } = useAssessmentStream(assessmentId);
  const [isActionLoading, setIsActionLoading] = useState(false);

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

  const handleDownloadPdf = () => {
    window.open(`/api/v1/assessments/${assessmentId}/report/pdf`, "_blank");
  };

  if (!assessment) {
    return (
      <div className="flex flex-col items-center justify-center min-h-[60vh] space-y-4">
        <div className="h-8 w-8 animate-spin rounded-full border-2 border-primary border-t-transparent"></div>
        <p className="text-xs font-mono text-muted-foreground">Connecting to Assessment Stream...</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Breadcrumb Nav */}
      <div className="flex items-center justify-between text-xs font-mono">
        <div className="flex items-center gap-2 text-muted-foreground">
          <Link href="/" className="hover:text-foreground flex items-center gap-1 transition-colors">
            <ArrowLeft className="h-3 w-3" />
            Command Center
          </Link>
          <span>/</span>
          <span className="text-foreground font-semibold">{assessment.name || assessment.id}</span>
        </div>

        <div className="flex items-center gap-3">
          <Link
            href={`/assessments/${assessmentId}/evidence`}
            className="text-muted-foreground hover:text-foreground transition-colors"
          >
            Evidence Vault →
          </Link>
          <Link
            href={`/assessments/${assessmentId}/report`}
            className="text-muted-foreground hover:text-foreground transition-colors"
          >
            Executive Report →
          </Link>
        </div>
      </div>

      {/* Top Bifrost Telemetry Bar */}
      <BifrostHUD
        assessment={assessment}
        onPause={handlePause}
        onResume={handleResume}
        onCancel={handleCancel}
        onDownloadPdf={handleDownloadPdf}
        isActionLoading={isActionLoading}
      />

      {/* Main Dual-Pane Live Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 items-start">
        {/* Left: Audit Timeline */}
        <AuditTimeline events={events} />

        {/* Right: Topology & Findings */}
        <div className="space-y-6">
          <TopologyGrid assessment={assessment} />
          <FindingsBoard
            findings={assessment.findings || []}
            assessmentId={assessmentId}
          />
        </div>
      </div>
    </div>
  );
}
