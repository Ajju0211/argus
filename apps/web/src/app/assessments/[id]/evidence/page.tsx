"use client";

import { use, useEffect, useState } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import {
  ArrowLeft,
  FileCode,
  Copy,
  Check,
  Download,
  Lock,
  Trash2,
} from "lucide-react";
import { deleteAssessment, getAssessment, getRawEvidence } from "@/lib/api";
import { AssessmentDetail } from "@/lib/types";
import { truncateHash } from "@/lib/utils";
import { DeleteAssessmentDialog } from "@/components/assessments/DeleteAssessmentDialog";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

interface PageProps {
  params: Promise<{ id: string }>;
}

export default function EvidenceVaultPage({ params }: PageProps) {
  const resolvedParams = use(params);
  const searchParams = useSearchParams();
  const router = useRouter();
  const assessmentId = resolvedParams.id;
  const initialFocus = searchParams.get("focus");

  const [assessment, setAssessment] = useState<AssessmentDetail | null>(null);
  const [selectedEvId, setSelectedEvId] = useState<string | null>(null);
  const [rawContent, setRawContent] = useState<string>("");
  const [isLoadingContent, setIsLoadingContent] = useState(false);
  const [hasCopied, setHasCopied] = useState(false);
  const [isDeleteDialogOpen, setIsDeleteDialogOpen] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);
  const [deleteError, setDeleteError] = useState<string | null>(null);

  useEffect(() => {
    getAssessment(assessmentId).then((data) => {
      setAssessment(data);
      const refs = data.evidence_refs || [];
      if (initialFocus) {
        setSelectedEvId(initialFocus);
      } else if (refs.length > 0) {
        const firstId = refs[0].evidence_id || refs[0].id;
        if (firstId) setSelectedEvId(firstId);
      }
    });
  }, [assessmentId, initialFocus]);

  useEffect(() => {
    if (!selectedEvId) return;
    setIsLoadingContent(true);
    getRawEvidence(assessmentId, selectedEvId)
      .then((content) => setRawContent(content))
      .catch((err) => setRawContent(`Failed to load artifact content: ${err.message}`))
      .finally(() => setIsLoadingContent(false));
  }, [assessmentId, selectedEvId]);

  const handleCopy = () => {
    navigator.clipboard.writeText(rawContent);
    setHasCopied(true);
    setTimeout(() => setHasCopied(false), 2000);
  };

  const handleDownload = () => {
    const blob = new Blob([rawContent], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${selectedEvId || "evidence"}.raw`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleDeleteAssessment = async () => {
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

  const selectedRef = assessment?.evidence_refs?.find(
    (r) => (r.evidence_id || r.id) === selectedEvId
  );

  return (
    <div className="space-y-6">
      {/* Breadcrumb Navigation */}
      <div className="flex items-center justify-between text-xs">
        <div className="flex items-center gap-2 text-muted-foreground">
          <Link href={`/assessments/${assessmentId}`} className="hover:text-foreground flex items-center gap-1 transition-colors">
            <ArrowLeft className="h-3 w-3" />
            Back to Assessment
          </Link>
          <span>/</span>
          <span className="text-foreground font-medium">Evidence Vault</span>
        </div>
      </div>

      <Card className="border-border/80">
        <CardHeader>
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <CardTitle className="text-base sm:text-lg">Cryptographic Evidence Inspector</CardTitle>
              <CardDescription>
                Evidence-backed verification vault. Every confirmed vulnerability links directly to an immutable on-disk artifact.
              </CardDescription>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <Badge variant="success" className="gap-1.5 w-fit">
                <Lock className="h-3.5 w-3.5" />
                Merkle Tamper-Evident Chain
              </Badge>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => {
                  setDeleteError(null);
                  setIsDeleteDialogOpen(true);
                }}
                disabled={!assessment}
                className="gap-1.5 h-7 text-xs text-rose-600 hover:bg-rose-500/10 hover:text-rose-600 dark:text-rose-400 dark:hover:text-rose-400"
              >
                <Trash2 className="h-3.5 w-3.5" />
                <span>Delete Assessment &amp; Evidence</span>
              </Button>
            </div>
          </div>
        </CardHeader>

        <CardContent className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-start">
            {/* Artifact Selector Sidebar */}
            <div className="lg:col-span-4 space-y-2">
              <div className="text-xs uppercase tracking-wider text-muted-foreground px-1 font-medium">
                Captured Artifacts ({assessment?.evidence_refs?.length || 0})
              </div>

              <div className="space-y-1.5 max-h-[500px] overflow-y-auto pr-1 custom-scrollbar">
                {!assessment?.evidence_refs || assessment.evidence_refs.length === 0 ? (
                  <div className="rounded-md border border-border bg-muted/20 p-6 text-center text-xs text-muted-foreground">
                    No artifacts stored yet.
                  </div>
                ) : (
                  assessment.evidence_refs.map((ref) => {
                    const evId = ref.evidence_id || ref.id;
                    const isSelected = evId === selectedEvId;
                    return (
                      <button
                        key={evId}
                        onClick={() => setSelectedEvId(evId || null)}
                        className={`w-full text-left p-3 rounded-md border text-xs transition-all ${
                          isSelected
                            ? "bg-foreground text-background border-foreground font-medium shadow-2xs"
                            : "bg-card border-border hover:bg-muted/50 text-foreground"
                        }`}
                      >
                        <div className="flex items-center justify-between gap-1">
                          <span className="truncate font-mono">{evId}</span>
                          <span className="text-[10px] opacity-75">{ref.action_name || ref.tool_name}</span>
                        </div>
                        <div className="text-[11px] opacity-75 flex items-center gap-1 mt-1 font-mono">
                          <span>SHA256:</span>
                          <code>
                            {truncateHash(ref.sha256 || ref.sha256_hash || "", 6)}
                          </code>
                        </div>
                      </button>
                    );
                  })
                )}
              </div>
            </div>

            {/* Artifact Content Viewer */}
            <div className="lg:col-span-8 rounded-lg border border-border bg-muted/20 p-4 space-y-4">
              {selectedRef ? (
                <>
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-border/60">
                    <div>
                      <div className="font-mono text-xs font-semibold text-foreground">
                        {selectedRef.evidence_id || selectedRef.id}
                      </div>
                      <div className="text-[11px] font-mono text-muted-foreground break-all">
                        SHA256: {selectedRef.sha256 || selectedRef.sha256_hash}
                      </div>
                    </div>

                    <div className="flex items-center gap-2">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={handleCopy}
                        className="gap-1.5 h-7 text-xs"
                      >
                        {hasCopied ? (
                          <>
                            <Check className="h-3 w-3 text-emerald-500" />
                            <span>Copied</span>
                          </>
                        ) : (
                          <>
                            <Copy className="h-3 w-3" />
                            <span>Copy Payload</span>
                          </>
                        )}
                      </Button>

                      <Button
                        variant="outline"
                        size="sm"
                        onClick={handleDownload}
                        className="gap-1.5 h-7 text-xs"
                      >
                        <Download className="h-3 w-3" />
                        <span>Save RAW</span>
                      </Button>
                    </div>
                  </div>

                  <div className="relative">
                    {isLoadingContent ? (
                      <div className="h-64 flex items-center justify-center text-xs text-muted-foreground">
                        Loading artifact payload...
                      </div>
                    ) : (
                      <pre className="font-mono text-xs bg-card p-4 rounded-md border border-border overflow-x-auto max-h-[420px] text-foreground leading-relaxed custom-scrollbar">
                        {rawContent}
                      </pre>
                    )}
                  </div>
                </>
              ) : (
                <div className="h-64 flex flex-col items-center justify-center text-muted-foreground space-y-2">
                  <FileCode className="h-6 w-6 opacity-40" />
                  <p className="text-xs">Select an evidence artifact from the left to inspect its raw verification payload.</p>
                </div>
              )}
            </div>
          </div>
        </CardContent>
      </Card>

      <DeleteAssessmentDialog
        open={isDeleteDialogOpen}
        assessment={assessment}
        isDeleting={isDeleting}
        error={deleteError}
        onClose={closeDeleteDialog}
        onConfirm={handleDeleteAssessment}
      />
    </div>
  );
}
