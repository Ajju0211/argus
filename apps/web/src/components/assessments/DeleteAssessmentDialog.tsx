"use client";

import { useEffect, useId, useState } from "react";
import { createPortal } from "react-dom";
import { AlertTriangle, Loader2, Trash2, X } from "lucide-react";
import { AssessmentDetail } from "@/lib/types";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

interface DeleteAssessmentDialogProps {
  open: boolean;
  assessment: AssessmentDetail | null;
  isDeleting?: boolean;
  error?: string | null;
  onClose: () => void;
  onConfirm: () => void;
}

export function DeleteAssessmentDialog({
  open,
  assessment,
  isDeleting = false,
  error = null,
  onClose,
  onConfirm,
}: DeleteAssessmentDialogProps) {
  const [mounted, setMounted] = useState(false);
  const [confirmation, setConfirmation] = useState("");
  const titleId = useId();
  const descriptionId = useId();
  const confirmationId = useId();

  useEffect(() => {
    setMounted(true);
  }, []);

  useEffect(() => {
    setConfirmation("");
  }, [open, assessment?.id]);

  useEffect(() => {
    if (!open) return;

    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";

    const handleKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape" && !isDeleting) {
        onClose();
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => {
      document.body.style.overflow = previousOverflow;
      window.removeEventListener("keydown", handleKeyDown);
    };
  }, [open, isDeleting, onClose]);

  if (!mounted || !open || !assessment) return null;

  const evidenceCount = assessment.evidence_refs?.length || 0;
  const findingCount = assessment.findings?.length || assessment.total_findings || 0;
  const isConfirmed = confirmation.trim().toUpperCase() === "DELETE";
  const canDelete = isConfirmed && !isDeleting;

  return createPortal(
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      role="dialog"
      aria-modal="true"
      aria-labelledby={titleId}
      aria-describedby={descriptionId}
    >
      <div
        className="absolute inset-0 bg-background/80 backdrop-blur-sm"
        onClick={() => {
          if (!isDeleting) onClose();
        }}
        aria-hidden="true"
      />

      <div className="relative w-full max-w-lg rounded-xl border border-rose-500/30 bg-card text-card-foreground shadow-2xl">
        <div className="flex items-start gap-3 border-b border-border/60 p-5">
          <div className="mt-0.5 flex h-9 w-9 shrink-0 items-center justify-center rounded-md border border-rose-500/20 bg-rose-500/10 text-rose-600 dark:text-rose-400">
            <AlertTriangle className="h-4 w-4" />
          </div>

          <div className="min-w-0 flex-1">
            <h2
              id={titleId}
              className="text-sm font-semibold tracking-tight text-foreground"
            >
              Delete assessment permanently?
            </h2>
            <p
              id={descriptionId}
              className="mt-1 text-xs leading-relaxed text-muted-foreground"
            >
              This is a hard delete. The assessment and everything attached to it will
              be removed immediately and cannot be recovered.
            </p>
          </div>

          <button
            type="button"
            onClick={onClose}
            disabled={isDeleting}
            className="rounded-md p-1 text-muted-foreground transition-colors hover:bg-muted/60 hover:text-foreground disabled:pointer-events-none disabled:opacity-50"
            aria-label="Close delete dialog"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="space-y-4 p-5">
          <div className="rounded-md border border-border/70 bg-muted/20 p-3">
            <p className="truncate text-xs font-medium text-foreground">
              {assessment.name || assessment.id}
            </p>
            <p className="mt-0.5 truncate font-mono text-[11px] text-muted-foreground">
              {assessment.id}
            </p>
            <p className="mt-1 truncate font-mono text-[11px] text-muted-foreground">
              Target: {assessment.target?.value || "Unknown"}
            </p>
          </div>

          <div className="space-y-2 rounded-md border border-rose-500/25 bg-rose-500/5 p-3.5">
            <p className="text-[11px] font-semibold uppercase tracking-wider text-rose-600 dark:text-rose-400">
              This will permanently delete
            </p>
            <ul className="space-y-1.5 text-xs text-foreground/90">
              <li className="flex items-start gap-2">
                <Trash2 className="mt-0.5 h-3.5 w-3.5 shrink-0 text-rose-500/80" />
                <span>The assessment record and its full execution history</span>
              </li>
              <li className="flex items-start gap-2">
                <Trash2 className="mt-0.5 h-3.5 w-3.5 shrink-0 text-rose-500/80" />
                <span>
                  {evidenceCount} evidence artifact{evidenceCount === 1 ? "" : "s"} and
                  all raw evidence files
                </span>
              </li>
              <li className="flex items-start gap-2">
                <Trash2 className="mt-0.5 h-3.5 w-3.5 shrink-0 text-rose-500/80" />
                <span>
                  {findingCount} finding{findingCount === 1 ? "" : "s"}, reports,
                  checkpoints, and telemetry
                </span>
              </li>
            </ul>
          </div>

          <p className="text-xs leading-relaxed text-muted-foreground">
            Evidence belongs to this assessment and cannot be deleted independently.
            Deleting the assessment removes every evidence artifact associated with it.
          </p>

          <div className="space-y-1.5">
            <label
              htmlFor={confirmationId}
              className="block text-xs font-medium text-foreground"
            >
              Type{" "}
              <code className="rounded bg-muted px-1 py-0.5 font-mono text-[11px] font-semibold">
                DELETE
              </code>{" "}
              to confirm
            </label>
            <Input
              id={confirmationId}
              value={confirmation}
              onChange={(event) => setConfirmation(event.target.value)}
              placeholder="DELETE"
              autoComplete="off"
              autoFocus
              disabled={isDeleting}
              className="font-mono"
            />
          </div>

          {error && (
            <div
              role="alert"
              className="rounded-md border border-rose-500/30 bg-rose-500/10 p-2.5 text-xs text-rose-700 dark:text-rose-300"
            >
              {error}
            </div>
          )}
        </div>

        <div className="flex flex-col-reverse gap-2 border-t border-border/60 p-4 sm:flex-row sm:justify-end">
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={onClose}
            disabled={isDeleting}
          >
            Cancel
          </Button>
          <Button
            type="button"
            variant="destructive"
            size="sm"
            onClick={onConfirm}
            disabled={!canDelete}
            className="gap-1.5 border-rose-600 bg-rose-600 text-white hover:bg-rose-700 hover:text-white"
          >
            {isDeleting ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <Trash2 className="h-3.5 w-3.5" />
            )}
            <span>{isDeleting ? "Deleting..." : "Delete assessment"}</span>
          </Button>
        </div>
      </div>
    </div>,
    document.body
  );
}
