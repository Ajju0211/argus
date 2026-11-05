"use client";

import { use, useEffect, useState } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import {
  ArrowLeft,
  ShieldCheck,
  FileCode,
  Copy,
  Check,
  Download,
  Terminal,
  Lock,
} from "lucide-react";
import { getAssessment, getRawEvidence } from "@/lib/api";
import { AssessmentDetail } from "@/lib/types";
import { truncateHash } from "@/lib/utils";

interface PageProps {
  params: Promise<{ id: string }>;
}

export default function EvidenceVaultPage({ params }: PageProps) {
  const resolvedParams = use(params);
  const searchParams = useSearchParams();
  const assessmentId = resolvedParams.id;
  const initialFocus = searchParams.get("focus");

  const [assessment, setAssessment] = useState<AssessmentDetail | null>(null);
  const [selectedEvId, setSelectedEvId] = useState<string | null>(null);
  const [rawContent, setRawContent] = useState<string>("");
  const [isLoadingContent, setIsLoadingContent] = useState(false);
  const [hasCopied, setHasCopied] = useState(false);

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

  const selectedRef = assessment?.evidence_refs?.find(
    (r) => (r.evidence_id || r.id) === selectedEvId
  );

  return (
    <div className="space-y-6">
      {/* Breadcrumb Navigation */}
      <div className="flex items-center justify-between text-xs font-mono">
        <div className="flex items-center gap-2 text-cyber-muted">
          <Link href={`/assessments/${assessmentId}`} className="hover:text-white flex items-center gap-1 transition-colors">
            <ArrowLeft className="h-3 w-3" />
            Back to Assessment
          </Link>
          <span>/</span>
          <span className="text-white">Evidence Vault & Cryptographic Proof</span>
        </div>
      </div>

      <div className="glass-panel-elevated rounded-3xl p-6 sm:p-8 border border-cyber-border space-y-6">
        <div>
          <h1 className="text-2xl font-black text-white tracking-wide">
            Cryptographic Evidence Inspector
          </h1>
          <p className="text-xs sm:text-sm text-cyber-muted mt-1">
            Zero-hallucination verification vault. Every confirmed vulnerability links directly to an immutable on-disk artifact.
          </p>
        </div>

        {/* Split Screen Layout */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
          {/* Left Column: Artifacts List */}
          <div className="lg:col-span-4 space-y-3">
            <div className="text-xs font-mono font-bold uppercase tracking-wider text-cyber-muted px-1">
              Captured Evidence Artifacts ({assessment?.evidence_refs?.length || 0})
            </div>

            <div className="space-y-2 max-h-[500px] overflow-y-auto">
              {!assessment?.evidence_refs || assessment.evidence_refs.length === 0 ? (
                <div className="rounded-xl border border-cyber-border/40 bg-cyber-bg/40 p-6 text-center text-xs font-mono text-cyber-muted">
                  No artifacts captured yet. Tools are executing...
                </div>
              ) : (
                assessment.evidence_refs.map((ref) => {
                  const evId = ref.evidence_id || ref.id || "ev-unknown";
                  const isSelected = evId === selectedEvId;
                  return (
                    <div
                      key={evId}
                      onClick={() => setSelectedEvId(evId)}
                      className={`p-3.5 rounded-xl border font-mono text-xs cursor-pointer transition-all ${
                        isSelected
                          ? "bg-indigo-600/20 border-indigo-500/60 shadow-lg shadow-indigo-500/10"
                          : "bg-cyber-bg/50 border-cyber-border/60 hover:border-cyber-border"
                      }`}
                    >
                      <div className="flex items-center justify-between mb-1.5">
                        <span className="font-bold text-white">{evId}</span>
                        <span className="rounded bg-cyan-500/10 px-1.5 py-0.5 text-[10px] text-cyan-300 border border-cyan-500/30">
                          {ref.tool_name || "tool"}
                        </span>
                      </div>
                      <div className="text-[11px] text-cyber-muted flex items-center gap-1">
                        <Lock className="h-3 w-3 text-emerald-400" />
                        <span>SHA: {truncateHash(ref.sha256 || "", 6)}</span>
                      </div>
                    </div>
                  );
                })
              )}
            </div>
          </div>

          {/* Right Column: Hex / Raw Output Viewer */}
          <div className="lg:col-span-8 glass-panel rounded-2xl border border-cyber-border overflow-hidden flex flex-col h-[560px]">
            {/* Inspector Header */}
            <div className="p-4 border-b border-cyber-border bg-cyber-bg/80 flex flex-wrap items-center justify-between gap-3 font-mono text-xs">
              <div className="flex items-center gap-2">
                <FileCode className="h-4 w-4 text-cyan-400" />
                <span className="font-bold text-white">{selectedEvId || "No Artifact Selected"}</span>
                {selectedRef?.sha256 && (
                  <span className="hidden sm:inline-flex items-center gap-1 text-[11px] text-emerald-400 bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/30">
                    <ShieldCheck className="h-3 w-3" />
                    Verified Digest
                  </span>
                )}
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={handleCopy}
                  disabled={!rawContent}
                  className="flex items-center gap-1.5 rounded-lg border border-cyber-border bg-cyber-panel px-3 py-1 text-xs text-cyber-muted hover:text-white transition-colors"
                >
                  {hasCopied ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
                  {hasCopied ? "Copied" : "Copy"}
                </button>
                <button
                  onClick={handleDownload}
                  disabled={!rawContent}
                  className="flex items-center gap-1.5 rounded-lg border border-indigo-500/40 bg-indigo-500/20 px-3 py-1 text-xs text-indigo-300 hover:bg-indigo-500/30 transition-colors"
                >
                  <Download className="h-3.5 w-3.5" />
                  Download .raw
                </button>
              </div>
            </div>

            {/* Content Display */}
            <div className="p-4 overflow-auto flex-1 font-mono text-xs bg-cyber-bg/90 text-cyber-text leading-relaxed">
              {isLoadingContent ? (
                <div className="h-full flex items-center justify-center text-cyber-muted">
                  Loading artifact from Evidence Vault...
                </div>
              ) : rawContent ? (
                <pre className="whitespace-pre-wrap break-all">{rawContent}</pre>
              ) : (
                <div className="h-full flex items-center justify-center text-cyber-muted">
                  Select an artifact on the left to inspect raw output.
                </div>
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

