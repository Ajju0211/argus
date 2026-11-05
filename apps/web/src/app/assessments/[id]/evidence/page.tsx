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
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

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
        <div className="flex items-center gap-2 text-muted-foreground">
          <Link href={`/assessments/${assessmentId}`} className="hover:text-foreground flex items-center gap-1 transition-colors">
            <ArrowLeft className="h-3 w-3" />
            Back to Assessment
          </Link>
          <span>/</span>
          <span className="text-foreground">Evidence Vault & Cryptographic Proof</span>
        </div>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="text-xl">Cryptographic Evidence Inspector</CardTitle>
              <CardDescription>
                Zero-hallucination verification vault. Every confirmed vulnerability links directly to an immutable on-disk artifact.
              </CardDescription>
            </div>
            <Badge variant="success" className="gap-1.5 font-mono">
              <Lock className="h-3.5 w-3.5" />
              Merkle Tamper-Evident Chain
            </Badge>
          </div>
        </CardHeader>

        <CardContent className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
            {/* Artifact Selector Sidebar */}
            <div className="lg:col-span-4 space-y-2 font-mono">
              <div className="text-xs uppercase tracking-wider text-muted-foreground px-1 font-semibold">
                Captured Artifacts ({assessment?.evidence_refs?.length || 0})
              </div>

              <div className="space-y-1.5 max-h-[500px] overflow-y-auto pr-1">
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
                            ? "bg-primary text-primary-foreground border-primary font-semibold shadow-sm"
                            : "bg-card border-border hover:bg-muted text-foreground"
                        }`}
                      >
                        <div className="flex items-center justify-between gap-1">
                          <span className="truncate">{evId}</span>
                          <span className="text-[10px] opacity-75">{ref.action_name || ref.tool_name}</span>
                        </div>
                        <div className="text-[11px] opacity-75 flex items-center gap-1 mt-1">
                          <span>SHA256:</span>
                          <code className="text-[10px] font-mono">
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
            <Card className="lg:col-span-8 overflow-hidden flex flex-col h-[560px]">
              <CardHeader className="p-4 border-b border-border bg-muted/30 flex flex-wrap items-center justify-between gap-3 text-xs font-mono">
                <div className="flex items-center gap-2">
                  <FileCode className="h-4 w-4 text-primary" />
                  <span className="font-bold text-foreground">{selectedEvId || "No Artifact Selected"}</span>
                  {selectedRef?.tool_name && (
                    <Badge variant="outline" className="text-[10px]">
                      {selectedRef.tool_name}
                    </Badge>
                  )}
                </div>

                <div className="flex items-center gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={handleCopy}
                    disabled={!rawContent || isLoadingContent}
                    className="h-7 text-xs gap-1"
                  >
                    {hasCopied ? <Check className="h-3 w-3 text-primary" /> : <Copy className="h-3 w-3" />}
                    <span>{hasCopied ? "Copied" : "Copy"}</span>
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={handleDownload}
                    disabled={!rawContent || isLoadingContent}
                    className="h-7 text-xs gap-1"
                  >
                    <Download className="h-3 w-3" />
                    <span>Download</span>
                  </Button>
                </div>
              </CardHeader>

              {/* SHA256 & Previous Hash Bar */}
              {selectedRef && (
                <div className="bg-muted/20 border-b border-border px-4 py-2 flex flex-wrap items-center gap-4 text-[11px] font-mono text-muted-foreground">
                  <div>
                    <span className="font-semibold text-foreground">Hash: </span>
                    <span className="select-all">{selectedRef.sha256 || selectedRef.sha256_hash}</span>
                  </div>
                  <div>
                    <span className="font-semibold text-foreground">Location: </span>
                    <span>{selectedRef.file_path || "vault artifact"}</span>
                  </div>
                </div>
              )}

              {/* Raw Payload Text */}
              <div className="p-4 overflow-auto flex-1 font-mono text-xs bg-muted/10 text-foreground leading-relaxed">
                {isLoadingContent ? (
                  <div className="h-full flex items-center justify-center text-muted-foreground">
                    Streaming raw artifact payload...
                  </div>
                ) : rawContent ? (
                  <pre className="whitespace-pre-wrap break-all">{rawContent}</pre>
                ) : (
                  <div className="h-full flex items-center justify-center text-muted-foreground">
                    Select an artifact on the left to inspect its cryptographic verification proof.
                  </div>
                )}
              </div>
            </Card>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
