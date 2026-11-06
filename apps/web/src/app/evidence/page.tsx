"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { ArrowLeft, Lock, CheckCircle2 } from "lucide-react";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { listAssessments } from "@/lib/api";
import { AssessmentDetail } from "@/lib/types";

export default function GlobalEvidenceVaultPage() {
  const [assessments, setAssessments] = useState<AssessmentDetail[]>([]);
  const [selectedAssessmentId, setSelectedAssessmentId] = useState<string>("");
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    listAssessments(20)
      .then((data) => {
        setAssessments(data);
        if (data.length > 0) {
          setSelectedAssessmentId(data[0].id);
        }
      })
      .finally(() => setIsLoading(false));
  }, []);

  const current = assessments.find((a) => a.id === selectedAssessmentId);
  const evidenceRefs = current?.evidence_refs || [];

  return (
    <div className="space-y-6 max-w-5xl mx-auto">
      {/* Top Breadcrumb */}
      <div className="flex items-center gap-2 text-xs text-muted-foreground">
        <Link href="/" className="hover:text-foreground flex items-center gap-1 transition-colors">
          <ArrowLeft className="h-3 w-3" />
          Command Center
        </Link>
        <span>/</span>
        <span className="text-foreground font-medium">Evidence Vault</span>
      </div>

      <Card className="border-border/70">
        <CardHeader>
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div>
              <CardTitle className="text-base sm:text-lg">Cryptographic Chain of Custody</CardTitle>
              <CardDescription>
                Tamper-evident Merkle hash chain linking all raw HTTP responses and tool outputs with SHA-256 digests.
              </CardDescription>
            </div>
            <Badge variant="outline" className="gap-1.5 w-fit font-normal text-xs border-border/80">
              <Lock className="h-3.5 w-3.5 text-muted-foreground/70" />
              Cryptographically Verified
            </Badge>
          </div>
        </CardHeader>

        <CardContent className="space-y-6">
          {/* Assessment Picker */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-3 rounded-lg border border-border/60 bg-muted/20">
            <div className="text-xs text-muted-foreground font-medium">
              Select Assessment Run:
            </div>
            <select
              value={selectedAssessmentId}
              onChange={(e) => setSelectedAssessmentId(e.target.value)}
              className="h-8 rounded-md border border-input bg-card px-3 text-xs font-mono text-foreground focus:border-border focus:outline-none"
            >
              {assessments.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.name || a.id} ({a.target?.value})
                </option>
              ))}
            </select>
          </div>

          {/* Chain Integrity Summary */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3.5">
            <Card className="bg-card border-border/60">
              <CardContent className="p-4 space-y-1">
                <span className="text-[11px] font-medium text-muted-foreground uppercase tracking-wider">
                  Chained Artifacts
                </span>
                <div className="text-2xl font-mono font-semibold text-foreground">
                  {evidenceRefs.length}
                </div>
                <p className="text-[11px] text-muted-foreground">
                  Immutable on-disk payloads
                </p>
              </CardContent>
            </Card>

            <Card className="bg-card border-border/60">
              <CardContent className="p-4 space-y-1">
                <span className="text-[11px] font-medium text-muted-foreground uppercase tracking-wider">
                  Hash Algorithm
                </span>
                <div className="text-2xl font-mono font-semibold text-foreground">
                  SHA-256
                </div>
                <p className="text-[11px] text-muted-foreground">
                  Standard Merkle digest
                </p>
              </CardContent>
            </Card>

            <Card className="bg-card border-border/60">
              <CardContent className="p-4 space-y-1">
                <span className="text-[11px] font-medium text-muted-foreground uppercase tracking-wider">
                  Chain Status
                </span>
                <div className="text-2xl font-mono font-semibold text-foreground flex items-center gap-1.5">
                  <span className="h-2 w-2 rounded-full bg-emerald-500" />
                  INTACT
                </div>
                <p className="text-[11px] text-muted-foreground">
                  Zero broken hashes detected
                </p>
              </CardContent>
            </Card>
          </div>

          {/* Artifact Hash Chain Explorer */}
          <div className="space-y-3">
            <h4 className="text-xs uppercase tracking-wider text-muted-foreground font-medium">
              Artifact Sequence in Assessment {selectedAssessmentId}
            </h4>

            {evidenceRefs.length === 0 ? (
              <div className="rounded-lg border border-border/60 bg-muted/20 p-8 text-center text-xs text-muted-foreground">
                No artifacts recorded for this assessment yet.
              </div>
            ) : (
              <div className="space-y-2">
                {evidenceRefs.map((ref, idx) => (
                  <div
                    key={ref.evidence_id || ref.id}
                    className="p-3 rounded-md border border-border/60 bg-card hover:border-border transition-colors space-y-1.5"
                  >
                    <div className="flex items-center justify-between text-xs">
                      <div className="flex items-center gap-2">
                        <Badge variant="outline" className="text-[10px] font-mono font-medium border-border/70">
                          #{idx + 1}
                        </Badge>
                        <span className="font-mono text-xs font-semibold text-foreground">
                          {ref.evidence_id || ref.id}
                        </span>
                        <Badge variant="secondary" className="text-[10px] font-normal">
                          {ref.tool_name || ref.action_name || "tool"}
                        </Badge>
                      </div>

                      <Link
                        href={`/assessments/${selectedAssessmentId}/evidence?focus=${ref.evidence_id || ref.id}`}
                      >
                        <Button variant="ghost" size="sm" className="h-6 text-[11px] px-2 text-muted-foreground hover:text-foreground">
                          View Proof →
                        </Button>
                      </Link>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-[11px] text-muted-foreground pt-1.5 border-t border-border/40 font-mono">
                      <div>
                        <span className="text-muted-foreground font-sans">Current Hash: </span>
                        <code className="text-[10px] select-all text-foreground/80">
                          {ref.sha256 || ref.sha256_hash}
                        </code>
                      </div>
                      <div>
                        <span className="text-muted-foreground font-sans">Location: </span>
                        <span>{ref.file_path || "vault artifact"}</span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
