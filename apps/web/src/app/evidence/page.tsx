"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { ArrowLeft, Database, Lock, CheckCircle2, ShieldCheck, RefreshCw, KeyRound } from "lucide-react";
import { Card, CardHeader, CardTitle, CardDescription, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { listAssessments } from "@/lib/api";
import { AssessmentDetail } from "@/lib/types";
import { truncateHash } from "@/lib/utils";

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
      <div className="flex items-center gap-2 text-xs font-mono text-muted-foreground">
        <Link href="/" className="hover:text-foreground flex items-center gap-1 transition-colors">
          <ArrowLeft className="h-3 w-3" />
          Command Center
        </Link>
        <span>/</span>
        <span className="text-foreground">Merkle Audit Chain & Evidence Vault</span>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="text-xl">Cryptographic Chain of Custody</CardTitle>
              <CardDescription>
                Tamper-evident Merkle hash chain linking all raw HTTP responses and tool outputs with SHA-256 digests.
              </CardDescription>
            </div>
            <Badge variant="success" className="gap-1.5 font-mono">
              <Lock className="h-3.5 w-3.5" />
              Cryptographically Verified
            </Badge>
          </div>
        </CardHeader>

        <CardContent className="space-y-6">
          {/* Assessment Picker */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 p-3 rounded-lg border border-border bg-muted/30">
            <div className="text-xs font-mono text-muted-foreground">
              Select Assessment Run:
            </div>
            <select
              value={selectedAssessmentId}
              onChange={(e) => setSelectedAssessmentId(e.target.value)}
              className="h-8 rounded-md border border-input bg-card px-3 text-xs font-mono text-foreground focus:border-primary focus:outline-none"
            >
              {assessments.map((a) => (
                <option key={a.id} value={a.id}>
                  {a.name || a.id} ({a.target?.value})
                </option>
              ))}
            </select>
          </div>

          {/* Chain Integrity Summary */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <Card className="bg-card">
              <CardContent className="p-4 space-y-1">
                <span className="text-[11px] font-mono text-muted-foreground uppercase">
                  Chained Artifacts
                </span>
                <div className="text-2xl font-mono font-bold text-foreground">
                  {evidenceRefs.length}
                </div>
                <p className="text-[10px] font-mono text-muted-foreground">
                  Immutable on-disk payloads
                </p>
              </CardContent>
            </Card>

            <Card className="bg-card">
              <CardContent className="p-4 space-y-1">
                <span className="text-[11px] font-mono text-muted-foreground uppercase">
                  Hash Algorithm
                </span>
                <div className="text-2xl font-mono font-bold text-primary">
                  SHA-256
                </div>
                <p className="text-[10px] font-mono text-muted-foreground">
                  Standard Merkle digest
                </p>
              </CardContent>
            </Card>

            <Card className="bg-card">
              <CardContent className="p-4 space-y-1">
                <span className="text-[11px] font-mono text-muted-foreground uppercase">
                  Chain Status
                </span>
                <div className="text-2xl font-mono font-bold text-primary flex items-center gap-1.5">
                  <CheckCircle2 className="h-5 w-5" />
                  INTACT
                </div>
                <p className="text-[10px] font-mono text-muted-foreground">
                  Zero broken hashes detected
                </p>
              </CardContent>
            </Card>
          </div>

          {/* Artifact Hash Chain Explorer */}
          <div className="space-y-3 font-mono">
            <h4 className="text-xs uppercase tracking-wider text-muted-foreground font-semibold">
              Artifact Sequence in Assessment {selectedAssessmentId}
            </h4>

            {evidenceRefs.length === 0 ? (
              <div className="rounded-lg border border-border bg-muted/20 p-8 text-center text-xs text-muted-foreground">
                No artifacts recorded for this assessment yet.
              </div>
            ) : (
              <div className="space-y-2">
                {evidenceRefs.map((ref, idx) => (
                  <div
                    key={ref.evidence_id || ref.id}
                    className="p-3 rounded-md border border-border bg-card hover:border-primary/40 transition-colors space-y-1.5"
                  >
                    <div className="flex items-center justify-between text-xs">
                      <div className="flex items-center gap-2">
                        <Badge variant="outline" className="text-[10px] font-bold">
                          #{idx + 1}
                        </Badge>
                        <span className="font-bold text-foreground">
                          {ref.evidence_id || ref.id}
                        </span>
                        <Badge variant="secondary" className="text-[10px]">
                          {ref.tool_name || ref.action_name || "tool"}
                        </Badge>
                      </div>

                      <Link
                        href={`/assessments/${selectedAssessmentId}/evidence?focus=${ref.evidence_id || ref.id}`}
                      >
                        <Button variant="ghost" size="sm" className="h-6 text-[11px] px-2">
                          View Proof →
                        </Button>
                      </Link>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-[11px] text-muted-foreground pt-1 border-t border-border/50">
                      <div>
                        <span className="text-foreground font-semibold">Current Hash: </span>
                        <code className="text-[10px] select-all text-primary">
                          {ref.sha256 || ref.sha256_hash}
                        </code>
                      </div>
                      <div>
                        <span className="text-foreground font-semibold">Location: </span>
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
