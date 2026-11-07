"use client";

import { useState, useEffect, useRef, useCallback } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import {
  ArrowLeft,
  Rocket,
  CheckCircle2,
  AlertCircle,
  AlertTriangle,
  Zap,
  Upload,
  FileText,
  Lock,
  Copy,
  Check,
  ShieldCheck,
  ShieldAlert,
  Sliders,
  Crosshair,
  FileCode,
} from "lucide-react";
import { createAssessment, parseScope, ScopeParseResponse } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";

const PRESET_MOCK_LAB = {
  name: "Judge Lab Demo Assessment",
  target: "http://mock-target-lab:8080",
  scopeYaml: `schema_version: "1.0"
assessment_id: judge-demo-lab
targets:
  allowed_hosts: ["mock-target-lab"]
  allowed_subnets: ["172.16.0.0/12"]
  denied_hosts: ["169.254.169.254", "127.0.0.1"]
ports:
  allowed_ports: [80, 8080]
  denied_ports: [22, 25, 445]
actions:
  allowed_categories: ["network_recon", "web_crawl", "active_template_check"]
network_policy:
  redirect_policy: strict_same_host`,
};

const PRESET_OWASP_JUICE = {
  name: "OWASP Juice Shop Staging Scan",
  target: "http://192.168.100.5:8080",
  scopeYaml: `schema_version: "1.0"
assessment_id: owasp-juice-scan
targets:
  allowed_hosts: ["192.168.100.5"]
  allowed_subnets: ["192.168.100.0/28"]
  denied_hosts: ["169.254.169.254", "127.0.0.1"]
ports:
  allowed_ports: [8080]
  denied_ports: [22, 25]
actions:
  allowed_categories: ["network_recon", "active_template_check"]`,
};

export default function NewAssessmentPage() {
  const router = useRouter();

  // Intake strategy tab: dropzone, paste, presets
  const [activeTab, setActiveTab] = useState<"dropzone" | "paste" | "presets">("presets");

  // Core assessment configuration
  const [name, setName] = useState(PRESET_MOCK_LAB.name);
  const [target, setTarget] = useState(PRESET_MOCK_LAB.target);
  const [scopeYaml, setScopeYaml] = useState(PRESET_MOCK_LAB.scopeYaml);

  // Objective strategy & proof tier (Track A Challenge 03)
  const [objectiveType, setObjectiveType] = useState<"find_cve" | "discover_services" | "exploit_chain">("find_cve");
  const [minimumProof, setMinimumProof] = useState<"data_exposure" | "code_execution" | "auth_bypass" | "simulated_canary">("data_exposure");
  const [allowPivoting, setAllowPivoting] = useState(false);

  // Runtime settings
  const [maxIterations, setMaxIterations] = useState(8);
  const [simulation, setSimulation] = useState(true);

  // Parsing & validation states
  const [parseResult, setParseResult] = useState<ScopeParseResponse | null>(null);
  const [isParsing, setIsParsing] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);
  const [copiedHash, setCopiedHash] = useState(false);
  const [isDragOver, setIsDragOver] = useState(false);

  const fileInputRef = useRef<HTMLInputElement>(null);

  // Server-side parsing call
  const triggerScopeParse = useCallback(async (content: string, filename?: string) => {
    if (!content.trim()) {
      setParseResult(null);
      return;
    }
    setIsParsing(true);
    try {
      const res = await parseScope(content, filename);
      setParseResult(res);
      if (res.is_valid && res.read_back?.summary.authorized_targets.length) {
        const firstTarget = res.read_back.summary.authorized_targets[0];
        const port = res.read_back.summary.permitted_ports[0] || 80;
        setTarget(`http://${firstTarget}:${port}`);
      }
    } catch (err: any) {
      setParseResult({
        is_valid: false,
        scope_hash: null,
        format_detected: "ERROR",
        parsing_confidence: "DETERMINISTIC",
        read_back: null,
        normalized_yaml: null,
        errors: [err.message || "Network error communicating with scope validator."],
        warnings: [],
      });
    } finally {
      setIsParsing(false);
    }
  }, []);

  // Debounce parse on text changes
  useEffect(() => {
    const timer = setTimeout(() => {
      triggerScopeParse(scopeYaml);
    }, 400);
    return () => clearTimeout(timer);
  }, [scopeYaml, triggerScopeParse]);

  const handleFile = (file: File) => {
    // 1MB anti-DoS client-side guard
    if (file.size > 1024 * 1024) {
      setParseResult({
        is_valid: false,
        scope_hash: null,
        format_detected: "FILE",
        parsing_confidence: "DETERMINISTIC",
        read_back: null,
        normalized_yaml: null,
        errors: [`File ${file.name} (${(file.size / 1024 / 1024).toFixed(2)}MB) exceeds strict 1MB size limit.`],
        warnings: [],
      });
      return;
    }

    const reader = new FileReader();
    reader.onload = (event) => {
      const content = event.target?.result as string;
      if (!content) return;
      setScopeYaml(content);
      setName(`Assessment-${file.name.replace(/\.[^/.]+$/, "")}`);
      triggerScopeParse(content, file.name);
    };
    reader.readAsText(file);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragOver(false);
    const file = e.dataTransfer.files?.[0];
    if (file) handleFile(file);
  };

  const handleCopyHash = () => {
    if (!parseResult?.scope_hash) return;
    navigator.clipboard.writeText(parseResult.scope_hash);
    setCopiedHash(true);
    setTimeout(() => setCopiedHash(false), 2000);
  };

  const handleLaunch = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!parseResult?.is_valid) return;

    setIsSubmitting(true);
    setSubmitError(null);

    try {
      const objPayload =
        objectiveType === "exploit_chain"
          ? {
              type: "exploit_chain",
              minimum_proof: minimumProof,
              allow_pivoting: allowPivoting,
              target_asset: target,
            }
          : objectiveType === "discover_services"
          ? { type: "discover_services", required_hosts: 1 }
          : { type: "find_cve", find_cve: true, required_hosts: 1 };

      const created = await createAssessment({
        name,
        target,
        scope_yaml: parseResult.normalized_yaml || scopeYaml,
        imported_scope_hash: parseResult.scope_hash || undefined,
        auto_confirm: true,
        objective: objPayload,
        simulation,
        max_iterations: Number(maxIterations),
        auto_start: true,
      });

      router.push(`/assessments/${created.id}`);
    } catch (err: any) {
      setSubmitError(err.message || "Failed to launch assessment");
      setIsSubmitting(false);
    }
  };

  return (
    <div className="max-w-4xl mx-auto space-y-6">
      {/* Top Breadcrumb */}
      <div className="flex items-center gap-2 text-xs text-muted-foreground">
        <Link href="/" className="hover:text-foreground flex items-center gap-1 transition-colors">
          <ArrowLeft className="h-3 w-3" />
          Command Center
        </Link>
        <span>/</span>
        <span className="text-foreground font-medium">New Assessment</span>
        <span>/</span>
        <span className="text-muted-foreground">Pre-Flight Intake & Scope Authorization</span>
      </div>

      <Card className="border-border/70 bg-card">
        <CardHeader className="pb-4">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="text-base sm:text-lg flex items-center gap-2">
                <ShieldCheck className="h-5 w-5 text-emerald-500" />
                Intake & Pre-Flight Operator Authorization
              </CardTitle>
              <CardDescription className="text-xs mt-1">
                Zero-network deterministic ingestion. Arbitrary input is parsed, verified against fail-closed boundaries (SEC-01), and cryptographically frozen.
              </CardDescription>
            </div>
            {parseResult?.scope_hash && (
              <Badge variant="outline" className="font-mono text-[10px] hidden sm:flex items-center gap-1 bg-muted/40">
                <Lock className="h-2.5 w-2.5 text-emerald-500" />
                Frozen Digest
              </Badge>
            )}
          </div>
        </CardHeader>

        <CardContent className="space-y-6">
          {/* Intake Strategy Tabs */}
          <div className="border-b border-border/70">
            <div className="flex gap-4 text-xs">
              <button
                type="button"
                onClick={() => setActiveTab("presets")}
                className={`pb-2.5 font-medium flex items-center gap-1.5 border-b-2 transition-colors ${
                  activeTab === "presets"
                    ? "border-emerald-500 text-foreground"
                    : "border-transparent text-muted-foreground hover:text-foreground"
                }`}
              >
                <Zap className="h-3.5 w-3.5" />
                Demo Presets
              </button>
              <button
                type="button"
                onClick={() => setActiveTab("dropzone")}
                className={`pb-2.5 font-medium flex items-center gap-1.5 border-b-2 transition-colors ${
                  activeTab === "dropzone"
                    ? "border-emerald-500 text-foreground"
                    : "border-transparent text-muted-foreground hover:text-foreground"
                }`}
              >
                <Upload className="h-3.5 w-3.5" />
                File Dropzone (≤1MB)
              </button>
              <button
                type="button"
                onClick={() => setActiveTab("paste")}
                className={`pb-2.5 font-medium flex items-center gap-1.5 border-b-2 transition-colors ${
                  activeTab === "paste"
                    ? "border-emerald-500 text-foreground"
                    : "border-transparent text-muted-foreground hover:text-foreground"
                }`}
              >
                <FileText className="h-3.5 w-3.5" />
                Quick Paste / Raw Editor
              </button>
            </div>
          </div>

          {/* Tab 1: Demo Presets */}
          {activeTab === "presets" && (
            <div className="rounded-lg border border-border/60 bg-muted/30 p-4 space-y-3">
              <div className="text-xs text-muted-foreground">
                One-click authorized lab environments configured for Track A Challenge 03 demonstrations:
              </div>
              <div className="flex flex-wrap gap-2.5">
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  className="font-mono text-xs gap-1.5"
                  onClick={() => {
                    setName(PRESET_MOCK_LAB.name);
                    setTarget(PRESET_MOCK_LAB.target);
                    setScopeYaml(PRESET_MOCK_LAB.scopeYaml);
                  }}
                >
                  <Crosshair className="h-3.5 w-3.5 text-emerald-500" />
                  Mock Lab (8080)
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  size="sm"
                  className="font-mono text-xs gap-1.5"
                  onClick={() => {
                    setName(PRESET_OWASP_JUICE.name);
                    setTarget(PRESET_OWASP_JUICE.target);
                    setScopeYaml(PRESET_OWASP_JUICE.scopeYaml);
                  }}
                >
                  <Crosshair className="h-3.5 w-3.5 text-blue-500" />
                  OWASP Juice Shop (192.168.100.5)
                </Button>
              </div>
            </div>
          )}

          {/* Tab 2: File Dropzone */}
          {activeTab === "dropzone" && (
            <div
              onDragOver={(e) => {
                e.preventDefault();
                setIsDragOver(true);
              }}
              onDragLeave={() => setIsDragOver(false)}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
              className={`rounded-lg border-2 border-dashed p-8 text-center cursor-pointer transition-colors ${
                isDragOver
                  ? "border-emerald-500 bg-emerald-500/5"
                  : "border-border/70 hover:border-muted-foreground/50 bg-muted/20"
              }`}
            >
              <input
                ref={fileInputRef}
                type="file"
                accept=".yaml,.yml,.json,.md,.txt"
                onChange={(e) => {
                  const f = e.target.files?.[0];
                  if (f) handleFile(f);
                }}
                className="hidden"
              />
              <div className="flex flex-col items-center justify-center space-y-2">
                <div className="p-3 rounded-full bg-muted/60 text-muted-foreground">
                  <Upload className="h-5 w-5" />
                </div>
                <div className="text-xs font-medium text-foreground">
                  Drag and drop your scope file here, or click to browse
                </div>
                <div className="text-[11px] text-muted-foreground font-mono">
                  Supports .yaml, .json, .md, .txt (Strict ≤1MB size cap enforced)
                </div>
              </div>
            </div>
          )}

          {/* Tab 3: Quick Paste Editor */}
          {activeTab === "paste" && (
            <div className="space-y-2">
              <div className="flex items-center justify-between text-xs text-muted-foreground">
                <span>Paste raw evaluator copy, slide text, or markdown checklist:</span>
                <span className="font-mono text-[10px]">Deterministic Heuristic Extractor</span>
              </div>
              <textarea
                rows={7}
                value={scopeYaml}
                onChange={(e) => setScopeYaml(e.target.value)}
                placeholder="Example: Assess target at 192.168.100.5 on ports 80, 8080. Do not touch 192.168.100.1 or port 22."
                className="w-full rounded-md border border-border/70 bg-muted/20 p-3 font-mono text-xs text-foreground focus:border-border focus:outline-none custom-scrollbar"
              />
            </div>
          )}

          {/* Errors and Warnings Alerts */}
          {submitError && (
            <div className="rounded-md border border-rose-500/25 bg-rose-500/5 p-3 text-xs font-mono text-rose-500 dark:text-rose-400 flex items-center gap-2.5">
              <AlertCircle className="h-4 w-4 shrink-0" />
              <span>{submitError}</span>
            </div>
          )}

          {parseResult?.errors && parseResult.errors.length > 0 && (
            <div className="rounded-md border border-rose-500/25 bg-rose-500/5 p-3 text-xs font-mono text-rose-500 dark:text-rose-400 space-y-1">
              <div className="font-semibold flex items-center gap-1.5">
                <AlertCircle className="h-4 w-4 shrink-0" />
                Scope Rejection (Fail-Closed SEC-01):
              </div>
              {parseResult.errors.map((err, i) => (
                <div key={i} className="pl-5 text-[11px]">• {err}</div>
              ))}
            </div>
          )}

          {parseResult?.warnings && parseResult.warnings.length > 0 && (
            <div className="rounded-md border border-amber-500/25 bg-amber-500/5 p-3 text-xs font-mono text-amber-600 dark:text-amber-400 space-y-1">
              <div className="font-semibold flex items-center gap-1.5">
                <AlertTriangle className="h-4 w-4 shrink-0" />
                Intake Advisory:
              </div>
              {parseResult.warnings.map((w, i) => (
                <div key={i} className="pl-5 text-[11px]">• {w}</div>
              ))}
            </div>
          )}

          <form onSubmit={handleLaunch} className="space-y-6">
            {/* Primary Target Info */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="space-y-1.5">
                <label className="block text-xs font-medium text-muted-foreground">
                  Assessment Identifier / Name
                </label>
                <Input
                  type="text"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  className="font-sans border-border/70"
                  required
                />
              </div>

              <div className="space-y-1.5">
                <label className="block text-xs font-medium text-muted-foreground">
                  Derived Target URL or Entry Host
                </label>
                <Input
                  type="text"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  className="font-mono text-xs border-border/70"
                  required
                />
              </div>
            </div>

            {/* Objective & Proof Strategy Selector */}
            <div className="rounded-lg border border-border/70 bg-muted/10 p-4 space-y-4">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
                  <Sliders className="h-4 w-4 text-blue-500" />
                  Objective & Demonstrated Proof Tier (Challenge 03)
                </span>
                <span className="text-[10px] text-muted-foreground font-mono">
                  Operator Confirmation Required
                </span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                <button
                  type="button"
                  onClick={() => setObjectiveType("find_cve")}
                  className={`p-3 rounded-md border text-left transition-colors ${
                    objectiveType === "find_cve"
                      ? "border-blue-500/80 bg-blue-500/10 text-foreground"
                      : "border-border/60 bg-card hover:border-border text-muted-foreground"
                  }`}
                >
                  <div className="text-xs font-semibold">Vulnerability Scan</div>
                  <div className="text-[11px] opacity-80 mt-1">Passive recon + active CVE templates (find_cve).</div>
                </button>

                <button
                  type="button"
                  onClick={() => setObjectiveType("exploit_chain")}
                  className={`p-3 rounded-md border text-left transition-colors ${
                    objectiveType === "exploit_chain"
                      ? "border-emerald-500/80 bg-emerald-500/10 text-foreground"
                      : "border-border/60 bg-card hover:border-border text-muted-foreground"
                  }`}
                >
                  <div className="text-xs font-semibold text-emerald-500">Prove Impact (Exploit)</div>
                  <div className="text-[11px] opacity-80 mt-1">Demonstrated multi-step exploitation path.</div>
                </button>

                <button
                  type="button"
                  onClick={() => setObjectiveType("discover_services")}
                  className={`p-3 rounded-md border text-left transition-colors ${
                    objectiveType === "discover_services"
                      ? "border-blue-500/80 bg-blue-500/10 text-foreground"
                      : "border-border/60 bg-card hover:border-border text-muted-foreground"
                  }`}
                >
                  <div className="text-xs font-semibold">Service Recon</div>
                  <div className="text-[11px] opacity-80 mt-1">Port discovery and banner identification only.</div>
                </button>
              </div>

              {/* Extended Exploit Chain Options */}
              {objectiveType === "exploit_chain" && (
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 pt-2 border-t border-border/50">
                  <div className="space-y-1.5">
                    <label className="block text-xs font-medium text-muted-foreground">
                      Minimum Proof Requirement
                    </label>
                    <select
                      value={minimumProof}
                      onChange={(e: any) => setMinimumProof(e.target.value)}
                      className="w-full h-8 rounded-md border border-border/70 bg-card px-2.5 text-xs text-foreground focus:border-border focus:outline-none"
                    >
                      <option value="data_exposure">Data Exposure (/etc/passwd, DB dumps, tokens)</option>
                      <option value="code_execution">Demonstrated Command Execution (whoami / id)</option>
                      <option value="auth_bypass">Verified Auth Bypass / Admin Login</option>
                      <option value="simulated_canary">Simulated Probe Canary (Demo Lab)</option>
                    </select>
                  </div>

                  <div className="flex items-center space-x-2 pt-6">
                    <input
                      type="checkbox"
                      id="allowPivoting"
                      checked={allowPivoting}
                      onChange={(e) => setAllowPivoting(e.target.checked)}
                      className="rounded border-border text-emerald-500 focus:ring-0"
                    />
                    <label htmlFor="allowPivoting" className="text-xs text-foreground cursor-pointer">
                      Authorize multi-host lateral pivoting (Foothold attestation required)
                    </label>
                  </div>
                </div>
              )}
            </div>

            {/* PRE-FLIGHT READ-BACK CARD (Spec 12 Section 6) */}
            <div className="rounded-lg border border-border/80 bg-muted/20 p-4 space-y-3">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-border/50 pb-2.5">
                <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
                  <ShieldCheck className="h-4 w-4 text-emerald-500" />
                  Pre-Flight Operator Read-Back Screen
                </span>
                <div className="flex items-center gap-2">
                  {parseResult && (
                    <Badge variant="outline" className="font-mono text-[10px] text-muted-foreground">
                      Format: {parseResult.format_detected} ({parseResult.parsing_confidence})
                    </Badge>
                  )}
                  {isParsing && (
                    <span className="text-[11px] text-muted-foreground animate-pulse">
                      Analyzing bounds...
                    </span>
                  )}
                </div>
              </div>

              {/* Cryptographic Scope Hash Anchor */}
              {parseResult?.scope_hash && (
                <div className="flex items-center justify-between bg-muted/40 rounded px-3 py-1.5 text-[11px] font-mono border border-border/50">
                  <div className="flex items-center gap-1.5 text-muted-foreground overflow-hidden">
                    <Lock className="h-3 w-3 text-emerald-500 shrink-0" />
                    <span className="shrink-0">Scope Digest:</span>
                    <span className="text-foreground truncate">{parseResult.scope_hash}</span>
                  </div>
                  <button
                    type="button"
                    onClick={handleCopyHash}
                    className="text-muted-foreground hover:text-foreground shrink-0 ml-2"
                  >
                    {copiedHash ? <Check className="h-3.5 w-3.5 text-emerald-500" /> : <Copy className="h-3.5 w-3.5" />}
                  </button>
                </div>
              )}

              {/* High-Contrast Bounds Matrix */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                {/* Green Allowed Envelope */}
                <div className="rounded border border-emerald-500/25 bg-emerald-500/5 p-3 space-y-2">
                  <div className="font-semibold text-emerald-600 dark:text-emerald-400 flex items-center gap-1.5">
                    <CheckCircle2 className="h-3.5 w-3.5" />
                    I WILL TEST (Authorized Envelope)
                  </div>
                  <div className="text-[11px] font-mono text-foreground space-y-1">
                    <div>
                      <span className="text-muted-foreground">Targets: </span>
                      {parseResult?.read_back?.summary.authorized_targets.length ? (
                        parseResult.read_back.summary.authorized_targets.join(", ")
                      ) : (
                        <span className="text-amber-500">None detected</span>
                      )}
                    </div>
                    <div>
                      <span className="text-muted-foreground">Subnets: </span>
                      {parseResult?.read_back?.summary.allowed_subnets.length
                        ? parseResult.read_back.summary.allowed_subnets.join(", ")
                        : "None"}
                    </div>
                    <div>
                      <span className="text-muted-foreground">Ports: </span>
                      {parseResult?.read_back?.summary.permitted_ports.length
                        ? parseResult.read_back.summary.permitted_ports.join(", ")
                        : "80, 443 (Default)"}
                    </div>
                  </div>
                </div>

                {/* Red Denied Boundaries */}
                <div className="rounded border border-rose-500/25 bg-rose-500/5 p-3 space-y-2">
                  <div className="font-semibold text-rose-600 dark:text-rose-400 flex items-center gap-1.5">
                    <ShieldAlert className="h-3.5 w-3.5" />
                    I WILL NOT TOUCH (Strictly Denied)
                  </div>
                  <div className="text-[11px] font-mono text-foreground space-y-1">
                    <div>
                      <span className="text-muted-foreground">Boundaries: </span>
                      {parseResult?.read_back?.summary.denied_boundaries.length ? (
                        parseResult.read_back.summary.denied_boundaries.join(", ")
                      ) : (
                        "169.254.169.254, 127.0.0.1, 22, 25"
                      )}
                    </div>
                    <div>
                      <span className="text-muted-foreground">Pivoting: </span>
                      {allowPivoting ? "Authorized with foothold proof" : "Prohibited"}
                    </div>
                    <div>
                      <span className="text-muted-foreground">Enforcement: </span>
                      Deterministic policy gate outside LLM
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Launch Action */}
            <div className="flex items-center justify-between pt-4 border-t border-border/60">
              <div className="text-[11px] text-muted-foreground font-mono">
                {parseResult?.is_valid ? "Ready for cryptographic lock" : "Awaiting valid scope definition"}
              </div>
              <Button
                type="submit"
                disabled={isSubmitting || !parseResult?.is_valid}
                size="default"
                className="gap-2 bg-emerald-600 hover:bg-emerald-700 text-white"
              >
                <Lock className="h-3.5 w-3.5" />
                <span>
                  {isSubmitting
                    ? "Locking Digest & Engaging Agent..."
                    : "Confirm Scope & Engage Agent"}
                </span>
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
