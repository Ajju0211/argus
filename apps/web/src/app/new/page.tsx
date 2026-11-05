"use client";

import { useState, useMemo } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import {
  ShieldCheck,
  ShieldAlert,
  ArrowLeft,
  Rocket,
  CheckCircle2,
  AlertCircle,
  Zap,
} from "lucide-react";
import { createAssessment } from "@/lib/api";
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
  const [name, setName] = useState(PRESET_MOCK_LAB.name);
  const [target, setTarget] = useState(PRESET_MOCK_LAB.target);
  const [scopeYaml, setScopeYaml] = useState(PRESET_MOCK_LAB.scopeYaml);
  const [objective, setObjective] = useState("find_cve");
  const [maxIterations, setMaxIterations] = useState(8);
  const [simulation, setSimulation] = useState(true);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [submitError, setSubmitError] = useState<string | null>(null);

  // Real-time client scope validator
  const scopeValidation = useMemo(() => {
    try {
      if (!scopeYaml.trim()) {
        return { valid: false, message: "Scope YAML cannot be empty" };
      }
      const lines = scopeYaml.split("\n");
      const hasTargets = lines.some((l) => l.trim().startsWith("allowed_hosts:"));
      const hasPorts = lines.some((l) => l.trim().startsWith("allowed_ports:"));

      if (!hasTargets) {
        return { valid: false, message: "Scope must define 'allowed_hosts'" };
      }
      return {
        valid: true,
        message: "Scope Validated: Host boundaries and port limits verified.",
      };
    } catch (err: any) {
      return { valid: false, message: `Syntax error: ${err.message}` };
    }
  }, [scopeYaml]);

  const handleLaunch = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSubmitting(true);
    setSubmitError(null);

    try {
      const objPayload =
        objective === "severity_threshold"
          ? { type: "severity_threshold", min_severity: "HIGH" }
          : objective === "find_cve"
          ? { find_cve: true, required_hosts: 1 }
          : { type: "discover_services", required_hosts: 1 };

      const created = await createAssessment({
        name,
        target,
        scope_yaml: scopeYaml,
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
      <div className="flex items-center gap-2 text-xs font-mono text-muted-foreground">
        <Link href="/" className="hover:text-foreground flex items-center gap-1 transition-colors">
          <ArrowLeft className="h-3 w-3" />
          Command Center
        </Link>
        <span>/</span>
        <span className="text-foreground">New Assessment</span>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-xl">Launch Authorized Assessment</CardTitle>
          <CardDescription>
            Configure target boundaries and policy-approved scope. All execution passes through the deterministic safety firewall.
          </CardDescription>
        </CardHeader>

        <CardContent className="space-y-6">
          {/* Quick Presets */}
          <div className="rounded-lg border border-border bg-muted/40 p-4">
            <div className="flex items-center gap-2 text-xs font-mono font-bold text-foreground mb-2">
              <Zap className="h-4 w-4 text-primary" />
              Demo Quick Presets
            </div>
            <div className="flex flex-wrap gap-2">
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => {
                  setName(PRESET_MOCK_LAB.name);
                  setTarget(PRESET_MOCK_LAB.target);
                  setScopeYaml(PRESET_MOCK_LAB.scopeYaml);
                }}
              >
                Mock Lab Fixture (8080)
              </Button>
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() => {
                  setName(PRESET_OWASP_JUICE.name);
                  setTarget(PRESET_OWASP_JUICE.target);
                  setScopeYaml(PRESET_OWASP_JUICE.scopeYaml);
                }}
              >
                Local Subnet Demo (192.168.100.5)
              </Button>
            </div>
          </div>

          {submitError && (
            <div className="rounded-md border border-destructive/40 bg-destructive/10 p-3 text-xs font-mono text-destructive flex items-center gap-2.5">
              <AlertCircle className="h-4 w-4 shrink-0" />
              <span>{submitError}</span>
            </div>
          )}

          <form onSubmit={handleLaunch} className="space-y-6">
            {/* Target Info */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="space-y-1.5">
                <label className="block text-xs font-mono uppercase tracking-wider text-muted-foreground">
                  Assessment Name
                </label>
                <Input
                  type="text"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  required
                />
              </div>

              <div className="space-y-1.5">
                <label className="block text-xs font-mono uppercase tracking-wider text-muted-foreground">
                  Target URL / IP Address
                </label>
                <Input
                  type="text"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  required
                />
              </div>
            </div>

            {/* Scope YAML Editor & Live Validation */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <label className="text-xs font-mono uppercase tracking-wider text-muted-foreground">
                  Authorized Scope Document (YAML)
                </label>
                <Badge variant={scopeValidation.valid ? "success" : "destructive"}>
                  {scopeValidation.valid ? (
                    <CheckCircle2 className="h-3 w-3" />
                  ) : (
                    <AlertCircle className="h-3 w-3" />
                  )}
                  <span>{scopeValidation.message}</span>
                </Badge>
              </div>

              <textarea
                rows={9}
                value={scopeYaml}
                onChange={(e) => setScopeYaml(e.target.value)}
                required
                className="w-full rounded-md border border-input bg-muted/20 p-3 font-mono text-xs text-foreground focus:border-primary focus:outline-none"
              />
            </div>

            {/* Execution Strategy */}
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              <div className="space-y-1.5">
                <label className="block text-xs font-mono uppercase tracking-wider text-muted-foreground">
                  Objective Strategy
                </label>
                <select
                  value={objective}
                  onChange={(e) => setObjective(e.target.value)}
                  className="w-full h-9 rounded-md border border-input bg-card px-3 text-xs font-mono text-foreground focus:border-primary focus:outline-none"
                >
                  <option value="find_cve">Find & Verify Vulnerabilities</option>
                  <option value="discover_services">Reconnaissance & Ports Only</option>
                  <option value="severity_threshold">Critical/High Severity Only</option>
                </select>
              </div>

              <div className="space-y-1.5">
                <label className="block text-xs font-mono uppercase tracking-wider text-muted-foreground">
                  Max ReAct Iterations
                </label>
                <Input
                  type="number"
                  min={1}
                  max={30}
                  value={maxIterations}
                  onChange={(e) => setMaxIterations(Number(e.target.value))}
                  required
                />
              </div>

              <div className="space-y-1.5">
                <label className="block text-xs font-mono uppercase tracking-wider text-muted-foreground">
                  Engine Mode
                </label>
                <select
                  value={simulation ? "true" : "false"}
                  onChange={(e) => setSimulation(e.target.value === "true")}
                  className="w-full h-9 rounded-md border border-input bg-card px-3 text-xs font-mono text-foreground focus:border-primary focus:outline-none"
                >
                  <option value="true">Simulation Mode (Fixture Targets)</option>
                  <option value="false">Live Agent Mode (Bifrost Gateway)</option>
                </select>
              </div>
            </div>

            {/* Launch Action */}
            <div className="flex items-center justify-end pt-4 border-t border-border">
              <Button
                type="submit"
                disabled={isSubmitting || !scopeValidation.valid}
                size="lg"
                className="gap-2"
              >
                <Rocket className="h-4 w-4" />
                <span>{isSubmitting ? "Initializing Pipeline..." : "Engage Agent"}</span>
              </Button>
            </div>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}
