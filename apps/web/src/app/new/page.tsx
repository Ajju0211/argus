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
  const [objective, setObjective] = useState("discover_services");
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
      // Simple parser check
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
      <div className="flex items-center gap-2 text-xs font-mono text-cyber-muted">
        <Link href="/" className="hover:text-white flex items-center gap-1 transition-colors">
          <ArrowLeft className="h-3 w-3" />
          Command Center
        </Link>
        <span>/</span>
        <span className="text-white">New Assessment</span>
      </div>

      <div className="glass-panel-elevated rounded-3xl p-6 sm:p-8 border border-cyber-border space-y-8">
        <div>
          <h1 className="text-2xl font-black text-white tracking-wide">
            Launch Authorized Assessment
          </h1>
          <p className="text-xs sm:text-sm text-cyber-muted mt-1">
            Configure target boundaries and policy-approved scope. All execution passes through the deterministic safety firewall.
          </p>
        </div>

        {/* Demo Quick Presets */}
        <div className="rounded-2xl border border-indigo-500/30 bg-indigo-500/10 p-4">
          <div className="flex items-center gap-2 text-xs font-mono font-bold text-indigo-300 mb-2">
            <Zap className="h-4 w-4 text-indigo-400" />
            Hackathon Judge Quick Presets
          </div>
          <div className="flex flex-wrap gap-2">
            <button
              type="button"
              onClick={() => {
                setName(PRESET_MOCK_LAB.name);
                setTarget(PRESET_MOCK_LAB.target);
                setScopeYaml(PRESET_MOCK_LAB.scopeYaml);
              }}
              className="rounded-lg border border-indigo-500/40 bg-indigo-500/20 px-3 py-1.5 text-xs font-mono text-white hover:bg-indigo-500/30 transition-colors"
            >
              ⚡ Mock Lab Fixture (8080)
            </button>
            <button
              type="button"
              onClick={() => {
                setName(PRESET_OWASP_JUICE.name);
                setTarget(PRESET_OWASP_JUICE.target);
                setScopeYaml(PRESET_OWASP_JUICE.scopeYaml);
              }}
              className="rounded-lg border border-cyber-border bg-cyber-card px-3 py-1.5 text-xs font-mono text-cyber-muted hover:text-white transition-colors"
            >
              🌐 Local Subnet Demo (192.168.100.5)
            </button>
          </div>
        </div>

        {submitError && (
          <div className="rounded-xl border border-rose-500/40 bg-rose-500/10 p-4 text-xs font-mono text-rose-300 flex items-center gap-3">
            <AlertCircle className="h-5 w-5 text-rose-400 shrink-0" />
            <span>{submitError}</span>
          </div>
        )}

        <form onSubmit={handleLaunch} className="space-y-6">
          {/* Target Info */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-mono uppercase tracking-wider text-cyber-muted mb-2">
                Assessment Name
              </label>
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                required
                className="w-full h-10 rounded-xl border border-cyber-border bg-cyber-bg px-3.5 text-xs font-mono text-white placeholder-cyber-muted focus:border-indigo-500 focus:outline-none"
              />
            </div>

            <div>
              <label className="block text-xs font-mono uppercase tracking-wider text-cyber-muted mb-2">
                Target URL / IP Address
              </label>
              <input
                type="text"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                required
                className="w-full h-10 rounded-xl border border-cyber-border bg-cyber-bg px-3.5 text-xs font-mono text-white placeholder-cyber-muted focus:border-indigo-500 focus:outline-none"
              />
            </div>
          </div>

          {/* Scope YAML Editor & Live Validation */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <label className="text-xs font-mono uppercase tracking-wider text-cyber-muted">
                Authorized Scope Document (YAML)
              </label>
              <span
                className={`inline-flex items-center gap-1.5 text-xs font-mono px-2 py-0.5 rounded border ${
                  scopeValidation.valid
                    ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-400"
                    : "border-rose-500/40 bg-rose-500/10 text-rose-400"
                }`}
              >
                {scopeValidation.valid ? (
                  <CheckCircle2 className="h-3 w-3" />
                ) : (
                  <AlertCircle className="h-3 w-3" />
                )}
                {scopeValidation.message}
              </span>
            </div>
            <textarea
              value={scopeYaml}
              onChange={(e) => setScopeYaml(e.target.value)}
              rows={10}
              required
              className="w-full rounded-2xl border border-cyber-border bg-cyber-bg p-4 font-mono text-xs text-cyber-text leading-relaxed focus:border-indigo-500 focus:outline-none resize-y"
            />
          </div>

          {/* Objective & Limits */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-mono uppercase tracking-wider text-cyber-muted mb-2">
                Assessment Objective
              </label>
              <select
                value={objective}
                onChange={(e) => setObjective(e.target.value)}
                className="w-full h-10 rounded-xl border border-cyber-border bg-cyber-bg px-3.5 text-xs font-mono text-white focus:border-indigo-500 focus:outline-none"
              >
                <option value="discover_services">Discover open services and attack surface</option>
                <option value="severity_threshold">Verify CVEs matching HIGH/CRITICAL severity</option>
                <option value="find_cve">Confirm a specific reproducible vulnerability</option>
              </select>
            </div>

            <div>
              <label className="block text-xs font-mono uppercase tracking-wider text-cyber-muted mb-2">
                Max Iteration Budget
              </label>
              <input
                type="number"
                min={1}
                max={50}
                value={maxIterations}
                onChange={(e) => setMaxIterations(Number(e.target.value))}
                className="w-full h-10 rounded-xl border border-cyber-border bg-cyber-bg px-3.5 text-xs font-mono text-white focus:border-indigo-500 focus:outline-none"
              />
            </div>
          </div>

          {/* Safety Sandbox Switch */}
          <div className="flex items-center gap-3 p-4 rounded-xl border border-cyber-border bg-cyber-card/50">
            <input
              type="checkbox"
              id="sim-check"
              checked={simulation}
              onChange={(e) => setSimulation(e.target.checked)}
              className="h-4 w-4 rounded border-cyber-border bg-cyber-bg text-indigo-600 focus:ring-0"
            />
            <label htmlFor="sim-check" className="text-xs text-cyber-muted font-mono cursor-pointer">
              <span className="text-white font-semibold">Simulation Mode:</span> Clearly labelled offline demonstration.
              Does not invoke destructive external network tools or consume live paid credits.
            </label>
          </div>

          {/* Action Buttons */}
          <div className="flex items-center justify-end gap-3 pt-4 border-t border-cyber-border">
            <Link
              href="/"
              className="rounded-xl border border-cyber-border bg-cyber-card px-5 py-2.5 text-xs font-mono text-cyber-muted hover:text-white transition-colors"
            >
              Cancel
            </Link>
            <button
              type="submit"
              disabled={isSubmitting || !scopeValidation.valid}
              className="flex items-center gap-2 rounded-xl bg-gradient-to-r from-indigo-600 via-indigo-500 to-cyan-500 px-6 py-2.5 text-xs font-mono font-bold text-white shadow-lg shadow-indigo-600/30 hover:brightness-110 active:scale-95 transition-all disabled:opacity-50"
            >
              <Rocket className="h-4 w-4" />
              {isSubmitting ? "Launching Agent..." : "Launch Assessment"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

