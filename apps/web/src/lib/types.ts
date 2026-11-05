export interface AssessmentTarget {
  type: string;
  value: string;
}

export interface AssessmentLimits {
  max_duration_seconds: number;
  max_iterations: number;
  max_concurrency: number;
}

export interface Finding {
  finding_id: string;
  assessment_id: string;
  title: string;
  description: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFORMATIONAL";
  confidence: "CONFIRMED" | "POTENTIAL" | "REJECTED" | "UNVERIFIABLE";
  affected_asset: string;
  affected_service: string;
  verification_method: string;
  reproduction_steps: string;
  impact: string;
  remediation: string;
  evidence_ids: string[];
  research_source_ids?: string[];
  created_at: string;
}

export interface EvidenceArtifact {
  evidence_id: string;
  assessment_id: string;
  tool_name: string;
  tool_version: string;
  command_executed: string;
  sha256: string;
  file_path: string;
  captured_at: string;
  content_type: string;
  redacted: boolean;
  metadata?: Record<string, unknown>;
}

export interface AssessmentDetail {
  id: string;
  name: string;
  status: "READY" | "QUEUED" | "RUNNING" | "PAUSED" | "COMPLETED" | "SUCCESS" | "FAILED" | "CANCELLED" | "PARTIAL_SUCCESS";
  target: AssessmentTarget;
  objective: string | Record<string, unknown>;
  discovered_assets: string[];
  discovered_services: Array<{
    port: number;
    protocol?: string;
    service?: string;
    product?: string;
    version?: string;
  }>;
  total_findings: number;
  created_at: string;
  completed_at?: string | null;
  outcome?: string | null;
  summary?: string | null;
  error?: string | null;
  simulation: boolean;
  updated_at?: string | null;
  report_url?: string | null;
  report_pdf_url?: string | null;
  findings: Finding[];
  evidence_refs: Array<{
    id?: string;
    evidence_id?: string;
    tool_name?: string;
    action_name?: string;
    sha256?: string;
    sha256_hash?: string;
    file_path?: string;
    file_size_bytes?: number;
  }>;
  blocked_actions: Array<{
    action_id?: string;
    tool_name?: string;
    target_host?: string;
    target_port?: number;
    denied_reason?: string;
    reject_reason?: string;
  }>;
  telemetry: Array<Record<string, unknown>>;
  budget: {
    iterations_used?: number;
    max_iterations?: number;
    tokens_consumed?: number;
    estimated_cost_usd?: number;
  };
  is_terminal: boolean;
  assessment_id?: string;
}

export interface AssessmentEvent {
  id: number;
  eventType: string;
  node?: string;
  message?: string;
  data: Record<string, unknown>;
  timestamp: string;
}

export interface StatusResponse {
  status: string;
}

export interface ScopeValidationResult {
  valid: boolean;
  allowedHosts: string[];
  allowedSubnets: string[];
  allowedPorts: number[];
  deniedPorts: number[];
  errors: string[];
}

