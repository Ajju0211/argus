import { AssessmentDetail, Finding, StatusResponse } from "./types";

const BASE_URL = "/api/v1/assessments";

export async function listAssessments(limit = 50): Promise<AssessmentDetail[]> {
  const res = await fetch(`${BASE_URL}?limit=${limit}`, { cache: "no-store" });
  if (!res.ok) throw new Error(`Failed to list assessments: ${res.statusText}`);
  return res.json();
}

export async function getAssessment(id: string): Promise<AssessmentDetail> {
  const res = await fetch(`${BASE_URL}/${id}`, { cache: "no-store" });
  if (!res.ok) throw new Error(`Failed to get assessment: ${res.statusText}`);
  return res.json();
}

export async function createAssessment(payload: {
  name?: string;
  target: string | { type: string; value: string };
  scope_yaml?: string;
  scope?: string | Record<string, unknown>;
  scope_document?: Record<string, unknown>;
  imported_scope_hash?: string;
  auto_confirm?: boolean;
  objective?: string | Record<string, unknown>;
  simulation?: boolean;
  auto_start?: boolean;
  max_iterations?: number;
}): Promise<AssessmentDetail> {
  const res = await fetch(BASE_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Failed to create assessment: ${res.statusText}`);
  }
  return res.json();
}

export interface ScopeParseResponse {
  is_valid: boolean;
  scope_hash: string | null;
  format_detected: string;
  parsing_confidence: "DETERMINISTIC" | "HEURISTIC";
  read_back: {
    assessment_name: string;
    scope_hash: string;
    parsed_format: string;
    parsing_confidence: string;
    summary: {
      authorized_targets: string[];
      allowed_subnets: string[];
      denied_boundaries: string[];
      permitted_ports: number[];
      permitted_actions: string[];
      multi_host_pivoting: boolean;
      objective: {
        type: string;
        minimum_proof?: string;
        description?: string;
        requires_operator_upgrade?: boolean;
      };
      budget: {
        max_iterations: number;
        max_duration_minutes: number;
      };
    };
    warnings: string[];
  } | null;
  normalized_yaml: string | null;
  errors: string[];
  warnings: string[];
}

export async function parseScope(
  content: string,
  filename?: string
): Promise<ScopeParseResponse> {
  const res = await fetch("/api/v1/scope/parse", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ file_content: content, filename }),
  });
  return res.json();
}

export async function startAssessment(id: string): Promise<StatusResponse> {
  const res = await fetch(`${BASE_URL}/${id}/start`, { method: "POST" });
  if (!res.ok) throw new Error(`Failed to start: ${res.statusText}`);
  return res.json();
}

export async function pauseAssessment(id: string): Promise<StatusResponse> {
  const res = await fetch(`${BASE_URL}/${id}/pause`, { method: "POST" });
  if (!res.ok) throw new Error(`Failed to pause: ${res.statusText}`);
  return res.json();
}

export async function resumeAssessment(id: string): Promise<StatusResponse> {
  const res = await fetch(`${BASE_URL}/${id}/resume`, { method: "POST" });
  if (!res.ok) throw new Error(`Failed to resume: ${res.statusText}`);
  return res.json();
}

export async function cancelAssessment(id: string): Promise<StatusResponse> {
  const res = await fetch(`${BASE_URL}/${id}/cancel`, { method: "POST" });
  if (!res.ok) throw new Error(`Failed to cancel: ${res.statusText}`);
  return res.json();
}

export async function deleteAssessment(id: string): Promise<StatusResponse> {
  const res = await fetch(`${BASE_URL}/${id}`, { method: "DELETE" });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.detail || `Failed to delete assessment: ${res.statusText}`);
  }
  return res.json();
}

export async function getFindings(id: string): Promise<Finding[]> {
  const res = await fetch(`${BASE_URL}/${id}/findings`, { cache: "no-store" });
  if (!res.ok) throw new Error(`Failed to get findings: ${res.statusText}`);
  return res.json();
}

export async function getRawEvidence(assessmentId: string, evidenceId: string): Promise<string> {
  const res = await fetch(`${BASE_URL}/${assessmentId}/evidence/${evidenceId}`, {
    cache: "no-store",
  });
  if (!res.ok) throw new Error(`Failed to download evidence: ${res.statusText}`);
  return res.text();
}

export async function getReport(id: string, format: "json" | "md" | "html" = "json"): Promise<any> {
  const res = await fetch(`${BASE_URL}/${id}/report?format=${format}`, { cache: "no-store" });
  if (!res.ok) throw new Error(`Failed to retrieve report: ${res.statusText}`);
  if (format === "json") return res.json();
  return res.text();
}

