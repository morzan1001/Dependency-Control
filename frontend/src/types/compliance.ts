export type ReportStatus = "pending" | "generating" | "completed" | "failed";
export type ReportFormat = "pdf" | "csv" | "json" | "sarif";
export type ReportFramework =
  | "nist-sp-800-131a"
  | "bsi-tr-02102"
  | "cnsa-2.0"
  | "fips-140-3"
  | "iso-19790"
  | "pqc-migration-plan"
  | "license-audit"
  | "cve-remediation-sla";

// Mirrors backend ControlStatus. "not_evaluated" is returned in place of a verdict that would
// have rested on the absence of a match in an input that did not cover the scope.
export type ControlStatus =
  | "passed"
  | "failed"
  | "waived"
  | "not_applicable"
  | "not_evaluated";

export type ControlStatusCounts = Partial<Record<ControlStatus, number>> & { total?: number };

// evaluated below in_scope means every verdict resting on this input was withheld as not_evaluated.
export interface InputCoverage {
  evaluated: number;
  in_scope: number;
  limit: number;
}

// What each input the verdicts rest on covered; null for an input the framework never reads.
export interface EvaluationCoverage {
  plan_items?: InputCoverage | null;
  // Parts of the scope no input could cover; each one withholds every verdict resting on finding no match.
  gaps?: string[];
}

export interface ComplianceReportMeta {
  _id: string;
  scope: "project" | "team" | "global" | "user";
  scope_id: string | null;
  framework: ReportFramework;
  format: ReportFormat;
  status: ReportStatus;
  requested_by: string;
  requested_at: string;
  completed_at: string | null;
  artifact_filename: string | null;
  artifact_size_bytes: number | null;
  artifact_mime_type: string | null;
  summary: ControlStatusCounts;
  coverage?: EvaluationCoverage | null;
  coverage_statement?: string | null;
  error_message: string | null;
  expires_at: string | null;
}

export interface ReportListResponse { reports: ComplianceReportMeta[]; }
export interface ReportAck { report_id: string; status: string; }
