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
  summary: Record<string, unknown>;
  error_message: string | null;
  expires_at: string | null;
}

export interface ReportListResponse { reports: ComplianceReportMeta[]; }
export interface ReportAck { report_id: string; status: string; }
