import { api } from "@/api/client";
import type {
  ComplianceReportMeta, ReportAck, ReportFormat, ReportFramework,
  ReportListResponse, ReportStatus,
} from "@/types/compliance";

export interface CreateReportPayload {
  scope: "project" | "team" | "global" | "user";
  scope_id?: string | null;
  framework: ReportFramework;
  format: ReportFormat;
  comment?: string;
}

export async function createReport(p: CreateReportPayload): Promise<ReportAck> {
  const { data } = await api.post<ReportAck>("/compliance/reports", p);
  return data;
}

export interface ListReportsParams {
  scope?: "project" | "team" | "global" | "user";
  scope_id?: string | null;
  framework?: ReportFramework;
  status?: ReportStatus;
  skip?: number;
  limit?: number;
}

export async function listReports(p: ListReportsParams = {}): Promise<ReportListResponse> {
  const { data } = await api.get<ReportListResponse>("/compliance/reports", {
    params: p,
  });
  return data;
}

export async function getReport(id: string): Promise<ComplianceReportMeta> {
  const { data } = await api.get<ComplianceReportMeta>(`/compliance/reports/${id}`);
  return data;
}

export async function deleteReport(id: string): Promise<void> {
  await api.delete(`/compliance/reports/${id}`);
}

export function downloadReportUrl(id: string): string {
  return `/api/v1/compliance/reports/${id}/download`;
}
