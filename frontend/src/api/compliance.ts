import { api } from "@/api/client";
import type {
  ReportAck, ReportFormat, ReportFramework,
  ReportListResponse,
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

export async function listReports(params: { limit: number }): Promise<ReportListResponse> {
  const { data } = await api.get<ReportListResponse>("/compliance/reports", { params });
  return data;
}

export async function deleteReport(id: string): Promise<void> {
  await api.delete(`/compliance/reports/${id}`);
}
