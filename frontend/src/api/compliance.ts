import { api, getServerFile } from "@/api/client";
import { triggerBrowserDownload } from "@/lib/download";
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

// Download via the authenticated axios client; the endpoint requires the bearer header (a plain anchor 401s).
export async function downloadReport(id: string, filename: string): Promise<void> {
  const { blob } = await getServerFile(`/compliance/reports/${id}/download`);
  triggerBrowserDownload(blob, filename);
}
