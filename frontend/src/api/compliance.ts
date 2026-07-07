import { api } from "@/api/client";
import type {
  ReportAck, ReportFormat, ReportFramework,
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

export async function deleteReport(id: string): Promise<void> {
  await api.delete(`/compliance/reports/${id}`);
}

// Extract a filename from a Content-Disposition header, handling RFC 5987 and plain forms.
function filenameFromContentDisposition(header: string | undefined): string | undefined {
  if (!header) return undefined;
  const utf8Match = /filename\*=(?:UTF-8'')?([^;]+)/i.exec(header);
  if (utf8Match?.[1]) {
    try {
      return decodeURIComponent(utf8Match[1].replace(/^"|"$/g, "").trim());
    } catch {
      /* fall through to the plain form */
    }
  }
  const plainMatch = /filename="?([^";]+)"?/i.exec(header);
  return plainMatch?.[1]?.trim() || undefined;
}

// Download via the authenticated axios client; the endpoint requires the bearer header (a plain anchor 401s).
export async function downloadReport(id: string, filename?: string): Promise<void> {
  const response = await api.get<Blob>(`/compliance/reports/${id}/download`, {
    responseType: "blob",
  });

  const name =
    filename ||
    filenameFromContentDisposition(
      response.headers?.["content-disposition"] as string | undefined,
    ) ||
    `compliance-report-${id}`;

  const url = window.URL.createObjectURL(response.data);
  try {
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = name;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
  } finally {
    window.URL.revokeObjectURL(url);
  }
}
