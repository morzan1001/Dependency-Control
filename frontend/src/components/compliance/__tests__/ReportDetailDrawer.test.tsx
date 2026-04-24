import { render, screen, fireEvent } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { describe, it, expect, vi } from "vitest";

import { ReportDetailDrawer } from "../ReportDetailDrawer";
import type { ComplianceReportMeta } from "@/types/compliance";

vi.mock("@/api/compliance", () => ({
  deleteReport: vi.fn().mockResolvedValue(undefined),
  downloadReportUrl: (id: string) => `/api/v1/compliance/reports/${id}/download`,
}));

function withClient(ui: React.ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={qc}>{ui}</QueryClientProvider>);
}

const sampleReport: ComplianceReportMeta = {
  _id: "r1",
  scope: "user",
  scope_id: null,
  framework: "nist-sp-800-131a",
  format: "pdf",
  status: "completed",
  requested_by: "user@example.com",
  requested_at: "2026-04-20T10:00:00Z",
  completed_at: "2026-04-20T10:05:00Z",
  artifact_filename: "report.pdf",
  artifact_size_bytes: 1024,
  summary: {},
} as ComplianceReportMeta;

describe("ReportDetailDrawer", () => {
  it("renders a Delete report button and opens confirmation dialog", async () => {
    withClient(<ReportDetailDrawer report={sampleReport} onClose={() => {}} />);
    const deleteBtn = await screen.findByRole("button", { name: /Delete report/i });
    expect(deleteBtn).toBeInTheDocument();
    fireEvent.click(deleteBtn);
    expect(await screen.findByText(/Delete this report\?/i)).toBeInTheDocument();
  });

  it("calls deleteReport when confirmed", async () => {
    const { deleteReport } = await import("@/api/compliance");
    withClient(<ReportDetailDrawer report={sampleReport} onClose={() => {}} />);
    fireEvent.click(await screen.findByRole("button", { name: /Delete report/i }));
    const confirm = await screen.findByRole("button", { name: /^Delete$/ });
    fireEvent.click(confirm);
    await new Promise((r) => setTimeout(r, 0));
    expect(deleteReport).toHaveBeenCalledWith("r1");
  });
});
