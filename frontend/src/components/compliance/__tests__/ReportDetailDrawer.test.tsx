import { render, screen, fireEvent } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { describe, it, expect, vi } from "vitest";

import { ReportDetailDrawer } from "../ReportDetailDrawer";
import type { ComplianceReportMeta } from "@/types/compliance";

vi.mock("@/api/compliance", () => ({
  deleteReport: vi.fn().mockResolvedValue(undefined),
  downloadReport: vi.fn().mockResolvedValue(undefined),
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

const EVALUATED = 20000;
const IN_SCOPE = 20050;
const NOT_EVALUATED = IN_SCOPE - EVALUATED;
const ASSET_CAP = 10000;
const ASSETS_IN_SCOPE = 10001;
const PARTIAL_WARNING = /rested on finding no match in a capped input/i;
const WITHHELD = 3;

describe("ReportDetailDrawer", () => {
  it("says no verdict over a subset may report passed or waived", () => {
    const partial: ComplianceReportMeta = {
      ...sampleReport,
      coverage: {
        findings: { evaluated: EVALUATED, in_scope: IN_SCOPE, limit: EVALUATED },
        crypto_assets: { evaluated: ASSETS_IN_SCOPE, in_scope: ASSETS_IN_SCOPE, limit: ASSET_CAP },
      },
    };
    withClient(<ReportDetailDrawer report={partial} onClose={() => {}} />);

    expect(screen.getByText(PARTIAL_WARNING)).toBeInTheDocument();
    expect(screen.getByText(new RegExp(NOT_EVALUATED.toLocaleString()))).toBeInTheDocument();
  });

  it("names the crypto inventory when that is the input the cap cut", () => {
    const partial: ComplianceReportMeta = {
      ...sampleReport,
      coverage: {
        findings: { evaluated: IN_SCOPE, in_scope: IN_SCOPE, limit: EVALUATED },
        crypto_assets: { evaluated: ASSET_CAP, in_scope: ASSETS_IN_SCOPE, limit: ASSET_CAP },
      },
    };
    withClient(<ReportDetailDrawer report={partial} onClose={() => {}} />);

    expect(screen.getByText(PARTIAL_WARNING)).toBeInTheDocument();
    expect(screen.getByText(/crypto assets in scope, a cap of/i)).toBeInTheDocument();
  });

  it("states plainly that a full evaluation covered the scope", () => {
    const complete: ComplianceReportMeta = {
      ...sampleReport,
      coverage: {
        findings: { evaluated: IN_SCOPE, in_scope: IN_SCOPE, limit: EVALUATED },
        crypto_assets: { evaluated: ASSETS_IN_SCOPE, in_scope: ASSETS_IN_SCOPE, limit: ASSET_CAP },
      },
    };
    withClient(<ReportDetailDrawer report={complete} onClose={() => {}} />);

    expect(screen.getByText(/Evaluated all/i)).toBeInTheDocument();
    expect(screen.queryByText(PARTIAL_WARNING)).not.toBeInTheDocument();
  });

  it("shows how many verdicts the cap withheld", () => {
    const withheld: ComplianceReportMeta = {
      ...sampleReport,
      coverage: {
        findings: { evaluated: EVALUATED, in_scope: IN_SCOPE, limit: EVALUATED },
        crypto_assets: { evaluated: ASSETS_IN_SCOPE, in_scope: ASSETS_IN_SCOPE, limit: ASSET_CAP },
      },
      summary: { passed: 0, failed: 0, waived: 0, not_applicable: 0, not_evaluated: WITHHELD, total: WITHHELD },
    };
    withClient(<ReportDetailDrawer report={withheld} onClose={() => {}} />);

    const label = screen.getByText("not_evaluated");
    expect(label).toBeInTheDocument();
    expect(label.className).toMatch(/amber/);
  });

  it("renders a Delete report button and opens confirmation dialog", async () => {
    withClient(<ReportDetailDrawer report={sampleReport} onClose={() => {}} />);
    const deleteBtn = await screen.findByRole("button", { name: /Delete report/i });
    expect(deleteBtn).toBeInTheDocument();
    fireEvent.click(deleteBtn);
    expect(await screen.findByText(/Delete this report\?/i)).toBeInTheDocument();
  });

  it("calls downloadReport with the report id when the download button is clicked", async () => {
    const { downloadReport } = await import("@/api/compliance");
    withClient(<ReportDetailDrawer report={sampleReport} onClose={() => {}} />);
    const downloadBtn = await screen.findByRole("button", { name: /Download/i });
    fireEvent.click(downloadBtn);
    await new Promise((r) => setTimeout(r, 0));
    expect(downloadReport).toHaveBeenCalledWith("r1", "report.pdf");
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
