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

const ASSET_CAP = 10000;
const ASSETS_IN_SCOPE = 10001;
const PARTIAL_WARNING = /rested on finding no match in a capped input/i;
const WITHHELD = 3;

describe("ReportDetailDrawer", () => {
  it("names the crypto inventory when that is the input the cap cut", () => {
    const partial: ComplianceReportMeta = {
      ...sampleReport,
      coverage: {
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
        crypto_assets: { evaluated: ASSETS_IN_SCOPE, in_scope: ASSETS_IN_SCOPE, limit: ASSET_CAP },
      },
    };
    withClient(<ReportDetailDrawer report={complete} onClose={() => {}} />);

    expect(screen.getByText(/Evaluated all/i)).toBeInTheDocument();
    expect(screen.queryByText(PARTIAL_WARNING)).not.toBeInTheDocument();
  });

  it("says a report over findings alone covered the whole scope", () => {
    const cveReport: ComplianceReportMeta = {
      ...sampleReport,
      coverage: { crypto_assets: null, plan_items: null, gaps: [] },
    };
    withClient(<ReportDetailDrawer report={cveReport} onClose={() => {}} />);

    expect(screen.getByText("The verdicts cover the whole scope.")).toBeInTheDocument();
    expect(screen.queryByText(/crypto assets|findings/i)).not.toBeInTheDocument();
  });

  it("states the plan items a migration plan report covered", () => {
    const pqcReport: ComplianceReportMeta = {
      ...sampleReport,
      coverage: { crypto_assets: null, plan_items: { evaluated: 1000, in_scope: 4200, limit: 1000 }, gaps: [] },
    };
    withClient(<ReportDetailDrawer report={pqcReport} onClose={() => {}} />);

    expect(screen.getByText(/Evaluated 1,000 of 4,200 migration plan items/i)).toBeInTheDocument();
  });

  it("warns about the part of the scope no input covered", () => {
    const gapped: ComplianceReportMeta = {
      ...sampleReport,
      coverage: { crypto_assets: null, gaps: ["project 'payments' has no usable scan"] },
    };
    withClient(<ReportDetailDrawer report={gapped} onClose={() => {}} />);

    const notice = screen.getByText(/project 'payments' has no usable scan/);
    expect(notice.className).toMatch(/amber/);
    expect(screen.queryByText(PARTIAL_WARNING)).not.toBeInTheDocument();
  });

  it("names five gaps and counts the rest", () => {
    const gaps = ["a", "b", "c", "d", "e", "f", "g"].map((name) => `project '${name}' has no usable scan`);
    const gapped: ComplianceReportMeta = {
      ...sampleReport,
      coverage: { gaps },
    };
    withClient(<ReportDetailDrawer report={gapped} onClose={() => {}} />);

    const notice = screen.getByText(/project 'e' has no usable scan and 2 more\./);
    expect(notice.textContent).not.toContain("project 'f'");
  });

  it("shows how many verdicts the cap withheld", () => {
    const withheld: ComplianceReportMeta = {
      ...sampleReport,
      coverage: { crypto_assets: { evaluated: ASSET_CAP, in_scope: ASSETS_IN_SCOPE, limit: ASSET_CAP } },
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
