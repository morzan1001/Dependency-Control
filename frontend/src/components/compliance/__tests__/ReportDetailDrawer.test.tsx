import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { beforeEach, describe, it, expect, vi } from "vitest";

import { ReportDetailDrawer } from "../ReportDetailDrawer";
import type { ComplianceReportMeta } from "@/types/compliance";

const { getServerFile } = vi.hoisted(() => ({ getServerFile: vi.fn() }));
vi.mock("@/api/client", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/api/client")>()),
  getServerFile,
}));
vi.mock("@/api/compliance", () => ({
  deleteReport: vi.fn().mockResolvedValue(undefined),
}));
const permissionSet = new Set<string>();
vi.mock("@/context/useAuth", () => ({ useAuth: () => ({ hasPermission: (p: string) => permissionSet.has(p) }) }));
vi.mock("@/hooks/queries/use-users", () => ({ useCurrentUser: () => ({ data: { id: "u1" } }) }));

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
  requested_by: "u1",
  requested_at: "2026-04-20T10:00:00Z",
  completed_at: "2026-04-20T10:05:00Z",
  artifact_filename: "report.pdf",
  artifact_size_bytes: 1024,
  summary: {},
} as ComplianceReportMeta;

const PLAN_CAP = 1000;
const PLAN_ITEMS_IN_SCOPE = 4200;
const CAPPED_STATEMENT =
  "Evaluated 1000 of 4200 migration plan items in scope, a cap of 1000 per report; the remaining 3200 were not read.";
const GAP_STATEMENT =
  "Inputs are missing for part of the scope, so every verdict that would have rested on finding no match is " +
  "reported as not_evaluated: project 'payments' has no usable scan.";
const WITHHELD = 3;

describe("ReportDetailDrawer", () => {
  beforeEach(() => permissionSet.clear());

  it("shows the coverage statement of a capped plan as a warning", () => {
    const partial: ComplianceReportMeta = {
      ...sampleReport,
      coverage: { plan_items: { evaluated: PLAN_CAP, in_scope: PLAN_ITEMS_IN_SCOPE, limit: PLAN_CAP } },
      coverage_statement: CAPPED_STATEMENT,
    };
    withClient(<ReportDetailDrawer report={partial} onClose={() => {}} />);

    expect(screen.getByText(CAPPED_STATEMENT).className).toMatch(/amber/);
  });

  it("states plainly that a full evaluation covered the scope", () => {
    const complete: ComplianceReportMeta = {
      ...sampleReport,
      coverage: { plan_items: { evaluated: PLAN_CAP, in_scope: PLAN_CAP, limit: PLAN_CAP } },
      coverage_statement: "Evaluated all 1000 migration plan items in scope.",
    };
    withClient(<ReportDetailDrawer report={complete} onClose={() => {}} />);

    expect(screen.getByText(/Evaluated all/i).className).not.toMatch(/amber/);
  });

  it("claims no coverage for a report that recorded no bounded input", () => {
    const cveReport: ComplianceReportMeta = {
      ...sampleReport,
      coverage: { plan_items: null, gaps: [] },
      coverage_statement: "The verdicts cover the whole scope.",
    };
    withClient(<ReportDetailDrawer report={cveReport} onClose={() => {}} />);

    expect(screen.queryByText(/whole scope/i)).not.toBeInTheDocument();
  });

  it("warns about the part of the scope no input covered", () => {
    const gapped: ComplianceReportMeta = {
      ...sampleReport,
      coverage: { gaps: ["project 'payments' has no usable scan"] },
      coverage_statement: GAP_STATEMENT,
    };
    withClient(<ReportDetailDrawer report={gapped} onClose={() => {}} />);

    expect(screen.getByText(GAP_STATEMENT).className).toMatch(/amber/);
  });

  it("shows how many verdicts the cap withheld", () => {
    const withheld: ComplianceReportMeta = {
      ...sampleReport,
      coverage: { plan_items: { evaluated: PLAN_CAP, in_scope: PLAN_ITEMS_IN_SCOPE, limit: PLAN_CAP } },
      coverage_statement: CAPPED_STATEMENT,
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

  it("offers no delete on a report someone else requested", () => {
    withClient(<ReportDetailDrawer report={{ ...sampleReport, requested_by: "u2" }} onClose={() => {}} />);

    expect(screen.queryByRole("button", { name: /Delete report/i })).not.toBeInTheDocument();
  });

  it("lets a system manager delete a report someone else requested", () => {
    permissionSet.add("system:manage");
    withClient(<ReportDetailDrawer report={{ ...sampleReport, requested_by: "u2" }} onClose={() => {}} />);

    expect(screen.getByRole("button", { name: /Delete report/i })).toBeInTheDocument();
  });

  it("downloads the report artifact under the server's filename", async () => {
    getServerFile.mockResolvedValue({ blob: new Blob(["pdf"]), filename: "report.pdf" });
    window.URL.createObjectURL = vi.fn(() => "blob:report");
    window.URL.revokeObjectURL = vi.fn();
    const saved: string[] = [];
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (this: HTMLAnchorElement) {
      saved.push(this.download);
    });
    withClient(<ReportDetailDrawer report={sampleReport} onClose={() => {}} />);

    fireEvent.click(await screen.findByRole("button", { name: /Download/i }));

    await waitFor(() => expect(saved).toEqual(["report.pdf"]));
    expect(getServerFile).toHaveBeenCalledWith("/compliance/reports/r1/download");
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
