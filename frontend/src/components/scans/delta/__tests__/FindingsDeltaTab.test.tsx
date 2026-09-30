import { render, screen, waitFor, fireEvent, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { FindingsDeltaTab } from "../tabs/FindingsDeltaTab";
import * as api from "@/api/scanDelta";
import type { ScanDeltaResponse } from "@/types/scanDelta";
import { formatDate } from "@/lib/utils";

vi.mock("@/api/scanDelta");

function renderTab(onLoaded: (delta: ScanDeltaResponse) => void = () => {}) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <FindingsDeltaTab projectId="p1" fromScanId="a" toScanId="b" onLoaded={onLoaded} />
    </QueryClientProvider>,
  );
}

const sampleResponse = {
  category: "findings",
  from_scan_id: "a",
  to_scan_id: "b",
  project_id: "p1",
  totals: {
    added: 2,
    removed: 1,
    unchanged: 5,
    changed: 0,
    by_severity: { CRITICAL: 1 },
    by_type: { vulnerability: 1 },
  },
  page: 1,
  page_size: 50,
  total_pages: 1,
  items: [
    {
      change: "added",
      finding_id: "f1",
      finding_type: "vulnerability",
      severity: "CRITICAL",
      title: "CVE-1",
      component: "lib",
      cve_id: "CVE-1",
      file_path: null,
      first_seen: "2026-05-11T08:00:00Z",
    },
  ],
};

describe("FindingsDeltaTab", () => {
  beforeEach(() => vi.clearAllMocks());

  it("renders finding rows in a table with change and severity badges", async () => {
    (api.getScanDelta as unknown as ReturnType<typeof vi.fn>).mockResolvedValue(sampleResponse);
    renderTab();
    await waitFor(() => expect(screen.getByText("CVE-1")).toBeInTheDocument());

    const table = screen.getByRole("table");
    expect(within(table).getByText("+ added")).toBeInTheDocument();
    expect(within(table).getByText("CRITICAL")).toBeInTheDocument();
  });

  it("renders summary totals from the response", async () => {
    (api.getScanDelta as unknown as ReturnType<typeof vi.fn>).mockResolvedValue(sampleResponse);
    renderTab();
    await waitFor(() => expect(screen.getByText("+2")).toBeInTheDocument());
    expect(screen.getByText("−1")).toBeInTheDocument();
    expect(screen.getByText("5")).toBeInTheDocument();
    expect(screen.getByText("Unchanged")).toBeInTheDocument();
  });

  it("shows skeleton rows while loading", () => {
    (api.getScanDelta as unknown as ReturnType<typeof vi.fn>).mockReturnValue(new Promise(() => {}));
    renderTab();
    const table = screen.getByRole("table");
    expect(within(table).getAllByRole("row")).toHaveLength(1 + 3); // header + 3 skeleton rows
  });

  it("re-fetches when severity filter changes", async () => {
    (api.getScanDelta as unknown as ReturnType<typeof vi.fn>).mockResolvedValue(sampleResponse);
    renderTab();
    await waitFor(() => expect(api.getScanDelta).toHaveBeenCalledTimes(1));

    const sevToggle = screen.getByRole("button", { name: /^critical$/i });
    fireEvent.click(sevToggle);
    await waitFor(() => {
      const calls = (api.getScanDelta as unknown as ReturnType<typeof vi.fn>).mock.calls;
      const lastCall = calls[calls.length - 1][0];
      expect(lastCall.severity).toEqual(["critical"]);
    });
  });

  it("shows a changed record with both versions and the CVEs that moved", async () => {
    (api.getScanDelta as unknown as ReturnType<typeof vi.fn>).mockResolvedValue({
      ...sampleResponse,
      totals: { ...sampleResponse.totals, changed: 1 },
      items: [
        {
          change: "changed",
          finding_id: "lodash:4.17.21",
          finding_type: "vulnerability",
          severity: "CRITICAL",
          title: "",
          component: "lodash",
          cve_id: "CVE-2020-8203",
          file_path: null,
          first_seen: "2026-01-05T00:00:00Z",
          from_version: "4.17.20",
          to_version: "4.17.21",
          added_cves: [],
          dropped_cves: ["CVE-2020-8203"],
        },
      ],
    });
    renderTab();

    const table = await screen.findByRole("table");
    await waitFor(() => expect(within(table).getByText("↻ changed")).toBeInTheDocument());
    expect(within(table).getByText("4.17.20 → 4.17.21")).toBeInTheDocument();
    expect(within(table).getByText("−CVE-2020-8203")).toBeInTheDocument();
    expect(screen.getByText("↻1")).toBeInTheDocument();
  });

  it("shows when a finding was first detected", async () => {
    (api.getScanDelta as unknown as ReturnType<typeof vi.fn>).mockResolvedValue(sampleResponse);
    renderTab();

    const table = await screen.findByRole("table");
    expect(within(table).getByRole("columnheader", { name: "First seen" })).toBeInTheDocument();
    await waitFor(() => expect(within(table).getByText(formatDate("2026-05-11T08:00:00Z"))).toBeInTheDocument());
  });

  it("filters to changed records", async () => {
    (api.getScanDelta as unknown as ReturnType<typeof vi.fn>).mockResolvedValue(sampleResponse);
    renderTab();
    await waitFor(() => expect(api.getScanDelta).toHaveBeenCalledTimes(1));

    fireEvent.click(screen.getByRole("button", { name: /^changed$/i }));

    await waitFor(() => {
      const calls = (api.getScanDelta as unknown as ReturnType<typeof vi.fn>).mock.calls;
      expect(calls[calls.length - 1][0].change).toBe("changed");
    });
  });
});
