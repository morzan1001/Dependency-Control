import { render, screen, waitFor, fireEvent } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { FindingsDeltaTab } from "../tabs/FindingsDeltaTab";
import * as api from "@/api/scanDelta";

vi.mock("@/api/scanDelta");

function renderTab(onCountLoaded: (n: number) => void = () => {}) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <FindingsDeltaTab projectId="p1" fromScanId="a" toScanId="b" onCountLoaded={onCountLoaded} />
    </QueryClientProvider>,
  );
}

const sampleResponse = {
  category: "findings",
  from_scan_id: "a",
  to_scan_id: "b",
  project_id: "p1",
  totals: {
    added: 1,
    removed: 0,
    unchanged: 0,
    changed: 0,
    by_severity: { critical: 1 },
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
      severity: "critical",
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

  it("renders finding rows", async () => {
    (api.getScanDelta as unknown as ReturnType<typeof vi.fn>).mockResolvedValue(sampleResponse);
    renderTab();
    await waitFor(() => expect(screen.getByText("CVE-1")).toBeInTheDocument());
  });

  it("re-fetches when severity filter changes", async () => {
    (api.getScanDelta as unknown as ReturnType<typeof vi.fn>).mockResolvedValue(sampleResponse);
    renderTab();
    await waitFor(() => expect(api.getScanDelta).toHaveBeenCalledTimes(1));

    const sevToggle = screen.getByRole("button", { name: /critical/i });
    fireEvent.click(sevToggle);
    await waitFor(() => {
      const calls = (api.getScanDelta as unknown as ReturnType<typeof vi.fn>).mock.calls;
      const lastCall = calls[calls.length - 1][0];
      expect(lastCall.severity).toEqual(["critical"]);
    });
  });
});
