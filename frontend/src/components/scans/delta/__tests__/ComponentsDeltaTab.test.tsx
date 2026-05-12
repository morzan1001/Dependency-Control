import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { ComponentsDeltaTab } from "../tabs/ComponentsDeltaTab";
import * as api from "@/api/scanDelta";

vi.mock("@/api/scanDelta");

function renderTab() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <ComponentsDeltaTab projectId="p1" fromScanId="a" toScanId="b" onCountLoaded={() => {}} />
    </QueryClientProvider>,
  );
}

describe("ComponentsDeltaTab", () => {
  beforeEach(() => vi.clearAllMocks());

  it("renders version_changed with from → to", async () => {
    (api.getScanDelta as unknown as ReturnType<typeof vi.fn>).mockResolvedValue({
      category: "components", from_scan_id: "a", to_scan_id: "b", project_id: "p1",
      totals: { added: 0, removed: 0, unchanged: 0, changed: 1, by_severity: {}, by_type: {} },
      page: 1, page_size: 50, total_pages: 1,
      items: [{
        change: "version_changed", name: "react", purl: "pkg:npm/react",
        version: null, from_version: "17.0.2", to_version: "18.2.0",
        license: null, from_license: null, to_license: null,
      }],
    });
    renderTab();
    await waitFor(() => {
      expect(screen.getByText(/react/)).toBeInTheDocument();
      expect(screen.getByText(/17\.0\.2/)).toBeInTheDocument();
      expect(screen.getByText(/18\.2\.0/)).toBeInTheDocument();
    });
  });

  it("renders license_changed with from → to", async () => {
    (api.getScanDelta as unknown as ReturnType<typeof vi.fn>).mockResolvedValue({
      category: "components", from_scan_id: "a", to_scan_id: "b", project_id: "p1",
      totals: { added: 0, removed: 0, unchanged: 0, changed: 1, by_severity: {}, by_type: {} },
      page: 1, page_size: 50, total_pages: 1,
      items: [{
        change: "license_changed", name: "lodash", purl: "pkg:npm/lodash",
        version: null, from_version: null, to_version: null,
        license: null, from_license: "MIT", to_license: "Apache-2.0",
      }],
    });
    renderTab();
    await waitFor(() => {
      expect(screen.getByText(/lodash/)).toBeInTheDocument();
      expect(screen.getByText(/MIT/)).toBeInTheDocument();
      expect(screen.getByText(/Apache-2\.0/)).toBeInTheDocument();
    });
  });
});
