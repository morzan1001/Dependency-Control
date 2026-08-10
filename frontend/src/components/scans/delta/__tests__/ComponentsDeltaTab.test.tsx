import { render, screen, waitFor, within } from "@testing-library/react";
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

  it("renders version_changed rows in a table with summary totals", async () => {
    (api.getScanDelta as unknown as ReturnType<typeof vi.fn>).mockResolvedValue({
      category: "components", from_scan_id: "a", to_scan_id: "b", project_id: "p1",
      totals: { added: 2, removed: 1, unchanged: 5, changed: 1, by_severity: {}, by_type: {} },
      page: 1, page_size: 50, total_pages: 1,
      items: [{
        change: "version_changed", name: "react", purl: "pkg:npm/react",
        version: null, from_version: "1.2.0", to_version: "1.4.1",
        license: null, from_license: null, to_license: null,
      }],
    });
    renderTab();
    await waitFor(() => expect(screen.getByText("1.2.0 → 1.4.1")).toBeInTheDocument());

    expect(within(screen.getByRole("table")).getByText("react")).toBeInTheDocument();
    expect(screen.getByText("+2")).toBeInTheDocument();
    expect(screen.getByText("−1")).toBeInTheDocument();
    expect(screen.getByText("↻1")).toBeInTheDocument();
    expect(screen.getByText("5")).toBeInTheDocument();
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
      expect(screen.getByText("MIT → Apache-2.0")).toBeInTheDocument();
    });
  });

  it("shows skeleton rows while loading", () => {
    (api.getScanDelta as unknown as ReturnType<typeof vi.fn>).mockReturnValue(new Promise(() => {}));
    renderTab();
    const table = screen.getByRole("table");
    expect(within(table).getAllByRole("row")).toHaveLength(1 + 3); // header + 3 skeleton rows
  });
});
