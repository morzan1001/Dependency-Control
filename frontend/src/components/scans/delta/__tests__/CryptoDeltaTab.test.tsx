import { render, screen, waitFor, fireEvent, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { CryptoDeltaTab } from "../tabs/CryptoDeltaTab";
import * as api from "@/api/scanDelta";

vi.mock("@/api/scanDelta");

function renderTab(onCountLoaded: (n: number) => void = () => {}) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <CryptoDeltaTab projectId="p1" fromScanId="a" toScanId="b" onCountLoaded={onCountLoaded} />
    </QueryClientProvider>,
  );
}

describe("CryptoDeltaTab", () => {
  beforeEach(() => vi.clearAllMocks());

  it("renders added and removed crypto items in a table with summary totals", async () => {
    (api.getScanDelta as unknown as ReturnType<typeof vi.fn>).mockResolvedValue({
      category: "crypto", from_scan_id: "a", to_scan_id: "b", project_id: "p1",
      totals: { added: 1, removed: 1, unchanged: 5, changed: 0, by_severity: {}, by_type: {} },
      page: 1, page_size: 50, total_pages: 1,
      items: [
        { change: "added", name: "SHA-256", variant: null, primitive: "hash", locations: [], asset_count: 1 },
        { change: "removed", name: "MD5", variant: null, primitive: "hash", locations: [], asset_count: 2 },
      ],
    });
    renderTab();
    await waitFor(() => expect(screen.getByText("SHA-256")).toBeInTheDocument());

    expect(screen.getByRole("table")).toBeInTheDocument();
    expect(screen.getByText("MD5")).toBeInTheDocument();
    expect(screen.getByText("+1")).toBeInTheDocument();
    expect(screen.getByText("−1")).toBeInTheDocument();
    expect(screen.getByText("5")).toBeInTheDocument();
  });

  it("renders locations count and asset_count multiplier", async () => {
    (api.getScanDelta as unknown as ReturnType<typeof vi.fn>).mockResolvedValue({
      category: "crypto", from_scan_id: "a", to_scan_id: "b", project_id: "p1",
      totals: { added: 1, removed: 0, unchanged: 0, changed: 0, by_severity: {}, by_type: {} },
      page: 1, page_size: 50, total_pages: 1,
      items: [
        { change: "added", name: "AES-128", variant: "CBC", primitive: "cipher", locations: ["a.py:1", "b.py:2"], asset_count: 3 },
      ],
    });
    renderTab();
    await waitFor(() => expect(screen.getByText("AES-128")).toBeInTheDocument());
    expect(screen.getByText("CBC")).toBeInTheDocument();
    expect(screen.getByText("2")).toBeInTheDocument();
    expect(screen.getByText("×3")).toBeInTheDocument();
  });

  it("calls onCountLoaded with totals after fetch", async () => {
    (api.getScanDelta as unknown as ReturnType<typeof vi.fn>).mockResolvedValue({
      category: "crypto", from_scan_id: "a", to_scan_id: "b", project_id: "p1",
      totals: { added: 3, removed: 2, unchanged: 7, changed: 0, by_severity: {}, by_type: {} },
      page: 1, page_size: 50, total_pages: 1, items: [],
    });
    const onCountLoaded = vi.fn();
    renderTab(onCountLoaded);
    await waitFor(() => expect(onCountLoaded).toHaveBeenCalledWith(5));
  });

  it("re-fetches when change filter changes", async () => {
    (api.getScanDelta as unknown as ReturnType<typeof vi.fn>).mockResolvedValue({
      category: "crypto", from_scan_id: "a", to_scan_id: "b", project_id: "p1",
      totals: { added: 0, removed: 0, unchanged: 0, changed: 0, by_severity: {}, by_type: {} },
      page: 1, page_size: 50, total_pages: 1, items: [],
    });
    renderTab();
    await waitFor(() => expect(api.getScanDelta).toHaveBeenCalledTimes(1));

    const addedToggle = screen.getByRole("button", { name: /^added$/i });
    fireEvent.click(addedToggle);
    await waitFor(() => {
      const calls = (api.getScanDelta as unknown as ReturnType<typeof vi.fn>).mock.calls;
      expect(calls[calls.length - 1][0].change).toBe("added");
    });
  });

  it("shows skeleton rows while loading", () => {
    (api.getScanDelta as unknown as ReturnType<typeof vi.fn>).mockReturnValue(new Promise(() => {}));
    renderTab();
    const table = screen.getByRole("table");
    expect(within(table).getAllByRole("row")).toHaveLength(1 + 3); // header + 3 skeleton rows
  });
});
