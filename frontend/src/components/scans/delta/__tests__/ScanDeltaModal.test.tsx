import { cleanup, render, screen, fireEvent, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { afterEach, describe, it, expect, vi, beforeEach } from "vitest";
import { ScanDeltaModal } from "../ScanDeltaModal";
import * as api from "@/api/scanDelta";

vi.mock("@/api/scanDelta");

const empty = (cat: "findings" | "components" | "crypto") => ({
  category: cat,
  from_scan_id: "a",
  to_scan_id: "b",
  project_id: "p1",
  totals: { added: 0, removed: 0, unchanged: 0, changed: 0, by_severity: {}, by_type: {} },
  page: 1,
  page_size: 50,
  total_pages: 1,
  items: [],
});

function renderModal() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <ScanDeltaModal projectId="p1" fromScanId="a" toScanId="b" onClose={() => {}} />
    </QueryClientProvider>,
  );
}

describe("ScanDeltaModal", () => {
  beforeEach(() => vi.clearAllMocks());
  afterEach(() => {
    cleanup();
    // Radix Dialog locks scroll on body; clear so subsequent tests start clean.
    document.body.style.pointerEvents = "";
    delete document.body.dataset.scrollLocked;
  });

  it("loads only the default Findings tab on open", async () => {
    (api.getScanDelta as unknown as ReturnType<typeof vi.fn>).mockResolvedValue(empty("findings"));
    renderModal();
    await waitFor(() => expect(api.getScanDelta).toHaveBeenCalledTimes(1));
    const args = (api.getScanDelta as unknown as ReturnType<typeof vi.fn>).mock.calls[0][0];
    expect(args.category).toBe("findings");
  });

  it("lazy-loads Components tab only when clicked", async () => {
    (api.getScanDelta as unknown as ReturnType<typeof vi.fn>).mockResolvedValue(empty("findings"));
    renderModal();
    await waitFor(() => expect(api.getScanDelta).toHaveBeenCalledTimes(1));

    (api.getScanDelta as unknown as ReturnType<typeof vi.fn>).mockResolvedValueOnce(empty("components"));
    const compTab = screen.getByRole("tab", { name: /components/i });
    // Radix Tabs activates on mouseDown (not click) in jsdom; fire both to
    // simulate a real user click.
    fireEvent.mouseDown(compTab);
    fireEvent.click(compTab);
    await waitFor(() => {
      expect(api.getScanDelta).toHaveBeenCalledTimes(2);
      const calls = (api.getScanDelta as unknown as ReturnType<typeof vi.fn>).mock.calls;
      const last = calls[calls.length - 1][0];
      expect(last.category).toBe("components");
    });
  });

  it("each tab badge shows its own count, not other tabs'", async () => {
    // Different totals per category — verify counts don't bleed across tabs.
    (api.getScanDelta as unknown as ReturnType<typeof vi.fn>).mockImplementation(
      ({ category }: { category: "findings" | "components" | "crypto" }) => {
        const totalsByCategory = {
          findings: { added: 3, removed: 2, unchanged: 0, changed: 0, by_severity: {}, by_type: {} },
          components: { added: 7, removed: 1, unchanged: 0, changed: 4, by_severity: {}, by_type: {} },
          crypto: { added: 10, removed: 5, unchanged: 0, changed: 0, by_severity: {}, by_type: {} },
        } as const;
        return Promise.resolve({ ...empty(category), totals: totalsByCategory[category] });
      },
    );
    renderModal();

    await waitFor(() => {
      expect(screen.getByRole("tab", { name: /findings/i })).toHaveTextContent("5");
    });

    // Visit components — should show its OWN total (added+removed+changed=12), not the findings 5.
    const compTab = screen.getByRole("tab", { name: /components/i });
    fireEvent.mouseDown(compTab);
    fireEvent.click(compTab);
    await waitFor(() => {
      expect(screen.getByRole("tab", { name: /components/i })).toHaveTextContent("12");
      // Findings badge stays at 5
      expect(screen.getByRole("tab", { name: /findings/i })).toHaveTextContent("5");
    });

    // Visit crypto — added+removed=15.
    const cryptoTab = screen.getByRole("tab", { name: /crypto/i });
    fireEvent.mouseDown(cryptoTab);
    fireEvent.click(cryptoTab);
    await waitFor(() => {
      expect(screen.getByRole("tab", { name: /crypto/i })).toHaveTextContent("15");
      expect(screen.getByRole("tab", { name: /findings/i })).toHaveTextContent("5");
      expect(screen.getByRole("tab", { name: /components/i })).toHaveTextContent("12");
    });
  });

  it("resets badge counts when reopened with a different scan pair", async () => {
    // First open: returns 5 changes.
    (api.getScanDelta as unknown as ReturnType<typeof vi.fn>).mockResolvedValueOnce({
      ...empty("findings"),
      totals: { added: 3, removed: 2, unchanged: 0, changed: 0, by_severity: {}, by_type: {} },
    });
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const { rerender } = render(
      <QueryClientProvider client={qc}>
        <ScanDeltaModal projectId="p1" fromScanId="a" toScanId="b" onClose={() => {}} />
      </QueryClientProvider>,
    );
    await waitFor(() => {
      expect(screen.getByRole("tab", { name: /findings/i })).toHaveTextContent("5");
    });

    // Now switch to a different scan pair. The badge must immediately show "—"
    // (loading), NOT the stale "5" from the previous comparison.
    let resolveSecond: (v: unknown) => void = () => {};
    (api.getScanDelta as unknown as ReturnType<typeof vi.fn>).mockReturnValueOnce(
      new Promise((resolve) => {
        resolveSecond = resolve;
      }),
    );
    rerender(
      <QueryClientProvider client={qc}>
        <ScanDeltaModal projectId="p1" fromScanId="c" toScanId="d" onClose={() => {}} />
      </QueryClientProvider>,
    );

    // Stale "5" must be gone; badge shows "—" until the new fetch resolves.
    expect(screen.getByRole("tab", { name: /findings/i })).not.toHaveTextContent("5");
    expect(screen.getByRole("tab", { name: /findings/i })).toHaveTextContent("—");

    // Resolve the second fetch with a new total.
    resolveSecond({
      ...empty("findings"),
      totals: { added: 1, removed: 0, unchanged: 0, changed: 0, by_severity: {}, by_type: {} },
    });
    await waitFor(() => {
      expect(screen.getByRole("tab", { name: /findings/i })).toHaveTextContent("1");
    });
  });
});
