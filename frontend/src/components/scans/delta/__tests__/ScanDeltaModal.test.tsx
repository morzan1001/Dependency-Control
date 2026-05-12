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

  it("shows tab badge counts after tab is loaded", async () => {
    (api.getScanDelta as unknown as ReturnType<typeof vi.fn>).mockResolvedValue({
      ...empty("findings"),
      totals: { added: 3, removed: 2, unchanged: 0, changed: 0, by_severity: {}, by_type: {} },
    });
    renderModal();
    await waitFor(() => {
      const tab = screen.getByRole("tab", { name: /findings/i });
      expect(tab).toHaveTextContent("5"); // added+removed
    });
  });
});
