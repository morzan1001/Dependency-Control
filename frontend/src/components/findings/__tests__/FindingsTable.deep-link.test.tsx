import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { describe, it, expect, vi, beforeEach } from "vitest";
import type { Finding } from "@/types/scan";
import { FindingsTable } from "../FindingsTable";

vi.mock("@/api/scans", () => ({
  scanApi: { getFindings: vi.fn() },
}));
vi.mock("sonner", () => ({ toast: { warning: vi.fn() } }));
vi.mock("../FindingDetailsModal", () => ({
  FindingDetailsModal: ({ finding }: { finding: Finding }) => <div data-testid="opened-finding">{finding.id}</div>,
}));

import { scanApi } from "@/api/scans";
import { toast } from "sonner";

const getFindingsMock = scanApi.getFindings as ReturnType<typeof vi.fn>;
const LINKED_ID = "CVE-2024-0001";

function envelope(items: Partial<Finding>[]) {
  return { items, total: items.length, page: 1, size: 50, pages: 1 };
}

function renderAt(url: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[url]}>
        <FindingsTable scanId="s1" projectId="p1" />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("FindingsTable ?finding= deep link", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("opens the finding whose id the link names", async () => {
    getFindingsMock.mockImplementation(async (_scanId: string, params: { search?: string }) =>
      params.search === LINKED_ID ? envelope([{ id: "other:1.0" }, { id: LINKED_ID }]) : envelope([]),
    );

    renderAt(`/?finding=${LINKED_ID}`);

    expect(await screen.findByTestId("opened-finding")).toHaveTextContent(LINKED_ID);
  });

  it("opens nothing when the only search hit is another finding that merely mentions the id", async () => {
    getFindingsMock.mockImplementation(async (_scanId: string, params: { search?: string }) =>
      params.search === LINKED_ID ? envelope([{ id: "lodash:4.17.20", description: `See ${LINKED_ID}` }]) : envelope([]),
    );

    renderAt(`/?finding=${LINKED_ID}`);

    await waitFor(() => expect(toast.warning).toHaveBeenCalled());
    expect(screen.queryByTestId("opened-finding")).not.toBeInTheDocument();
  });

  it("opens the finding once on a page that also lists the waived findings", async () => {
    getFindingsMock.mockImplementation(async (_scanId: string, params: { search?: string }) =>
      params.search === LINKED_ID ? envelope([{ id: LINKED_ID }]) : envelope([]),
    );
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });

    render(
      <QueryClientProvider client={client}>
        <MemoryRouter initialEntries={[`/?finding=${LINKED_ID}`]}>
          <FindingsTable scanId="s1" projectId="p1" />
          <FindingsTable scanId="s1" projectId="p1" waivedFilter="waived" />
        </MemoryRouter>
      </QueryClientProvider>,
    );

    expect(await screen.findByTestId("opened-finding")).toHaveTextContent(LINKED_ID);
    await waitFor(() => expect(screen.getAllByTestId("opened-finding")).toHaveLength(1));
    const searches = getFindingsMock.mock.calls.filter(([, params]) => params.search === LINKED_ID);
    expect(searches).toHaveLength(1);
  });
});
