import { render, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { FindingsTable } from "../FindingsTable";

vi.mock("@/api/scans", () => ({
  scanApi: { getFindings: vi.fn() },
}));

import { scanApi } from "@/api/scans";

const getFindingsMock = scanApi.getFindings as ReturnType<typeof vi.fn>;

function renderWithProviders(node: React.ReactElement) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, staleTime: Infinity } },
  });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>{node}</MemoryRouter>
    </QueryClientProvider>,
  );
}

const emptyEnvelope = { items: [], total: 0, page: 1, size: 50, pages: 1 };

describe("FindingsTable direct-only filter", () => {
  beforeEach(() => {
    getFindingsMock.mockReset();
    getFindingsMock.mockResolvedValue(emptyEnvelope);
  });

  it("sends direct_only=true when the directOnly prop is set", async () => {
    renderWithProviders(<FindingsTable scanId="s1" projectId="p1" directOnly />);
    await waitFor(() => expect(getFindingsMock).toHaveBeenCalled());
    const [, params] = getFindingsMock.mock.calls[0];
    expect((params as Record<string, unknown>).direct_only).toBe(true);
  });

  it("omits direct_only by default so transitive findings stay visible", async () => {
    renderWithProviders(<FindingsTable scanId="s1" projectId="p1" />);
    await waitFor(() => expect(getFindingsMock).toHaveBeenCalled());
    const [, params] = getFindingsMock.mock.calls[0];
    expect((params as Record<string, unknown>).direct_only).toBeUndefined();
  });
});
