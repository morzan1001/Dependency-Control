import { fireEvent, render, screen, waitFor } from "@testing-library/react";
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

describe("FindingsTable severity filter", () => {
  beforeEach(() => {
    getFindingsMock.mockReset();
    getFindingsMock.mockResolvedValue(emptyEnvelope);
  });

  it("asks the API for the findings of the requested severity only", async () => {
    renderWithProviders(<FindingsTable scanId="s1" projectId="p1" severity="CRITICAL" />);
    await waitFor(() => expect(getFindingsMock).toHaveBeenCalled());
    const [, params] = getFindingsMock.mock.calls[0];
    expect((params as Record<string, unknown>).severity).toBe("CRITICAL");
  });
});

describe("FindingsTable sorting", () => {
  const finding = { id: "CVE-1", type: "vulnerability", severity: "HIGH", component: "lodash", version: "4.17.20", scanners: [] };

  beforeEach(() => {
    getFindingsMock.mockReset();
    getFindingsMock.mockResolvedValue({ ...emptyEnvelope, items: [finding], total: 1 });
  });

  const lastSort = () => {
    const params = getFindingsMock.mock.calls[getFindingsMock.mock.calls.length - 1][1] as Record<string, unknown>;
    return [params.sort_by, params.sort_order];
  };

  it("asks for the most severe findings first, then sorts a clicked column descending and flips it", async () => {
    renderWithProviders(<FindingsTable scanId="s1" projectId="p1" />);
    await screen.findByText("lodash");
    expect(lastSort()).toEqual(["severity", "desc"]);

    fireEvent.click(screen.getByRole("columnheader", { name: "Component" }));
    await waitFor(() => expect(lastSort()).toEqual(["component", "desc"]));

    await screen.findByText("lodash");
    fireEvent.click(screen.getByRole("columnheader", { name: "Component" }));
    await waitFor(() => expect(lastSort()).toEqual(["component", "asc"]));
  });
});
