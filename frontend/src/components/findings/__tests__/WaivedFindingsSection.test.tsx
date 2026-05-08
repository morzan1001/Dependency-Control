import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { WaivedFindingsSection } from "../WaivedFindingsSection";

vi.mock("@/api/scans", () => {
  return {
    scanApi: {
      getFindings: vi.fn(),
    },
  };
});

import { scanApi } from "@/api/scans";

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

const baseEnvelope = (overrides: Partial<{ items: unknown[]; total: number }>) => ({
  items: [],
  total: 0,
  page: 1,
  size: 1,
  pages: 1,
  ...overrides,
});

describe("WaivedFindingsSection", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("renders nothing when there are no waived findings in this category", async () => {
    (scanApi.getFindings as ReturnType<typeof vi.fn>).mockResolvedValue(baseEnvelope({ total: 0 }));

    const { container } = renderWithProviders(
      <WaivedFindingsSection scanId="s1" projectId="p1" category="security" />,
    );

    // The probe call settles first; section then decides to render nothing.
    await waitFor(() => {
      expect(scanApi.getFindings).toHaveBeenCalled();
    });
    expect(container).toBeEmptyDOMElement();
  });

  it("renders a 'Waived findings' header when there are waived findings", async () => {
    (scanApi.getFindings as ReturnType<typeof vi.fn>).mockResolvedValue(baseEnvelope({ total: 3 }));

    renderWithProviders(<WaivedFindingsSection scanId="s1" projectId="p1" category="security" />);

    expect(await screen.findByText(/Waived findings/i)).toBeInTheDocument();
    // The count is exposed for transparency.
    expect(screen.getByText(/\b3\b/)).toBeInTheDocument();
  });

  it("requests with waived=true and the supplied category filter", async () => {
    (scanApi.getFindings as ReturnType<typeof vi.fn>).mockResolvedValue(baseEnvelope({ total: 0 }));

    renderWithProviders(
      <WaivedFindingsSection scanId="s1" projectId="p1" category="security" />,
    );

    await waitFor(() => {
      expect(scanApi.getFindings).toHaveBeenCalled();
    });
    const probeCall = (scanApi.getFindings as ReturnType<typeof vi.fn>).mock.calls.find(
      ([, params]) => (params as Record<string, unknown>).limit === 1,
    );
    expect(probeCall).toBeDefined();
    const [scanIdArg, paramsArg] = probeCall!;
    expect(scanIdArg).toBe("s1");
    expect((paramsArg as Record<string, unknown>).waived).toBe(true);
    expect((paramsArg as Record<string, unknown>).category).toBe("security");
  });
});
