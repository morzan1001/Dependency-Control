import { describe, it, expect, vi, beforeEach } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";

import { scanApi } from "@/api/scans";
import { useProjectScans } from "../use-scans";

vi.mock("@/api/scans", () => ({
  scanApi: { getProjectScans: vi.fn() },
}));

const PROJECT_ID = "p1";
const TRI_STATE_COUNT = 3;

function renderFilter(client: QueryClient, isRelease?: boolean) {
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}>{children}</QueryClientProvider>
  );
  return renderHook(() => useProjectScans(PROJECT_ID, { isRelease }), { wrapper });
}

describe("useProjectScans release filter", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(scanApi.getProjectScans).mockResolvedValue([]);
  });

  it("gives each tri-state of the release filter its own cache entry", async () => {
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });

    renderFilter(client, true);
    renderFilter(client, false);
    renderFilter(client);

    await waitFor(() =>
      expect(client.getQueryCache().getAll()).toHaveLength(TRI_STATE_COUNT),
    );
  });

  it("asks the server for the state the caller selected", async () => {
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });

    renderFilter(client, false);

    await waitFor(() => expect(scanApi.getProjectScans).toHaveBeenCalled());
    expect(vi.mocked(scanApi.getProjectScans).mock.calls[0][1]?.isRelease).toBe(false);
  });
});
