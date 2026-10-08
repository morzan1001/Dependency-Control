import { render, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { describe, it, expect, vi } from "vitest";
import { AnalyticsDependencyModal } from "../AnalyticsDependencyModal";

vi.mock("@/api/analytics", () => ({
  analyticsApi: { getComponentFindings: vi.fn(), getDependencyMetadata: vi.fn() },
}));

import { analyticsApi } from "@/api/analytics";

describe("AnalyticsDependencyModal reopened", () => {
  it("serves the same component from cache instead of re-running its estate-wide queries", async () => {
    vi.mocked(analyticsApi.getComponentFindings).mockResolvedValue({ items: [], total: 0 });
    vi.mocked(analyticsApi.getDependencyMetadata).mockResolvedValue(null);
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const modal = (open: boolean) => (
      <QueryClientProvider client={client}>
        <MemoryRouter>
          <AnalyticsDependencyModal component="lodash" version="4.17.20" open={open} onOpenChange={() => {}} />
        </MemoryRouter>
      </QueryClientProvider>
    );

    const { rerender } = render(modal(true));
    await waitFor(() => expect(analyticsApi.getComponentFindings).toHaveBeenCalledTimes(1));
    await waitFor(() => expect(analyticsApi.getDependencyMetadata).toHaveBeenCalledTimes(1));
    rerender(modal(false));
    rerender(modal(true));
    await new Promise((resolve) => setTimeout(resolve, 20));

    expect(analyticsApi.getComponentFindings).toHaveBeenCalledTimes(1);
    expect(analyticsApi.getDependencyMetadata).toHaveBeenCalledTimes(1);
  });
});
