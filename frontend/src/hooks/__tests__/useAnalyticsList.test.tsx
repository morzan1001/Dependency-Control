import { describe, it, expect } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";

import { useAnalyticsList } from "../useAnalyticsList";

function wrapper({ children }: { children: ReactNode }) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return <QueryClientProvider client={qc}>{children}</QueryClientProvider>;
}

interface Resp {
  items: Array<{ id: string }>;
}

describe("useAnalyticsList", () => {
  it("loads items and exposes isEmpty=false", async () => {
    const { result } = renderHook(
      () =>
        useAnalyticsList<Resp, { id: string }>({
          queryKey: ["t1"],
          queryFn: async () => ({ items: [{ id: "a" }, { id: "b" }] }),
          selectItems: (r) => r.items,
        }),
      { wrapper },
    );

    await waitFor(() => expect(result.current.isLoading).toBe(false));
    expect(result.current.items).toHaveLength(2);
    expect(result.current.isEmpty).toBe(false);
  });

  it("reports isEmpty=true when the response contains no items", async () => {
    const { result } = renderHook(
      () =>
        useAnalyticsList<Resp, { id: string }>({
          queryKey: ["t2"],
          queryFn: async () => ({ items: [] }),
          selectItems: (r) => r.items,
        }),
      { wrapper },
    );

    await waitFor(() => expect(result.current.isLoading).toBe(false));
    expect(result.current.isEmpty).toBe(true);
  });

  it("surfaces errors via the error field", async () => {
    const { result } = renderHook(
      () =>
        useAnalyticsList<Resp, { id: string }>({
          queryKey: ["t3"],
          queryFn: async () => {
            throw new Error("boom");
          },
          selectItems: (r) => r.items,
        }),
      { wrapper },
    );

    await waitFor(() => expect(result.current.error).not.toBeNull());
    expect(result.current.error?.message).toBe("boom");
  });
});
