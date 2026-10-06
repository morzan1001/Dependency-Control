import { describe, it, expect, vi, beforeEach } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";

import { waiverApi } from "@/api/waivers";
import { useGlobalWaivers, useProjectWaivers } from "../use-waivers";

vi.mock("@/api/waivers", () => ({
  waiverApi: { getByProject: vi.fn(), getAll: vi.fn() },
}));

const getByProject = vi.mocked(waiverApi.getByProject);
const emptyPage = { items: [], total: 0, page: 1, size: 50, pages: 1 };

// One client across rerenders: a client per render would drop the cache the hook keeps.
function makeWrapper() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return ({ children }: { children: ReactNode }) => <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe("useProjectWaivers", () => {
  it("asks for the unexpired waivers only when told to", async () => {
    getByProject.mockResolvedValue(emptyPage);

    const { result } = renderHook(() => useProjectWaivers("p1", { active: true }), { wrapper: makeWrapper() });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(getByProject).toHaveBeenCalledWith("p1", expect.objectContaining({ active: true }));
  });
});

describe("useGlobalWaivers", () => {
  it("keeps the last page while the next search is loading, so the page does not fall back to a skeleton", async () => {
    const firstPage = { items: [], total: 3, page: 1, size: 50, pages: 1 };
    vi.mocked(waiverApi.getAll).mockResolvedValueOnce(firstPage).mockReturnValueOnce(new Promise(() => {}));

    const { result, rerender } = renderHook(({ search }) => useGlobalWaivers({ search }), {
      wrapper: makeWrapper(),
      initialProps: { search: "" },
    });
    await waitFor(() => expect(result.current.data?.pages[0]).toEqual(firstPage));

    rerender({ search: "lodash" });

    await waitFor(() => expect(waiverApi.getAll).toHaveBeenCalledTimes(2));
    expect(result.current.isLoading).toBe(false);
    expect(result.current.data?.pages[0]).toEqual(firstPage);
  });
});
