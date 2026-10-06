import { describe, it, expect, vi, beforeEach } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";

import { waiverApi } from "@/api/waivers";
import { useProjectWaivers } from "../use-waivers";

vi.mock("@/api/waivers", () => ({
  waiverApi: { getByProject: vi.fn(), getAll: vi.fn() },
}));

const getByProject = vi.mocked(waiverApi.getByProject);
const emptyPage = { items: [], total: 0, page: 1, size: 50, pages: 1 };

function wrapper({ children }: { children: ReactNode }) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe("useProjectWaivers", () => {
  it("asks for the unexpired waivers only when told to", async () => {
    getByProject.mockResolvedValue(emptyPage);

    const { result } = renderHook(() => useProjectWaivers("p1", { active: true }), { wrapper });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(getByProject).toHaveBeenCalledWith("p1", expect.objectContaining({ active: true }));
  });
});
