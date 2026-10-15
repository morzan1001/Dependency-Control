import { describe, it, expect, vi } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";

import { teamApi } from "@/api/teams";
import type { Team } from "@/types/team";
import { useTeams } from "../use-teams";

vi.mock("@/api/teams", () => ({ teamApi: { getAll: vi.fn() } }));

// One client across rerenders: a client per render would drop the cache the hook keeps.
function makeWrapper() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return ({ children }: { children: ReactNode }) => <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}

describe("useTeams", () => {
  it("keeps the last list while the next search is loading, so the page does not fall back to a skeleton", async () => {
    const firstPage = [{ id: "t1", name: "Payments" }] as Team[];
    vi.mocked(teamApi.getAll).mockResolvedValueOnce(firstPage).mockReturnValueOnce(new Promise(() => {}));

    const { result, rerender } = renderHook(({ search }) => useTeams(search), {
      wrapper: makeWrapper(),
      initialProps: { search: "" },
    });
    await waitFor(() => expect(result.current.data).toEqual(firstPage));

    rerender({ search: "pay" });

    await waitFor(() => expect(teamApi.getAll).toHaveBeenCalledTimes(2));
    expect(result.current.isLoading).toBe(false);
    expect(result.current.data).toEqual(firstPage);
  });
});
