import { describe, it, expect, vi } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";

import { teamApi } from "@/api/teams";
import type { Team } from "@/types/team";
import { useTeamNameTaken, useTeams } from "../use-teams";

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

describe("useTeamNameTaken", () => {
  it("flags a name another visible team holds, whatever its case and surrounding spaces", async () => {
    vi.mocked(teamApi.getAll).mockResolvedValue([{ id: "t2", name: "Platform" }] as Team[]);

    const { result } = renderHook(() => useTeamNameTaken(" PLATFORM "), { wrapper: makeWrapper() });

    await waitFor(() => expect(result.current).toBe(true));
    expect(teamApi.getAll).toHaveBeenLastCalledWith("PLATFORM", "name", "asc");
  });

  it("does not flag the team being renamed, nor a longer name that holds this one", async () => {
    vi.mocked(teamApi.getAll).mockResolvedValue([
      { id: "t1", name: "Platform" },
      { id: "t3", name: "Platform EU" },
    ] as Team[]);

    const { result } = renderHook(
      () => ({
        renamed: useTeamNameTaken("platform", { id: "t1", name: "Platform" }),
        other: useTeamNameTaken("platform", { id: "t2", name: "Core" }),
      }),
      { wrapper: makeWrapper() },
    );

    await waitFor(() => expect(result.current.other).toBe(true));
    expect(result.current.renamed).toBe(false);
  });

  it("asks nothing while the team keeps its name", () => {
    vi.mocked(teamApi.getAll).mockClear();

    const { result } = renderHook(() => useTeamNameTaken("Platform", { id: "t1", name: "Platform" }), {
      wrapper: makeWrapper(),
    });

    expect(result.current).toBe(false);
    expect(teamApi.getAll).not.toHaveBeenCalled();
  });

  it("asks nothing for an empty name", () => {
    vi.mocked(teamApi.getAll).mockClear();

    const { result } = renderHook(() => useTeamNameTaken(""), { wrapper: makeWrapper() });

    expect(result.current).toBe(false);
    expect(teamApi.getAll).not.toHaveBeenCalled();
  });
});
