import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { renderHook, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";

import { githubInstancesApi } from "@/api/github-instances";
import { gitlabInstancesApi } from "@/api/gitlab-instances";
import { githubInstanceKeys, gitlabInstanceKeys, useGitHubInstances, useGitLabInstances } from "../use-instances";

vi.mock("@/api/gitlab-instances", () => ({ gitlabInstancesApi: { list: vi.fn() } }));
vi.mock("@/api/github-instances", () => ({ githubInstancesApi: { list: vi.fn() } }));

describe("instance listings", () => {
  it.each([
    ["gitlab-instances", () => useGitLabInstances({ active_only: true }), gitlabInstancesApi.list, gitlabInstanceKeys.all],
    ["github-instances", () => useGitHubInstances({ active_only: true }), githubInstancesApi.list, githubInstanceKeys.all],
  ] as const)("lists %s under its prefix, so invalidating the prefix refetches it", async (prefix, useListing, list, all) => {
    vi.mocked(list).mockReset().mockResolvedValue({ items: [], total: 0, page: 1, size: 50, pages: 0 } as never);
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const wrapper = ({ children }: { children: ReactNode }) => <QueryClientProvider client={qc}>{children}</QueryClientProvider>;

    const { result } = renderHook(() => useListing().isSuccess, { wrapper });
    await waitFor(() => expect(result.current).toBe(true));

    expect(list).toHaveBeenCalledWith({ active_only: true });
    expect(qc.getQueryCache().find({ queryKey: [prefix, { active_only: true }], exact: true })).toBeDefined();
    await qc.invalidateQueries({ queryKey: all });
    expect(list).toHaveBeenCalledTimes(2);
  });
});
