import { describe, it, expect, vi, beforeEach } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";

import { releaseApi } from "@/api/releases";
import { SMALL_PAGE_SIZE } from "@/lib/constants";
import { analyticsKeys } from "../use-analytics";
import { scanKeys } from "../use-scans";
import { releaseKeys, useMarkRelease, useProjectReleases, useUnmarkRelease } from "../use-releases";

vi.mock("@/api/releases", () => ({
  releaseApi: { list: vi.fn(), mark: vi.fn(), unmark: vi.fn() },
}));

const PROJECT_ID = "p1";
const SCAN_ID = "s1";
const STAGING = "staging";
const PRODUCTION = "production";
const COMMIT_HASH = "abc";
const DISTINCT_SCOPE_COUNT = 3;
const DISTINCT_LIMIT_COUNT = 2;
const LATEST_ONLY_LIMIT = 1;
const NO_ENVIRONMENT_FILTER = undefined;
const FIRST_PAGE = 1;
const SINGLE_ITEM_TOTAL = 1;
const RELEASED_AT = "2026-09-04T00:00:00Z";
const BRANCH = "main";
const SCAN_STATUS_COMPLETED = "completed";

function makeClient() {
  return new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
}

function wrapperFor(client: QueryClient) {
  return ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}>{children}</QueryClientProvider>
  );
}

describe("useProjectReleases", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(releaseApi.list).mockResolvedValue({
      items: [],
      total: 0,
      page: FIRST_PAGE,
      size: SMALL_PAGE_SIZE,
    });
  });

  it("caches each environment apart from the unfiltered list", async () => {
    const client = makeClient();
    const wrapper = wrapperFor(client);

    renderHook(() => useProjectReleases(PROJECT_ID, STAGING), { wrapper });
    renderHook(() => useProjectReleases(PROJECT_ID, PRODUCTION), { wrapper });
    renderHook(() => useProjectReleases(PROJECT_ID), { wrapper });

    await waitFor(() =>
      expect(client.getQueryCache().getAll()).toHaveLength(DISTINCT_SCOPE_COUNT),
    );
  });

  it("asks the endpoint for only as many releases as the caller needs", async () => {
    const { result } = renderHook(
      () => useProjectReleases(PROJECT_ID, NO_ENVIRONMENT_FILTER, LATEST_ONLY_LIMIT),
      { wrapper: wrapperFor(makeClient()) },
    );

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(releaseApi.list).toHaveBeenCalledWith(PROJECT_ID, {
      environment: NO_ENVIRONMENT_FILTER,
      limit: LATEST_ONLY_LIMIT,
    });
  });

  it("caches a narrowed page apart from the default one", async () => {
    const client = makeClient();
    const wrapper = wrapperFor(client);

    renderHook(() => useProjectReleases(PROJECT_ID), { wrapper });
    renderHook(() => useProjectReleases(PROJECT_ID, NO_ENVIRONMENT_FILTER, LATEST_ONLY_LIMIT), { wrapper });

    await waitFor(() => expect(client.getQueryCache().getAll()).toHaveLength(DISTINCT_LIMIT_COUNT));
  });

  it("keeps a release whose scan retention removed", async () => {
    vi.mocked(releaseApi.list).mockResolvedValue({
      items: [
        {
          scan_id: SCAN_ID,
          project_id: PROJECT_ID,
          environment: PRODUCTION,
          version: null,
          released_at: RELEASED_AT,
          commit_hash: null,
          branch: null,
          scan_status: null,
          analysis_scan_id: null,
        },
      ],
      total: SINGLE_ITEM_TOTAL,
      page: FIRST_PAGE,
      size: SMALL_PAGE_SIZE,
    });

    const { result } = renderHook(() => useProjectReleases(PROJECT_ID), {
      wrapper: wrapperFor(makeClient()),
    });

    await waitFor(() => expect(result.current.data?.items).toHaveLength(SINGLE_ITEM_TOTAL));
    expect(result.current.data?.items[0].branch).toBeNull();
  });
});

describe("release mutations", () => {
  beforeEach(() => vi.clearAllMocks());

  it("marking refreshes the releases, the scans and the analytics that read them", async () => {
    const client = makeClient();
    vi.mocked(releaseApi.mark).mockResolvedValue({
      scan_id: SCAN_ID,
      project_id: PROJECT_ID,
      environment: PRODUCTION,
      version: null,
      released_at: RELEASED_AT,
      commit_hash: COMMIT_HASH,
      branch: BRANCH,
      scan_status: SCAN_STATUS_COMPLETED,
      analysis_scan_id: SCAN_ID,
    });
    const invalidate = vi.spyOn(client, "invalidateQueries");

    const { result } = renderHook(() => useMarkRelease(), { wrapper: wrapperFor(client) });
    result.current.mutate({ projectId: PROJECT_ID, payload: { commit_hash: COMMIT_HASH } });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(invalidate).toHaveBeenCalledWith({ queryKey: releaseKeys.project(PROJECT_ID) });
    expect(invalidate).toHaveBeenCalledWith({ queryKey: scanKeys.project(PROJECT_ID) });
    expect(invalidate).toHaveBeenCalledWith({ queryKey: scanKeys.details() });
    expect(invalidate).toHaveBeenCalledWith({ queryKey: analyticsKeys.all });
  });

  it("withdrawing passes the environment on to the api", async () => {
    const client = makeClient();
    vi.mocked(releaseApi.unmark).mockResolvedValue({
      scan_id: SCAN_ID,
      environment: STAGING,
      is_release: true,
      remaining_environments: [PRODUCTION],
    });

    const { result } = renderHook(() => useUnmarkRelease(), { wrapper: wrapperFor(client) });
    result.current.mutate({ projectId: PROJECT_ID, scanId: SCAN_ID, environment: STAGING });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(releaseApi.unmark).toHaveBeenCalledWith(PROJECT_ID, SCAN_ID, STAGING);
  });
});
