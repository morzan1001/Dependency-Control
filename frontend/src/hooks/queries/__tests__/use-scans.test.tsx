import { describe, it, expect, vi, beforeEach } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";

import { scanApi } from "@/api/scans";
import type { ScanWithReleases } from "@/types/scan";
import { SCAN_WINDOW_PAGE_SIZE, useProjectScanWindow, useProjectScans } from "../use-scans";

vi.mock("@/api/scans", () => ({
  scanApi: { getProjectScans: vi.fn() },
}));

const PROJECT_ID = "p1";
const TRI_STATE_COUNT = 3;
const SCAN_ID = "s1";
const BRANCH = "main";
const CREATED_AT = "2026-09-04T00:00:00Z";
const RELEASED_AT = "2026-09-04T01:00:00Z";
const SCAN_STATUS_COMPLETED = "completed";
const STAGING = "staging";
const PRODUCTION = "production";
const STAGING_VERSION = "v1.3.0-rc1";
const RELEASE_ENVIRONMENT_COUNT = 2;

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

  it("hands the caller every environment the server attached to a scan", async () => {
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    vi.mocked(scanApi.getProjectScans).mockResolvedValue([
      {
        id: SCAN_ID,
        project_id: PROJECT_ID,
        branch: BRANCH,
        created_at: CREATED_AT,
        status: SCAN_STATUS_COMPLETED,
        is_release: true,
        releases: [
          { environment: STAGING, version: STAGING_VERSION, released_at: RELEASED_AT },
          { environment: PRODUCTION, version: null, released_at: RELEASED_AT },
        ],
      },
    ]);

    const { result } = renderFilter(client, true);

    await waitFor(() => expect(result.current.data).toBeDefined());
    expect(result.current.data?.[0].releases).toHaveLength(RELEASE_ENVIRONMENT_COUNT);
    expect(result.current.data?.[0].releases[0].environment).toBe(STAGING);
  });
});

function scanPage(size: number): ScanWithReleases[] {
  return Array.from({ length: size }, (_, index) => ({
    id: `s${index}`,
    project_id: PROJECT_ID,
    branch: BRANCH,
    created_at: CREATED_AT,
    status: SCAN_STATUS_COMPLETED,
    releases: [],
  }));
}

function renderWindow(client: QueryClient, pages: number) {
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}>{children}</QueryClientProvider>
  );
  return renderHook(() => useProjectScanWindow(PROJECT_ID, pages), { wrapper });
}

describe("useProjectScanWindow", () => {
  beforeEach(() => vi.clearAllMocks());

  it("reports the window as incomplete while a full page came back", async () => {
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    vi.mocked(scanApi.getProjectScans).mockResolvedValue(scanPage(SCAN_WINDOW_PAGE_SIZE));

    const { result } = renderWindow(client, 1);

    await waitFor(() => expect(result.current.data).toBeDefined());
    expect(result.current.data?.complete).toBe(false);
    expect(result.current.data?.scans).toHaveLength(SCAN_WINDOW_PAGE_SIZE);
  });

  it("reports the window as complete once a short page ends it", async () => {
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    vi.mocked(scanApi.getProjectScans).mockResolvedValue(scanPage(SCAN_WINDOW_PAGE_SIZE - 1));

    const { result } = renderWindow(client, 1);

    await waitFor(() => expect(result.current.data).toBeDefined());
    expect(result.current.data?.complete).toBe(true);
  });

  it("reads one page per requested page and skips past the ones already read", async () => {
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    vi.mocked(scanApi.getProjectScans).mockResolvedValue(scanPage(SCAN_WINDOW_PAGE_SIZE));

    const { result } = renderWindow(client, 2);

    await waitFor(() => expect(result.current.data).toBeDefined());
    expect(result.current.data?.scans).toHaveLength(SCAN_WINDOW_PAGE_SIZE * 2);
    const skips = vi.mocked(scanApi.getProjectScans).mock.calls.map((call) => call[1]?.skip);
    expect(skips).toEqual([0, SCAN_WINDOW_PAGE_SIZE]);
  });
});
