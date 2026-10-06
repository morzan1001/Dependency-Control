import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { act, renderHook, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider, useQuery } from "@tanstack/react-query";
import type { ReactNode } from "react";

import { scanApi } from "@/api/scans";
import type { ScanWithReleases } from "@/types/scan";
import {
  SCAN_WINDOW_PAGE_SIZE,
  useProjectScanWindow,
  useProjectScans,
  useRecentScans,
  useScan,
  useScanStats,
} from "../use-scans";

vi.mock("@/api/scans", () => ({
  scanApi: { getProjectScans: vi.fn(), getRecent: vi.fn(), getOne: vi.fn(), getStats: vi.fn(), getFindings: vi.fn() },
}));

const PROJECT_ID = "p1";
const TRI_STATE_COUNT = 3;
const SCAN_ID = "s1";
const RESCAN_ID = "r1";
const POLL_WAIT_MS = 10_000;
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

function scanIn(status: string): ScanWithReleases {
  return { id: SCAN_ID, project_id: PROJECT_ID, branch: BRANCH, created_at: CREATED_AT, status, releases: [] };
}

// The scan page: the scan itself, its category stats, and the findings table under its own key.
function renderScanPage(client: QueryClient) {
  const wrapper = ({ children }: { children: ReactNode }) => (
    <QueryClientProvider client={client}>{children}</QueryClientProvider>
  );
  return renderHook(
    () => ({
      scan: useScan(SCAN_ID),
      stats: useScanStats(SCAN_ID),
      findings: useQuery({
        queryKey: ["findings", SCAN_ID, "security"],
        queryFn: () => scanApi.getFindings(SCAN_ID, {}),
      }),
    }),
    { wrapper },
  );
}

describe("useScan while the scan is being analysed", () => {
  const FINDINGS_AFTER_ANALYSIS = 7;

  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers({ shouldAdvanceTime: true });
    vi.mocked(scanApi.getStats).mockResolvedValueOnce({ security: 0 }).mockResolvedValue({ security: 3 });
    vi.mocked(scanApi.getFindings)
      .mockResolvedValueOnce({ items: [], total: 0, page: 1, size: 50, pages: 0 })
      .mockResolvedValue({ items: [], total: FINDINGS_AFTER_ANALYSIS, page: 1, size: 50, pages: 1 });
  });

  afterEach(() => vi.useRealTimers());

  it("polls a running scan until it finishes", async () => {
    vi.mocked(scanApi.getOne).mockResolvedValueOnce(scanIn("processing")).mockResolvedValue(scanIn("completed"));
    const { result } = renderScanPage(new QueryClient({ defaultOptions: { queries: { retry: false } } }));

    await waitFor(() => expect(result.current.scan.data?.status).toBe("processing"));
    await act(() => vi.advanceTimersByTimeAsync(POLL_WAIT_MS));

    await waitFor(() => expect(result.current.scan.data?.status).toBe("completed"));
  });

  it("refreshes what the page shows about the scan once it finishes", async () => {
    vi.mocked(scanApi.getOne).mockResolvedValueOnce(scanIn("pending")).mockResolvedValue(scanIn("completed"));
    const { result } = renderScanPage(new QueryClient({ defaultOptions: { queries: { retry: false } } }));

    await waitFor(() => expect(result.current.stats.data?.security).toBe(0));
    await act(() => vi.advanceTimersByTimeAsync(POLL_WAIT_MS));

    await waitFor(() => expect(result.current.stats.data?.security).toBe(3));
    await waitFor(() => expect(result.current.findings.data?.total).toBe(FINDINGS_AFTER_ANALYSIS));
  });

  it("stops polling once the scan has finished", async () => {
    vi.mocked(scanApi.getOne).mockResolvedValueOnce(scanIn("processing")).mockResolvedValue(scanIn("completed"));
    const { result } = renderScanPage(new QueryClient({ defaultOptions: { queries: { retry: false } } }));

    await waitFor(() => expect(result.current.scan.data?.status).toBe("processing"));
    await act(() => vi.advanceTimersByTimeAsync(POLL_WAIT_MS));
    await waitFor(() => expect(result.current.scan.data?.status).toBe("completed"));
    const settled = vi.mocked(scanApi.getOne).mock.calls.length;

    await act(() => vi.advanceTimersByTimeAsync(6 * POLL_WAIT_MS));

    expect(scanApi.getOne).toHaveBeenCalledTimes(settled);
  });

  it("does not poll a scan that is already analysed", async () => {
    vi.mocked(scanApi.getOne).mockResolvedValue(scanIn("completed"));
    const { result } = renderScanPage(new QueryClient({ defaultOptions: { queries: { retry: false } } }));

    await waitFor(() => expect(result.current.scan.data?.status).toBe("completed"));
    await act(() => vi.advanceTimersByTimeAsync(6 * POLL_WAIT_MS));

    expect(scanApi.getOne).toHaveBeenCalledTimes(1);
  });
});

const LIST_HOOKS = [
  { name: "useProjectScans", useList: () => useProjectScans(PROJECT_ID), fetchList: () => vi.mocked(scanApi.getProjectScans) },
  { name: "useRecentScans", useList: useRecentScans, fetchList: () => vi.mocked(scanApi.getRecent) },
];

describe.each(LIST_HOOKS)("$name while a listed scan is being analysed", ({ useList, fetchList }) => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.useFakeTimers({ shouldAdvanceTime: true });
  });

  afterEach(() => vi.useRealTimers());

  function renderList() {
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const wrapper = ({ children }: { children: ReactNode }) => (
      <QueryClientProvider client={client}>{children}</QueryClientProvider>
    );
    return renderHook(useList, { wrapper });
  }

  it("polls a running scan until it finishes", async () => {
    fetchList().mockResolvedValueOnce([scanIn("processing")]).mockResolvedValue([scanIn("completed")]);
    const { result } = renderList();

    await waitFor(() => expect(result.current.data?.[0].status).toBe("processing"));
    await act(() => vi.advanceTimersByTimeAsync(POLL_WAIT_MS));

    await waitFor(() => expect(result.current.data?.[0].status).toBe("completed"));
  });

  it("polls a finished scan while its rescan is queued", async () => {
    const withRescan = (status: string) => ({ ...scanIn("completed"), latest_run: { scan_id: RESCAN_ID, status } });
    fetchList().mockResolvedValueOnce([withRescan("pending")]).mockResolvedValue([withRescan("completed")]);
    const { result } = renderList();

    await waitFor(() => expect(result.current.data?.[0].latest_run?.status).toBe("pending"));
    await act(() => vi.advanceTimersByTimeAsync(POLL_WAIT_MS));

    await waitFor(() => expect(result.current.data?.[0].latest_run?.status).toBe("completed"));
  });

  it("does not poll a list with nothing being analysed", async () => {
    fetchList().mockResolvedValue([scanIn("completed")]);
    const { result } = renderList();

    await waitFor(() => expect(result.current.data).toBeDefined());
    await act(() => vi.advanceTimersByTimeAsync(6 * POLL_WAIT_MS));

    expect(fetchList()).toHaveBeenCalledTimes(1);
  });
});
