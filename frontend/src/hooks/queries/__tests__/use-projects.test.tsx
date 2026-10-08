import { describe, it, expect, vi, beforeEach } from "vitest";
import { act, renderHook, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";

import { projectApi } from "@/api/projects";
import { useProjectArchives, useProjectsDropdown, useRestoreArchive } from "../use-projects";
import { DROPDOWN_PAGE_SIZE } from "@/lib/constants";
import type { ProjectsResponse } from "@/types/project";

vi.mock("@/api/projects", () => ({
  projectApi: {
    getAll: vi.fn(),
    getArchives: vi.fn(),
    restoreArchive: vi.fn(),
  },
}));

function wrapper({ children }: { children: ReactNode }) {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return <QueryClientProvider client={qc}>{children}</QueryClientProvider>;
}

function makePage(skip: number, count: number, total: number): ProjectsResponse {
  return {
    items: Array.from({ length: count }, (_, i) => ({
      id: `p${skip + i}`,
      name: `project-${skip + i}`,
    })) as ProjectsResponse["items"],
    total,
    page: Math.floor(skip / DROPDOWN_PAGE_SIZE) + 1,
    size: DROPDOWN_PAGE_SIZE,
    pages: Math.ceil(total / DROPDOWN_PAGE_SIZE),
  };
}

describe("useProjectsDropdown", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("fetches every project across pages instead of truncating to the first page", async () => {
    const total = 120; // more than one DROPDOWN_PAGE_SIZE page
    const mock = vi.mocked(projectApi.getAll);
    mock.mockImplementation(async (_search, skip = 0) => {
      const remaining = total - (skip as number);
      const count = Math.min(DROPDOWN_PAGE_SIZE, remaining);
      return makePage(skip as number, count, total);
    });

    const { result } = renderHook(() => useProjectsDropdown(), { wrapper });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));

    expect(result.current.data?.items).toHaveLength(total);
    expect(result.current.data?.total).toBe(total);
    expect(mock).toHaveBeenCalledTimes(2);
  });

  it("requests the remaining pages together instead of one after another", async () => {
    const total = 3 * DROPDOWN_PAGE_SIZE - 10;
    const mock = vi.mocked(projectApi.getAll);
    const held: Array<() => void> = [];
    mock.mockImplementation((_search, skip = 0) => {
      const page = makePage(skip as number, Math.min(DROPDOWN_PAGE_SIZE, total - (skip as number)), total);
      if (skip === 0) return Promise.resolve(page);
      return new Promise((resolve) => held.push(() => resolve(page)));
    });

    const { result } = renderHook(() => useProjectsDropdown(), { wrapper });

    await waitFor(() => expect(mock).toHaveBeenCalledTimes(3));
    held.forEach((release) => release());
    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(result.current.data?.items.map((p) => p.id)).toEqual(Array.from({ length: total }, (_, i) => `p${i}`));
  });

  it("makes a single request when all projects fit in one page", async () => {
    const mock = vi.mocked(projectApi.getAll);
    mock.mockResolvedValue(makePage(0, 10, 10));

    const { result } = renderHook(() => useProjectsDropdown(), { wrapper });

    await waitFor(() => expect(result.current.isSuccess).toBe(true));

    expect(result.current.data?.items).toHaveLength(10);
    expect(mock).toHaveBeenCalledTimes(1);
  });
});

describe("useRestoreArchive", () => {
  it("refetches the project's archive list once a restore succeeds", async () => {
    vi.mocked(projectApi.getArchives).mockResolvedValue({ items: [], total: 0, page: 1, size: 20, pages: 1 });
    vi.mocked(projectApi.restoreArchive).mockResolvedValue({
      scan_id: "s1", project_id: "p1", message: "Restored", collections_restored: [],
    });

    const { result } = renderHook(
      () => ({ archives: useProjectArchives("p1"), restore: useRestoreArchive() }),
      { wrapper },
    );
    await waitFor(() => expect(result.current.archives.isSuccess).toBe(true));
    await act(() => result.current.restore.mutateAsync({ projectId: "p1", scanId: "s1" }));

    await waitFor(() => expect(projectApi.getArchives).toHaveBeenCalledTimes(2));
  });
});

