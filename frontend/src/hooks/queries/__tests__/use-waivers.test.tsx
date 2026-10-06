import { describe, it, expect, vi, beforeEach } from "vitest";
import { act, renderHook, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider, useQuery } from "@tanstack/react-query";
import type { ReactNode } from "react";

import { waiverApi } from "@/api/waivers";
import { useCreateWaiver, useDeleteWaiver, useGlobalWaivers, useProjectWaivers } from "../use-waivers";

vi.mock("@/api/waivers", () => ({
  waiverApi: {
    getByProject: vi.fn(),
    getAll: vi.fn(),
    create: vi.fn().mockResolvedValue({}),
    delete: vi.fn().mockResolvedValue({}),
  },
}));

const getByProject = vi.mocked(waiverApi.getByProject);
const emptyPage = { items: [], total: 0, page: 1, size: 50, pages: 1 };
const SCAN_ID = "s1";

// One client across rerenders: a client per render would drop the cache the hook keeps.
function makeWrapper() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return ({ children }: { children: ReactNode }) => <QueryClientProvider client={client}>{children}</QueryClientProvider>;
}

// The scan page's findings table and waived-findings probe, keyed as FindingsTable and WaivedFindingsSection key them.
function renderScanPageWith<T>(useMutationUnderTest: () => T) {
  const findings = vi.fn().mockResolvedValue({ total: 1 });
  const waivedProbe = vi.fn().mockResolvedValue({ total: 0 });
  const { result } = renderHook(
    () => {
      useQuery({ queryKey: ["findings", SCAN_ID, "security", "", "severity", "desc"], queryFn: findings });
      useQuery({ queryKey: ["waived-findings-probe", SCAN_ID, "security", undefined], queryFn: waivedProbe });
      return useMutationUnderTest();
    },
    { wrapper: makeWrapper() },
  );
  return { result, findings, waivedProbe };
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

describe("waiver mutations", () => {
  it("refetch the findings table and the waived-findings probe after a waiver is created", async () => {
    const { result, findings, waivedProbe } = renderScanPageWith(useCreateWaiver);
    await waitFor(() => expect(findings).toHaveBeenCalledTimes(1));

    act(() => result.current.mutate({ project_id: "p1", scan_id: SCAN_ID, finding_id: "f1", reason: "accepted" }));

    await waitFor(() => expect(waiverApi.create).toHaveBeenCalled());
    await waitFor(() => expect(findings).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(waivedProbe).toHaveBeenCalledTimes(2));
  });

  it("refetch both after a waiver is deleted", async () => {
    const { result, findings, waivedProbe } = renderScanPageWith(useDeleteWaiver);
    await waitFor(() => expect(findings).toHaveBeenCalledTimes(1));

    act(() => result.current.mutate("w1"));

    await waitFor(() => expect(findings).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(waivedProbe).toHaveBeenCalledTimes(2));
  });
});
