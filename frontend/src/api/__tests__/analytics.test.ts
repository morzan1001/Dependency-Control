import { describe, it, expect, vi, beforeEach } from "vitest";
import { analyticsApi } from "@/api/analytics";
import { api } from "@/api/client";

vi.mock("@/api/client", async () => {
  const actual = await vi.importActual<typeof import("@/api/client")>(
    "@/api/client"
  );
  return {
    ...actual,
    api: { get: vi.fn() },
  };
});

const mockGet = api.get as unknown as ReturnType<typeof vi.fn>;

describe("analyticsApi.searchDependencies", () => {
  beforeEach(() => vi.clearAllMocks());

  it("unwraps the paginated envelope and returns the items array", async () => {
    const items = [
      {
        project_id: "p1",
        project_name: "Proj One",
        package: "react",
        version: "18.2.0",
        type: "npm",
        license: "MIT",
        direct: true,
      },
    ];
    mockGet.mockResolvedValue({
      data: { items, total: 1, page: 0, size: 50 },
    });

    const result = await analyticsApi.searchDependencies("react");

    expect(Array.isArray(result)).toBe(true);
    expect(result).toEqual(items);
    // A consumer that calls .map / .length must not crash.
    expect(result).toHaveLength(1);
    expect(result.map((r) => r.package)).toEqual(["react"]);
  });

  it("hits the /analytics/search endpoint with q and version params", async () => {
    mockGet.mockResolvedValue({
      data: { items: [], total: 0, page: 0, size: 50 },
    });

    await analyticsApi.searchDependencies("lodash", "4.17.21");

    const [url, config] = mockGet.mock.calls[0];
    expect(url).toBe("/analytics/search");
    const params = config.params as URLSearchParams;
    expect(params.get("q")).toBe("lodash");
    expect(params.get("version")).toBe("4.17.21");
  });

  it("returns an empty array when the envelope has no items", async () => {
    mockGet.mockResolvedValue({
      data: { items: [], total: 0, page: 0, size: 50 },
    });

    const result = await analyticsApi.searchDependencies("nonexistent");

    expect(result).toEqual([]);
    expect(result).toHaveLength(0);
  });
});
