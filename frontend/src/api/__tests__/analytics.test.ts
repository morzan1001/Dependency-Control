import { describe, it, expect, vi, beforeEach } from "vitest";
import { analyticsApi } from "@/api/analytics";
import { api } from "@/api/client";
import { API_TIMEOUT_MS, UPDATE_FREQUENCY_TIMEOUT_MS } from "@/lib/constants";

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

describe("analyticsApi update-frequency query params", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGet.mockResolvedValue({ data: {} });
  });

  it("sends the project window and nothing the endpoint no longer reads", async () => {
    await analyticsApi.getUpdateFrequency("p1", { windowDays: 365 });

    const params = mockGet.mock.calls[0][1].params as URLSearchParams;
    expect([...params.entries()]).toEqual([["window_days", "365"]]);
  });

  it("sends team and window to the comparison, which has no scan-count mode", async () => {
    await analyticsApi.getUpdateFrequencyComparison("t1", { windowDays: 90 });

    const params = mockGet.mock.calls[0][1].params as URLSearchParams;
    expect([...params.entries()]).toEqual([
      ["team_id", "t1"],
      ["window_days", "90"],
    ]);
  });

  it("omits the window entirely in the scan-count mode of the project page", async () => {
    await analyticsApi.getUpdateFrequency("p1", { windowDays: undefined });

    const params = mockGet.mock.calls[0][1].params as URLSearchParams;
    expect([...params.entries()]).toEqual([]);
  });
});

describe("analyticsApi update-frequency timeouts", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGet.mockResolvedValue({ data: {} });
  });

  it("gives the per-project endpoint the long timeout instead of the global one", async () => {
    const signal = new AbortController().signal;

    await analyticsApi.getUpdateFrequency("p1", { windowDays: 90 }, signal);

    const [url, config] = mockGet.mock.calls[0];
    expect(url).toBe("/analytics/projects/p1/update-frequency");
    expect(config.timeout).toBe(UPDATE_FREQUENCY_TIMEOUT_MS);
    expect(config.timeout).toBeGreaterThan(API_TIMEOUT_MS);
    expect(config.signal).toBe(signal);
  });

  it("gives the comparison endpoint the long timeout instead of the global one", async () => {
    const signal = new AbortController().signal;

    await analyticsApi.getUpdateFrequencyComparison("t1", { windowDays: 90 }, signal);

    const [url, config] = mockGet.mock.calls[0];
    expect(url).toBe("/analytics/update-frequency/comparison");
    expect(config.timeout).toBe(UPDATE_FREQUENCY_TIMEOUT_MS);
    expect(config.timeout).toBeGreaterThan(API_TIMEOUT_MS);
    expect(config.signal).toBe(signal);
  });
});

describe("analyticsApi release environment", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockGet.mockResolvedValue({ data: { items: [], total: 0, page: 0, size: 50 } });
  });

  const RELEASE_PARAM = "release_environment";
  const PRODUCTION = "production";
  const HEAD_MODE = undefined;
  const SEARCH_TERM = "log4j";

  // Every analytics endpoint the backend accepts release_environment on, with the argument
  // position each of its callers uses.
  const inReleaseMode: [string, () => Promise<unknown>][] = [
    ["/analytics/scope", () => analyticsApi.getScope(PRODUCTION)],
    ["/analytics/summary", () => analyticsApi.getSummary(PRODUCTION)],
    ["/analytics/dependencies/top", () => analyticsApi.getTopDependencies(undefined, undefined, PRODUCTION)],
    ["/analytics/dependency-types", () => analyticsApi.getDependencyTypes(PRODUCTION)],
    ["/analytics/impact", () => analyticsApi.getImpactAnalysis(undefined, PRODUCTION)],
    ["/analytics/hotspots", () => analyticsApi.getVulnerabilityHotspots({ release_environment: PRODUCTION })],
    ["/analytics/search", () => analyticsApi.searchDependenciesAdvanced(SEARCH_TERM, { release_environment: PRODUCTION })],
    [
      "/analytics/vulnerability-search",
      () => analyticsApi.searchVulnerabilities(SEARCH_TERM, { release_environment: PRODUCTION }),
    ],
  ];

  const inHeadMode: [string, () => Promise<unknown>][] = [
    ["/analytics/scope", () => analyticsApi.getScope(HEAD_MODE)],
    ["/analytics/summary", () => analyticsApi.getSummary(HEAD_MODE)],
    ["/analytics/dependencies/top", () => analyticsApi.getTopDependencies()],
    ["/analytics/dependency-types", () => analyticsApi.getDependencyTypes()],
    ["/analytics/impact", () => analyticsApi.getImpactAnalysis()],
    ["/analytics/hotspots", () => analyticsApi.getVulnerabilityHotspots()],
    ["/analytics/search", () => analyticsApi.searchDependenciesAdvanced(SEARCH_TERM)],
    ["/analytics/vulnerability-search", () => analyticsApi.searchVulnerabilities(SEARCH_TERM)],
  ];

  it.each(inReleaseMode)("sends the environment to %s", async (url, call) => {
    await call();

    const [requested, config] = mockGet.mock.calls[0];
    expect(requested).toBe(url);
    expect((config.params as URLSearchParams).get(RELEASE_PARAM)).toBe(PRODUCTION);
  });

  it.each(inHeadMode)("omits the environment from %s in head mode", async (url, call) => {
    await call();

    const [requested, config] = mockGet.mock.calls[0];
    expect(requested).toBe(url);
    expect((config.params as URLSearchParams).has(RELEASE_PARAM)).toBe(false);
  });
});
