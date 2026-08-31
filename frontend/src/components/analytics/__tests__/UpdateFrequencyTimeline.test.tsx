import { cloneElement, isValidElement, type ReactElement, type ReactNode } from "react";
import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { describe, it, expect, vi, beforeEach } from "vitest";
import type { UpdateFrequencyMetrics } from "@/types/analytics";
import { UpdateFrequency } from "../UpdateFrequency";

vi.mock("@/api/analytics", () => ({
  analyticsApi: { getUpdateFrequency: vi.fn() },
}));

// Everything but ResponsiveContainer stays real -- the behaviour under test is how recharts
// draws a null-neighboured point. ResponsiveContainer measures zero in jsdom, so it is replaced
// by a stand-in that hands the chart the fixed size the real one would have measured.
vi.mock("recharts", async (importOriginal) => ({
  ...(await importOriginal<typeof import("recharts")>()),
  ResponsiveContainer: ({ children }: { children?: ReactNode }) =>
    isValidElement(children) ? cloneElement(children as ReactElement<Record<string, unknown>>, { width: 600, height: 300 }) : null,
}));

import { analyticsApi } from "@/api/analytics";

const mockedFrequency = analyticsApi.getUpdateFrequency as ReturnType<typeof vi.fn>;

const metrics: UpdateFrequencyMetrics = {
  project_id: "p1",
  project_name: "proj",
  branch: "main",
  scan_count: 2,
  time_range_days: 90,
  first_scan_date: "2026-05-01T00:00:00Z",
  last_scan_date: "2026-08-01T00:00:00Z",
  total_updates: 0,
  updates_per_scan: 0,
  updates_per_month: 0,
  patch_updates: 0,
  minor_updates: 0,
  major_updates: 0,
  unknown_updates: 0,
  downgrade_updates: 0,
  granularity_ratio: {},
  avg_days_between_scans: 7,
  total_outdated_detected: 3,
  outdated_resolved: 0,
  update_coverage_pct: 0,
  trend_direction: "stable",
  trend_detail: "steady",
  upstream_releases_last_12m_median: null,
  upstream_days_between_releases_median: null,
  upstream_days_since_latest_release_median: null,
  adoption_latency_days_median: null,
  dominant_ecosystem: "npm",
  scan_timeline: [
    {
      scan_id: "s1",
      date: "2026-05-01T00:00:00Z",
      updates_count: 0,
      outdated_count: 3,
      patch: 0,
      minor: 0,
      major: 0,
      unknown: 0,
      downgrades: 0,
    },
    {
      scan_id: "s2",
      date: "2026-08-01T00:00:00Z",
      updates_count: 0,
      outdated_count: null,
      patch: 0,
      minor: 0,
      major: 0,
      unknown: 0,
      downgrades: 0,
    },
  ],
  slowest_packages: [],
  recent_updates: [],
};

describe("UpdateFrequency timeline with an unmeasured scan", () => {
  beforeEach(() => vi.clearAllMocks());

  it("still plots the one scan that did measure a backlog", async () => {
    mockedFrequency.mockResolvedValue(metrics);
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    const { container } = render(
      <QueryClientProvider client={client}>
        <UpdateFrequency projectId="p1" />
      </QueryClientProvider>,
    );

    expect(await screen.findByText("Update Timeline")).toBeInTheDocument();
    // A null neighbour suppresses the line segment, so the dot is the only mark left.
    await waitFor(() => expect(container.querySelectorAll(".recharts-line-dot").length).toBeGreaterThan(0));
  });
});
