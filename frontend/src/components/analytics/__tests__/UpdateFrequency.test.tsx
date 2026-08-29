import type { ReactNode } from "react";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { describe, it, expect, vi, beforeEach } from "vitest";
import type { UpdateFrequencyMetrics } from "@/types/analytics";
import { UpdateFrequency } from "../UpdateFrequency";

vi.mock("@/api/analytics", () => ({
  analyticsApi: {
    getUpdateFrequency: vi.fn(),
  },
}));

vi.mock("recharts", () => ({
  ResponsiveContainer: ({ children }: { children?: ReactNode }) => <div>{children}</div>,
  ComposedChart: ({ children }: { children?: ReactNode }) => <div data-testid="timeline">{children}</div>,
  PieChart: ({ children }: { children?: ReactNode }) => <div>{children}</div>,
  Pie: () => null,
  Cell: () => null,
  Bar: () => null,
  Line: () => null,
  Legend: () => null,
  XAxis: () => null,
  YAxis: () => null,
  CartesianGrid: () => null,
  Tooltip: () => null,
}));

import { analyticsApi } from "@/api/analytics";

const mockedFrequency = analyticsApi.getUpdateFrequency as ReturnType<typeof vi.fn>;

const metrics: UpdateFrequencyMetrics = {
  project_id: "p1",
  project_name: "proj",
  branch: "main",
  scan_count: 5,
  time_range_days: 90,
  first_scan_date: "2026-05-01T00:00:00Z",
  last_scan_date: "2026-08-01T00:00:00Z",
  total_updates: 10,
  updates_per_scan: 2,
  updates_per_month: 3,
  patch_updates: 5,
  minor_updates: 3,
  major_updates: 2,
  unknown_updates: 0,
  downgrade_updates: 0,
  granularity_ratio: {},
  avg_days_between_scans: 7,
  total_outdated_detected: 8,
  outdated_resolved: 4,
  update_coverage_pct: 50,
  trend_direction: "stable",
  trend_detail: "steady",
  upstream_releases_last_12m_median: null,
  upstream_days_between_releases_median: null,
  upstream_days_since_latest_release_median: null,
  adoption_latency_days_median: null,
  dominant_ecosystem: "npm",
  scan_timeline: [],
  slowest_packages: [],
  recent_updates: [],
};

function renderFrequency(): void {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <UpdateFrequency projectId="p1" />
    </QueryClientProvider>,
  );
}

describe("UpdateFrequency", () => {
  beforeEach(() => vi.clearAllMocks());

  it("surfaces the failure reason and lets the user retry", async () => {
    mockedFrequency.mockRejectedValue({
      message: "timeout of 300000ms exceeded",
      response: { data: { detail: "Aggregation timed out" } },
    });
    renderFrequency();

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Failed to load update frequency data");
    expect(alert).toHaveTextContent("Aggregation timed out");

    mockedFrequency.mockResolvedValue(metrics);
    fireEvent.click(screen.getByRole("button", { name: /retry/i }));

    await waitFor(() => expect(mockedFrequency).toHaveBeenCalledTimes(2));
    expect(await screen.findByText("Update Timeline")).toBeInTheDocument();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("keeps the upstream card and says why it is empty", async () => {
    mockedFrequency.mockResolvedValue(metrics);
    renderFrequency();

    expect(await screen.findByText("Upstream Release Cadence")).toBeInTheDocument();
    expect(screen.getByText(/no upstream release data for this project/i)).toBeInTheDocument();
  });

  it("drops that note as soon as one cadence median arrives", async () => {
    mockedFrequency.mockResolvedValue({ ...metrics, upstream_releases_last_12m_median: 4 });
    renderFrequency();

    await screen.findByText("Upstream Release Cadence");
    expect(screen.getByText("4.0")).toBeInTheDocument();
    expect(screen.queryByText(/no upstream release data/i)).not.toBeInTheDocument();
  });
});
