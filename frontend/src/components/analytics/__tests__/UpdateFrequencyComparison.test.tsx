import type { ReactNode } from "react";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { describe, it, expect, vi, beforeEach } from "vitest";
import type { ProjectUpdateSummary, UpdateFrequencyComparison as Comparison } from "@/types/analytics";
import { UpdateFrequencyComparison } from "../UpdateFrequencyComparison";

vi.mock("@/api/analytics", () => ({
  analyticsApi: {
    getUpdateFrequencyComparison: vi.fn(),
  },
}));

vi.mock("@/hooks/queries/use-teams", () => ({
  useTeams: () => ({ data: [] }),
}));

// Radix Select isn't driveable in jsdom (pointer capture); use a native select.
vi.mock("../WindowSelect", () => ({
  WindowSelect: ({ value, onChange }: { value: number | undefined; onChange: (v: number) => void }) => (
    <select
      data-testid="window-select"
      value={String(value)}
      onChange={(e) => onChange(Number(e.target.value))}
    >
      <option value="90">90</option>
      <option value="180">180</option>
    </select>
  ),
}));

vi.mock("recharts", () => ({
  ResponsiveContainer: ({ children }: { children?: ReactNode }) => <div>{children}</div>,
  BarChart: ({ data, children }: { data: unknown[]; children?: ReactNode }) => (
    <div data-testid="bar-chart" data-bars={data.length}>
      {children}
    </div>
  ),
  Bar: ({ isAnimationActive }: { isAnimationActive?: boolean }) => (
    <div data-testid="bar" data-animated={String(isAnimationActive)} />
  ),
  XAxis: () => null,
  YAxis: () => null,
  CartesianGrid: () => null,
  Tooltip: () => null,
}));

import { analyticsApi } from "@/api/analytics";

const mockedComparison = analyticsApi.getUpdateFrequencyComparison as ReturnType<typeof vi.fn>;

const makeProject = (idx: number): ProjectUpdateSummary => ({
  project_id: `p${idx}`,
  project_name: `project-${idx}`,
  team_name: null,
  scan_count: 5,
  updates_per_month: idx,
  update_coverage_pct: idx,
  patch_ratio: 0.5,
  trend_direction: "stable",
  total_outdated: idx,
  last_scan_date: "2026-08-01T00:00:00Z",
});

const makeComparison = (count: number): Comparison => ({
  projects: Array.from({ length: count }, (_, i) => makeProject(count - i)),
  team_avg_updates_per_month: 3,
  team_avg_coverage_pct: 42,
  best_project: null,
  worst_project: null,
  skipped_projects: 0,
});

function renderComparison(): void {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <UpdateFrequencyComparison />
    </QueryClientProvider>,
  );
}

const clickLoad = (): void => {
  fireEvent.click(screen.getByRole("button", { name: /load comparison/i }));
};

describe("UpdateFrequencyComparison", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockedComparison.mockResolvedValue(makeComparison(3));
  });

  it("fires no request until the user explicitly loads the comparison", async () => {
    renderComparison();

    await screen.findByText(/pick a team and time window/i);
    expect(mockedComparison).not.toHaveBeenCalled();

    clickLoad();

    await waitFor(() => expect(mockedComparison).toHaveBeenCalledTimes(1));
    expect(mockedComparison).toHaveBeenCalledWith(undefined, { windowDays: 90 }, expect.any(AbortSignal));
  });

  it("caps the chart at the top 25 projects and says so", async () => {
    mockedComparison.mockResolvedValue(makeComparison(60));
    renderComparison();
    clickLoad();

    const chart = await screen.findByTestId("bar-chart");
    expect(chart).toHaveAttribute("data-bars", "25");
    expect(screen.getByText(/top 25 of 60 projects/i)).toBeInTheDocument();
    expect(screen.getByTestId("bar")).toHaveAttribute("data-animated", "false");
  });

  it("paginates the ranking table instead of rendering every project", async () => {
    mockedComparison.mockResolvedValue(makeComparison(60));
    renderComparison();
    clickLoad();

    await screen.findByText("Project Ranking");
    const bodyRows = screen.getAllByRole("row").filter((row) => row.querySelector("td"));
    expect(bodyRows).toHaveLength(25);
    expect(screen.getByText(/page 1 of 3/i)).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /next/i }));
    expect(screen.getByText("project-26")).toBeInTheDocument();
    expect(screen.queryByText("project-1")).not.toBeInTheDocument();
  });

  it("clamps the ranking page when a shorter cached result arrives without a fetch", async () => {
    mockedComparison
      .mockResolvedValueOnce(makeComparison(2))
      .mockResolvedValueOnce(makeComparison(60));
    renderComparison();

    clickLoad();
    await screen.findByText("Project Ranking");

    fireEvent.change(screen.getByTestId("window-select"), { target: { value: "180" } });
    clickLoad();
    await screen.findByText(/page 1 of 3/i);

    fireEvent.click(screen.getByRole("button", { name: /next/i }));
    fireEvent.click(screen.getByRole("button", { name: /next/i }));
    expect(screen.getByText(/page 3 of 3/i)).toBeInTheDocument();

    fireEvent.change(screen.getByTestId("window-select"), { target: { value: "90" } });
    clickLoad();

    await screen.findByText("project-2");
    expect(mockedComparison).toHaveBeenCalledTimes(2);
    const bodyRows = screen.getAllByRole("row").filter((row) => row.querySelector("td"));
    expect(bodyRows).toHaveLength(2);
  });

  it("keeps the load button usable after a successful run and refetches", async () => {
    renderComparison();
    clickLoad();

    await screen.findByText("Project Ranking");
    const reload = screen.getByRole("button", { name: /reload comparison/i });
    expect(reload).toBeEnabled();

    fireEvent.click(reload);

    await waitFor(() => expect(mockedComparison).toHaveBeenCalledTimes(2));
  });

  it("surfaces the failure reason and lets the user retry", async () => {
    mockedComparison.mockRejectedValue({
      message: "timeout of 300000ms exceeded",
      response: { data: { detail: "Aggregation timed out" } },
    });
    renderComparison();
    clickLoad();

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Aggregation timed out");

    mockedComparison.mockResolvedValue(makeComparison(1));
    fireEvent.click(screen.getByRole("button", { name: /retry/i }));

    await waitFor(() => expect(mockedComparison).toHaveBeenCalledTimes(2));
    expect(await screen.findByText("Project Ranking")).toBeInTheDocument();
  });
});
