import type { ReactNode } from "react";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
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
  // Distinct per project: a branch cell that ignored its row would still read "main".
  branch: `release/${idx}.x`,
  window_days: 90,
  scan_count: 5,
  updates_per_month: idx,
  update_coverage_pct: idx,
  patch_ratio: 0.5,
  trend_direction: "stable",
  total_outdated: idx,
  total_updates: idx * 2,
  last_scan_date: "2026-08-01T00:00:00Z",
  data_status: "ready",
});

const makeUnmeasured = (
  name: string,
  status: Exclude<ProjectUpdateSummary["data_status"], "ready">,
): ProjectUpdateSummary => ({
  project_id: name,
  project_name: name,
  team_name: null,
  branch: null,
  window_days: 90,
  scan_count: null,
  updates_per_month: null,
  update_coverage_pct: null,
  patch_ratio: null,
  trend_direction: "unknown",
  total_outdated: null,
  total_updates: null,
  last_scan_date: null,
  data_status: status,
});

const makePartial = (name: string): ProjectUpdateSummary => ({
  ...makeProject(9),
  project_id: name,
  project_name: name,
  data_status: "partial",
  scan_count: 2,
});

const makeComparison = (count: number, overrides: Partial<Comparison> = {}): Comparison => ({
  projects: Array.from({ length: count }, (_, i) => makeProject(count - i)),
  team_avg_updates_per_month: 3,
  team_avg_coverage_pct: 42,
  best_project: null,
  worst_project: null,
  partial_projects: 0,
  pending_projects: 0,
  skipped_insufficient_data: 0,
  skipped_error: 0,
  ...overrides,
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

const rowFor = (projectName: string): HTMLElement => {
  const row = screen.getByText(projectName).closest("tr");
  if (!row) throw new Error(`no table row for ${projectName}`);
  return row;
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
    expect(screen.getByText(/top 25 of 60 measured projects/i)).toBeInTheDocument();
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

  it("names the branch each project was measured on", async () => {
    mockedComparison.mockResolvedValue(makeComparison(2));
    renderComparison();
    clickLoad();

    await screen.findByText("Project Ranking");
    expect(screen.getByRole("columnheader", { name: "Branch" })).toBeInTheDocument();
    // Each row shows its own branch, so neither a constant nor a neighbour's value passes.
    expect(within(rowFor("project-1")).getByText("release/1.x")).toBeInTheDocument();
    expect(within(rowFor("project-2")).getByText("release/2.x")).toBeInTheDocument();
  });

  it("shows a partially covered project's numbers with the caveat, not as a failure", async () => {
    mockedComparison.mockResolvedValue(
      makeComparison(1, {
        projects: [makeProject(1), makePartial("half-measured")],
        partial_projects: 1,
      }),
    );
    renderComparison();
    clickLoad();

    await screen.findByText("Project Ranking");
    const row = rowFor("half-measured");
    const badge = within(row).getByText("Partial window");
    expect(badge.closest("[title]")).toHaveAttribute("title", expect.stringContaining("only 2 scans"));
    // The numbers it does carry are shown rather than replaced by a status placeholder.
    const cells = within(row).getAllByRole("cell");
    expect(cells[4]).toHaveTextContent("9");
    expect(cells[5]).toHaveTextContent("9%");
    expect(cells[6]).toHaveTextContent("50%");
  });

  it("leaves a partially covered project unranked, uncharted and out of the averages", async () => {
    mockedComparison.mockResolvedValue(
      makeComparison(1, {
        projects: [makeProject(1), makePartial("half-measured")],
        partial_projects: 1,
      }),
    );
    renderComparison();
    clickLoad();

    const chart = await screen.findByTestId("bar-chart");
    expect(chart).toHaveAttribute("data-bars", "1");
    expect(screen.getByText("across 1 measured project")).toBeInTheDocument();
    expect(screen.getByText("1 on a partial window")).toBeInTheDocument();
    expect(screen.getByText("1 project measured on part of the window")).toBeInTheDocument();
    expect(screen.getByText(/1 of 2 projects ranked/i)).toBeInTheDocument();
    // The rank column stays empty for a row that was not ranked.
    expect(within(rowFor("half-measured")).getAllByRole("cell")[0]).toHaveTextContent("—");
    expect(within(rowFor("project-1")).getAllByRole("cell")[0]).toHaveTextContent("1");
  });

  it("marks a project without a rollup as pending instead of scoring it zero", async () => {
    mockedComparison.mockResolvedValue(
      makeComparison(1, {
        projects: [makeProject(1), makeUnmeasured("waiting-project", "pending")],
        pending_projects: 1,
      }),
    );
    renderComparison();
    clickLoad();

    await screen.findByText("Project Ranking");
    const row = rowFor("waiting-project");
    expect(within(row).getByText("Not computed yet")).toBeInTheDocument();
    expect(within(row).queryByText("0%")).not.toBeInTheDocument();
    expect(within(row).queryByText("N/A")).not.toBeInTheDocument();
    expect(screen.getByText("1 project not computed yet")).toBeInTheDocument();
    expect(screen.getByText("across 1 measured project")).toBeInTheDocument();
  });

  it("tells too few scans apart from a failed measurement and drops the banner", async () => {
    mockedComparison.mockResolvedValue(
      makeComparison(1, {
        projects: [
          makeUnmeasured("thin-project", "insufficient_data"),
          makeUnmeasured("broken-project", "error"),
        ],
        skipped_insufficient_data: 1,
        skipped_error: 1,
      }),
    );
    renderComparison();
    clickLoad();

    await screen.findByText("Project Ranking");
    expect(within(rowFor("thin-project")).getByText("Too few scans")).toBeInTheDocument();
    expect(within(rowFor("broken-project")).getByText("Measurement failed")).toBeInTheDocument();
    expect(screen.getByText("1 with too few scans · 1 failed")).toBeInTheDocument();
    expect(screen.queryByText(/not computed yet/i)).not.toBeInTheDocument();
    expect(screen.queryByTestId("bar-chart")).not.toBeInTheDocument();
  });

  it("charts only the measured projects while listing every one", async () => {
    mockedComparison.mockResolvedValue(
      makeComparison(1, {
        projects: [makeProject(1), makeProject(2), makeUnmeasured("waiting-project", "pending")],
        pending_projects: 1,
      }),
    );
    renderComparison();
    clickLoad();

    const chart = await screen.findByTestId("bar-chart");
    expect(chart).toHaveAttribute("data-bars", "2");
    const bodyRows = screen.getAllByRole("row").filter((row) => row.querySelector("td"));
    expect(bodyRows).toHaveLength(3);
  });

  it("keeps a project with too few scans in the table rather than reporting an empty scope", async () => {
    mockedComparison.mockResolvedValue(
      makeComparison(1, {
        projects: [makeUnmeasured("thin-project", "insufficient_data")],
        skipped_insufficient_data: 1,
      }),
    );
    renderComparison();
    clickLoad();

    await screen.findByText("Project Ranking");
    expect(screen.getByText("thin-project")).toBeInTheDocument();
    expect(screen.queryByText("No projects in this scope")).not.toBeInTheDocument();
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
