import { cloneElement, isValidElement, type ReactElement, type ReactNode } from "react";
import { fireEvent, render, screen, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { describe, expect, it, vi } from "vitest";

import type { ProjectUpdateSummary } from "@/types/analytics";
import { UpdateFrequencyComparison } from "../UpdateFrequencyComparison";

const LONG_NAME = "identity-and-access-management-gateway";

vi.mock("@/api/analytics", () => ({ analyticsApi: { getUpdateFrequencyComparison: vi.fn() } }));
vi.mock("@/hooks/queries/use-teams", () => ({ useTeams: () => ({ data: [] }) }));
vi.mock("recharts", async (importOriginal) => ({
  ...(await importOriginal<typeof import("recharts")>()),
  // jsdom lays nothing out, so the chart gets the size a browser would measure.
  ResponsiveContainer: ({ children }: { children?: ReactNode }) =>
    isValidElement(children) ? cloneElement(children as ReactElement<Record<string, unknown>>, { width: 600, height: 300 }) : null,
}));

import { analyticsApi } from "@/api/analytics";

const project = (name: string, coverage: number): ProjectUpdateSummary => ({
  project_id: name,
  project_name: name,
  teams: [],
  branch: "main",
  window_days: 90,
  scan_count: 5,
  updates_per_month: 1,
  update_coverage_pct: coverage,
  patch_ratio: 0.5,
  trend_direction: "stable",
  total_outdated: 1,
  total_updates: 2,
  last_scan_date: "2026-08-01T00:00:00Z",
  data_status: "ready",
  window_scan_cap: null,
});

describe("UpdateFrequencyComparison chart", () => {
  it("shortens a long project name beside its bar and names it in full in the tooltip", async () => {
    vi.mocked(analyticsApi.getUpdateFrequencyComparison).mockResolvedValue({
      projects: [project(LONG_NAME, 80), project("search", 40)],
      team_avg_updates_per_month: 1,
      team_avg_coverage_pct: 60,
      best_project: null,
      worst_project: null,
      partial_projects: 0,
      pending_projects: 0,
      skipped_insufficient_data: 0,
      skipped_error: 0,
    });
    render(
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <UpdateFrequencyComparison />
      </QueryClientProvider>,
    );
    fireEvent.click(screen.getByRole("button", { name: /load comparison/i }));

    const card = (await screen.findByText("Project Comparison")).closest(".bg-card") as HTMLElement;
    expect(await within(card).findByText("identity-and-access-…")).toBeInTheDocument();
    expect(within(card).queryByText(LONG_NAME)).not.toBeInTheDocument();

    fireEvent.focus(card.querySelector(".recharts-wrapper")!);

    expect(await within(card).findByText(LONG_NAME)).toBeInTheDocument();
  });
});
