import { fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cloneElement, type ReactElement } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { getCryptoHotspots } from "@/api/cryptoAnalytics";
import type { HotspotEntry, HotspotResponse } from "@/types/cryptoAnalytics";
import { HotspotBarChart } from "../HotspotBarChart";

const LONG_KEY = "org.bouncycastle:bcprov-jdk18on:1.78";

vi.mock("recharts", async (importOriginal) => ({
  ...(await importOriginal<typeof import("recharts")>()),
  // jsdom lays nothing out, so the chart gets the size a browser would measure.
  ResponsiveContainer: ({ children }: { children: ReactElement<{ width?: number; height?: number }> }) =>
    cloneElement(children, { width: 800, height: 400 }),
}));

const entry = (key: string): HotspotEntry => ({
  key,
  grouping_dimension: "name",
  asset_count: 3,
  finding_count: 2,
  severity_mix: { HIGH: 2 },
  locations: [],
  locations_complete: true,
  project_ids: ["p1"],
  project_count: 1,
  first_seen: "2026-10-01T00:00:00Z",
  last_seen: "2026-10-14T00:00:00Z",
});

const page: HotspotResponse = {
  scope: "user",
  scope_id: null,
  grouping_dimension: "name",
  items: [entry(LONG_KEY), entry("RSA")],
  total: 2,
  projects_total: 1,
  generated_at: "2026-10-14T00:00:00Z",
};

vi.mock("@/api/cryptoAnalytics", () => ({ getCryptoHotspots: vi.fn() }));

function renderChart() {
  return render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <HotspotBarChart scope="user" groupBy="name" />
    </QueryClientProvider>,
  );
}

describe("HotspotBarChart", () => {
  beforeEach(() => vi.mocked(getCryptoHotspots).mockResolvedValue(page));

  it("shortens a long hotspot name under its bars and names it in full in the tooltip", async () => {
    const { container } = renderChart();

    expect(await screen.findByText("…:bcprov-jdk18on:1.78")).toBeInTheDocument();
    expect(screen.queryByText(LONG_KEY)).not.toBeInTheDocument();

    fireEvent.focus(container.querySelector(".recharts-wrapper")!);

    expect(await screen.findByText(LONG_KEY)).toBeInTheDocument();
  });

  it("says how many hotspots its top N leaves out, like the table, heatmap and treemap", async () => {
    vi.mocked(getCryptoHotspots).mockResolvedValue({ ...page, total: 150 });
    renderChart();

    expect(await screen.findByText("Showing 2 of 150 hotspots")).toBeInTheDocument();
  });

  it("adds no count when its top N holds every hotspot", async () => {
    renderChart();

    await screen.findByText("RSA");
    expect(screen.queryByText(/Showing/)).not.toBeInTheDocument();
  });
});
