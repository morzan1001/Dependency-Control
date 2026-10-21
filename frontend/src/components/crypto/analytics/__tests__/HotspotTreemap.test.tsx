import { render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { getCryptoHotspots } from "@/api/cryptoAnalytics";
import { SEVERITY_CHART_COLORS } from "@/lib/finding-utils";
import type { HotspotEntry } from "@/types/cryptoAnalytics";
import { HotspotTreemap } from "../HotspotTreemap";

vi.mock("recharts", () => ({
  ResponsiveContainer: ({ children }: { children: ReactNode }) => children,
  Treemap: ({ data }: { data: { name: string; fill: string }[] }) => (
    <ul>{data.map((cell) => <li key={cell.name} data-fill={cell.fill}>{cell.name}</li>)}</ul>
  ),
}));

const entry = (key: string, severity_mix: Record<string, number>): HotspotEntry => ({
  key,
  grouping_dimension: "name",
  asset_count: 1,
  finding_count: Object.values(severity_mix).reduce((a, b) => a + b, 0),
  severity_mix,
  locations: [],
  locations_complete: true,
  project_ids: ["p1"],
  project_count: 1,
  first_seen: "2026-10-01T00:00:00Z",
  last_seen: "2026-10-14T00:00:00Z",
});

const page = {
  scope: "user" as const,
  scope_id: null,
  grouping_dimension: "name" as const,
  items: [entry("RSA", { MEDIUM: 4, HIGH: 2 }), entry("SHA-224", { LOW: 1 }), entry("AES", {})],
  total: 3,
  projects_total: 1,
  generated_at: "2026-10-14T00:00:00Z",
};

vi.mock("@/api/cryptoAnalytics", () => ({ getCryptoHotspots: vi.fn() }));

function renderTreemap() {
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <HotspotTreemap scope="user" groupBy="name" />
    </QueryClientProvider>,
  );
}

describe("HotspotTreemap", () => {
  beforeEach(() => vi.mocked(getCryptoHotspots).mockResolvedValue(page));

  it("colours each cell by its worst severity from the palette every severity chart uses", async () => {
    renderTreemap();

    expect(await screen.findByText("RSA")).toHaveAttribute("data-fill", SEVERITY_CHART_COLORS.HIGH);
    expect(screen.getByText("SHA-224")).toHaveAttribute("data-fill", SEVERITY_CHART_COLORS.LOW);
    expect(screen.getByText("AES")).toHaveAttribute("data-fill", SEVERITY_CHART_COLORS.UNKNOWN);
  });

  it("says how many hotspots the page cut", async () => {
    vi.mocked(getCryptoHotspots).mockResolvedValue({ ...page, total: 150 });
    renderTreemap();

    expect(await screen.findByText("Showing 3 of 150 hotspots")).toBeInTheDocument();
  });

  it("adds no count when it draws every hotspot", async () => {
    renderTreemap();

    await screen.findByText("RSA");
    expect(screen.queryByText(/Showing/)).not.toBeInTheDocument();
  });
});
