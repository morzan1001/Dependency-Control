import { render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { describe, expect, it, vi } from "vitest";

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
  first_seen: "2026-10-01T00:00:00Z",
  last_seen: "2026-10-14T00:00:00Z",
});

vi.mock("@/api/cryptoAnalytics", () => ({
  getCryptoHotspots: vi.fn(async () => ({
    scope: "user",
    scope_id: null,
    grouping_dimension: "name",
    items: [entry("RSA", { MEDIUM: 4, HIGH: 2 }), entry("SHA-224", { LOW: 1 }), entry("AES", {})],
    total: 3,
    generated_at: "2026-10-14T00:00:00Z",
  })),
}));

describe("HotspotTreemap", () => {
  it("colours each cell by its worst severity from the palette every severity chart uses", async () => {
    render(
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <HotspotTreemap scope="user" groupBy="name" />
      </QueryClientProvider>,
    );

    expect(await screen.findByText("RSA")).toHaveAttribute("data-fill", SEVERITY_CHART_COLORS.HIGH);
    expect(screen.getByText("SHA-224")).toHaveAttribute("data-fill", SEVERITY_CHART_COLORS.LOW);
    expect(screen.getByText("AES")).toHaveAttribute("data-fill", SEVERITY_CHART_COLORS.UNKNOWN);
  });
});
