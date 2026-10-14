import { fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cloneElement, type ReactElement } from "react";
import { describe, expect, it, vi } from "vitest";

import type { HotspotEntry } from "@/types/cryptoAnalytics";
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
  first_seen: "2026-10-01T00:00:00Z",
  last_seen: "2026-10-14T00:00:00Z",
});

vi.mock("@/api/cryptoAnalytics", () => ({
  getCryptoHotspots: vi.fn(async () => ({
    scope: "user",
    scope_id: null,
    grouping_dimension: "name",
    items: [entry(LONG_KEY), entry("RSA")],
    total: 2,
    generated_at: "2026-10-14T00:00:00Z",
  })),
}));

describe("HotspotBarChart", () => {
  it("shortens a long hotspot name under its bars and names it in full in the tooltip", async () => {
    const { container } = render(
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <HotspotBarChart scope="user" groupBy="name" />
      </QueryClientProvider>,
    );

    expect(await screen.findByText("org.bouncycastle:bcp…")).toBeInTheDocument();
    expect(screen.queryByText(LONG_KEY)).not.toBeInTheDocument();

    fireEvent.focus(container.querySelector(".recharts-wrapper")!);

    expect(await screen.findByText(LONG_KEY)).toBeInTheDocument();
  });
});
