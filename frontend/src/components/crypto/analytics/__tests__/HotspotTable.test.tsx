import { render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { describe, it, expect, vi } from "vitest";

import { HotspotTable } from "../HotspotTable";

vi.mock("@/api/cryptoAnalytics", () => ({
  getCryptoHotspots: vi.fn().mockResolvedValue({
    scope: "project",
    scope_id: "p",
    grouping_dimension: "name",
    items: [
      {
        key: "MD5",
        grouping_dimension: "name",
        asset_count: 3,
        finding_count: 2,
        severity_mix: { HIGH: 2 },
        locations: ["/path/a", "/path/b"],
        project_ids: ["p"],
        first_seen: "2026-01-01",
        last_seen: "2026-04-01",
      },
    ],
    total: 1,
    generated_at: "2026-04-20",
    cache_hit: false,
  }),
}));

function renderWithClient(ui: React.ReactElement) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <MemoryRouter>
      <QueryClientProvider client={client}>{ui}</QueryClientProvider>
    </MemoryRouter>,
  );
}

describe("HotspotTable", () => {
  it("renders hotspot rows with asset count", async () => {
    renderWithClient(
      <HotspotTable scope="project" scopeId="p" groupBy="name" />,
    );
    expect(await screen.findByText("MD5")).toBeInTheDocument();
    expect(screen.getByText("3")).toBeInTheDocument();
  });

  it("shows severity mix", async () => {
    renderWithClient(
      <HotspotTable scope="project" scopeId="p" groupBy="name" />,
    );
    expect(await screen.findByText(/HIGH/)).toBeInTheDocument();
  });
});
