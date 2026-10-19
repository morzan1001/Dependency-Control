import { render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { describe, it, expect, vi } from "vitest";

import { getCryptoHotspots } from "@/api/cryptoAnalytics";
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

  it("counts the severity mix in the severity pills the other breakdowns use", async () => {
    renderWithClient(
      <HotspotTable scope="project" scopeId="p" groupBy="name" />,
    );
    expect(await screen.findByText("H:2")).toHaveClass("text-xs", "bg-severity-high", "text-severity-high-foreground");
  });

  it("codes negligible, info and unknown as N, I and U", async () => {
    vi.mocked(getCryptoHotspots).mockResolvedValueOnce({
      scope: "project",
      scope_id: "p",
      grouping_dimension: "name",
      items: [{
        key: "RSA", grouping_dimension: "name", asset_count: 4, finding_count: 7,
        severity_mix: { UNKNOWN: 1, INFO: 3, NEGLIGIBLE: 2, CRITICAL: 1 }, locations: [], locations_complete: true,
        project_ids: ["p"], first_seen: "2026-01-01", last_seen: "2026-04-01",
      }],
      total: 1,
      generated_at: "2026-04-20",
    });
    renderWithClient(<HotspotTable scope="project" scopeId="p" groupBy="name" />);

    const cell = (await screen.findByText("RSA")).closest("tr")!.querySelectorAll("td")[3];
    expect(cell.textContent).toBe("C:1N:2I:3U:1");
    expect(screen.getByText("I:3")).toHaveClass("bg-severity-info");
  });

  it("says the hotspots failed to load instead of reporting none", async () => {
    vi.mocked(getCryptoHotspots).mockRejectedValueOnce(new Error("Request failed"));
    renderWithClient(
      <HotspotTable scope="project" scopeId="p" groupBy="name" />,
    );
    expect(await screen.findByText("Failed to load hotspots.")).toBeInTheDocument();
    expect(screen.queryByText("No hotspots in this scope.")).not.toBeInTheDocument();
  });

  it("keeps its columns at their widths and scrolls sideways on a narrow screen", async () => {
    renderWithClient(
      <HotspotTable scope="project" scopeId="p" groupBy="name" />,
    );
    const table = (await screen.findByText("MD5")).closest("table");
    expect(table).toHaveClass("min-w-[640px]");
    expect(table?.parentElement).toHaveClass("overflow-x-auto");
  });

  it("lists a row's severity mix in severity order, whatever order the API sent", async () => {
    vi.mocked(getCryptoHotspots).mockResolvedValueOnce({
      scope: "project",
      scope_id: "p",
      grouping_dimension: "name",
      items: [{
        key: "RSA", grouping_dimension: "name", asset_count: 4, finding_count: 7,
        severity_mix: { LOW: 1, MEDIUM: 4, HIGH: 2 }, locations: [], locations_complete: true, project_ids: ["p"],
        first_seen: "2026-01-01", last_seen: "2026-04-01",
      }],
      total: 1,
      generated_at: "2026-04-20",
    });
    renderWithClient(<HotspotTable scope="project" scopeId="p" groupBy="name" />);

    const cell = (await screen.findByText("RSA")).closest("tr")!.querySelectorAll("td")[3];
    expect(cell.textContent).toBe("H:2M:4L:1");
  });
});
