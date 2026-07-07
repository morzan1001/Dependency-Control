import { render, screen, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { describe, it, expect, vi } from "vitest";

import { HotspotHeatmap } from "../HotspotHeatmap";

const OID_A = "0123456789abcdef01234567"; // resolvable -> "Payments API"
const OID_B = "aaaaaaaaaaaaaaaaaaaaaaaa"; // unresolved -> truncated

// Build an org-scope response whose union of project_ids exceeds the 30-column cap.
const manyProjectIds = Array.from({ length: 40 }, (_, i) => `proj${String(i).padStart(3, "0")}`);

vi.mock("@/api/cryptoAnalytics", () => ({
  getCryptoHotspots: vi.fn().mockImplementation(({ scope }: { scope: string }) => {
    if (scope === "project") {
      return Promise.resolve({
        scope: "project",
        scope_id: "p",
        grouping_dimension: "name",
        items: [
          {
            key: "MD5",
            grouping_dimension: "name",
            asset_count: 3,
            finding_count: 0,
            severity_mix: {},
            locations: ["/path/a"],
            project_ids: ["p"],
            first_seen: "",
            last_seen: "",
          },
        ],
        total: 1,
        generated_at: "",
        cache_hit: false,
      });
    }
    return Promise.resolve({
      scope: "global",
      scope_id: null,
      grouping_dimension: "name",
      items: [
        {
          key: "RSA-2048",
          grouping_dimension: "name",
          asset_count: 5,
          finding_count: 0,
          severity_mix: {},
          locations: [],
          project_ids: [OID_A, OID_B, ...manyProjectIds],
          first_seen: "",
          last_seen: "",
        },
      ],
      total: 1,
      generated_at: "",
      cache_hit: false,
    });
  }),
}));

vi.mock("@/hooks/queries/use-projects", () => ({
  useProjectsDropdown: () => ({
    data: { items: [{ id: OID_A, name: "Payments API" }], total: 1 },
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

describe("HotspotHeatmap (org scope columns)", () => {
  it("caps org-scope columns at 30 instead of rendering all project ids", async () => {
    renderWithClient(<HotspotHeatmap scope="global" groupBy="name" />);
    await screen.findByText("RSA-2048");
    const headerRow = screen.getAllByRole("row")[0];
    // 1 "Key" column + 30 project columns (cap), never the full 42 unique ids.
    const headerCells = within(headerRow).getAllByRole("columnheader");
    expect(headerCells).toHaveLength(1 + 30);
  });

  it("resolves a project ObjectId to its name in the column header", async () => {
    renderWithClient(<HotspotHeatmap scope="global" groupBy="name" />);
    expect(await screen.findByText("Payments API")).toBeInTheDocument();
  });

  it("truncates an unresolved ObjectId and keeps the full id in a title tooltip", async () => {
    renderWithClient(<HotspotHeatmap scope="global" groupBy="name" />);
    await screen.findByText("RSA-2048");
    // Never render the raw 24-hex ObjectId as visible label text.
    expect(screen.queryByText(OID_B)).not.toBeInTheDocument();
    const truncated = screen.getByText(`${OID_B.slice(0, 8)}…`);
    expect(truncated).toHaveAttribute("title", OID_B);
  });
});
