import { render, screen, within } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { describe, it, expect, vi } from "vitest";

import { HotspotHeatmap } from "../HotspotHeatmap";

const OID_A = "0123456789abcdef01234567"; // resolvable -> "Payments API"
const OID_B = "aaaaaaaaaaaaaaaaaaaaaaaa"; // unresolved -> truncated

// An org-scope response names the 30 column projects of keys spread over 42.
const manyProjectIds = Array.from({ length: 28 }, (_, i) => `proj${String(i).padStart(3, "0")}`);

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
            locations_complete: false,
            project_ids: ["p"],
            project_count: 1,
            first_seen: "",
            last_seen: "",
          },
        ],
        total: 1,
        projects_total: 1,
        generated_at: "",
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
          locations_complete: false,
          project_ids: [OID_A, OID_B, ...manyProjectIds],
          project_count: 42,
          first_seen: "",
          last_seen: "",
        },
      ],
      total: 12,
      projects_total: 42,
      generated_at: "",
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
  it("renders the 30 project columns the API names", async () => {
    renderWithClient(<HotspotHeatmap scope="global" groupBy="name" />);
    await screen.findByText("RSA-2048");
    const headerRow = screen.getAllByRole("row")[0];
    const headerCells = within(headerRow).getAllByRole("columnheader");
    expect(headerCells).toHaveLength(1 + 30);
  });

  it("says how many of the columns it is showing", async () => {
    renderWithClient(<HotspotHeatmap scope="global" groupBy="name" />);
    await screen.findByText("RSA-2048");
    expect(screen.getByText("Showing 30 of 42 projects")).toBeInTheDocument();
  });

  it("says how many of the scope's hotspots it lists as rows, in the words of the other hotspot views", async () => {
    renderWithClient(<HotspotHeatmap scope="global" groupBy="name" />);
    await screen.findByText("RSA-2048");
    expect(screen.getByText("Showing 1 of 12 hotspots")).toBeInTheDocument();
  });

  it("resolves a project ObjectId to its name in the column header", async () => {
    renderWithClient(<HotspotHeatmap scope="global" groupBy="name" />);
    expect(await screen.findByText("Payments API")).toBeInTheDocument();
  });

  it("truncates an unresolved ObjectId and keeps the full id in a title tooltip", async () => {
    renderWithClient(<HotspotHeatmap scope="global" groupBy="name" />);
    await screen.findByText("RSA-2048");
    expect(screen.queryByText(OID_B)).not.toBeInTheDocument();
    const truncated = screen.getByText(`${OID_B.slice(0, 8)}…`);
    expect(truncated).toHaveAttribute("title", OID_B);
  });
});

describe("HotspotHeatmap (project scope locations)", () => {
  it("says a row whose locations are a sample carries unknown cells rather than absent ones", async () => {
    renderWithClient(<HotspotHeatmap scope="project" scopeId="p" groupBy="name" />);
    await screen.findByText("MD5");
    expect(screen.getByText(/list a sample of their locations/)).toBeInTheDocument();
  });
});
