import { fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, useLocation } from "react-router-dom";
import { describe, it, expect, vi } from "vitest";

import type { Finding } from "@/types/scan";
import type { ScanContext } from "../details/SastDetailsView";

vi.mock("@/context/useAuth", () => ({
  useAuth: () => ({ hasPermission: () => true, permissions: [] }),
}));
vi.mock("@/hooks/queries/use-projects", () => ({ useProject: () => ({ data: undefined }) }));
vi.mock("@/hooks/queries/use-users", () => ({ useCurrentUser: () => ({ data: undefined }) }));
vi.mock("@/hooks/queries/use-waivers", () => ({ useWaiverById: () => ({ data: undefined }) }));

import { FindingDetailsModal } from "../FindingDetailsModal";

function finding(foundIn: string[]): Finding {
  return {
    id: "lodash:4.17.20",
    type: "outdated",
    severity: "LOW",
    component: "lodash",
    version: "4.17.20",
    description: "",
    scanners: [],
    details: {},
    found_in: foundIn,
    aliases: [],
    waived: false,
  } as unknown as Finding;
}

function Location() {
  const location = useLocation();
  return <output data-testid="location">{location.pathname + location.search}</output>;
}

function clickSource(source: string, scanContext?: ScanContext): string | null {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <FindingDetailsModal
          finding={finding([source])}
          isOpen
          onClose={() => {}}
          projectId="p1"
          scanId="s1"
          scanContext={scanContext}
        />
        <Location />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  fireEvent.click(screen.getByText(source));
  return screen.getByTestId("location").textContent;
}

describe("FindingDetailsModal Found In sources", () => {
  it("opens the raw SBOMs without pointing at the first one for a named source of a multi-SBOM scan", () => {
    expect(clickSource("frontend", { sbomCount: 2 })).toBe("/projects/p1/scans/s1?tab=raw");
  });

  it("points at the SBOM a positional source names", () => {
    expect(clickSource("SBOM #2", { sbomCount: 2 })).toBe("/projects/p1/scans/s1?tab=raw&sbom=1");
  });

  it("points at the only SBOM of a single-SBOM scan for a named source", () => {
    expect(clickSource("frontend", { sbomCount: 1 })).toBe("/projects/p1/scans/s1?tab=raw&sbom=0");
  });
});
