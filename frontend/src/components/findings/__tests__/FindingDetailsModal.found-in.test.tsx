import { fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter, useLocation } from "react-router-dom";
import { describe, it, expect, vi } from "vitest";

import type { Finding } from "@/types/scan";

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

// Rendered without a scanContext, as the analytics dependency modal renders it.
function clickSource(source: string): string | null {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <FindingDetailsModal
          finding={finding([source])}
          onClose={() => {}}
          projectId="p1"
          scanId="s1"
        />
        <Location />
      </MemoryRouter>
    </QueryClientProvider>,
  );
  fireEvent.click(screen.getByText(source));
  return screen.getByTestId("location").textContent;
}

describe("FindingDetailsModal Found In sources", () => {
  it("hands a named source to the scan page instead of pointing at an SBOM", () => {
    expect(clickSource("frontend")).toBe("/projects/p1/scans/s1?tab=raw&sbomSource=frontend");
  });

  it("points at the SBOM a positional source names", () => {
    expect(clickSource("SBOM #2")).toBe("/projects/p1/scans/s1?tab=raw&sbom=1");
  });
});
