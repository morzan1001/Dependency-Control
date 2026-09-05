import { render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { describe, it, expect, vi } from "vitest";

import type { Finding } from "@/types/scan";

vi.mock("@/context/useAuth", () => ({
  useAuth: () => ({ hasPermission: () => false, permissions: [] }),
}));
vi.mock("@/hooks/queries/use-projects", () => ({ useProject: () => ({ data: undefined }) }));
vi.mock("@/hooks/queries/use-users", () => ({ useCurrentUser: () => ({ data: undefined }) }));
vi.mock("@/hooks/queries/use-waivers", () => ({ useWaiverById: () => ({ data: undefined }) }));

import { FindingDetailsModal } from "../FindingDetailsModal";

const OMITTED = 1234;
const SIBLING_ID = "SAST-2";

function makeFinding(overrides: Partial<Finding>): Finding {
  return {
    id: "SAST-1",
    type: "sast",
    severity: "HIGH",
    component: "app/handlers.py",
    description: "eval() detected",
    scanners: ["opengrep"],
    details: {},
    found_in: [],
    aliases: [],
    waived: false,
    ...overrides,
  } as unknown as Finding;
}

function renderModal(finding: Finding) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <FindingDetailsModal finding={finding} isOpen onClose={() => {}} />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("FindingDetailsModal related findings", () => {
  it("says the list was omitted rather than rendering nothing", () => {
    renderModal(makeFinding({ related_findings: [], related_findings_omitted: OMITTED }));

    expect(screen.getByText(/Not listed/i)).toBeInTheDocument();
    expect(screen.getByText(new RegExp(OMITTED.toLocaleString()))).toBeInTheDocument();
  });

  it("renders no such note for a finding that genuinely has no siblings", () => {
    renderModal(makeFinding({ related_findings: [] }));

    expect(screen.queryByText(/Not listed/i)).not.toBeInTheDocument();
    expect(screen.queryByText("Related Findings")).not.toBeInTheDocument();
  });

  it("keeps rendering the list when the group was small enough to link", () => {
    renderModal(makeFinding({ related_findings: [SIBLING_ID] }));

    expect(screen.getByText(SIBLING_ID)).toBeInTheDocument();
    expect(screen.queryByText(/Not listed/i)).not.toBeInTheDocument();
  });
});
