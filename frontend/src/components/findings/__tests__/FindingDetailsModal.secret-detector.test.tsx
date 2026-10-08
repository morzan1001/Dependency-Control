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

function secretFinding(details: Record<string, unknown>, description: string): Finding {
  return {
    id: "SECRET-2-317e5726",
    type: "secret",
    severity: "CRITICAL",
    component: "config.py",
    description,
    scanners: ["trufflehog"],
    details: { verified: false, risk_score: 40, adjusted_risk_score: 40, ...details },
    found_in: [],
    aliases: [],
    waived: false,
  } as unknown as Finding;
}

function renderModal(finding: Finding) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <FindingDetailsModal finding={finding} onClose={() => {}} projectId="p1" />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("FindingDetailsModal secret detector", () => {
  it("names the detector TruffleHog reported rather than its ordinal", () => {
    renderModal(secretFinding({ detector: "2", detector_name: "AWS" }, "Secret detected: AWS"));

    expect(screen.getByText("AWS")).toBeInTheDocument();
    expect(screen.queryByText("2")).not.toBeInTheDocument();
  });

  it("shows the stored ordinal for a finding written without a name", () => {
    renderModal(secretFinding({ detector: "17" }, "Secret detected: 17"));

    expect(screen.getByText("17")).toBeInTheDocument();
  });
});
