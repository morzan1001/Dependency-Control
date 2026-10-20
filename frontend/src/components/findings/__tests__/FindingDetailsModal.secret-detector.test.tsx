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

describe("FindingDetailsModal secret locations", () => {
  it("shows the secret's file and line beside its other lines and commits without a scan context", () => {
    const locations = [
      { line: 9, commit: "a".repeat(40) },
      { line: 3, commit: "b".repeat(40) },
    ];
    renderModal(
      secretFinding({ detector: "2", detector_name: "AWS", line: 3, commit: "a".repeat(40), additional_locations: locations }, "Secret detected: AWS"),
    );

    expect(screen.getByText("File").nextElementSibling).toHaveTextContent("config.py");
    expect(screen.getByText("Location").nextElementSibling).toHaveTextContent("Line 3");
    expect(screen.getByText("Additional Locations")).toBeInTheDocument();
    expect(screen.getByText("Line 9")).toBeInTheDocument();
    expect(screen.getAllByText("Line 3")).toHaveLength(2);
    expect(screen.getByText("bbbbbbb")).toBeInTheDocument();
  });
});
