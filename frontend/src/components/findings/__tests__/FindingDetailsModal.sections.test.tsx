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

function finding(overrides: Partial<Finding>): Finding {
  return {
    id: "lodash:4.17.20",
    type: "vulnerability",
    severity: "HIGH",
    component: "lodash",
    version: "4.17.20",
    description: "",
    scanners: ["trivy"],
    found_in: [],
    aliases: [],
    waived: false,
    details: {},
    ...overrides,
  } as Finding;
}

function renderModal(shown: Finding) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <FindingDetailsModal finding={shown} onClose={() => {}} projectId="p1" />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("FindingDetailsModal vulnerability entries", () => {
  it("describes an advisory by its own text, never by the finding's", () => {
    renderModal(
      finding({
        description: "finding-level text",
        details: { vulnerabilities: [{ id: "CVE-2024-1", description: "advisory text" }, { id: "CVE-2024-2" }] },
      }),
    );

    expect(screen.getByText("advisory text")).toBeInTheDocument();
    expect(screen.getByText("No description available.")).toBeInTheDocument();
    expect(screen.queryByText("finding-level text")).not.toBeInTheDocument();
  });

  it("dates a known-exploited advisory and flags its ransomware use", () => {
    renderModal(
      finding({
        details: {
          vulnerabilities: [{ id: "CVE-2024-1", in_kev: true, kev_ransomware_use: true, kev_date_added: "2024-03-01" }],
        },
      }),
    );

    expect(screen.getByText("Known Exploited")).toBeInTheDocument();
    expect(screen.getByText("Ransomware")).toBeInTheDocument();
    expect(screen.getByText(/since .*2024/)).toBeInTheDocument();
  });

  it("shows the finding's reachability verdict, symbols and evidence on each advisory", () => {
    renderModal(
      finding({
        details: {
          reachability: {
            is_reachable: true,
            analysis_level: "symbol",
            confidence_score: 0.9,
            matched_symbols: ["merge", "template"],
            message: "Imported in app/main.py",
            import_locations: ["app/main.py:3"],
          },
          vulnerabilities: [{ id: "CVE-2024-1" }],
        },
      }),
    );

    expect(screen.getByText("Reachable (confirmed)")).toBeInTheDocument();
    expect(screen.getByText("symbol")).toBeInTheDocument();
    expect(screen.getByText("(90% confidence)")).toBeInTheDocument();
    expect(screen.getByText("Affected Symbols:")).toBeInTheDocument();
    expect(screen.getByText("template")).toBeInTheDocument();
    expect(screen.getByText("Imported in app/main.py")).toBeInTheDocument();
    expect(screen.getByText("app/main.py:3")).toBeInTheDocument();
  });

  it("shows no reachability for an advisory nothing analysed", () => {
    renderModal(finding({ details: { vulnerabilities: [{ id: "CVE-2024-1" }] } }));

    expect(screen.queryByText(/Reachab/)).not.toBeInTheDocument();
    expect(screen.queryByText("Affected Symbols:")).not.toBeInTheDocument();
  });
});

describe("FindingDetailsModal type sections", () => {
  it.each(["sast", "iac"])("lays out a %s finding with the code-scanner view", (type) => {
    renderModal(finding({ type: type as Finding["type"], details: { rule_id: "R-1" } }));

    expect(screen.getByText("Rule ID")).toBeInTheDocument();
    expect(screen.getByText("R-1")).toBeInTheDocument();
  });

  it.each(["outdated", "eol"])("shows the context banners of a %s finding", (type) => {
    renderModal(finding({ type: type as Finding["type"], details: { eol_info: { is_eol: true, cycle: "4" } } }));

    expect(screen.getByText("End of Life")).toBeInTheDocument();
  });
});

describe("FindingDetailsModal context banners", () => {
  it("names quality concerns on a finding that is not itself the quality aggregate", () => {
    renderModal(finding({ type: "license", details: { quality_info: { has_quality_issues: true, issue_count: 2 } } }));

    expect(screen.getByText("Quality Concerns")).toBeInTheDocument();
  });

  it("leaves the quality concerns to the aggregate's own issue list", () => {
    renderModal(
      finding({
        type: "quality",
        details: { quality_info: { has_quality_issues: true }, quality_issues: [{ id: "Q-1", type: "maintainer_risk", details: {} }] },
      }),
    );

    expect(screen.queryByText("Quality Concerns")).not.toBeInTheDocument();
  });

  it("shows the scorecard score and its critical issues", () => {
    renderModal(
      finding({
        details: {
          vulnerabilities: [{ id: "CVE-2024-1" }],
          scorecard_context: { overall_score: 2.5, critical_issues: ["Dangerous-Workflow"], project_url: "https://x.example" },
        },
      }),
    );

    expect(screen.getByText("OpenSSF Scorecard")).toBeInTheDocument();
    expect(screen.getByText("2.5/10")).toBeInTheDocument();
    expect(screen.getByText("Dangerous Workflow")).toBeInTheDocument();
  });
});
