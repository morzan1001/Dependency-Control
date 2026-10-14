import { fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { describe, it, expect, vi } from "vitest";

import type { Finding } from "@/types/scan";
import type { ScanContext } from "../details/SastDetailsView";

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

const NVD = "https://nvd.nist.gov/vuln/detail/";

function renderModal(shown: Finding, props: { scanContext?: ScanContext; onSelectFinding?: (id: string) => void } = {}) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <FindingDetailsModal finding={shown} onClose={() => {}} projectId="p1" {...props} />
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

describe("FindingDetailsModal advisory details", () => {
  it("counts the advisories of a package with more than one", () => {
    renderModal(finding({ details: { vulnerabilities: [{ id: "CVE-2024-1" }, { id: "CVE-2024-2" }] } }));

    expect(screen.getByText("Found 2 vulnerabilities in lodash")).toBeInTheDocument();
  });

  it("links a CVE to NVD, a GHSA to its stored advisory page and to the CVE it resolves to", () => {
    const ghsaPage = "https://github.example.com/advisories/GHSA-aaaa-bbbb-cccc";
    renderModal(
      finding({
        details: {
          vulnerabilities: [
            { id: "CVE-2024-1" },
            { id: "GHSA-aaaa-bbbb-cccc", github_advisory_url: ghsaPage, resolved_cve: "CVE-2024-2" },
          ],
        },
      }),
    );

    expect(screen.getByRole("link", { name: "CVE-2024-1" })).toHaveAttribute("href", `${NVD}CVE-2024-1`);
    expect(screen.getByRole("link", { name: "GHSA-aaaa-bbbb-cccc" })).toHaveAttribute("href", ghsaPage);
    expect(screen.getByRole("link", { name: "CVE-2024-2" })).toHaveAttribute("href", `${NVD}CVE-2024-2`);
    for (const link of screen.getAllByRole("link")) {
      expect(link).toHaveAttribute("target", "_blank");
      expect(link).toHaveAttribute("rel", "noopener noreferrer");
    }
  });

  it("links a GHSA without a stored page to GitHub's advisory database", () => {
    renderModal(finding({ details: { vulnerabilities: [{ id: "GHSA-aaaa-bbbb-cccc" }] } }));

    expect(screen.getByRole("link", { name: "GHSA-aaaa-bbbb-cccc" })).toHaveAttribute(
      "href",
      "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
    );
  });

  it("names an advisory without a public page without linking it", () => {
    renderModal(finding({ details: { vulnerabilities: [{ id: "PYSEC-2024-1", aliases: ["CVE-2024-3", "OSV-2024-9"] }] } }));

    expect(screen.getByText("PYSEC-2024-1")).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "PYSEC-2024-1" })).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: "CVE-2024-3" })).toHaveAttribute("href", `${NVD}CVE-2024-3`);
    expect(screen.getByText("OSV-2024-9")).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "OSV-2024-9" })).not.toBeInTheDocument();
  });

  it("rates an advisory by its own severity and falls back to the finding's", () => {
    renderModal(finding({ severity: "HIGH", details: { vulnerabilities: [{ id: "CVE-2024-1", severity: "LOW" }, { id: "CVE-2024-2" }] } }));

    expect(screen.getAllByText("LOW")).toHaveLength(1);
    expect(screen.getAllByText("HIGH")).toHaveLength(2);
  });

  it.each(["NEGLIGIBLE", "UNKNOWN"])("styles a %s advisory like the header styles the finding", (severity) => {
    renderModal(finding({ severity: severity as Finding["severity"], details: { vulnerabilities: [{ id: "CVE-2024-1" }] } }));

    const [header, entry] = screen.getAllByText(severity);
    expect(entry.className).toBe(header.className);
  });

  it("dims an unlikely EPSS score as the analytics tables do", () => {
    renderModal(finding({ details: { vulnerabilities: [{ id: "CVE-2024-1", epss_score: 0.005 }] } }));

    expect(screen.getByText("EPSS: 0.50%")).toHaveClass("text-muted-foreground");
  });

  it("shows the scores, dates, weaknesses and scanners of an advisory, falling back to the finding's", () => {
    renderModal(
      finding({
        details: {
          cvss_score: 7.5,
          cvss_vector: "CVSS:3.1/AV:N",
          cwe_ids: ["CWE-79"],
          vulnerabilities: [
            {
              id: "CVE-2024-1",
              epss_score: 0.25,
              epss_percentile: 97,
              details: { published_date: "2024-05-01" },
              scanners: ["grype"],
              references: ["https://example.com/a", "https://example.com/b"],
            },
          ],
        },
      }),
    );

    expect(screen.getByText("CVSS: 7.5")).toBeInTheDocument();
    expect(screen.getByText("CVSS:3.1/AV:N")).toBeInTheDocument();
    expect(screen.getByText("EPSS: 25.00%")).toHaveClass("text-severity-critical");
    expect(screen.getByText("(Top 3%)")).toBeInTheDocument();
    expect(screen.getByText("Published:")).toBeInTheDocument();
    expect(screen.getByText("CWE-79")).toBeInTheDocument();
    expect(screen.getByText("grype")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /References \(2\)/ })).toBeInTheDocument();
  });
});

describe("FindingDetailsModal secret details", () => {
  const secret = (details: Record<string, unknown>) =>
    finding({ id: "SECRET-1", type: "secret", severity: "CRITICAL", component: "config/settings.py", scanners: ["trufflehog"], details });

  it("tells the user to rotate a live credential that only the history holds", () => {
    renderModal(secret({ verified: true, in_current_tree: false }));

    expect(screen.getByText(/Live credential found only in git history/)).toBeInTheDocument();
    expect(screen.getByText("Verified Live")).toBeInTheDocument();
    expect(screen.getByText("Only in history")).toBeInTheDocument();
  });

  it("marks an unverified secret that the current code still holds", () => {
    renderModal(secret({ verified: false, in_current_tree: true }));

    expect(screen.getByText("Remove the secret from the code and rotate the credential.")).toBeInTheDocument();
    expect(screen.getByText("Unverified")).toBeInTheDocument();
    expect(screen.getByText("In current code")).toBeInTheDocument();
  });

  it("shows the origin commit with line and date and the redacted value", () => {
    renderModal(secret({ commit: "0123456789abcdef", line: 42, commit_timestamp: "2026-01-02T03:04:05Z", redacted: "AKIA****" }));

    expect(screen.getByText("0123456")).toHaveTextContent("0123456:42");
    expect(screen.getByText("Origin Commit").parentElement).toHaveTextContent(/2026/);
    expect(screen.getByText("AKIA****")).toBeInTheDocument();
  });

  it("places the secret in its file only when the scan's source is known", () => {
    const shown = secret({ line: 42 });
    const { unmount } = renderModal(shown);
    expect(screen.queryByText("Line 42")).not.toBeInTheDocument();
    unmount();

    renderModal(shown, { scanContext: { projectUrl: "https://gitlab.example.com/acme/app", commitHash: "abc1234" } });

    expect(screen.getByText("Line 42")).toBeInTheDocument();
  });
});

describe("FindingDetailsModal related finding badges", () => {
  it.each([
    ["OUTDATED-lodash", "Outdated: lodash", "text-blue-700"],
    ["QUALITY:lodash:4.17.20", "Quality: lodash (4.17.20)", "text-yellow-700"],
    ["LIC-MIT", "License: MIT", "text-purple-700"],
    ["EOL-spring-boot-2", "EOL: spring-boot-2", "text-orange-700"],
    ["lodash:4.17.21", "Vuln: lodash (4.17.21)", "text-red-700"],
    ["org.apache:log4j-core:2.14.1", "org.apache:log4j-core:2.14.1", "text-red-700"],
    ["SAST-2", "SAST-2", "text-gray-700"],
  ])("names %s as %s and opens it on click", (id, label, colour) => {
    const onSelectFinding = vi.fn();
    renderModal(finding({ related_findings: [id, id] }), { onSelectFinding });

    const badge = screen.getByText(label);
    fireEvent.click(badge);

    expect(badge).toHaveClass(colour);
    expect(onSelectFinding).toHaveBeenCalledWith(id);
  });
});

describe("FindingDetailsModal details by type", () => {
  it("lists the own details of a finding type without a dedicated view", () => {
    renderModal(finding({ type: "malware", details: { explanation: "typosquat of lodash" } }));

    expect(screen.getByText("Additional Details")).toBeInTheDocument();
    expect(screen.getByText("typosquat of lodash")).toBeInTheDocument();
  });

  it("shows an end-of-life finding's banners beside its own details", () => {
    renderModal(finding({ type: "eol", details: { eol_info: { is_eol: true, cycle: "4" }, explanation: "support ended" } }));

    expect(screen.getByText("End of Life")).toBeInTheDocument();
    expect(screen.getByText("Additional Details")).toBeInTheDocument();
    expect(screen.getByText("support ended")).toBeInTheDocument();
  });

  it.each(["vulnerability", "secret", "sast", "iac", "license", "quality", "outdated", "system_warning"])(
    "keeps the generic details list off a %s finding",
    (type) => {
      renderModal(finding({ type: type as Finding["type"], details: { explanation: "generic" } }));

      expect(screen.queryByText("Additional Details")).not.toBeInTheDocument();
    },
  );

  it("reports a scanner failure with its error details", () => {
    renderModal(finding({ type: "system_warning", description: "trivy timed out", details: { error_details: "exit status 124" } }));

    expect(screen.getByText("Scanner Failure")).toBeInTheDocument();
    expect(screen.getAllByText("trivy timed out")).toHaveLength(2);
    expect(screen.getByText("exit status 124")).toBeInTheDocument();
  });

  it.each(["vulnerability", "sast", "iac"])("leaves a %s finding's description to its own view", (type) => {
    renderModal(finding({ type: type as Finding["type"], description: "finding-level text" }));

    expect(screen.queryByText("Description")).not.toBeInTheDocument();
  });

  it("describes a finding whose view does not", () => {
    renderModal(finding({ type: "license", description: "GPL in a proprietary app" }));

    expect(screen.getByText("Description")).toBeInTheDocument();
    expect(screen.getByText("GPL in a proprietary app")).toBeInTheDocument();
  });
});
