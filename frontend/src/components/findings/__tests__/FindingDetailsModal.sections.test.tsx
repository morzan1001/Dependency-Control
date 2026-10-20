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

describe("FindingDetailsModal header", () => {
  it("names the finding's type with the findings table's badge, like the other types beside it", () => {
    renderModal(finding({ type: "crypto_weak_algorithm", details: { additional_finding_types: [{ type: "outdated", severity: "INFO" }] } }));

    expect(screen.getByText("Weak algorithm")).toHaveClass("wrap-anywhere");
    expect(screen.queryByText("crypto_weak_algorithm")).not.toBeInTheDocument();
    expect(screen.getByText("Outdated")).toHaveClass("wrap-anywhere");
  });

  it("names the other types only as header badges, not again as raw chips under Additional Details", () => {
    renderModal(finding({ type: "crypto_weak_algorithm", details: { technology: ["openssl"], additional_finding_types: [{ type: "outdated", severity: "INFO" }] } }));

    expect(screen.getByText("openssl")).toBeInTheDocument();
    expect(screen.queryByText("Additional Finding Types")).not.toBeInTheDocument();
    expect(screen.queryByText("[object Object]")).not.toBeInTheDocument();
  });
});

describe("FindingDetailsModal fixed version", () => {
  it("shows a fix version in the success colour", () => {
    renderModal(finding({ details: { fixed_version: "4.17.21" } }));

    expect(screen.getByText("4.17.21")).toHaveClass("text-success");
  });

  it("says no fix is known in the neutral colour, like the findings tables, instead of a green None", () => {
    renderModal(finding({ details: {} }));

    expect(screen.queryByText("None")).not.toBeInTheDocument();
    expect(screen.getByText("No known fix")).toHaveClass("text-muted-foreground");
    expect(screen.getByText("No known fix")).not.toHaveClass("text-success");
  });

  it("says no fix is known on an advisory without one instead of Fixed in: None", () => {
    renderModal(finding({ details: { vulnerabilities: [{ id: "CVE-2024-1", fixed_version: "4.17.21" }, { id: "CVE-2024-2" }] } }));

    expect(screen.queryByText("None")).not.toBeInTheDocument();
    expect(screen.getByText("4.17.21").parentElement).toHaveTextContent("Fixed in: 4.17.21");
    expect(screen.getByText("No known fix")).toHaveClass("text-muted-foreground");
  });

  it("says the fix varies by advisory when no single version fixes the finding but an advisory names one", () => {
    renderModal(finding({ details: { vulnerabilities: [{ id: "CVE-2024-1", fixed_version: "4.17.21" }, { id: "CVE-2024-2", fixed_version: "5.0.1" }] } }));

    expect(screen.getByText("Varies by advisory")).toHaveClass("text-muted-foreground");
    expect(screen.queryByText("No known fix")).not.toBeInTheDocument();
  });
});

describe("FindingDetailsModal severity", () => {
  it("colours the finding's and each advisory's severity like the findings table row", () => {
    renderModal(finding({ severity: "MEDIUM", details: { vulnerabilities: [{ id: "CVE-2024-1", severity: "LOW" }] } }));

    expect(screen.getByText("MEDIUM")).toHaveClass("bg-severity-medium");
    expect(screen.getByText("LOW")).toHaveClass("bg-severity-low");
  });
});

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

  it("links a CVE that absorbed its GitHub advisory once, to NVD", () => {
    renderModal(
      finding({
        details: {
          vulnerabilities: [
            { id: "CVE-2024-1", resolved_cve: "CVE-2024-1", github_advisory_url: "https://github.com/advisories/GHSA-aaaa-bbbb-cccc" },
          ],
        },
      }),
    );

    const links = screen.getAllByRole("link", { name: "CVE-2024-1" });
    expect(links).toHaveLength(1);
    expect(links[0]).toHaveAttribute("href", `${NVD}CVE-2024-1`);
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
    expect(screen.getByText("Aliases:")).toBeInTheDocument();
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
    ["OUTDATED-lodash", "Outdated: lodash", "yellow"],
    ["QUALITY:lodash:4.17.20", "Quality: lodash (4.17.20)", "green"],
    ["QUALITY:org.apache.logging.log4j:log4j-core:2.14.1", "Quality: org.apache.logging.log4j:log4j-core:2.14.1", "green"],
    ["LIC-MIT", "License: MIT", "purple"],
    ["EOL-spring-boot-2", "EOL: spring-boot-2", "orange"],
    ["lodash:4.17.21", "Vuln: lodash (4.17.21)", "red"],
    ["org.apache:log4j-core:2.14.1", "org.apache:log4j-core:2.14.1", "red"],
  ])("names %s as %s in its type badge's %s, in both themes, and opens it on click", (id, label, hue) => {
    const onSelectFinding = vi.fn();
    renderModal(finding({ related_findings: [id, id] }), { onSelectFinding });

    const badge = screen.getByText(label);
    fireEvent.click(badge);

    expect(badge).toHaveClass(`text-${hue}-700`, `dark:text-${hue}-400`, `dark:bg-${hue}-950/50`);
    expect(onSelectFinding).toHaveBeenCalledWith(id);
  });

  it("leaves a related finding of unknown type in the neutral outline and opens it on click", () => {
    const onSelectFinding = vi.fn();
    renderModal(finding({ related_findings: ["SAST-2"] }), { onSelectFinding });

    const badge = screen.getByText("SAST-2");
    fireEvent.click(badge);

    expect(badge.className).not.toMatch(/\bbg-[a-z]+-50\b/);
    expect(onSelectFinding).toHaveBeenCalledWith("SAST-2");
  });
});

describe("FindingDetailsModal details by type", () => {
  it("lists the own details of a finding type without a dedicated view", () => {
    renderModal(finding({ type: "malware", details: { explanation: "typosquat of lodash" } }));

    expect(screen.getByText("Additional Details")).toBeInTheDocument();
    expect(screen.getByText("typosquat of lodash")).toBeInTheDocument();
  });

  it("writes each of several quality issues' severity in the pill colours and with the icon of that severity", () => {
    renderModal(
      finding({
        type: "quality",
        details: {
          quality_issues: [
            { id: "Q-1", type: "maintainer_risk", severity: "MEDIUM", details: {} },
            { id: "Q-2", type: "scorecard", severity: "UNKNOWN", details: {} },
          ],
        },
      }),
    );

    expect(screen.getByText("MEDIUM")).toHaveClass("bg-severity-medium", "text-severity-medium-foreground");
    expect(screen.getByText("UNKNOWN")).toHaveClass("bg-severity-unknown", "text-severity-unknown-foreground");
    expect(screen.getByText("MEDIUM").querySelector("svg")).not.toBeNull();
  });

  it("shows an end-of-life finding's banners beside its own details", () => {
    renderModal(finding({ type: "eol", details: { eol_info: { is_eol: true, cycle: "4" }, explanation: "support ended" } }));

    expect(screen.getByText("End of Life")).toBeInTheDocument();
    expect(screen.getByText("Additional Details")).toBeInTheDocument();
    expect(screen.getByText("support ended")).toBeInTheDocument();
  });

  it("counts an end-of-life finding's vulnerabilities in their banner only, not again as raw JSON under Additional Details", () => {
    renderModal(
      finding({
        type: "eol",
        details: { cycle: "3.2", vulnerability_info: { has_vulnerabilities: true, vuln_count: 32, critical_count: 5, high_count: 14 } } as Finding["details"],
      }),
    );

    expect(screen.getByText("Has Vulnerabilities")).toBeInTheDocument();
    expect(screen.getByText("3.2")).toBeInTheDocument();
    expect(screen.queryByText("Vulnerability Info")).not.toBeInTheDocument();
  });

  it("labels an end-of-life finding's LTS flag and EOL date in capitals, like the EOL badge above them", () => {
    renderModal(finding({ type: "eol", details: { cycle: "3.2", lts: true, eol_date: "2024-04-01" } as Finding["details"] }));

    expect(screen.getByText("LTS")).toBeInTheDocument();
    expect(screen.getByText("EOL Date")).toBeInTheDocument();
  });

  it("lists every rule a crypto asset matched with its fields, not as [object Object]", () => {
    const rule = (rule_id: string, policy_source: string) => ({ rule_id, rule_name: `${rule_id} name`, policy_source, severity: "HIGH" });
    renderModal(
      finding({
        type: "crypto_weak_key",
        details: {
          bom_ref: "sha-79c0",
          rule_id: "nist-131a-rsa-min-2048",
          matched_rules: [rule("nist-131a-rsa-min-2048", "nist-sp-800-131a"), rule("bsi-02102-rsa-min-3000", "bsi-tr-02102")],
        } as Finding["details"],
      }),
    );

    expect(screen.queryByText("[object Object]")).not.toBeInTheDocument();
    expect(screen.getByText(/bsi-02102-rsa-min-3000 name/)).toBeInTheDocument();
    expect(screen.getByText("BOM Ref")).toBeInTheDocument();
    expect(screen.getByText("Rule ID")).toBeInTheDocument();
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

  it("shows each failure of a scanner with its source and details, not only the first", () => {
    const errors = [
      { source: "SBOM #1", message: "Scanner 'trivy' failed: timed out", error_details: "exit status 124" },
      { source: "SBOM #2", message: "Scanner 'trivy' failed: bad report", error_details: { code: "E_JSON", message: "unexpected token" } },
    ];
    renderModal(
      finding({
        type: "system_warning",
        description: errors.map((error) => error.message).join("; "),
        details: { error_details: "exit status 124", errors },
      }),
    );

    expect(screen.getByText("SBOM #1")).toBeInTheDocument();
    expect(screen.getByText("SBOM #2")).toBeInTheDocument();
    expect(screen.getByText("Scanner 'trivy' failed: bad report")).toBeInTheDocument();
    expect(screen.getByText("exit status 124")).toBeInTheDocument();
    expect(screen.getByText(/unexpected token/)).toBeInTheDocument();
  });

  it("leaves a single failure's message to the banner above it", () => {
    const error = { source: "System: trivy", message: "Scanner 'trivy' failed: timed out", error_details: "exit status 124" };
    renderModal(finding({ type: "system_warning", description: error.message, details: { error_details: "exit status 124", errors: [error] } }));

    expect(screen.getByText("System: trivy")).toBeInTheDocument();
    expect(screen.getAllByText(error.message)).toHaveLength(2);
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

describe("FindingDetailsModal footer", () => {
  it("spaces Close apart like every dialog footer, without a gap of its own", () => {
    renderModal(finding({}));

    const footer = screen.getByText("Close", { selector: "button:not(.absolute)" }).parentElement;
    expect(footer).toHaveClass("gap-2");
    expect(footer).not.toHaveClass("sm:gap-0");
  });
});

describe("FindingDetailsModal on a phone", () => {
  it("breaks a long component, version and fix anywhere, so none runs under the column beside it", () => {
    renderModal(finding({
      component: "org.apache.logging.log4j:log4j-core",
      version: "2.14.1-SNAPSHOT+build.20261014",
      details: { fixed_version: "2.17.1-hotfix-for-the-jndi-lookup" },
    }));

    expect(screen.getByText("org.apache.logging.log4j:log4j-core")).toHaveClass("wrap-anywhere");
    expect(screen.getByText("2.14.1-SNAPSHOT+build.20261014")).toHaveClass("wrap-anywhere");
    expect(screen.getByText("2.17.1-hotfix-for-the-jndi-lookup")).toHaveClass("wrap-anywhere");
  });
});

describe("FindingDetailsModal advisory description", () => {
  it("sets an advisory's headings apart from its text, like the chat and a SAST rule", () => {
    renderModal(finding({
      id: "CVE-2021-44228",
      details: { vulnerabilities: [{ id: "CVE-2021-44228", severity: "CRITICAL", description: "### Impact\n\nRemote code execution." }] },
    }));

    expect(screen.getByRole("heading", { name: "Impact" })).toHaveClass("font-semibold");
    expect(screen.getByText("Remote code execution.")).not.toHaveClass("font-semibold");
  });

  it("ranks an advisory's headings below the dialog's h4 sections", () => {
    renderModal(finding({
      id: "CVE-2021-44228",
      details: { vulnerabilities: [{ id: "CVE-2021-44228", severity: "CRITICAL", description: "# Summary\n\n## Impact\n\nRemote code execution." }] },
    }));

    expect(screen.getByRole("heading", { level: 5, name: "Summary" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { level: 6, name: "Impact" })).toBeInTheDocument();
  });

  it("shows an advisory's list with bullets, like the chat and a SAST rule", () => {
    renderModal(finding({
      id: "CVE-2021-44228",
      details: { vulnerabilities: [{ id: "CVE-2021-44228", severity: "CRITICAL", description: "Affected:\n\n- log4j-core\n- log4j-api" }] },
    }));

    expect(screen.getByRole("list")).toHaveClass("list-disc");
  });
});
