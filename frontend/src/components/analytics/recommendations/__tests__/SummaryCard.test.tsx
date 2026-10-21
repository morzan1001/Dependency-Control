import { render, screen } from "@testing-library/react";
import { describe, it, expect } from "vitest";

import { SummaryCard } from "../SummaryCard";
import type { RecommendationsResponse, RecommendationsSummary } from "@/types/analytics";

const READ = 10000;
const TOTAL = 42317;
const TRUNCATION_NOTE = /Reasoned over/i;

const EMPTY_SUMMARY: RecommendationsSummary = {
  base_image_updates: 0,
  direct_updates: 0,
  transitive_updates: 0,
  no_fix: 0,
  total_fixable_vulns: 0,
  total_unfixable_vulns: 0,
  secrets_to_rotate: 0,
  sast_issues: 0,
  iac_issues: 0,
  license_issues: 0,
  quality_issues: 0,
};

function makeResponse(overrides: Partial<RecommendationsResponse>): RecommendationsResponse {
  return {
    project_id: "p1",
    project_name: "demo",
    scan_id: "s1",
    total_findings: 0,
    findings_total: overrides.total_findings ?? 0,
    total_vulnerabilities: 0,
    recommendations: [],
    summary: EMPTY_SUMMARY,
    dependencies_read: TOTAL,
    dependencies_total: TOTAL,
    ...overrides,
  };
}

describe("SummaryCard dependency coverage", () => {
  it("says what the advice was reasoned over when the read was capped", () => {
    render(<SummaryCard data={makeResponse({ dependencies_read: READ })} />);

    expect(screen.getByText(TRUNCATION_NOTE)).toBeInTheDocument();
    expect(screen.getByText(new RegExp(TOTAL.toLocaleString()))).toBeInTheDocument();
  });

  it("stays quiet when the whole scan was read", () => {
    render(<SummaryCard data={makeResponse({})} />);

    expect(screen.queryByText(TRUNCATION_NOTE)).not.toBeInTheDocument();
  });
});

describe("SummaryCard findings coverage", () => {
  const FINDINGS_NOTE = /findings in this scan/;

  it("says what the advice was reasoned over when the findings read was capped", () => {
    render(<SummaryCard data={makeResponse({ total_findings: 100000, findings_total: 123456 })} />);

    expect(screen.getByText(FINDINGS_NOTE)).toHaveTextContent(
      `Reasoned over ${(100000).toLocaleString()} of ${(123456).toLocaleString()} findings in this scan.`,
    );
  });

  it("looks like the dependency notice beside it", () => {
    render(
      <SummaryCard data={makeResponse({ total_findings: 100000, findings_total: 123456, dependencies_read: READ })} />,
    );

    expect(screen.getByText(FINDINGS_NOTE).className).toBe(screen.getByText(/dependency rows in this scan/).className);
  });

  it("stays quiet when every finding was read", () => {
    render(<SummaryCard data={makeResponse({ total_findings: 12 })} />);

    expect(screen.queryByText(FINDINGS_NOTE)).not.toBeInTheDocument();
  });
});

describe("SummaryCard live threat intel", () => {
  it("says the advice rests on the scan's exploit signals when a live source could not be read", () => {
    render(<SummaryCard data={makeResponse({ threat_intel_unavailable: ["KEV"] })} />);

    expect(screen.getByText(/Live KEV data could not be read in full/)).toHaveTextContent(/stored at scan time/);
  });

  it("says only the EPSS scores come from the scan when EPSS alone could not be read", () => {
    render(<SummaryCard data={makeResponse({ threat_intel_unavailable: ["EPSS"] })} />);

    expect(screen.getByText(/Live EPSS data could not be read in full/)).toHaveTextContent(
      "Live EPSS data could not be read in full; this advice uses live KEV marks and the EPSS scores stored at scan time.",
    );
  });

  it("stays quiet when every live source answered", () => {
    render(<SummaryCard data={makeResponse({ threat_intel_unavailable: [] })} />);

    expect(screen.queryByText(/could not be read in full/)).not.toBeInTheDocument();
  });
});

describe("SummaryCard headline", () => {
  it("counts each finding once, since total_findings already holds secrets, SAST and IaC", () => {
    render(
      <SummaryCard
        data={makeResponse({
          total_findings: 10,
          total_vulnerabilities: 4,
          summary: { ...EMPTY_SUMMARY, secrets_to_rotate: 2, sast_issues: 3, iac_issues: 1 },
        })}
      />,
    );

    expect(screen.getByText(/^10 findings/)).toBeInTheDocument();
  });

  it("reports no issues when a scan has neither findings nor insights", () => {
    render(<SummaryCard data={makeResponse({})} />);

    expect(screen.getByText("No significant issues found")).toBeInTheDocument();
  });

  it("leads with the insights when a scan has no findings", () => {
    render(<SummaryCard data={makeResponse({ summary: { ...EMPTY_SUMMARY, fragmentation_issues: 2 } })} />);

    expect(screen.getByText("2 dependency insights found")).toBeInTheDocument();
  });
});

// Each tile's number sits right above its label.
function tile(label: string): { value: string | null; className: string } {
  const value = screen.getByText(label).previousElementSibling!;
  return { value: value.textContent, className: value.className };
}

describe("SummaryCard tiles", () => {
  it("shows all four vulnerability tiles, zeros included, whenever the scan has vulnerabilities", () => {
    render(
      <SummaryCard
        data={makeResponse({
          total_vulnerabilities: 3,
          summary: { ...EMPTY_SUMMARY, total_fixable_vulns: 3, direct_updates: 1, transitive_updates: 2 },
        })}
      />,
    );

    expect(screen.getByText("Vulnerabilities")).toBeInTheDocument();
    expect(tile("Fixable")).toEqual({ value: "3", className: "text-2xl font-bold text-success" });
    expect(tile("No Fix")).toEqual({ value: "0", className: "text-2xl font-bold text-gray-500" });
    expect(tile("Image Updates")).toEqual({ value: "0", className: "text-2xl font-bold text-blue-500" });
    expect(tile("Pkg Updates")).toEqual({ value: "3", className: "text-2xl font-bold text-purple-500" });
  });

  it("shows no vulnerability tiles for a scan without vulnerabilities", () => {
    render(<SummaryCard data={makeResponse({ summary: { ...EMPTY_SUMMARY, total_fixable_vulns: 3 } })} />);

    expect(screen.queryByText("Vulnerabilities")).not.toBeInTheDocument();
    expect(screen.queryByText("Fixable")).not.toBeInTheDocument();
  });

  it("shows only the non-zero other-finding tiles, and the section only when one is", () => {
    const { rerender } = render(
      <SummaryCard data={makeResponse({ summary: { ...EMPTY_SUMMARY, secrets_to_rotate: 2, iac_issues: 1 } })} />,
    );

    expect(screen.getByText("Other Security Findings")).toBeInTheDocument();
    expect(tile("Secrets")).toEqual({ value: "2", className: "text-2xl font-bold text-destructive" });
    expect(tile("IAC Issues")).toEqual({ value: "1", className: "text-2xl font-bold text-indigo-500" });
    expect(screen.queryByText("SAST Issues")).not.toBeInTheDocument();
    expect(screen.queryByText("License Issues")).not.toBeInTheDocument();

    rerender(<SummaryCard data={makeResponse({ summary: { ...EMPTY_SUMMARY, sast_issues: 5, license_issues: 4 } })} />);
    expect(tile("SAST Issues")).toEqual({ value: "5", className: "text-2xl font-bold text-cyan-500" });
    expect(tile("License Issues")).toEqual({ value: "4", className: "text-2xl font-bold text-pink-500" });

    rerender(<SummaryCard data={makeResponse({})} />);
    expect(screen.queryByText("Other Security Findings")).not.toBeInTheDocument();
  });

  it("counts the crypto issues among the other security findings, in the crypto colour", () => {
    const { rerender } = render(<SummaryCard data={makeResponse({ summary: { ...EMPTY_SUMMARY, crypto_issues: 6 } })} />);

    expect(screen.getByText("Other Security Findings")).toBeInTheDocument();
    expect(tile("Crypto Issues")).toEqual({ value: "6", className: "text-2xl font-bold text-teal-500" });

    rerender(<SummaryCard data={makeResponse({ summary: { ...EMPTY_SUMMARY, crypto_issues: 0 } })} />);
    expect(screen.queryByText("Crypto Issues")).not.toBeInTheDocument();
  });

  it("shows only the non-zero health tiles, and the section only when one is", () => {
    const { rerender } = render(<SummaryCard data={makeResponse({ summary: { ...EMPTY_SUMMARY, trend_alerts: 4 } })} />);

    expect(screen.getByText("Health & Insights")).toBeInTheDocument();
    expect(tile("Trend Alerts")).toEqual({ value: "4", className: "text-2xl font-bold text-rose-500" });
    expect(screen.queryByText("Fragmentation")).not.toBeInTheDocument();
    expect(screen.queryByText("Cross-Project")).not.toBeInTheDocument();

    rerender(
      <SummaryCard data={makeResponse({ summary: { ...EMPTY_SUMMARY, fragmentation_issues: 2, cross_project_issues: 1 } })} />,
    );
    expect(tile("Fragmentation")).toEqual({ value: "2", className: "text-2xl font-bold text-violet-500" });
    expect(tile("Cross-Project")).toEqual({ value: "1", className: "text-2xl font-bold text-sky-500" });
    expect(screen.getByText("3 dependency insights found")).toBeInTheDocument();

    rerender(<SummaryCard data={makeResponse({})} />);
    expect(screen.queryByText("Health & Insights")).not.toBeInTheDocument();
  });

  it("leads the health tiles with the outdated packages and counts them as insights", () => {
    render(<SummaryCard data={makeResponse({ summary: { ...EMPTY_SUMMARY, outdated_deps: 7, trend_alerts: 1 } })} />);

    expect(tile("Outdated")).toEqual({ value: "7", className: "text-2xl font-bold text-amber-600" });
    const health = screen.getByText("Outdated").parentElement!.parentElement!;
    expect(Array.from(health.children, (card) => card.lastElementChild!.textContent)).toEqual(["Outdated", "Trend Alerts"]);
    expect(screen.getByText("8 dependency insights found")).toBeInTheDocument();
  });

  it("lays out every tile the same way", () => {
    render(<SummaryCard data={makeResponse({ summary: { ...EMPTY_SUMMARY, secrets_to_rotate: 2 } })} />);

    const card = screen.getByText("Secrets").parentElement!;
    expect(card.className).toBe("text-center p-3 bg-muted rounded-lg");
    expect(card.parentElement!.className).toBe("grid grid-cols-2 md:grid-cols-4 gap-3");
    expect(screen.getByText("Secrets").className).toBe("text-xs text-muted-foreground");
    expect(screen.getByText("Other Security Findings").className).toBe("text-sm font-medium mb-2 flex items-center gap-2");
  });
});
