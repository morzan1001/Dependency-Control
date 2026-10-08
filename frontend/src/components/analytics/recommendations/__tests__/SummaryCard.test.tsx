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

  it("lays out every tile the same way", () => {
    render(<SummaryCard data={makeResponse({ summary: { ...EMPTY_SUMMARY, secrets_to_rotate: 2 } })} />);

    const card = screen.getByText("Secrets").parentElement!;
    expect(card.className).toBe("text-center p-3 bg-muted rounded-lg");
    expect(card.parentElement!.className).toBe("grid grid-cols-2 md:grid-cols-4 gap-3");
    expect(screen.getByText("Secrets").className).toBe("text-xs text-muted-foreground");
    expect(screen.getByText("Other Security Findings").className).toBe("text-sm font-medium mb-2 flex items-center gap-2");
  });
});
