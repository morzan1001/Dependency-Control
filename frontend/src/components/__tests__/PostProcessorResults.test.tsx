import { render, screen } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import { EPSSKEVResults, ReachabilityResults } from "../PostProcessorResults";

const baseData = {
  total_vulnerabilities: 100,
  epss_enriched: 100,
  kev_matches: 0,
  kev_ransomware: 0,
  epss_scores: { high: 0, medium: 0, low: 0 },
  exploit_maturity: {
    weaponized: 1,
    active: 0,
    high: 0,
    medium: 0,
    low: 0,
    unknown: 0,
  },
  avg_epss_score: null,
  max_epss_score: null,
  avg_risk_score: null,
  max_risk_score: null,
  kev_details: [],
  high_risk_cves: [],
  timestamp: "2026-07-07T00:00:00Z",
};

describe("EPSSKEVResults exploit maturity bars", () => {
  it("colors the Progress indicator (not the track) for each maturity", () => {
    render(<EPSSKEVResults data={baseData} />);

    // Only the weaponized row (count > 0) is rendered, giving one progress bar.
    const bars = screen.getAllByRole("progressbar");
    expect(bars).toHaveLength(1);

    const cls = bars[0].getAttribute("class") ?? "";
    // Color must target the moving Indicator via the child selector, else the whole track is colored.
    expect(cls).toContain("[&>div]:bg-red-600");
    expect(cls).not.toMatch(/(^|\s)bg-red-600(\s|$)/);
  });
});

describe("EPSSKEVResults risk-score tile label", () => {
  it("does not reuse the dashboard's 'Avg Risk Score' wording", () => {
    // Both tiles read from a field literally named avg_risk_score, but this one averages
    // per-CVE EPSS/KEV threat scores (prod: ~31) while the dashboard averages projects'
    // saturating exposure scores (prod: 42.8). Identical labels invite a false comparison.
    render(<EPSSKEVResults data={{ ...baseData, avg_risk_score: 30.9, max_risk_score: 88.0 }} />);

    expect(screen.getByText("Avg Threat Score")).toBeInTheDocument();
    expect(screen.queryByText("Avg Risk Score")).toBeNull();
  });
});

const reachabilityData = {
  total_vulnerabilities: 60,
  analyzed: 60,
  reachability_levels: { confirmed: 5, likely: 37, unknown: 0, unreachable: 18 },
  callgraph_info: [
    { language: "python", total_modules: 120, total_imports: 340, coverage_modules: 87 },
  ],
  languages: ["python"],
  reachable_vulnerabilities: Array.from({ length: 30 }, (_, i) => ({
    cve: `CVE-2026-${i}`,
    component: "pkg",
    version: "1.0.0",
    severity: "HIGH",
    reachability_level: "likely",
    reachable_functions: [],
  })),
  unreachable_vulnerabilities: Array.from({ length: 30 }, (_, i) => ({
    cve: `CVE-2025-${i}`,
    component: "pkg",
    version: "1.0.0",
    severity: "LOW",
    reachability_level: "unreachable",
    reachable_functions: [],
  })),
  reachable_total: 42,
  unreachable_total: 18,
  timestamp: "2026-08-30T00:00:00Z",
};

describe("ReachabilityResults truncated lists", () => {
  it("counts the population, not the server-capped list", () => {
    render(<ReachabilityResults data={reachabilityData} />);

    expect(screen.getByText("Reachable Vulnerabilities (42)")).toBeInTheDocument();
    expect(screen.getByText("Showing 15 of 42")).toBeInTheDocument();
  });

  it("omits the truncation note when everything is shown", () => {
    const data = {
      ...reachabilityData,
      unreachable_vulnerabilities: reachabilityData.unreachable_vulnerabilities.slice(0, 4),
      unreachable_total: 4,
    };
    render(<ReachabilityResults data={data} />);

    expect(screen.getByText("Unreachable Vulnerabilities (4)")).toBeInTheDocument();
    expect(screen.queryByText(/Showing 4 of/)).toBeNull();
  });

  it("reports the coverage universe of each callgraph", () => {
    render(<ReachabilityResults data={reachabilityData} />);

    expect(screen.getByText("Packages in coverage")).toBeInTheDocument();
    expect(screen.getByText("87")).toBeInTheDocument();
  });
});
