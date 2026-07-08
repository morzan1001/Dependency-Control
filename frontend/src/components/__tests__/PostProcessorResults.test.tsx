import { render, screen } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import { EPSSKEVResults } from "../PostProcessorResults";

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
