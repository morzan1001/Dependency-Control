import { render, screen } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import { ThreatIntelligenceDashboard } from "../ThreatIntelligenceDashboard";

const threatIntel = {
  kev_count: 0,
  kev_ransomware_count: 0,
  high_epss_count: 0,
  medium_epss_count: 0,
  avg_epss_score: null,
  max_epss_score: null,
  weaponized_count: 0,
  active_exploitation_count: 0,
};

function makeStats(prioritized: {
  total: number;
  actionable_total?: number;
  deprioritized_count: number;
}) {
  return {
    critical: 0,
    high: 2,
    medium: 0,
    low: 0,
    risk_score: 21.1,
    threat_intel: threatIntel,
    prioritized: {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      actionable_critical: 0,
      actionable_high: 0,
      actionable_total: 0,
      ...prioritized,
    },
  };
}

describe("ThreatIntelligenceDashboard noise reduction", () => {
  it("uses the vulnerability-only total as denominator and clamps at 100%", () => {
    // Stale stored stats can still hold deprioritized > total; the badge must never exceed 100%.
    render(<ThreatIntelligenceDashboard stats={makeStats({ total: 2, deprioritized_count: 81 })} />);
    expect(screen.getByText(/100% noise reduction/)).toBeInTheDocument();
    expect(screen.queryByText(/4050%/)).not.toBeInTheDocument();
  });

  it("shows no reduction badge when the scan has no vulnerabilities", () => {
    render(<ThreatIntelligenceDashboard stats={makeStats({ total: 0, deprioritized_count: 0 })} />);
    expect(screen.queryByText(/noise reduction/)).not.toBeInTheDocument();
  });
});
