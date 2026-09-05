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
