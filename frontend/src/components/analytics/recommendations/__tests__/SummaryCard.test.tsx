import { render, screen } from "@testing-library/react";
import { describe, it, expect } from "vitest";

import { SummaryCard } from "../SummaryCard";
import type { RecommendationsResponse } from "@/types/analytics";

const READ = 10000;
const TOTAL = 42317;
const TRUNCATION_NOTE = /Reasoned over/i;

function makeResponse(overrides: Partial<RecommendationsResponse>): RecommendationsResponse {
  return {
    project_id: "p1",
    project_name: "demo",
    scan_id: "s1",
    total_findings: 0,
    total_vulnerabilities: 0,
    recommendations: [],
    summary: {},
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
