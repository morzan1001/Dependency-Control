import { render, screen } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import type { ReachabilityInfo } from "@/types/scan";
import { ReachabilityEvidence } from "../ReachabilityEvidence";

const LOCATIONS_KEPT = 10;
const IMPORT_SITES = 40;

const sample = (overrides: Partial<ReachabilityInfo> = {}): ReachabilityInfo => ({
  is_reachable: true,
  analysis_level: "import",
  confidence_score: 0.5,
  message: `Package is imported in ${IMPORT_SITES} file(s). Could not determine specific vulnerable functions.`,
  import_locations: Array.from({ length: LOCATIONS_KEPT }, (_, i) => `src/mod_${i}.py`),
  import_location_count: IMPORT_SITES,
  ...overrides,
});

describe("ReachabilityEvidence", () => {
  it("renders the enrichment's sentence, which is the only place the import count is stated", () => {
    render(<ReachabilityEvidence reachability={sample()} />);

    expect(screen.getByText(new RegExp(`imported in ${IMPORT_SITES} file`))).toBeInTheDocument();
  });

  it("says how many import sites the location list was cut from", () => {
    render(<ReachabilityEvidence reachability={sample()} />);

    expect(screen.getByText(`showing ${LOCATIONS_KEPT} of ${IMPORT_SITES}`)).toBeInTheDocument();
  });

  it("says nothing about a cut when every import site is listed", () => {
    render(
      <ReachabilityEvidence
        reachability={sample({ import_locations: ["src/only.py"], import_location_count: 1 })}
      />,
    );

    expect(screen.queryByText(/showing \d+ of/)).toBeNull();
  });
});
