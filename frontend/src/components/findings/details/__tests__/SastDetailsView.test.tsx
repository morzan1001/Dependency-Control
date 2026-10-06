import { render, screen } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import type { Finding } from "@/types/scan";
import { SastDetailsView } from "../SastDetailsView";

const SPAN = { start: { line: 12, column: 5 }, end: { line: 14, column: 20 } };

function finding(type: "sast" | "iac", details: Record<string, unknown>): Finding {
  return {
    id: "f1",
    type,
    severity: "HIGH",
    component: "app/handlers.py",
    description: "eval() detected",
    scanners: ["opengrep"],
    found_in: [],
    aliases: [],
    waived: false,
    details,
  } as unknown as Finding;
}

describe("SastDetailsView location", () => {
  it("reads lines and columns from the scanner entry a SAST finding is stored with", () => {
    // The persisted shape: the scanner's own details sit under sast_findings, the wrapper keeps only file and line.
    const sast = finding("sast", {
      file: "app/handlers.py",
      line: SPAN.start.line,
      sast_findings: [{ id: "python.eval", scanner: "opengrep", severity: "HIGH", details: { rule_id: "python.eval", ...SPAN } }],
    });

    render(<SastDetailsView finding={sast} />);

    expect(screen.getByText("Line 12 - 14 (Col 5-20)")).toBeInTheDocument();
  });

  it("reads lines and columns from an IaC finding's own details", () => {
    render(<SastDetailsView finding={finding("iac", { rule_id: "kics-1", ...SPAN })} />);

    expect(screen.getByText("Line 12 - 14 (Col 5-20)")).toBeInTheDocument();
  });
});
