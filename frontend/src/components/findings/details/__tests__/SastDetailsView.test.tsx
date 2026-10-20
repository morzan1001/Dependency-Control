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

describe("SastDetailsView aggregated issues", () => {
  it("colours each scanner's severity like the findings table row", () => {
    const sast = finding("sast", {
      sast_findings: [
        { id: "python.eval", scanner: "opengrep", severity: "HIGH", details: SPAN },
        { id: "B307", scanner: "bandit", severity: "LOW", details: SPAN },
      ],
    });

    render(<SastDetailsView finding={sast} />);

    expect(screen.getByText("HIGH")).toHaveClass("bg-severity-high");
    expect(screen.getByText("LOW")).toHaveClass("bg-severity-low");
  });
});

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

  it("lists the rule's other hits in the file as additional locations, linked like the first", () => {
    const other = { start: { line: 12, column: 30 }, end: { line: 12, column: 36 } };
    const sast = finding("sast", {
      file: "app/handlers.py",
      line: 12,
      sast_findings: [
        { id: "python.eval", scanner: "opengrep", severity: "HIGH", details: { ...SPAN, additional_locations: [other] } },
      ],
    });
    const scanContext = { projectUrl: "https://github.com/acme/app", commitHash: "c0ffee" };

    render(<SastDetailsView finding={sast} scanContext={scanContext} />);

    expect(screen.getByText("Additional Locations")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Line 12 (Col 30-36)" })).toHaveAttribute(
      "href",
      "https://github.com/acme/app/blob/c0ffee/app/handlers.py#L12",
    );
  });

  it("tells an IaC hit on the same line apart by its search key", () => {
    const iac = finding("iac", {
      rule_id: "kics-1",
      ...SPAN,
      additional_locations: [{ start: { line: 12 }, end: { line: 12 }, search_key: "spec.containers.name={{b}}" }],
    });

    render(<SastDetailsView finding={iac} />);

    expect(screen.getByText("Line 12")).toBeInTheDocument();
    expect(screen.getByText("spec.containers.name={{b}}")).toBeInTheDocument();
  });

  it("adds no section for a finding with a single hit", () => {
    render(<SastDetailsView finding={finding("iac", { rule_id: "kics-1", ...SPAN })} />);

    expect(screen.queryByText("Additional Locations")).not.toBeInTheDocument();
  });
});

describe("SastDetailsView description", () => {
  it("sets a rule's subheading apart from its text like its section headings", () => {
    const sast = { ...finding("sast", {}), description: "## Description\n\nUser input reaches eval().\n\n### Example\n\nAvoid eval." };

    render(<SastDetailsView finding={sast} />);

    expect(screen.getByRole("heading", { name: "Example" })).toHaveClass("font-semibold");
    expect(screen.getByRole("heading", { name: "Description" })).toHaveClass("font-semibold");
  });

  it("ranks a rule's headings below its h4 section, in the order the markdown gives them", () => {
    const sast = { ...finding("sast", {}), description: "# Rule\n\n## Description\n\nUser input reaches eval().\n\n### Example\n\nAvoid eval." };

    render(<SastDetailsView finding={sast} />);

    expect(screen.getByRole("heading", { level: 4, name: "Description & Remediation" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { level: 5, name: "Rule" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { level: 6, name: "Description" }).querySelector("svg")).not.toBeNull();
    expect(screen.getByRole("heading", { level: 6, name: "Example" })).toBeInTheDocument();
  });
});
