import { render, screen } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import type { FindingDetails } from "@/types/scan";
import { LicenseDetailsView } from "../LicenseDetailsView";

// The LicenseDetails the backend normalizer stores for a GPL dependency of an internal-only project.
const internalOnlyGpl: FindingDetails = {
  license: "GPL-3.0-only",
  license_url: undefined,
  category: "strong_copyleft",
  explanation: "GNU General Public License v3.0 only.",
  recommendation: "This project is internal-only.",
  obligations: ["Disclose source"],
  risks: ["Entire application must be GPL if distributed"],
  context_reason: "Severity reduced: project is internal-only, GPL distribution obligations do not apply.",
  severity_without_context: "HIGH",
};

describe("LicenseDetailsView", () => {
  it("lists the licence risks the finding carries", () => {
    render(<LicenseDetailsView details={internalOnlyGpl} />);

    expect(screen.getByText("Risks (1)")).toBeInTheDocument();
    expect(screen.getByText("Entire application must be GPL if distributed")).toBeInTheDocument();
  });

  it("names the severity the finding would have without the project context", () => {
    render(<LicenseDetailsView details={internalOnlyGpl} />);

    expect(screen.getByText("HIGH")).toBeInTheDocument();
  });
});
