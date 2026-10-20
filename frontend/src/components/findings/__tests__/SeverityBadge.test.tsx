import { render, screen } from "@testing-library/react";
import { describe, it, expect } from "vitest";

import { SeverityBadge } from "../SeverityBadge";

describe("SeverityBadge", () => {
  it.each([
    ["CRITICAL", "text-severity-critical-foreground"],
    ["HIGH", "text-severity-high-foreground"],
    ["MEDIUM", "text-severity-medium-foreground"],
    ["LOW", "text-severity-low-foreground"],
    ["INFO", "text-severity-info-foreground"],
    ["NEGLIGIBLE", "text-severity-negligible-foreground"],
    ["UNKNOWN", "text-severity-unknown-foreground"],
  ])("writes %s in the text colour designed for its background", (severity, foreground) => {
    render(<SeverityBadge severity={severity} />);

    const pill = screen.getByText(severity);
    expect(pill).toHaveClass(foreground);
    expect(pill).not.toHaveClass("text-white");
  });
});
