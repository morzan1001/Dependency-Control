import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { DeltaSummaryCards } from "../shared/DeltaSummaryCards";

describe("DeltaSummaryCards", () => {
  it("lists the severity counts in severity order, whatever order the API sent", () => {
    render(
      <DeltaSummaryCards
        added={5}
        removed={0}
        unchanged={0}
        bySeverity={{ CRITICAL: 1, HIGH: 1, MEDIUM: 1, INFO: 1, LOW: 1, UNKNOWN: 1, NEGLIGIBLE: 1 }}
      />,
    );

    const order = screen.getAllByText(/^(CRITICAL|HIGH|MEDIUM|LOW|NEGLIGIBLE|INFO|UNKNOWN)$/).map((el) => el.textContent);
    expect(order).toEqual(["CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE", "INFO", "UNKNOWN"]);
  });
});
