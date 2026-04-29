import { render, screen } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import { ReportStatusBadge } from "../ReportStatusBadge";

describe("ReportStatusBadge", () => {
  it("renders each status label", () => {
    const { rerender } = render(<ReportStatusBadge status="pending" />);
    expect(screen.getByText("Pending")).toBeInTheDocument();
    rerender(<ReportStatusBadge status="generating" />);
    expect(screen.getByText("Generating…")).toBeInTheDocument();
    rerender(<ReportStatusBadge status="completed" />);
    expect(screen.getByText("Completed")).toBeInTheDocument();
    rerender(<ReportStatusBadge status="failed" />);
    expect(screen.getByText("Failed")).toBeInTheDocument();
  });
});
