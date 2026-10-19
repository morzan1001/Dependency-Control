import { render, screen } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import { ReportStatusBadge } from "../ReportStatusBadge";
import type { ReportStatus } from "@/types/compliance";

describe("ReportStatusBadge", () => {
  it.each<[ReportStatus, string, string, string]>([
    ["pending", "Pending", "bg-yellow-100", "dark:bg-yellow-900/30"],
    ["generating", "Generating…", "bg-yellow-100", "dark:bg-yellow-900/30"],
    ["completed", "Completed", "bg-green-100", "dark:bg-green-900/30"],
    ["failed", "Failed", "bg-red-100", "dark:bg-red-900/30"],
  ])("shows %s in the status pill the user and API key tables use", (status, label, tone, darkTone) => {
    render(<ReportStatusBadge status={status} />);

    expect(screen.getByText(label)).toHaveClass("rounded-full", tone, darkTone);
  });
});
