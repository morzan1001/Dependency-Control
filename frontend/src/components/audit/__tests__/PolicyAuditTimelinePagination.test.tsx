import { render, screen, fireEvent } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { describe, it, expect, vi } from "vitest";

import { PolicyAuditTimeline } from "../PolicyAuditTimeline";

vi.mock("@/api/policyAudit", () => {
  // A full page of 50 entries (versions 100..51); older versions exist beyond the loaded window.
  const entries = Array.from({ length: 50 }, (_, i) => {
    const version = 100 - i;
    return {
      _id: `a${version}`,
      policy_scope: "system",
      project_id: null,
      version,
      action: "update",
      actor_user_id: null,
      actor_display_name: "sys",
      timestamp: `2026-01-01T00:00:00Z`,
      snapshot: { rules: [] },
      change_summary: `v${version} change`,
      comment: null,
      reverted_from_version: null,
    };
  });
  return {
    listSystemAudit: vi.fn().mockResolvedValue({ entries }),
    listProjectAudit: vi.fn(),
    getSystemAuditEntry: vi.fn(),
    getProjectAuditEntry: vi.fn(),
    revertSystemPolicy: vi.fn(),
    revertProjectPolicy: vi.fn(),
    pruneSystemAudit: vi.fn(),
    pruneProjectAudit: vi.fn(),
  };
});

function withClient(ui: React.ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={qc}>{ui}</QueryClientProvider>);
}

describe("PolicyAuditTimeline pagination boundary", () => {
  it("shows a 'beyond the loaded window' hint for the last entry when full page", async () => {
    withClient(<PolicyAuditTimeline policyScope="system" />);

    await screen.findByText("v100 change");

    const lastSummary = await screen.findByText("v51 change");
    fireEvent.click(lastSummary);

    expect(
      screen.getByText(/Previous version is beyond the loaded window/i),
    ).toBeInTheDocument();
  });
});
