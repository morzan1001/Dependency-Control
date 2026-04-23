import { render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { describe, it, expect, vi } from "vitest";

import { PolicyAuditTimeline } from "../PolicyAuditTimeline";

vi.mock("@/api/policyAudit", () => ({
  listSystemAudit: vi.fn().mockResolvedValue({
    entries: [
      {
        _id: "a1", policy_scope: "system", project_id: null, version: 3,
        action: "update", actor_user_id: "u1", actor_display_name: "alice",
        timestamp: "2026-04-20T10:00:00Z",
        snapshot: {}, change_summary: "Added 1 rule", comment: "Q2 audit",
        reverted_from_version: null,
      },
      {
        _id: "a2", policy_scope: "system", project_id: null, version: 2,
        action: "seed", actor_user_id: null, actor_display_name: null,
        timestamp: "2026-04-01T10:00:00Z",
        snapshot: {}, change_summary: "Initial policy (5 rules)", comment: null,
        reverted_from_version: null,
      },
    ],
  }),
  listProjectAudit: vi.fn(),
  getSystemAuditEntry: vi.fn(),
  getProjectAuditEntry: vi.fn(),
  revertSystemPolicy: vi.fn(),
  revertProjectPolicy: vi.fn(),
}));

function withClient(ui: React.ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={qc}>{ui}</QueryClientProvider>);
}

describe("PolicyAuditTimeline", () => {
  it("renders entries with actor and summary", async () => {
    withClient(<PolicyAuditTimeline policyScope="system" />);
    expect(await screen.findByText("alice")).toBeInTheDocument();
    expect(screen.getByText("Added 1 rule")).toBeInTheDocument();
    expect(screen.getByText(/Q2 audit/)).toBeInTheDocument();
    expect(screen.getByText("Initial policy (5 rules)")).toBeInTheDocument();
  });
});
