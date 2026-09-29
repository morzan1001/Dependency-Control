import { fireEvent, render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { describe, it, expect, vi } from "vitest";

import type { Finding } from "@/types/scan";

const mutate = vi.fn();

vi.mock("@/context/useAuth", () => ({
  useAuth: () => ({ hasPermission: () => true, permissions: [] }),
}));
vi.mock("@/hooks/queries/use-projects", () => ({ useProject: () => ({ data: undefined }) }));
vi.mock("@/hooks/queries/use-users", () => ({ useCurrentUser: () => ({ data: undefined }) }));
vi.mock("@/hooks/queries/use-waivers", () => ({
  useWaiverById: () => ({ data: undefined }),
  useCreateWaiver: () => ({ mutate, isPending: false }),
  waiverKeys: { project: (id: string) => ["waivers", id] },
}));

import { FindingDetailsModal } from "../FindingDetailsModal";

const FINDING = {
  id: "SAST-1",
  type: "sast",
  severity: "HIGH",
  component: "app/handlers.py",
  description: "eval() detected",
  scanners: ["opengrep"],
  details: {},
  found_in: [],
  aliases: [],
  waived: false,
} as unknown as Finding;

describe("FindingDetailsModal waiver", () => {
  it("sends the scan the finding was opened from, so a branch-only finding validates", () => {
    const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={qc}>
        <MemoryRouter>
          <FindingDetailsModal finding={FINDING} isOpen onClose={() => {}} projectId="p1" scanId="scan-feature" />
        </MemoryRouter>
      </QueryClientProvider>,
    );

    fireEvent.click(screen.getByRole("button", { name: /Create Waiver/i }));
    fireEvent.change(screen.getByPlaceholderText(/Why is this finding being ignored/i), {
      target: { value: "branch only" },
    });
    fireEvent.click(screen.getByRole("button", { name: /Confirm Waiver/i }));

    expect(mutate).toHaveBeenCalledWith(
      expect.objectContaining({ project_id: "p1", scan_id: "scan-feature" }),
      expect.anything(),
    );
  });
});
