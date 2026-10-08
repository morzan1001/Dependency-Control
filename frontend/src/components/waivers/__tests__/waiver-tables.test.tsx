import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { ProjectWaivers } from "@/components/project/ProjectWaivers";
import GlobalWaivers from "@/pages/GlobalWaivers";
import type { Waiver } from "@/types/waiver";

// A per-CVE waiver as GET /waivers returns it after the finding modal's per-advisory Waive.
const PER_CVE_WAIVER = {
  id: "54cefd54",
  project_id: null,
  finding_id: null,
  vulnerability_id: "CVE-2020-7598",
  package_name: "minimist",
  package_version: "1.2.0",
  finding_type: null,
  scope: "finding",
  rule_id: null,
  reason: "not reachable",
  status: "accepted_risk",
  expiration_date: null,
  created_by: "admin",
  created_at: "2026-09-01T00:00:00Z",
  last_eval_scan_id: null,
  last_match_count: 1,
  is_active: true,
} as unknown as Waiver;

const waiverPages = {
  data: { pages: [{ items: [PER_CVE_WAIVER], total: 1, page: 1, size: 50, pages: 1 }] },
  fetchNextPage: vi.fn(),
  hasNextPage: false,
  isFetchingNextPage: false,
  isLoading: false,
  isError: false,
};

vi.mock("@/hooks/queries/use-waivers", () => ({
  useWaiverList: () => waiverPages,
  useDeleteWaiver: () => ({ mutate: vi.fn(), isPending: false }),
  useUpdateWaiver: () => ({ mutate: vi.fn(), isPending: false }),
  useCreateWaiver: () => ({ mutate: vi.fn(), isPending: false }),
  waiverKeys: { all: ["waivers"] },
}));
vi.mock("@/context/useAuth", () => ({ useAuth: () => ({ permissions: [], hasPermission: () => false }) }));
vi.mock("@/hooks/queries/use-projects", () => ({ useProject: () => ({ data: undefined }) }));
vi.mock("@/hooks/queries/use-users", () => ({ useCurrentUser: () => ({ data: undefined }) }));

function renderWithClient(ui: React.ReactNode) {
  return render(<QueryClientProvider client={new QueryClient()}>{ui}</QueryClientProvider>);
}

describe("waiver tables", () => {
  it.each([
    ["project", <ProjectWaivers key="project" projectId="p1" />],
    ["global", <GlobalWaivers key="global" />],
  ])("name the CVE a per-CVE waiver covers in the %s table", (_table, table) => {
    renderWithClient(table);

    expect(screen.getByText("CVE-2020-7598")).toHaveAttribute("title", "CVE-2020-7598");
    expect(screen.queryByText("Any")).toBeNull();
  });
});
