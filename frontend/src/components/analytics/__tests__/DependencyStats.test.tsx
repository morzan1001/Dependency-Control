import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { describe, it, expect, vi, beforeEach } from "vitest";
import type { DependencyUsage } from "@/types/analytics";
import { DependencyStats } from "../DependencyStats";

vi.mock("@/api/analytics", () => ({
  analyticsApi: {
    getTopDependencies: vi.fn(),
    getDependencyTypes: vi.fn(),
  },
}));

import { analyticsApi } from "@/api/analytics";

const makeDep = (name: string): DependencyUsage => ({
  name,
  type: "npm",
  project_count: 2,
  total_occurrences: 5,
  versions: ["1.0.0"],
  has_vulnerabilities: false,
  vulnerability_count: 0,
});

function renderStats(): void {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  render(
    <QueryClientProvider client={client}>
      <DependencyStats />
    </QueryClientProvider>,
  );
}

describe("DependencyStats row hover icon", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    (analyticsApi.getDependencyTypes as ReturnType<typeof vi.fn>).mockResolvedValue([]);
    (analyticsApi.getTopDependencies as ReturnType<typeof vi.fn>).mockResolvedValue([
      makeDep("left-pad"),
    ]);
  });

  it("marks the dependency row as a Tailwind `group` so the group-hover ExternalLink icon can appear", async () => {
    renderStats();

    const nameCell = await screen.findByText("left-pad");

    // The ExternalLink icon relies on `group-hover:opacity-100`; that only works
    // if an ancestor carries the `group` class. Walk up to the enclosing <tr>.
    const row = nameCell.closest("tr");
    expect(row).not.toBeNull();
    expect(row).toHaveClass("group");

    // The icon itself must still be the group-hover target within that row.
    const icon = row?.querySelector(".group-hover\\:opacity-100");
    expect(icon).not.toBeNull();

    await waitFor(() => {
      expect(analyticsApi.getTopDependencies).toHaveBeenCalled();
    });
  });
});
