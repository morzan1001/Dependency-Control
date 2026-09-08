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

const makeDep = (name: string, versions: string[] = ["1.0.0"], versionCount?: number): DependencyUsage => ({
  name,
  type: "npm",
  project_count: 2,
  total_occurrences: 5,
  versions,
  version_count: versionCount ?? versions.length,
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

    // group-hover:opacity-100 only works if an ancestor carries the `group` class.
    const row = nameCell.closest("tr");
    expect(row).not.toBeNull();
    expect(row).toHaveClass("group");

    const icon = row?.querySelector(".group-hover\\:opacity-100");
    expect(icon).not.toBeNull();

    await waitFor(() => {
      expect(analyticsApi.getTopDependencies).toHaveBeenCalled();
    });
  });
});

const VERSION_BADGES_SHOWN = 3;
const VERSIONS_IN_PAYLOAD = 10;
const DISTINCT_VERSIONS = 40;

describe("DependencyStats version badge", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    (analyticsApi.getDependencyTypes as ReturnType<typeof vi.fn>).mockResolvedValue([]);
  });

  it("counts the overflow badge from the distinct total, not the ten versions it received", () => {
    const versions = Array.from({ length: VERSIONS_IN_PAYLOAD }, (_, i) => `1.${DISTINCT_VERSIONS - 1 - i}.0`);
    (analyticsApi.getTopDependencies as ReturnType<typeof vi.fn>).mockResolvedValue([
      makeDep("left-pad", versions, DISTINCT_VERSIONS),
    ]);
    renderStats();

    return waitFor(() => {
      expect(screen.getByText(`+${DISTINCT_VERSIONS - VERSION_BADGES_SHOWN}`)).toBeInTheDocument();
    });
  });

  it("shows no overflow badge when the component has three versions or fewer", () => {
    (analyticsApi.getTopDependencies as ReturnType<typeof vi.fn>).mockResolvedValue([
      makeDep("left-pad", ["2.0.0", "1.0.0"], 2),
    ]);
    renderStats();

    return waitFor(() => {
      expect(screen.getByText("2.0.0")).toBeInTheDocument();
      expect(screen.queryByText(/^\+\d+$/)).toBeNull();
    });
  });
});
