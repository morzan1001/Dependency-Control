import { render, screen, fireEvent } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { describe, it, expect, vi, beforeEach } from "vitest";

import { PQCMigrationPanel } from "../PQCMigrationPanel";
import type { MigrationPlanResponse } from "@/types/pqcMigration";

vi.mock("@/api/pqcMigration", () => ({
  getPQCMigrationPlan: vi.fn(),
}));

const plan: MigrationPlanResponse = {
  scope: "user",
  scope_id: null,
  generated_at: "2026-01-01T00:00:00Z",
  items: [],
  mappings_version: 3,
  summary: {
    total_items: 0,
    items_returned: 0,
    status_counts: {
      migrate_now: 1,
      migrate_soon: 0,
      plan_migration: 0,
      monitor: 0,
    },
    earliest_deadline: null,
  },
};

function renderPanel(onExportReport: () => void = () => {}) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <PQCMigrationPanel onExportReport={onExportReport} />
    </QueryClientProvider>,
  );
}

describe("PQCMigrationPanel export-as-compliance-report", () => {
  beforeEach(async () => {
    const { getPQCMigrationPlan } = await import("@/api/pqcMigration");
    vi.mocked(getPQCMigrationPlan).mockResolvedValue(plan);
  });

  it("hands the export to the page that owns the compliance view", async () => {
    const onExportReport = vi.fn();
    renderPanel(onExportReport);

    fireEvent.click(await screen.findByRole("button", { name: /Export as Compliance Report/i }));

    expect(onExportReport).toHaveBeenCalledTimes(1);
  });
});

const PLAN_LIMIT = 500;
const MIGRATABLE_GROUPS = 600;

function migrationItem(index: number): MigrationPlanResponse["items"][number] {
  return {
    asset_bom_ref: `ref-${index}`,
    asset_name: "RSA",
    asset_variant: null,
    asset_key_size_bits: 2048,
    project_ids: ["p1"],
    asset_count: 1,
    source_family: "RSA",
    source_primitive: "pke",
    use_case: "key-exchange",
    recommended_pqc: "ML-KEM-768",
    recommended_standard: "FIPS 203",
    notes: "",
    priority_score: 40,
    status: "plan_migration",
    recommended_deadline: null,
  };
}

describe("PQCMigrationPanel item count", () => {
  beforeEach(async () => {
    const { getPQCMigrationPlan } = await import("@/api/pqcMigration");
    vi.mocked(getPQCMigrationPlan).mockResolvedValue({
      ...plan,
      items: Array.from({ length: PLAN_LIMIT }, (_, i) => migrationItem(i)),
      summary: { ...plan.summary, total_items: MIGRATABLE_GROUPS, items_returned: PLAN_LIMIT },
    });
  });

  it("names the migration work the estate holds, not the page the endpoint returned", async () => {
    renderPanel();

    expect(
      await screen.findByText(new RegExp(`Showing ${PLAN_LIMIT} of ${MIGRATABLE_GROUPS} item`)),
    ).toBeInTheDocument();
  });
});
