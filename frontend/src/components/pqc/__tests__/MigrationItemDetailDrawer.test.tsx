import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { MigrationItemDetailDrawer } from "../MigrationItemDetailDrawer";
import type { MigrationItem } from "@/types/pqcMigration";

const item: MigrationItem = {
  asset_bom_ref: "ref-1",
  asset_name: "RSA",
  asset_variant: null,
  asset_key_size_bits: 1024,
  project_ids: ["p1"],
  asset_count: 1,
  source_family: "RSA",
  source_primitive: "pke",
  use_case: "key-exchange",
  recommended_pqc: "ML-KEM-768",
  recommended_standard: "FIPS 203",
  notes: "",
  priority_score: 61,
  status: "migrate_soon",
  recommended_deadline: null,
};

describe("MigrationItemDetailDrawer", () => {
  it("names the status the way the plan table does", () => {
    render(<MigrationItemDetailDrawer item={item} projectNames={{ p1: "checkout-service" }} onClose={vi.fn()} />);

    expect(screen.getByText("Migrate soon")).toBeInTheDocument();
    expect(screen.queryByText("migrate_soon")).not.toBeInTheDocument();
  });
});
