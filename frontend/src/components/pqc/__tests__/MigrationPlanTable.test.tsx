import { render, screen, fireEvent } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";

import { MigrationPlanTable } from "../MigrationPlanTable";
import type { MigrationItem } from "@/types/pqcMigration";

const items: MigrationItem[] = [
  {
    asset_bom_ref: "rsa-1", asset_name: "RSA", asset_variant: "RSA-2048",
    asset_key_size_bits: 2048, project_ids: ["p1"], asset_count: 1,
    source_family: "RSA", source_primitive: "pke", use_case: "key-exchange",
    recommended_pqc: "ML-KEM-768", recommended_standard: "FIPS 203",
    notes: "...", priority_score: 88, status: "migrate_now",
    recommended_deadline: "2030-01-01",
  },
  {
    asset_bom_ref: "ecdsa-1", asset_name: "ECDSA", asset_variant: null,
    asset_key_size_bits: null, project_ids: ["p1", "p2"], asset_count: 3,
    source_family: "ECDSA", source_primitive: "signature",
    use_case: "digital-signature",
    recommended_pqc: "ML-DSA-65", recommended_standard: "FIPS 204",
    notes: "...", priority_score: 55, status: "migrate_soon",
    recommended_deadline: "2030-01-01",
  },
];

describe("MigrationPlanTable", () => {
  it("renders one row per item with family and recommended pqc", () => {
    render(<MigrationPlanTable items={items} onSelect={() => {}} />);
    expect(screen.getByText("RSA")).toBeInTheDocument();
    expect(screen.getByText("ML-KEM-768")).toBeInTheDocument();
    expect(screen.getByText("ECDSA")).toBeInTheDocument();
    expect(screen.getByText("ML-DSA-65")).toBeInTheDocument();
  });

  it("invokes onSelect with the row's item when clicked", () => {
    const onSelect = vi.fn();
    render(<MigrationPlanTable items={items} onSelect={onSelect} />);
    const row = screen.getByText("RSA");
    fireEvent.click(row);
    expect(onSelect).toHaveBeenCalledWith(expect.objectContaining({ asset_bom_ref: "rsa-1" }));
  });

  it("invokes onSelect on Enter keydown", () => {
    const onSelect = vi.fn();
    render(<MigrationPlanTable items={items} onSelect={onSelect} />);
    const row = screen.getByText("RSA").closest("tr")!;
    fireEvent.keyDown(row, { key: "Enter" });
    expect(onSelect).toHaveBeenCalledWith(expect.objectContaining({ asset_bom_ref: "rsa-1" }));
  });

  it("renders priority score visibly", () => {
    render(<MigrationPlanTable items={items} onSelect={() => {}} />);
    expect(screen.getByText("88")).toBeInTheDocument();
    expect(screen.getByText("55")).toBeInTheDocument();
  });
});
