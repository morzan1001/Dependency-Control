import { render, screen, fireEvent } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { describe, it, expect, vi } from "vitest";

import { CryptoAssetTable } from "../CryptoAssetTable";
import type { CryptoAsset } from "@/types/crypto";

vi.mock("@/api/crypto", () => ({
  listCryptoAssets: vi.fn().mockResolvedValue({
    items: [
      {
        _id: "1",
        project_id: "p",
        scan_id: "s",
        bom_ref: "c1",
        name: "MD5",
        asset_type: "algorithm",
        primitive: "hash",
        cipher_suites: [],
        occurrence_locations: [],
        related_dependency_purls: [],
        properties: {},
        created_at: "2026-04-20T00:00:00Z",
      } as CryptoAsset,
    ],
    total: 1,
    limit: 100,
    skip: 0,
  }),
}));

function renderWithClient(ui: React.ReactElement) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}>{ui}</QueryClientProvider>);
}

describe("CryptoAssetTable", () => {
  it("renders asset rows", async () => {
    renderWithClient(
      <CryptoAssetTable projectId="p" scanId="s" onSelect={() => {}} />
    );
    expect(await screen.findByText("MD5")).toBeInTheDocument();
  });

  it("invokes onSelect when a row is clicked", async () => {
    const onSelect = vi.fn();
    renderWithClient(
      <CryptoAssetTable projectId="p" scanId="s" onSelect={onSelect} />
    );
    const row = await screen.findByText("MD5");
    fireEvent.click(row);
    expect(onSelect).toHaveBeenCalledWith(expect.objectContaining({ name: "MD5" }));
  });
});
