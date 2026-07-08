import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";

import { CryptoPolicyEditor } from "../CryptoPolicyEditor";
import type { CryptoRule } from "@/types/cryptoPolicy";

function systemRule(): CryptoRule {
  return {
    rule_id: "sys-rc4",
    name: "Block RC4",
    description: "",
    finding_type: "crypto_weak_algorithm",
    default_severity: "HIGH",
    match_primitive: null,
    match_name_patterns: [],
    match_min_key_size_bits: null,
    match_curves: [],
    match_protocol_versions: [],
    quantum_vulnerable: null,
    enabled: true,
    source: "nist-sp-800-131a",
    references: [],
  };
}

describe("CryptoPolicyEditor prop resync", () => {
  it("resyncs local rules when initialRules changes (e.g. after 'Reset all overrides' refetch)", async () => {
    const sys = systemRule();
    const systemRules = [sys];
    const overridden = [{ ...sys, name: "Block RC4 (custom)" }];

    const onSave = vi.fn().mockResolvedValue(undefined);

    const { rerender } = render(
      <CryptoPolicyEditor
        initialRules={overridden}
        systemRules={systemRules}
        onSave={onSave}
      />,
    );

    expect(screen.getByDisplayValue("Block RC4 (custom)")).toBeInTheDocument();
    expect(screen.getByText("Overridden")).toBeInTheDocument();

    // Parent refetches after reset and passes the system rules as the effective list.
    rerender(
      <CryptoPolicyEditor
        initialRules={[{ ...sys }]}
        systemRules={systemRules}
        onSave={onSave}
      />,
    );

    expect(screen.getByDisplayValue("Block RC4")).toBeInTheDocument();
    expect(screen.queryByDisplayValue("Block RC4 (custom)")).not.toBeInTheDocument();
    expect(screen.getByText("System default")).toBeInTheDocument();

    // Rule now matches system, so save must emit an empty delta.
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(onSave).toHaveBeenCalledTimes(1));
    expect(onSave).toHaveBeenCalledWith([]);
  });
});
