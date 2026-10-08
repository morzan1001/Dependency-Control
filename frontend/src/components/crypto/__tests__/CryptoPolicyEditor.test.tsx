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

describe("CryptoPolicyEditor add rule", () => {
  it("adds a new custom rule disabled, so saving it before its matchers are filled flags nothing", async () => {
    const onSave = vi.fn().mockResolvedValue(undefined);
    render(<CryptoPolicyEditor initialRules={[]} onSave={onSave} />);

    fireEvent.click(screen.getByRole("button", { name: "Add custom rule" }));
    const [ruleId, name] = screen.getAllByRole("textbox");
    fireEvent.change(ruleId, { target: { value: "custom-rc4" } });
    fireEvent.change(name, { target: { value: "Block RC4" } });
    fireEvent.click(screen.getByRole("button", { name: "Add" }));
    fireEvent.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => expect(onSave).toHaveBeenCalledTimes(1));
    expect(onSave.mock.calls[0][0]).toEqual([expect.objectContaining({ rule_id: "custom-rc4", enabled: false })]);
  });
});

describe("CryptoPolicyEditor override detection", () => {
  it("keeps an override that differs from the system rule only in a certificate threshold", async () => {
    const sys = {
      ...systemRule(),
      rule_id: "sys-cert-expiring",
      name: "Certificate expiring soon",
      finding_type: "crypto_cert_expiring_soon" as const,
      expiry_high_days: 30,
    };
    const override = { ...sys, expiry_high_days: 90 };
    const onSave = vi.fn().mockResolvedValue(undefined);

    render(<CryptoPolicyEditor initialRules={[override]} systemRules={[sys]} onSave={onSave} />);

    expect(screen.getByText("Overridden")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(onSave).toHaveBeenCalledTimes(1));
    expect(onSave).toHaveBeenCalledWith([override]);
  });
});
