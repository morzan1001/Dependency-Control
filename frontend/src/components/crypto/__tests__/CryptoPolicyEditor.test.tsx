import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";

import { CryptoPolicyEditor } from "../CryptoPolicyEditor";
import type { CryptoRule } from "@/types/cryptoPolicy";
import { expectEveryFieldNamed, expectFieldLabel } from "@/test/form-field";

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

describe("CryptoPolicyEditor add rule dialog", () => {
  it("labels its fields like the other form dialogs", () => {
    render(<CryptoPolicyEditor initialRules={[]} onSave={vi.fn()} />);
    fireEvent.click(screen.getByRole("button", { name: "Add custom rule" }));

    for (const name of ["Rule ID", "Name", "Description", "Name patterns (comma-separated)"]) expectFieldLabel(name);
  });

  it("opens at the default dialog width, like the other form dialogs", () => {
    render(<CryptoPolicyEditor initialRules={[]} onSave={vi.fn()} />);
    fireEvent.click(screen.getByRole("button", { name: "Add custom rule" }));

    expect(screen.getByRole("dialog", { name: "Add custom crypto rule" })).toHaveClass("max-w-lg");
  });

  it.each([
    ["no rule ID", "", "Block RC4", "Rule ID", "Enter a rule ID"],
    ["a rule ID already taken", "sys-rc4", "Block RC4", "Rule ID", "A rule with this ID already exists"],
    ["no name", "custom-rc4", "", "Name", "Enter a name"],
  ])("marks the field and says why under it for %s, like the other field errors", (_, ruleId, name, field, reason) => {
    render(<CryptoPolicyEditor initialRules={[systemRule()]} onSave={vi.fn()} />);
    fireEvent.click(screen.getByRole("button", { name: "Add custom rule" }));
    fireEvent.change(screen.getByLabelText("Rule ID"), { target: { value: ruleId } });
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: name } });
    fireEvent.click(screen.getByRole("button", { name: "Add" }));

    expect(screen.getByRole("alert")).toHaveTextContent(reason);
    expect(screen.getByLabelText(field)).toHaveAttribute("aria-invalid", "true");
    expect(screen.getByLabelText(field)).toHaveAccessibleDescription(reason);
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

function typeInto(input: HTMLElement, text: string) {
  for (const ch of text) {
    fireEvent.change(input, { target: { value: (input as HTMLInputElement).value + ch } });
  }
}

describe("CryptoPolicyEditor name patterns", () => {
  it("keeps commas and spaces while typing in a rule row and saves the parsed patterns", async () => {
    const onSave = vi.fn().mockResolvedValue(undefined);
    render(<CryptoPolicyEditor initialRules={[{ ...systemRule(), match_name_patterns: ["RC4"] }]} onSave={onSave} />);

    const input = screen.getByDisplayValue("RC4");
    typeInto(input, ", DES");
    expect(input).toHaveValue("RC4, DES");

    // A browser blurs the field on the mousedown that precedes the Save click.
    fireEvent.blur(input);
    fireEvent.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => expect(onSave).toHaveBeenCalledTimes(1));
    expect(onSave.mock.calls[0][0][0].match_name_patterns).toEqual(["RC4", "DES"]);
  });

  it("keeps commas and spaces while typing a new rule's patterns", async () => {
    const onSave = vi.fn().mockResolvedValue(undefined);
    render(<CryptoPolicyEditor initialRules={[]} onSave={onSave} />);

    fireEvent.click(screen.getByRole("button", { name: "Add custom rule" }));
    const [ruleId, name] = screen.getAllByRole("textbox");
    fireEvent.change(ruleId, { target: { value: "custom-rc4" } });
    fireEvent.change(name, { target: { value: "Block RC4" } });
    const patterns = screen.getByLabelText("Name patterns (comma-separated)");
    typeInto(patterns, "RC4, DES");
    expect(patterns).toHaveValue("RC4, DES");
    fireEvent.click(screen.getByRole("button", { name: "Add" }));
    fireEvent.click(screen.getByRole("button", { name: "Save" }));

    await waitFor(() => expect(onSave).toHaveBeenCalledTimes(1));
    expect(onSave.mock.calls[0][0][0].match_name_patterns).toEqual(["RC4", "DES"]);
  });
});

describe("CryptoPolicyEditor rules table width", () => {
  it("fits a project's columns and a 200px Rule column into the 989px a 1440px screen leaves, and scrolls sideways below that", () => {
    const sys = systemRule();
    render(<CryptoPolicyEditor initialRules={[sys]} systemRules={[sys]} onSave={vi.fn()} />);

    const table = screen.getByRole("table");
    expect(table).toHaveClass("table-fixed");
    expect(table).toHaveStyle({ minWidth: "960px" });
    expect(table.parentElement).toHaveClass("overflow-x-auto");
    expect(screen.getByRole("columnheader", { name: "Rule" })).toHaveClass("w-auto");
    expect(screen.getByRole("columnheader", { name: "Status" })).toHaveClass("w-30");
    expect(screen.getAllByRole("columnheader")).toHaveLength(7);
  });

  it("fits the system policy's columns and a 200px Rule column on a 1440px screen", () => {
    render(<CryptoPolicyEditor initialRules={[systemRule()]} onSave={vi.fn()} />);

    expect(screen.getByRole("table")).toHaveStyle({ minWidth: "936px" });
    expect(screen.queryByRole("columnheader", { name: "Status" })).not.toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: "Min key size" })).toHaveClass("w-24");
  });

  it("keeps no room for the Remove column a read-only viewer of the system policy does not get", () => {
    render(<CryptoPolicyEditor initialRules={[systemRule()]} readOnly onSave={vi.fn()} />);

    expect(screen.getByRole("table")).toHaveStyle({ minWidth: "840px" });
    expect(screen.getAllByRole("columnheader")).toHaveLength(6);
  });

  it("names each rule's source under its name instead of in a column of its own", () => {
    render(<CryptoPolicyEditor initialRules={[systemRule()]} onSave={vi.fn()} />);

    expect(screen.queryByRole("columnheader", { name: "Source" })).not.toBeInTheDocument();
    const ruleCell = screen.getByDisplayValue("Block RC4").closest("td");
    expect(ruleCell).toContainElement(screen.getByText("nist-sp-800-131a"));
    expect(screen.getByText("nist-sp-800-131a")).toHaveClass("font-mono", "text-xs");
  });

  it("offers Revert beside an overridden rule's status, as Deactivate sits beside a user's", () => {
    const sys = systemRule();
    render(<CryptoPolicyEditor initialRules={[{ ...sys, name: "Block RC4 now" }]} systemRules={[sys]} onSave={vi.fn()} />);

    const revert = screen.getByRole("button", { name: "Revert" });
    expect(revert).toHaveClass("h-6", "text-xs");
    expect(revert.closest("td")).toContainElement(screen.getByText("Overridden"));
    fireEvent.click(revert);
    expect(screen.getByDisplayValue("Block RC4")).toBeInTheDocument();
  });

  it("offers Remove beside a project's custom rule's status", () => {
    const sys = systemRule();
    const custom = { ...sys, rule_id: "custom-des", name: "Block DES", source: "custom" as const };
    render(<CryptoPolicyEditor initialRules={[sys, custom]} systemRules={[sys]} onSave={vi.fn()} />);

    const remove = screen.getByRole("button", { name: "Remove" });
    expect(remove).toHaveClass("h-6", "text-xs");
    expect(remove.closest("td")).toContainElement(screen.getByText("Custom"));
    fireEvent.click(remove);
    expect(screen.queryByDisplayValue("Block DES")).not.toBeInTheDocument();
  });

  it("keeps the System default pill on one line in its column", () => {
    const sys = systemRule();
    render(<CryptoPolicyEditor initialRules={[sys]} systemRules={[sys]} onSave={vi.fn()} />);

    expect(screen.getByText("System default")).toHaveClass("whitespace-nowrap");
  });

  it("wraps a rule's name over as many lines as it needs instead of cutting it off", () => {
    const long = { ...systemRule(), name: "BSI requires RSA keys of at least 3000 bits from 2024 onwards" };
    render(<CryptoPolicyEditor initialRules={[long]} onSave={vi.fn()} />);

    const name = screen.getByDisplayValue(long.name);
    expect(name.tagName).toBe("TEXTAREA");
    expect(name).toHaveClass("field-sizing-content", "resize-none");
    expect(name).toHaveAttribute("title", long.name);
  });

  it("keeps a rule's name on one logical line when a line break is typed or pasted", () => {
    const onSave = vi.fn().mockResolvedValue(undefined);
    render(<CryptoPolicyEditor initialRules={[systemRule()]} onSave={onSave} />);

    fireEvent.change(screen.getByDisplayValue("Block RC4"), { target: { value: "Block\nRC4 \n now" } });

    expect(screen.getByDisplayValue("Block RC4 now")).toBeInTheDocument();
  });
});

describe("CryptoPolicyEditor accessible names", () => {
  it("names its filters and every field of a rule row by the rule and its column, like the notification matrix", () => {
    const sys = systemRule();
    render(<CryptoPolicyEditor initialRules={[sys]} systemRules={[sys]} onSave={vi.fn()} />);

    expectEveryFieldNamed();
    expect(screen.getByRole("combobox", { name: "Source" })).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: "Status" })).toBeInTheDocument();
    expect(screen.getByRole("switch", { name: "sys-rc4: Enabled" })).toBeInTheDocument();
    expect(screen.getByRole("textbox", { name: "sys-rc4: Rule" })).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: "sys-rc4: Finding type" })).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: "sys-rc4: Severity" })).toBeInTheDocument();
    expect(screen.getByRole("spinbutton", { name: "sys-rc4: Min key size" })).toBeInTheDocument();
    expect(screen.getByRole("textbox", { name: "sys-rc4: Name patterns" })).toBeInTheDocument();
  });
});
