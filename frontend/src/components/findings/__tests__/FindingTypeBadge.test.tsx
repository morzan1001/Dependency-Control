import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { FINDING_TYPE_LABELS } from "@/lib/constants";

import { FindingTypeBadge } from "../FindingTypeBadge";

const SEVERITY_HUES = ["red", "orange", "yellow", "blue", "gray"];

function badgeOf(type: string) {
  const { container, unmount } = render(<FindingTypeBadge type={type} />);
  const badge = container.firstElementChild as HTMLElement;
  const hue = /\bbg-([a-z]+)-50\b/.exec(badge.className)?.[1];
  const hasIcon = badge.querySelector("svg") !== null;
  unmount();
  return { hue, hasIcon };
}

describe("FindingTypeBadge", () => {
  it.each([
    ["crypto_cert_expired", "Certificate expired"],
    ["crypto_weak_algorithm", "Weak algorithm"],
    ["crypto_key_management", "Key management misuse"],
  ])("names the crypto type %s by the crypto policy editor's label", (type, label) => {
    render(<FindingTypeBadge type={type} />);

    expect(screen.getByText(label)).toBeInTheDocument();
    expect(screen.queryByText(type)).not.toBeInTheDocument();
  });

  it("truncates a long label within its cell and keeps all of it in the title, like other truncated table text", () => {
    render(<FindingTypeBadge type="crypto_cert_validity_too_long" />);

    const label = screen.getByText("Certificate validity too long");
    expect(label).toHaveClass("truncate");
    expect(label.parentElement).toHaveClass("max-w-full");
    expect(label.parentElement).toHaveAttribute("title", "Certificate validity too long");
  });

  it("keeps its icon whole beside a truncated label", () => {
    render(<FindingTypeBadge type="vulnerability" />);

    expect(screen.getByText("Vulnerability").parentElement?.querySelector("svg")).toHaveClass("shrink-0");
  });

  it("names a malware finding by its label", () => {
    render(<FindingTypeBadge type="malware" />);

    expect(screen.getByText("Malware")).toBeInTheDocument();
  });

  it("still names a type it has no label for by the type itself", () => {
    render(<FindingTypeBadge type="typosquat" />);

    expect(screen.getByText("typosquat")).toHaveClass("capitalize");
  });

  it("hugs its label wherever it sits, as in the findings table, instead of stretching across a cell", () => {
    render(<FindingTypeBadge type="vulnerability" />);

    const badge = screen.getByText("Vulnerability").parentElement;
    expect(badge).toHaveClass("inline-flex");
    expect(badge).not.toHaveClass("flex");
  });

  it("writes a crypto label in the policy editor's casing", () => {
    render(<FindingTypeBadge type="crypto_weak_algorithm" />);

    expect(screen.getByText("Weak algorithm")).not.toHaveClass("capitalize");
  });

  it.each(["malware", "crypto_weak_algorithm"])("tints %s and gives it an icon, like every other type", (type) => {
    const { hue, hasIcon } = badgeOf(type);

    expect(hue).toBeDefined();
    expect(hasIcon).toBe(true);
  });

  it("tints malware and crypto apart from each other, every other type and the severity colours", () => {
    const otherHues = Object.keys(FINDING_TYPE_LABELS)
      .filter((type) => type !== "malware")
      .map((type) => badgeOf(type).hue);
    const malware = badgeOf("malware").hue;
    const crypto = badgeOf("crypto_cert_expired").hue;

    expect(malware).not.toBe(crypto);
    for (const hue of [malware, crypto]) {
      expect([...otherHues, ...SEVERITY_HUES]).not.toContain(hue);
    }
  });

  it("tints every crypto type alike", () => {
    const { hue } = badgeOf("crypto_key_management");

    expect(hue).toBeDefined();
    expect(badgeOf("crypto_weak_key").hue).toBe(hue);
  });
});
