import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { FindingTypeBadge } from "../FindingTypeBadge";

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

  it("still names a type it has no label for by the type itself", () => {
    render(<FindingTypeBadge type="malware" />);

    expect(screen.getByText("malware")).toHaveClass("capitalize");
  });
});
