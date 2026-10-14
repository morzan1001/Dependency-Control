import { fireEvent, render, screen } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";

import { AdvisoryLink } from "../AdvisoryLink";

describe("AdvisoryLink", () => {
  it.each([
    ["CVE-2024-1", "https://nvd.nist.gov/vuln/detail/CVE-2024-1"],
    ["GHSA-aaaa-bbbb-cccc", "https://github.com/advisories/GHSA-aaaa-bbbb-cccc"],
  ])("opens the public page of %s in a new tab", (id, href) => {
    render(<AdvisoryLink id={id} />);

    const link = screen.getByRole("link", { name: id });
    expect(link).toHaveAttribute("href", href);
    expect(link).toHaveAttribute("target", "_blank");
    expect(link).toHaveAttribute("rel", "noopener noreferrer");
  });

  it("opens the page the caller knows for the advisory", () => {
    render(<AdvisoryLink id="GHSA-aaaa-bbbb-cccc" href="https://github.example.com/advisories/GHSA-aaaa-bbbb-cccc" />);

    expect(screen.getByRole("link")).toHaveAttribute("href", "https://github.example.com/advisories/GHSA-aaaa-bbbb-cccc");
  });

  it("names an advisory without a public page and links nothing", () => {
    render(<AdvisoryLink id="PYSEC-2024-1" />);

    expect(screen.getByText("PYSEC-2024-1")).toBeInTheDocument();
    expect(screen.queryByRole("link")).not.toBeInTheDocument();
  });

  it("keeps the click from reaching the row or card around it", () => {
    const onContainerClick = vi.fn();
    render(
      <div onClick={onContainerClick}>
        <AdvisoryLink id="CVE-2024-1" />
      </div>,
    );

    fireEvent.click(screen.getByRole("link"));

    expect(onContainerClick).not.toHaveBeenCalled();
  });
});
