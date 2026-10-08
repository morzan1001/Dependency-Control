import { render, screen } from "@testing-library/react";
import { describe, it, expect } from "vitest";
import { AlertTriangle } from "lucide-react";
import { BadgeList } from "../BadgeList";

describe("BadgeList", () => {
  it("links each item it can build a URL for, under its formatted label", () => {
    render(
      <BadgeList
        items={["79", "89"]}
        variant="outline"
        icon={AlertTriangle}
        formatLabel={(cwe) => `CWE-${cwe}`}
        buildUrl={(cwe) => `https://cwe.mitre.org/data/definitions/${cwe}.html`}
      />,
    );

    const link = screen.getByText("CWE-89").closest("a")!;
    expect(link).toHaveAttribute("href", "https://cwe.mitre.org/data/definitions/89.html");
    expect(link).toHaveAttribute("target", "_blank");
    expect(screen.getByText("CWE-89").className).toContain("hover:bg-muted cursor-pointer");
    expect(screen.getByText("CWE-79").querySelectorAll("svg")).toHaveLength(2);
  });

  it("renders plain badges with the given class when there is nothing to link", () => {
    render(<BadgeList items={["A01:2021"]} variant="outline" badgeClassName="text-orange-600 border-orange-300" />);

    const badge = screen.getByText("A01:2021");
    expect(badge.closest("a")).toBeNull();
    expect(badge.className).toContain("text-orange-600 border-orange-300");
    expect(badge.className).not.toContain("cursor-pointer");
  });

  it("renders nothing for an empty list", () => {
    const { container } = render(<BadgeList items={[]} />);

    expect(container).toBeEmptyDOMElement();
  });
});
