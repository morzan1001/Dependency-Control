import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, it, expect, vi, beforeEach } from "vitest";
import type { ComponentFinding, DependencyMetadata } from "@/types/analytics";
import { AnalyticsDependencyModal } from "../AnalyticsDependencyModal";
import { resolveRelatedFinding } from "../related-finding";

vi.mock("@/hooks/queries/use-analytics", () => ({
  useDependencyMetadata: vi.fn(),
  useComponentFindings: vi.fn(),
}));

import {
  useDependencyMetadata,
  useComponentFindings,
} from "@/hooks/queries/use-analytics";

// --- helpers ---------------------------------------------------------------

const makeFinding = (overrides: Partial<ComponentFinding>): ComponentFinding =>
  ({
    id: "x",
    type: "vulnerability",
    severity: "HIGH",
    component: "pkg",
    version: "1.0.0",
    description: "",
    scanners: [],
    details: {},
    found_in: [],
    aliases: [],
    waived: false,
    project_id: "p1",
    project_name: "Project 1",
    ...overrides,
  }) as ComponentFinding;

const baseMetadata: DependencyMetadata = {
  name: "pkg",
  version: "1.0.0",
  type: "npm",
  project_count: 0,
  affected_projects: [],
  total_vulnerability_count: 0,
  total_finding_count: 0,
};

function renderModal(metadata: DependencyMetadata) {
  (useDependencyMetadata as ReturnType<typeof vi.fn>).mockReturnValue({
    data: metadata,
    isLoading: false,
  });
  (useComponentFindings as ReturnType<typeof vi.fn>).mockReturnValue({
    data: [],
    isLoading: false,
  });
  return render(
    <MemoryRouter>
      <AnalyticsDependencyModal
        component="pkg"
        version="1.0.0"
        open
        onOpenChange={() => {}}
      />
    </MemoryRouter>,
  );
}

// --- Finding 1: safeHref hardening on metadata links -----------------------

describe("AnalyticsDependencyModal metadata link hardening", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("never renders a javascript:/data: URI from third-party metadata as an href", async () => {
    renderModal({
      ...baseMetadata,
      homepage: "javascript:alert(1)",
      repository_url: "data:text/html,<script>alert(1)</script>",
      download_url: "javascript:void(0)",
      license: "MIT",
      license_url: "javascript:alert('lic')",
      deps_dev: {
        links: {
          Malicious: "javascript:alert('link')",
          Homepage: "https://good.example.com",
        },
      },
    });

    // Reveal the collapsible "Additional Details" (deps.dev links + license).
    fireEvent.click(screen.getByText(/Additional Details/i));

    await waitFor(() => {
      expect(screen.getByText("Homepage")).toBeInTheDocument();
    });

    const anchors = Array.from(document.querySelectorAll("a"));
    for (const a of anchors) {
      const href = a.getAttribute("href") ?? "";
      expect(href.toLowerCase().startsWith("javascript:")).toBe(false);
      expect(href.toLowerCase().startsWith("data:")).toBe(false);
    }

    // The safe deps.dev link is still rendered as a real anchor.
    const safeLink = anchors.find(
      (a) => a.getAttribute("href") === "https://good.example.com",
    );
    expect(safeLink).toBeDefined();

    // The malicious "Homepage" button (external links section) must not link out.
    // Its label exists but carries no javascript: href.
    const homepageButton = screen
      .getAllByText("Homepage")
      .map((el) => el.closest("a"))
      .filter(Boolean) as HTMLAnchorElement[];
    for (const a of homepageButton) {
      expect(a.getAttribute("href")?.startsWith("javascript:")).not.toBe(true);
    }
  });

  it("renders valid http(s) metadata links normally", async () => {
    renderModal({
      ...baseMetadata,
      homepage: "https://home.example.com",
      repository_url: "https://github.com/acme/pkg",
    });

    const home = screen
      .getByText("Homepage")
      .closest("a") as HTMLAnchorElement | null;
    expect(home?.getAttribute("href")).toBe("https://home.example.com");
  });
});

// --- Finding 2: resolveRelatedFinding id parsing ---------------------------

describe("resolveRelatedFinding", () => {
  it("resolves EOL ids with hyphenated component names by stripping only the cycle", () => {
    const findings = [
      makeFinding({ id: "eol-1", type: "eol", component: "spring-boot" }),
      makeFinding({ id: "eol-2", type: "eol", component: "spring" }),
    ];
    const found = resolveRelatedFinding(findings, "EOL-spring-boot-2");
    expect(found?.component).toBe("spring-boot");
  });

  it("resolves single-word EOL component ids", () => {
    const findings = [makeFinding({ id: "e", type: "eol", component: "openssl" })];
    expect(resolveRelatedFinding(findings, "EOL-openssl-3")?.component).toBe(
      "openssl",
    );
  });

  it("does not select an arbitrary license finding for an unmatched LIC- id", () => {
    const findings = [
      makeFinding({ id: "lic-a", type: "license", component: "gpl-pkg" }),
    ];
    // No exact id match -> must NOT fall back to the first license finding.
    expect(resolveRelatedFinding(findings, "LIC-MIT")).toBeUndefined();
  });

  it("still resolves a LIC- id by exact id match", () => {
    const findings = [
      makeFinding({ id: "LIC-MIT", type: "license", component: "pkg" }),
    ];
    expect(resolveRelatedFinding(findings, "LIC-MIT")?.id).toBe("LIC-MIT");
  });

  it("resolves exact id, OUTDATED-, QUALITY: and component:version formats", () => {
    const findings = [
      makeFinding({ id: "exact", component: "pkg" }),
      makeFinding({ id: "o", type: "outdated", component: "lodash" }),
      makeFinding({ id: "q", type: "quality", component: "react", version: "18.0.0" }),
      makeFinding({ id: "v", component: "axios", version: "1.2.3" }),
    ];
    expect(resolveRelatedFinding(findings, "exact")?.id).toBe("exact");
    expect(resolveRelatedFinding(findings, "OUTDATED-lodash")?.id).toBe("o");
    expect(resolveRelatedFinding(findings, "QUALITY:react:18.0.0")?.id).toBe("q");
    expect(resolveRelatedFinding(findings, "axios:1.2.3")?.id).toBe("v");
  });
});

// --- Finding 3: CopyButton uses shared clipboard hook ----------------------

describe("AnalyticsDependencyModal copy button", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("copies the PURL via navigator.clipboard and does not throw when copy is rejected", async () => {
    const writeText = vi
      .fn()
      .mockRejectedValueOnce(new Error("denied"))
      .mockResolvedValue(undefined);
    Object.defineProperty(navigator, "clipboard", {
      value: { writeText },
      configurable: true,
    });

    renderModal({ ...baseMetadata, purl: "pkg:npm/pkg@1.0.0" });

    fireEvent.click(screen.getByText(/Additional Details/i));

    await waitFor(() => {
      expect(screen.getByText("pkg:npm/pkg@1.0.0")).toBeInTheDocument();
    });

    // The copy button is the icon-only button next to the PURL code block.
    const purlCode = screen.getByText("pkg:npm/pkg@1.0.0");
    const copyBtn = purlCode.parentElement?.querySelector("button");
    expect(copyBtn).toBeTruthy();

    // First click: clipboard rejects -> hook must swallow (no unhandled rejection).
    fireEvent.click(copyBtn as HTMLElement);
    await waitFor(() => {
      expect(writeText).toHaveBeenCalledWith("pkg:npm/pkg@1.0.0");
    });
  });
});
