import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, it, expect, vi, beforeEach } from "vitest";
import type { ComponentFinding, DependencyMetadata } from "@/types/analytics";
import { AnalyticsDependencyModal } from "../AnalyticsDependencyModal";
import { AnalyticsModeContext } from "@/context/analytics-mode";

const RELEASE_ENVIRONMENT = "production";

vi.mock("@/hooks/queries/use-analytics", () => ({
  useDependencyMetadata: vi.fn(),
  useComponentFindings: vi.fn(),
}));

import {
  useDependencyMetadata,
  useComponentFindings,
} from "@/hooks/queries/use-analytics";

const baseMetadata: DependencyMetadata = {
  name: "pkg",
  version: "1.0.0",
  type: "npm",
  project_count: 0,
  affected_projects: [],
  total_vulnerability_count: 0,
};

const NO_FINDINGS = { items: [], total: 0 };

function renderModal(metadata: DependencyMetadata) {
  (useDependencyMetadata as ReturnType<typeof vi.fn>).mockReturnValue({
    data: metadata,
    isLoading: false,
  });
  (useComponentFindings as ReturnType<typeof vi.fn>).mockReturnValue({
    data: NO_FINDINGS,
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

describe("AnalyticsDependencyModal header", () => {
  it("centres the package icon, name and version on a phone, as the centred header does with a plain title, and starts them on the left from sm up", () => {
    renderModal(baseMetadata);

    expect(screen.getByRole("heading", { name: /pkg/ })).toHaveClass("justify-center", "sm:justify-start");
  });
});

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

    const safeLink = anchors.find(
      (a) => a.getAttribute("href") === "https://good.example.com",
    );
    expect(safeLink).toBeDefined();

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

describe("AnalyticsDependencyModal project statistics", () => {
  it("shows the deps.dev counts it has, in order, and leaves out the missing ones", () => {
    renderModal({ ...baseMetadata, deps_dev: { stars: 12345, open_issues: 7, dependents: { total: 300 } } });

    const tiles = screen.getAllByText(/^(Stars|Forks|Issues|Dependents)$/).map((label) => label.parentElement?.textContent);
    expect(tiles).toEqual([`${(12345).toLocaleString()}Stars`, "7Issues", "300Dependents"]);
  });

  it("marks a package deps.dev reports as deprecated", () => {
    renderModal({ ...baseMetadata, deps_dev: { is_deprecated: true } });

    expect(screen.getByText("Deprecated")).toBeInTheDocument();
  });

  it("offers the homepage, repository and download links in that order", () => {
    renderModal({
      ...baseMetadata,
      download_url: "https://registry.example.com/pkg.tgz",
      homepage: "https://home.example.com",
      repository_url: "https://github.com/acme/pkg",
    });

    const links = screen.getAllByRole("link").map((a) => [a.textContent, a.getAttribute("href")]);
    expect(links).toEqual([
      ["Homepage", "https://home.example.com"],
      ["Repository", "https://github.com/acme/pkg"],
      ["Download", "https://registry.example.com/pkg.tgz"],
    ]);
  });
});

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

    const purlCode = screen.getByText("pkg:npm/pkg@1.0.0");
    const copyBtn = purlCode.parentElement?.querySelector("button");
    expect(copyBtn).toBeTruthy();

    // First click: clipboard rejects; the hook must swallow it (no unhandled rejection).
    fireEvent.click(copyBtn as HTMLElement);
    await waitFor(() => {
      expect(writeText).toHaveBeenCalledWith("pkg:npm/pkg@1.0.0");
    });
  });
});

describe("AnalyticsDependencyModal scope", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    (useDependencyMetadata as ReturnType<typeof vi.fn>).mockReturnValue({ data: baseMetadata, isLoading: false });
    (useComponentFindings as ReturnType<typeof vi.fn>).mockReturnValue({ data: NO_FINDINGS, isLoading: false });
  });

  function renderInMode(releaseEnvironment: string | undefined) {
    return render(
      <MemoryRouter>
        <AnalyticsModeContext.Provider value={releaseEnvironment}>
          <AnalyticsDependencyModal component="pkg" version="1.0.0" open onOpenChange={() => {}} />
        </AnalyticsModeContext.Provider>
      </MemoryRouter>,
    );
  }

  it("asks for the same scope the table that opened it rendered from", () => {
    renderInMode(RELEASE_ENVIRONMENT);

    expect(useComponentFindings).toHaveBeenCalledWith("pkg", "1.0.0", RELEASE_ENVIRONMENT);
    expect(useDependencyMetadata).toHaveBeenCalledWith("pkg", "1.0.0", undefined, RELEASE_ENVIRONMENT);
  });

  it("asks for the branch tip when the page is in head mode", () => {
    renderInMode(undefined);

    expect(useComponentFindings).toHaveBeenCalledWith("pkg", "1.0.0", undefined);
    expect(useDependencyMetadata).toHaveBeenCalledWith("pkg", "1.0.0", undefined, undefined);
  });
});

describe("AnalyticsDependencyModal additional details", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("lists the group, maintainers and publication date it knows and nothing for the rest", () => {
    renderModal({
      ...baseMetadata,
      group: "org.acme",
      author: "Ann Author",
      deps_dev: { published_at: "2024-01-02T00:00:00Z" },
    });

    fireEvent.click(screen.getByText(/Additional Details/i));

    expect(screen.getByText("Group").nextElementSibling).toHaveTextContent("org.acme");
    expect(screen.getByText("Author").nextElementSibling).toHaveTextContent("Ann Author");
    expect(screen.getByText("Published").nextElementSibling).toHaveTextContent(/2024/);
    expect(screen.queryByText("Publisher")).not.toBeInTheDocument();
  });

  it("leaves the group out when the metadata names none", () => {
    renderModal({ ...baseMetadata, author: "Ann Author" });

    fireEvent.click(screen.getByText(/Additional Details/i));

    expect(screen.queryByText("Group")).not.toBeInTheDocument();
  });
});

describe("AnalyticsDependencyModal version", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("says the metadata describes one of several versions in use", () => {
    renderModal({ ...baseMetadata, version: "2.0.0", versions: ["3.0.0", "2.0.0", "1.0.0"] });

    expect(screen.getByText("Most used of 3 versions")).toHaveAttribute("title", "3.0.0, 2.0.0, 1.0.0");
  });

  it("says nothing more when only one version is in use", () => {
    renderModal({ ...baseMetadata, versions: ["1.0.0"] });

    expect(screen.queryByText(/Most used of/)).not.toBeInTheDocument();
  });
});

describe("AnalyticsDependencyModal findings list", () => {
  const finding = (id: string, severity: string): ComponentFinding =>
    ({
      id,
      type: "vulnerability",
      severity,
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
      scan_id: `scan-${id}`,
    }) as ComponentFinding;

  beforeEach(() => {
    vi.clearAllMocks();
    // A name that spans several package paths, such as openssl from deb and apk, has no metadata.
    (useDependencyMetadata as ReturnType<typeof vi.fn>).mockReturnValue({ data: null, isLoading: false });
  });

  function renderFindings() {
    return render(
      <MemoryRouter>
        <AnalyticsDependencyModal component="pkg" version="1.0.0" open onOpenChange={() => {}} />
      </MemoryRouter>,
    );
  }

  it("counts every finding and says the list holds only the most severe of them", () => {
    (useComponentFindings as ReturnType<typeof vi.fn>).mockReturnValue({
      data: { items: [finding("CVE-1", "CRITICAL"), finding("CVE-2", "HIGH")], total: 130 },
      isLoading: false,
    });

    renderFindings();

    expect(screen.getByText("130")).toBeInTheDocument();
    expect(screen.getByText("Showing the 2 most severe of 130 findings.")).toBeInTheDocument();
  });

  it("says the findings failed to load instead of reporting none, and retries them", () => {
    const refetch = vi.fn();
    (useComponentFindings as ReturnType<typeof vi.fn>).mockReturnValue({
      data: undefined,
      isLoading: false,
      error: Object.assign(new Error("Request failed"), { response: { status: 403, data: { detail: "Not enough permissions" } } }),
      refetch,
    });

    renderFindings();

    expect(screen.getByRole("alert")).toHaveTextContent("Not enough permissions");
    expect(screen.queryByText("No findings for this dependency")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(refetch).toHaveBeenCalled();
  });

  it("names a vulnerability row by its advisory, not by the package it aggregates on", () => {
    const single = { ...finding("pkg:1.0", "HIGH"), details: { vulnerabilities: [{ id: "CVE-2024-1" }] } };
    const several = {
      ...finding("lib:2.0", "HIGH"),
      details: { vulnerabilities: [{ id: "CVE-2024-2" }, { id: "CVE-2024-3" }] },
    };
    (useComponentFindings as ReturnType<typeof vi.fn>).mockReturnValue({
      data: { items: [single, several], total: 2 },
      isLoading: false,
    });

    renderFindings();

    expect(screen.getByText("CVE-2024-1")).toBeInTheDocument();
    expect(screen.getByText("Multiple Vulnerabilities")).toBeInTheDocument();
    expect(screen.queryByText("pkg:1.0")).not.toBeInTheDocument();
  });

  it("writes each row's severity in the pill colours and with the icon of that severity, UNKNOWN without one", () => {
    (useComponentFindings as ReturnType<typeof vi.fn>).mockReturnValue({
      data: { items: [finding("CVE-1", "MEDIUM"), finding("CVE-2", "")], total: 2 },
      isLoading: false,
    });

    renderFindings();

    expect(screen.getByText("MEDIUM")).toHaveClass("bg-severity-medium", "text-severity-medium-foreground");
    expect(screen.getByText("UNKNOWN")).toHaveClass("bg-severity-unknown", "text-severity-unknown-foreground");
    expect(screen.getByText("MEDIUM").querySelector("svg")).not.toBeNull();
  });

  it("names each row's type with the findings table's badge, in a column as wide as the table's", () => {
    (useComponentFindings as ReturnType<typeof vi.fn>).mockReturnValue({
      data: { items: [{ ...finding("CERT-1", "HIGH"), type: "crypto_cert_expired" }], total: 1 },
      isLoading: false,
    });

    renderFindings();

    expect(screen.getByText("Certificate expired")).toHaveClass("truncate");
    expect(screen.queryByText("crypto_cert_expired")).not.toBeInTheDocument();
    expect(screen.getByText("Type", { selector: "th" })).toHaveClass("w-[160px]");
  });

  it("marks the column the findings are sorted by and the direction", () => {
    (useComponentFindings as ReturnType<typeof vi.fn>).mockReturnValue({
      data: { items: [finding("CVE-1", "HIGH")], total: 1 },
      isLoading: false,
    });

    renderFindings();
    const header = (name: string) => screen.getByText(name, { selector: "th" });
    expect(header("Severity").querySelector("svg.lucide-arrow-down")).not.toBeNull();

    fireEvent.click(header("Type"));

    expect(header("Type").querySelector("svg.lucide-arrow-up")).not.toBeNull();
    expect(header("Severity").querySelector("svg")).toBeNull();
  });

  it("sorts the Finding column by the advisory it shows", () => {
    const rows = [
      { ...finding("a:1.0", "HIGH"), details: { vulnerabilities: [{ id: "CVE-2024-9" }] } },
      { ...finding("b:1.0", "HIGH"), details: { vulnerabilities: [{ id: "CVE-2024-1" }] } },
    ];
    (useComponentFindings as ReturnType<typeof vi.fn>).mockReturnValue({
      data: { items: rows, total: 2 },
      isLoading: false,
    });

    renderFindings();
    fireEvent.click(screen.getByText("Finding", { selector: "th" }));

    const shown = screen.getAllByText(/^CVE-2024-/).map((cell) => cell.textContent);
    expect(shown).toEqual(["CVE-2024-1", "CVE-2024-9"]);
  });
  it("keeps the Project column 200px wide and scrolls the findings table sideways in a phone-wide dialog", () => {
    (useComponentFindings as ReturnType<typeof vi.fn>).mockReturnValue({
      data: { items: [finding("CVE-1", "CRITICAL")], total: 1 },
      isLoading: false,
    });

    renderFindings();

    const table = screen.getByRole("table");
    expect(table).toHaveClass("table-fixed", "min-w-[660px]");
    expect(table.parentElement).toHaveClass("overflow-auto");
  });
});

describe("AnalyticsDependencyModal known advisories", () => {
  it("links each known advisory with a public page and names the others", () => {
    renderModal({ ...baseMetadata, deps_dev: { known_advisories: ["GHSA-aaaa-bbbb-cccc", "CVE-2024-1", "OSV-2024-1"] } });

    expect(screen.getByText("3 Known Security Advisories")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "GHSA-aaaa-bbbb-cccc" })).toHaveAttribute(
      "href",
      "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
    );
    expect(screen.getByRole("link", { name: "CVE-2024-1" })).toHaveAttribute("href", "https://nvd.nist.gov/vuln/detail/CVE-2024-1");
    expect(screen.getByText("OSV-2024-1")).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "OSV-2024-1" })).not.toBeInTheDocument();
  });
});
