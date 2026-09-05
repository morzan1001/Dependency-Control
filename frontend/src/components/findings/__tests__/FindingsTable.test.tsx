import { describe, it, expect, vi, beforeEach } from "vitest";
import type { Finding } from "@/types/scan";

// Mock before importing so the module's scanApi reference points at the mock.
vi.mock("@/api/scans", () => ({
  scanApi: {
    getFindings: vi.fn(),
  },
}));

import { scanApi } from "@/api/scans";
import {
  RELATED_FINDING_SEARCH_LIMIT,
  resolveRelatedFindingInRows,
  fetchRelatedFinding,
} from "../related-finding-rows";

const makeFinding = (overrides: Partial<Finding>): Finding =>
  ({
    id: "x",
    type: "vulnerability",
    severity: "HIGH",
    component: "pkg",
    version: "1.0.0",
    description: "",
    scanners: [],
    details: {},
    ...overrides,
  }) as unknown as Finding;

const getFindingsMock = scanApi.getFindings as ReturnType<typeof vi.fn>;

beforeEach(() => {
  getFindingsMock.mockReset();
});

describe("resolveRelatedFindingInRows", () => {
  it("resolves a LIC- id to the finding with the matching id, not the first license row", () => {
    const rows = [
      makeFinding({ id: "CVE-1", type: "vulnerability", component: "a" }),
      makeFinding({ id: "LIC-MIT", type: "license", component: "mitpkg" }),
      makeFinding({ id: "LIC-GPL-3.0", type: "license", component: "gplpkg" }),
    ];
    const found = resolveRelatedFindingInRows(rows, "LIC-GPL-3.0");
    expect(found?.id).toBe("LIC-GPL-3.0");
  });

  it("does NOT select an arbitrary license row for an unmatched LIC- id", () => {
    const rows = [
      makeFinding({ id: "LIC-MIT", type: "license", component: "mitpkg" }),
      makeFinding({ id: "LIC-GPL-3.0", type: "license", component: "gplpkg" }),
    ];
    expect(resolveRelatedFindingInRows(rows, "LIC-Apache-2.0")).toBeUndefined();
  });

  it("resolves OUTDATED-{component} by type + component", () => {
    const rows = [
      makeFinding({ id: "u1", type: "outdated", component: "lodash" }),
      makeFinding({ id: "u2", type: "outdated", component: "react" }),
    ];
    expect(resolveRelatedFindingInRows(rows, "OUTDATED-react")?.id).toBe("u2");
  });

  it("resolves QUALITY:{component}:{version}", () => {
    const rows = [
      makeFinding({ id: "q1", type: "quality", component: "pkg", version: "1.0.0" }),
      makeFinding({ id: "q2", type: "quality", component: "pkg", version: "2.0.0" }),
    ];
    expect(resolveRelatedFindingInRows(rows, "QUALITY:pkg:2.0.0")?.id).toBe("q2");
  });

  it("resolves EOL- keeping hyphenated component names (strips only trailing cycle)", () => {
    const rows = [
      makeFinding({ id: "e1", type: "eol", component: "spring-boot" }),
      makeFinding({ id: "e2", type: "eol", component: "spring" }),
    ];
    expect(resolveRelatedFindingInRows(rows, "EOL-spring-boot-2")?.id).toBe("e1");
  });

  it("resolves component:version vulnerabilities", () => {
    const rows = [
      makeFinding({ id: "v1", type: "vulnerability", component: "openssl", version: "1.1.1" }),
    ];
    expect(resolveRelatedFindingInRows(rows, "openssl:1.1.1")?.id).toBe("v1");
  });

  it("prefers an exact id match over format-specific dispatch", () => {
    const rows = [
      makeFinding({ id: "OUTDATED-react", type: "vulnerability", component: "other" }),
      makeFinding({ id: "u2", type: "outdated", component: "react" }),
    ];
    expect(resolveRelatedFindingInRows(rows, "OUTDATED-react")?.id).toBe("OUTDATED-react");
  });
});

describe("fetchRelatedFinding", () => {
  it("prefers exact id then first item for LIC- ids (API path precedence)", async () => {
    getFindingsMock.mockResolvedValue({
      items: [
        makeFinding({ id: "LIC-MIT", type: "license" }),
        makeFinding({ id: "LIC-GPL-3.0", type: "license" }),
      ],
      total: 2,
      page: 1,
      size: 2,
      pages: 1,
    });
    const outcome = await fetchRelatedFinding("scan1", "LIC-GPL-3.0");
    expect(outcome).toEqual({ status: "found", finding: expect.objectContaining({ id: "LIC-GPL-3.0" }) });
    expect(getFindingsMock).toHaveBeenCalledWith("scan1", {
      type: "license",
      search: "LIC-GPL-3.0",
      skip: 0,
      limit: RELATED_FINDING_SEARCH_LIMIT,
    });
  });

  it("queries the outdated type with the parsed component", async () => {
    getFindingsMock.mockResolvedValue({
      items: [makeFinding({ id: "u2", type: "outdated", component: "react" })],
      total: 1,
      page: 1,
      size: 1,
      pages: 1,
    });
    const outcome = await fetchRelatedFinding("scan1", "OUTDATED-react");
    expect(outcome).toEqual({ status: "found", finding: expect.objectContaining({ id: "u2" }) });
    expect(getFindingsMock).toHaveBeenCalledWith("scan1", {
      type: "outdated",
      search: "react",
      skip: 0,
      limit: RELATED_FINDING_SEARCH_LIMIT,
    });
  });

  it("queries EOL with the full hyphenated component (trailing cycle stripped)", async () => {
    getFindingsMock.mockResolvedValue({
      items: [makeFinding({ id: "e1", type: "eol", component: "spring-boot" })],
      total: 1,
      page: 1,
      size: 1,
      pages: 1,
    });
    const outcome = await fetchRelatedFinding("scan1", "EOL-spring-boot-2");
    expect(outcome).toEqual({ status: "found", finding: expect.objectContaining({ id: "e1" }) });
    expect(getFindingsMock).toHaveBeenCalledWith("scan1", {
      type: "eol",
      search: "spring-boot",
      skip: 0,
      limit: RELATED_FINDING_SEARCH_LIMIT,
    });
  });

  it("separates a reference the scan does not hold from one the window did not reach", async () => {
    const matched = RELATED_FINDING_SEARCH_LIMIT * 20;
    getFindingsMock.mockResolvedValue({
      items: [makeFinding({ id: "other", type: "vulnerability", component: "openssl", version: "1.1.1" })],
      total: matched,
      page: 1,
      size: RELATED_FINDING_SEARCH_LIMIT,
      pages: 20,
    });

    const outcome = await fetchRelatedFinding("scan1", "openssl:3.0.0");

    expect(outcome).toEqual({ status: "beyond-window", searched: RELATED_FINDING_SEARCH_LIMIT, matched });
  });

  it("reports a genuine miss as missing rather than as a window that was too small", async () => {
    getFindingsMock.mockResolvedValue({
      items: [],
      total: 0,
      page: 1,
      size: RELATED_FINDING_SEARCH_LIMIT,
      pages: 0,
    });

    const outcome = await fetchRelatedFinding("scan1", "openssl:3.0.0");

    expect(outcome).toEqual({ status: "missing" });
  });
});
