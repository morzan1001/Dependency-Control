import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { downloadReport } from "@/api/compliance";
import { api } from "@/api/client";

vi.mock("@/api/client", () => ({
  api: { get: vi.fn() },
}));

const mockedGet = api.get as unknown as ReturnType<typeof vi.fn>;

describe("downloadReport", () => {
  let createObjectURL: ReturnType<typeof vi.fn>;
  let revokeObjectURL: ReturnType<typeof vi.fn>;
  let clickSpy: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    vi.clearAllMocks();
    createObjectURL = vi.fn(() => "blob:mock-url");
    revokeObjectURL = vi.fn();
    // jsdom does not implement the object-URL APIs.
    window.URL.createObjectURL = createObjectURL as unknown as typeof window.URL.createObjectURL;
    window.URL.revokeObjectURL = revokeObjectURL as unknown as typeof window.URL.revokeObjectURL;
    clickSpy = vi.fn();
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(clickSpy);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("fetches the artifact through the authenticated client as a blob", async () => {
    const blob = new Blob(["pdf-bytes"], { type: "application/pdf" });
    mockedGet.mockResolvedValue({ data: blob, headers: {} });

    await downloadReport("r1");

    // The authenticated axios client (which attaches the bearer token and
    // resolves the runtime base URL) must be used with a blob responseType,
    // instead of a bare unauthenticated anchor href.
    expect(mockedGet).toHaveBeenCalledWith("/compliance/reports/r1/download", {
      responseType: "blob",
    });
    expect(createObjectURL).toHaveBeenCalledWith(blob);
    expect(clickSpy).toHaveBeenCalledTimes(1);
    expect(revokeObjectURL).toHaveBeenCalledWith("blob:mock-url");
  });

  it("uses the explicit filename argument for the download attribute", async () => {
    const blob = new Blob(["x"]);
    mockedGet.mockResolvedValue({ data: blob, headers: {} });

    let downloadedName: string | undefined;
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (
      this: HTMLAnchorElement,
    ) {
      downloadedName = this.download;
    });

    await downloadReport("r1", "audit.pdf");

    expect(downloadedName).toBe("audit.pdf");
  });

  it("derives the filename from Content-Disposition when no name is given", async () => {
    const blob = new Blob(["x"]);
    mockedGet.mockResolvedValue({
      data: blob,
      headers: { "content-disposition": 'attachment; filename="report-2026.pdf"' },
    });

    let downloadedName: string | undefined;
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (
      this: HTMLAnchorElement,
    ) {
      downloadedName = this.download;
    });

    await downloadReport("r1");

    expect(downloadedName).toBe("report-2026.pdf");
  });

  it("falls back to a report-id filename when nothing else is available", async () => {
    const blob = new Blob(["x"]);
    mockedGet.mockResolvedValue({ data: blob, headers: {} });

    let downloadedName: string | undefined;
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (
      this: HTMLAnchorElement,
    ) {
      downloadedName = this.download;
    });

    await downloadReport("abc");

    expect(downloadedName).toBe("compliance-report-abc");
  });
});
