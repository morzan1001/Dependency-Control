import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { downloadReport } from "@/api/compliance";
import { getServerFile } from "@/api/client";

vi.mock("@/api/client", () => ({
  api: {},
  getServerFile: vi.fn(),
}));

describe("downloadReport", () => {
  let revokeObjectURL: ReturnType<typeof vi.fn>;

  beforeEach(() => {
    vi.clearAllMocks();
    revokeObjectURL = vi.fn();
    // jsdom does not implement the object-URL APIs.
    window.URL.createObjectURL = vi.fn(() => "blob:mock-url") as unknown as typeof window.URL.createObjectURL;
    window.URL.revokeObjectURL = revokeObjectURL as unknown as typeof window.URL.revokeObjectURL;
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("fetches the artifact through the authenticated client and saves it under the given name", async () => {
    const blob = new Blob(["pdf-bytes"], { type: "application/pdf" });
    vi.mocked(getServerFile).mockResolvedValue({ blob, filename: "server-name.pdf" });
    let downloadedName: string | undefined;
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (this: HTMLAnchorElement) {
      downloadedName = this.download;
    });

    await downloadReport("r1", "audit.pdf");

    expect(getServerFile).toHaveBeenCalledWith("/compliance/reports/r1/download");
    expect(window.URL.createObjectURL).toHaveBeenCalledWith(blob);
    expect(downloadedName).toBe("audit.pdf");
    expect(revokeObjectURL).toHaveBeenCalledWith("blob:mock-url");
  });

  it("lets a failed fetch reach the caller's error handling", async () => {
    vi.mocked(getServerFile).mockRejectedValue(new Error("Request failed with status code 404"));

    await expect(downloadReport("r1", "audit.pdf")).rejects.toThrow("404");
  });
});
