import { describe, it, expect, vi, beforeEach } from "vitest";
import { getScanDelta } from "@/api/scanDelta";
import { api } from "@/api/client";

vi.mock("@/api/client", () => ({
  api: { get: vi.fn() },
}));

describe("getScanDelta", () => {
  beforeEach(() => vi.clearAllMocks());

  it("serializes csv params for severity and finding_type", async () => {
    (api.get as unknown as ReturnType<typeof vi.fn>).mockResolvedValue({
      data: { items: [] },
    });
    await getScanDelta({
      projectId: "p1",
      fromScanId: "a",
      toScanId: "b",
      category: "findings",
      page: 2,
      pageSize: 50,
      severity: ["critical", "high"],
      findingType: ["secret"],
    });
    expect(api.get).toHaveBeenCalledWith("/analytics/scan-delta", {
      params: {
        project_id: "p1",
        from_scan_id: "a",
        to_scan_id: "b",
        category: "findings",
        page: 2,
        page_size: 50,
        severity: "critical,high",
        finding_type: "secret",
      },
    });
  });

  it("omits filter params when not provided", async () => {
    (api.get as unknown as ReturnType<typeof vi.fn>).mockResolvedValue({
      data: { items: [] },
    });
    await getScanDelta({
      projectId: "p1",
      fromScanId: "a",
      toScanId: "b",
      category: "crypto",
    });
    const callArgs = (api.get as unknown as ReturnType<typeof vi.fn>).mock
      .calls[0][1];
    expect(callArgs.params).not.toHaveProperty("severity");
    expect(callArgs.params).not.toHaveProperty("finding_type");
    expect(callArgs.params).not.toHaveProperty("change");
  });
});
