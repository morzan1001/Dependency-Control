import { beforeEach, describe, expect, it, vi } from "vitest";
import { api } from "@/api/client";
import { scanApi } from "@/api/scans";

vi.mock("@/api/client", () => ({ api: { get: vi.fn() } }));

const mocked = (fn: unknown) => fn as unknown as ReturnType<typeof vi.fn>;
const FILE = { bomFormat: "CycloneDX" };

describe("scanApi raw file previews", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mocked(api.get).mockResolvedValue({ data: FILE });
  });

  it("fetches an SBOM through its download route", async () => {
    await expect(scanApi.getSbom("s1", 0)).resolves.toEqual(FILE);

    expect(api.get).toHaveBeenCalledWith("/projects/scans/s1/sboms/0");
  });

  it("fetches a result through its download route with the row id escaped", async () => {
    await expect(scanApi.getResult("s1", "s1:trivy:SBOM #1")).resolves.toEqual(FILE);

    expect(api.get).toHaveBeenCalledWith("/projects/scans/s1/results/s1%3Atrivy%3ASBOM%20%231", { timeout: 0 });
  });
});
