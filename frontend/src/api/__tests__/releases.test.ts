import { describe, it, expect, vi, beforeEach } from "vitest";
import { releaseApi } from "@/api/releases";
import { scanApi } from "@/api/scans";
import { api } from "@/api/client";
import { SMALL_PAGE_SIZE } from "@/lib/constants";

vi.mock("@/api/client", () => ({
  api: { get: vi.fn(), post: vi.fn(), delete: vi.fn() },
}));

const PROJECT_ID = "p1";
const SCAN_ID = "s1";
const STAGING = "staging";
const PRODUCTION = "production";
const COMMIT_HASH = "abc";
const SECOND_PAGE_SKIP = SMALL_PAGE_SIZE;

const mocked = (fn: unknown) => fn as unknown as ReturnType<typeof vi.fn>;

const emptyList = {
  data: { items: [], total: 0, page: 1, size: SMALL_PAGE_SIZE },
};

describe("releaseApi", () => {
  beforeEach(() => vi.clearAllMocks());

  it("lists releases with pagination and an optional environment", async () => {
    mocked(api.get).mockResolvedValue(emptyList);

    await releaseApi.list(PROJECT_ID, {
      skip: SECOND_PAGE_SKIP,
      limit: SMALL_PAGE_SIZE,
      environment: STAGING,
    });

    expect(api.get).toHaveBeenCalledWith(`/projects/${PROJECT_ID}/releases`, {
      params: { skip: SECOND_PAGE_SKIP, limit: SMALL_PAGE_SIZE, environment: STAGING },
    });
  });

  it("omits an unset environment instead of sending an empty string", async () => {
    mocked(api.get).mockResolvedValue(emptyList);

    await releaseApi.list(PROJECT_ID);

    expect(mocked(api.get).mock.calls[0][1].params).not.toHaveProperty("environment");
  });

  it("marks a release", async () => {
    mocked(api.post).mockResolvedValue({ data: { scan_id: SCAN_ID } });

    await releaseApi.mark(PROJECT_ID, { commit_hash: COMMIT_HASH, environment: PRODUCTION });

    expect(api.post).toHaveBeenCalledWith(`/projects/${PROJECT_ID}/releases`, {
      commit_hash: COMMIT_HASH,
      environment: PRODUCTION,
    });
  });

  it("withdraws a scan from the named environment only", async () => {
    mocked(api.delete).mockResolvedValue({
      data: {
        scan_id: SCAN_ID,
        environment: STAGING,
        is_release: true,
        remaining_environments: [PRODUCTION],
      },
    });

    const result = await releaseApi.unmark(PROJECT_ID, SCAN_ID, STAGING);

    expect(api.delete).toHaveBeenCalledWith(`/projects/${PROJECT_ID}/scans/${SCAN_ID}/release`, {
      params: { environment: STAGING },
    });
    expect(result.remaining_environments).toEqual([PRODUCTION]);
  });
});

describe("scanApi.getProjectScans release filter", () => {
  beforeEach(() => vi.clearAllMocks());

  it("passes is_release through when set", async () => {
    mocked(api.get).mockResolvedValue({ data: [] });

    await scanApi.getProjectScans(PROJECT_ID, { isRelease: true });

    expect(mocked(api.get).mock.calls[0][1].params.is_release).toBe(true);
  });

  it("keeps false distinct from unset so the non-release scans can be listed", async () => {
    mocked(api.get).mockResolvedValue({ data: [] });

    await scanApi.getProjectScans(PROJECT_ID, { isRelease: false });

    expect(mocked(api.get).mock.calls[0][1].params.is_release).toBe(false);
  });

  it("sends undefined, not an empty value, when the filter is off", async () => {
    mocked(api.get).mockResolvedValue({ data: [] });

    await scanApi.getProjectScans(PROJECT_ID, {});

    expect(mocked(api.get).mock.calls[0][1].params.is_release).toBeUndefined();
  });
});
