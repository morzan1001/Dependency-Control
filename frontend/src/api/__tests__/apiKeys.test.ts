import { describe, it, expect, vi, beforeEach } from "vitest";
import { apiKeysApi } from "@/api/apiKeys";
import { api } from "@/api/client";
import type {
  ApiKeyCreatePayload,
  ApiKeyCreateResponse,
  ApiKeyListResponse,
} from "@/types/apiKey";

vi.mock("@/api/client", () => ({
  api: { get: vi.fn(), post: vi.fn(), delete: vi.fn() },
}));

const KEY_ID = "k1";
const KEY_NAME = "unified-key";
const KEY_PREFIX = "dca_unified123";
const PLAINTEXT_TOKEN = "dca_unified_secret";
const CREATED_AT = "2026-09-01T10:00:00Z";
const EXPIRES_AT = "2026-12-10T10:00:00Z";

const mocked = (fn: unknown) => fn as unknown as ReturnType<typeof vi.fn>;

const emptyList: ApiKeyListResponse = { keys: [], truncated: null };

const createdKey: ApiKeyCreateResponse = {
  id: KEY_ID,
  name: KEY_NAME,
  prefix: KEY_PREFIX,
  surfaces: ["mcp", "adhoc"],
  created_at: CREATED_AT,
  expires_at: EXPIRES_AT,
  revoked_at: null,
  last_used_at: null,
  token: PLAINTEXT_TOKEN,
};

describe("apiKeysApi", () => {
  beforeEach(() => vi.clearAllMocks());

  it("lists keys from the unified api-keys endpoint", async () => {
    mocked(api.get).mockResolvedValue({ data: emptyList });

    const result = await apiKeysApi.list();

    expect(api.get).toHaveBeenCalledWith("/api-keys/");
    expect(result).toEqual(emptyList);
  });

  it("posts the create payload unchanged and returns the one-time token", async () => {
    mocked(api.post).mockResolvedValue({ data: createdKey });

    const payload: ApiKeyCreatePayload = {
      name: KEY_NAME,
      surfaces: ["mcp", "adhoc"],
      expires_in_days: 100,
    };

    const created = await apiKeysApi.create(payload);

    expect(api.post).toHaveBeenCalledWith("/api-keys/", payload);
    expect(created.token).toBe(PLAINTEXT_TOKEN);
    expect(created.surfaces).toEqual(["mcp", "adhoc"]);
  });

  it("revokes by id", async () => {
    mocked(api.delete).mockResolvedValue({ data: {} });

    await apiKeysApi.revoke(KEY_ID);

    expect(api.delete).toHaveBeenCalledWith(`/api-keys/${KEY_ID}`);
  });

  it("enforces surface union type", () => {
    const validPayload: ApiKeyCreatePayload = {
      name: "test",
      surfaces: ["mcp", "adhoc"],
    };
    expect(validPayload.surfaces).toEqual(["mcp", "adhoc"]);
  });
});
