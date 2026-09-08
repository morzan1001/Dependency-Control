import { describe, it, expect, vi, beforeEach } from "vitest";
import { adhocKeysApi } from "@/api/adhocKeys";
import { api } from "@/api/client";
import type {
  AdhocApiKeyCreateResponse,
  AdhocApiKeyListResponse,
} from "@/types/adhocKey";

vi.mock("@/api/client", () => ({
  api: { get: vi.fn(), post: vi.fn(), delete: vi.fn() },
}));

const KEY_ID = "k1";
const KEY_NAME = "ci";
const KEY_PREFIX = "dca_abcdefgh";
const PLAINTEXT_TOKEN = "dca_secret";
const EXPIRES_IN_DAYS = 30;
const CREATED_AT = "2026-09-01T10:00:00Z";
const EXPIRES_AT = "2026-10-01T10:00:00Z";

const mocked = (fn: unknown) => fn as unknown as ReturnType<typeof vi.fn>;

const emptyList: AdhocApiKeyListResponse = { keys: [], truncated: null };

const createdKey: AdhocApiKeyCreateResponse = {
  id: KEY_ID,
  name: KEY_NAME,
  prefix: KEY_PREFIX,
  created_at: CREATED_AT,
  expires_at: EXPIRES_AT,
  revoked_at: null,
  token: PLAINTEXT_TOKEN,
};

describe("adhocKeysApi", () => {
  beforeEach(() => vi.clearAllMocks());

  it("lists keys from the analyze-keys collection route", async () => {
    mocked(api.get).mockResolvedValue({ data: emptyList });

    const result = await adhocKeysApi.list();

    expect(api.get).toHaveBeenCalledWith("/analyze-keys/");
    expect(result).toEqual(emptyList);
  });

  it("posts the create payload unchanged and returns the one-time token", async () => {
    mocked(api.post).mockResolvedValue({ data: createdKey });

    const created = await adhocKeysApi.create({
      name: KEY_NAME,
      expires_in_days: EXPIRES_IN_DAYS,
    });

    expect(api.post).toHaveBeenCalledWith("/analyze-keys/", {
      name: KEY_NAME,
      expires_in_days: EXPIRES_IN_DAYS,
    });
    expect(created.token).toBe(PLAINTEXT_TOKEN);
  });

  it("revokes by id", async () => {
    mocked(api.delete).mockResolvedValue({ data: {} });

    await adhocKeysApi.revoke(KEY_ID);

    expect(api.delete).toHaveBeenCalledWith(`/analyze-keys/${KEY_ID}`);
  });
});
