import { describe, it, expect, vi, beforeEach } from "vitest";
import { renderHook, act } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useCreateApiKey, useRevokeApiKey, apiKeyQueryKeys } from "../use-api-keys";
import { apiKeysApi } from "@/api/apiKeys";
import type { ApiKeyCreatePayload } from "@/types/apiKey";
import { createElement, ReactNode } from "react";

vi.mock("@/api/apiKeys", () => ({
  apiKeysApi: {
    create: vi.fn(),
    revoke: vi.fn(),
    list: vi.fn(),
  },
}));

const mocked = (fn: unknown) => fn as unknown as ReturnType<typeof vi.fn>;

describe("useCreateApiKey", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("invalidates the list query on successful create", async () => {
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
    });
    const invalidateSpy = vi.spyOn(queryClient, "invalidateQueries");

    mocked(apiKeysApi.create).mockResolvedValue({
      id: "k1",
      name: "test",
      prefix: "dca_test",
      surfaces: ["mcp"],
      created_at: "2026-09-01T10:00:00Z",
      expires_at: "2026-10-01T10:00:00Z",
      revoked_at: null,
      last_used_at: null,
      token: "dca_secret",
    });

    const wrapper = ({ children }: { children: ReactNode }) =>
      createElement(QueryClientProvider, { client: queryClient }, children);
    const { result } = renderHook(() => useCreateApiKey(), { wrapper });

    const payload: ApiKeyCreatePayload = { name: "test", surfaces: ["mcp"] };

    await act(async () => {
      await result.current.mutateAsync(payload);
    });

    expect(invalidateSpy).toHaveBeenCalledWith(
      expect.objectContaining({ queryKey: ["api-keys", "list"] })
    );
  });
});

describe("useRevokeApiKey", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("invalidates the list query on successful revoke", async () => {
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
    });
    const invalidateSpy = vi.spyOn(queryClient, "invalidateQueries");

    mocked(apiKeysApi.revoke).mockResolvedValue(undefined);

    const wrapper = ({ children }: { children: ReactNode }) =>
      createElement(QueryClientProvider, { client: queryClient }, children);
    const { result } = renderHook(() => useRevokeApiKey(), { wrapper });

    const keyId = "k1";

    await act(async () => {
      await result.current.mutateAsync(keyId);
    });

    expect(invalidateSpy).toHaveBeenCalledWith(
      expect.objectContaining({ queryKey: ["api-keys", "list"] })
    );
  });
});

describe("apiKeyQueryKeys", () => {
  it("provides consistent query keys for list", () => {
    const listKey = apiKeyQueryKeys.list();
    expect(listKey).toEqual(["api-keys", "list"]);
  });
});
