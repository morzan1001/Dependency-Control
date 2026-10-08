import { describe, it, expect, vi } from "vitest";
import { renderHook, act } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createElement, ReactNode } from "react";
import { webhookApi } from "@/api/webhooks";
import { useUpdateWebhook, webhookKeys } from "../use-webhooks";

vi.mock("@/api/webhooks", () => ({ webhookApi: { update: vi.fn() } }));

const mocked = (fn: unknown) => fn as unknown as ReturnType<typeof vi.fn>;

describe("useUpdateWebhook", () => {
  it("marks the project, team and global webhook lists stale", async () => {
    const queryClient = new QueryClient({
      defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
    });
    const lists = [webhookKeys.project("p1"), webhookKeys.team("t1"), webhookKeys.global()];
    for (const key of lists) queryClient.setQueryData(key, []);
    mocked(webhookApi.update).mockResolvedValue({ id: "w1" });
    const wrapper = ({ children }: { children: ReactNode }) =>
      createElement(QueryClientProvider, { client: queryClient }, children);
    const { result } = renderHook(() => useUpdateWebhook(), { wrapper });

    await act(async () => {
      await result.current.mutateAsync({ id: "w1", data: { is_active: false } });
    });

    expect(webhookApi.update).toHaveBeenCalledWith("w1", { is_active: false });
    expect(lists.map((key) => queryClient.getQueryState(key)?.isInvalidated)).toEqual([true, true, true]);
  });
});
