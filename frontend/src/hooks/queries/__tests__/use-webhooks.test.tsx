import { describe, it, expect, vi } from "vitest";
import { renderHook, act } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createElement, ReactNode } from "react";
import { webhookApi } from "@/api/webhooks";
import { useCreateProjectWebhook, useDeleteWebhook, useUpdateWebhook, webhookKeys } from "../use-webhooks";

vi.mock("@/api/webhooks", () => ({
  webhookApi: { createProject: vi.fn(), update: vi.fn(), delete: vi.fn() },
}));

const mocked = (fn: unknown) => fn as unknown as ReturnType<typeof vi.fn>;

const LISTS = [webhookKeys.project("p1"), webhookKeys.team("t1"), webhookKeys.global()];

function renderWithLists<T>(hook: () => T) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  for (const key of LISTS) queryClient.setQueryData(key, []);
  const wrapper = ({ children }: { children: ReactNode }) =>
    createElement(QueryClientProvider, { client: queryClient }, children);
  const { result } = renderHook(hook, { wrapper });
  const stale = () => LISTS.map((key) => queryClient.getQueryState(key)?.isInvalidated);
  return { result, stale };
}

describe("webhook mutations refresh the lists that show the webhook", () => {
  it("an update marks the project, team and global lists stale", async () => {
    mocked(webhookApi.update).mockResolvedValue({ id: "w1" });
    const { result, stale } = renderWithLists(() => useUpdateWebhook());

    await act(async () => {
      await result.current.mutateAsync({ id: "w1", data: { is_active: false } });
    });

    expect(webhookApi.update).toHaveBeenCalledWith("w1", { is_active: false });
    expect(stale()).toEqual([true, true, true]);
  });

  it("a delete marks the project, team and global lists stale", async () => {
    mocked(webhookApi.delete).mockResolvedValue(undefined);
    const { result, stale } = renderWithLists(() => useDeleteWebhook());

    await act(async () => {
      await result.current.mutateAsync("w1");
    });

    expect(stale()).toEqual([true, true, true]);
  });

  it("a project create marks only that project's list stale", async () => {
    mocked(webhookApi.createProject).mockResolvedValue({ id: "w1" });
    const { result, stale } = renderWithLists(() => useCreateProjectWebhook());

    await act(async () => {
      await result.current.mutateAsync({ projectId: "p1", data: { url: "https://example.com/hook", events: ["scan.completed"] } });
    });

    expect(stale()).toEqual([true, false, false]);
  });
});
