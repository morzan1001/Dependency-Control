import { describe, it, expect, vi, beforeEach } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";

import { toast } from "sonner";
import { broadcastApi } from "@/api/broadcast";
import { useBroadcast } from "../use-broadcast";
import type { BroadcastRequest } from "@/types/broadcast";

vi.mock("sonner", () => ({
  toast: {
    success: vi.fn(),
    error: vi.fn(),
  },
}));

vi.mock("@/api/broadcast", () => ({
  broadcastApi: {
    send: vi.fn(),
  },
}));

function wrapper({ children }: { children: ReactNode }) {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return <QueryClientProvider client={qc}>{children}</QueryClientProvider>;
}

const dryRunAdvisory: BroadcastRequest = {
  type: "advisory",
  target_type: "advisory",
  subject: "Dry Run",
  message: "Dry Run",
  channels: [],
  dry_run: true,
};

const realAdvisory: BroadcastRequest = {
  ...dryRunAdvisory,
  subject: "Real",
  message: "Real",
  dry_run: false,
};

describe("useBroadcast", () => {
  beforeEach(() => {
    vi.mocked(toast.success).mockReset();
    vi.mocked(toast.error).mockReset();
    vi.mocked(broadcastApi.send).mockReset();
  });

  it("does not toast success for a dry-run impact calculation", async () => {
    vi.mocked(broadcastApi.send).mockResolvedValue({
      recipient_count: 0,
      project_count: 3,
    });

    const { result } = renderHook(() => useBroadcast(), { wrapper });
    await result.current.mutateAsync(dryRunAdvisory);

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(toast.success).not.toHaveBeenCalled();
  });

  it("does not toast success on a real send (the page owns that toast)", async () => {
    vi.mocked(broadcastApi.send).mockResolvedValue({
      recipient_count: 5,
      project_count: 3,
    });

    const { result } = renderHook(() => useBroadcast(), { wrapper });
    await result.current.mutateAsync(realAdvisory);

    await waitFor(() => expect(result.current.isSuccess).toBe(true));
    expect(toast.success).not.toHaveBeenCalled();
  });

  it("does not toast error on a real send (the page owns that toast)", async () => {
    vi.mocked(broadcastApi.send).mockRejectedValue(new Error("boom"));

    const { result } = renderHook(() => useBroadcast(), { wrapper });
    await expect(result.current.mutateAsync(realAdvisory)).rejects.toThrow();

    await waitFor(() => expect(result.current.isError).toBe(true));
    expect(toast.error).not.toHaveBeenCalled();
  });

  it("toasts an error for a failed dry-run (delegated to the hook by the page)", async () => {
    vi.mocked(broadcastApi.send).mockRejectedValue(new Error("boom"));

    const { result } = renderHook(() => useBroadcast(), { wrapper });
    await expect(result.current.mutateAsync(dryRunAdvisory)).rejects.toThrow();

    await waitFor(() => expect(result.current.isError).toBe(true));
    expect(toast.error).toHaveBeenCalledTimes(1);
  });
});
