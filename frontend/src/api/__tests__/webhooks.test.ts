import { describe, it, expect, vi } from "vitest";
import { webhookApi } from "@/api/webhooks";
import { api } from "@/api/client";
import type { Webhook } from "@/types/webhook";

vi.mock("@/api/client", () => ({ api: { patch: vi.fn() } }));

const mocked = (fn: unknown) => fn as unknown as ReturnType<typeof vi.fn>;

describe("webhookApi.update", () => {
  it("patches the webhook with the given fields and returns the stored webhook", async () => {
    const stored: Webhook = {
      id: "w1",
      url: "https://example.com/hook",
      events: ["scan.completed"],
      is_active: false,
      created_at: "2026-10-08T08:00:00Z",
      webhook_type: "generic",
      secret_configured: false,
    };
    mocked(api.patch).mockResolvedValue({ data: stored });

    const result = await webhookApi.update("w1", { is_active: false, secret: null });

    expect(api.patch).toHaveBeenCalledWith("/webhooks/w1", { is_active: false, secret: null });
    expect(result).toEqual(stored);
  });
});
