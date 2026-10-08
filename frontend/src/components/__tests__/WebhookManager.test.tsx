import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";

import { toast } from "sonner";

import { webhookApi } from "@/api/webhooks";
import type { Webhook } from "@/types/webhook";

import { WebhookManager } from "../WebhookManager";

vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));
vi.mock("@/api/webhooks", () => ({ webhookApi: { test: vi.fn() } }));

vi.mock("@/context/useAuth", () => ({
  useAuth: () => ({
    isAuthenticated: true,
    isLoading: false,
    permissions: ["webhook:create", "webhook:delete", "webhook:update"],
    hasPermission: (p: string) =>
      ["webhook:create", "webhook:delete", "webhook:update"].includes(p),
    login: vi.fn(),
    logout: vi.fn(),
  }),
}));

describe("WebhookManager", () => {
  it("exposes every webhook event type in the create dialog", () => {
    render(
      <WebhookManager
        webhooks={[]}
        isLoading={false}
        onCreate={vi.fn().mockResolvedValue({ id: "w1" })}
        onDelete={vi.fn().mockResolvedValue(undefined)}
      />,
    );

    fireEvent.click(screen.getByRole("button", { name: /Add Webhook/i }));

    expect(screen.getByLabelText(/Scan completed/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/Vulnerability found/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/Analysis failed/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/SBOM ingested/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/Crypto asset ingested/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/Crypto policy changed/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/License policy changed/i)).toBeInTheDocument();
    expect(
      screen.getByLabelText(/Compliance report generated/i),
    ).toBeInTheDocument();
    expect(screen.getAllByRole("checkbox")).toHaveLength(8);
  });

  it.each([
    [false, undefined],
    [true, "generic"],
  ])("sends webhook_type generic for a workflow URL only when the JSON opt-out is ticked (%s)", async (optOut, expected) => {
    const onCreate = vi.fn().mockResolvedValue({ id: "w1" });
    render(
      <WebhookManager webhooks={[]} isLoading={false} onCreate={onCreate} onDelete={vi.fn()} />,
    );
    fireEvent.click(screen.getByRole("button", { name: /Add Webhook/i }));
    fireEvent.change(screen.getByPlaceholderText("https://example.com/webhook"), {
      target: { value: "https://prod-1.westeurope.logic.azure.com/workflows/abc/triggers/manual" },
    });
    if (optOut) fireEvent.click(screen.getByLabelText(/event JSON instead/i));
    fireEvent.click(screen.getByLabelText(/Scan completed/i));
    fireEvent.click(screen.getByRole("button", { name: /Create Webhook/i }));

    await waitFor(() => expect(onCreate).toHaveBeenCalledTimes(1));
    expect(onCreate.mock.calls[0][0].webhook_type).toBe(expected);
  });

  const slackHook: Webhook = {
    id: "w-slack",
    url: "https://hooks.slack.com/services/T0/B0/x",
    events: ["vulnerability.found"],
    is_active: true,
    created_at: "2026-10-07T07:26:42Z",
    webhook_type: "slack",
    last_failure_at: "2026-10-07T09:25:42Z",
  };

  const renderWith = (webhooks: Webhook[]) =>
    render(
      <WebhookManager
        webhooks={webhooks}
        isLoading={false}
        onCreate={vi.fn()}
        onDelete={vi.fn().mockResolvedValue(undefined)}
      />,
    );

  it("labels a Slack webhook as Slack", () => {
    renderWith([slackHook]);

    expect(screen.getByText("Slack")).toBeInTheDocument();
  });

  it("marks a webhook whose last delivery failed", () => {
    renderWith([slackHook, { ...slackHook, id: "w-ok", last_triggered_at: "2026-10-07T10:00:00Z" }]);

    expect(screen.getAllByText("Failing")).toHaveLength(1);
  });

  it("shows why a test delivery failed", async () => {
    vi.mocked(webhookApi.test).mockResolvedValue({ success: false, status_code: 400, error: "HTTP 400: no_text" });
    renderWith([slackHook]);

    fireEvent.click(screen.getByRole("button", { name: /Send test/i }));

    await waitFor(() => expect(toast.error).toHaveBeenCalledWith(expect.stringContaining("HTTP 400: no_text")));
    expect(webhookApi.test).toHaveBeenCalledWith("w-slack");
  });
});
