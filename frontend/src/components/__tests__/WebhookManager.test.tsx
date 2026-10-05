import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";

import { WebhookManager } from "../WebhookManager";

vi.mock("@/context/useAuth", () => ({
  useAuth: () => ({
    isAuthenticated: true,
    isLoading: false,
    permissions: ["webhook:create", "webhook:delete"],
    hasPermission: (p: string) =>
      ["webhook:create", "webhook:delete"].includes(p),
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
});
