import { render, screen, fireEvent } from "@testing-library/react";
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
  it("exposes all 7 webhook event types in the create dialog", () => {
    render(
      <WebhookManager
        webhooks={[]}
        isLoading={false}
        onCreate={vi.fn().mockResolvedValue({ id: "w1" })}
        onDelete={vi.fn().mockResolvedValue(undefined)}
      />,
    );

    // Open the create dialog
    fireEvent.click(screen.getByRole("button", { name: /Add Webhook/i }));

    // All 7 event labels must be present
    expect(screen.getByLabelText(/Scan completed/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/Vulnerability found/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/Analysis failed/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/Crypto asset ingested/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/Crypto policy changed/i)).toBeInTheDocument();
    expect(
      screen.getByLabelText(/Compliance report generated/i),
    ).toBeInTheDocument();
    expect(
      screen.getByLabelText(/PQC migration plan generated/i),
    ).toBeInTheDocument();
  });
});
