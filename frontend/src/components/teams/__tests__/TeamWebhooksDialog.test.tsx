import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { TeamWebhooksDialog } from "../TeamWebhooksDialog";

vi.mock("@/api/webhooks", () => ({
  webhookApi: {
    getTeam: vi.fn().mockResolvedValue([]),
    createTeam: vi.fn(),
    update: vi.fn(),
    delete: vi.fn(),
    test: vi.fn(),
  },
}));
vi.mock("@/context/useAuth", () => ({
  useAuth: () => ({ permissions: [], hasPermission: () => false }),
}));

describe("TeamWebhooksDialog", () => {
  it("is as wide as the dependency dialog, so the webhook table fits without scrolling sideways on a desktop", () => {
    render(
      <QueryClientProvider client={new QueryClient()}>
        <TeamWebhooksDialog teamId="t-1" teamName="Platform" isOpen onClose={vi.fn()} canCreate={false} canDelete={false} canUpdate={false} />
      </QueryClientProvider>,
    );

    expect(screen.getByRole("dialog")).toHaveClass("max-w-5xl");
  });
});
