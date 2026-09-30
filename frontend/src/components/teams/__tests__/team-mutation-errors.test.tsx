import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { AxiosError, type AxiosResponse } from "axios";
import type { ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { Team } from "@/types/team";

import { AddMemberDialog } from "../AddMemberDialog";
import { CreateTeamDialog } from "../CreateTeamDialog";
import { EditTeamDialog } from "../EditTeamDialog";
import { TeamMembersDialog } from "../TeamMembersDialog";

const { teamApi, toastError } = vi.hoisted(() => ({
  teamApi: {
    create: vi.fn(),
    update: vi.fn(),
    addMember: vi.fn(),
    updateMember: vi.fn(),
    removeMember: vi.fn(),
  },
  toastError: vi.fn(),
}));

vi.mock("@/api/teams", () => ({ teamApi }));

vi.mock("sonner", () => ({
  toast: { error: toastError, success: vi.fn() },
}));

vi.mock("@/context/useAuth", () => ({
  useAuth: () => ({ permissions: [], hasPermission: () => false }),
}));

vi.mock("@/hooks/queries/use-users", () => ({
  useCurrentUser: () => ({ data: { id: "u-admin" } }),
}));

const TEAM: Team = {
  id: "t-1",
  name: "Team Beta",
  members: [
    { user_id: "u-admin", username: "admin", role: "admin" },
    { user_id: "u-2", username: "uimember", role: "member" },
  ],
  bindings: [],
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
};

function apiError(status: number, detail: string): AxiosError {
  const response = { status, statusText: "", headers: {}, config: {}, data: { detail } } as AxiosResponse;
  return new AxiosError(`Request failed with status code ${status}`, "ERR_BAD_REQUEST", undefined, undefined, response);
}

function memberRow(username: string): HTMLElement {
  return screen.getByText(username).closest("tr")!;
}

function renderWithClient(ui: ReactNode) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false }, mutations: { retry: false } } });
  return render(<QueryClientProvider client={qc}>{ui}</QueryClientProvider>);
}

beforeEach(() => vi.clearAllMocks());

describe("team mutations show the server's refusal", () => {
  it("adding an unverified user", async () => {
    teamApi.addMember.mockRejectedValue(apiError(404, "No user has verified this email address"));
    renderWithClient(<AddMemberDialog teamId="t-1" isOpen onClose={vi.fn()} />);

    fireEvent.change(screen.getByLabelText("Email"), { target: { value: "nobody-ui@example.com" } });
    fireEvent.click(screen.getByRole("button", { name: "Add Member" }));

    await waitFor(() =>
      expect(toastError).toHaveBeenCalledWith("Failed to add member", {
        description: "No user has verified this email address",
      }),
    );
  });

  it("creating a team", async () => {
    teamApi.create.mockRejectedValue(apiError(403, "Not enough permissions"));
    renderWithClient(<CreateTeamDialog />);

    fireEvent.click(screen.getByRole("button", { name: /Create Team/ }));
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "Team Gamma" } });
    fireEvent.click(screen.getByRole("button", { name: "Create Team" }));

    await waitFor(() =>
      expect(toastError).toHaveBeenCalledWith("Failed to create team", { description: "Not enough permissions" }),
    );
  });

  it("updating a team", async () => {
    teamApi.update.mockRejectedValue(apiError(404, "Team not found"));
    renderWithClient(<EditTeamDialog team={TEAM} isOpen onClose={vi.fn()} />);

    fireEvent.click(screen.getByRole("button", { name: "Update Team" }));

    await waitFor(() =>
      expect(toastError).toHaveBeenCalledWith("Failed to update team", { description: "Team not found" }),
    );
  });

  it("changing the role of a member removed meanwhile", async () => {
    teamApi.updateMember.mockRejectedValue(apiError(404, "User not in team"));
    renderWithClient(<TeamMembersDialog team={TEAM} isOpen onClose={vi.fn()} />);

    fireEvent.keyDown(within(memberRow("uimember")).getByRole("combobox"), { key: "Enter" });
    fireEvent.click(await screen.findByRole("option", { name: "Admin" }));

    await waitFor(() =>
      expect(toastError).toHaveBeenCalledWith("Failed to update member role", { description: "User not in team" }),
    );
  });

  it("removing a member", async () => {
    teamApi.removeMember.mockRejectedValue(apiError(404, "User not in team"));
    renderWithClient(<TeamMembersDialog team={TEAM} isOpen onClose={vi.fn()} />);

    fireEvent.click(within(memberRow("uimember")).getByRole("button"));

    await waitFor(() =>
      expect(toastError).toHaveBeenCalledWith("Failed to remove member", { description: "User not in team" }),
    );
  });
});
