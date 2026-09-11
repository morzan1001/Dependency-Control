import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { Team } from "@/types/team";

import { TeamCard } from "../TeamCard";

const { granted } = vi.hoisted(() => ({ granted: { current: [] as string[] } }));

vi.mock("@/context/useAuth", () => ({
  useAuth: () => ({
    permissions: granted.current,
    hasPermission: (permission: string) => granted.current.includes(permission),
  }),
}));

vi.mock("@/hooks/queries/use-users", () => ({
  useCurrentUser: () => ({ data: { id: "u-1" } }),
}));

const TEAM: Team = {
  id: "t-1",
  name: "Payments Guild",
  members: [{ user_id: "u-1", role: "admin" }],
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
};

function renderCard(onManageGithubBinding = vi.fn()) {
  render(
    <TeamCard
      team={TEAM}
      onEdit={vi.fn()}
      onManageMembers={vi.fn()}
      onAddMember={vi.fn()}
      onDelete={vi.fn()}
      onManageWebhooks={vi.fn()}
      onManageGithubBinding={onManageGithubBinding}
    />,
  );
  return onManageGithubBinding;
}

beforeEach(() => {
  granted.current = [];
});

describe("TeamCard GitHub binding", () => {
  it("is offered to a system administrator", () => {
    granted.current = ["system:manage"];

    const open = renderCard();

    fireEvent.click(screen.getByRole("button", { name: "GitHub binding" }));

    expect(open).toHaveBeenCalledWith(TEAM);
  });

  it("is withheld from a team admin, whose own team it would let capture other repositories", () => {
    granted.current = ["team:update", "team:read"];

    renderCard();

    expect(screen.queryByRole("button", { name: "GitHub binding" })).not.toBeInTheDocument();
  });
});
