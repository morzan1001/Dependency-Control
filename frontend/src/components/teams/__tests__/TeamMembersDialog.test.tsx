import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { gitlabInstancesApi } from "@/api/gitlab-instances";
import { githubInstancesApi } from "@/api/github-instances";
import type { Team } from "@/types/team";

import { TeamMembersDialog } from "../TeamMembersDialog";

const auth = vi.hoisted(() => ({ permissions: [] as string[] }));

vi.mock("@/api/gitlab-instances", () => ({ gitlabInstancesApi: { list: vi.fn() } }));
vi.mock("@/api/github-instances", () => ({ githubInstancesApi: { list: vi.fn() } }));
vi.mock("@/context/useAuth", () => ({
  useAuth: () => ({ permissions: auth.permissions, hasPermission: (p: string) => auth.permissions.includes(p) }),
}));
vi.mock("@/hooks/queries/use-users", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/hooks/queries/use-users")>()),
  useCurrentUser: () => ({ data: { id: "u-admin" } }),
}));

const TEAM: Team = {
  id: "t-1",
  name: "Platform Engineering",
  members: [
    { user_id: "u-admin", username: "carol", role: "admin", source: "manual" },
    { user_id: "u-gitlab", username: "Bob Example", role: "member", source: "gitlab:gl-1" },
    { user_id: "u-github", username: "alice.jensen", role: "member", source: "github:gh-removed" },
  ],
  bindings: [],
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
};

function page<T>(items: T[]) {
  return { items, total: items.length, page: 1, size: 100, pages: 1 };
}

function renderDialog(team: Team = TEAM) {
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <TeamMembersDialog team={team} isOpen onClose={vi.fn()} />
    </QueryClientProvider>,
  );
}

beforeEach(() => {
  vi.clearAllMocks();
  auth.permissions = [];
  vi.mocked(gitlabInstancesApi.list).mockResolvedValue(
    page([{ id: "gl-1", name: "Internal GitLab", url: "https://gitlab.example.com" }]) as never,
  );
  vi.mocked(githubInstancesApi.list).mockResolvedValue(page([]) as never);
});

describe("TeamMembersDialog empty team", () => {
  it("names an empty team under the table, as the other tables do", () => {
    renderDialog({ ...TEAM, members: [] });

    expect(screen.getByText("No members in this team.").closest("table")).toBeNull();
  });
});

describe("TeamMembersDialog sync source", () => {
  it("names a synced member's provider and instance the way the binding dialog names a binding", async () => {
    auth.permissions = ["system:manage"];

    renderDialog();

    expect(await screen.findByText("Synced from GitLab · Internal GitLab")).toBeInTheDocument();
    expect(screen.queryByText(/gl-1/)).not.toBeInTheDocument();
  });

  it("names only the provider of an instance it cannot name", async () => {
    auth.permissions = ["system:manage"];

    renderDialog();

    await screen.findByText("Synced from GitLab · Internal GitLab");
    expect(screen.getByText("Synced from GitHub")).toBeInTheDocument();
    expect(screen.queryByText(/gh-removed/)).not.toBeInTheDocument();
  });

  it("names only the provider for a caller who may not list the instances, and asks for none", () => {
    renderDialog();

    expect(screen.getByText("Synced from GitLab")).toBeInTheDocument();
    expect(gitlabInstancesApi.list).not.toHaveBeenCalled();
    expect(githubInstancesApi.list).not.toHaveBeenCalled();
  });

  it("shows a source it does not know as it is stored and none for a member added by hand", () => {
    renderDialog({ ...TEAM, members: [TEAM.members[0], { user_id: "u-legacy", username: "dana", role: "member", source: "auth-shepherd" }] });

    expect(screen.getByText("Synced from auth-shepherd")).toBeInTheDocument();
    expect(screen.getAllByText(/Synced from/)).toHaveLength(1);
  });
});

describe("TeamMembersDialog accessible names", () => {
  it("names each role dropdown by its member, as the notification matrix names its boxes", () => {
    auth.permissions = ["team:update"];
    renderDialog();

    expect(screen.getByRole("combobox", { name: "Bob Example: Role" })).toBeInTheDocument();
  });
});

describe("TeamMembersDialog sync-owned members", () => {
  const SYNC_OWNED: Team = {
    ...TEAM,
    members: [TEAM.members[0], { ...TEAM.members[1], sync_owned: true }, TEAM.members[2]],
  };

  it("offers no role change or removal for a member a live sync owns and says where to change it", async () => {
    auth.permissions = ["team:update", "system:manage"];
    renderDialog(SYNC_OWNED);

    const role = screen.getByRole("combobox", { name: "Bob Example: Role" });
    expect(role).toBeDisabled();
    expect(screen.getByRole("button", { name: "Remove Bob Example" })).toBeDisabled();

    await screen.findByText("Synced from GitLab · Internal GitLab");
    fireEvent.pointerMove(role.parentElement!, { pointerType: "mouse" });
    expect(await screen.findByRole("tooltip")).toHaveTextContent(
      "Synced from GitLab · Internal GitLab; change their membership there",
    );
  });

  it("leaves a synced member editable when no live sync owns the entry", () => {
    auth.permissions = ["team:update"];
    renderDialog();

    expect(screen.getByRole("combobox", { name: "Bob Example: Role" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "Remove Bob Example" })).toBeEnabled();
  });
});
