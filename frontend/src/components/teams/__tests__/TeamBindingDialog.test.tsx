import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { Team } from "@/types/team";

import { TeamBindingDialog } from "../TeamBindingDialog";

const {
  setGithubBinding,
  clearGithubBinding,
  setGitlabBinding,
  clearGitlabBinding,
  listInstances,
  listOrgs,
  listOrgTeams,
  listGitlabInstances,
  listGroups,
  toastError,
} = vi.hoisted(() => ({
  setGithubBinding: vi.fn(),
  clearGithubBinding: vi.fn(),
  setGitlabBinding: vi.fn(),
  clearGitlabBinding: vi.fn(),
  listInstances: vi.fn(),
  listOrgs: vi.fn(),
  listOrgTeams: vi.fn(),
  listGitlabInstances: vi.fn(),
  listGroups: vi.fn(),
  toastError: vi.fn(),
}));

vi.mock("@/api/teams", () => ({
  teamApi: { setGithubBinding, clearGithubBinding, setGitlabBinding, clearGitlabBinding },
}));

vi.mock("@/api/github-instances", () => ({
  githubInstancesApi: { list: listInstances, listOrgs, listOrgTeams },
}));

vi.mock("@/api/gitlab-instances", () => ({
  gitlabInstancesApi: { list: listGitlabInstances, listGroups },
}));

vi.mock("sonner", () => ({
  toast: { error: toastError, success: vi.fn() },
}));

const INSTANCE = { id: "gh-1", name: "GitHub.com" };
const GITLAB_INSTANCE = { id: "gl-1", name: "GitLab Corp" };
const ORG_TEAMS = [
  { id: 4711, slug: "payments", name: "Payments", parent_slug: null, parent_name: null },
  { id: 900, slug: "cards", name: "Cards", parent_slug: "payments", parent_name: "Payments" },
];
const GROUPS = [
  { id: 77, full_path: "mo/edge", name: "Edge" },
  { id: 12, full_path: "mo", name: "MO" },
];

function team(overrides: Partial<Team> = {}): Team {
  return {
    id: "t-1",
    name: "Payments Guild",
    members: [],
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
    ...overrides,
  };
}

const BOUND = team({
  github_instance_id: "gh-1",
  github_org: "Acme",
  github_team_id: 4711,
  github_team_slug: "payments",
});

const GITLAB_BOUND = team({
  gitlab_instance_id: "gl-1",
  gitlab_group_id: 77,
  gitlab_group_path: "mo/edge",
});

function Wrapper({ children }: { children: ReactNode }) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>;
}

function renderDialog(subject: Team) {
  render(<TeamBindingDialog team={subject} isOpen onClose={() => {}} />, { wrapper: Wrapper });
}

function pickProvider(name: "GitHub" | "GitLab") {
  fireEvent.click(screen.getByLabelText("Provider"));
  fireEvent.click(screen.getByRole("option", { name }));
}

// The listing selects stay disabled until their query settles, and a click on a disabled
// trigger is silently dropped.
async function openSelect(label: string) {
  const trigger = await screen.findByLabelText(label);
  await waitFor(() => expect(trigger).toBeEnabled());
  fireEvent.click(trigger);
}

async function pickOption(label: string, optionName: string) {
  await openSelect(label);
  fireEvent.click(await screen.findByRole("option", { name: optionName }));
}

beforeEach(() => {
  vi.clearAllMocks();
  listInstances.mockResolvedValue({ items: [INSTANCE], total: 1, page: 1, size: 100, pages: 1 });
  listGitlabInstances.mockResolvedValue({
    items: [GITLAB_INSTANCE],
    total: 1,
    page: 1,
    size: 100,
    pages: 1,
  });
  listOrgs.mockResolvedValue(["Acme"]);
  listOrgTeams.mockResolvedValue(ORG_TEAMS);
  listGroups.mockResolvedValue(GROUPS);
  setGithubBinding.mockResolvedValue(BOUND);
  clearGithubBinding.mockResolvedValue(team());
  setGitlabBinding.mockResolvedValue(GITLAB_BOUND);
  clearGitlabBinding.mockResolvedValue(team());
});

describe("TeamBindingDialog", () => {
  it("offers both providers, because a team can be bound on either", async () => {
    renderDialog(team());

    fireEvent.click(screen.getByLabelText("Provider"));

    expect(await screen.findByRole("option", { name: "GitHub" })).toBeInTheDocument();
    expect(await screen.findByRole("option", { name: "GitLab" })).toBeInTheDocument();
  });

  it("says a team nothing resolves to is unbound on either provider and offers nothing to remove", () => {
    renderDialog(team());

    expect(screen.getAllByText("Not bound")).toHaveLength(2);
    expect(screen.queryByRole("button", { name: /Remove/ })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Save Binding/ })).toBeDisabled();
  });

  it("shows both bindings at once, because holding one does not release the other", () => {
    renderDialog(
      team({
        github_org: "Acme",
        github_team_id: 4711,
        github_team_slug: "payments",
        gitlab_group_id: 77,
        gitlab_group_path: "mo/edge",
      }),
    );

    expect(screen.getByText("Acme/payments (#4711)")).toBeInTheDocument();
    expect(screen.getByText("mo/edge (#77)")).toBeInTheDocument();
  });

  it("says what removing a binding costs, so a mis-binding is reversed knowingly", () => {
    renderDialog(BOUND);

    expect(screen.getByText(/retired on their next sync/)).toBeInTheDocument();
  });

  it("sends the team number as a number, which is what the binding is stored on", async () => {
    renderDialog(BOUND);

    fireEvent.click(screen.getByRole("button", { name: /Save Binding/ }));

    await waitFor(() =>
      expect(setGithubBinding).toHaveBeenCalledWith("t-1", {
        github_instance_id: "gh-1",
        github_org: "Acme",
        github_team_id: 4711,
      }),
    );
  });

  it("removes a GitHub mis-binding", async () => {
    renderDialog(BOUND);

    fireEvent.click(screen.getByRole("button", { name: "Remove GitHub binding" }));

    await waitFor(() => expect(clearGithubBinding).toHaveBeenCalledWith("t-1"));
  });

  it("surfaces the refusal when the GitHub team is already bound elsewhere", async () => {
    setGithubBinding.mockRejectedValue({
      response: { data: { detail: "Team 'Payments' is already bound to GitHub team 4711." } },
    });
    renderDialog(BOUND);

    fireEvent.click(screen.getByRole("button", { name: /Save Binding/ }));

    await waitFor(() =>
      expect(toastError).toHaveBeenCalledWith("Team 'Payments' is already bound to GitHub team 4711."),
    );
  });

  it("offers the organisation's teams with the parent that tells a nested one apart", async () => {
    renderDialog(BOUND);

    await openSelect("GitHub team");

    expect(await screen.findByRole("option", { name: "Cards (cards) — under Payments" })).toBeInTheDocument();
  });

  it("opens on GitLab for a team only GitLab resolves to", () => {
    renderDialog(GITLAB_BOUND);

    expect(screen.getByLabelText("Group")).toBeInTheDocument();
  });

  it("sends the group number as a number, which is what the binding is stored on", async () => {
    renderDialog(GITLAB_BOUND);

    fireEvent.click(screen.getByRole("button", { name: /Save Binding/ }));

    await waitFor(() =>
      expect(setGitlabBinding).toHaveBeenCalledWith("t-1", {
        gitlab_instance_id: "gl-1",
        gitlab_group_id: 77,
      }),
    );
  });

  it("offers the instance's groups by the full path that tells two same-named subgroups apart", async () => {
    renderDialog(GITLAB_BOUND);

    await openSelect("Group");

    expect(await screen.findByRole("option", { name: "Edge (mo/edge)" })).toBeInTheDocument();
  });

  it("removes a GitLab mis-binding", async () => {
    renderDialog(GITLAB_BOUND);

    fireEvent.click(screen.getByRole("button", { name: "Remove GitLab binding" }));

    await waitFor(() => expect(clearGitlabBinding).toHaveBeenCalledWith("t-1"));
  });

  it("surfaces the refusal when the GitLab group is already bound elsewhere", async () => {
    setGitlabBinding.mockRejectedValue({
      response: { data: { detail: "Team 'Platform' is already bound to GitLab group 77." } },
    });
    renderDialog(GITLAB_BOUND);

    fireEvent.click(screen.getByRole("button", { name: /Save Binding/ }));

    await waitFor(() =>
      expect(toastError).toHaveBeenCalledWith("Team 'Platform' is already bound to GitLab group 77."),
    );
  });

  it("binds on GitLab a team that only GitHub resolves to, without touching the GitHub binding", async () => {
    renderDialog(BOUND);

    pickProvider("GitLab");
    await pickOption("Instance", "GitLab Corp");
    await pickOption("Group", "Edge (mo/edge)");
    fireEvent.click(screen.getByRole("button", { name: /Save Binding/ }));

    await waitFor(() =>
      expect(setGitlabBinding).toHaveBeenCalledWith("t-1", {
        gitlab_instance_id: "gl-1",
        gitlab_group_id: 77,
      }),
    );
    expect(setGithubBinding).not.toHaveBeenCalled();
  });
});
