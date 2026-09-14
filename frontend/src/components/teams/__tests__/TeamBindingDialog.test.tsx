import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { Team, TeamBinding } from "@/types/team";

import { TeamBindingDialog } from "../TeamBindingDialog";

const {
  setBinding,
  clearBinding,
  listInstances,
  listOrgs,
  listOrgTeams,
  listGitlabInstances,
  listGroups,
  toastError,
} = vi.hoisted(() => ({
  setBinding: vi.fn(),
  clearBinding: vi.fn(),
  listInstances: vi.fn(),
  listOrgs: vi.fn(),
  listOrgTeams: vi.fn(),
  listGitlabInstances: vi.fn(),
  listGroups: vi.fn(),
  toastError: vi.fn(),
}));

vi.mock("@/api/teams", () => ({
  teamApi: { setBinding, clearBinding },
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

const GITHUB = { id: "gh-1", name: "GitHub.com", is_active: true, sync_teams: true };
// This installation runs two GitLab instances, one of which does not sync teams.
const GITLAB = { id: "gl-1", name: "GitLab Corp", is_active: true, sync_teams: true };
const GITLAB_NO_SYNC = { id: "gl-2", name: "GitLab Legacy", is_active: true, sync_teams: false };

const listOf = (items: object[]) => ({ items, total: items.length, page: 1, size: 100, pages: 1 });
const NO_INSTANCES = listOf([]);
const NOTHING_CONFIGURED = /No active GitHub or GitLab instance is configured/;
const WITHHELD_NOTE = /GitLab Legacy is not offered: team sync is off/;

const ORG_TEAMS = [
  { id: 4711, slug: "payments", name: "Payments", parent_slug: null, parent_name: null },
  { id: 900, slug: "cards", name: "Cards", parent_slug: "payments", parent_name: "Payments" },
];
const GROUPS = [
  { id: 77, full_path: "mo/edge", name: "Edge" },
  { id: 12, full_path: "mo", name: "MO" },
];

const GITHUB_BINDING: TeamBinding = {
  provider: "github",
  instance_id: "gh-1",
  org: "Acme",
  slug: "payments",
  external_id: 4711,
};
const GITLAB_BINDING: TeamBinding = {
  provider: "gitlab",
  instance_id: "gl-1",
  path: "mo/edge",
  external_id: 77,
};
const LEGACY_BINDING: TeamBinding = {
  provider: "gitlab",
  instance_id: "gl-2",
  path: "mo/attic",
  external_id: 5,
};

function team(bindings: TeamBinding[] = []): Team {
  return {
    id: "t-1",
    name: "Payments Guild",
    members: [],
    bindings,
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
  };
}

function Wrapper({ children }: { children: ReactNode }) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>;
}

function renderDialog(subject: Team) {
  render(<TeamBindingDialog team={subject} isOpen onClose={() => {}} />, { wrapper: Wrapper });
}

async function saveBinding() {
  fireEvent.click(await screen.findByRole("button", { name: /Save Binding/ }));
}

// The listing selects stay disabled until their query settles, and a click on a disabled
// trigger is silently dropped.
async function openSelect(label: string) {
  const trigger = await screen.findByLabelText(label);
  await waitFor(() => expect(trigger).toBeEnabled());
  fireEvent.click(trigger);
}

async function pickOption(label: string, optionName: string | RegExp) {
  await openSelect(label);
  fireEvent.click(await screen.findByRole("option", { name: optionName }));
}

beforeEach(() => {
  vi.clearAllMocks();
  listInstances.mockResolvedValue(listOf([GITHUB]));
  listGitlabInstances.mockResolvedValue(listOf([GITLAB, GITLAB_NO_SYNC]));
  listOrgs.mockResolvedValue(["Acme"]);
  listOrgTeams.mockResolvedValue(ORG_TEAMS);
  listGroups.mockResolvedValue(GROUPS);
  setBinding.mockResolvedValue(team([GITLAB_BINDING]));
  clearBinding.mockResolvedValue(team());
});

describe("TeamBindingDialog", () => {
  it("lists every binding the team holds, each naming the instance it is held on", async () => {
    renderDialog(team([GITHUB_BINDING, GITLAB_BINDING, LEGACY_BINDING]));

    expect(await screen.findByText("GitHub · GitHub.com")).toBeInTheDocument();
    expect(screen.getByText("Acme/payments (#4711)")).toBeInTheDocument();
    expect(screen.getByText("GitLab · GitLab Corp")).toBeInTheDocument();
    expect(screen.getByText("mo/edge (#77)")).toBeInTheDocument();
    expect(screen.getByText("GitLab · GitLab Legacy")).toBeInTheDocument();
    expect(screen.getByText("mo/attic (#5)")).toBeInTheDocument();
  });

  it("offers nothing to remove for a team no instance resolves to", async () => {
    renderDialog(team());

    expect(await screen.findByLabelText("Instance")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /^Remove/ })).not.toBeInTheDocument();
    expect(screen.queryByText(/retired on their next sync/)).not.toBeInTheDocument();
  });

  it("does not offer an instance this team is already bound to", async () => {
    renderDialog(team([GITLAB_BINDING]));

    await openSelect("Instance");

    expect(await screen.findByRole("option", { name: "GitHub.com" })).toBeInTheDocument();
    expect(screen.queryByRole("option", { name: "GitLab Corp" })).not.toBeInTheDocument();
  });

  it("does not offer an instance whose team sync is off", async () => {
    renderDialog(team());

    await openSelect("Instance");

    expect(await screen.findByRole("option", { name: "GitLab Corp" })).toBeInTheDocument();
    expect(screen.queryByRole("option", { name: /GitLab Legacy/ })).not.toBeInTheDocument();
  });

  it("keeps a binding listed and removable once its instance is gone", async () => {
    listGitlabInstances.mockResolvedValue(listOf([GITLAB_NO_SYNC]));
    renderDialog(team([GITLAB_BINDING]));

    expect(await screen.findByText("mo/edge (#77)")).toBeInTheDocument();
    expect(await screen.findByText(/this binding can only be removed/)).toBeInTheDocument();
    expect(screen.getByText("GitLab · gl-1")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Remove the binding on gl-1" }));

    await waitFor(() => expect(clearBinding).toHaveBeenCalledWith("t-1", "gl-1"));
  });

  it("keeps a binding on a deactivated instance removable", async () => {
    listGitlabInstances.mockResolvedValue(listOf([{ ...GITLAB, is_active: false }]));
    renderDialog(team([GITLAB_BINDING]));

    expect(await screen.findByText(/this binding can only be removed/)).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Remove the binding on GitLab Corp" }));

    await waitFor(() => expect(clearBinding).toHaveBeenCalledWith("t-1", "gl-1"));

    await openSelect("Instance");
    expect(screen.queryByRole("option", { name: "GitLab Corp" })).not.toBeInTheDocument();
  });

  it("removes one binding and leaves the others, because each instance stands alone", async () => {
    renderDialog(team([GITHUB_BINDING, GITLAB_BINDING]));

    fireEvent.click(await screen.findByRole("button", { name: "Remove the binding on GitHub.com" }));

    await waitFor(() => expect(clearBinding).toHaveBeenCalledWith("t-1", "gh-1"));
    expect(clearBinding).toHaveBeenCalledTimes(1);
  });

  it("says what removing a binding costs, so a mis-binding is reversed knowingly", async () => {
    renderDialog(team([GITLAB_BINDING]));

    expect(await screen.findByText(/retired on their next sync/)).toBeInTheDocument();
  });

  it("names the team that already holds the group when the write is refused", async () => {
    setBinding.mockRejectedValue({
      response: { data: { detail: "Team 'Platform' is already bound to GitLab group 77." } },
    });
    renderDialog(team());

    await pickOption("Instance", "GitLab Corp");
    await pickOption("Group", "Edge (mo/edge)");
    await saveBinding();

    await waitFor(() =>
      expect(toastError).toHaveBeenCalledWith("Team 'Platform' is already bound to GitLab group 77."),
    );
  });

  it("binds the picked GitLab instance, sending the group number as a number", async () => {
    renderDialog(team([GITHUB_BINDING]));

    await pickOption("Instance", "GitLab Corp");
    await pickOption("Group", "Edge (mo/edge)");
    await saveBinding();

    await waitFor(() =>
      expect(setBinding).toHaveBeenCalledWith("t-1", {
        provider: "gitlab",
        instance_id: "gl-1",
        external_id: 77,
      }),
    );
  });

  it("binds the picked GitHub instance, sending the team number as a number", async () => {
    renderDialog(team([GITLAB_BINDING]));

    await pickOption("Instance", "GitHub.com");
    await pickOption("Organisation", "Acme");
    await pickOption("GitHub team", "Cards (cards) — under Payments");
    await saveBinding();

    await waitFor(() =>
      expect(setBinding).toHaveBeenCalledWith("t-1", {
        provider: "github",
        instance_id: "gh-1",
        org: "Acme",
        external_id: 900,
      }),
    );
  });

  it("offers the instance's groups by the full path that tells two same-named subgroups apart", async () => {
    renderDialog(team());

    await pickOption("Instance", "GitLab Corp");
    await openSelect("Group");

    expect(await screen.findByRole("option", { name: "Edge (mo/edge)" })).toBeInTheDocument();
  });

  it("names the instance it withholds, so its absence is not read as a fault", async () => {
    renderDialog(team());

    expect(await screen.findByText(WITHHELD_NOTE)).toHaveTextContent(
      "Switch it on under Settings → Integrations.",
    );
  });

  it("says nothing about withheld instances when every instance syncs teams", async () => {
    listGitlabInstances.mockResolvedValue(listOf([GITLAB]));
    renderDialog(team());

    expect(await screen.findByLabelText("Instance")).toBeInTheDocument();
    expect(screen.queryByText(/not offered/)).not.toBeInTheDocument();
  });

  it("keeps a binding held on an instance without team sync listed and removable", async () => {
    renderDialog(team([LEGACY_BINDING]));

    expect(await screen.findByText("GitLab · GitLab Legacy")).toBeInTheDocument();
    expect(screen.getByText("mo/attic (#5)")).toBeInTheDocument();
    expect(screen.getByText(/Team sync is off on this instance/)).toBeInTheDocument();
    expect(screen.queryByText(WITHHELD_NOTE)).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Remove the binding on GitLab Legacy" }));

    await waitFor(() => expect(clearBinding).toHaveBeenCalledWith("t-1", "gl-2"));
  });

  it("picks the only instance on offer, so a single-instance installation needs no choice", async () => {
    listInstances.mockResolvedValue(NO_INSTANCES);
    listGitlabInstances.mockResolvedValue(listOf([GITLAB]));
    renderDialog(team());

    expect(await screen.findByLabelText("Group")).toBeInTheDocument();
  });

  it("offers no GitHub instance to an installation without one", async () => {
    listInstances.mockResolvedValue(NO_INSTANCES);
    renderDialog(team());

    await openSelect("Instance");

    expect(await screen.findByRole("option", { name: "GitLab Corp" })).toBeInTheDocument();
    expect(screen.queryByText("GitHub")).not.toBeInTheDocument();
    expect(
      screen.getByText(/Repositories held by a bound GitLab group are assigned to Payments Guild/),
    ).toBeInTheDocument();
  });

  it("names where instances are managed when none is active", async () => {
    listInstances.mockResolvedValue(NO_INSTANCES);
    listGitlabInstances.mockResolvedValue(NO_INSTANCES);
    renderDialog(team());

    expect(await screen.findByText(NOTHING_CONFIGURED)).toHaveTextContent(
      "Instances are managed under Settings → Integrations.",
    );
    expect(screen.queryByLabelText("Instance")).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Save Binding/ })).not.toBeInTheDocument();
  });

  it("says so when the team already holds a binding on every active instance", async () => {
    renderDialog(team([GITHUB_BINDING, GITLAB_BINDING, LEGACY_BINDING]));

    expect(
      await screen.findByText("This team already holds a binding on every active instance."),
    ).toBeInTheDocument();
    expect(screen.queryByLabelText("Instance")).not.toBeInTheDocument();
  });

  it("waits for both instance lists before declaring the installation empty", async () => {
    let releaseGithub: (list: ReturnType<typeof listOf>) => void = () => {};
    listInstances.mockReturnValue(
      new Promise<ReturnType<typeof listOf>>((resolve) => {
        releaseGithub = resolve;
      }),
    );
    listGitlabInstances.mockResolvedValue(NO_INSTANCES);
    renderDialog(team());

    await waitFor(() => expect(listGitlabInstances).toHaveBeenCalled());
    expect(screen.queryByText(NOTHING_CONFIGURED)).not.toBeInTheDocument();

    releaseGithub(listOf([GITHUB]));

    expect(await screen.findByLabelText("Organisation")).toBeInTheDocument();
    expect(screen.queryByText(NOTHING_CONFIGURED)).not.toBeInTheDocument();
  });
});
