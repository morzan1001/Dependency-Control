import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import type { ReactNode } from "react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { Team } from "@/types/team";

import { TeamGitHubBindingDialog } from "../TeamGitHubBindingDialog";

const { setGithubBinding, clearGithubBinding, listInstances, listOrgs, listOrgTeams, toastError } = vi.hoisted(
  () => ({
    setGithubBinding: vi.fn(),
    clearGithubBinding: vi.fn(),
    listInstances: vi.fn(),
    listOrgs: vi.fn(),
    listOrgTeams: vi.fn(),
    toastError: vi.fn(),
  }),
);

vi.mock("@/api/teams", () => ({
  teamApi: { setGithubBinding, clearGithubBinding },
}));

vi.mock("@/api/github-instances", () => ({
  githubInstancesApi: { list: listInstances, listOrgs, listOrgTeams },
}));

vi.mock("sonner", () => ({
  toast: { error: toastError, success: vi.fn() },
}));

const INSTANCE = { id: "gh-1", name: "GitHub.com" };
const ORG_TEAMS = [
  { id: 4711, slug: "payments", name: "Payments", parent_slug: null, parent_name: null },
  { id: 900, slug: "cards", name: "Cards", parent_slug: "payments", parent_name: "Payments" },
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

function Wrapper({ children }: { children: ReactNode }) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>;
}

function renderDialog(subject: Team) {
  render(<TeamGitHubBindingDialog team={subject} isOpen onClose={() => {}} />, { wrapper: Wrapper });
}

beforeEach(() => {
  vi.clearAllMocks();
  listInstances.mockResolvedValue({ items: [INSTANCE], total: 1, page: 1, size: 100, pages: 1 });
  listOrgs.mockResolvedValue(["Acme"]);
  listOrgTeams.mockResolvedValue(ORG_TEAMS);
  setGithubBinding.mockResolvedValue(BOUND);
  clearGithubBinding.mockResolvedValue(team());
});

describe("TeamGitHubBindingDialog", () => {
  it("says a team nothing resolves to is unbound and offers nothing to remove", () => {
    renderDialog(team());

    expect(screen.getByText(/Not bound/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Remove" })).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Save Binding/ })).toBeDisabled();
  });

  it("shows the organisation and the number the binding points at, not only the team's name", () => {
    renderDialog(BOUND);

    expect(screen.getByText("Acme/payments (#4711)")).toBeInTheDocument();
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

  it("removes a mis-binding", async () => {
    renderDialog(BOUND);

    fireEvent.click(screen.getByRole("button", { name: "Remove" }));

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

    const [, , teamSelect] = await screen.findAllByRole("combobox");
    fireEvent.click(teamSelect);

    expect(await screen.findByText("Cards (cards) — under Payments")).toBeInTheDocument();
  });
});
