import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import type { Team } from "@/types/team";

import { TeamFormDialog } from "../TeamFormDialog";

const { teamApi } = vi.hoisted(() => ({ teamApi: { create: vi.fn(), update: vi.fn(), getAll: vi.fn() } }));
vi.mock("@/api/teams", () => ({ teamApi }));
vi.mock("sonner", () => ({ toast: { error: vi.fn(), success: vi.fn() } }));

const TEAM: Team = {
  id: "t-1",
  name: "Team Beta",
  description: "Platform squad",
  members: [],
  bindings: [],
  created_at: "2026-01-01T00:00:00Z",
  updated_at: "2026-01-01T00:00:00Z",
};

beforeEach(() => {
  vi.clearAllMocks();
  teamApi.create.mockResolvedValue({ id: "t-new" });
  teamApi.update.mockResolvedValue(TEAM);
  teamApi.getAll.mockResolvedValue([TEAM, { ...TEAM, id: "t-2", name: "Team Gamma" }, { ...TEAM, id: "t-3", name: "TEAM BETA" }]);
});

function editTeam() {
  const onClose = vi.fn();
  render(
    <QueryClientProvider client={new QueryClient()}>
      <TeamFormDialog team={TEAM} onClose={onClose} />
    </QueryClientProvider>,
  );
  return { onClose, dialog: screen.getByRole("dialog") };
}

describe("editing a team", () => {
  it("stacks its fields in a default-width dialog that ends in Cancel and Save Changes, like the other edit dialogs", () => {
    const { dialog } = editTeam();

    expect(dialog).not.toHaveClass("sm:max-w-[425px]");
    expect(screen.getByLabelText("Name").parentElement).toHaveClass("grid", "gap-2");
    expect(screen.getByLabelText("Description").parentElement).toHaveClass("grid", "gap-2");
    expect(within(dialog).getByRole("button", { name: "Cancel" })).toHaveClass("border");
    expect(within(dialog).getByRole("button", { name: "Save Changes" })).toHaveAttribute("type", "submit");
    expect(within(dialog).queryByRole("button", { name: "Update Team" })).not.toBeInTheDocument();
  });

  it("saves the name and description with Save Changes and closes", async () => {
    const { onClose, dialog } = editTeam();

    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "Team Gamma" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Save Changes" }));

    await waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(teamApi.update).toHaveBeenCalledWith("t-1", { name: "Team Gamma", description: "Platform squad" });
  });

  it("closes without saving through Cancel", () => {
    const { onClose, dialog } = editTeam();

    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "Team Gamma" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));

    expect(onClose).toHaveBeenCalled();
    expect(teamApi.update).not.toHaveBeenCalled();
  });
});

describe("creating a team", () => {
  it("keeps an unsent draft across closing and starts empty after a create", async () => {
    render(
      <QueryClientProvider client={new QueryClient()}>
        <TeamFormDialog />
      </QueryClientProvider>,
    );
    const open = () => fireEvent.click(screen.getByRole("button", { name: /Create Team/ }));

    open();
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "Team Gamma" } });
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Close" }));
    open();
    expect(screen.getByLabelText("Name")).toHaveValue("Team Gamma");

    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Create Team" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());
    expect(teamApi.create).toHaveBeenCalledWith({ name: "Team Gamma", description: "" });
    open();
    expect(screen.getByLabelText("Name")).toHaveValue("");
  });

  it("offers Cancel beside Create Team and keeps the draft it closes on", () => {
    render(
      <QueryClientProvider client={new QueryClient()}>
        <TeamFormDialog />
      </QueryClientProvider>,
    );
    fireEvent.click(screen.getByRole("button", { name: /Create Team/ }));
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "Team Gamma" } });

    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Cancel" }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: /Create Team/ }));

    expect(screen.getByLabelText("Name")).toHaveValue("Team Gamma");
    expect(teamApi.create).not.toHaveBeenCalled();
  });
});

describe("the team name check", () => {
  const TAKEN = "A team with this name already exists";

  it("hints at a name another team holds, says nothing while the name is unchanged, and still saves", async () => {
    const { onClose, dialog } = editTeam();

    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "team gamma " } });
    const hint = await screen.findByText(TAKEN);
    expect(screen.getByLabelText("Name").parentElement).toContainElement(hint);
    expect(screen.getByLabelText("Name")).toHaveAccessibleDescription(TAKEN);
    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "Team Beta" } });
    expect(screen.queryByText(TAKEN)).not.toBeInTheDocument();
    expect(screen.getByLabelText("Name")).not.toHaveAttribute("aria-describedby");

    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "Team Gamma" } });
    await screen.findByText(TAKEN);
    fireEvent.click(within(dialog).getByRole("button", { name: "Save Changes" }));
    await waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(teamApi.update).toHaveBeenCalledWith("t-1", { name: "Team Gamma", description: "Platform squad" });
  });

  it("hints at a taken name while creating a team, and loads the teams only once the dialog opens", async () => {
    render(
      <QueryClientProvider client={new QueryClient()}>
        <TeamFormDialog />
      </QueryClientProvider>,
    );
    expect(teamApi.getAll).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: /Create Team/ }));

    fireEvent.change(screen.getByLabelText("Name"), { target: { value: "TEAM BETA" } });

    expect(await screen.findByText(TAKEN)).toBeInTheDocument();
    expect(within(screen.getByRole("dialog")).getByRole("button", { name: "Create Team" })).toBeEnabled();
  });
});
