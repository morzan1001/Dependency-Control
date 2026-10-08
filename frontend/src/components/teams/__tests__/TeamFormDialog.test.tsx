import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { TeamFormDialog } from "../TeamFormDialog";

const { teamApi } = vi.hoisted(() => ({ teamApi: { create: vi.fn(), update: vi.fn() } }));
vi.mock("@/api/teams", () => ({ teamApi }));
vi.mock("sonner", () => ({ toast: { error: vi.fn(), success: vi.fn() } }));

beforeEach(() => {
  vi.clearAllMocks();
  teamApi.create.mockResolvedValue({ id: "t-new" });
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
});
