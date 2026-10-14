import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { AddMemberDialog } from "../AddMemberDialog";

const { teamApi } = vi.hoisted(() => ({ teamApi: { addMember: vi.fn() } }));
vi.mock("@/api/teams", () => ({ teamApi }));
vi.mock("sonner", () => ({ toast: { error: vi.fn(), success: vi.fn() } }));

beforeEach(() => {
  vi.clearAllMocks();
  teamApi.addMember.mockResolvedValue({ id: "t-1" });
});

function openDialog() {
  const onClose = vi.fn();
  render(
    <QueryClientProvider client={new QueryClient()}>
      <AddMemberDialog teamId="t-1" isOpen onClose={onClose} />
    </QueryClientProvider>,
  );
  return { onClose, dialog: screen.getByRole("dialog") };
}

describe("AddMemberDialog", () => {
  it("stacks its fields in a default-width dialog that ends in Cancel and Add Member, like the team dialog", () => {
    const { dialog } = openDialog();

    expect(dialog).not.toHaveClass("sm:max-w-[425px]");
    expect(screen.getByLabelText("Email").parentElement).toHaveClass("grid", "gap-2");
    expect(within(dialog).getByText("Role").parentElement).toHaveClass("grid", "gap-2");
    expect(within(dialog).getByRole("button", { name: "Cancel" })).toHaveClass("border");
    expect(within(dialog).getByRole("button", { name: "Add Member" })).toHaveAttribute("type", "submit");
  });

  it("adds the member with the chosen role and closes", async () => {
    const { onClose, dialog } = openDialog();

    fireEvent.change(screen.getByLabelText("Email"), { target: { value: "lena@example.com" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Add Member" }));

    await waitFor(() => expect(onClose).toHaveBeenCalled());
    expect(teamApi.addMember).toHaveBeenCalledWith("t-1", { email: "lena@example.com", role: "member" });
  });

  it("closes without adding through Cancel", () => {
    const { onClose, dialog } = openDialog();

    fireEvent.change(screen.getByLabelText("Email"), { target: { value: "lena@example.com" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));

    expect(onClose).toHaveBeenCalled();
    expect(teamApi.addMember).not.toHaveBeenCalled();
  });
});
