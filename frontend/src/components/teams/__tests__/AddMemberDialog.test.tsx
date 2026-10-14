import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { toast } from "sonner";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { createMutationCache } from "@/lib/mutation-cache";

import { AddMemberDialog } from "../AddMemberDialog";

const { teamApi } = vi.hoisted(() => ({ teamApi: { addMember: vi.fn() } }));
vi.mock("@/api/teams", () => ({ teamApi }));
vi.mock("sonner", () => ({ toast: { error: vi.fn(), success: vi.fn() } }));

beforeEach(() => {
  vi.clearAllMocks();
  teamApi.addMember.mockResolvedValue({ id: "t-1" });
});

const NO_VERIFIED_USER = "No user has verified this email address";

function openDialog() {
  const onClose = vi.fn();
  const client = new QueryClient({ mutationCache: createMutationCache(), defaultOptions: { mutations: { retry: false } } });
  const ui = (isOpen: boolean) => (
    <QueryClientProvider client={client}>
      <AddMemberDialog teamId="t-1" isOpen={isOpen} onClose={onClose} />
    </QueryClientProvider>
  );
  const { rerender } = render(ui(true));
  const reopen = () => {
    rerender(ui(false));
    rerender(ui(true));
  };
  return { onClose, reopen, dialog: screen.getByRole("dialog") };
}

function addMember(email: string) {
  const opened = openDialog();
  fireEvent.change(screen.getByLabelText("Email"), { target: { value: email } });
  fireEvent.click(within(opened.dialog).getByRole("button", { name: "Add Member" }));
  return opened;
}

describe("AddMemberDialog", () => {
  it("stacks its fields in a default-width dialog that ends in Cancel and Add Member, like the team dialog", () => {
    const { dialog } = openDialog();

    expect(dialog).not.toHaveClass("sm:max-w-[425px]");
    expect(screen.getByLabelText("Email").parentElement).toHaveClass("grid", "gap-2");
    expect(screen.getByLabelText("Role").parentElement).toHaveClass("grid", "gap-2");
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

  it("sends a pasted address without the non-breaking spaces around it", async () => {
    // An email field strips the plain spaces around its value itself, so only a pasted non-breaking space reaches the dialog.
    addMember("\u00a0lena@example.com\u00a0");

    await waitFor(() => expect(teamApi.addMember).toHaveBeenCalledWith("t-1", { email: "lena@example.com", role: "member" }));
  });

  it("closes without adding through Cancel", () => {
    const { onClose, dialog } = openDialog();

    fireEvent.change(screen.getByLabelText("Email"), { target: { value: "lena@example.com" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));

    expect(onClose).toHaveBeenCalled();
    expect(teamApi.addMember).not.toHaveBeenCalled();
  });
});

describe("AddMemberDialog refusals", () => {
  it.each(["", "   "])("says under the field that the blank address %j needs an email address and adds nothing", async (blank) => {
    addMember(blank);

    expect(await screen.findByRole("alert")).toHaveTextContent("Enter an email address");
    expect(screen.getByLabelText("Email")).toHaveAccessibleDescription("Enter an email address");
    expect(teamApi.addMember).not.toHaveBeenCalled();
  });

  it.each([
    [404, NO_VERIFIED_USER],
    [400, "User already in team"],
  ])("shows under the field why the server refused the address (%i), without a toast, like the invite user dialog", async (status, detail) => {
    teamApi.addMember.mockRejectedValue({ response: { status, data: { detail } } });

    addMember("nobody@example.com");

    expect(await screen.findByRole("alert")).toHaveTextContent(detail);
    expect(screen.getByLabelText("Email")).toHaveAttribute("aria-invalid", "true");
    expect(screen.getByLabelText("Email")).toHaveAccessibleDescription(detail);
    expect(toast.error).not.toHaveBeenCalled();
    fireEvent.change(screen.getByLabelText("Email"), { target: { value: "lena@example.com" } });
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("names a failure that belongs to no field in a toast", async () => {
    teamApi.addMember.mockRejectedValue({ response: { status: 403, data: { detail: "Not enough permissions" } } });

    addMember("lena@example.com");

    await waitFor(() =>
      expect(toast.error).toHaveBeenCalledWith("Failed to add member", { description: "Not enough permissions" }),
    );
    expect(vi.mocked(toast.error)).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("opens again on an empty field without the refusal shown before it was closed", async () => {
    teamApi.addMember.mockRejectedValue({ response: { status: 404, data: { detail: NO_VERIFIED_USER } } });
    const { dialog, reopen } = addMember("nobody@example.com");
    await screen.findByRole("alert");

    fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    reopen();

    expect(screen.getByLabelText("Email")).toHaveValue("");
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });
});
