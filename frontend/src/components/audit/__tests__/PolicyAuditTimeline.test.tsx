import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { toast } from "sonner";
import { describe, it, expect, vi } from "vitest";

import { pruneSystemAudit, revertSystemPolicy } from "@/api/policyAudit";
import { createMutationCache } from "@/lib/mutation-cache";
import { expectFieldLabel } from "@/test/form-field";
import { PolicyAuditTimeline } from "../PolicyAuditTimeline";

vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

vi.mock("@/api/policyAudit", () => ({
  listSystemAudit: vi.fn().mockResolvedValue({
    entries: [
      {
        _id: "a1", policy_scope: "system", project_id: null, version: 3,
        action: "update", actor_user_id: "u1", actor_display_name: "alice",
        timestamp: "2026-04-20T10:00:00Z",
        snapshot: {}, change_summary: "Added 1 rule", comment: "Q2 audit",
        reverted_from_version: null,
      },
      {
        _id: "a2", policy_scope: "system", project_id: null, version: 2,
        action: "seed", actor_user_id: null, actor_display_name: null,
        timestamp: "2026-04-01T10:00:00Z",
        snapshot: {}, change_summary: "Initial policy (5 rules)", comment: null,
        reverted_from_version: null,
      },
    ],
  }),
  listProjectAudit: vi.fn(),
  revertSystemPolicy: vi.fn(),
  revertProjectPolicy: vi.fn(),
  pruneSystemAudit: vi.fn().mockResolvedValue({ deleted: 0 }),
  pruneProjectAudit: vi.fn().mockResolvedValue({ deleted: 0 }),
}));

function withClient(ui: React.ReactElement) {
  const qc = new QueryClient({ mutationCache: createMutationCache(), defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={qc}>{ui}</QueryClientProvider>);
}

describe("PolicyAuditTimeline", () => {
  it("renders entries with actor and summary", async () => {
    withClient(<PolicyAuditTimeline policyScope="system" />);
    expect(await screen.findByText("alice")).toBeInTheDocument();
    expect(screen.getByText("Added 1 rule")).toBeInTheDocument();
    expect(screen.getByText(/Q2 audit/)).toBeInTheDocument();
    expect(screen.getByText("Initial policy (5 rules)")).toBeInTheDocument();
  });

  it("hides the prune button when canRevert is false", () => {
    withClient(<PolicyAuditTimeline policyScope="system" />);
    expect(screen.queryByRole("button", { name: /Prune old entries/i }))
      .not.toBeInTheDocument();
  });

  it("shows the prune button and opens the dialog when canRevert is true", async () => {
    withClient(<PolicyAuditTimeline policyScope="system" canRevert />);
    const btn = await screen.findByRole("button", { name: /Prune old entries/i });
    expect(btn).toBeInTheDocument();
    fireEvent.click(btn);
    expect(screen.getByText(/Prune audit entries/i)).toBeInTheDocument();
    expect(screen.getByText(/Destructive:/i)).toBeInTheDocument();
  });

  it("labels the revert comment like the other form dialogs, with the shared text area", async () => {
    withClient(<PolicyAuditTimeline policyScope="system" canRevert />);
    fireEvent.click((await screen.findAllByTitle("Revert to this version"))[0]);

    expectFieldLabel("Comment (required for revert)");
    expect(screen.getByLabelText("Comment (required for revert)")).toHaveClass("border-input");
  });

  it("labels the prune cutoff like the other form dialogs, with the shared date field", async () => {
    withClient(<PolicyAuditTimeline policyScope="system" canRevert />);
    fireEvent.click(await screen.findByRole("button", { name: /Prune old entries/i }));

    expectFieldLabel("Prune entries before");
    expect(screen.getByLabelText("Prune entries before")).toHaveClass("border-input");
  });

  it("opens the revert and prune dialogs at the default dialog width, like the other confirmations", async () => {
    withClient(<PolicyAuditTimeline policyScope="system" canRevert />);
    fireEvent.click((await screen.findAllByTitle("Revert to this version"))[0]);
    expect(screen.getByRole("dialog")).toHaveClass("max-w-lg");
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));

    fireEvent.click(await screen.findByRole("button", { name: /Prune old entries/i }));
    expect(screen.getByRole("dialog")).toHaveClass("max-w-lg");
  });

  it("shows the server's reason when a revert is refused", async () => {
    vi.mocked(revertSystemPolicy).mockRejectedValueOnce(
      Object.assign(new Error("Request failed with status code 422"), {
        response: { data: { detail: "Version 2 holds rules a write would refuse: rule 'r1': needs a subject matcher" } },
      }),
    );
    withClient(<PolicyAuditTimeline policyScope="system" canRevert />);
    fireEvent.click((await screen.findAllByTitle("Revert to this version"))[1]);
    fireEvent.change(screen.getByRole("textbox"), { target: { value: "back to seed" } });
    fireEvent.click(screen.getByRole("button", { name: "Confirm revert" }));

    await waitFor(() => expect(toast.error).toHaveBeenCalledWith("Failed to revert policy", {
      description: "Version 2 holds rules a write would refuse: rule 'r1': needs a subject matcher",
    }));
  });

  it("opens the revert dialog for another version without the previous revert's comment", async () => {
    withClient(<PolicyAuditTimeline policyScope="system" canRevert />);
    fireEvent.click((await screen.findAllByTitle("Revert to this version"))[0]);
    fireEvent.change(screen.getByRole("textbox"), { target: { value: "roll back X" } });
    fireEvent.click(screen.getByRole("button", { name: "Confirm revert" }));
    await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument());

    fireEvent.click(screen.getAllByTitle("Revert to this version")[1]);

    expect(screen.getByRole("textbox")).toHaveValue("");
  });

  it("reports a refused prune through the toast without an unhandled rejection", async () => {
    const unhandled = vi.fn();
    process.on("unhandledRejection", unhandled);
    try {
      vi.mocked(pruneSystemAudit).mockRejectedValueOnce(
        Object.assign(new Error("Request failed with status code 400"), {
          response: { data: { detail: "Cutoff must be at least 90 days in the past" } },
        }),
      );
      withClient(<PolicyAuditTimeline policyScope="system" canRevert />);
      fireEvent.click(await screen.findByRole("button", { name: /Prune old entries/i }));
      fireEvent.click(screen.getByRole("button", { name: "Prune" }));

      await waitFor(() => expect(toast.error).toHaveBeenCalledWith("Failed to prune audit entries", {
        description: "Cutoff must be at least 90 days in the past",
      }));
      await new Promise((resolve) => setTimeout(resolve, 0));
      expect(unhandled).not.toHaveBeenCalled();
      expect(screen.getByRole("dialog")).toBeInTheDocument();
    } finally {
      process.off("unhandledRejection", unhandled);
    }
  });

  it("wraps an entry's summary, date and revert button on a phone instead of pushing the button off the screen", async () => {
    withClient(<PolicyAuditTimeline policyScope="system" canRevert />);

    const summary = await screen.findByText("Added 1 rule");
    const toggle = summary.closest("button");
    expect(toggle).toHaveClass("flex-wrap");
    expect(toggle?.parentElement).toHaveClass("flex-wrap");
    expect(screen.getByText("Policy audit history").parentElement).toHaveClass("flex-wrap", "gap-2");
  });
});
