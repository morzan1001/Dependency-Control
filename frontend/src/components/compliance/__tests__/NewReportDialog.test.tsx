import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { toast } from "sonner";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { createReport } from "@/api/compliance";
import { teamApi } from "@/api/teams";
import { NewReportDialog } from "../NewReportDialog";

vi.mock("@/api/compliance", () => ({
  createReport: vi.fn().mockResolvedValue({ report_id: "r1", status: "pending" }),
}));
vi.mock("sonner", () => ({ toast: { success: vi.fn(), error: vi.fn() } }));
vi.mock("@/api/teams", () => ({
  teamApi: {
    getAll: vi.fn().mockResolvedValue([
      { id: "t-9", name: "Payments", members: [], bindings: [], created_at: "", updated_at: "" },
    ]),
  },
}));
vi.mock("@/api/projects", () => ({
  projectApi: {
    getAll: vi.fn().mockResolvedValue({ items: [], total: 0, page: 1, size: 50, pages: 0 }),
    getOne: vi.fn(),
  },
}));

const permissionSet = new Set<string>();
vi.mock("@/context/useAuth", () => ({
  useAuth: () => ({
    isAuthenticated: true,
    isLoading: false,
    permissions: Array.from(permissionSet),
    hasPermission: (p: string) => permissionSet.has(p),
    login: vi.fn(),
    logout: vi.fn(),
  }),
}));

function withClient(ui: React.ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={qc}>{ui}</QueryClientProvider>);
}

async function pickOption(trigger: HTMLElement, name: string) {
  fireEvent.click(trigger);
  fireEvent.click(await screen.findByRole("option", { name }));
}

describe("NewReportDialog", () => {
  beforeEach(() => {
    permissionSet.clear();
    vi.mocked(createReport).mockClear();
    vi.mocked(teamApi.getAll).mockClear();
  });

  it("offers the caller's teams by name and sends the picked team's id", async () => {
    withClient(<NewReportDialog onClose={vi.fn()} />);
    await pickOption(screen.getAllByRole("combobox")[0], "Team");
    await pickOption(screen.getAllByRole("combobox")[1], "Payments");
    fireEvent.click(screen.getByRole("button", { name: "Generate" }));

    await waitFor(() => expect(createReport).toHaveBeenCalledWith(expect.objectContaining({ scope: "team", scope_id: "t-9" })));
  });

  it.each(["analytics:global", "system:manage", "project:read_all"])(
    "lets a caller with %s but without team:read_all type the id of any team",
    async (permission) => {
      permissionSet.add(permission);
      permissionSet.add("team:read");
      withClient(<NewReportDialog onClose={vi.fn()} />);
      await pickOption(screen.getAllByRole("combobox")[0], "Team");
      fireEvent.change(screen.getByPlaceholderText("Team ID"), { target: { value: " t-other " } });
      fireEvent.click(screen.getByRole("button", { name: "Generate" }));

      await waitFor(() => expect(createReport).toHaveBeenCalledWith(expect.objectContaining({ scope: "team", scope_id: "t-other" })));
      expect(teamApi.getAll).not.toHaveBeenCalled();
    },
  );

  it("offers a team:read_all holder the teams by name", async () => {
    permissionSet.add("system:manage");
    permissionSet.add("team:read_all");
    withClient(<NewReportDialog onClose={vi.fn()} />);
    await pickOption(screen.getAllByRole("combobox")[0], "Team");
    await pickOption(screen.getAllByRole("combobox")[1], "Payments");
    fireEvent.click(screen.getByRole("button", { name: "Generate" }));

    await waitFor(() => expect(createReport).toHaveBeenCalledWith(expect.objectContaining({ scope: "team", scope_id: "t-9" })));
    expect(screen.queryByPlaceholderText("Team ID")).not.toBeInTheDocument();
  });

  it("forgets the picked team when the scope changes", async () => {
    withClient(<NewReportDialog onClose={vi.fn()} />);
    await pickOption(screen.getAllByRole("combobox")[0], "Team");
    await pickOption(screen.getAllByRole("combobox")[1], "Payments");
    await pickOption(screen.getAllByRole("combobox")[0], "Project");
    fireEvent.click(screen.getByRole("button", { name: "Generate" }));

    expect(await screen.findByText("Select a project for project scope.")).toBeInTheDocument();
    expect(createReport).not.toHaveBeenCalled();
  });

  it("shows the server's reason when the report is refused", async () => {
    vi.mocked(createReport).mockRejectedValueOnce(
      Object.assign(new Error("Request failed with status code 403"), {
        response: { data: { detail: "User not authorised for project x" } },
      }),
    );
    withClient(<NewReportDialog onClose={vi.fn()} />);
    fireEvent.click(screen.getByRole("button", { name: "Generate" }));

    await waitFor(() => expect(toast.error).toHaveBeenCalledWith("Failed to queue report: User not authorised for project x"));
  });

  it("renders the dialog title when open", () => {
    withClient(<NewReportDialog onClose={() => {}} />);
    expect(screen.getByText(/Generate Compliance Report/i)).toBeInTheDocument();
  });

  it("submits with default user scope and calls createReport", async () => {
    withClient(<NewReportDialog onClose={vi.fn()} />);
    fireEvent.click(screen.getByRole("button", { name: /Generate/i }));
    await new Promise((r) => setTimeout(r, 0));
    expect(createReport).toHaveBeenCalledWith(
      expect.objectContaining({ scope: "user", scope_id: null }),
    );
  });

  it("hides Global scope when user lacks system:manage and analytics:global", () => {
    withClient(<NewReportDialog onClose={() => {}} />);
    expect(screen.queryByText(/^Global$/)).not.toBeInTheDocument();
  });

  it("shows Global scope option when user has system:manage", () => {
    permissionSet.add("system:manage");
    withClient(<NewReportDialog onClose={() => {}} />);
    const triggers = screen.getAllByRole("combobox");
    fireEvent.click(triggers[0]);
    expect(screen.getAllByText(/Global/).length).toBeGreaterThan(0);
  });
});
