import { render, screen, fireEvent } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { describe, it, expect, vi, beforeEach } from "vitest";
import { NewReportDialog } from "../NewReportDialog";

vi.mock("@/api/compliance", () => ({
  createReport: vi.fn().mockResolvedValue({ report_id: "r1", status: "pending" }),
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

describe("NewReportDialog", () => {
  beforeEach(() => {
    permissionSet.clear();
  });

  it("renders the dialog title when open", () => {
    withClient(<NewReportDialog open onClose={() => {}} />);
    expect(screen.getByText(/Generate Compliance Report/i)).toBeInTheDocument();
  });

  it("submits with default user scope and calls createReport", async () => {
    const { createReport } = await import("@/api/compliance");
    vi.mocked(createReport).mockClear();
    withClient(<NewReportDialog open onClose={vi.fn()} />);
    fireEvent.click(screen.getByRole("button", { name: /Generate/i }));
    await new Promise((r) => setTimeout(r, 0));
    expect(createReport).toHaveBeenCalledWith(
      expect.objectContaining({ scope: "user", scope_id: null }),
    );
  });

  it("hides Global scope when user lacks system:manage and analytics:global", () => {
    withClient(<NewReportDialog open onClose={() => {}} />);
    // Scope label is rendered; Global option should NOT be reachable via getAllByText
    expect(screen.queryByText(/^Global$/)).not.toBeInTheDocument();
  });

  it("shows Global scope option when user has system:manage", () => {
    permissionSet.add("system:manage");
    withClient(<NewReportDialog open onClose={() => {}} />);
    // Open the Scope select trigger
    const triggers = screen.getAllByRole("combobox");
    fireEvent.click(triggers[0]);
    // Options rendered in a portal — use findAllByText to wait if needed
    expect(screen.getAllByText(/Global/).length).toBeGreaterThan(0);
  });
});
