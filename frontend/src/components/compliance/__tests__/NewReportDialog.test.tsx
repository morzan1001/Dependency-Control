import { render, screen, fireEvent } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { describe, it, expect, vi } from "vitest";
import { NewReportDialog } from "../NewReportDialog";

vi.mock("@/api/compliance", () => ({
  createReport: vi.fn().mockResolvedValue({ report_id: "r1", status: "pending" }),
}));

function withClient(ui: React.ReactElement) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={qc}>{ui}</QueryClientProvider>);
}

describe("NewReportDialog", () => {
  it("renders the dialog title when open", () => {
    withClient(<NewReportDialog open onClose={() => {}} />);
    expect(screen.getByText(/Generate Compliance Report/i)).toBeInTheDocument();
  });

  it("submits with selected values and calls createReport", async () => {
    const { createReport } = await import("@/api/compliance");
    const onClose = vi.fn();
    withClient(<NewReportDialog open onClose={onClose} />);
    fireEvent.click(screen.getByRole("button", { name: /Generate/i }));
    await new Promise((r) => setTimeout(r, 0));
    expect(createReport).toHaveBeenCalled();
  });
});
