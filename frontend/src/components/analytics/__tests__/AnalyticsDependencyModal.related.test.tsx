import { fireEvent, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, it, expect, vi } from "vitest";
import type { ComponentFinding } from "@/types/analytics";
import { AnalyticsDependencyModal } from "../AnalyticsDependencyModal";

vi.mock("@/hooks/queries/use-analytics", () => ({
  useDependencyMetadata: () => ({ data: null, isLoading: false }),
  useComponentFindings: vi.fn(),
}));
vi.mock("@/components/findings/FindingDetailsModal", () => ({
  FindingDetailsModal: ({ finding, onSelectFinding, onClose, onNavigate }: {
    finding: ComponentFinding;
    onSelectFinding: (id: string) => void;
    onClose: () => void;
    onNavigate: () => void;
  }) => (
    <div>
      <output data-testid="opened-finding">{`${finding.type} ${finding.project_name}`}</output>
      <button type="button" onClick={() => onSelectFinding("lodash:4.17.20")}>open-vulnerability</button>
      {/* A Found In badge closes the finding, then leaves for the scan page. */}
      <button type="button" onClick={() => { onClose(); onNavigate(); }}>go-to-scan</button>
    </div>
  ),
}));

import { useComponentFindings } from "@/hooks/queries/use-analytics";

const finding = (type: string, severity: string, project: string): ComponentFinding =>
  ({
    id: type === "license" ? "LIC-MIT" : "lodash:4.17.20",
    type,
    severity,
    component: "lodash",
    version: "4.17.20",
    description: "",
    scanners: [],
    details: {},
    found_in: [],
    aliases: [],
    waived: false,
    project_id: project,
    project_name: project,
    scan_id: `scan-${project}`,
  }) as ComponentFinding;

describe("AnalyticsDependencyModal related findings", () => {
  it("opens the related finding of the project the open finding belongs to", () => {
    vi.mocked(useComponentFindings).mockReturnValue({
      data: {
        items: [finding("vulnerability", "CRITICAL", "alpha"), finding("vulnerability", "HIGH", "beta"), finding("license", "LOW", "beta")],
        total: 3,
      },
      isLoading: false,
    } as never);
    render(
      <MemoryRouter>
        <AnalyticsDependencyModal component="lodash" version="4.17.20" open onOpenChange={() => {}} />
      </MemoryRouter>,
    );

    fireEvent.click(screen.getByText("LIC-MIT"));
    fireEvent.click(screen.getByText("open-vulnerability"));

    expect(screen.getByTestId("opened-finding")).toHaveTextContent("vulnerability beta");
  });

  it("closes itself along with the finding when the finding leaves for its scan", () => {
    const onOpenChange = vi.fn();
    vi.mocked(useComponentFindings).mockReturnValue({
      data: { items: [finding("license", "LOW", "beta")], total: 1 },
      isLoading: false,
    } as never);
    render(
      <MemoryRouter>
        <AnalyticsDependencyModal component="lodash" version="4.17.20" open onOpenChange={onOpenChange} />
      </MemoryRouter>,
    );

    fireEvent.click(screen.getByText("LIC-MIT"));
    fireEvent.click(screen.getByText("go-to-scan"));

    expect(onOpenChange).toHaveBeenCalledWith(false);
    expect(screen.queryByTestId("opened-finding")).not.toBeInTheDocument();
  });

  it("lists a license finding of two versions in one scan under their own row keys", () => {
    const consoleError = vi.spyOn(console, "error").mockImplementation(() => {});
    vi.mocked(useComponentFindings).mockReturnValue({
      data: { items: [finding("license", "LOW", "beta"), { ...finding("license", "LOW", "beta"), version: "4.17.21" }], total: 2 },
      isLoading: false,
    } as never);
    render(
      <MemoryRouter>
        <AnalyticsDependencyModal component="lodash" open onOpenChange={() => {}} />
      </MemoryRouter>,
    );

    expect(screen.getAllByText("LIC-MIT")).toHaveLength(2);
    const keyWarnings = consoleError.mock.calls.filter(([message]) => String(message).includes("same key"));
    expect(keyWarnings).toEqual([]);
    consoleError.mockRestore();
  });
});
