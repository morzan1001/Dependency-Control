import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, it, expect, vi } from "vitest";
import type { Finding } from "@/types/scan";
import { FindingsTable } from "../FindingsTable";

vi.mock("@/api/scans", () => ({
  scanApi: { getFindings: vi.fn() },
}));
vi.mock("../FindingDetailsModal", () => ({
  FindingDetailsModal: ({ finding, onSelectFinding }: { finding: Finding; onSelectFinding: (id: string) => void }) => (
    <div>
      <output data-testid="opened-finding">{`${finding.type} ${finding.component}`}</output>
      <button type="button" onClick={() => onSelectFinding("LIC-UNKNOWN")}>open-license</button>
    </div>
  ),
}));

import { scanApi } from "@/api/scans";

type GetFindings = typeof scanApi.getFindings;

const row = (id: string, type: string, component: string): Partial<Finding> => ({
  id,
  type: type as Finding["type"],
  severity: "LOW",
  component,
  version: "1.0",
  scanners: [],
  details: {},
});

const FOO_LICENSE = row("LIC-UNKNOWN", "license", "foo");
const BAR_LICENSE = row("LIC-UNKNOWN", "license", "bar");
const BAR_VULNERABILITY = row("bar:1.0", "vulnerability", "bar");
const ROWS = [FOO_LICENSE, BAR_LICENSE, BAR_VULNERABILITY];

const envelope = (items: Partial<Finding>[], total = items.length) =>
  ({ items, total, page: 1, size: 50, pages: Math.ceil(total / 50) }) as never;

function renderTable(getFindings: GetFindings = async () => envelope(ROWS)) {
  vi.mocked(scanApi.getFindings).mockImplementation(getFindings);
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <FindingsTable scanId="s1" projectId="p1" />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("FindingsTable findings that share an id", () => {
  it("lists every package's license finding under its own row key", async () => {
    const consoleError = vi.spyOn(console, "error").mockImplementation(() => {});
    renderTable();

    expect(await screen.findAllByText("LIC-UNKNOWN")).toHaveLength(2);
    const keyWarnings = consoleError.mock.calls.filter(([message]) => String(message).includes("same key"));
    expect(keyWarnings).toEqual([]);
  });

  it("opens the license finding of the package whose finding links to it", async () => {
    renderTable();

    fireEvent.click(await screen.findByText("bar:1.0"));
    fireEvent.click(screen.getByText("open-license"));

    expect(screen.getByTestId("opened-finding")).toHaveTextContent("license bar");
  });

  it("looks up the linking package's license finding when only another package's is loaded", async () => {
    const getFindings = vi.fn<GetFindings>(async (_scanId, params) =>
      params?.type === "license" ? envelope([BAR_LICENSE]) : envelope([FOO_LICENSE, BAR_VULNERABILITY], 300),
    );
    renderTable(getFindings);

    fireEvent.click(await screen.findByText("bar:1.0"));
    fireEvent.click(screen.getByText("open-license"));

    await waitFor(() => expect(screen.getByTestId("opened-finding")).toHaveTextContent("license bar"));
    expect(getFindings.mock.calls.filter(([, params]) => params?.type === "license")).toHaveLength(1);
  });
});
