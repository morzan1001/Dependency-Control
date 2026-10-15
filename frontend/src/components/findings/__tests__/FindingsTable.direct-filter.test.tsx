import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, it, expect, vi, beforeEach } from "vitest";
import { showObservedElements } from "@/test/intersection-observer";
import { FindingsTable } from "../FindingsTable";

vi.mock("@/api/scans", () => ({
  scanApi: { getFindings: vi.fn() },
}));

import { scanApi } from "@/api/scans";

const getFindingsMock = scanApi.getFindings as ReturnType<typeof vi.fn>;

function renderWithProviders(node: React.ReactElement): QueryClient {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, staleTime: Infinity } },
  });
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter>{node}</MemoryRouter>
    </QueryClientProvider>,
  );
  return client;
}

const emptyEnvelope = { items: [], total: 0, page: 1, size: 50, pages: 1 };

describe("FindingsTable direct-only filter", () => {
  beforeEach(() => {
    getFindingsMock.mockReset();
    getFindingsMock.mockResolvedValue(emptyEnvelope);
  });

  it("sends direct_only=true when the directOnly prop is set", async () => {
    renderWithProviders(<FindingsTable scanId="s1" projectId="p1" directOnly />);
    await waitFor(() => expect(getFindingsMock).toHaveBeenCalled());
    const [, params] = getFindingsMock.mock.calls[0];
    expect((params as Record<string, unknown>).direct_only).toBe(true);
  });

  it("omits direct_only by default so transitive findings stay visible", async () => {
    renderWithProviders(<FindingsTable scanId="s1" projectId="p1" />);
    await waitFor(() => expect(getFindingsMock).toHaveBeenCalled());
    const [, params] = getFindingsMock.mock.calls[0];
    expect((params as Record<string, unknown>).direct_only).toBeUndefined();
  });
});

describe("FindingsTable severity filter", () => {
  beforeEach(() => {
    getFindingsMock.mockReset();
    getFindingsMock.mockResolvedValue(emptyEnvelope);
  });

  it("asks the API for the findings of the requested severity only", async () => {
    renderWithProviders(<FindingsTable scanId="s1" projectId="p1" severity="CRITICAL" />);
    await waitFor(() => expect(getFindingsMock).toHaveBeenCalled());
    const [, params] = getFindingsMock.mock.calls[0];
    expect((params as Record<string, unknown>).severity).toBe("CRITICAL");
  });
});

describe("FindingsTable sorting", () => {
  const finding = { id: "CVE-1", type: "vulnerability", severity: "HIGH", component: "lodash", version: "4.17.20", scanners: [] };

  beforeEach(() => {
    getFindingsMock.mockReset();
    getFindingsMock.mockResolvedValue({ ...emptyEnvelope, items: [finding], total: 1 });
  });

  const lastSort = () => {
    const params = getFindingsMock.mock.calls[getFindingsMock.mock.calls.length - 1][1] as Record<string, unknown>;
    return [params.sort_by, params.sort_order];
  };

  it("asks for the most severe findings first, then sorts a text column ascending first and flips it", async () => {
    renderWithProviders(<FindingsTable scanId="s1" projectId="p1" />);
    await screen.findByText("lodash");
    expect(lastSort()).toEqual(["severity", "desc"]);

    fireEvent.click(screen.getByRole("columnheader", { name: "Component" }));
    await waitFor(() => expect(lastSort()).toEqual(["component", "asc"]));

    await screen.findByText("lodash");
    fireEvent.click(screen.getByRole("columnheader", { name: "Component" }));
    await waitFor(() => expect(lastSort()).toEqual(["component", "desc"]));
  });

  it.each(["ID", "Source", "Type", "Scanner"])("sorts the %s text column ascending first", async (column) => {
    renderWithProviders(<FindingsTable scanId="s1" projectId="p1" />);
    await screen.findByText("lodash");

    fireEvent.click(screen.getByRole("columnheader", { name: column }));

    await waitFor(() => expect(lastSort()[1]).toBe("asc"));
  });
});

describe("FindingsTable later page error", () => {
  let restoreObserver: () => void;

  beforeEach(() => {
    restoreObserver = showObservedElements();
    getFindingsMock.mockReset();
    getFindingsMock.mockImplementation(async (_scanId: string, params: { skip: number }) => {
      if (params.skip > 0) {
        // A failure that takes a moment, as over the network, renders the retry in between.
        await new Promise((resolve) => setTimeout(resolve, 5));
        throw new Error("Request failed with status code 504");
      }
      const finding = { id: "CVE-1", type: "vulnerability", severity: "HIGH", component: "lodash", version: "4.17.20", scanners: [] };
      return { ...emptyEnvelope, items: [finding], total: 2 };
    });
  });

  afterEach(() => restoreObserver());

  it("keeps the loaded findings, stops requesting the failed page and offers a retry", async () => {
    renderWithProviders(<FindingsTable scanId="s1" projectId="p1" />);

    expect(await screen.findByRole("alert")).toHaveTextContent("Failed to load more findings");
    await act(() => new Promise((resolve) => setTimeout(resolve, 50)));
    expect(screen.getByText("lodash")).toBeInTheDocument();
    expect(getFindingsMock.mock.calls.map(([, params]) => (params as { skip: number }).skip)).toEqual([0, 1]);

    fireEvent.click(screen.getByRole("button", { name: "Retry" }));

    // Under the table, where a phone shows it rather than centred on the scrolling table.
    expect((await screen.findByText("Loading more...")).closest("table")).toBeNull();
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(await screen.findByRole("alert")).toHaveTextContent("Failed to load more findings");
    expect(getFindingsMock.mock.calls.map(([, params]) => (params as { skip: number }).skip)).toEqual([0, 1, 1]);
  });
});

describe("FindingsTable first page error", () => {
  beforeEach(() => {
    getFindingsMock.mockReset();
    getFindingsMock.mockRejectedValue(new Error("Request failed with status code 503"));
  });

  it("says why the findings could not load and retries the first page", async () => {
    renderWithProviders(<FindingsTable scanId="s1" projectId="p1" />);

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Error loading findings");
    expect(alert).toHaveTextContent("Request failed with status code 503");
    expect(screen.queryByText("No findings found")).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Retry" }));

    await waitFor(() => expect(getFindingsMock).toHaveBeenCalledTimes(2));
    expect((getFindingsMock.mock.calls[1][1] as { skip: number }).skip).toBe(0);
  });
});

describe("FindingsTable reload error", () => {
  const finding = { id: "CVE-1", type: "vulnerability", severity: "HIGH", component: "lodash", version: "4.17.20", scanners: [] };

  beforeEach(() => {
    getFindingsMock.mockReset();
    getFindingsMock.mockResolvedValueOnce({ ...emptyEnvelope, items: [finding], total: 1 });
  });

  it("keeps the loaded findings, says the reload failed and retries the reload", async () => {
    const client = renderWithProviders(<FindingsTable scanId="s1" projectId="p1" />);
    await screen.findByText("lodash");
    getFindingsMock.mockRejectedValue(new Error("Request failed with status code 503"));

    await act(() => client.invalidateQueries({ queryKey: ["findings"] }));

    expect(await screen.findByRole("alert")).toHaveTextContent("Error loading findings");
    expect(screen.getByRole("alert")).toHaveTextContent("Request failed with status code 503");
    expect(screen.getByText("lodash")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Retry" }));

    await waitFor(() => expect(getFindingsMock).toHaveBeenCalledTimes(3));
    expect((getFindingsMock.mock.calls[2][1] as { skip: number }).skip).toBe(0);
  });
});

describe("FindingsTable Type column", () => {
  beforeEach(() => {
    getFindingsMock.mockReset();
    getFindingsMock.mockResolvedValue({
      ...emptyEnvelope,
      items: [{ id: "CRYPTO-CERT-EXPIRED-api", type: "crypto_cert_expired", severity: "CRITICAL", component: "api.example.com", version: "", scanners: ["cbomkit"] }],
      total: 1,
    });
  });

  it("fits the widest type badge, so only a long crypto label truncates", async () => {
    renderWithProviders(<FindingsTable scanId="s1" projectId="p1" />);

    expect(await screen.findByText("Certificate expired")).toHaveClass("truncate");
    expect(screen.getByRole("columnheader", { name: "Type" })).toHaveClass("w-[160px]");
  });
});

describe("FindingsTable Scanner column", () => {
  beforeEach(() => {
    getFindingsMock.mockReset();
    getFindingsMock.mockResolvedValue({
      ...emptyEnvelope,
      items: [{ id: "CRYPTO-crypto_cert_validity_too_long-cert-1", type: "crypto_cert_validity_too_long", severity: "LOW", component: "internal.example.com", version: "", scanners: ["crypto_cert_validity_too_long"] }],
      total: 1,
    });
  });

  it("fits the longest analyzer name and breaks a longer crypto scanner name anywhere, like a long branch name", async () => {
    renderWithProviders(<FindingsTable scanId="s1" projectId="p1" />);

    expect(await screen.findByText("crypto_cert_validity_too_long")).toHaveClass("wrap-anywhere");
    expect(screen.getByRole("columnheader", { name: "Scanner" })).toHaveClass("w-[170px]");
  });
});

describe("FindingsTable on a narrow screen", () => {
  beforeEach(() => {
    getFindingsMock.mockReset();
  });

  it("keeps the Component column 200px wide while loading and loaded, scrolling the table sideways", async () => {
    let resolve: (value: unknown) => void = () => {};
    getFindingsMock.mockReturnValue(new Promise((r) => { resolve = r; }));
    renderWithProviders(<FindingsTable scanId="s1" projectId="p1" />);

    const skeleton = await screen.findByRole("table");
    expect(skeleton).toHaveClass("table-fixed", "min-w-[930px]");

    resolve({ ...emptyEnvelope, items: [{ id: "CVE-1", type: "vulnerability", severity: "HIGH", component: "lodash", version: "4.17.20", scanners: ["trivy"], details: {} }], total: 1 });
    const table = (await screen.findByText("lodash")).closest("table");
    expect(table).toHaveClass("table-fixed", "min-w-[930px]");
    expect(table?.parentElement).toHaveClass("overflow-x-auto");
  });

  it("drops its scroll container from xl on, where the table fits, so the header sticks while the page scrolls", async () => {
    getFindingsMock.mockResolvedValue({ ...emptyEnvelope, items: [{ id: "CVE-1", type: "vulnerability", severity: "HIGH", component: "lodash", version: "4.17.20", scanners: ["trivy"], details: {} }], total: 1 });
    renderWithProviders(<FindingsTable scanId="s1" projectId="p1" stickyHeaderTop={0} />);

    const table = (await screen.findByText("lodash")).closest("table");
    expect(table?.parentElement).toHaveClass("overflow-x-auto", "xl:overflow-visible");
    expect(table?.querySelector("thead")).toHaveClass("sticky");
  });
});
