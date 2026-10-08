import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, it, expect, vi } from "vitest";
import { DEBOUNCE_DELAY_MS } from "@/lib/constants";
import { CrossProjectSearch } from "../CrossProjectSearch";

vi.mock("@/api/analytics", () => ({
  analyticsApi: {
    searchDependenciesAdvanced: vi.fn(),
    getDependencyTypes: vi.fn(),
  },
}));
vi.mock("@/api/projects", () => ({
  projectApi: { getAll: vi.fn(async () => ({ items: [], total: 0, page: 1, size: 50, pages: 0 })), getOne: vi.fn() },
}));

import { analyticsApi } from "@/api/analytics";
import { projectApi } from "@/api/projects";

const search = vi.mocked(analyticsApi.searchDependenciesAdvanced);

afterEach(() => {
  vi.useRealTimers();
});

describe("CrossProjectSearch version filter", () => {
  it("searches for a version once the user stops typing, not once per keystroke", () => {
    vi.useFakeTimers();
    search.mockResolvedValue({ items: [], total: 0, page: 1, size: 50, pages: 1 });
    vi.mocked(analyticsApi.getDependencyTypes).mockResolvedValue([]);
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={client}>
        <MemoryRouter>
          <CrossProjectSearch />
        </MemoryRouter>
      </QueryClientProvider>,
    );
    fireEvent.change(screen.getByPlaceholderText(/Search for a package name/), { target: { value: "lodash" } });
    act(() => {
      vi.advanceTimersByTime(DEBOUNCE_DELAY_MS);
    });
    fireEvent.click(screen.getByRole("button", { name: /Filters/ }));

    for (const value of ["4", "4.1", "4.17"]) {
      fireEvent.change(screen.getByPlaceholderText("e.g., 1.0.0"), { target: { value } });
    }
    act(() => {
      vi.advanceTimersByTime(DEBOUNCE_DELAY_MS);
    });

    const versions = search.mock.calls.map(([, options]) => options?.version);
    expect(versions).toEqual([undefined, "4.17"]);
  });
});

describe("CrossProjectSearch load error", () => {
  it("says the search failed instead of reporting no packages, and retries it", async () => {
    search.mockReset();
    search.mockRejectedValue(
      Object.assign(new Error("Request failed"), { response: { status: 403, data: { detail: "Not enough permissions" } } }),
    );
    vi.mocked(analyticsApi.getDependencyTypes).mockResolvedValue([]);
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={client}>
        <MemoryRouter>
          <CrossProjectSearch />
        </MemoryRouter>
      </QueryClientProvider>,
    );

    fireEvent.change(screen.getByPlaceholderText(/Search for a package name/), { target: { value: "lodash" } });

    expect(await screen.findByRole("alert")).toHaveTextContent("Not enough permissions");
    expect(screen.queryByText(/No packages found/)).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    await waitFor(() => expect(search).toHaveBeenCalledTimes(2));
  });
});

describe("CrossProjectSearch project filter", () => {
  it("reads no project list until the filter panel opens, and then a single page", async () => {
    const getAll = vi.mocked(projectApi.getAll);
    getAll.mockClear();
    getAll.mockResolvedValue({ items: [], total: 801, page: 1, size: 100, pages: 9 });
    vi.mocked(analyticsApi.getDependencyTypes).mockResolvedValue([]);
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={client}>
        <MemoryRouter>
          <CrossProjectSearch />
        </MemoryRouter>
      </QueryClientProvider>,
    );

    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 20));
    });
    expect(getAll).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole("button", { name: /Filters/ }));
    await waitFor(() => expect(getAll).toHaveBeenCalledTimes(1));
  });
});
