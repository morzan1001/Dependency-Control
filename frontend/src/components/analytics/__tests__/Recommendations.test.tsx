import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { describe, it, expect, vi } from "vitest";
import { Recommendations } from "../Recommendations";

vi.mock("@/api/analytics", () => ({
  analyticsApi: { getProjectRecommendations: vi.fn() },
}));
vi.mock("@/components/ui/project-combobox", () => ({
  ProjectCombobox: ({ onValueChange }: { onValueChange: (v: string) => void }) => (
    <button type="button" onClick={() => onValueChange("p1")}>select-project</button>
  ),
}));

import { analyticsApi } from "@/api/analytics";

describe("Recommendations load error", () => {
  it("names why the recommendations failed and retries them", async () => {
    const getRecommendations = vi.mocked(analyticsApi.getProjectRecommendations);
    getRecommendations.mockRejectedValue(
      Object.assign(new Error("Request failed"), { response: { status: 403, data: { detail: "Not enough permissions" } } }),
    );
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
    render(
      <QueryClientProvider client={client}>
        <Recommendations />
      </QueryClientProvider>,
    );

    fireEvent.click(screen.getByText("select-project"));

    expect(await screen.findByRole("alert")).toHaveTextContent("Not enough permissions");
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    await waitFor(() => expect(getRecommendations).toHaveBeenCalledTimes(2));
  });
});
