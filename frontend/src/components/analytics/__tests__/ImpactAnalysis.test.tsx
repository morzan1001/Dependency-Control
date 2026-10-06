import { render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { describe, it, expect, vi } from "vitest";
import { ImpactAnalysis } from "../ImpactAnalysis";

vi.mock("@/api/analytics", () => ({
  analyticsApi: { getImpactAnalysis: vi.fn() },
}));

import { analyticsApi } from "@/api/analytics";

describe("ImpactAnalysis load error", () => {
  it("says the request failed instead of reporting nothing to analyze", async () => {
    vi.mocked(analyticsApi.getImpactAnalysis).mockRejectedValue(
      Object.assign(new Error("Request failed"), { response: { status: 403, data: { detail: "Not enough permissions" } } }),
    );
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });

    render(
      <QueryClientProvider client={client}>
        <ImpactAnalysis />
      </QueryClientProvider>,
    );

    expect(await screen.findByRole("alert")).toHaveTextContent("Not enough permissions");
    expect(screen.queryByText("No vulnerabilities found to analyze")).not.toBeInTheDocument();
  });
});
