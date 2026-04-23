import { render, screen } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { describe, it, expect, vi } from "vitest";

import { TrendsTimeSeriesChart } from "../TrendsTimeSeriesChart";

vi.mock("@/api/cryptoAnalytics", () => ({
  getCryptoTrends: vi.fn().mockResolvedValue({
    scope: "project",
    scope_id: "p",
    metric: "total_crypto_findings",
    bucket: "week",
    points: [
      { timestamp: "2026-01-01T00:00:00Z", metric: "total_crypto_findings", value: 5 },
      { timestamp: "2026-01-08T00:00:00Z", metric: "total_crypto_findings", value: 7 },
    ],
    range_start: "2026-01-01T00:00:00Z",
    range_end: "2026-01-15T00:00:00Z",
    cache_hit: false,
  }),
}));

function renderWithClient(ui: React.ReactElement) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}>{ui}</QueryClientProvider>);
}

describe("TrendsTimeSeriesChart", () => {
  it("renders the chart responsive container", async () => {
    const { container } = renderWithClient(
      <TrendsTimeSeriesChart
        scope="project" scopeId="p"
        metric="total_crypto_findings" bucket="week"
        rangeStart={new Date("2026-01-01")} rangeEnd={new Date("2026-01-15")}
      />,
    );
    await screen.findByText(/crypto findings/i, undefined, { timeout: 2000 }).catch(() => null);
    expect(container.querySelector(".recharts-responsive-container")).toBeTruthy();
  });
});
