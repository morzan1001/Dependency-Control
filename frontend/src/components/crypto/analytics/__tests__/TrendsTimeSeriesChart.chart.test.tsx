import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { cloneElement, type ReactElement } from "react";
import { describe, expect, it, vi } from "vitest";

import { expectLabelsOnTheirTicks, measureChartText } from "@/test/chart-axis";
import { TrendsTimeSeriesChart } from "../TrendsTimeSeriesChart";

measureChartText();

vi.mock("recharts", async (importOriginal) => ({
  ...(await importOriginal<typeof import("recharts")>()),
  // jsdom lays nothing out, so the chart gets the size a browser would measure.
  ResponsiveContainer: ({ children }: { children: ReactElement<{ width?: number; height?: number }> }) =>
    cloneElement(children, { width: 600, height: 320 }),
}));

vi.mock("@/api/cryptoAnalytics", () => ({
  getCryptoTrends: vi.fn().mockResolvedValue({
    scope: "user",
    scope_id: null,
    metric: "total_crypto_findings",
    bucket: "week",
    points: [
      { timestamp: "2026-09-27T00:00:00Z", metric: "total_crypto_findings", value: 34 },
      { timestamp: "2026-10-11T00:00:00Z", metric: "total_crypto_findings", value: 33 },
      { timestamp: "2026-10-18T00:00:00Z", metric: "total_crypto_findings", value: 36 },
    ],
    range_start: "2026-09-20T00:00:00Z",
    range_end: "2026-10-20T00:00:00Z",
  }),
}));

describe("TrendsTimeSeriesChart axis", () => {
  it("draws the top value's label on its grid line, level with a point that reaches it", async () => {
    const { container } = render(
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <TrendsTimeSeriesChart
          scope="user"
          metric="total_crypto_findings"
          label="Total Crypto Findings"
          bucket="week"
          rangeStart={new Date("2026-09-20")}
          rangeEnd={new Date("2026-10-20")}
        />
      </QueryClientProvider>,
    );

    await waitFor(() => expect(screen.getByText("36")).toBeInTheDocument());
    expectLabelsOnTheirTicks(container, "y");
  });
});
