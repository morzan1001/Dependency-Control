import { render, screen, fireEvent } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

import { CryptoAnalyticsTab } from "../CryptoAnalyticsTab";

// Capture the range props the trends chart receives so we can assert they stay stable.
const capturedRanges: Array<{ start: string; end: string }> = [];

vi.mock("@/components/crypto/analytics/TrendsTimeSeriesChart", () => ({
  TrendsTimeSeriesChart: (p: { rangeStart: Date; rangeEnd: Date }) => {
    capturedRanges.push({
      start: p.rangeStart.toISOString(),
      end: p.rangeEnd.toISOString(),
    });
    return <div data-testid="trends-chart" />;
  },
}));

// Keep the default (hotspots) tab from hitting the network.
vi.mock("@/api/cryptoAnalytics", () => ({
  getCryptoHotspots: vi.fn().mockResolvedValue({ rows: [], total: 0 }),
  getCryptoTrends: vi.fn().mockResolvedValue({ points: [] }),
}));

function renderTab() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <CryptoAnalyticsTab />
      </MemoryRouter>
    </QueryClientProvider>,
  );
}

describe("CryptoAnalyticsTab trends range", () => {
  beforeEach(() => {
    capturedRanges.length = 0;
    vi.useFakeTimers({ shouldAdvanceTime: false });
    // Fixed midday instant so start-of-day normalization is deterministic.
    vi.setSystemTime(new Date("2026-07-07T12:00:00"));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("keeps the derived range stable across re-renders on the same day (same days preset)", () => {
    renderTab();

    // Radix mounts TrendsSection on activation and triggers on mouseDown, so fire both.
    const trendsTab = screen.getByRole("tab", { name: /trends/i });
    fireEvent.mouseDown(trendsTab);
    fireEvent.click(trendsTab);
    expect(capturedRanges.length).toBeGreaterThan(0);
    const first = capturedRanges[capturedRanges.length - 1];

    // Advance the clock within the same day, then return to the same preset; the range must stay identical.
    vi.setSystemTime(new Date("2026-07-07T12:05:00"));
    fireEvent.click(screen.getByRole("button", { name: "7d" }));
    fireEvent.click(screen.getByRole("button", { name: "30d" }));

    const last = capturedRanges[capturedRanges.length - 1];
    expect(last.start).toBe(first.start);
    expect(last.end).toBe(first.end);
    // Day-boundary normalized: no millisecond precision leaks into the query key.
    expect(last.end).toMatch(/:00:00\.000Z$/);
    expect(last.start).toMatch(/:00:00\.000Z$/);
  });
});
