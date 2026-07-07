import { render, screen, fireEvent } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

import { CryptoAnalyticsTab } from "../CryptoAnalyticsTab";

// Capture the range props the trends chart receives across renders so we can
// assert the derived query-key inputs stay stable.
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

    // Enter the Trends tab (Radix mounts TrendsSection on activation; Radix
    // triggers select on mouseDown, matching the repo's existing tab tests).
    const trendsTab = screen.getByRole("tab", { name: /trends/i });
    fireEvent.mouseDown(trendsTab);
    fireEvent.click(trendsTab);
    expect(capturedRanges.length).toBeGreaterThan(0);
    const first = capturedRanges[capturedRanges.length - 1];

    // Simulate wall-clock advancing within the same calendar day, then force a
    // re-render of TrendsSection back to the SAME days preset (30d default:
    // 7d -> 30d). With the pre-fix `new Date()` in render this yields a
    // millisecond-different ISO string; with the memoized day-granularity range
    // it must be identical.
    vi.setSystemTime(new Date("2026-07-07T12:05:00"));
    fireEvent.click(screen.getByRole("button", { name: "7d" }));
    fireEvent.click(screen.getByRole("button", { name: "30d" }));

    const last = capturedRanges[capturedRanges.length - 1];
    expect(last.start).toBe(first.start);
    expect(last.end).toBe(first.end);
    // Normalized to a day boundary: no sub-minute (millisecond) precision leaks
    // into the range that would break the query key. Robust across whole-hour
    // timezones (local midnight -> HH:00:00.000Z).
    expect(last.end).toMatch(/:00:00\.000Z$/);
    expect(last.start).toMatch(/:00:00\.000Z$/);
  });
});
