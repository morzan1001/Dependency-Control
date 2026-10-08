import { render, screen, fireEvent, within } from "@testing-library/react";
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
  getCryptoHotspots: vi.fn().mockResolvedValue({ items: [], total: 0 }),
  getCryptoTrends: vi.fn().mockResolvedValue({ points: [] }),
}));

vi.mock("@/api/pqcMigration", () => ({
  getPQCMigrationPlan: vi.fn().mockResolvedValue({
    scope: "user", scope_id: null, generated_at: "2026-01-01T00:00:00Z", items: [], mappings_version: 3,
    summary: { total_items: 0, items_returned: 0, status_counts: {}, earliest_deadline: null },
  }),
}));
vi.mock("@/api/compliance", () => ({ listReports: vi.fn().mockResolvedValue({ reports: [] }), createReport: vi.fn() }));
vi.mock("@/context/useAuth", () => ({ useAuth: () => ({ hasPermission: () => false }) }));

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

describe("CryptoAnalyticsTab PQC export", () => {
  it("opens the compliance tab with a PQC migration report prefilled, and a later report starts from the default", async () => {
    renderTab();
    const pqcTab = screen.getByRole("tab", { name: "PQC Migration" });
    fireEvent.mouseDown(pqcTab);
    fireEvent.click(pqcTab);
    fireEvent.click(await screen.findByRole("button", { name: "Export as Compliance Report" }));

    expect(await screen.findByRole("dialog")).toHaveTextContent("PQC Migration Plan");
    expect(screen.getByRole("tab", { name: "Compliance Reports", hidden: true })).toHaveAttribute("aria-selected", "true");

    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Cancel" }));
    fireEvent.click(screen.getByRole("button", { name: "Generate report" }));
    expect(screen.getByRole("dialog")).toHaveTextContent("NIST SP 800-131A");
  });
});
