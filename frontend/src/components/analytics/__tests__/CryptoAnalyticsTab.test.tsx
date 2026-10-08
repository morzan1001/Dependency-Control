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
  getCryptoHotspots: vi.fn().mockResolvedValue({ rows: [], total: 0 }),
  getCryptoTrends: vi.fn().mockResolvedValue({ points: [] }),
}));

vi.mock("@/api/pqcMigration", () => ({
  getPQCMigrationPlan: vi.fn().mockResolvedValue({
    scope: "user",
    scope_id: null,
    generated_at: "2026-01-01T00:00:00Z",
    items: [],
    mappings_version: 3,
    summary: {
      total_items: 0,
      items_returned: 0,
      status_counts: { migrate_now: 1, migrate_soon: 0, plan_migration: 0, monitor: 0 },
      earliest_deadline: null,
    },
  }),
}));
vi.mock("@/api/compliance", () => ({
  listReports: vi.fn().mockResolvedValue({ reports: [] }),
  createReport: vi.fn(),
}));
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

describe("CryptoAnalyticsTab compliance export", () => {
  // Radix activates a tab on mouseDown.
  function openTab(name: RegExp) {
    const tab = screen.getByRole("tab", { name });
    fireEvent.mouseDown(tab);
    fireEvent.click(tab);
  }

  it("lands on the compliance view with a PQC migration report prefilled, once", async () => {
    renderTab();

    openTab(/PQC Migration/);
    fireEvent.click(await screen.findByRole("button", { name: /Export as Compliance Report/i }));

    const dialog = await screen.findByRole("dialog");
    // The open dialog hides the rest of the page from the accessibility tree.
    expect(screen.getByRole("tab", { name: /Compliance Reports/, hidden: true })).toHaveAttribute("data-state", "active");
    expect(within(dialog).getByText("PQC Migration Plan")).toBeInTheDocument();

    fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    openTab(/Hotspots/);
    openTab(/Compliance Reports/);

    expect(await screen.findByText("No reports yet")).toBeInTheDocument();
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });
});
