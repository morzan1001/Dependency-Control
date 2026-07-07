import { useEffect, useState } from "react";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { describe, it, expect, vi, beforeEach } from "vitest";

import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { PQCMigrationPanel } from "../PQCMigrationPanel";
import type { MigrationPlanResponse } from "@/types/pqcMigration";

vi.mock("@/api/pqcMigration", () => ({
  getPQCMigrationPlan: vi.fn(),
}));

// This jsdom setup runs without a backing localStorage; provide an in-memory
// stub so the export flow (which reads/writes prefill state) can be exercised.
if (typeof globalThis.localStorage === "undefined") {
  const store = new Map<string, string>();
  const stub: Storage = {
    get length() {
      return store.size;
    },
    clear: () => store.clear(),
    getItem: (k: string) => (store.has(k) ? store.get(k)! : null),
    key: (i: number) => Array.from(store.keys())[i] ?? null,
    removeItem: (k: string) => store.delete(k),
    setItem: (k: string, v: string) => store.set(k, String(v)),
  };
  Object.defineProperty(globalThis, "localStorage", { value: stub, configurable: true });
}

const plan: MigrationPlanResponse = {
  scope: "user",
  scope_id: null,
  generated_at: "2026-01-01T00:00:00Z",
  items: [],
  mappings_version: 3,
  summary: {
    total_items: 0,
    status_counts: {
      migrate_now: 1,
      migrate_soon: 0,
      plan_migration: 0,
      monitor: 0,
    },
    earliest_deadline: null,
  },
};

// Faithful stand-in for <ComplianceReportsPanel /> that replicates ONLY the
// contract exercised by the export flow: it lives in an inactive tab (so Radix
// keeps it unmounted) and attaches the prefill listener in a mount effect,
// reading + clearing localStorage exactly like the real panel does.
function ComplianceStub() {
  const [framework, setFramework] = useState<string | null>(null);
  useEffect(() => {
    const onPrefill = () => {
      const stored = localStorage.getItem("prefill_compliance_framework");
      if (stored) {
        setFramework(stored);
        localStorage.removeItem("prefill_compliance_framework");
      }
    };
    globalThis.addEventListener("goto-compliance-reports-tab", onPrefill);
    return () =>
      globalThis.removeEventListener("goto-compliance-reports-tab", onPrefill);
  }, []);
  return (
    <div>
      {framework && (
        <div data-testid="prefill-dialog">prefill: {framework}</div>
      )}
    </div>
  );
}

// Mirrors CryptoAnalyticsTab: an uncontrolled Radix Tabs whose inactive tab
// content (the compliance panel) is unmounted.
function Harness() {
  return (
    <Tabs defaultValue="pqc-migration">
      <TabsList>
        <TabsTrigger value="pqc-migration">PQC Migration</TabsTrigger>
        <TabsTrigger value="compliance-reports">Compliance Reports</TabsTrigger>
      </TabsList>
      <TabsContent value="pqc-migration">
        <PQCMigrationPanel />
      </TabsContent>
      <TabsContent value="compliance-reports">
        <ComplianceStub />
      </TabsContent>
    </Tabs>
  );
}

function renderHarness() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <Harness />
    </QueryClientProvider>,
  );
}

describe("PQCMigrationPanel export-as-compliance-report", () => {
  beforeEach(async () => {
    localStorage.clear();
    const { getPQCMigrationPlan } = await import("@/api/pqcMigration");
    vi.mocked(getPQCMigrationPlan).mockResolvedValue(plan);
  });

  it("switches to the compliance tab and delivers the prefill intent", async () => {
    renderHarness();

    const exportButton = await screen.findByRole("button", {
      name: /Export as Compliance Report/i,
    });

    // Precondition: the compliance panel is not mounted while on the PQC tab.
    expect(screen.queryByTestId("prefill-dialog")).not.toBeInTheDocument();

    fireEvent.click(exportButton);

    // The panel must mount (tab switched) AND receive the prefill event.
    await waitFor(() => {
      expect(screen.getByTestId("prefill-dialog")).toHaveTextContent(
        "pqc-migration-plan",
      );
    });

    // Intent consumed — the orphaned-key leak is gone.
    expect(localStorage.getItem("prefill_compliance_framework")).toBeNull();
  });
});
