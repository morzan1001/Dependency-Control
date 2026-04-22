import { useState } from "react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import {
  AnalyticsViewSwitcher, useAnalyticsView,
} from "@/components/crypto/analytics/AnalyticsViewSwitcher";
import { HotspotBarChart } from "@/components/crypto/analytics/HotspotBarChart";
import { HotspotHeatmap } from "@/components/crypto/analytics/HotspotHeatmap";
import { HotspotTable } from "@/components/crypto/analytics/HotspotTable";
import { HotspotTreemap } from "@/components/crypto/analytics/HotspotTreemap";
import { TrendsTimeSeriesChart } from "@/components/crypto/analytics/TrendsTimeSeriesChart";
import type { GroupingDimension, TrendBucket, TrendMetric } from "@/types/cryptoAnalytics";

const GROUPINGS: GroupingDimension[] = [
  "name", "primitive", "asset_type", "weakness_tag", "severity",
];

const TREND_METRICS: TrendMetric[] = [
  "total_crypto_findings",
  "quantum_vulnerable_findings",
  "weak_algo_findings",
  "weak_key_findings",
  "cert_expiring_soon",
  "cert_expired",
  "unique_algorithms",
  "unique_cipher_suites",
];

const TREND_PRESETS = [
  { label: "7d", days: 7 },
  { label: "30d", days: 30 },
  { label: "90d", days: 90 },
  { label: "365d", days: 365 },
];

function autoBucket(days: number): TrendBucket {
  if (days <= 14) return "day";
  if (days <= 90) return "week";
  return "month";
}

export function CryptoAnalyticsTab() {
  return (
    <Tabs defaultValue="hotspots" className="space-y-4">
      <TabsList>
        <TabsTrigger value="hotspots">Hotspots</TabsTrigger>
        <TabsTrigger value="trends">Trends</TabsTrigger>
        <TabsTrigger value="inventory">Inventory</TabsTrigger>
        <TabsTrigger value="findings">Findings</TabsTrigger>
      </TabsList>

      <TabsContent value="hotspots">
        <HotspotsSection />
      </TabsContent>
      <TabsContent value="trends">
        <TrendsSection />
      </TabsContent>
      <TabsContent value="inventory">
        <InventorySection />
      </TabsContent>
      <TabsContent value="findings">
        <FindingsSection />
      </TabsContent>
    </Tabs>
  );
}

function HotspotsSection() {
  const [groupBy, setGroupBy] = useState<GroupingDimension>("name");
  const view = useAnalyticsView("table");
  const common = { scope: "user" as const, groupBy };

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <span className="text-sm text-muted-foreground">Group by</span>
        <Select value={groupBy} onValueChange={(v) => setGroupBy(v as GroupingDimension)}>
          <SelectTrigger className="w-48"><SelectValue /></SelectTrigger>
          <SelectContent>
            {GROUPINGS.map((g) => <SelectItem key={g} value={g}>{g}</SelectItem>)}
          </SelectContent>
        </Select>
        <div className="ml-auto">
          <AnalyticsViewSwitcher availableViews={["table", "heatmap", "treemap", "bar"]} />
        </div>
      </div>
      {view === "table" && <HotspotTable {...common} />}
      {view === "heatmap" && <HotspotHeatmap {...common} />}
      {view === "treemap" && <HotspotTreemap {...common} />}
      {view === "bar" && <HotspotBarChart {...common} />}
    </div>
  );
}

function TrendsSection() {
  const [metric, setMetric] = useState<TrendMetric>("total_crypto_findings");
  const [days, setDays] = useState(30);
  const end = new Date();
  const start = new Date(end);
  start.setDate(end.getDate() - days);

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3">
        <Select value={metric} onValueChange={(v) => setMetric(v as TrendMetric)}>
          <SelectTrigger className="w-64"><SelectValue /></SelectTrigger>
          <SelectContent>
            {TREND_METRICS.map((m) => <SelectItem key={m} value={m}>{m}</SelectItem>)}
          </SelectContent>
        </Select>
        <div className="flex gap-1">
          {TREND_PRESETS.map((p) => (
            <button
              key={p.days}
              type="button"
              onClick={() => setDays(p.days)}
              className={`rounded px-3 py-1 text-xs ${days === p.days ? "bg-primary text-primary-foreground" : "border"}`}
            >
              {p.label}
            </button>
          ))}
        </div>
      </div>
      <TrendsTimeSeriesChart
        scope="user"
        metric={metric}
        bucket={autoBucket(days)}
        rangeStart={start}
        rangeEnd={end}
      />
    </div>
  );
}

function InventorySection() {
  return (
    <div className="space-y-3">
      <div className="text-sm text-muted-foreground">
        Crypto assets across your accessible projects (grouped by name).
      </div>
      <HotspotTable scope="user" groupBy="name" />
    </div>
  );
}

function FindingsSection() {
  return (
    <div className="space-y-3">
      <div className="text-sm text-muted-foreground">
        Crypto findings aggregated across your accessible projects.
      </div>
      <HotspotTable scope="user" groupBy="severity" />
    </div>
  );
}

export default CryptoAnalyticsTab;
