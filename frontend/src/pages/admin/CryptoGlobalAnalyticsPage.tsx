import { useState } from "react";
import { ExternalLink } from "lucide-react";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import { Button } from "@/components/ui/button";
import {
  AnalyticsViewSwitcher, useAnalyticsView,
} from "@/components/crypto/analytics/AnalyticsViewSwitcher";
import { CrossProjectNetworkView } from "@/components/crypto/analytics/CrossProjectNetworkView";
import { HotspotBarChart } from "@/components/crypto/analytics/HotspotBarChart";
import { HotspotHeatmap } from "@/components/crypto/analytics/HotspotHeatmap";
import { HotspotTable } from "@/components/crypto/analytics/HotspotTable";
import { HotspotTreemap } from "@/components/crypto/analytics/HotspotTreemap";
import type { GroupingDimension } from "@/types/cryptoAnalytics";

const GROUPINGS: GroupingDimension[] = [
  "name", "primitive", "asset_type", "weakness_tag", "severity",
];

const METABASE_URL = import.meta.env.VITE_METABASE_CRYPTO_DASHBOARD_URL ?? "";

export function CryptoGlobalAnalyticsPage() {
  const [groupBy, setGroupBy] = useState<GroupingDimension>("name");
  const view = useAnalyticsView("table");
  const common = { scope: "global" as const, groupBy };

  return (
    <div className="space-y-4 p-6">
      <div className="flex items-center gap-3">
        <h2 className="text-lg font-semibold">Global crypto analytics</h2>
        <div className="ml-auto flex items-center gap-2">
          <Select value={groupBy} onValueChange={(v) => setGroupBy(v as GroupingDimension)}>
            <SelectTrigger className="w-48"><SelectValue /></SelectTrigger>
            <SelectContent>
              {GROUPINGS.map((g) => <SelectItem key={g} value={g}>{g}</SelectItem>)}
            </SelectContent>
          </Select>
          <AnalyticsViewSwitcher
            availableViews={["table", "heatmap", "treemap", "bar", "network"]}
          />
        </div>
      </div>

      {view === "table" && <HotspotTable {...common} />}
      {view === "heatmap" && <HotspotHeatmap {...common} />}
      {view === "treemap" && <HotspotTreemap {...common} />}
      {view === "bar" && <HotspotBarChart {...common} />}
      {view === "network" && <CrossProjectNetworkView scope="global" />}

      {METABASE_URL && (
        <div className="mt-8 rounded border bg-muted/20 p-4">
          <div className="mb-2 text-sm font-medium">Advanced analytics</div>
          <p className="mb-3 text-xs text-muted-foreground">
            Ad-hoc queries and compliance reports live in Metabase.
          </p>
          <Button asChild variant="outline" size="sm">
            <a href={METABASE_URL} target="_blank" rel="noopener noreferrer">
              Open crypto dashboard in Metabase <ExternalLink className="ml-2 h-3 w-3" />
            </a>
          </Button>
        </div>
      )}
    </div>
  );
}

export default CryptoGlobalAnalyticsPage;
