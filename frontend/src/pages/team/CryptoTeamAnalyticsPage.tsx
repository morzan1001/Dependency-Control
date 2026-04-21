import { useState } from "react";
import { useParams } from "react-router-dom";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
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

interface Props {
  teamIdOverride?: string;
}

export function CryptoTeamAnalyticsPage({ teamIdOverride }: Props = {}) {
  const routeParams = useParams<{ teamId: string }>();
  const teamId = teamIdOverride ?? routeParams.teamId;
  const [groupBy, setGroupBy] = useState<GroupingDimension>("name");
  const view = useAnalyticsView("table");
  if (!teamId) return null;
  const common = { scope: "team" as const, scopeId: teamId, groupBy };

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <Select value={groupBy} onValueChange={(v) => setGroupBy(v as GroupingDimension)}>
          <SelectTrigger className="w-48"><SelectValue /></SelectTrigger>
          <SelectContent>
            {GROUPINGS.map((g) => <SelectItem key={g} value={g}>{g}</SelectItem>)}
          </SelectContent>
        </Select>
        <div className="ml-auto">
          <AnalyticsViewSwitcher
            availableViews={["table", "heatmap", "treemap", "bar", "network"]}
          />
        </div>
      </div>
      {view === "table" && <HotspotTable {...common} />}
      {view === "heatmap" && <HotspotHeatmap {...common} />}
      {view === "treemap" && <HotspotTreemap {...common} />}
      {view === "bar" && <HotspotBarChart {...common} />}
      {view === "network" && <CrossProjectNetworkView scope="team" scopeId={teamId} />}
    </div>
  );
}

export default CryptoTeamAnalyticsPage;
