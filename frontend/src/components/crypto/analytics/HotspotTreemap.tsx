import { useQuery } from "@tanstack/react-query";
import { ResponsiveContainer, Treemap } from "recharts";
import { getCryptoHotspots } from "@/api/cryptoAnalytics";
import { SEVERITY_CHART_COLORS, SEVERITY_ORDER } from "@/lib/finding-utils";
import type { Severity } from "@/types/common";
import type { AnalyticsScope, GroupingDimension } from "@/types/cryptoAnalytics";

interface Props {
  scope: AnalyticsScope;
  scopeId?: string;
  groupBy: GroupingDimension;
}

function topSeverity(mix: Record<string, number>): Severity {
  return SEVERITY_ORDER.find((s) => (mix[s] ?? 0) > 0) ?? "UNKNOWN";
}

export function HotspotTreemap({ scope, scopeId, groupBy }: Readonly<Props>) {
  const { data, isLoading, isError } = useQuery({
    queryKey: ["crypto-hotspots", scope, scopeId, groupBy],
    queryFn: () => getCryptoHotspots({ scope, scopeId, groupBy }),
  });
  if (isLoading) return <div className="p-4 text-sm">Loading treemap…</div>;
  if (isError || !data) return <div className="p-4 text-sm text-destructive">Failed to load treemap data.</div>;

  const chartData = data.items.map((e) => ({
    name: e.key,
    size: e.asset_count,
    fill: SEVERITY_CHART_COLORS[topSeverity(e.severity_mix)],
  }));

  return (
    <div style={{ width: "100%", height: 500 }}>
      <ResponsiveContainer>
        <Treemap data={chartData} dataKey="size" stroke="#fff" />
      </ResponsiveContainer>
    </div>
  );
}
