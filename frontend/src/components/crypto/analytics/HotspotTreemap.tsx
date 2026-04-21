import { useQuery } from "@tanstack/react-query";
import { ResponsiveContainer, Treemap } from "recharts";
import { getCryptoHotspots } from "@/api/cryptoAnalytics";
import type { AnalyticsScope, GroupingDimension } from "@/types/cryptoAnalytics";

interface Props {
  scope: AnalyticsScope;
  scopeId?: string;
  groupBy: GroupingDimension;
  scanId?: string;
}

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: "#dc2626",
  HIGH: "#ea580c",
  MEDIUM: "#ca8a04",
  LOW: "#0891b2",
  NEGLIGIBLE: "#94a3b8",
  INFO: "#6366f1",
  UNKNOWN: "#6b7280",
};

function topSeverity(mix: Record<string, number>): string {
  const order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE", "INFO", "UNKNOWN"];
  for (const s of order) if ((mix[s] ?? 0) > 0) return s;
  return "UNKNOWN";
}

export function HotspotTreemap({ scope, scopeId, groupBy, scanId }: Props) {
  const { data, isLoading } = useQuery({
    queryKey: ["crypto-hotspots", scope, scopeId, groupBy, scanId],
    queryFn: () => getCryptoHotspots({ scope, scopeId, groupBy, scanId }),
  });
  if (isLoading || !data) return <div className="p-4 text-sm">Loading treemap…</div>;

  const chartData = data.items.map((e) => ({
    name: e.key,
    size: e.asset_count,
    fill: SEVERITY_COLORS[topSeverity(e.severity_mix)],
  }));

  return (
    <div style={{ width: "100%", height: 500 }}>
      <ResponsiveContainer>
        <Treemap data={chartData} dataKey="size" stroke="#fff" />
      </ResponsiveContainer>
    </div>
  );
}
