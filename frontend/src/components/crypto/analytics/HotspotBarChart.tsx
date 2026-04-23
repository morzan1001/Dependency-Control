import { useQuery } from "@tanstack/react-query";
import {
  Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip,
  XAxis, YAxis,
} from "recharts";
import { getCryptoHotspots } from "@/api/cryptoAnalytics";
import type { AnalyticsScope, GroupingDimension } from "@/types/cryptoAnalytics";

interface Props {
  scope: AnalyticsScope;
  scopeId?: string;
  groupBy: GroupingDimension;
  scanId?: string;
  topN?: number;
}

export function HotspotBarChart({ scope, scopeId, groupBy, scanId, topN = 20 }: Props) {
  const { data, isLoading } = useQuery({
    queryKey: ["crypto-hotspots", scope, scopeId, groupBy, scanId, topN],
    queryFn: () => getCryptoHotspots({ scope, scopeId, groupBy, scanId, limit: topN }),
  });
  if (isLoading || !data) return <div className="p-4 text-sm">Loading…</div>;

  const chartData = data.items.map((e) => ({
    name: e.key,
    assets: e.asset_count,
    findings: e.finding_count,
  }));

  return (
    <div style={{ width: "100%", height: 400 }}>
      <ResponsiveContainer>
        <BarChart data={chartData} margin={{ top: 20, right: 20, left: 20, bottom: 60 }}>
          <CartesianGrid strokeDasharray="3 3" />
          <XAxis dataKey="name" angle={-30} textAnchor="end" height={80} interval={0} />
          <YAxis />
          <Tooltip />
          <Bar dataKey="assets" fill="#6366f1" name="Assets" />
          <Bar dataKey="findings" fill="#dc2626" name="Findings" />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
