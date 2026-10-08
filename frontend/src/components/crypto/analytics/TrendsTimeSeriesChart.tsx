import { useQuery } from "@tanstack/react-query";
import {
  CartesianGrid, Line, LineChart, ResponsiveContainer, Tooltip,
  XAxis, YAxis,
} from "recharts";
import { getCryptoTrends } from "@/api/cryptoAnalytics";
import { formatDate } from "@/lib/utils";
import type {
  AnalyticsScope, TrendBucket, TrendMetric,
} from "@/types/cryptoAnalytics";

interface Props {
  scope: AnalyticsScope;
  scopeId?: string;
  metric: TrendMetric;
  label: string;
  bucket: TrendBucket;
  rangeStart: Date;
  rangeEnd: Date;
}

export function TrendsTimeSeriesChart(p: Readonly<Props>) {
  const { data, isLoading, isError } = useQuery({
    queryKey: [
      "crypto-trends",
      p.scope, p.scopeId, p.metric, p.bucket,
      p.rangeStart.toISOString(), p.rangeEnd.toISOString(),
    ],
    queryFn: () => getCryptoTrends({
      scope: p.scope, scopeId: p.scopeId,
      metric: p.metric, bucket: p.bucket,
      rangeStart: p.rangeStart, rangeEnd: p.rangeEnd,
    }),
  });

  if (isLoading) return <div className="p-4 text-sm text-muted-foreground">Loading trend…</div>;
  if (isError || !data) return <div className="p-4 text-sm text-destructive">Failed to load trend data.</div>;

  const chartData = data.points.map((pt) => ({
    date: formatDate(pt.timestamp),
    value: pt.value,
  }));

  return (
    <div className="space-y-2">
      <div className="text-sm font-medium">{p.label}</div>
      <div style={{ width: "100%", height: 320 }}>
        <ResponsiveContainer>
          <LineChart data={chartData}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="date" />
            <YAxis />
            <Tooltip />
            <Line type="monotone" dataKey="value" stroke="#6366f1" strokeWidth={2} />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
