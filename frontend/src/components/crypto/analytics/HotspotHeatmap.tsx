import { useQuery } from "@tanstack/react-query";
import { getCryptoHotspots } from "@/api/cryptoAnalytics";
import type { AnalyticsScope, GroupingDimension } from "@/types/cryptoAnalytics";

interface Props {
  scope: AnalyticsScope;
  scopeId?: string;
  groupBy: GroupingDimension;
  scanId?: string;
}

function bgClass(count: number, max: number): string {
  if (count === 0) return "bg-muted/30";
  const ratio = count / Math.max(max, 1);
  if (ratio >= 0.8) return "bg-red-500/80 text-white";
  if (ratio >= 0.5) return "bg-orange-500/70";
  if (ratio >= 0.25) return "bg-yellow-500/50";
  return "bg-yellow-500/20";
}

export function HotspotHeatmap({ scope, scopeId, groupBy, scanId }: Props) {
  const { data, isLoading, isError } = useQuery({
    queryKey: ["crypto-hotspots", scope, scopeId, groupBy, scanId],
    queryFn: () => getCryptoHotspots({ scope, scopeId, groupBy, scanId }),
  });

  if (isLoading) return <div className="p-4 text-sm text-muted-foreground">Loading heatmap…</div>;
  if (isError || !data) return <div className="p-4 text-sm text-destructive">Failed to load heatmap data.</div>;

  const columns =
    scope === "project"
      ? Array.from(new Set(data.items.flatMap((e) => e.locations))).slice(0, 30)
      : Array.from(new Set(data.items.flatMap((e) => e.project_ids)));

  const max = Math.max(...data.items.map((e) => e.asset_count), 1);

  return (
    <div className="overflow-auto">
      <table className="text-xs">
        <thead>
          <tr>
            <th className="sticky left-0 bg-background p-1 text-left">Key</th>
            {columns.map((c) => (
              <th key={c} className="p-1 font-mono text-muted-foreground whitespace-nowrap">
                {c}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {data.items.map((e) => (
            <tr key={e.key}>
              <td className="sticky left-0 bg-background p-1 font-mono">{e.key}</td>
              {columns.map((c) => {
                const present =
                  scope === "project"
                    ? e.locations.includes(c)
                    : e.project_ids.includes(c);
                const count = present ? e.asset_count : 0;
                return (
                  <td
                    key={c}
                    className={`p-1 text-center min-w-6 ${bgClass(count, max)}`}
                    title={`${e.key} × ${c}: ${count}`}
                  >
                    {count > 0 ? count : ""}
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
