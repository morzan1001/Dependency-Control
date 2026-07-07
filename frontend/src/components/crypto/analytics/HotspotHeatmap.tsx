import { useQuery } from "@tanstack/react-query";
import { getCryptoHotspots } from "@/api/cryptoAnalytics";
import type { AnalyticsScope, GroupingDimension } from "@/types/cryptoAnalytics";
import { heatmapBgClass, heatmapCell } from "./heatmap-utils";

interface Props {
  scope: AnalyticsScope;
  scopeId?: string;
  groupBy: GroupingDimension;
  scanId?: string;
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
              <td className="sticky left-0 bg-background p-1 font-mono whitespace-nowrap">
                {e.key} <span className="text-muted-foreground">({e.asset_count})</span>
              </td>
              {columns.map((c) => {
                const cell = heatmapCell(e, c, scope, max);
                return (
                  <td
                    key={c}
                    className={`p-1 text-center min-w-6 ${heatmapBgClass(cell.present, cell.intensityRatio)}`}
                    title={cell.title}
                  >
                    {cell.label}
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
