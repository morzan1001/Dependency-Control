import { useQuery } from "@tanstack/react-query";
import { getCryptoHotspots } from "@/api/cryptoAnalytics";
import { useProjectsDropdown } from "@/hooks/queries/use-projects";
import type { AnalyticsScope, GroupingDimension } from "@/types/cryptoAnalytics";
import { heatmapBgClass, heatmapCell } from "./heatmap-utils";

const MAX_COLUMNS = 30;

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
  const { data: projectsData } = useProjectsDropdown();

  if (isLoading) return <div className="p-4 text-sm text-muted-foreground">Loading heatmap…</div>;
  if (isError || !data) return <div className="p-4 text-sm text-destructive">Failed to load heatmap data.</div>;

  const axis = scope === "project" ? "locations" : "projects";
  const everyColumn = Array.from(
    new Set(data.items.flatMap((e) => (scope === "project" ? e.locations : e.project_ids))),
  );
  // Capped so a tenant with many projects/locations never renders an unbounded grid.
  const columns = everyColumn.slice(0, MAX_COLUMNS);
  const sampledRows = scope === "project" ? data.items.filter((e) => !e.locations_complete).length : 0;

  const projectNameById = new Map((projectsData?.items ?? []).map((p) => [p.id, p.name]));

  const columnLabel = (c: string): string => {
    if (scope === "project") return c;
    const name = projectNameById.get(c);
    if (name) return name;
    return c.length > 10 ? `${c.slice(0, 8)}…` : c;
  };

  const max = Math.max(...data.items.map((e) => e.asset_count), 1);

  return (
    <div className="overflow-auto">
      {(columns.length < everyColumn.length || sampledRows > 0) && (
        <p className="pb-2 text-xs text-muted-foreground">
          {columns.length < everyColumn.length && `Showing ${columns.length} of ${everyColumn.length} ${axis}. `}
          {sampledRows > 0 &&
            `${sampledRows} row(s) list a sample of their locations — a "?" cell is unknown, not absent.`}
        </p>
      )}
      <table className="text-xs">
        <thead>
          <tr>
            <th className="sticky left-0 bg-background p-1 text-left">Key</th>
            {columns.map((c) => (
              <th
                key={c}
                className="p-1 font-mono text-muted-foreground whitespace-nowrap"
                title={scope === "project" ? c : (projectNameById.get(c) ?? c)}
              >
                {columnLabel(c)}
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
                    className={`p-1 text-center min-w-6 ${heatmapBgClass(cell.state, cell.intensityRatio)}`}
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
