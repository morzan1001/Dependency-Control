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
  // App-wide cached projects list; used to resolve project ObjectIds -> names
  // for the org/team/user-scope heatmap column headers.
  const { data: projectsData } = useProjectsDropdown();

  if (isLoading) return <div className="p-4 text-sm text-muted-foreground">Loading heatmap…</div>;
  if (isError || !data) return <div className="p-4 text-sm text-destructive">Failed to load heatmap data.</div>;

  // Columns are keyed on the raw identifier (location path or project ObjectId)
  // because heatmapCell matches against entry.locations / entry.project_ids.
  // Both branches are capped so a tenant with many projects/locations does not
  // render an unbounded rows x columns grid.
  const columns =
    scope === "project"
      ? Array.from(new Set(data.items.flatMap((e) => e.locations))).slice(0, MAX_COLUMNS)
      : Array.from(new Set(data.items.flatMap((e) => e.project_ids))).slice(0, MAX_COLUMNS);

  const projectNameById = new Map((projectsData?.items ?? []).map((p) => [p.id, p.name]));

  // Header display for a column: for non-project scope resolve the ObjectId to a
  // project name when known, otherwise truncate the raw id (full value in title).
  const columnLabel = (c: string): string => {
    if (scope === "project") return c;
    const name = projectNameById.get(c);
    if (name) return name;
    return c.length > 10 ? `${c.slice(0, 8)}…` : c;
  };

  const max = Math.max(...data.items.map((e) => e.asset_count), 1);

  return (
    <div className="overflow-auto">
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
