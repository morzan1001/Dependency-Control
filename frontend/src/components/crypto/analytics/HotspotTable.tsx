import { useQuery } from "@tanstack/react-query";
import { getCryptoHotspots } from "@/api/cryptoAnalytics";
import { SeverityBreakdownBadges } from "@/components/analytics/VulnerabilityHotspots";
import { formatDate } from "@/lib/utils";
import type { AnalyticsScope, GroupingDimension } from "@/types/cryptoAnalytics";

interface Props {
  scope: AnalyticsScope;
  scopeId?: string;
  groupBy: GroupingDimension;
}

export function HotspotTable({ scope, scopeId, groupBy }: Readonly<Props>) {
  const { data, isLoading, isError } = useQuery({
    queryKey: ["crypto-hotspots", scope, scopeId, groupBy],
    queryFn: () => getCryptoHotspots({ scope, scopeId, groupBy }),
  });
  const items = data?.items ?? [];

  if (isLoading) {
    return <div className="p-4 text-sm text-muted-foreground">Loading hotspots…</div>;
  }
  if (isError) {
    return <div className="p-4 text-sm text-destructive">Failed to load hotspots.</div>;
  }
  if (items.length === 0) {
    return <div className="p-4 text-sm text-muted-foreground">No hotspots in this scope.</div>;
  }

  return (
    <div className="rounded-md border overflow-x-auto">
      <table className="w-full min-w-[640px] text-sm">
        <thead className="bg-muted/50 text-left">
          <tr>
            <th className="p-2">Key</th>
            <th className="p-2 w-24">Assets</th>
            <th className="p-2 w-24">Findings</th>
            <th className="p-2">Severity</th>
            <th className="p-2">Projects</th>
            <th className="p-2">Last seen</th>
          </tr>
        </thead>
        <tbody>
          {items.map((e) => (
            <tr key={e.key} className="border-t hover:bg-muted/30">
              <td className="p-2 font-mono">{e.key}</td>
              <td className="p-2">{e.asset_count}</td>
              <td className="p-2">{e.finding_count}</td>
              <td className="p-2">
                <SeverityBreakdownBadges
                  breakdown={Object.fromEntries(Object.entries(e.severity_mix).map(([sev, n]) => [sev.toLowerCase(), n]))}
                />
              </td>
              <td className="p-2 text-xs">{e.project_ids.length}</td>
              <td className="p-2 text-xs">{formatDate(e.last_seen)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
