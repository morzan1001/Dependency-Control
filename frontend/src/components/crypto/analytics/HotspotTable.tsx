import { useQuery } from "@tanstack/react-query";
import { getCryptoHotspots } from "@/api/cryptoAnalytics";
import type { AnalyticsScope, GroupingDimension, HotspotEntry } from "@/types/cryptoAnalytics";

interface Props {
  scope: AnalyticsScope;
  scopeId?: string;
  groupBy: GroupingDimension;
  scanId?: string;
  onSelect?: (entry: HotspotEntry) => void;
}

export function HotspotTable({ scope, scopeId, groupBy, scanId, onSelect }: Props) {
  const { data, isLoading } = useQuery({
    queryKey: ["crypto-hotspots", scope, scopeId, groupBy, scanId],
    queryFn: () => getCryptoHotspots({ scope, scopeId, groupBy, scanId }),
  });

  if (isLoading) return <div className="p-4 text-sm text-muted-foreground">Loading hotspots…</div>;
  if (!data || data.items.length === 0) {
    return <div className="p-4 text-sm text-muted-foreground">No hotspots in this scope.</div>;
  }

  return (
    <div className="rounded-md border">
      <table className="w-full text-sm">
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
          {data.items.map((e) => (
            <tr
              key={e.key}
              className="border-t cursor-pointer hover:bg-muted/30"
              onClick={() => onSelect?.(e)}
            >
              <td className="p-2 font-mono">{e.key}</td>
              <td className="p-2">{e.asset_count}</td>
              <td className="p-2">{e.finding_count}</td>
              <td className="p-2 text-xs">
                {Object.entries(e.severity_mix).map(([sev, n]) => (
                  <span key={sev} className="mr-2">
                    {sev}: <strong>{n}</strong>
                  </span>
                ))}
              </td>
              <td className="p-2 text-xs">{e.project_ids.length}</td>
              <td className="p-2 text-xs">{new Date(e.last_seen).toLocaleDateString()}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
