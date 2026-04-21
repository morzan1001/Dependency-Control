import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ChevronDown, ChevronRight } from "lucide-react";
import { getCryptoHotspots } from "@/api/cryptoAnalytics";
import type { AnalyticsScope } from "@/types/cryptoAnalytics";

interface Props {
  scope: Extract<AnalyticsScope, "team" | "global">;
  scopeId?: string;
}

export function CrossProjectNetworkView({ scope, scopeId }: Props) {
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const { data, isLoading } = useQuery({
    queryKey: ["crypto-hotspots", scope, scopeId, "name"],
    queryFn: () => getCryptoHotspots({ scope, scopeId, groupBy: "name" }),
  });
  if (isLoading || !data) {
    return <div className="p-4 text-sm text-muted-foreground">Loading cross-project data…</div>;
  }

  return (
    <div className="rounded border">
      <div className="border-b p-2 text-xs text-muted-foreground">
        Algorithms shared across projects in this {scope}
      </div>
      <ul className="divide-y">
        {data.items
          .filter((e) => e.project_ids.length > 1)
          .sort((a, b) => b.project_ids.length - a.project_ids.length)
          .map((e) => {
            const isOpen = expanded.has(e.key);
            return (
              <li key={e.key} className="p-2 text-sm">
                <button
                  type="button"
                  className="flex w-full items-center gap-2 text-left"
                  onClick={() => {
                    const next = new Set(expanded);
                    if (isOpen) {
                      next.delete(e.key);
                    } else {
                      next.add(e.key);
                    }
                    setExpanded(next);
                  }}
                >
                  {isOpen ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
                  <span className="font-mono">{e.key}</span>
                  <span className="ml-auto text-xs text-muted-foreground">
                    used in {e.project_ids.length} projects
                  </span>
                </button>
                {isOpen && (
                  <ul className="mt-2 ml-5 list-disc font-mono text-xs">
                    {e.project_ids.map((pid) => <li key={pid}>{pid}</li>)}
                  </ul>
                )}
              </li>
            );
          })}
      </ul>
    </div>
  );
}
