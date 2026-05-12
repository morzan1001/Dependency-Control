import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { getScanDelta } from "@/api/scanDelta";
import type { ComponentDeltaItem } from "@/types/scanDelta";
import { Button } from "@/components/ui/button";
import { DeltaList } from "../shared/DeltaList";
import { DeltaPagination } from "../shared/DeltaPagination";

interface Props {
  projectId: string;
  fromScanId: string;
  toScanId: string;
  onCountLoaded: (totalChanges: number) => void;
}

const CHANGES = ["all", "added", "removed", "changed"] as const;

const CHANGE_PREFIX: Record<ComponentDeltaItem["change"], string> = {
  added: "+",
  removed: "−",
  version_changed: "↻",
  license_changed: "⚖",
};
const CHANGE_COLOR: Record<ComponentDeltaItem["change"], string> = {
  added: "text-green-600",
  removed: "text-red-600",
  version_changed: "text-amber-600",
  license_changed: "text-blue-600",
};

export function ComponentsDeltaTab({ projectId, fromScanId, toScanId, onCountLoaded }: Props) {
  const [page, setPage] = useState(1);
  const [change, setChange] = useState<"all" | "added" | "removed" | "changed">("all");

  const { data, isLoading, isError } = useQuery({
    queryKey: ["scan-delta", "components", projectId, fromScanId, toScanId, page, change],
    queryFn: () =>
      getScanDelta({
        projectId,
        fromScanId,
        toScanId,
        category: "components",
        page,
        pageSize: 50,
        change,
      }),
    enabled: !!(projectId && fromScanId && toScanId),
  });

  useEffect(() => {
    if (data) {
      const t = data.totals;
      onCountLoaded(t.added + t.removed + t.changed);
    }
  }, [data, onCountLoaded]);

  if (isError) {
    return <div className="text-destructive text-sm">Failed to load components delta.</div>;
  }

  return (
    <div className="space-y-3 text-sm">
      <div className="rounded border bg-muted/20 p-2 text-xs">
        +{data?.totals.added ?? 0} added · -{data?.totals.removed ?? 0} removed · ↻
        {data?.totals.changed ?? 0} changed · {data?.totals.unchanged ?? 0} unchanged
      </div>
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <span className="text-muted-foreground">Change:</span>
        {CHANGES.map((c) => (
          <Button
            key={c}
            size="sm"
            variant={change === c ? "default" : "outline"}
            onClick={() => {
              setPage(1);
              setChange(c);
            }}
          >
            {c}
          </Button>
        ))}
      </div>
      <DeltaList<ComponentDeltaItem & { id: string }>
        isLoading={isLoading}
        emptyMessage="No component changes"
        items={
          (data?.items as ComponentDeltaItem[] | undefined)?.map((it, i) => ({
            ...it,
            id: `${it.change}-${it.name}-${i}`,
          })) ?? []
        }
        renderRow={(it) => (
          <div className="flex items-baseline gap-2 font-mono text-xs">
            <span className={CHANGE_COLOR[it.change]}>{CHANGE_PREFIX[it.change]}</span>
            <span className="text-sm">{it.name}</span>
            {it.change === "added" && it.version && (
              <span className="text-muted-foreground">@{it.version}</span>
            )}
            {it.change === "removed" && it.version && (
              <span className="text-muted-foreground">@{it.version}</span>
            )}
            {it.change === "version_changed" && (
              <span className="text-muted-foreground">
                {it.from_version} → {it.to_version}
              </span>
            )}
            {it.from_license && it.to_license && it.from_license !== it.to_license && (
              <span className="text-blue-600">
                {it.from_license} → {it.to_license}
              </span>
            )}
            {(it.change === "added" || it.change === "removed") && it.license && (
              <span className="text-muted-foreground">[{it.license}]</span>
            )}
          </div>
        )}
      />
      <DeltaPagination
        page={data?.page ?? 1}
        totalPages={data?.total_pages ?? 1}
        onChange={setPage}
      />
    </div>
  );
}
