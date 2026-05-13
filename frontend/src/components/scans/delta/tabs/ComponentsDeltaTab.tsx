import { useEffect, useState } from "react";
import type { ComponentDeltaItem } from "@/types/scanDelta";
import { Button } from "@/components/ui/button";
import { DeltaError } from "../shared/DeltaError";
import { DeltaList } from "../shared/DeltaList";
import { DeltaPagination } from "../shared/DeltaPagination";
import { DeltaSummary } from "../shared/DeltaSummary";
import { type DeltaTabProps, useDeltaTabQuery } from "../shared/useDeltaTabQuery";

const CHANGES = ["all", "added", "removed", "changed"] as const;
type ComponentChangeFilter = (typeof CHANGES)[number];

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

export function ComponentsDeltaTab({
  projectId,
  fromScanId,
  toScanId,
  onCountLoaded,
}: DeltaTabProps) {
  const [change, setChange] = useState<ComponentChangeFilter>("all");

  const { query, setPage } = useDeltaTabQuery({
    category: "components",
    projectId,
    fromScanId,
    toScanId,
    extra: { change },
    filterKey: [change],
  });
  const { data, isLoading, isError } = query;

  useEffect(() => {
    if (data) onCountLoaded(data.totals.added + data.totals.removed + data.totals.changed);
  }, [data, onCountLoaded]);

  if (isError) return <DeltaError category="components" />;

  return (
    <div className="space-y-3 text-sm">
      <DeltaSummary
        added={data?.totals.added ?? 0}
        removed={data?.totals.removed ?? 0}
        changed={data?.totals.changed ?? 0}
        unchanged={data?.totals.unchanged ?? 0}
      />
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
            {(it.change === "added" || it.change === "removed") && it.version && (
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
