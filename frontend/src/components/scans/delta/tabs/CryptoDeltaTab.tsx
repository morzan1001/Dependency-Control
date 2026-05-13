import { useEffect } from "react";
import type { CryptoDeltaItem } from "@/types/scanDelta";
import { DeltaError } from "../shared/DeltaError";
import { DeltaList } from "../shared/DeltaList";
import { DeltaPagination } from "../shared/DeltaPagination";
import { DeltaSummary } from "../shared/DeltaSummary";
import { type DeltaTabProps, useDeltaTabQuery } from "../shared/useDeltaTabQuery";

export function CryptoDeltaTab({ projectId, fromScanId, toScanId, onCountLoaded }: DeltaTabProps) {
  const { query, setPage } = useDeltaTabQuery({
    category: "crypto",
    projectId,
    fromScanId,
    toScanId,
  });
  const { data, isLoading, isError } = query;

  useEffect(() => {
    if (data) onCountLoaded(data.totals.added + data.totals.removed);
  }, [data, onCountLoaded]);

  if (isError) return <DeltaError category="crypto" />;

  return (
    <div className="space-y-3 text-sm">
      <DeltaSummary
        added={data?.totals.added ?? 0}
        removed={data?.totals.removed ?? 0}
        unchanged={data?.totals.unchanged ?? 0}
      />
      <DeltaList<CryptoDeltaItem & { id: string }>
        isLoading={isLoading}
        items={
          (data?.items as CryptoDeltaItem[] | undefined)?.map((it, i) => ({
            ...it,
            id: `${it.change}-${it.name}-${i}`,
          })) ?? []
        }
        emptyMessage="No crypto changes"
        renderRow={(it) => (
          <div className="flex items-center gap-2 font-mono">
            <span className={it.change === "added" ? "text-green-600" : "text-red-600"}>
              {it.change === "added" ? "+" : "−"}
            </span>
            <span>{it.name}</span>
            {it.primitive && <span className="text-muted-foreground">[{it.primitive}]</span>}
            {it.asset_count > 1 && (
              <span className="text-xs text-muted-foreground">×{it.asset_count}</span>
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
