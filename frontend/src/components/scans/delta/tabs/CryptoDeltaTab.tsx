import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { getScanDelta } from "@/api/scanDelta";
import type { CryptoDeltaItem } from "@/types/scanDelta";
import { DeltaList } from "../shared/DeltaList";
import { DeltaPagination } from "../shared/DeltaPagination";

interface Props {
  projectId: string;
  fromScanId: string;
  toScanId: string;
  onCountLoaded: (totalChanges: number) => void;
}

export function CryptoDeltaTab({ projectId, fromScanId, toScanId, onCountLoaded }: Props) {
  const [page, setPage] = useState(1);

  const { data, isLoading, isError } = useQuery({
    queryKey: ["scan-delta", "crypto", projectId, fromScanId, toScanId, page],
    queryFn: () =>
      getScanDelta({ projectId, fromScanId, toScanId, category: "crypto", page, pageSize: 50 }),
    enabled: !!(projectId && fromScanId && toScanId),
  });

  useEffect(() => {
    if (data) onCountLoaded(data.totals.added + data.totals.removed);
  }, [data, onCountLoaded]);

  if (isError) {
    return <div className="text-destructive text-sm">Failed to load crypto delta.</div>;
  }
  return (
    <div className="space-y-3 text-sm">
      <div className="rounded border bg-muted/20 p-2 text-xs">
        +{data?.totals.added ?? 0} added · -{data?.totals.removed ?? 0} removed · {data?.totals.unchanged ?? 0} unchanged
      </div>
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
      <DeltaPagination page={data?.page ?? 1} totalPages={data?.total_pages ?? 1} onChange={setPage} />
    </div>
  );
}
