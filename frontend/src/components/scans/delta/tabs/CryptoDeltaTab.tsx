import { useEffect, useState } from "react";
import type { CryptoDeltaItem } from "@/types/scanDelta";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { ChangeBadge } from "../shared/ChangeBadge";
import { DeltaError } from "../shared/DeltaError";
import { DeltaPagination } from "../shared/DeltaPagination";
import { DeltaSummaryCards } from "../shared/DeltaSummaryCards";
import { type DeltaTabProps, useDeltaTabQuery } from "../shared/useDeltaTabQuery";

const CHANGES = ["all", "added", "removed"] as const;
type CryptoChangeFilter = (typeof CHANGES)[number];

export function CryptoDeltaTab({ projectId, fromScanId, toScanId, onCountLoaded }: DeltaTabProps) {
  const [change, setChange] = useState<CryptoChangeFilter>("all");

  const { query, setPage } = useDeltaTabQuery({
    category: "crypto",
    projectId,
    fromScanId,
    toScanId,
    extra: { change },
    filterKey: [change],
  });
  const { data, isLoading, isError } = query;

  useEffect(() => {
    if (data) onCountLoaded(data.totals.added + data.totals.removed);
  }, [data, onCountLoaded]);

  if (isError) return <DeltaError category="crypto" />;

  return (
    <div className="space-y-3 text-sm">
      <DeltaSummaryCards
        added={data?.totals.added ?? 0}
        removed={data?.totals.removed ?? 0}
        unchanged={data?.totals.unchanged ?? 0}
      />
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2 rounded-md border bg-muted/30 p-2 text-xs">
        <div className="flex flex-wrap items-center gap-2">
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
      </div>
      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-[110px]">Change</TableHead>
              <TableHead>Name</TableHead>
              <TableHead>Primitive</TableHead>
              <TableHead>Variant</TableHead>
              <TableHead>Locations</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {isLoading &&
              ["s1", "s2", "s3"].map((id) => (
                <TableRow key={id}>
                  {["c1", "c2", "c3", "c4", "c5"].map((c) => (
                    <TableCell key={c}>
                      <Skeleton className="h-5 w-20" />
                    </TableCell>
                  ))}
                </TableRow>
              ))}
            {(data?.items as CryptoDeltaItem[] | undefined)?.map((item, i) => (
              <TableRow key={`${item.change}-${item.name}-${i}`}>
                <TableCell><ChangeBadge change={item.change} /></TableCell>
                <TableCell>{item.name}</TableCell>
                <TableCell className="text-muted-foreground">{item.primitive ?? ""}</TableCell>
                <TableCell className="text-muted-foreground">{item.variant ?? ""}</TableCell>
                <TableCell className="text-muted-foreground">
                  <span title={item.locations.join("\n")}>{item.locations.length}</span>
                  {item.asset_count > 1 && <span> ×{item.asset_count}</span>}
                </TableCell>
              </TableRow>
            ))}
            {!isLoading && (data?.items.length ?? 0) === 0 && (
              <TableRow>
                <TableCell colSpan={5} className="py-8 text-center text-muted-foreground">
                  No crypto changes
                </TableCell>
              </TableRow>
            )}
          </TableBody>
        </Table>
      </div>
      <DeltaPagination
        page={data?.page ?? 1}
        totalPages={data?.total_pages ?? 1}
        onChange={setPage}
      />
    </div>
  );
}
