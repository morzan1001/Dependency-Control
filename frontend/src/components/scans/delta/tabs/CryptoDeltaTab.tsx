import { useState } from "react";
import type { CryptoDeltaItem } from "@/types/scanDelta";
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
import { Pagination } from "@/components/ui/pagination";
import { DeltaSummaryCards } from "../shared/DeltaSummaryCards";
import { DeltaFilterBar, DeltaFilterGroup, DeltaStatusRows } from "../shared/DeltaTableParts";
import { type DeltaTabProps, useDeltaTabQuery } from "../shared/useDeltaTabQuery";

const CHANGES = ["all", "added", "removed"] as const;
type CryptoChangeFilter = (typeof CHANGES)[number];

export function CryptoDeltaTab(props: DeltaTabProps) {
  const [change, setChange] = useState<CryptoChangeFilter>("all");

  const { query, setPage } = useDeltaTabQuery({ ...props, category: "crypto", filters: { change } });
  const { data, isLoading, isError } = query;

  if (isError) return <DeltaError category="crypto" />;

  return (
    <div className="space-y-3 text-sm">
      <DeltaSummaryCards
        added={data?.totals.added ?? 0}
        removed={data?.totals.removed ?? 0}
        unchanged={data?.totals.unchanged ?? 0}
      />
      <DeltaFilterBar>
        <DeltaFilterGroup label="Change" options={CHANGES} isActive={(c) => change === c} onSelect={setChange} />
      </DeltaFilterBar>
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
            <DeltaStatusRows isLoading={isLoading} rows={data?.items.length ?? 0} columns={5} emptyText="No crypto changes" />
          </TableBody>
        </Table>
      </div>
      <Pagination
        page={data?.page ?? 1}
        totalPages={data?.total_pages ?? 1}
        onChange={setPage}
      />
    </div>
  );
}
