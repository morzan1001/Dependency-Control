import { useState } from "react";
import type { ComponentDeltaItem } from "@/types/scanDelta";
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

const CHANGES = ["all", "added", "removed", "changed"] as const;
type ComponentChangeFilter = (typeof CHANGES)[number];

export function ComponentsDeltaTab(props: DeltaTabProps) {
  const [change, setChange] = useState<ComponentChangeFilter>("all");

  const { query, setPage } = useDeltaTabQuery({ ...props, category: "components", filters: { change } });
  const { data, isLoading, isError } = query;

  if (isError) return <DeltaError category="components" />;

  return (
    <div className="space-y-3 text-sm">
      <DeltaSummaryCards
        added={data?.totals.added ?? 0}
        removed={data?.totals.removed ?? 0}
        unchanged={data?.totals.unchanged ?? 0}
        changed={data?.totals.changed ?? 0}
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
              <TableHead>Version</TableHead>
              <TableHead>License</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {(data?.items as ComponentDeltaItem[] | undefined)?.map((item, i) => (
              <TableRow key={`${item.change}-${item.name}-${i}`}>
                <TableCell><ChangeBadge change={item.change} /></TableCell>
                <TableCell>{item.name}</TableCell>
                <TableCell className="font-mono text-xs text-muted-foreground">
                  {item.change === "version_changed"
                    ? `${item.from_version} → ${item.to_version}`
                    : item.version ?? ""}
                </TableCell>
                <TableCell className="font-mono text-xs text-muted-foreground">
                  {item.change === "license_changed"
                    ? `${item.from_license} → ${item.to_license}`
                    : item.license ?? ""}
                </TableCell>
              </TableRow>
            ))}
            <DeltaStatusRows isLoading={isLoading} rows={data?.items.length ?? 0} columns={4} emptyText="No component changes" />
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
