import { useState } from "react";
import type { FindingDeltaItem } from "@/types/scanDelta";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { SeverityBadge } from "@/components/findings/SeverityBadge";
import { formatDate } from "@/lib/utils";
import { ChangeBadge } from "../shared/ChangeBadge";
import { DeltaError } from "../shared/DeltaError";
import { Pagination } from "@/components/ui/pagination";
import { DeltaSummaryCards } from "../shared/DeltaSummaryCards";
import { DeltaFilterBar, DeltaFilterGroup, DeltaStatusRows } from "../shared/DeltaTableParts";
import { type DeltaTabProps, useDeltaTabQuery } from "../shared/useDeltaTabQuery";

const SEVERITIES = ["critical", "high", "medium", "low"] as const;
const TYPES = ["vulnerability", "secret", "sast", "iac", "license", "malware", "eol"] as const;
const CHANGES = ["all", "added", "removed", "changed"] as const;
type FindingsChangeFilter = (typeof CHANGES)[number];

function ChangedDetail({ item }: { readonly item: FindingDeltaItem }) {
  return (
    <div className="flex flex-wrap gap-x-2 font-mono text-xs">
      {item.from_version !== item.to_version && <span>{`${item.from_version} → ${item.to_version}`}</span>}
      {item.added_cves.map((cve) => <span key={cve} className="text-red-600">{`+${cve}`}</span>)}
      {item.dropped_cves.map((cve) => <span key={cve} className="text-green-600">{`−${cve}`}</span>)}
    </div>
  );
}

function toggle<T extends string>(list: readonly T[], value: T): T[] {
  return list.includes(value) ? list.filter((v) => v !== value) : [...list, value];
}

export function FindingsDeltaTab(props: DeltaTabProps) {
  const [severity, setSeverity] = useState<string[]>([]);
  const [types, setTypes] = useState<string[]>([]);
  const [change, setChange] = useState<FindingsChangeFilter>("all");

  const { query, setPage } = useDeltaTabQuery({
    ...props,
    category: "findings",
    filters: {
      change,
      severity: severity.length ? severity : undefined,
      findingType: types.length ? types : undefined,
    },
  });
  const { data, isLoading, isError } = query;

  if (isError) return <DeltaError category="findings" />;

  return (
    <div className="space-y-3 text-sm">
      <DeltaSummaryCards
        added={data?.totals.added ?? 0}
        removed={data?.totals.removed ?? 0}
        unchanged={data?.totals.unchanged ?? 0}
        changed={data?.totals.changed ?? 0}
        bySeverity={data?.totals.by_severity}
      />
      <DeltaFilterBar>
        <DeltaFilterGroup label="Severity" options={SEVERITIES} isActive={(s) => severity.includes(s)}
          onSelect={(s) => setSeverity(toggle(severity, s))} />
        <DeltaFilterGroup label="Type" options={TYPES} isActive={(t) => types.includes(t)}
          onSelect={(t) => setTypes(toggle(types, t))} />
        <DeltaFilterGroup label="Change" options={CHANGES} isActive={(c) => change === c} onSelect={setChange} />
      </DeltaFilterBar>
      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-[110px]">Change</TableHead>
              <TableHead className="w-[110px]">Severity</TableHead>
              <TableHead className="w-[120px]">Type</TableHead>
              <TableHead>Title</TableHead>
              <TableHead>Component</TableHead>
              <TableHead className="w-[120px]">First seen</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {(data?.items as FindingDeltaItem[] | undefined)?.map((item) => (
              <TableRow key={`${item.change}-${item.finding_id}`}>
                <TableCell><ChangeBadge change={item.change} /></TableCell>
                <TableCell><SeverityBadge severity={item.severity} /></TableCell>
                <TableCell className="font-mono text-xs text-muted-foreground">{item.finding_type}</TableCell>
                <TableCell>{item.title}</TableCell>
                <TableCell className="text-muted-foreground">
                  {item.component ?? ""}
                  {item.change === "changed" && <ChangedDetail item={item} />}
                </TableCell>
                <TableCell className="text-xs text-muted-foreground">
                  {item.first_seen ? formatDate(item.first_seen) : ""}
                </TableCell>
              </TableRow>
            ))}
            <DeltaStatusRows isLoading={isLoading} rows={data?.items.length ?? 0} columns={6} emptyText="No findings changes" />
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
