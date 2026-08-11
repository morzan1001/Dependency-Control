import { useEffect, useState } from "react";
import type { FindingDeltaItem } from "@/types/scanDelta";
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
import { SeverityBadge } from "@/components/findings/SeverityBadge";
import { ChangeBadge } from "../shared/ChangeBadge";
import { DeltaError } from "../shared/DeltaError";
import { DeltaPagination } from "../shared/DeltaPagination";
import { DeltaSummaryCards } from "../shared/DeltaSummaryCards";
import { type DeltaTabProps, useDeltaTabQuery } from "../shared/useDeltaTabQuery";

const SEVERITIES = ["critical", "high", "medium", "low"] as const;
const TYPES = ["vulnerability", "secret", "sast", "iac", "license", "malware", "eol"] as const;
const CHANGES = ["all", "added", "removed"] as const;
type FindingsChangeFilter = (typeof CHANGES)[number];

function toggle<T extends string>(list: readonly T[], value: T): T[] {
  return list.includes(value) ? list.filter((v) => v !== value) : [...list, value];
}

export function FindingsDeltaTab({
  projectId,
  fromScanId,
  toScanId,
  onCountLoaded,
}: DeltaTabProps) {
  const [severity, setSeverity] = useState<string[]>([]);
  const [types, setTypes] = useState<string[]>([]);
  const [change, setChange] = useState<FindingsChangeFilter>("all");

  const { query, setPage } = useDeltaTabQuery({
    category: "findings",
    projectId,
    fromScanId,
    toScanId,
    extra: {
      change,
      severity: severity.length ? severity : undefined,
      findingType: types.length ? types : undefined,
    },
    filterKey: [severity, types, change],
  });
  const { data, isLoading, isError } = query;

  useEffect(() => {
    if (data) onCountLoaded(data.totals.added + data.totals.removed);
  }, [data, onCountLoaded]);

  if (isError) return <DeltaError category="findings" />;

  return (
    <div className="space-y-3 text-sm">
      <DeltaSummaryCards
        added={data?.totals.added ?? 0}
        removed={data?.totals.removed ?? 0}
        unchanged={data?.totals.unchanged ?? 0}
        bySeverity={data?.totals.by_severity}
      />
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2 rounded-md border bg-muted/30 p-2 text-xs">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-muted-foreground">Severity:</span>
          {SEVERITIES.map((s) => (
            <Button
              key={s}
              size="sm"
              variant={severity.includes(s) ? "default" : "outline"}
              onClick={() => {
                setPage(1);
                setSeverity(toggle(severity, s));
              }}
            >
              {s}
            </Button>
          ))}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-muted-foreground">Type:</span>
          {TYPES.map((t) => (
            <Button
              key={t}
              size="sm"
              variant={types.includes(t) ? "default" : "outline"}
              onClick={() => {
                setPage(1);
                setTypes(toggle(types, t));
              }}
            >
              {t}
            </Button>
          ))}
        </div>
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
              <TableHead className="w-[110px]">Severity</TableHead>
              <TableHead className="w-[120px]">Type</TableHead>
              <TableHead>Title</TableHead>
              <TableHead>Component</TableHead>
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
            {(data?.items as FindingDeltaItem[] | undefined)?.map((item) => (
              <TableRow key={`${item.change}-${item.finding_id}`}>
                <TableCell><ChangeBadge change={item.change} /></TableCell>
                <TableCell><SeverityBadge severity={item.severity.toUpperCase()} /></TableCell>
                <TableCell className="font-mono text-xs text-muted-foreground">{item.finding_type}</TableCell>
                <TableCell>{item.title}</TableCell>
                <TableCell className="text-muted-foreground">{item.component ?? ""}</TableCell>
              </TableRow>
            ))}
            {!isLoading && (data?.items.length ?? 0) === 0 && (
              <TableRow>
                <TableCell colSpan={5} className="py-8 text-center text-muted-foreground">
                  No findings changes
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
