import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { getScanDelta } from "@/api/scanDelta";
import type { FindingDeltaItem } from "@/types/scanDelta";
import { Button } from "@/components/ui/button";
import { DeltaList } from "../shared/DeltaList";
import { DeltaPagination } from "../shared/DeltaPagination";

interface Props {
  projectId: string;
  fromScanId: string;
  toScanId: string;
  onCountLoaded: (totalChanges: number) => void;
}

const SEVERITIES = ["critical", "high", "medium", "low"] as const;
const TYPES = ["vulnerability", "secret", "sast", "iac", "license", "malware", "eol"] as const;
const CHANGES = ["all", "added", "removed"] as const;

export function FindingsDeltaTab({ projectId, fromScanId, toScanId, onCountLoaded }: Props) {
  const [page, setPage] = useState(1);
  const [severity, setSeverity] = useState<string[]>([]);
  const [types, setTypes] = useState<string[]>([]);
  const [change, setChange] = useState<"all" | "added" | "removed">("all");

  const toggle = (list: string[], setter: (v: string[]) => void, value: string) =>
    setter(list.includes(value) ? list.filter((v) => v !== value) : [...list, value]);

  const { data, isLoading, isError } = useQuery({
    queryKey: [
      "scan-delta",
      "findings",
      projectId,
      fromScanId,
      toScanId,
      page,
      severity,
      types,
      change,
    ],
    queryFn: () =>
      getScanDelta({
        projectId,
        fromScanId,
        toScanId,
        category: "findings",
        page,
        pageSize: 50,
        change,
        severity: severity.length ? severity : undefined,
        findingType: types.length ? types : undefined,
      }),
    enabled: !!(projectId && fromScanId && toScanId),
  });

  useEffect(() => {
    if (data) onCountLoaded(data.totals.added + data.totals.removed);
  }, [data, onCountLoaded]);

  if (isError) {
    return <div className="text-destructive text-sm">Failed to load findings delta.</div>;
  }

  return (
    <div className="space-y-3 text-sm">
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <span className="text-muted-foreground">Severity:</span>
        {SEVERITIES.map((s) => (
          <Button
            key={s}
            size="sm"
            variant={severity.includes(s) ? "default" : "outline"}
            onClick={() => {
              setPage(1);
              toggle(severity, setSeverity, s);
            }}
          >
            {s}
          </Button>
        ))}
      </div>
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <span className="text-muted-foreground">Type:</span>
        {TYPES.map((t) => (
          <Button
            key={t}
            size="sm"
            variant={types.includes(t) ? "default" : "outline"}
            onClick={() => {
              setPage(1);
              toggle(types, setTypes, t);
            }}
          >
            {t}
          </Button>
        ))}
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
      <DeltaList<FindingDeltaItem & { id: string }>
        isLoading={isLoading}
        emptyMessage="No findings changes"
        items={
          (data?.items as FindingDeltaItem[] | undefined)?.map((it) => ({
            ...it,
            id: `${it.change}-${it.finding_id}`,
          })) ?? []
        }
        renderRow={(it) => (
          <div className="flex items-baseline gap-2">
            <span className={it.change === "added" ? "text-green-600" : "text-red-600"}>
              {it.change === "added" ? "+" : "−"}
            </span>
            <span className="font-mono text-xs">[{it.severity}]</span>
            <span className="font-mono text-xs text-muted-foreground">{it.finding_type}</span>
            <span>{it.title}</span>
            {it.component && <span className="text-muted-foreground">— {it.component}</span>}
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
