import { useCallback, useState } from "react";
import type { FindingDeltaItem } from "@/types/scanDelta";
import { Button } from "@/components/ui/button";
import { DeltaError } from "../shared/DeltaError";
import { DeltaList } from "../shared/DeltaList";
import { DeltaPagination } from "../shared/DeltaPagination";
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

  const reportCount = useCallback(
    (totals: { added: number; removed: number }) => onCountLoaded(totals.added + totals.removed),
    [onCountLoaded],
  );

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
    onCountLoaded: reportCount,
  });
  const { data, isLoading, isError } = query;

  if (isError) return <DeltaError category="findings" />;

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
              setSeverity(toggle(severity, s));
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
              setTypes(toggle(types, t));
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
