import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { getPQCMigrationPlan } from "@/api/pqcMigration";
import { Card } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { MigrationPlanTable } from "./MigrationPlanTable";
import { MigrationItemDetailDrawer } from "./MigrationItemDetailDrawer";
import { formatDate } from "@/lib/utils";
import type { MigrationItem } from "@/types/pqcMigration";

export function PQCMigrationPanel() {
  const [selected, setSelected] = useState<MigrationItem | null>(null);
  const { data, isLoading } = useQuery({
    queryKey: ["pqc-migration", "user"],
    queryFn: () => getPQCMigrationPlan({ scope: "user" }),
  });

  if (isLoading || !data) return <div className="p-4 text-sm">Loading PQC migration plan…</div>;

  const s = data.summary;
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
        <SummaryCard label="Migrate now" value={s.status_counts.migrate_now ?? 0} color="bg-red-500/90" />
        <SummaryCard label="Migrate soon" value={s.status_counts.migrate_soon ?? 0} color="bg-orange-500/80" />
        <SummaryCard label="Plan migration" value={s.status_counts.plan_migration ?? 0} color="bg-yellow-500/60" />
        <SummaryCard label="Monitor" value={s.status_counts.monitor ?? 0} color="bg-muted" />
      </div>
      {s.earliest_deadline && (
        <div className="rounded border bg-muted/30 p-3 text-sm">
          Earliest PQC migration deadline:{" "}
          <strong>{formatDate(s.earliest_deadline)}</strong>
        </div>
      )}
      <div className="flex items-center gap-3">
        <div className="text-sm text-muted-foreground">
          {data.items.length} item(s) • mappings v{data.mappings_version}
        </div>
        <div className="ml-auto">
          <ExportAsReportButton />
        </div>
      </div>
      <MigrationPlanTable items={data.items} onSelect={setSelected} />
      <MigrationItemDetailDrawer item={selected} onClose={() => setSelected(null)} />
    </div>
  );
}

function SummaryCard({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <Card className="p-4">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className={`mt-1 inline-block rounded px-2 py-0.5 text-2xl font-semibold ${color} text-white`}>
        {value}
      </div>
    </Card>
  );
}

function ExportAsReportButton() {
  const handleClick = () => {
    localStorage.setItem("prefill_compliance_framework", "pqc-migration-plan");
    window.dispatchEvent(new CustomEvent("goto-compliance-reports-tab"));
  };
  return (
    <Button variant="outline" size="sm" onClick={handleClick}>
      Export as Compliance Report
    </Button>
  );
}
