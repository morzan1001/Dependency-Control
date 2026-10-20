import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { listReports } from "@/api/compliance";
import { useDialogState } from "@/hooks/use-dialog-state";
import { REPORT_FRAMEWORK_LABELS } from "@/lib/constants";
import { formatDateTime, sharedNames } from "@/lib/utils";
import type { ComplianceReportMeta, ReportFramework } from "@/types/compliance";
import { ReportStatusBadge } from "./ReportStatusBadge";
import { NewReportDialog } from "./NewReportDialog";
import { ReportDetailDrawer } from "./ReportDetailDrawer";
import { ReportScope } from "./ReportScope";

export function ComplianceReportsPanel({ defaultFramework }: Readonly<{ defaultFramework?: ReportFramework }>) {
  const newReportDialog = useDialogState(defaultFramework !== undefined);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [prefillFramework, setPrefillFramework] = useState(defaultFramework);

  const { data, isLoading, isError } = useQuery({
    queryKey: ["compliance-reports"],
    queryFn: () => listReports({ limit: 50 }),
    refetchInterval: (q) => {
      const reports = q.state.data?.reports ?? [];
      const hasInFlight = reports.some((r) => r.status === "pending" || r.status === "generating");
      return hasInFlight ? 2000 : false;
    },
  });

  const reports = data?.reports ?? [];
  const namesakes = sharedNames(
    reports.flatMap((r) => (r.scope === "project" && r.scope_id && r.scope_name ? [{ id: r.scope_id, name: r.scope_name }] : [])),
  );
  const scopeNamesakes = (r: ComplianceReportMeta) => (r.scope === "project" ? namesakes.get(r.scope_name ?? "") : undefined);
  const selected = reports.find((r) => r._id === selectedId) ?? null;

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="text-sm text-muted-foreground">
          {reports.length} report(s)
        </div>
        <Button onClick={() => { setPrefillFramework(undefined); newReportDialog.openDialog(); }}>
          Generate report
        </Button>
      </div>

      <div className="rounded-md border overflow-x-auto">
        <table className="w-full min-w-[680px] text-sm">
          <thead className="bg-muted/50 text-left">
            <tr>
              <th className="p-2">Framework</th>
              <th className="p-2">Format</th>
              <th className="p-2">Status</th>
              <th className="p-2">Requested</th>
              <th className="p-2">Scope</th>
            </tr>
          </thead>
          <tbody>
            {!isLoading && !isError && reports.map((r) => (
              <tr
                key={r._id}
                role="button"
                tabIndex={0}
                className="cursor-pointer border-t hover:bg-muted/30 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2"
                onClick={() => setSelectedId(r._id)}
                onKeyDown={(e) => {
                  if (e.key === "Enter" || e.key === " ") {
                    e.preventDefault();
                    setSelectedId(r._id);
                  }
                }}
              >
                <td className="p-2">{REPORT_FRAMEWORK_LABELS[r.framework] ?? r.framework}</td>
                <td className="p-2">{r.format.toUpperCase()}</td>
                <td className="p-2"><ReportStatusBadge status={r.status} /></td>
                <td className="p-2 text-xs">{formatDateTime(r.requested_at)}</td>
                <td className="p-2 text-xs"><ReportScope report={r} namesakes={scopeNamesakes(r)} /></td>
              </tr>
            ))}
          </tbody>
        </table>
        {isLoading && <p className="p-4 text-center text-sm text-muted-foreground">Loading reports…</p>}
        {!isLoading && isError && <p className="p-4 text-center text-sm text-destructive">Failed to load reports.</p>}
        {!isLoading && !isError && reports.length === 0 && (
          <p className="p-4 text-center text-sm text-muted-foreground">No reports yet</p>
        )}
      </div>

      {newReportDialog.open && (
        <NewReportDialog onClose={newReportDialog.closeDialog} defaultFramework={prefillFramework} />
      )}
      <ReportDetailDrawer report={selected} namesakes={selected ? scopeNamesakes(selected) : undefined} onClose={() => setSelectedId(null)} />
    </div>
  );
}
