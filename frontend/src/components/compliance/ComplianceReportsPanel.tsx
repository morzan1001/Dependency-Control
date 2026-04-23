import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Button } from "@/components/ui/button";
import { listReports } from "@/api/compliance";
import type { ComplianceReportMeta, ReportFramework } from "@/types/compliance";
import { ReportStatusBadge } from "./ReportStatusBadge";
import { NewReportDialog } from "./NewReportDialog";
import { ReportDetailDrawer } from "./ReportDetailDrawer";

export function ComplianceReportsPanel() {
  const [dialogOpen, setDialogOpen] = useState(false);
  const [selected, setSelected] = useState<ComplianceReportMeta | null>(null);
  const [prefillFramework, setPrefillFramework] = useState<ReportFramework | undefined>();

  const { data } = useQuery({
    queryKey: ["compliance-reports"],
    queryFn: () => listReports({ scope: "user", limit: 50 }),
    refetchInterval: (q) => {
      const reports = q.state.data?.reports ?? [];
      const hasInFlight = reports.some((r) => r.status === "pending" || r.status === "generating");
      return hasInFlight ? 2000 : false;
    },
  });

  useEffect(() => {
    const onPrefill = () => {
      const stored = localStorage.getItem("prefill_compliance_framework") as ReportFramework | null;
      if (stored) {
        setPrefillFramework(stored);
        setDialogOpen(true);
        localStorage.removeItem("prefill_compliance_framework");
      }
    };
    globalThis.addEventListener("goto-compliance-reports-tab", onPrefill);
    return () => globalThis.removeEventListener("goto-compliance-reports-tab", onPrefill);
  }, []);

  const reports = data?.reports ?? [];

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="text-sm text-muted-foreground">
          {reports.length} report(s)
        </div>
        <Button onClick={() => { setPrefillFramework(undefined); setDialogOpen(true); }}>
          Generate report
        </Button>
      </div>

      <div className="rounded-md border">
        <table className="w-full text-sm">
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
            {reports.length === 0 ? (
              <tr><td colSpan={5} className="p-4 text-center text-muted-foreground">No reports yet</td></tr>
            ) : reports.map((r) => (
              <tr
                key={r._id}
                className="cursor-pointer border-t hover:bg-muted/30"
                onClick={() => setSelected(r)}
              >
                <td className="p-2 font-mono">{r.framework}</td>
                <td className="p-2">{r.format.toUpperCase()}</td>
                <td className="p-2"><ReportStatusBadge status={r.status} /></td>
                <td className="p-2 text-xs">{new Date(r.requested_at).toLocaleString()}</td>
                <td className="p-2 text-xs">{r.scope}{r.scope_id ? `:${r.scope_id}` : ""}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <NewReportDialog
        open={dialogOpen}
        onClose={() => setDialogOpen(false)}
        defaultFramework={prefillFramework}
      />
      <ReportDetailDrawer report={selected} onClose={() => setSelected(null)} />
    </div>
  );
}
