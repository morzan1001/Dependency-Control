import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { deleteReport, downloadReport } from "@/api/compliance";
import { useDialogState } from "@/hooks/use-dialog-state";
import { extractErrorMessage } from "@/lib/errors";
import { formatDateTime } from "@/lib/utils";
import { ReportStatusBadge } from "./ReportStatusBadge";
import type { ComplianceReportMeta, ControlStatus, EvaluationCoverage } from "@/types/compliance";

interface Props { report: ComplianceReportMeta | null; onClose: () => void; }

function CoverageNotice({ coverage }: { readonly coverage: EvaluationCoverage }) {
  if (coverage.findings_evaluated >= coverage.findings_in_scope) {
    return (
      <div className="text-xs text-muted-foreground">
        Evaluated all {coverage.findings_in_scope.toLocaleString()} findings in scope.
      </div>
    );
  }
  return (
    <div className="rounded border border-amber-400 bg-amber-50 p-2 text-xs text-amber-900 dark:bg-amber-950 dark:text-amber-200">
      Evaluated {coverage.findings_evaluated.toLocaleString()} of{" "}
      {coverage.findings_in_scope.toLocaleString()} findings in scope, a cap of{" "}
      {coverage.limit.toLocaleString()} per report. The remaining{" "}
      {(coverage.findings_in_scope - coverage.findings_evaluated).toLocaleString()} were not read,
      so no control reports passed or waived: every verdict that would have rested on finding no
      match is reported as not_evaluated instead. Failures stand. Narrow the scope and regenerate
      before handing this to an auditor.
    </div>
  );
}

const WITHHELD_KEY: ControlStatus = "not_evaluated";

function SummaryRow({ label, value }: { readonly label: string; readonly value: number | undefined }) {
  const withheld = label === WITHHELD_KEY && (value ?? 0) > 0;
  const tone = withheld ? "text-amber-700 dark:text-amber-300 font-medium" : "";
  return (
    <div className="contents">
      <dt className={`text-xs ${withheld ? tone : "text-muted-foreground"}`}>{label}</dt>
      <dd className={`text-xs ${tone}`}>{String(value)}</dd>
    </div>
  );
}

export function ReportDetailDrawer({ report, onClose }: Props) {
  const qc = useQueryClient();
  const confirm = useDialogState();

  const del = useMutation({
    mutationFn: (id: string) => deleteReport(id),
    onSuccess: () => {
      toast.success("Report deleted");
      qc.invalidateQueries({ queryKey: ["compliance-reports"] });
      confirm.closeDialog();
      onClose();
    },
    onError: (e: unknown) => {
      toast.error(`Failed to delete: ${extractErrorMessage(e)}`);
    },
  });

  const dl = useMutation({
    mutationFn: (r: ComplianceReportMeta) =>
      downloadReport(r._id, r.artifact_filename ?? `compliance-report-${r._id}`),
    onError: (e: unknown) => {
      toast.error(`Failed to download: ${extractErrorMessage(e)}`);
    },
  });

  return (
    <>
      <Dialog open={!!report} onOpenChange={(o) => { if (!o) onClose(); }}>
        <DialogContent className="max-w-xl">
          {report && (
            <>
              <DialogHeader>
                <DialogTitle className="font-mono">{report.framework}</DialogTitle>
              </DialogHeader>
              <div className="space-y-2 text-sm">
                <div>
                  Status: <ReportStatusBadge status={report.status} />
                </div>
                <div className="text-muted-foreground">
                  Requested {formatDateTime(report.requested_at)} by {report.requested_by}
                </div>
                {report.completed_at && (
                  <div className="text-muted-foreground">
                    Completed {formatDateTime(report.completed_at)}
                  </div>
                )}
                {report.status === "failed" && report.error_message && (
                  <div className="rounded border border-red-400 bg-red-50 p-2 text-sm text-red-800">
                    {report.error_message}
                  </div>
                )}
                {report.coverage && <CoverageNotice coverage={report.coverage} />}
                {Object.keys(report.summary || {}).length > 0 && (
                  <dl className="mt-3 grid grid-cols-2 gap-y-1">
                    {Object.entries(report.summary).map(([k, v]) => (
                      <SummaryRow key={k} label={k} value={v} />
                    ))}
                  </dl>
                )}
                {report.status === "completed" && report.artifact_filename && (
                  <div className="mt-4">
                    <Button
                      size="sm"
                      variant="default"
                      onClick={() => dl.mutate(report)}
                      disabled={dl.isPending}
                    >
                      Download {report.format.toUpperCase()} · {report.artifact_filename}
                    </Button>
                    {report.artifact_size_bytes && (
                      <span className="ml-2 text-xs text-muted-foreground">
                        {(report.artifact_size_bytes / 1024).toFixed(1)} KB
                      </span>
                    )}
                  </div>
                )}
              </div>
              <DialogFooter className="mt-4">
                <Button
                  variant="destructive"
                  size="sm"
                  onClick={confirm.openDialog}
                  disabled={del.isPending}
                >
                  Delete report
                </Button>
              </DialogFooter>
            </>
          )}
        </DialogContent>
      </Dialog>

      <Dialog open={confirm.open} onOpenChange={confirm.setOpen}>
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle>Delete this report?</DialogTitle>
          </DialogHeader>
          <p className="text-sm text-muted-foreground">
            The report metadata and its generated artifact will be permanently
            removed. This action cannot be undone.
          </p>
          <DialogFooter>
            <Button variant="outline" onClick={confirm.closeDialog}>
              Cancel
            </Button>
            <Button
              variant="destructive"
              disabled={del.isPending || !report}
              onClick={() => { if (report) del.mutate(report._id); }}
            >
              {del.isPending ? "Deleting\u2026" : "Delete"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
