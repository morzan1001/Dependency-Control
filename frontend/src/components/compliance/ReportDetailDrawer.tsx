import { useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { deleteReport, downloadReport } from "@/api/compliance";
import { useDialogState } from "@/hooks/use-dialog-state";
import { formatDateTime, getErrorMessage } from "@/lib/utils";
import { ReportStatusBadge } from "./ReportStatusBadge";
import type { ComplianceReportMeta, ControlStatus, EvaluationCoverage, InputCoverage } from "@/types/compliance";

interface Props { report: ComplianceReportMeta | null; onClose: () => void; }

function isComplete(input: InputCoverage): boolean {
  return input.evaluated >= input.in_scope;
}

function inputSentence(input: InputCoverage, subject: string): string {
  if (isComplete(input)) {
    return `Evaluated all ${input.in_scope.toLocaleString()} ${subject} in scope.`;
  }
  return (
    `Evaluated ${input.evaluated.toLocaleString()} of ${input.in_scope.toLocaleString()} ${subject} ` +
    `in scope, a cap of ${input.limit.toLocaleString()} per report; the remaining ` +
    `${(input.in_scope - input.evaluated).toLocaleString()} were not read.`
  );
}

const GAPS_SHOWN = 5;

function gapSentence(gaps: readonly string[]): string {
  const shown = gaps.slice(0, GAPS_SHOWN).join(", ");
  const rest = gaps.length - GAPS_SHOWN;
  return (
    "Inputs are missing for part of the scope, so every verdict that would have rested on finding " +
    `no match is reported as not_evaluated: ${rest > 0 ? `${shown} and ${rest} more` : shown}.`
  );
}

function CoverageNotice({ coverage }: { readonly coverage: EvaluationCoverage }) {
  const reads = [
    [coverage.findings, "findings"],
    [coverage.crypto_assets, "crypto assets"],
    [coverage.plan_items, "migration plan items"],
  ] as const;
  const sentences = reads.flatMap(([input, subject]) => (input ? [inputSentence(input, subject)] : []));
  const gaps = coverage.gaps ?? [];
  if (gaps.length > 0) sentences.push(gapSentence(gaps));
  const capped = reads.some(([input]) => input && !isComplete(input));
  if (capped) {
    sentences.push(
      "Every verdict that would have rested on finding no match in a capped input is reported as " +
        "not_evaluated instead. Failures stand. Narrow the scope and regenerate before handing this to an auditor.",
    );
  }
  const tone =
    capped || gaps.length > 0
      ? "rounded border border-amber-400 bg-amber-50 p-2 text-xs text-amber-900 dark:bg-amber-950 dark:text-amber-200"
      : "text-xs text-muted-foreground";
  return <div className={tone}>{sentences.join(" ")}</div>;
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

export function ReportDetailDrawer({ report, onClose }: Readonly<Props>) {
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
      toast.error(`Failed to delete: ${getErrorMessage(e)}`);
    },
  });

  const dl = useMutation({
    mutationFn: (r: ComplianceReportMeta) =>
      downloadReport(r._id, r.artifact_filename ?? `compliance-report-${r._id}`),
    onError: (e: unknown) => {
      toast.error(`Failed to download: ${getErrorMessage(e)}`);
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
