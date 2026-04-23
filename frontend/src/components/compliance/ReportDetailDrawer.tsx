import {
  Dialog, DialogContent, DialogHeader, DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { downloadReportUrl } from "@/api/compliance";
import { ReportStatusBadge } from "./ReportStatusBadge";
import type { ComplianceReportMeta } from "@/types/compliance";

interface Props { report: ComplianceReportMeta | null; onClose: () => void; }

export function ReportDetailDrawer({ report, onClose }: Props) {
  return (
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
                Requested {new Date(report.requested_at).toLocaleString()} by {report.requested_by}
              </div>
              {report.completed_at && (
                <div className="text-muted-foreground">
                  Completed {new Date(report.completed_at).toLocaleString()}
                </div>
              )}
              {report.status === "failed" && report.error_message && (
                <div className="rounded border border-red-400 bg-red-50 p-2 text-sm text-red-800">
                  {report.error_message}
                </div>
              )}
              {Object.keys(report.summary || {}).length > 0 && (
                <dl className="mt-3 grid grid-cols-2 gap-y-1">
                  {Object.entries(report.summary).map(([k, v]) => (
                    <div key={k} className="contents">
                      <dt className="text-muted-foreground text-xs">{k}</dt>
                      <dd className="text-xs">{String(v)}</dd>
                    </div>
                  ))}
                </dl>
              )}
              {report.status === "completed" && report.artifact_filename && (
                <div className="mt-4">
                  <a href={downloadReportUrl(report._id)} target="_blank" rel="noopener noreferrer">
                    <Button size="sm" variant="default">
                      Download {report.format.toUpperCase()} · {report.artifact_filename}
                    </Button>
                  </a>
                  {report.artifact_size_bytes && (
                    <span className="ml-2 text-xs text-muted-foreground">
                      {(report.artifact_size_bytes / 1024).toFixed(1)} KB
                    </span>
                  )}
                </div>
              )}
            </div>
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}
