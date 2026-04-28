import type { ReportStatus } from "@/types/compliance";

const COLOR: Record<ReportStatus, string> = {
  pending: "bg-muted text-foreground",
  generating: "bg-blue-500/70 text-white",
  completed: "bg-green-500/80 text-white",
  failed: "bg-red-500/90 text-white",
};

const LABEL: Record<ReportStatus, string> = {
  pending: "Pending",
  generating: "Generating…",
  completed: "Completed",
  failed: "Failed",
};

export function ReportStatusBadge({ status }: { status: ReportStatus }) {
  return (
    <span className={`inline-block rounded px-2 py-0.5 text-xs ${COLOR[status]}`}>
      {LABEL[status]}
    </span>
  );
}
