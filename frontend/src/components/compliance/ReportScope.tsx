import { ProjectOwnerById } from "@/components/project/ProjectOwner";
import type { Named } from "@/lib/utils";
import type { ComplianceReportMeta } from "@/types/compliance";

export function ReportScope({ report, namesakes }: Readonly<{ report: ComplianceReportMeta; namesakes?: readonly Named[] }>) {
  const label = <span>{report.scope}{report.scope_id ? `: ${report.scope_name ?? report.scope_id}` : ""}</span>;
  if (!namesakes || !report.scope_id) return label;
  return (
    <span className="inline-flex min-w-0 items-center gap-2">
      {label}
      <ProjectOwnerById projectId={report.scope_id} namesakes={namesakes} />
    </span>
  );
}
