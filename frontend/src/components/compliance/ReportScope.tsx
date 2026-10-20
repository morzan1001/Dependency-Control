import { ProjectOwnerById } from "@/components/project/ProjectOwner";
import type { ComplianceReportMeta } from "@/types/compliance";

export function ReportScope({ report, namesakeIds }: Readonly<{ report: ComplianceReportMeta; namesakeIds?: readonly string[] }>) {
  const label = <span>{report.scope}{report.scope_id ? `: ${report.scope_name ?? report.scope_id}` : ""}</span>;
  if (!namesakeIds || !report.scope_id) return label;
  return (
    <span className="inline-flex min-w-0 items-center gap-2">
      {label}
      <ProjectOwnerById projectId={report.scope_id} namesakeIds={namesakeIds} />
    </span>
  );
}
