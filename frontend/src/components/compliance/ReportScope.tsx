import { ProjectOwnerById } from "@/components/project/ProjectOwner";
import type { ComplianceReportMeta } from "@/types/compliance";

export function ReportScope({ report, namesake = false }: Readonly<{ report: ComplianceReportMeta; namesake?: boolean }>) {
  const label = <span>{report.scope}{report.scope_id ? `: ${report.scope_name ?? report.scope_id}` : ""}</span>;
  if (!namesake || !report.scope_id) return label;
  return (
    <span className="inline-flex min-w-0 items-center gap-2">
      {label}
      <ProjectOwnerById projectId={report.scope_id} />
    </span>
  );
}
