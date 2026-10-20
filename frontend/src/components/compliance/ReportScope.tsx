import type { ComplianceReportMeta } from "@/types/compliance";

export function ReportScope({ report }: Readonly<{ report: ComplianceReportMeta }>) {
  return <span>{report.scope}{report.scope_id ? `: ${report.scope_name ?? report.scope_id}` : ""}</span>;
}
