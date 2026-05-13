import { api } from "@/api/client";
import type { ScanDeltaResponse, DeltaCategory } from "@/types/scanDelta";

export interface GetScanDeltaArgs {
  projectId: string;
  fromScanId: string;
  toScanId: string;
  category: DeltaCategory;
  page?: number;
  pageSize?: number;
  change?: "added" | "removed" | "changed" | "all";
  severity?: string[];
  findingType?: string[];
}

export async function getScanDelta(
  args: GetScanDeltaArgs,
): Promise<ScanDeltaResponse> {
  const params: Record<string, string | number> = {
    project_id: args.projectId,
    from_scan_id: args.fromScanId,
    to_scan_id: args.toScanId,
    category: args.category,
  };
  if (args.page !== undefined) params.page = args.page;
  if (args.pageSize !== undefined) params.page_size = args.pageSize;
  if (args.change) params.change = args.change;
  if (args.severity && args.severity.length > 0) {
    params.severity = args.severity.join(",");
  }
  if (args.findingType && args.findingType.length > 0) {
    params.finding_type = args.findingType.join(",");
  }

  const { data } = await api.get<ScanDeltaResponse>("/analytics/scan-delta", {
    params,
  });
  return data;
}
