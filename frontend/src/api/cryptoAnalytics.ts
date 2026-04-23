import { api } from "@/api/client";
import type {
  AnalyticsScope, GroupingDimension, HotspotResponse,
  ScanDelta, TrendBucket, TrendMetric, TrendSeries,
} from "@/types/cryptoAnalytics";

export interface GetHotspotsParams {
  scope: AnalyticsScope;
  scopeId?: string;
  groupBy: GroupingDimension;
  scanId?: string;
  limit?: number;
}

export async function getCryptoHotspots(p: GetHotspotsParams): Promise<HotspotResponse> {
  const { data } = await api.get<HotspotResponse>("/analytics/crypto/hotspots", {
    params: {
      scope: p.scope,
      scope_id: p.scopeId,
      group_by: p.groupBy,
      scan_id: p.scanId,
      limit: p.limit ?? 100,
    },
  });
  return data;
}

export interface GetTrendsParams {
  scope: AnalyticsScope;
  scopeId?: string;
  metric: TrendMetric;
  bucket: TrendBucket;
  rangeStart: Date;
  rangeEnd: Date;
}

export async function getCryptoTrends(p: GetTrendsParams): Promise<TrendSeries> {
  const { data } = await api.get<TrendSeries>("/analytics/crypto/trends", {
    params: {
      scope: p.scope,
      scope_id: p.scopeId,
      metric: p.metric,
      bucket: p.bucket,
      range_start: p.rangeStart.toISOString(),
      range_end: p.rangeEnd.toISOString(),
    },
  });
  return data;
}

export async function getScanDelta(
  projectId: string, fromScanId: string, toScanId: string,
): Promise<ScanDelta> {
  const { data } = await api.get<ScanDelta>("/analytics/crypto/scan-delta", {
    params: { project_id: projectId, from: fromScanId, to: toScanId },
  });
  return data;
}
