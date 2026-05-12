/**
 * Shared per-tab query hook for the scan-delta modal.
 *
 * The three category tabs (Findings, Components, Crypto) share an identical
 * "fetch + report total to parent + paginate" lifecycle. Centralising it here
 * avoids three slightly-different copies of the same useQuery + useEffect
 * pattern and keeps the queryKey shape consistent.
 */

import { useEffect, useState } from "react";
import { useQuery, type UseQueryResult } from "@tanstack/react-query";
import { getScanDelta, type GetScanDeltaArgs } from "@/api/scanDelta";
import type { DeltaCategory, ScanDeltaResponse } from "@/types/scanDelta";

export interface DeltaTabProps {
  projectId: string;
  fromScanId: string;
  toScanId: string;
  onCountLoaded: (totalChanges: number) => void;
}

interface UseDeltaTabQueryArgs {
  category: DeltaCategory;
  projectId: string;
  fromScanId: string;
  toScanId: string;
  /** Additional fetch args appended to every request (filters, change toggle). */
  extra?: Omit<GetScanDeltaArgs, "projectId" | "fromScanId" | "toScanId" | "category" | "page" | "pageSize">;
  /** Anything in this array becomes part of the queryKey so the cache splits per filter combo. */
  filterKey?: ReadonlyArray<unknown>;
  /** Called once whenever new data arrives. Caller is responsible for memoising. */
  onCountLoaded: (totals: ScanDeltaResponse["totals"]) => void;
}

interface UseDeltaTabQueryResult {
  query: UseQueryResult<ScanDeltaResponse>;
  page: number;
  setPage: (page: number) => void;
}

const PAGE_SIZE = 50;

export function useDeltaTabQuery({
  category,
  projectId,
  fromScanId,
  toScanId,
  extra,
  filterKey = [],
  onCountLoaded,
}: UseDeltaTabQueryArgs): UseDeltaTabQueryResult {
  const [page, setPage] = useState(1);

  const query = useQuery({
    queryKey: ["scan-delta", category, projectId, fromScanId, toScanId, page, ...filterKey],
    queryFn: () =>
      getScanDelta({
        projectId,
        fromScanId,
        toScanId,
        category,
        page,
        pageSize: PAGE_SIZE,
        ...extra,
      }),
    enabled: !!(projectId && fromScanId && toScanId),
  });

  const { data } = query;
  useEffect(() => {
    if (data) onCountLoaded(data.totals);
  }, [data, onCountLoaded]);

  return { query, page, setPage };
}
