import { useEffect, useState } from "react";
import { useQuery, type UseQueryResult } from "@tanstack/react-query";
import { getScanDelta, type GetScanDeltaArgs } from "@/api/scanDelta";
import type { DeltaCategory, ScanDeltaResponse } from "@/types/scanDelta";

export interface DeltaTabProps {
  readonly projectId: string;
  readonly fromScanId: string;
  readonly toScanId: string;
  /** The whole response: the tab badge counts it, the header explains the two sides from it. */
  readonly onLoaded: (delta: ScanDeltaResponse) => void;
}

interface UseDeltaTabQueryArgs extends DeltaTabProps {
  category: DeltaCategory;
  filters: Omit<GetScanDeltaArgs, "projectId" | "fromScanId" | "toScanId" | "category" | "page" | "pageSize">;
}

interface UseDeltaTabQueryResult {
  query: UseQueryResult<ScanDeltaResponse>;
  setPage: (page: number) => void;
}

const PAGE_SIZE = 50;

export function useDeltaTabQuery({
  category,
  projectId,
  fromScanId,
  toScanId,
  onLoaded,
  filters,
}: UseDeltaTabQueryArgs): UseDeltaTabQueryResult {
  const [page, setPage] = useState(1);
  const filterKey = JSON.stringify(filters);
  const [pageFilterKey, setPageFilterKey] = useState(filterKey);
  if (pageFilterKey !== filterKey) {
    setPageFilterKey(filterKey);
    setPage(1);
  }

  const query = useQuery({
    queryKey: ["scan-delta", category, projectId, fromScanId, toScanId, page, filters],
    queryFn: () =>
      getScanDelta({
        projectId,
        fromScanId,
        toScanId,
        category,
        page,
        pageSize: PAGE_SIZE,
        ...filters,
      }),
    enabled: !!(projectId && fromScanId && toScanId),
  });

  const { data } = query;
  useEffect(() => {
    if (data) onLoaded(data);
  }, [data, onLoaded]);

  return { query, setPage };
}
