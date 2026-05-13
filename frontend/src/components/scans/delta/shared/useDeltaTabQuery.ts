/**
 * Shared per-tab query hook for the scan-delta modal.
 *
 * The three category tabs (Findings, Components, Crypto) share an identical
 * useQuery + page-state lifecycle. Centralising it here keeps the queryKey
 * shape consistent and removes one of the three near-duplicate copies of
 * the same `useQuery({ queryKey, queryFn, enabled })` block.
 *
 * The badge-count effect lives in each tab (`useEffect` on `query.data`)
 * because each tab maps totals to a count differently. Parents are
 * expected to pass a stable `onCountLoaded` (the modal already wraps it
 * in `useCallback`); the tabs depend on it directly.
 */

import { useState } from "react";
import { useQuery, type UseQueryResult } from "@tanstack/react-query";
import { getScanDelta, type GetScanDeltaArgs } from "@/api/scanDelta";
import type { DeltaCategory, ScanDeltaResponse } from "@/types/scanDelta";

export interface DeltaTabProps {
  readonly projectId: string;
  readonly fromScanId: string;
  readonly toScanId: string;
  readonly onCountLoaded: (totalChanges: number) => void;
}

interface UseDeltaTabQueryArgs {
  category: DeltaCategory;
  projectId: string;
  fromScanId: string;
  toScanId: string;
  /** Extra request args (filters, change toggle). */
  extra?: Omit<
    GetScanDeltaArgs,
    "projectId" | "fromScanId" | "toScanId" | "category" | "page" | "pageSize"
  >;
  /** Entries become part of the queryKey so the cache splits per filter combo. */
  filterKey?: ReadonlyArray<unknown>;
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

  return { query, page, setPage };
}
