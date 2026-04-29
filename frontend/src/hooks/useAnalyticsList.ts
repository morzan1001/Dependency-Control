/**
 * useAnalyticsList — shared scaffolding for analytics list views.
 *
 * Bundles the three boilerplate pieces every analytics panel needs:
 *   1. TanStack useQuery with a typed query key
 *   2. Normalised `isLoading` / `isEmpty` flags
 *   3. A refetch handle + error exposure
 *
 * Consumers still render their own domain-specific table/cards; this
 * hook only owns the data-loading shape so HotspotTable,
 * VulnerabilityHotspots, PQCMigrationPanel etc. don't each reinvent
 * their own `isLoading` / `items.length === 0` dance.
 */

import { useQuery, type QueryKey, type UseQueryOptions } from "@tanstack/react-query";

export interface AnalyticsListResult<TResponse, TItem> {
  data: TResponse | undefined;
  items: TItem[];
  isLoading: boolean;
  isFetching: boolean;
  isEmpty: boolean;
  error: Error | null;
  refetch: () => void;
}

export interface UseAnalyticsListArgs<TResponse, TItem> {
  queryKey: QueryKey;
  queryFn: () => Promise<TResponse>;
  /** Extract the list items from the response. Required so the hook can
   *  compute `isEmpty` without coupling to a specific response shape. */
  selectItems: (response: TResponse) => TItem[];
  /** Forwarded to TanStack useQuery (e.g. enabled, refetchInterval). */
  options?: Omit<
    UseQueryOptions<TResponse, Error, TResponse, QueryKey>,
    "queryKey" | "queryFn"
  >;
}

export function useAnalyticsList<TResponse, TItem>(
  args: UseAnalyticsListArgs<TResponse, TItem>,
): AnalyticsListResult<TResponse, TItem> {
  const query = useQuery<TResponse, Error, TResponse, QueryKey>({
    queryKey: args.queryKey,
    queryFn: args.queryFn,
    ...(args.options ?? {}),
  });

  const items = query.data ? args.selectItems(query.data) : [];
  const isEmpty = !query.isLoading && items.length === 0;

  return {
    data: query.data,
    items,
    isLoading: query.isLoading,
    isFetching: query.isFetching,
    isEmpty,
    error: query.error ?? null,
    refetch: () => {
      query.refetch();
    },
  };
}
