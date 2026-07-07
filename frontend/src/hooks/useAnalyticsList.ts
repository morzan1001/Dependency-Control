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
  selectItems: (response: TResponse) => TItem[];
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
