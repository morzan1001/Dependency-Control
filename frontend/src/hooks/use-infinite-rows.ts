import { useCallback } from 'react'
import type { InfiniteData, UseInfiniteQueryResult } from '@tanstack/react-query'

export type InfiniteRows<TRow> = ReturnType<typeof useInfiniteRows<unknown, TRow>>

export function useInfiniteRows<TPage, TRow>(
  query: UseInfiniteQueryResult<InfiniteData<TPage>>,
  rowsOf: (page: TPage) => TRow[],
) {
  const { data, hasNextPage, isFetchingNextPage, isFetchNextPageError, fetchNextPage } = query
  const nextPageFailed = isFetchNextPageError && !isFetchingNextPage
  // A failed page waits for Retry; asking for it again on the next render would loop.
  const canLoadMore = hasNextPage && !isFetchingNextPage && !nextPageFailed

  const loadMore = useCallback(() => {
    if (canLoadMore) fetchNextPage()
  }, [canLoadMore, fetchNextPage])

  const observeEnd = useCallback(
    (node: HTMLElement | null) => {
      if (!node || !canLoadMore) return
      const observer = new IntersectionObserver(
        (entries) => {
          if (entries[0]?.isIntersecting) fetchNextPage()
        },
        { rootMargin: '300px' },
      )
      observer.observe(node)
      return () => observer.disconnect()
    },
    [canLoadMore, fetchNextPage],
  )

  return {
    rows: data?.pages.flatMap(rowsOf) ?? [],
    hasMore: hasNextPage && !nextPageFailed,
    nextPageFailed,
    loadMore,
    observeEnd,
  }
}
