import { useState } from 'react'
import { useDebounce } from '@/hooks/use-debounce'
import { DEBOUNCE_DELAY_MS } from '@/lib/constants'

/**
 * Unified pagination and search state management hook.
 *
 * Provides consistent page/search/sort state across all paginated pages.
 * Automatically resets to page 1 when the debounced search query changes.
 *
 * @example
 * ```tsx
 * const { search, setSearch, page, setPage, debouncedSearch, sortBy, setSortBy, sortOrder, setSortOrder } =
 *   usePaginationState({ defaultSort: 'created_at' })
 * ```
 */
export function usePaginationState(options?: {
  defaultSort?: string
  defaultOrder?: 'asc' | 'desc'
  debounceMs?: number
}) {
  const {
    defaultSort = 'created_at',
    defaultOrder = 'desc',
    debounceMs = DEBOUNCE_DELAY_MS,
  } = options ?? {}

  const [search, setSearch] = useState('')
  const [page, setPage] = useState(1)
  const [sortBy, setSortBy] = useState(defaultSort)
  const [sortOrder, setSortOrder] = useState<'asc' | 'desc'>(defaultOrder)
  const debouncedSearch = useDebounce(search, debounceMs)

  // Reset to first page when search changes
  const [prevSearch, setPrevSearch] = useState(debouncedSearch)
  if (debouncedSearch !== prevSearch) {
    setPrevSearch(debouncedSearch)
    setPage(1)
  }

  return {
    search,
    setSearch,
    page,
    setPage,
    sortBy,
    setSortBy,
    sortOrder,
    setSortOrder,
    debouncedSearch,
  }
}
