import { useState } from 'react'
import { useDebounce } from '@/hooks/use-debounce'
import { DEBOUNCE_DELAY_MS } from '@/lib/constants'

export type SortOrder = 'asc' | 'desc'

export interface SortState<T extends string = string> {
  sortBy: T
  sortOrder: SortOrder
  toggleSort: (column: T, firstOrder?: SortOrder) => void
}

export function useSortState<T extends string = string>(defaultSort: NoInfer<T>, defaultOrder: SortOrder = 'desc') {
  const [sortBy, setSortBy] = useState<T>(defaultSort)
  const [sortOrder, setSortOrder] = useState<SortOrder>(defaultOrder)

  const toggleSort = (column: T, firstOrder: SortOrder = 'desc') => {
    if (column === sortBy) {
      setSortOrder(sortOrder === 'asc' ? 'desc' : 'asc')
    } else {
      setSortBy(column)
      setSortOrder(firstOrder)
    }
  }

  return { sortBy, setSortBy, sortOrder, setSortOrder, toggleSort }
}

export function usePaginationState(options?: {
  defaultSort?: string
  defaultOrder?: SortOrder
  debounceMs?: number
}) {
  const {
    defaultSort = 'created_at',
    defaultOrder = 'desc',
    debounceMs = DEBOUNCE_DELAY_MS,
  } = options ?? {}

  const [search, setSearch] = useState('')
  const [page, setPage] = useState(1)
  const sort = useSortState(defaultSort, defaultOrder)
  const debouncedSearch = useDebounce(search, debounceMs)

  const [prevSearch, setPrevSearch] = useState(debouncedSearch)
  if (debouncedSearch !== prevSearch) {
    setPrevSearch(debouncedSearch)
    setPage(1)
  }

  const toggleSort = (column: string, firstOrder?: SortOrder) => {
    sort.toggleSort(column, firstOrder)
    setPage(1)
  }

  return {
    search,
    setSearch,
    page,
    setPage,
    ...sort,
    toggleSort,
    debouncedSearch,
  }
}
