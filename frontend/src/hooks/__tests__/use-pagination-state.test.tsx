import { act, renderHook } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import { usePaginationState, useSortState } from '../use-pagination-state'

describe('useSortState', () => {
  it('sorts a newly clicked column descending unless told otherwise, and flips it on the next click', () => {
    const { result } = renderHook(() => useSortState('created_at'))
    expect([result.current.sortBy, result.current.sortOrder]).toEqual(['created_at', 'desc'])

    act(() => result.current.toggleSort('name'))
    expect([result.current.sortBy, result.current.sortOrder]).toEqual(['name', 'desc'])

    act(() => result.current.toggleSort('name'))
    expect([result.current.sortBy, result.current.sortOrder]).toEqual(['name', 'asc'])

    act(() => result.current.toggleSort('version', 'asc'))
    expect([result.current.sortBy, result.current.sortOrder]).toEqual(['version', 'asc'])
  })
})

describe('usePaginationState', () => {
  it('returns to the first page when the sort changes', () => {
    const { result } = renderHook(() => usePaginationState({ defaultSort: 'username', defaultOrder: 'asc' }))
    act(() => result.current.setPage(3))

    act(() => result.current.toggleSort('email'))

    expect(result.current.page).toBe(1)
    expect([result.current.sortBy, result.current.sortOrder]).toEqual(['email', 'desc'])
  })
})
