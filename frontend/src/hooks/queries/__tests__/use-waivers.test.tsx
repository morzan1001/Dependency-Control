import { act, renderHook, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider, useQuery } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { describe, expect, it, vi } from 'vitest'

import { waiverApi } from '@/api/waivers'

import { useCreateWaiver, useDeleteWaiver } from '../use-waivers'

vi.mock('@/api/waivers', () => ({ waiverApi: { create: vi.fn().mockResolvedValue({}), delete: vi.fn().mockResolvedValue({}) } }))

const SCAN_ID = 's1'

// The scan page's findings table and waived-findings probe, keyed as FindingsTable and WaivedFindingsSection key them.
function renderScanPageWith<T>(useMutationUnderTest: () => T) {
  const findings = vi.fn().mockResolvedValue({ total: 1 })
  const waivedProbe = vi.fn().mockResolvedValue({ total: 0 })
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  const wrapper = ({ children }: { children: ReactNode }) => <QueryClientProvider client={client}>{children}</QueryClientProvider>
  const { result } = renderHook(
    () => {
      useQuery({ queryKey: ['findings', SCAN_ID, 'security', '', 'severity', 'desc'], queryFn: findings })
      useQuery({ queryKey: ['waived-findings-probe', SCAN_ID, 'security', undefined], queryFn: waivedProbe })
      return useMutationUnderTest()
    },
    { wrapper },
  )
  return { result, findings, waivedProbe }
}

describe('waiver mutations', () => {
  it('refetch the findings table and the waived-findings probe after a waiver is created', async () => {
    const { result, findings, waivedProbe } = renderScanPageWith(useCreateWaiver)
    await waitFor(() => expect(findings).toHaveBeenCalledTimes(1))

    act(() => result.current.mutate({ project_id: 'p1', scan_id: SCAN_ID, finding_id: 'f1', reason: 'accepted' }))

    await waitFor(() => expect(waiverApi.create).toHaveBeenCalled())
    await waitFor(() => expect(findings).toHaveBeenCalledTimes(2))
    await waitFor(() => expect(waivedProbe).toHaveBeenCalledTimes(2))
  })

  it('refetch both after a waiver is deleted', async () => {
    const { result, findings, waivedProbe } = renderScanPageWith(useDeleteWaiver)
    await waitFor(() => expect(findings).toHaveBeenCalledTimes(1))

    act(() => result.current.mutate('w1'))

    await waitFor(() => expect(findings).toHaveBeenCalledTimes(2))
    await waitFor(() => expect(waivedProbe).toHaveBeenCalledTimes(2))
  })
})
