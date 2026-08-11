// Force a non-UTC timezone so date parsing is exercised in local time.
process.env.TZ = 'America/New_York'

import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { describe, it, expect, vi, afterEach } from 'vitest'
import { DeltaHeader } from '../DeltaHeader'
import * as scansApi from '@/api/scans'
import { useProjectScans } from '@/hooks/queries/use-scans'

vi.mock('@/api/scans')
vi.mock('@/hooks/queries/use-scans')

// 'rescan-1' is a rescan the project-scans hook excludes from its option list.
const rescan = { id: 'rescan-1', project_id: 'p1', branch: 'feature-x', status: 'completed', created_at: '2026-08-10T12:00:00Z' }
const toScan = { id: 'b', project_id: 'p1', branch: 'main', status: 'completed', created_at: '2026-08-09T12:00:00Z' }

function getOne(id: string) {
  if (id === rescan.id) return Promise.resolve(rescan)
  if (id === toScan.id) return Promise.resolve(toScan)
  return Promise.reject(new Error(`unexpected scan id ${id}`))
}

function renderHeader(onChange = vi.fn()) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  render(
    <QueryClientProvider client={qc}>
      <DeltaHeader projectId="p1" fromScanId="rescan-1" toScanId="b" onChange={onChange} />
    </QueryClientProvider>,
  )
  return { onChange }
}

describe('DeltaHeader', () => {
  afterEach(() => vi.clearAllMocks())

  it("shows the compared scan's label on the From side even though it is excluded from the pickable options", async () => {
    vi.mocked(scansApi.scanApi.getOne).mockImplementation(getOne)
    vi.mocked(useProjectScans).mockReturnValue({
      data: [toScan],
    } as unknown as ReturnType<typeof useProjectScans>)

    renderHeader()

    const [fromTrigger] = screen.getAllByRole('combobox')
    await waitFor(() => expect(fromTrigger).toHaveTextContent(/feature-x/))
  })

  it('swaps the pair when the swap button is clicked', () => {
    vi.mocked(scansApi.scanApi.getOne).mockImplementation(getOne)
    vi.mocked(useProjectScans).mockReturnValue({
      data: [toScan],
    } as unknown as ReturnType<typeof useProjectScans>)

    const { onChange } = renderHeader()

    fireEvent.click(screen.getByLabelText('Swap scans'))

    expect(onChange).toHaveBeenCalledWith('b', 'rescan-1')
  })
})
