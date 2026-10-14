import { render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cloneElement, type ReactElement } from 'react'
import { describe, expect, it, vi } from 'vitest'

import type { ScanWithReleases } from '@/types/scan'

import { ProjectOverview } from '../ProjectOverview'

const SCAN: ScanWithReleases = {
  id: 's-main',
  project_id: 'p1',
  branch: 'main',
  status: 'completed',
  is_rescan: false,
  is_release: false,
  releases: [],
  created_at: '2026-07-01T00:00:00Z',
  stats: { critical: 1, high: 2, medium: 3, low: 4 },
}

vi.mock('recharts', async (importOriginal) => {
  const recharts = await importOriginal<typeof import('recharts')>()
  return {
    ...recharts,
    // jsdom lays nothing out, so the chart gets the size a browser would measure.
    ResponsiveContainer: ({ children }: { children: ReactElement<{ width?: number; height?: number }> }) =>
      cloneElement(children, { width: 600, height: 300 }),
  }
})
vi.mock('@/api/scans')
vi.mock('@/hooks/queries/use-scans', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/hooks/queries/use-scans')>()),
  useProjectScans: () => ({ data: [SCAN], isLoading: false }),
  useProjectBranchTips: () => ({ data: { branches: [{ branch: 'main', scan_count: 1, tip: SCAN }] }, isLoading: false }),
  useScan: () => ({ data: SCAN }),
  useScanResults: () => ({ data: [] }),
}))
vi.mock('@/hooks/queries/use-releases', () => ({
  useLatestProjectRelease: () => ({ latestRelease: undefined, hasReleases: false, isLoading: false }),
}))
vi.mock('@/hooks/queries/use-waivers', () => ({ useWaiverList: () => ({ data: undefined }) }))
vi.mock('react-router-dom', () => ({ useNavigate: () => vi.fn() }))

async function legendOf(title: string) {
  const card = screen.getByText(title).closest('.bg-card') as HTMLElement
  await waitFor(() => expect(card.querySelectorAll('.recharts-legend-item-text').length).toBeGreaterThan(0))
  return [...card.querySelectorAll('.recharts-legend-item-text')].map((item) => item.textContent)
}

describe('ProjectOverview severity legends', () => {
  it('list the severities most severe first, in the app\'s severity order', async () => {
    render(
      <QueryClientProvider client={new QueryClient()}>
        <ProjectOverview projectId="p1" selectedBranches={['main']} />
      </QueryClientProvider>,
    )

    expect(await legendOf('Severity Distribution')).toEqual(['Critical', 'High', 'Medium', 'Low'])
    expect(await legendOf('Severity Distribution by Branch')).toEqual(['Critical', 'High', 'Medium', 'Low'])
  })
})
