import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cloneElement, type ReactElement } from 'react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

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

const LONG_BRANCH = 'feature/PAY-4821-checkout-redesign'
const { branchTips } = vi.hoisted(() => ({
  branchTips: { current: [] as { branch: string; scan_count: number; tip: ScanWithReleases }[] },
}))

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
  useProjectBranchTips: () => ({ data: { branches: branchTips.current }, isLoading: false }),
  useScan: () => ({ data: SCAN }),
  useScanResults: () => ({ data: [] }),
}))
vi.mock('@/hooks/queries/use-releases', () => ({
  useLatestProjectRelease: () => ({ latestRelease: undefined, hasReleases: false, isLoading: false }),
}))
vi.mock('@/hooks/queries/use-waivers', () => ({ useWaiverList: () => ({ data: undefined }) }))
vi.mock('react-router-dom', () => ({ useNavigate: () => vi.fn() }))

beforeEach(() => {
  branchTips.current = [{ branch: 'main', scan_count: 1, tip: SCAN }]
})

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

describe('ProjectOverview trend legend', () => {
  it('lists the branches in the order their lines are coloured, not alphabetically', async () => {
    render(
      <QueryClientProvider client={new QueryClient()}>
        <ProjectOverview projectId="p1" selectedBranches={['main', 'develop']} />
      </QueryClientProvider>,
    )

    expect(await legendOf('Vulnerability Trends')).toEqual(['main', 'develop'])
  })
})

describe('ProjectOverview branch chart', () => {
  it('shortens a long branch name under its bars and names it in full in the tooltip', async () => {
    branchTips.current = [{ branch: LONG_BRANCH, scan_count: 1, tip: { ...SCAN, id: 's-long', branch: LONG_BRANCH } }]
    render(
      <QueryClientProvider client={new QueryClient()}>
        <ProjectOverview projectId="p1" selectedBranches={[LONG_BRANCH]} />
      </QueryClientProvider>,
    )

    const card = screen.getByText('Severity Distribution by Branch').closest('.bg-card') as HTMLElement
    expect(await within(card).findByText('feature/PAY-4821-che…')).toBeInTheDocument()
    expect(within(card).queryByText(LONG_BRANCH)).not.toBeInTheDocument()

    fireEvent.focus(card.querySelector('.recharts-wrapper')!)

    expect(await within(card).findByText(LONG_BRANCH)).toBeInTheDocument()
  })
})
