import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { cloneElement, type ReactElement } from 'react'
import { describe, expect, it, vi } from 'vitest'

import Dashboard from '../Dashboard'

const LONG_NAME = 'identity-and-access-management-gateway'

vi.mock('recharts', async (importOriginal) => ({
  ...(await importOriginal<typeof import('recharts')>()),
  // jsdom lays nothing out, so the chart gets the size a browser would measure.
  ResponsiveContainer: ({ children }: { children: ReactElement<{ width?: number; height?: number }> }) =>
    cloneElement(children, { width: 600, height: 300 }),
}))
vi.mock('@/hooks/queries/use-analytics', () => ({
  useDashboardStats: () => ({
    data: {
      total_projects: 2,
      total_critical: 0,
      total_high: 0,
      avg_risk_score: 0,
      top_risky_projects: [
        { id: 'p1', name: LONG_NAME, risk: 80 },
        { id: 'p2', name: 'search', risk: 40 },
        { id: 'p3', name: 'aufstrg/tm/app', risk: 30 },
        { id: 'p4', name: 'aufstrg/tm/web', risk: 20 },
      ],
    },
    isLoading: false,
  }),
}))
vi.mock('@/hooks/queries/use-scans', () => ({ useRecentScans: () => ({ data: [], isLoading: false }) }))
vi.mock('@/hooks/queries/use-projects', () => ({ useProjects: () => ({ data: undefined, isLoading: false }) }))
vi.mock('react-router-dom', () => ({ useNavigate: () => vi.fn() }))

describe('Dashboard riskiest projects chart', () => {
  it('shortens a long project name under its bar and names it in full in the tooltip', async () => {
    const { container } = render(<Dashboard />)

    await waitFor(() => expect(screen.getByText('search')).toBeInTheDocument())
    expect(screen.getByText('…ent-gateway')).toBeInTheDocument()
    expect(screen.queryByText(LONG_NAME)).not.toBeInTheDocument()

    fireEvent.focus(container.querySelector('.recharts-wrapper')!)

    expect(await screen.findByText(LONG_NAME)).toBeInTheDocument()
  })

  it('names two projects of one group apart under their bars by the ends of their paths', async () => {
    const { container } = render(<Dashboard />)

    await waitFor(() => expect(screen.getByText('search')).toBeInTheDocument())
    const ticks = [...container.querySelectorAll('.recharts-xAxis-tick-labels text')].map((tick) => tick.textContent)
    expect(ticks).toEqual(['…ent-gateway', 'search', '…strg/tm/app', '…strg/tm/web'])
  })
})
