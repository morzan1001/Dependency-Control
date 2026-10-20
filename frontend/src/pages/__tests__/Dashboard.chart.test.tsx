import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { cloneElement, type ReactElement } from 'react'
import { describe, expect, it, vi } from 'vitest'

import { expectLabelsOnTheirTicks, measureChartText } from '@/test/chart-axis'

import Dashboard from '../Dashboard'

measureChartText()

const LONG_NAME = 'identity-and-access-management-gateway'

const { chart } = vi.hoisted(() => ({
  chart: {
    projects: [
      { id: 'p1', name: 'identity-and-access-management-gateway', risk: 80 },
      { id: 'p2', name: 'search', risk: 40 },
      { id: 'p3', name: 'aufstrg/tm/app', risk: 30 },
      { id: 'p4', name: 'aufstrg/tm/web', risk: 20 },
    ],
  },
}))

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
      top_risky_projects: chart.projects,
    },
    isLoading: false,
  }),
}))
vi.mock('@/hooks/queries/use-scans', () => ({ useRecentScans: () => ({ data: [], isLoading: false }) }))
vi.mock('@/hooks/queries/use-projects', () => ({
  useProjects: () => ({ data: undefined, isLoading: false }),
  useProjectDetails: (ids: readonly string[]) =>
    ids.map((id) => ({ id, name: 'checkout-service', teams: [{ id: `t-${id}`, name: id === 'c1' ? 'Retail' : 'Payments' }] })),
}))
vi.mock('@/hooks/queries/use-instances', () => ({ useInstanceNames: () => new Map() }))
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

  it('draws the top risk label on its grid line, level with a bar that reaches it', async () => {
    const { container } = render(<Dashboard />)

    await waitFor(() => expect(screen.getByText('search')).toBeInTheDocument())
    expectLabelsOnTheirTicks(container, 'y')
  })

  it('names the owner and the risk of each bar whose project name another bar shares in its tooltip', async () => {
    const saved = chart.projects
    chart.projects = [
      { id: 'c1', name: 'checkout-service', risk: 80 },
      { id: 'c2', name: 'checkout-service', risk: 60 },
      { id: 's1', name: 'search', risk: 40 },
    ]
    try {
      const { container } = render(<Dashboard />)
      await waitFor(() => expect(container.querySelector('.recharts-wrapper')).not.toBeNull())

      fireEvent.focus(container.querySelector('.recharts-wrapper')!)

      expect(await screen.findByText('Retail')).toBeInTheDocument()
      expect(screen.queryByText('Payments')).not.toBeInTheDocument()

      fireEvent.keyDown(container.querySelector('.recharts-wrapper')!, { key: 'ArrowRight' })

      expect(await screen.findByText('Payments')).toBeInTheDocument()
      expect(container.querySelector('.recharts-tooltip-item-value')).toHaveTextContent('60')
    } finally {
      chart.projects = saved
    }
  })
})
