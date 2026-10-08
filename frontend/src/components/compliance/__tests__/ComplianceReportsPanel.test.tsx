import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { createReport, listReports } from '@/api/compliance'
import type { ComplianceReportMeta, ReportStatus } from '@/types/compliance'

import { ComplianceReportsPanel } from '../ComplianceReportsPanel'

vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
vi.mock('@/api/compliance', () => ({
  listReports: vi.fn(),
  createReport: vi.fn(),
  deleteReport: vi.fn(),
  downloadReport: vi.fn(),
}))
vi.mock('@/context/useAuth', () => ({ useAuth: () => ({ hasPermission: () => false }) }))

function report(status: ReportStatus): ComplianceReportMeta {
  return {
    _id: 'r1', scope: 'user', scope_id: null, framework: 'nist-sp-800-131a', format: 'pdf', status,
    requested_by: 'lena', requested_at: '2026-10-06T09:00:00Z', completed_at: null, artifact_filename: null,
    artifact_size_bytes: null, artifact_mime_type: null, summary: {}, error_message: null, expires_at: null,
  }
}

function renderPanel(props: Parameters<typeof ComplianceReportsPanel>[0] = {}) {
  render(
    <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
      <ComplianceReportsPanel {...props} />
    </QueryClientProvider>,
  )
}

beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(createReport).mockResolvedValue({ report_id: 'r2', status: 'pending' })
})

describe('ComplianceReportsPanel', () => {
  afterEach(() => vi.useRealTimers())

  it('updates the open report when its generation finishes', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    vi.mocked(listReports)
      .mockResolvedValueOnce({ reports: [report('generating')] })
      .mockResolvedValue({ reports: [report('completed')] })
    renderPanel()

    fireEvent.click(await screen.findByRole('button', { name: /nist-sp-800-131a/ }))
    expect(within(screen.getByRole('dialog')).getByText('Generating…')).toBeInTheDocument()
    await act(() => vi.advanceTimersByTimeAsync(3_000))

    await waitFor(() => expect(within(screen.getByRole('dialog')).getByText('Completed')).toBeInTheDocument())
  })

  it('queues the framework another tab handed over, and lets go of it once used', async () => {
    vi.mocked(listReports).mockResolvedValue({ reports: [] })
    const onPrefillUsed = vi.fn()
    renderPanel({ prefillFramework: 'pqc-migration-plan', onPrefillUsed })

    fireEvent.click(screen.getByRole('button', { name: 'Generate' }))

    await waitFor(() => expect(createReport).toHaveBeenCalledWith(expect.objectContaining({ framework: 'pqc-migration-plan' })))
    await waitFor(() => expect(onPrefillUsed).toHaveBeenCalled())
  })

  it('lists project, team and global reports too, not only personal ones', async () => {
    vi.mocked(listReports).mockResolvedValue({ reports: [] })
    renderPanel()
    await screen.findByText('No reports yet')

    expect(listReports).toHaveBeenCalledWith({ limit: 50 })
  })

  it('opens an empty form again after a cancelled draft', async () => {
    vi.mocked(listReports).mockResolvedValue({ reports: [] })
    renderPanel()
    await screen.findByText('No reports yet')

    fireEvent.click(screen.getByRole('button', { name: 'Generate report' }))
    fireEvent.change(screen.getByRole('textbox'), { target: { value: 'draft for Q3' } })
    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    fireEvent.click(screen.getByRole('button', { name: 'Generate report' }))

    expect(screen.getByRole('textbox')).toHaveValue('')
  })
})
