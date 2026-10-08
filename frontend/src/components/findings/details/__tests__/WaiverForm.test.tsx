import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import type { Finding } from '@/types/scan'
import { useWaiverList } from '@/hooks/queries/use-waivers'
import { WaiverForm } from '../WaiverForm'

vi.mock('@/api/waivers', () => ({
  waiverApi: {
    getAll: vi.fn(async () => ({ items: [], total: 0, page: 1, size: 50, pages: 1 })),
    create: vi.fn(async () => ({})),
  },
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

import { waiverApi } from '@/api/waivers'

function finding(type: 'vulnerability' | 'sast' | 'iac', details: Record<string, unknown>): Finding {
  return {
    id: `${type}-finding`,
    type,
    severity: 'HIGH',
    component: 'app/handlers.py',
    version: '',
    description: 'eval() detected',
    scanners: ['opengrep'],
    found_in: [],
    aliases: [],
    waived: false,
    details,
  } as unknown as Finding
}

function confirmWaiver(reason: string) {
  fireEvent.change(screen.getByPlaceholderText(/Why is this finding being ignored/), { target: { value: reason } })
  fireEvent.click(screen.getByRole('button', { name: 'Confirm Waiver' }))
}

async function waiveForTheWholeProject(target: Finding) {
  render(
    <QueryClientProvider client={new QueryClient()}>
      <WaiverForm finding={target} vulnId={null} projectId="p1" onCancel={() => {}} onSuccess={() => {}} />
    </QueryClientProvider>,
  )
  fireEvent.click(screen.getByRole('radio', { name: 'All occurrences in project' }))
  confirmWaiver('reviewed')
  await waitFor(() => expect(waiverApi.create).toHaveBeenCalled())
  return vi.mocked(waiverApi.create).mock.calls[0][0]
}

function OpenWaiverList() {
  useWaiverList('p1')
  return null
}

describe('WaiverForm', () => {
  beforeEach(() => vi.clearAllMocks())

  it('offers a stored SAST finding rule scope and sends the rule of its scanner entry', async () => {
    // The persisted shape: the scanner's own details sit under sast_findings, the wrapper keeps only file and line.
    const sast = finding('sast', {
      file: 'app/handlers.py',
      line: 12,
      sast_findings: [{ id: 'python.eval', scanner: 'opengrep', severity: 'HIGH', details: { rule_id: 'python.eval' } }],
    })

    expect(await waiveForTheWholeProject(sast)).toMatchObject({ scope: 'rule', rule_id: 'python.eval' })
  })

  it('offers an IaC finding rule scope from its own rule id', async () => {
    expect(await waiveForTheWholeProject(finding('iac', { rule_id: 'kics-1' }))).toMatchObject({
      scope: 'rule',
      rule_id: 'kics-1',
    })
  })

  it("refetches the project's open waiver list once after the waiver is created", async () => {
    const onSuccess = vi.fn()
    const client = new QueryClient({ defaultOptions: { queries: { retry: false } } })
    render(
      <QueryClientProvider client={client}>
        <OpenWaiverList />
        <WaiverForm
          finding={finding('vulnerability', {})}
          vulnId={null}
          projectId="p1"
          onCancel={() => {}}
          onSuccess={onSuccess}
        />
      </QueryClientProvider>,
    )
    await waitFor(() => expect(waiverApi.getAll).toHaveBeenCalledTimes(1))

    confirmWaiver('accepted')

    await waitFor(() => expect(onSuccess).toHaveBeenCalled())
    await waitFor(() => expect(client.isFetching()).toBe(0))
    expect(waiverApi.getAll).toHaveBeenCalledTimes(2)
  })
})
