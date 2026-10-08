import { fireEvent, render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import type { Finding } from '@/types/scan'
import { WaiverForm } from '../WaiverForm'

const mutate = vi.fn()

vi.mock('@/hooks/queries/use-waivers', () => ({
  useCreateWaiver: () => ({ mutate, isPending: false }),
  waiverKeys: { project: (projectId: string) => ['waivers', 'project', projectId] },
}))
vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))

function finding(type: 'sast' | 'iac', details: Record<string, unknown>): Finding {
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

function waiveForTheWholeProject(target: Finding) {
  render(
    <QueryClientProvider client={new QueryClient()}>
      <WaiverForm finding={target} vulnId={null} projectId="p1" onCancel={() => {}} onSuccess={() => {}} />
    </QueryClientProvider>,
  )
  fireEvent.click(screen.getByRole('radio', { name: 'All occurrences in project' }))
  fireEvent.change(screen.getByPlaceholderText(/Why is this finding being ignored/), {
    target: { value: 'reviewed' },
  })
  fireEvent.click(screen.getByRole('button', { name: 'Confirm Waiver' }))
  return mutate.mock.calls[0][0]
}

describe('WaiverForm rule scope', () => {
  beforeEach(() => mutate.mockReset())

  it('offers a stored SAST finding rule scope and sends the rule of its scanner entry', () => {
    // The persisted shape: the scanner's own details sit under sast_findings, the wrapper keeps only file and line.
    const sast = finding('sast', {
      file: 'app/handlers.py',
      line: 12,
      sast_findings: [{ id: 'python.eval', scanner: 'opengrep', severity: 'HIGH', details: { rule_id: 'python.eval' } }],
    })

    expect(waiveForTheWholeProject(sast)).toMatchObject({ scope: 'rule', rule_id: 'python.eval' })
  })

  it('offers an IaC finding rule scope from its own rule id', () => {
    expect(waiveForTheWholeProject(finding('iac', { rule_id: 'kics-1' }))).toMatchObject({
      scope: 'rule',
      rule_id: 'kics-1',
    })
  })
})
