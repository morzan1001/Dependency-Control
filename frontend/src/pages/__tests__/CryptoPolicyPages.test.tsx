import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { getEffectivePolicy, getSystemPolicy, putProjectPolicy, putSystemPolicy } from '@/api/cryptoPolicy'
import { listProjectAudit, listSystemAudit, revertProjectPolicy, revertSystemPolicy } from '@/api/policyAudit'
import type { PolicyAuditEntry } from '@/types/policyAudit'

import { CryptoPolicyPage } from '../admin/CryptoPolicyPage'
import { CryptoPolicyOverridePage } from '../project/CryptoPolicyOverridePage'

vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }))
vi.mock('@/api/cryptoPolicy', () => ({
  getSystemPolicy: vi.fn(),
  putSystemPolicy: vi.fn(),
  getEffectivePolicy: vi.fn(),
  putProjectPolicy: vi.fn(),
  deleteProjectPolicy: vi.fn(),
}))
vi.mock('@/api/policyAudit', () => ({
  listSystemAudit: vi.fn(),
  listProjectAudit: vi.fn(),
  revertSystemPolicy: vi.fn(),
  revertProjectPolicy: vi.fn(),
  pruneSystemAudit: vi.fn(),
  pruneProjectAudit: vi.fn(),
}))

const PROJECT_ID = 'p1'

function auditEntry(scope: 'system' | 'project'): PolicyAuditEntry {
  return {
    _id: `${scope}-v1`, policy_scope: scope, project_id: scope === 'project' ? PROJECT_ID : null, version: 1,
    action: 'update', actor_user_id: 'u1', actor_display_name: 'alice', timestamp: '2026-10-01T10:00:00Z',
    snapshot: {}, change_summary: 'Added 1 rule', comment: null, reverted_from_version: null,
  }
}

function renderWithClient(ui: React.ReactElement) {
  render(<QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>{ui}</QueryClientProvider>)
}

async function revertFirstEntry() {
  fireEvent.click(await screen.findByTitle('Revert to this version'))
  fireEvent.change(screen.getByRole('textbox'), { target: { value: 'back to v1' } })
  fireEvent.click(screen.getByRole('button', { name: 'Confirm revert' }))
}

beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(getSystemPolicy).mockResolvedValue({ scope: 'system', rules: [], version: 2 })
  vi.mocked(putSystemPolicy).mockResolvedValue({ scope: 'system', rules: [], version: 3 })
  vi.mocked(getEffectivePolicy).mockResolvedValue({
    system_version: 2, override_version: 1, override_locked: false, rules: [], system_rules: [],
  })
  vi.mocked(putProjectPolicy).mockResolvedValue({ scope: 'project', rules: [], version: 2 })
  vi.mocked(listSystemAudit).mockResolvedValue({ entries: [auditEntry('system')] })
  vi.mocked(listProjectAudit).mockResolvedValue({ entries: [auditEntry('project')] })
  vi.mocked(revertSystemPolicy).mockResolvedValue(undefined)
  vi.mocked(revertProjectPolicy).mockResolvedValue(undefined)
})

describe('system crypto policy', () => {
  it('reloads the rules in the editor after a revert from the history', async () => {
    renderWithClient(<CryptoPolicyPage />)
    await revertFirstEntry()

    await waitFor(() => expect(revertSystemPolicy).toHaveBeenCalled())
    await waitFor(() => expect(getSystemPolicy).toHaveBeenCalledTimes(2))
  })

  it('lists the new version in the history after a save', async () => {
    renderWithClient(<CryptoPolicyPage />)
    fireEvent.click(await screen.findByRole('button', { name: 'Save' }))

    await waitFor(() => expect(putSystemPolicy).toHaveBeenCalled())
    await waitFor(() => expect(listSystemAudit).toHaveBeenCalledTimes(2))
  })
})

describe('project crypto policy override', () => {
  it('reloads the effective rules after a revert from the history', async () => {
    renderWithClient(<CryptoPolicyOverridePage projectId={PROJECT_ID} canEdit />)
    await revertFirstEntry()

    await waitFor(() => expect(revertProjectPolicy).toHaveBeenCalled())
    await waitFor(() => expect(getEffectivePolicy).toHaveBeenCalledTimes(2))
  })

  it('lists the new version in the history after a save', async () => {
    renderWithClient(<CryptoPolicyOverridePage projectId={PROJECT_ID} canEdit />)
    fireEvent.click(await screen.findByRole('button', { name: 'Save' }))

    await waitFor(() => expect(putProjectPolicy).toHaveBeenCalled())
    await waitFor(() => expect(listProjectAudit).toHaveBeenCalledTimes(2))
  })
})
