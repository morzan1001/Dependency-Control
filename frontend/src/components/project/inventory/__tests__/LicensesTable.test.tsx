import { cleanup, render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { LicensesTable } from '../LicensesTable'
import * as inventoryApiModule from '@/api/inventory'
import * as downloadModule from '@/lib/download'

vi.mock('@/api/inventory')
vi.mock('@/lib/download')

const payload = {
  scan: { scan_id: 's1', branch: 'main', created_at: '2026-08-10T12:00:00Z' },
  items: [
    { license: 'MIT', category: 'permissive', risks: [], component_count: 12, components: ['a@1', 'b@2'] },
    { license: 'GPL-3.0-only', category: 'strong_copyleft', risks: ['copyleft obligations'], component_count: 1, components: ['c@3'] },
  ],
}

function renderTable() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <LicensesTable projectId="p1" projectName="proj" branch="main" />
    </QueryClientProvider>,
  )
}

describe('LicensesTable', () => {
  afterEach(() => { cleanup(); vi.clearAllMocks() })

  it('renders license rows with category badge and risks', async () => {
    vi.mocked(inventoryApiModule.inventoryApi.getLicenses).mockResolvedValue(payload)
    renderTable()
    await waitFor(() => expect(screen.getByText('GPL-3.0-only')).toBeInTheDocument())
    expect(screen.getByText('strong copyleft')).toBeInTheDocument()
    expect(screen.getByText('copyleft obligations')).toBeInTheDocument()
    expect(screen.getByText('12')).toBeInTheDocument()
  })

  it('triggers a CSV download for the selected branch', async () => {
    vi.mocked(inventoryApiModule.inventoryApi.getLicenses).mockResolvedValue(payload)
    renderTable()
    await waitFor(() => expect(screen.getByText('MIT')).toBeInTheDocument())

    fireEvent.click(screen.getByRole('button', { name: /download csv/i }))

    await waitFor(() => expect(downloadModule.downloadFile).toHaveBeenCalled())
    const [, filename] = vi.mocked(downloadModule.downloadFile).mock.calls[0]
    expect(filename).toMatch(/proj_licenses_main_\d{4}-\d{2}-\d{2}\.csv/)
  })
})
