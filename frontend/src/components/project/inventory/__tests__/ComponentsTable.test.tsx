import { cleanup, render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { ComponentsTable } from '../ComponentsTable'
import * as inventoryApiModule from '@/api/inventory'
import * as downloadModule from '@/lib/download'

vi.mock('@/api/inventory')
vi.mock('@/lib/download')

const page = {
  scan: { scan_id: 's1', branch: 'main', created_at: '2026-08-10T12:00:00Z' },
  items: [
    { name: 'lodash', version: '4.17.20', latest_version: '4.17.21', ecosystem: 'npm',
      license: 'MIT', license_category: 'permissive', direct: true, eol: false, outdated: true, purl: 'pkg:npm/lodash@4.17.20' },
    { name: 'leftpad', version: '0.9.0', latest_version: null, ecosystem: 'npm',
      license: null, license_category: null, direct: false, eol: true, outdated: false, purl: null },
  ],
  total: 2, page: 1, page_size: 25,
}

function renderTable() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <ComponentsTable projectId="p1" projectName="proj" branch="main" />
    </QueryClientProvider>,
  )
}

describe('ComponentsTable', () => {
  afterEach(() => { cleanup(); vi.clearAllMocks() })

  it('renders lifecycle badges per component', async () => {
    vi.mocked(inventoryApiModule.inventoryApi.getComponents).mockResolvedValue(page)
    renderTable()
    await waitFor(() => expect(screen.getByText('lodash')).toBeInTheDocument())
    expect(screen.getByText('Outdated')).toBeInTheDocument()
    expect(screen.getByText('EOL')).toBeInTheDocument()
    expect(screen.getByText('4.17.21')).toBeInTheDocument()
  })

  it('triggers a CSV download for the selected branch', async () => {
    vi.mocked(inventoryApiModule.inventoryApi.getComponents).mockResolvedValue(page)
    renderTable()
    await waitFor(() => expect(screen.getByText('lodash')).toBeInTheDocument())

    fireEvent.click(screen.getByRole('button', { name: /download csv/i }))

    await waitFor(() => expect(downloadModule.downloadFile).toHaveBeenCalled())
    const [, filename] = vi.mocked(downloadModule.downloadFile).mock.calls[0]
    expect(filename).toMatch(/proj_components_main_\d{4}-\d{2}-\d{2}\.csv/)
  })

  it('shows an error row with a retry button when loading fails', async () => {
    vi.mocked(inventoryApiModule.inventoryApi.getComponents).mockRejectedValue(
      Object.assign(new Error('not found'), { response: { status: 404 } }),
    )
    renderTable()

    await waitFor(() => expect(screen.getByText('Failed to load components.')).toBeInTheDocument())
    expect(screen.queryByText(/no components found/i)).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: /retry/i })).toBeInTheDocument()
  })

  it('reloads the table when Retry is clicked after a failure', async () => {
    vi.mocked(inventoryApiModule.inventoryApi.getComponents)
      .mockRejectedValueOnce(Object.assign(new Error('not found'), { response: { status: 404 } }))
      .mockResolvedValueOnce(page)
    renderTable()
    await waitFor(() => expect(screen.getByText('Failed to load components.')).toBeInTheDocument())

    fireEvent.click(screen.getByRole('button', { name: /retry/i }))

    await waitFor(() => expect(screen.getByText('lodash')).toBeInTheDocument())
  })
})
