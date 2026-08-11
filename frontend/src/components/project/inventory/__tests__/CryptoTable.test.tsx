import { cleanup, render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { CryptoTable } from '../CryptoTable'
import * as inventoryApiModule from '@/api/inventory'
import * as downloadModule from '@/lib/download'

vi.mock('@/api/inventory')
vi.mock('@/lib/download')

const page = {
  scan: { scan_id: 's1', branch: 'main', created_at: '2026-08-10T12:00:00Z' },
  items: [
    { name: 'TLS handshake', asset_type: 'protocol', primitive: 'RSA', variant: 'RSA-2048', key_size_bits: 2048, location_count: 3, locations: ['a.py:10', 'b.py:20', 'c.py:30'] },
    { name: 'hash.py:5', asset_type: 'algorithm', primitive: 'MD5', variant: null, key_size_bits: null, location_count: 1, locations: ['hash.py:5'] },
  ],
  total: 2, page: 1, page_size: 25,
}

function renderTable() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <CryptoTable projectId="p1" projectName="proj" branch="main" />
    </QueryClientProvider>,
  )
}

describe('CryptoTable', () => {
  afterEach(() => { cleanup(); vi.clearAllMocks() })

  it('renders crypto asset rows with primitive and location count', async () => {
    vi.mocked(inventoryApiModule.inventoryApi.getCrypto).mockResolvedValue(page)
    renderTable()
    await waitFor(() => expect(screen.getByText('TLS handshake')).toBeInTheDocument())
    expect(screen.getByText('RSA')).toBeInTheDocument()
    expect(screen.getByText('3')).toBeInTheDocument()
  })

  it('triggers a CSV download for the selected branch', async () => {
    vi.mocked(inventoryApiModule.inventoryApi.getCrypto).mockResolvedValue(page)
    renderTable()
    await waitFor(() => expect(screen.getByText('TLS handshake')).toBeInTheDocument())

    fireEvent.click(screen.getByRole('button', { name: /download csv/i }))

    await waitFor(() => expect(downloadModule.downloadFile).toHaveBeenCalled())
    const [, filename] = vi.mocked(downloadModule.downloadFile).mock.calls[0]
    expect(filename).toMatch(/proj_crypto_main_\d{4}-\d{2}-\d{2}\.csv/)
  })

  it('shows an error row with a retry button when loading fails', async () => {
    vi.mocked(inventoryApiModule.inventoryApi.getCrypto).mockRejectedValue(
      Object.assign(new Error('not found'), { response: { status: 404 } }),
    )
    renderTable()

    await waitFor(() => expect(screen.getByText('Failed to load crypto assets.')).toBeInTheDocument())
    expect(screen.queryByText(/no cryptographic assets found/i)).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: /retry/i })).toBeInTheDocument()
  })

  it('reloads the table when Retry is clicked after a failure', async () => {
    vi.mocked(inventoryApiModule.inventoryApi.getCrypto)
      .mockRejectedValueOnce(Object.assign(new Error('not found'), { response: { status: 404 } }))
      .mockResolvedValueOnce(page)
    renderTable()
    await waitFor(() => expect(screen.getByText('Failed to load crypto assets.')).toBeInTheDocument())

    fireEvent.click(screen.getByRole('button', { name: /retry/i }))

    await waitFor(() => expect(screen.getByText('TLS handshake')).toBeInTheDocument())
  })
})
