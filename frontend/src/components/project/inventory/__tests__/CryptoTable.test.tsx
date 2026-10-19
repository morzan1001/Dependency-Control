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

function renderTable(cbomEvaluated?: boolean) {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return render(
    <QueryClientProvider client={qc}>
      <CryptoTable projectId="p1" branch="main" cbomEvaluated={cbomEvaluated} />
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

    await waitFor(() => expect(downloadModule.downloadServerFile).toHaveBeenCalled())
    const [fetchFile] = vi.mocked(downloadModule.downloadServerFile).mock.calls[0]
    await fetchFile()
    expect(inventoryApiModule.inventoryApi.exportTable).toHaveBeenCalledWith('p1', 'crypto', 'main')
  })

  it('shows an error row with a retry button when loading fails', async () => {
    vi.mocked(inventoryApiModule.inventoryApi.getCrypto).mockRejectedValue(
      Object.assign(new Error('not found'), { response: { status: 404 } }),
    )
    renderTable()

    await waitFor(() => expect(screen.getByText('Failed to load crypto assets.')).toBeInTheDocument())
    expect(screen.queryByText(/No CBOM|No cryptography/)).not.toBeInTheDocument()
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

  it("stacks Download CSV under the title on a phone, like the waiver list's header", async () => {
    vi.mocked(inventoryApiModule.inventoryApi.getCrypto).mockResolvedValue(page)
    renderTable()
    await waitFor(() => expect(screen.getByText('TLS handshake')).toBeInTheDocument())

    const header = screen.getByRole('heading', { name: 'Cryptography' }).parentElement?.parentElement
    expect(header).toHaveClass('flex-col', 'sm:flex-row', 'sm:items-center', 'sm:justify-between')
    expect(header).toContainElement(screen.getByRole('button', { name: /download csv/i }))
  })

  it("names an empty table under it, where a phone shows the message, instead of in a row centred on the scrolling table", async () => {
    vi.mocked(inventoryApiModule.inventoryApi.getCrypto).mockResolvedValue({ ...page, items: [], total: 0 })
    renderTable(true)

    expect((await screen.findByText('No cryptography found in the latest CBOM.')).closest('table')).toBeNull()
  })

  it('tells a scan without a CBOM from one whose CBOM listed no cryptography', async () => {
    vi.mocked(inventoryApiModule.inventoryApi.getCrypto).mockResolvedValue({ ...page, items: [], total: 0 })
    renderTable(false)

    expect(await screen.findByText('No CBOM uploaded for the latest scan.')).toBeInTheDocument()
    expect(screen.queryByText('No cryptography found in the latest CBOM.')).not.toBeInTheDocument()
  })

  it('names no empty state before it knows whether the scan has a CBOM', async () => {
    vi.mocked(inventoryApiModule.inventoryApi.getCrypto).mockResolvedValue({ ...page, items: [], total: 0 })
    renderTable()

    await waitFor(() => expect(inventoryApiModule.inventoryApi.getCrypto).toHaveBeenCalled())
    expect(screen.queryByText(/No CBOM|No cryptography/)).not.toBeInTheDocument()
  })

  it('shows a failure and its retry under the table the same way', async () => {
    vi.mocked(inventoryApiModule.inventoryApi.getCrypto).mockRejectedValue(
      Object.assign(new Error('not found'), { response: { status: 404 } }),
    )
    renderTable()

    expect((await screen.findByText('Failed to load crypto assets.')).closest('table')).toBeNull()
    expect(screen.getByRole('button', { name: /retry/i }).closest('table')).toBeNull()
  })
})
