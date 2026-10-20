import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { InventoryStatCards } from '../InventoryStatCards'
import type { InventoryStats } from '@/types/inventory'

const stats: InventoryStats = {
  scan: { scan_id: 's1', branch: 'main', created_at: '2026-08-10T12:00:00Z' },
  components_total: 3, direct_count: 2, transitive_count: 1,
  license_count: 2, ecosystem_count: 1, ecosystems: ['npm'], crypto_asset_count: 0, cbom_evaluated: true,
}

function cryptoTile() {
  return screen.getByText('Crypto Assets').closest('.rounded-lg') as HTMLElement
}

describe('InventoryStatCards crypto tile', () => {
  it('counts the assets of a scan that has them', () => {
    render(<InventoryStatCards stats={{ ...stats, crypto_asset_count: 4 }} isLoading={false} />)

    expect(cryptoTile()).toHaveTextContent('4')
    expect(cryptoTile()).toHaveTextContent('Algorithms, certificates, protocols')
  })

  it('reports a scan whose CBOM listed no asset as free of cryptography', () => {
    render(<InventoryStatCards stats={stats} isLoading={false} />)

    expect(cryptoTile()).toHaveTextContent('0')
    expect(cryptoTile()).toHaveTextContent('No cryptography found in the latest CBOM')
  })

  it('counts nothing for a scan without a CBOM and says so', () => {
    render(<InventoryStatCards stats={{ ...stats, cbom_evaluated: false }} isLoading={false} />)

    expect(cryptoTile()).toHaveTextContent('—')
    expect(cryptoTile()).not.toHaveTextContent('0')
    expect(cryptoTile()).toHaveTextContent('No CBOM uploaded for the latest scan')
  })
})

describe('InventoryStatCards ecosystems tile', () => {
  function ecosystemsTile() {
    return screen.getByText('Ecosystems').closest('.rounded-lg') as HTMLElement
  }

  it('names the ecosystems of a scan like the Package Types tile names its types', () => {
    render(<InventoryStatCards stats={{ ...stats, ecosystem_count: 2, ecosystems: ['npm', 'unknown'] }} isLoading={false} />)

    expect(ecosystemsTile()).toHaveTextContent('npm, unknown')
    expect(ecosystemsTile()).not.toHaveTextContent('…')
  })

  it('names the first three ecosystems and marks that there are more', () => {
    const ecosystems = ['npm', 'pypi', 'maven', 'golang']
    render(<InventoryStatCards stats={{ ...stats, ecosystem_count: 4, ecosystems }} isLoading={false} />)

    expect(ecosystemsTile()).toHaveTextContent('npm, pypi, maven, …')
    expect(ecosystemsTile()).not.toHaveTextContent('golang')
  })

  it('describes the count like the license count when the scan names no ecosystem', () => {
    render(<InventoryStatCards stats={{ ...stats, ecosystem_count: 0, ecosystems: [] }} isLoading={false} />)

    expect(ecosystemsTile()).toHaveTextContent('Distinct ecosystems, unknown included')
  })
})
