import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import { InventoryStatCards } from '../InventoryStatCards'

const stats = {
  scan: { scan_id: 's1', branch: 'main', created_at: '2026-08-10T12:00:00Z', commit_hash: 'abcdef1234' },
  components_total: 42, direct_count: 10, transitive_count: 32,
  license_count: 7, ecosystem_count: 1, crypto_asset_count: 3,
}

describe('InventoryStatCards', () => {
  it('describes the ecosystem count like the license count, without naming ecosystems the scan may not have', () => {
    render(<InventoryStatCards stats={stats} isLoading={false} />)

    expect(screen.getByText('Distinct ecosystems, unknown included')).toBeInTheDocument()
    expect(screen.queryByText(/npm|pypi|maven/)).not.toBeInTheDocument()
  })
})
