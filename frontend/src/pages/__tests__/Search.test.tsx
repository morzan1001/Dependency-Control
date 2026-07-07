import { render, screen } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import { MemoryRouter, Routes, Route } from 'react-router-dom'

import SearchPage from '../Search'

describe('SearchPage', () => {
  it('redirects /search/dependencies to /analytics', () => {
    render(
      <MemoryRouter initialEntries={['/search/dependencies']}>
        <Routes>
          <Route path="/search/dependencies" element={<SearchPage />} />
          <Route path="/analytics" element={<div>Analytics Page</div>} />
        </Routes>
      </MemoryRouter>,
    )

    expect(screen.getByText('Analytics Page')).toBeInTheDocument()
  })
})
