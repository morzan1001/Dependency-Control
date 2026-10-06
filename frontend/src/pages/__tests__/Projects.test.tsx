import { render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { describe, it, expect, vi } from 'vitest'

import ProjectsPage from '../Projects'

const VISIBLE_PROJECTS = 5

vi.mock('@/hooks/queries/use-projects', () => ({
  useProjects: () => ({
    data: { items: [], total: VISIBLE_PROJECTS, page: 1, size: 12, pages: 1 },
    isLoading: false,
    error: null,
  }),
}))
vi.mock('@/hooks/queries/use-teams', () => ({ useTeams: () => ({ data: [] }) }))
vi.mock('@/hooks/queries/use-system', () => ({
  useAppConfig: () => ({ data: { project_limit_per_user: 1 } }),
}))
vi.mock('@/context/useAuth', () => ({
  useAuth: () => ({ hasPermission: (permission: string) => permission === 'project:create' }),
}))
vi.mock('@/components/project/CreateProjectDialog', () => ({ CreateProjectDialog: () => null }))

describe('ProjectsPage New Project button', () => {
  it('stays enabled however many projects the user can see, since the server counts the ones the user administers', () => {
    render(
      <MemoryRouter>
        <ProjectsPage />
      </MemoryRouter>,
    )

    expect(screen.getByRole('button', { name: /New Project/i })).toBeEnabled()
  })
})
