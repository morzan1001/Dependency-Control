import { describe, it, expect } from 'vitest'

import { mergeInstances } from '@/components/settings/cicd-instances'
import type { GitHubInstance } from '@/types/github'

function githubInstance(overrides: Partial<GitHubInstance> = {}): GitHubInstance {
  return {
    id: 'gh-1',
    name: 'GitHub.com',
    url: 'https://token.actions.githubusercontent.com',
    github_url: 'https://github.com',
    is_active: true,
    oidc_audience: 'dependency-control',
    auto_create_projects: false,
    sync_teams: false,
    has_access_token: true,
    created_at: '2026-09-01T00:00:00Z',
    created_by: 'admin',
    ...overrides,
  }
}

describe('mergeInstances', () => {
  it('carries sync_teams through for GitHub instances', () => {
    const merged = mergeInstances(undefined, [githubInstance({ sync_teams: true })])
    expect(merged[0].sync_teams).toBe(true)
  })

  it('leaves sync_teams off when GitHub reports it off', () => {
    const merged = mergeInstances(undefined, [githubInstance({ sync_teams: false })])
    expect(merged[0].sync_teams).toBe(false)
  })
})
