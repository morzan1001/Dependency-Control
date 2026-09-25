import { describe, it, expect } from 'vitest'

import { isSharedIssuer, mergeInstances, parseAllowlist } from '@/components/settings/cicd-instances'
import type { GitHubInstance } from '@/types/github'
import type { GitLabInstance } from '@/types/gitlab'

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
    allowed_owner_ids: [],
    has_access_token: true,
    created_at: '2026-09-01T00:00:00Z',
    created_by: 'admin',
    ...overrides,
  }
}

function gitlabInstance(overrides: Partial<GitLabInstance> = {}): GitLabInstance {
  return {
    id: 'gl-1',
    name: 'GitLab.com',
    url: 'https://gitlab.com',
    is_active: true,
    is_default: false,
    auto_create_projects: false,
    sync_teams: false,
    team_sync_depth: 1,
    allowed_namespaces: [],
    token_configured: true,
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

  it('carries each provider its own allowlist', () => {
    const merged = mergeInstances(
      [gitlabInstance({ allowed_namespaces: ['acme'] })],
      [githubInstance({ allowed_owner_ids: ['111'] })],
    )
    const github = merged.find((instance) => instance._type === 'github')
    const gitlab = merged.find((instance) => instance._type === 'gitlab')
    expect(github?.allowed_owner_ids).toEqual(['111'])
    expect(gitlab?.allowed_namespaces).toEqual(['acme'])
  })
})

describe('parseAllowlist', () => {
  it('splits on commas, spaces and newlines and drops empty entries', () => {
    expect(parseAllowlist(' 111, 222\n333 ,, ')).toEqual(['111', '222', '333'])
  })

  it('reads an empty field as an empty list', () => {
    expect(parseAllowlist('   ')).toEqual([])
  })
})

describe('isSharedIssuer', () => {
  it('recognises the github.com Actions issuer, with or without a trailing slash', () => {
    expect(isSharedIssuer('github', 'https://token.actions.githubusercontent.com')).toBe(true)
    expect(isSharedIssuer('github', 'https://token.actions.githubusercontent.com/')).toBe(true)
  })

  it('treats an enterprise-scoped issuer and GHES as single-tenant', () => {
    expect(isSharedIssuer('github', 'https://token.actions.githubusercontent.com/acme')).toBe(false)
    expect(isSharedIssuer('github', 'https://github.corp.example.com/_services/token')).toBe(false)
  })

  it('recognises gitlab.com but not a self-managed GitLab', () => {
    expect(isSharedIssuer('gitlab', 'https://gitlab.com')).toBe(true)
    expect(isSharedIssuer('gitlab', 'https://gitlab.example.com')).toBe(false)
  })
})
