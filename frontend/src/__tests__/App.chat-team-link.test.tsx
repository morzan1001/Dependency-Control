import { render, screen } from '@testing-library/react'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { collectEntitiesFromToolCalls, linkifyAssistantMarkdown } from '@/components/chat/chat-entities'
import App from '../App'

vi.mock('@/hooks/queries/use-system', () => ({
  usePublicConfig: () => ({ data: undefined }),
  useAppConfig: () => ({ data: undefined }),
}))
vi.mock('@/api/users', () => ({ userApi: { getMe: vi.fn().mockResolvedValue({ permissions: ['team:read'] }) } }))
vi.mock('../pages/Teams', () => ({ default: () => <p>teams page</p> }))

// The signature is never verified client-side.
function sessionToken(permissions: string[]): string {
  const encode = (obj: unknown) => btoa(JSON.stringify(obj)).replace(/=+$/, '')
  return `${encode({ alg: 'HS256' })}.${encode({ sub: 'u1', permissions, type: 'access' })}.sig`
}

beforeEach(() => {
  localStorage.clear()
  localStorage.setItem('token', sessionToken(['team:read']))
  localStorage.setItem('refresh_token', 'refresh')
  // next-themes reads the colour-scheme preference, which jsdom does not implement.
  globalThis.matchMedia = vi.fn().mockReturnValue({ matches: false, addListener: vi.fn(), removeListener: vi.fn() })
})

describe('a team link in a chat answer', () => {
  it('opens a page that exists', async () => {
    const entities = collectEntitiesFromToolCalls([
      { tool_name: 'projects', arguments: {}, result: { teams: [{ id: 't1', name: 'Payments' }] }, duration_ms: 1 },
    ])
    const href = /\]\(([^)]+)\)/.exec(linkifyAssistantMarkdown('Payments owns it.', entities))![1]
    globalThis.history.replaceState(null, '', href)

    render(<App />)

    expect(await screen.findByText('teams page')).toBeInTheDocument()
  })
})
