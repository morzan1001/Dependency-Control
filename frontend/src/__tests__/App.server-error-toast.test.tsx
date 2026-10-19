import { render, waitFor } from '@testing-library/react'
import { useQuery } from '@tanstack/react-query'
import { toast } from 'sonner'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import App from '../App'

vi.mock('@/hooks/queries/use-system', () => ({
  usePublicConfig: () => ({ data: undefined }),
  useAppConfig: () => ({ data: undefined }),
}))
vi.mock('@/api/users', () => ({ userApi: { getMe: vi.fn().mockResolvedValue({ permissions: ['archive:read_all'] }) } }))

const serverFailure = vi.hoisted(() => ({ current: undefined as unknown }))
vi.mock('../pages/Archives', () => ({
  default: function ArchivesStub() {
    useQuery({ queryKey: ['archives-stub'], queryFn: () => Promise.reject(serverFailure.current), retry: false })
    return <p>archives</p>
  },
}))

function sessionToken(permissions: string[]): string {
  const encode = (obj: unknown) => btoa(JSON.stringify(obj)).replace(/=+$/, '')
  return `${encode({ alg: 'HS256' })}.${encode({ sub: 'u1', permissions, type: 'access' })}.sig`
}

const failure = (status: number, data: unknown) =>
  Object.assign(new Error(`Request failed with status code ${status}`), { response: { status, data } })

beforeEach(() => {
  localStorage.clear()
  sessionStorage.clear()
  globalThis.matchMedia = vi.fn().mockReturnValue({ matches: false, addListener: vi.fn(), removeListener: vi.fn() })
  localStorage.setItem('token', sessionToken(['archive:read_all']))
  localStorage.setItem('refresh_token', 'refresh')
  globalThis.history.replaceState(null, '', '/archives')
  vi.spyOn(toast, 'error').mockClear()
})

describe('a page load the server refuses', () => {
  it("gives the server's reason, as a failed save does", async () => {
    serverFailure.current = failure(501, { detail: 'Archive storage is not configured' })

    render(<App />)

    await waitFor(() =>
      expect(toast.error).toHaveBeenCalledWith('Server Error', { description: 'Archive storage is not configured' }),
    )
  })

  it('says something went wrong on the server when the server gives no reason', async () => {
    serverFailure.current = failure(502, '<html>Bad Gateway</html>')

    render(<App />)

    await waitFor(() =>
      expect(toast.error).toHaveBeenCalledWith('Server Error', { description: 'Something went wrong on the server' }),
    )
  })
})
