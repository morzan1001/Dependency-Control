import { MutationObserver, QueryClient, type MutationMeta } from '@tanstack/react-query'
import { toast } from 'sonner'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { createMutationCache } from '../mutation-cache'

vi.mock('sonner', () => ({ toast: { error: vi.fn() } }))

const refusal = Object.assign(new Error('Request failed with status code 409'), {
  response: { status: 409, data: { detail: 'Team already exists' } },
})

async function failingMutation(meta?: MutationMeta) {
  const client = new QueryClient({ mutationCache: createMutationCache() })
  const observer = new MutationObserver(client, { mutationFn: () => Promise.reject(refusal), meta })
  await observer.mutate().catch(() => undefined)
}

beforeEach(() => vi.mocked(toast.error).mockClear())

describe('createMutationCache', () => {
  it('names a failed mutation by its errorTitle and gives the server message as the description', async () => {
    await failingMutation({ errorTitle: 'Failed to create team' })

    expect(vi.mocked(toast.error).mock.calls).toEqual([['Failed to create team', { description: 'Team already exists' }]])
  })

  it('leaves a mutation without an errorTitle to its caller', async () => {
    await failingMutation()

    expect(toast.error).not.toHaveBeenCalled()
  })
})
