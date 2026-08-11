import { describe, expect, it } from 'vitest'
import { retryUnlessClientError } from '../use-inventory'

describe('retryUnlessClientError', () => {
  it('does not retry 4xx', () => {
    expect(retryUnlessClientError(0, Object.assign(new Error('x'), { response: { status: 404 } }))).toBe(false)
  })

  it('retries 5xx up to 2 times', () => {
    const err = Object.assign(new Error('x'), { response: { status: 500 } })
    expect(retryUnlessClientError(0, err)).toBe(true)
    expect(retryUnlessClientError(1, err)).toBe(true)
    expect(retryUnlessClientError(2, err)).toBe(false)
  })

  it('retries network errors without response', () => {
    expect(retryUnlessClientError(0, new Error('network'))).toBe(true)
  })
})
