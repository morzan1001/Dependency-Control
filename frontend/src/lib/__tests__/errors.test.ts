import { describe, expect, it } from 'vitest'
import { extractErrorMessage } from '../errors'
import { getErrorMessage } from '../utils'

describe('extractErrorMessage', () => {
  it('returns message from Error object', () => {
    expect(extractErrorMessage(new Error('test error'))).toBe('test error')
  })

  it('returns detail string from response', () => {
    const error = { response: { data: { detail: 'Not found' } } }
    expect(extractErrorMessage(error)).toBe('Not found')
  })

  it('joins ALL validation errors and strips the "Value error, " prefix', () => {
    const error = {
      response: {
        data: {
          detail: [
            { msg: 'Value error, Name is required' },
            { msg: 'Value error, Email is invalid' },
          ],
        },
      },
    }
    expect(extractErrorMessage(error)).toBe('Name is required\nEmail is invalid')
  })

  it('serializes object details (branch not present in getErrorMessage)', () => {
    const error = { response: { data: { detail: { code: 42 } } } }
    expect(extractErrorMessage(error)).toBe('{"code":42}')
  })

  it('returns unified fallback for null', () => {
    expect(extractErrorMessage(null)).toBe('An unknown error occurred')
  })

  it('returns unified fallback for a bare non-object', () => {
    expect(extractErrorMessage('boom')).toBe('An unknown error occurred')
  })

  it('renders identically to getErrorMessage for shared-shaped errors', () => {
    const cases: unknown[] = [
      new Error('kaboom'),
      { response: { data: { detail: 'Not found' } } },
      {
        response: {
          data: {
            detail: [
              { msg: 'Value error, Name is required' },
              { msg: 'Value error, Email is invalid' },
            ],
          },
        },
      },
      null,
      {},
    ]
    for (const c of cases) {
      expect(extractErrorMessage(c)).toBe(getErrorMessage(c))
    }
  })
})
