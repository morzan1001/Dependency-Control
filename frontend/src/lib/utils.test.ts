import { describe, expect, it } from 'vitest'
import { cn, getErrorMessage, formatDate, shortCommitHash } from './utils'

describe('cn', () => {
  it('merges class names', () => {
    expect(cn('foo', 'bar')).toBe('foo bar')
  })

  it('deduplicates tailwind classes', () => {
    expect(cn('p-4', 'p-2')).toBe('p-2')
  })

  it('handles conditional classes', () => {
    const isHidden = false
    expect(cn('base', isHidden && 'hidden', 'end')).toBe('base end')
  })
})

describe('getErrorMessage', () => {
  it('returns message from Error object', () => {
    expect(getErrorMessage(new Error('test error'))).toBe('test error')
  })

  it('returns detail string from response', () => {
    const error = { response: { data: { detail: 'Not found' } } }
    expect(getErrorMessage(error)).toBe('Not found')
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
    expect(getErrorMessage(error)).toBe('Name is required\nEmail is invalid')
  })

  it('serializes a validation entry that carries no msg', () => {
    const error = { response: { data: { detail: [{ type: 'missing', loc: ['body', 'name'] }] } } }
    expect(getErrorMessage(error)).toBe('{"type":"missing","loc":["body","name"]}')
  })

  it('serializes object details', () => {
    const error = { response: { data: { detail: { code: 42 } } } }
    expect(getErrorMessage(error)).toBe('{"code":42}')
  })

  it('returns fallback for null', () => {
    expect(getErrorMessage(null)).toBe('An unknown error occurred')
  })

  it('returns fallback for a bare non-object', () => {
    expect(getErrorMessage('boom')).toBe('An unknown error occurred')
  })

  it('returns fallback for an object carrying neither detail nor message', () => {
    expect(getErrorMessage({})).toBe('An unknown error occurred')
  })
})

describe('formatDate', () => {
  it('returns N/A for undefined', () => {
    expect(formatDate(undefined)).toBe('N/A')
  })

  it('returns N/A for null', () => {
    expect(formatDate(null)).toBe('N/A')
  })

  it('formats a valid date string', () => {
    const result = formatDate('2024-01-15')
    expect(result).toBeTruthy()
    expect(result).not.toBe('N/A')
  })

  it('returns original string for invalid date', () => {
    expect(formatDate('not-a-date')).toBe('not-a-date')
  })
})

describe('shortCommitHash', () => {
  it('returns first 7 characters', () => {
    expect(shortCommitHash('abc1234567890')).toBe('abc1234')
  })

  it('returns empty string for null', () => {
    expect(shortCommitHash(null)).toBe('')
  })

  it('returns empty string for undefined', () => {
    expect(shortCommitHash(undefined)).toBe('')
  })
})
