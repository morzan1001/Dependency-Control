import { render, screen } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import { ScanStatusBadge } from '../ScanStatusBadge'
import { isScanUsable } from '@/lib/scan-status'

describe('ScanStatusBadge', () => {
  it('renders a plain completed badge', () => {
    render(<ScanStatusBadge status="completed" />)
    expect(screen.getByText('completed')).toBeInTheDocument()
  })

  it('renders a distinct warning badge for completed_with_errors', () => {
    render(<ScanStatusBadge status="completed_with_errors" />)
    expect(screen.getByText('completed with errors')).toBeInTheDocument()
  })

  it('renders pending with a spinner label', () => {
    render(<ScanStatusBadge status="pending" />)
    expect(screen.getByText('pending')).toBeInTheDocument()
  })
})

describe('isScanUsable', () => {
  it('treats completed and completed_with_errors as usable', () => {
    expect(isScanUsable('completed')).toBe(true)
    expect(isScanUsable('completed_with_errors')).toBe(true)
  })

  it('rejects other statuses', () => {
    expect(isScanUsable('failed')).toBe(false)
    expect(isScanUsable('pending')).toBe(false)
    expect(isScanUsable(undefined)).toBe(false)
  })
})
