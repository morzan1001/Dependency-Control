import { cleanup, render, screen, fireEvent } from '@testing-library/react'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { SecretInput } from '../SecretInput'

describe('SecretInput', () => {
  afterEach(() => cleanup())

  it('shows the configured placeholder when a stored secret exists and the field is empty', () => {
    render(<SecretInput id="s" value="" configured onChange={() => {}} placeholder="ghp_..." />)
    expect(screen.getByPlaceholderText(/configured — enter a new value to replace/i)).toBeInTheDocument()
  })

  it('shows the normal placeholder when nothing is configured', () => {
    render(<SecretInput id="s" value="" configured={false} onChange={() => {}} placeholder="ghp_..." />)
    expect(screen.getByPlaceholderText('ghp_...')).toBeInTheDocument()
  })

  it('offers to remove a stored secret', () => {
    const onChange = vi.fn()
    render(<SecretInput id="s" value="" configured onChange={onChange} />)

    fireEvent.click(screen.getByRole('button', { name: 'Remove' }))

    expect(onChange).toHaveBeenCalledWith(null)
  })

  it('offers no removal when nothing is stored', () => {
    render(<SecretInput id="s" value="" configured={false} onChange={() => {}} />)

    expect(screen.queryByRole('button', { name: 'Remove' })).not.toBeInTheDocument()
  })

  it('shows a pending removal and lets it be undone', () => {
    const onChange = vi.fn()
    render(<SecretInput id="s" value={null} configured onChange={onChange} />)

    expect(screen.getByPlaceholderText('Removed when you save')).toHaveValue('')
    fireEvent.click(screen.getByRole('button', { name: 'Undo' }))

    expect(onChange).toHaveBeenCalledWith('')
  })

  it('keeps the typed value editable and reports changes', () => {
    const onChange = vi.fn()
    render(<SecretInput id="s" value="abc" configured onChange={onChange} />)
    const input = screen.getByDisplayValue('abc')
    expect(input).toHaveAttribute('type', 'password')
    fireEvent.change(input, { target: { value: 'abcd' } })
    expect(onChange).toHaveBeenCalledWith('abcd')
  })
})
