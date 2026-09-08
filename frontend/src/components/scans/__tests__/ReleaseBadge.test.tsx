import { render, screen } from '@testing-library/react'
import { describe, it, expect } from 'vitest'
import { ReleaseBadge } from '../ReleaseBadge'

const PRODUCTION = 'production'
const STAGING = 'staging'
const CANARY = 'canary'
const VERSION = 'v1.2.3'
const SHORT_VERSION = 'v9'
const GENERIC_LABEL = 'release'
const GENERIC_ARIA_LABEL = 'Release'
const CALLER_CLASS = 'ml-2'

describe('ReleaseBadge', () => {
  it('names the environment', () => {
    render(<ReleaseBadge environment={PRODUCTION} />)
    expect(screen.getByText(PRODUCTION)).toBeInTheDocument()
  })

  it('appends the version when there is one', () => {
    render(<ReleaseBadge environment={STAGING} version={VERSION} />)
    expect(screen.getByText(STAGING)).toBeInTheDocument()
    expect(screen.getByText(VERSION)).toBeInTheDocument()
  })

  it('falls back to a generic label when the environment is unknown', () => {
    render(<ReleaseBadge />)
    expect(screen.getByText(GENERIC_LABEL)).toBeInTheDocument()
    expect(screen.getByLabelText(GENERIC_ARIA_LABEL)).toBeInTheDocument()
  })

  it('names the version alone when there is no environment', () => {
    render(<ReleaseBadge version={SHORT_VERSION} />)
    expect(screen.getByLabelText(`${GENERIC_ARIA_LABEL} ${SHORT_VERSION}`)).toBeInTheDocument()
  })

  it('is labelled for assistive technology', () => {
    render(<ReleaseBadge environment={CANARY} version={SHORT_VERSION} />)
    expect(screen.getByLabelText(`Release ${SHORT_VERSION} in ${CANARY}`)).toBeInTheDocument()
  })

  it('accepts extra classes from the caller', () => {
    render(<ReleaseBadge environment={PRODUCTION} className={CALLER_CLASS} />)
    expect(screen.getByLabelText(`Release in ${PRODUCTION}`)).toHaveClass(CALLER_CLASS)
  })
})
