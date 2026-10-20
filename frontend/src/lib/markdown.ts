import { createElement, type ReactNode } from 'react'
import type { Components } from 'react-markdown'

const HEADING_LEVELS = ['h1', 'h2', 'h3', 'h4', 'h5', 'h6'] as const

// Preflight resets heading sizes and weights and no typography plugin restores them.
export const MARKDOWN_HEADINGS: Components = Object.fromEntries(
  HEADING_LEVELS.map((tag) => [
    tag,
    ({ children }: { children?: ReactNode }) => createElement(tag, { className: 'mb-2 mt-4 text-sm font-semibold first:mt-0' }, children),
  ]),
)
