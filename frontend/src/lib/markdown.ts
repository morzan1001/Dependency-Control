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

export const MARKDOWN_BODY: Components = {
  p: ({ children }) => createElement('p', { className: 'my-1' }, children),
  ul: ({ children }) => createElement('ul', { className: 'my-1 list-disc pl-5' }, children),
  ol: ({ children }) => createElement('ol', { className: 'my-1 list-decimal pl-5' }, children),
}
