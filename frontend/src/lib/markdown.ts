import { createElement, type ReactNode } from 'react'
import type { Components } from 'react-markdown'

const HEADING_LEVELS = ['h1', 'h2', 'h3', 'h4', 'h5', 'h6'] as const

// Preflight resets heading sizes and weights and no typography plugin restores them.
// Markdown renders under a page or dialog title, so each level moves one down and a # opens no second h1.
export const MARKDOWN_HEADINGS: Components = Object.fromEntries(
  HEADING_LEVELS.map((tag, index) => [
    tag,
    ({ children }: { children?: ReactNode }) =>
      createElement(HEADING_LEVELS[Math.min(index + 1, HEADING_LEVELS.length - 1)], { className: 'mb-2 mt-4 text-sm font-semibold first:mt-0' }, children),
  ]),
)

export const MARKDOWN_BODY: Components = {
  p: ({ children }) => createElement('p', { className: 'my-1' }, children),
  ul: ({ children }) => createElement('ul', { className: 'my-1 list-disc pl-5' }, children),
  ol: ({ children }) => createElement('ol', { className: 'my-1 list-decimal pl-5' }, children),
}
