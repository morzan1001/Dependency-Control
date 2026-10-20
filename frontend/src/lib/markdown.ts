import { createElement, type ReactNode } from 'react'
import type { Components } from 'react-markdown'

const HEADING_LEVELS = ['h1', 'h2', 'h3', 'h4', 'h5', 'h6'] as const

export function markdownHeadingTag(top: number, level: number) {
  return HEADING_LEVELS[Math.min(top + level - 1, HEADING_LEVELS.length) - 1]
}

// Preflight resets heading sizes and weights and no typography plugin restores them.
// Markdown renders under the page title or a dialog section, so its # becomes h{top} and ranks below them.
export function markdownHeadings(top: number): Components {
  return Object.fromEntries(
    HEADING_LEVELS.map((tag, index) => [
      tag,
      ({ children }: { children?: ReactNode }) =>
        createElement(markdownHeadingTag(top, index + 1), { className: 'mb-2 mt-4 text-sm font-semibold first:mt-0' }, children),
    ]),
  )
}

export const MARKDOWN_BODY: Components = {
  p: ({ children }) => createElement('p', { className: 'my-1' }, children),
  ul: ({ children }) => createElement('ul', { className: 'my-1 list-disc pl-5' }, children),
  ol: ({ children }) => createElement('ol', { className: 'my-1 list-decimal pl-5' }, children),
}
