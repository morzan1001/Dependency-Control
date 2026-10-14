import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'

import { SEVERITY_CHART_COLORS, type Severity } from '@/lib/finding-utils'

type Rgb = [number, number, number]

const lightTheme = /:root\s*\{([^}]*)\}/.exec(readFileSync(`${import.meta.dirname}/../../index.css`, 'utf8'))![1]
const severityTokens = [...lightTheme.matchAll(/--severity-([a-z]+):/g)].map((match) => match[1])

function token(name: string): Rgb {
  const match = new RegExp(`--${name}:\\s*([\\d.]+) ([\\d.]+)% ([\\d.]+)%;`).exec(lightTheme)
  if (!match) throw new Error(`no light-theme token --${name}`)
  const [h, s, l] = match.slice(1).map(Number)
  const k = (n: number) => (n + h / 30) % 12
  const a = (s / 100) * Math.min(l / 100, 1 - l / 100)
  const channel = (n: number) => l / 100 - a * Math.max(-1, Math.min(k(n) - 3, 9 - k(n), 1))
  return [channel(0), channel(8), channel(4)].map((v) => Math.round(v * 255)) as Rgb
}

function luminance(rgb: Rgb): number {
  const [r, g, b] = rgb.map((v) => (v / 255 <= 0.03928 ? v / 255 / 12.92 : ((v / 255 + 0.055) / 1.055) ** 2.4))
  return 0.2126 * r + 0.7152 * g + 0.0722 * b
}

function contrast(a: Rgb, b: Rgb): number {
  const [lighter, darker] = [luminance(a), luminance(b)].sort((x, y) => y - x)
  return (lighter + 0.05) / (darker + 0.05)
}

describe('light-theme severity colours', () => {
  it('pair every severity fill with its own text colour, unknown included', () => {
    expect(severityTokens).toEqual(expect.arrayContaining(['critical', 'high', 'medium', 'low', 'info', 'unknown']))
  })

  it.each(severityTokens)('give the %s pill text a WCAG contrast of at least 4.5:1 on its fill', (name) => {
    expect(contrast(token(`severity-${name}`), token(`severity-${name}-foreground`))).toBeGreaterThanOrEqual(4.5)
  })

  // NEGLIGIBLE and UNKNOWN chart in their own greys; only their pills need a fill dark enough for text.
  it.each(['critical', 'high', 'medium', 'low', 'info'])('paint the %s chart colour in the pill fill', (name) => {
    const hex = SEVERITY_CHART_COLORS[name.toUpperCase() as Severity]
    const chart = [1, 3, 5].map((i) => Number.parseInt(hex.slice(i, i + 2), 16))
    token(`severity-${name}`).forEach((value, i) => expect(Math.abs(value - chart[i])).toBeLessThanOrEqual(2))
  })
})
