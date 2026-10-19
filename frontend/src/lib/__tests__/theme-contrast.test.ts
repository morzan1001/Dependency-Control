import { readFileSync } from 'node:fs'
import { describe, expect, it } from 'vitest'

import { SEVERITY_CHART_COLORS } from '@/lib/finding-utils'

type Rgb = [number, number, number]

const css = readFileSync(`${import.meta.dirname}/../../index.css`, 'utf8')
const lightTheme = /:root\s*\{([^}]*)\}/.exec(css)![1]
const darkTheme = /\.dark\s*\{([^}]*)\}/.exec(css)![1]
const severityTokens = [...lightTheme.matchAll(/--severity-([a-z]+):/g)].map((match) => match[1])

function token(theme: string, name: string): Rgb {
  const match = new RegExp(`--${name}:\\s*([\\d.]+) ([\\d.]+)% ([\\d.]+)%;`).exec(theme)
  if (!match) throw new Error(`no token --${name}`)
  const [h, s, l] = match.slice(1).map(Number)
  const k = (n: number) => (n + h / 30) % 12
  const a = (s / 100) * Math.min(l / 100, 1 - l / 100)
  const channel = (n: number) => l / 100 - a * Math.max(-1, Math.min(k(n) - 3, 9 - k(n), 1))
  return [channel(0), channel(8), channel(4)].map((v) => Math.round(v * 255)) as Rgb
}

const hex = (value: string): Rgb => [1, 3, 5].map((i) => Number.parseInt(value.slice(i, i + 2), 16)) as Rgb

function luminance(rgb: Rgb): number {
  const [r, g, b] = rgb.map((v) => (v / 255 <= 0.03928 ? v / 255 / 12.92 : ((v / 255 + 0.055) / 1.055) ** 2.4))
  return 0.2126 * r + 0.7152 * g + 0.0722 * b
}

function contrast(a: Rgb, b: Rgb): number {
  const [lighter, darker] = [luminance(a), luminance(b)].sort((x, y) => y - x)
  return (lighter + 0.05) / (darker + 0.05)
}

function lab(rgb: Rgb): Rgb {
  const [r, g, b] = rgb.map((v) => (v / 255 <= 0.04045 ? v / 255 / 12.92 : ((v / 255 + 0.055) / 1.055) ** 2.4))
  const f = (t: number) => (t > 216 / 24389 ? Math.cbrt(t) : ((24389 / 27) * t + 16) / 116)
  const [x, y, z] = [
    (0.4124 * r + 0.3576 * g + 0.1805 * b) / 0.95047,
    0.2126 * r + 0.7152 * g + 0.0722 * b,
    (0.0193 * r + 0.1192 * g + 0.9505 * b) / 1.08883,
  ].map(f)
  return [116 * y - 16, 500 * (x - y), 200 * (y - z)]
}

const deltaE76 = (a: Rgb, b: Rgb) => Math.hypot(...lab(a).map((v, i) => v - lab(b)[i]))

describe('light-theme severity colours', () => {
  it('pair every severity fill with its own text colour, unknown included', () => {
    expect(severityTokens).toEqual(expect.arrayContaining(['critical', 'high', 'medium', 'low', 'info', 'unknown']))
  })

  it.each(severityTokens)('give the %s pill text a WCAG contrast of at least 4.5:1 on its fill', (name) => {
    expect(contrast(token(lightTheme, `severity-${name}`), token(lightTheme, `severity-${name}-foreground`))).toBeGreaterThanOrEqual(4.5)
  })
})

describe.each([
  ['light', lightTheme],
  ['dark', darkTheme],
])('%s-theme destructive colour', (_name, theme) => {
  it('gives destructive text and icons a WCAG contrast of at least 4.5:1 on the background', () => {
    expect(contrast(token(theme, 'destructive'), token(theme, 'background'))).toBeGreaterThanOrEqual(4.5)
  })

  it('gives a destructive button its label at a WCAG contrast of at least 4.5:1', () => {
    expect(contrast(token(theme, 'destructive'), token(theme, 'destructive-foreground'))).toBeGreaterThanOrEqual(4.5)
  })
})

describe('negligible chart colour', () => {
  const negligible = hex(SEVERITY_CHART_COLORS.NEGLIGIBLE)

  it.each([
    ['light', lightTheme],
    ['dark', darkTheme],
  ])('draws its slice at a WCAG contrast of at least 3:1 on the %s card', (_name, theme) => {
    expect(contrast(negligible, token(theme, 'card'))).toBeGreaterThanOrEqual(3)
  })

  it.each(['INFO', 'UNKNOWN'] as const)('differs in colour from the %s grey beside it by a Delta E of at least 15', (other) => {
    expect(deltaE76(negligible, hex(SEVERITY_CHART_COLORS[other]))).toBeGreaterThanOrEqual(15)
  })
})
