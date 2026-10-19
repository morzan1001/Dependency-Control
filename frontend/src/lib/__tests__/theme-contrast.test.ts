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

describe('light-theme severity colours', () => {
  it('pair every severity fill with its own text colour, unknown included', () => {
    expect(severityTokens).toEqual(expect.arrayContaining(['critical', 'high', 'medium', 'low', 'info', 'unknown']))
  })

  it.each(severityTokens)('give the %s pill text a WCAG contrast of at least 4.5:1 on its fill', (name) => {
    expect(contrast(token(lightTheme, `severity-${name}`), token(lightTheme, `severity-${name}-foreground`))).toBeGreaterThanOrEqual(4.5)
  })
})

describe('dark-theme destructive colour', () => {
  it('gives destructive text and icons a WCAG contrast of at least 4.5:1 on the background', () => {
    expect(contrast(token(darkTheme, 'destructive'), token(darkTheme, 'background'))).toBeGreaterThanOrEqual(4.5)
  })

  it('gives a destructive button its label at a WCAG contrast of at least 4.5:1', () => {
    expect(contrast(token(darkTheme, 'destructive'), token(darkTheme, 'destructive-foreground'))).toBeGreaterThanOrEqual(4.5)
  })
})

describe('negligible chart colour', () => {
  const negligible = hex(SEVERITY_CHART_COLORS.NEGLIGIBLE)

  it('writes its legend label, drawn in the slice colour, at a WCAG contrast of at least 4.5:1 on the light card', () => {
    expect(contrast(negligible, token(lightTheme, 'card'))).toBeGreaterThanOrEqual(4.5)
  })

  it('draws its slice at a WCAG contrast of at least 3:1 on the dark card too', () => {
    expect(contrast(negligible, token(darkTheme, 'card'))).toBeGreaterThanOrEqual(3)
  })

  it('stays apart from the info and unknown greys beside it', () => {
    expect(SEVERITY_CHART_COLORS.NEGLIGIBLE).not.toBe(SEVERITY_CHART_COLORS.INFO)
    expect(SEVERITY_CHART_COLORS.NEGLIGIBLE).not.toBe(SEVERITY_CHART_COLORS.UNKNOWN)
  })
})
