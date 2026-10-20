import { expect, vi } from 'vitest'

// jsdom measures every text as 0x0, so Recharts never moves an end tick label inward to fit, as it does in a browser.
export function measureChartText() {
  const measure = HTMLElement.prototype.getBoundingClientRect
  vi.spyOn(HTMLElement.prototype, 'getBoundingClientRect').mockImplementation(function (this: HTMLElement) {
    if (this.id !== 'recharts_measurement_span') return measure.call(this)
    const width = 8 * (this.textContent ?? '').length
    return { x: 0, y: 0, top: 0, left: 0, width, height: 18, right: width, bottom: 18, toJSON: () => ({}) }
  })
}

const GRID_LINES = { x: 'vertical', y: 'horizontal' } as const

export function expectLabelsOnTheirTicks(container: HTMLElement, axis: 'x' | 'y') {
  const lines = container.querySelectorAll(
    `.recharts-${axis}Axis .recharts-cartesian-axis-tick-line, .recharts-cartesian-grid-${GRID_LINES[axis]} line`,
  )
  const ticks = new Set([...lines].map((line) => line.getAttribute(`${axis}1`)))
  const labels = [...container.querySelectorAll(`.recharts-${axis}Axis-tick-labels text`)]
  expect(labels.length).toBeGreaterThan(0)
  for (const label of labels) expect(ticks, `label ${label.textContent}`).toContain(label.getAttribute(axis))
}
