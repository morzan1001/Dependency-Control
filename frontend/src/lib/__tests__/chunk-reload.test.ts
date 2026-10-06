import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import '../chunk-reload'

const reload = vi.fn()

// What Vite dispatches on window when a lazy route's chunk no longer exists on the server.
const chunkError = () => globalThis.dispatchEvent(new Event('vite:preloadError', { cancelable: true }))

describe('chunk reload on vite:preloadError', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    sessionStorage.clear()
    reload.mockClear()
    vi.stubGlobal('location', { ...globalThis.location, reload })
  })

  afterEach(() => {
    vi.unstubAllGlobals()
    vi.useRealTimers()
  })

  it('reloads the page when a chunk of an older release fails to load', () => {
    chunkError()

    expect(reload).toHaveBeenCalledTimes(1)
  })

  it('leaves a chunk that still fails right after the reload to the error boundary', () => {
    chunkError()
    vi.advanceTimersByTime(2_000)
    chunkError()

    expect(reload).toHaveBeenCalledTimes(1)
  })

  it('reloads again for a later release in the same tab', () => {
    chunkError()
    vi.advanceTimersByTime(60 * 60 * 1000)
    chunkError()

    expect(reload).toHaveBeenCalledTimes(2)
  })
})
