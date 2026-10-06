const RELOADED_AT_KEY = 'chunk-reload-at'
// A chunk that still fails this soon after the reload is broken rather than stale.
const LOOP_GUARD_MS = 10_000

globalThis.addEventListener('vite:preloadError', () => {
  if (Date.now() - Number(sessionStorage.getItem(RELOADED_AT_KEY)) < LOOP_GUARD_MS) return
  sessionStorage.setItem(RELOADED_AT_KEY, String(Date.now()))
  globalThis.location.reload()
})
