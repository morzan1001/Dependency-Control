// The setup stub never reports an intersection; this one reports every observed element as on screen.
export function showObservedElements(): () => void {
  const original = globalThis.IntersectionObserver
  class VisibleObserver {
    private connected = true
    constructor(private readonly callback: IntersectionObserverCallback) {}
    observe = (target: Element) =>
      queueMicrotask(() => {
        if (this.connected) this.callback([{ isIntersecting: true, target } as IntersectionObserverEntry], this as unknown as IntersectionObserver)
      })
    disconnect = (): void => {
      this.connected = false
    }
    unobserve = (): void => undefined
    takeRecords = (): IntersectionObserverEntry[] => []
  }
  globalThis.IntersectionObserver = VisibleObserver as unknown as typeof IntersectionObserver
  return () => {
    globalThis.IntersectionObserver = original
  }
}
