import "@testing-library/jest-dom";

// jsdom lacks IntersectionObserver; stub it so component tests don't crash.
const intersectionObserverStub = class {
  observe = (): void => undefined;
  disconnect = (): void => undefined;
  takeRecords = (): IntersectionObserverEntry[] => [];
  unobserve = (): void => undefined;
};
if (globalThis.IntersectionObserver === undefined) {
  (globalThis as unknown as { IntersectionObserver: typeof intersectionObserverStub }).IntersectionObserver =
    intersectionObserverStub;
}

// jsdom lacks scrollIntoView; Radix's Select calls it on the item it focuses when the list opens.
if (typeof Element !== 'undefined' && Element.prototype.scrollIntoView === undefined) {
  Element.prototype.scrollIntoView = (): void => undefined;
}

// jsdom lacks ResizeObserver; Radix's useSize constructs one on mount.
const resizeObserverStub = class {
  observe = (): void => undefined;
  disconnect = (): void => undefined;
  unobserve = (): void => undefined;
};
if (globalThis.ResizeObserver === undefined) {
  (globalThis as unknown as { ResizeObserver: typeof resizeObserverStub }).ResizeObserver = resizeObserverStub;
}
