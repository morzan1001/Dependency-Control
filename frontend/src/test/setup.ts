import "@testing-library/jest-dom";

// jsdom has no IntersectionObserver; FindingsTable uses one for infinite
// scroll. Stub the minimum surface so component tests don't crash. Methods
// intentionally do nothing — tests that need real observation should mock
// per-test instead.
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
