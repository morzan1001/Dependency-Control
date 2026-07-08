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
