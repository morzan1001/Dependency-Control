import type { TestingLibraryMatchers } from "@testing-library/jest-dom/matchers";

// jest-dom 7.0.1 augments Assertion<T> but vitest 5 declares Assertion<R, T>, so bind the matchers to Matchers.
declare module "vitest" {
  // eslint-disable-next-line @typescript-eslint/no-empty-object-type, @typescript-eslint/no-unused-vars -- the empty body is what makes this a declaration merge, and `_T` only exists to match vitest's arity
  interface Matchers<R extends void | Promise<void> = void | Promise<void>, _T = unknown>
    extends TestingLibraryMatchers<unknown, R> {}
}
