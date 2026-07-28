import "@testing-library/jest-dom/vitest";

// Silence antd ResizeObserver warnings in jsdom
class MockResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
}
globalThis.ResizeObserver = MockResizeObserver as unknown as typeof ResizeObserver;

// matchMedia polyfill for antd components
if (!globalThis.matchMedia) {
  globalThis.matchMedia = (query: string) => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: () => {},
    removeListener: () => {},
    addEventListener: () => {},
    removeEventListener: () => {},
    dispatchEvent: () => false,
  });
}

// jsdom logs a not-implemented error when Ant Design asks for pseudo-element
// styles while measuring a table scrollbar. The pseudo-element is irrelevant
// to layout assertions in this suite, so delegate to the regular style lookup.
const getComputedStyle = globalThis.getComputedStyle;
globalThis.getComputedStyle = (element) => getComputedStyle(element);

// Polyfill scrollIntoView for jsdom (not implemented)
if (!Element.prototype.scrollIntoView) {
  Element.prototype.scrollIntoView = function () {
    // noop — jsdom does not implement layout scrolling
  };
}
