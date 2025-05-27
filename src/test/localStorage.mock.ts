import { vi } from 'vitest';

// Create a mock storage object
const createStorageMock = () => {
  let store: Record<string, string> = {};
  
  const storageMock = {
    getItem: vi.fn((key: string) => store[key] || null),
    setItem: vi.fn((key: string, value: string) => {
      store[key] = value.toString();
    }),
    removeItem: vi.fn((key: string) => {
      delete store[key];
    }),
    clear: vi.fn(() => {
      store = {};
    }),
    key: vi.fn((index: number) => Object.keys(store)[index] || null),
    get length() {
      return Object.keys(store).length;
    },
    // Helper to pre-populate the store for testing
    _populate: (items: Record<string, string>) => {
      store = { ...items };
    },
    // Helper to get the current state of the store
    _getStore: () => ({ ...store }),
  };
  
  // Make the mock object behave like Storage for iteration
  return new Proxy(storageMock, {
    ownKeys: () => [...Object.keys(store), ...Object.keys(storageMock)],
    getOwnPropertyDescriptor: (target, key) => {
      if (key in store) {
        return { enumerable: true, configurable: true, value: store[key as string] };
      }
      return Reflect.getOwnPropertyDescriptor(target, key);
    },
    get: (target, key) => {
      if (typeof key === 'string' && key in store) {
        return store[key];
      }
      return Reflect.get(target, key);
    },
    has: (target, key) => {
      return key in store || key in target;
    }
  });
};

// Create mock instances
export const localStorageMock = createStorageMock();
export const sessionStorageMock = createStorageMock();

// Setup global mocks
export const setupStorageMocks = () => {
  Object.defineProperty(window, 'localStorage', {
    value: localStorageMock,
    writable: true
  });
  
  Object.defineProperty(window, 'sessionStorage', {
    value: sessionStorageMock,
    writable: true
  });
};

// Reset mocks between tests
export const resetStorageMocks = () => {
  localStorageMock.clear();
  sessionStorageMock.clear();
  vi.clearAllMocks();
};