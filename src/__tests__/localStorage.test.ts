import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { localStorageMock, sessionStorageMock, setupStorageMocks, resetStorageMocks } from '../test/localStorage.mock';

describe('localStorage mock', () => {
  beforeEach(() => {
    setupStorageMocks();
  });

  afterEach(() => {
    resetStorageMocks();
  });

  it('should store and retrieve values', () => {
    localStorage.setItem('testKey', 'testValue');
    expect(localStorage.getItem('testKey')).toBe('testValue');
  });

  it('should remove values', () => {
    localStorage.setItem('testKey', 'testValue');
    localStorage.removeItem('testKey');
    expect(localStorage.getItem('testKey')).toBeNull();
  });

  it('should clear all values', () => {
    localStorage.setItem('testKey1', 'testValue1');
    localStorage.setItem('testKey2', 'testValue2');
    localStorage.clear();
    expect(localStorage.getItem('testKey1')).toBeNull();
    expect(localStorage.getItem('testKey2')).toBeNull();
  });

  it('should track method calls', () => {
    localStorage.setItem('testKey', 'testValue');
    expect(localStorageMock.setItem).toHaveBeenCalledWith('testKey', 'testValue');
    expect(localStorageMock.getItem).not.toHaveBeenCalled();

    localStorage.getItem('testKey');
    expect(localStorageMock.getItem).toHaveBeenCalledWith('testKey');
  });

  it('should support for...in iteration', () => {
    localStorage.setItem('key1', 'value1');
    localStorage.setItem('key2', 'value2');

    const keys = [];
    for (const key in localStorage) {
      // Only include actual storage keys, not methods or properties
      if (key === 'key1' || key === 'key2') {
        keys.push(key);
      }
    }

    expect(keys).toContain('key1');
    expect(keys).toContain('key2');
  });

  it('should support pre-populating values', () => {
    localStorageMock._populate({
      'preKey1': 'preValue1',
      'preKey2': 'preValue2'
    });

    expect(localStorage.getItem('preKey1')).toBe('preValue1');
    expect(localStorage.getItem('preKey2')).toBe('preValue2');
  });
});

describe('sessionStorage mock', () => {
  beforeEach(() => {
    setupStorageMocks();
  });

  afterEach(() => {
    resetStorageMocks();
  });

  it('should store and retrieve values', () => {
    sessionStorage.setItem('testKey', 'testValue');
    expect(sessionStorage.getItem('testKey')).toBe('testValue');
  });

  it('should be separate from localStorage', () => {
    localStorage.setItem('sharedKey', 'localValue');
    sessionStorage.setItem('sharedKey', 'sessionValue');

    expect(localStorage.getItem('sharedKey')).toBe('localValue');
    expect(sessionStorage.getItem('sharedKey')).toBe('sessionValue');
  });
});