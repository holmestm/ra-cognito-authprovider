import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { clearLocalStorage } from '../utils/cognitoUtils';
import { localStorageMock, sessionStorageMock, setupStorageMocks, resetStorageMocks } from '../test/localStorage.mock';

describe('clearLocalStorage', () => {
  beforeEach(() => {
    setupStorageMocks();
  });

  afterEach(() => {
    resetStorageMocks();
  });

  it('should clear auth-related items from localStorage', () => {
    // Setup localStorage with test data
    localStorageMock._populate({
      'auth': JSON.stringify({ token: 'test-token' }),
      'CognitoIdentityServiceProvider': 'test-value',
      'CognitoIdentityServiceProvider.test-client': 'test-value',
      'other-key': 'other-value',
    });
    sessionStorageMock._populate({
      'pkce_code_verifier': 'test-verifier',
    });

    // Call the function
    clearLocalStorage();

    // Verify localStorage items were removed
    expect(localStorage.getItem('auth')).toBeNull();
    expect(localStorage.getItem('CognitoIdentityServiceProvider')).toBeNull();
    expect(localStorage.getItem('CognitoIdentityServiceProvider.test-client')).toBeNull();
    expect(sessionStorage.getItem('pkce_code_verifier')).toBeNull();
    
    // Verify other items were not removed
    expect(localStorage.getItem('other-key')).toBe('other-value');
  });

  it('should handle iteration over localStorage keys', () => {
    // Setup localStorage with Cognito keys
    localStorageMock._populate({
      'CognitoIdentityServiceProvider.client1': 'value1',
      'CognitoIdentityServiceProvider.client2': 'value2',
      'regular-key': 'regular-value',
    });

    // Call the function
    clearLocalStorage();

    // Verify Cognito keys were removed but regular key remains
    expect(localStorage.getItem('CognitoIdentityServiceProvider.client1')).toBeNull();
    expect(localStorage.getItem('CognitoIdentityServiceProvider.client2')).toBeNull();
    expect(localStorage.getItem('regular-key')).toBe('regular-value');
  });
});