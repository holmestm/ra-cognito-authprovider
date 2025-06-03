import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import { clearLocalStorage, cognitoLogout, pkceCognitoLogin } from '../utils/cognitoUtils';
import { localStorageMock, sessionStorageMock, setupStorageMocks, resetStorageMocks } from '../test/localStorage.mock';
import { pkceUtils } from '../utils/pkceUtils';
import { CognitoAuthProviderOptionsIds } from '../authProvider';
import { CognitoIdToken } from 'amazon-cognito-identity-js';

// Mock window.location
Object.defineProperty(window, 'location', {
  value: {
    ...window.location,
    origin: 'https://example.com',
    assign: vi.fn(),
  },
  writable: true,
});

// Mock pkceUtils
vi.mock('../utils/pkceUtils', () => ({
  pkceUtils: {
    generateCodeVerifier: vi.fn(() => 'test-code-verifier'),
    generateCodeChallenge: vi.fn(() => Promise.resolve('test-code-challenge')),
  },
}));

// Mock revokeTokens
vi.mock('../utils/cognitoTokens', () => ({
  resolveTokens: vi.fn(),
  revokeTokens: vi.fn(() => Promise.resolve()),
}));

describe('cognitoUtils', () => {
  beforeEach(() => {
    setupStorageMocks();
    vi.clearAllMocks();
  });

  afterEach(() => {
    resetStorageMocks();
  });

  describe('clearLocalStorage', () => {
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
      expect(localStorageMock.removeItem).toHaveBeenCalledWith('auth');
      expect(localStorageMock.removeItem).toHaveBeenCalledWith('CognitoIdentityServiceProvider');
      expect(localStorageMock.removeItem).toHaveBeenCalledWith('CognitoIdentityServiceProvider.test-client');
      expect(sessionStorageMock.removeItem).toHaveBeenCalledWith('pkce_code_verifier');

      // Verify other items were not removed
      const store = localStorageMock._getStore();
      expect(store['other-key']).toBe('other-value');
      expect(store['auth']).toBeUndefined();
    });
  });

  describe('pkceCognitoLogin', () => {
    it('should generate PKCE values and return authorization URL', async () => {
      const options: CognitoAuthProviderOptionsIds = {
        clientId: 'test-client-id',
        hostedUIUrl: 'https://auth.example.com',
        scope: ['openid', 'email', 'profile'],
        redirect_uri: 'https://example.com/callback',
        userPoolId: 'userpool-id',
        mode: 'oauth',
        oauthGrantType: 'code',
      };

      const result = await pkceCognitoLogin('https://example.com/page', options);

      // Verify code verifier was stored
      expect(sessionStorageMock.setItem).toHaveBeenCalledWith('pkce_code_verifier', 'test-code-verifier');

      // Verify current URL was stored
      expect(localStorageMock.setItem).toHaveBeenCalledWith('currentUrl', 'https://example.com/page');

      // Verify authorization URL was constructed correctly
      expect(result).toContain('https://auth.example.com/oauth2/authorize');
      expect(result).toContain('client_id=test-client-id');
      expect(result).toContain('response_type=code');
      expect(result).toContain('scope=openid+email+profile');
      expect(result).toContain(`redirect_uri=${encodeURIComponent('https://example.com/callback')}`);
      expect(result).toContain('code_challenge=test-code-challenge');
      expect(result).toContain('code_challenge_method=S256');
    });
  });

  describe('cognitoLogout', () => {
    it('should clear storage and return logout URL', async () => {
      const options: CognitoAuthProviderOptionsIds = {
        clientId: 'test-client-id',
        hostedUIUrl: 'https://auth.example.com',
        scope: ['openid', 'email', 'profile'],
        redirect_uri: 'https://example.com/callback',
        userPoolId: 'userpool-id',
        mode: 'oauth',
        oauthGrantType: 'code',
      };

      // Setup localStorage with auth data
      localStorageMock._populate({
        'auth': JSON.stringify({ id_token: 'test-id-token' }),
      });

      const logoutUrl = await cognitoLogout(options);

      // Verify localStorage was cleared
      expect(localStorageMock.removeItem).toHaveBeenCalledWith('auth');
      expect(localStorageMock.removeItem).toHaveBeenCalledWith('CognitoIdentityServiceProvider');
      console.log('logoutUrl', logoutUrl);
      // Verify logout URL was constructed correctly
      expect(logoutUrl).toContain('https://auth.example.com/logout');
      expect(logoutUrl).toContain('client_id=test-client-id');
      expect(logoutUrl).toContain(`logout_uri=${encodeURIComponent('https://example.com/')}`);
      expect(logoutUrl).toContain('id_token_hint=test-id-token');
    });
  });
});