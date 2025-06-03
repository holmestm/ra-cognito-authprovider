import { describe, it, expect, beforeEach, afterEach, vi, Mock } from 'vitest';
import { CognitoAuthProvider, CognitoAuthProviderOptionsIds } from '../authProvider';
import { setupStorageMocks, resetStorageMocks, localStorageMock } from '../test/localStorage.mock';
import * as cognitoTokens from '../utils/cognitoTokens';
import * as cognitoUtils from '../utils/cognitoUtils';
import { create } from '@mui/material/styles/createTransitions';

// Mock window.location
Object.defineProperty(window, 'location', {
  value: {
    ...window.location,
    href: 'https://example.com/callback?code=test-auth-code',
    hash: '',
    assign: vi.fn(),
  },
  writable: true,
});

const mocks: any = vi.hoisted(() => {
  const mockCognitoUserSession = vi.fn(() => ({
    isValid: vi.fn(() => true),
    getIdToken: vi.fn(() => ({
      decodePayload: vi.fn(() => ({ 'cognito:groups': ['admin'] })),
    })),
  }));
  const mockCognitoUser = {
    getSession: mockCognitoUserSession,
    getUserAttributes: vi.fn(),
    getUsername: vi.fn(() => 'testuser'),
    setSignInUserSession: vi.fn(),
  };
  const mockGetCurrentUser = vi.fn(() => mockCognitoUser) as Mock | undefined;

  return {
    mockCognitoUserSession,
    mockCognitoUser,
    mockGetCurrentUser,
    mockCognitoUserPool: vi.fn(() => ({
      getCurrentUser: mockGetCurrentUser,
    }))
  }
});

// Mock cognitoTokens module
const resolveTokensFromCodeSpy = vi.spyOn(cognitoTokens, 'resolveTokensFromCode');
const resolveTokensFromUrlSpy = vi.spyOn(cognitoTokens, 'resolveTokensFromUrl');

// Mock cognitoUtils module
vi.mock('../utils/cognitoUtils', () => ({
  createCognitoSession: vi.fn(),
  createCognitoUserPool: mocks.mockCognitoUserPool,
}));

// Mock amazon-cognito-identity-js
vi.mock('amazon-cognito-identity-js', () => {
  return {
    CognitoUserPool: mocks.mockCognitoUserPool,
    CognitoUser: mocks.mockGetCurrentUser,
    CognitoUserSession: mocks.mockCognitoUserSession,
    CognitoIdToken: vi.fn(),
    CognitoAccessToken: vi.fn(),
    CognitoRefreshToken: vi.fn(),
  };
});

describe('handleCallback', () => {
  let authProvider: any;
  const mockUser = { username: 'testuser' };
  const sampleConfig: CognitoAuthProviderOptionsIds = {
    userPoolId: 'test-pool-id',
    clientId: 'test-client-id',
    mode: 'oauth',
    oauthGrantType: 'code',
    hostedUIUrl: 'https://idp.cognito.com',
    scope: ['openid', 'email', 'profile'],
    redirect_uri: 'https://example.com/callback',
  };
  beforeEach(() => {
    vi.clearAllMocks();
    setupStorageMocks();

    // Setup localStorage with test data
    localStorageMock._populate({
      'currentUrl': '/dashboard',
    });

    // Mock resolveTokens to return test tokens
    (cognitoTokens.resolveTokensFromCode as any).mockResolvedValue({
      id_token: 'test-id-token',
      access_token: 'test-access-token',
      refresh_token: 'test-refresh-token',
    });

    // Mock resolveTokens to return test tokens
    // Mock createCognitoSession to return test user
    (cognitoUtils.createCognitoSession as any).mockReturnValue(mockUser);

    // Create auth provider with test options
    authProvider = CognitoAuthProvider({
      ...sampleConfig,
      userPoolId: 'test-pool-id',
      clientId: 'test-client-id',
      mode: 'oauth',
      oauthGrantType: 'code',
    });
  });

  afterEach(() => {
    resetStorageMocks();
  });

  describe('code flow', () => {
    it('should handle authorization code callback', async () => {
      // Call handleCallback
      await authProvider.handleCallback();

      // Verify tokens were resolved
      expect(cognitoTokens.resolveTokensFromCode).toHaveBeenCalledWith(
        'test-auth-code',
        expect.objectContaining({ clientId: 'test-client-id' })
      );

      // Verify tokens were stored in localStorage
      const storedAuth = JSON.parse(localStorage.getItem('auth') || '{}');
      expect(storedAuth).toEqual({
        id_token: 'test-id-token',
        access_token: 'test-access-token',
        refresh_token: 'test-refresh-token',
      });

      // Verify code verifier was removed
      expect(sessionStorage.getItem('pkce_code_verifier')).toBeNull();

      // Verify user session was created
      expect(cognitoUtils.createCognitoSession).toHaveBeenCalled();

      // Verify redirect to previous URL
      expect(window.location.assign).toHaveBeenCalled();
      expect(localStorage.getItem('currentUrl')).toBeNull();
    });

    it('should throw error when no code is present', async () => {
      // Change window.location.href to not include code
      Object.defineProperty(window, 'location', {
        value: {
          ...window.location,
          href: 'https://example.com/callback',
        },
        writable: true,
      });

      // Call handleCallback and expect error
      await expect(authProvider.handleCallback()).rejects.toThrow('No authorization code in callback URL');
    });
  });

  describe('implicit flow', () => {
    beforeEach(() => {
      // Create auth provider with implicit flow
      authProvider = CognitoAuthProvider({
        ...sampleConfig,
        userPoolId: 'test-pool-id',
        clientId: 'test-client-id',
        mode: 'oauth',
        oauthGrantType: 'implicit',
      });

      // Set hash fragment with tokens
      Object.defineProperty(window, 'location', {
        value: {
          ...window.location,
          href: 'https://example.com/callback',
          hash: '#id_token=test-id-token&access_token=test-access-token',
        },
        writable: true,
      });
    });

    it('should handle implicit flow callback', async () => {
      // Call handleCallback
      const result = await authProvider.handleCallback();

      // Verify result
      expect(result).toEqual({});
      expect(cognitoTokens.resolveTokensFromUrl).toHaveBeenCalled();

      // Verify user session was created
      expect(cognitoUtils.createCognitoSession).toHaveBeenCalled();

      // Verify redirect to previous URL
      expect(window.location.assign).toHaveBeenCalled();
      expect(localStorage.getItem('currentUrl')).toBeNull();
    });

    it('should reject when error is present in hash', async () => {
      // Set hash fragment with error
      Object.defineProperty(window, 'location', {
        value: {
          ...window.location,
          hash: '#error=invalid_request&error_description=Invalid+request',
        },
        writable: true,
      });

      // Call handleCallback and expect rejection
      await expect(authProvider.handleCallback()).rejects.toThrow('invalid_request');
    });

    it('should throw error when tokens are missing', async () => {
      // Set hash fragment without tokens
      Object.defineProperty(window, 'location', {
        value: {
          ...window.location,
          hash: '#state=test-state',
        },
        writable: true,
      });

      // Call handleCallback and expect error
      await expect(authProvider.handleCallback()).rejects.toThrow('No id_token or access_token');
    });
  });
});