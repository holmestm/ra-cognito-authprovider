import { CognitoUserPool } from 'amazon-cognito-identity-js';
import { describe, it, expect, beforeEach, afterEach, vi, Mock } from 'vitest';
import { CognitoAuthProvider, CognitoAuthProviderOptionsIds } from '../authProvider';
import { AuthProvider } from 'react-admin';

// Import storage mocks
import { setupStorageMocks, resetStorageMocks } from '../test/localStorage.mock';

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

describe('CognitoAuthProvider', () => {
  let mockUserPool: CognitoUserPool;
  let authProvider: any;
  let mockUser: any;
  let mockSession: any;

  beforeEach(() => {
    vi.clearAllMocks();

    // Reset window.location.assign mock
    (window.location.assign as any).mockReset();

    // Setup localStorage and sessionStorage mocks
    setupStorageMocks();

    // Mock window.location
    Object.defineProperty(window, 'location', {
      value: {
        ...window.location,
        assign: vi.fn(),
        href: 'https://example.com/secure',
      },
      writable: true,
    });

    const baseProviderOptions: CognitoAuthProviderOptionsIds = {
      userPoolId: 'test-pool-id',
      clientId: 'test-client-id',
      mode: 'oauth',
      oauthGrantType: 'code',
      hostedUIUrl: 'https://idp.cognito.com',
      scope: ['openid', 'email', 'profile'],
      redirect_uri: 'https://example.com/callback',
    };

    mockUserPool = new CognitoUserPool({
      UserPoolId: baseProviderOptions.userPoolId,
      ClientId: baseProviderOptions.clientId,
    });

    mockUser = {
      getSession: vi.fn((callback) => callback(null, mockSession)),
      getUserAttributes: vi.fn((callback) => callback(null, [])),
      getUsername: vi.fn(() => 'testuser'),
    };

    mockSession = {
      isValid: vi.fn(() => true),
      getIdToken: vi.fn(() => ({
        decodePayload: vi.fn(() => ({ 'cognito:groups': ['admin'] })),
      })),
    };

    // Set default return value for mockGetCurrentUser
    mocks.mockGetCurrentUser.mockReturnValue(mockUser);

    const options: CognitoAuthProviderOptionsIds = {
      ...baseProviderOptions
    };
    const config = {}

    authProvider = CognitoAuthProvider(
      options,
      { applicationName: 'TestApp' }
    );
  });

  describe('login', () => {
    it('should throw error for unsupported login method', async () => {
      await expect(authProvider.login({ username: 'test', password: 'password' }))
        .rejects.toThrow('Login method not supported');
    });
  });

  describe('checkAuth', () => {
    it('should resolve when user is authenticated', async () => {
      await expect(authProvider.checkAuth()).resolves.not.toThrow();
    });

    it('should redirect when no user is found', async () => {
      mocks.mockGetCurrentUser.mockReturnValueOnce(undefined);

      await authProvider.checkAuth();
      expect(window.location.assign).toHaveBeenCalled;
      expect(window.location.assign).toHaveBeenCalledWith(expect.stringContaining('/oauth2/authorize'));
    });

    it('should redirect when session is invalid', async () => {
      mockUser.getSession.mockImplementationOnce((callback: (arg0: null, arg1: { isValid: () => boolean; }) => void) => {
        callback(null, { isValid: () => false });
      });
      expect(window.location.assign).toHaveBeenCalled;
    });
  });

  describe('getPermissions', () => {
    it('should return user groups', async () => {
      mocks.mockGetCurrentUser.mockReturnValueOnce(mockUser);
      const permissions = await authProvider.getPermissions();
      expect(permissions).toEqual(['admin']);
    });

    it('should return empty array when no user is found', async () => {
      mocks.mockGetCurrentUser.mockReturnValueOnce(null);

      const permissions = await authProvider.getPermissions();
      expect(permissions).toEqual([]);
    });
  });

  describe('getIdentity', () => {
    it('should return user identity', async () => {
      mockUser.getUserAttributes.mockImplementationOnce((callback: (arg0: null, arg1: { Name: string; Value: string; }[]) => void) => {
        callback(null, [
          { Name: 'name', Value: 'Test User' },
          { Name: 'picture', Value: 'https://example.com/avatar.jpg' },
        ]);
      });

      const identity = await authProvider.getIdentity();

      expect(identity).toEqual({
        id: 'testuser',
        fullName: 'Test User',
        avatar: 'https://example.com/avatar.jpg',
        cognitoUser: mockUser,
      });
    });

    it('should reject when no user is found', async () => {
      mocks.mockGetCurrentUser.mockReturnValueOnce(null);

      await expect(authProvider.getIdentity()).rejects.toEqual(undefined);
    });
  });

  afterEach(() => {
    // Reset localStorage and sessionStorage mocks
    resetStorageMocks();
  });
});