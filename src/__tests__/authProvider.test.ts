import { CognitoUserPool } from 'amazon-cognito-identity-js';
import { describe, it, expect, beforeEach, vi } from 'vitest';
import { CognitoAuthProvider } from '../authProvider';
import { AuthProvider } from 'react-admin';

// Mock amazon-cognito-identity-js
vi.mock('amazon-cognito-identity-js', () => {
  const mockGetCurrentUser = vi.fn();
  const mockCognitoUser = {
    getSession: vi.fn(),
    getUserAttributes: vi.fn(),
    getUsername: vi.fn(() => 'testuser'),
    setSignInUserSession: vi.fn(),
  };

  return {
    CognitoUserPool: vi.fn(() => ({
      getCurrentUser: mockGetCurrentUser,
    })),
    CognitoUser: vi.fn(() => mockCognitoUser),
    CognitoUserSession: vi.fn(() => ({
      isValid: vi.fn(() => true),
      getIdToken: vi.fn(() => ({
        decodePayload: vi.fn(() => ({ 'cognito:groups': ['admin'] })),
      })),
    })),
    CognitoIdToken: vi.fn(),
    CognitoAccessToken: vi.fn(),
    CognitoRefreshToken: vi.fn(),
  };
});

describe('createCognitoAuthProvider', () => {
  let providerOptions: CognitoUserPool;
  let authProvider: AuthProvider;
  let mockUser: any;
  let mockSession: any;

  beforeEach(() => {
    vi.clearAllMocks();

    providerOptions = new CognitoUserPool({
      UserPoolId: 'test-pool-id',
      ClientId: 'test-client-id',
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

    (providerOptions.getCurrentUser as any).mockReturnValue(mockUser);

    const options = { userPool: providerOptions };
    const config = {}

    authProvider = CognitoAuthProvider(
      providerOptions,
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

    it('should reject when no user is found', async () => {
      (providerOptions.getCurrentUser as any).mockReturnValueOnce(null);

      await expect(authProvider.checkAuth()).rejects.toThrow();
    });

    it('should reject when session is invalid', async () => {
      mockUser.getSession.mockImplementationOnce((callback: (arg0: null, arg1: { isValid: () => boolean; }) => void) => {
        callback(null, { isValid: () => false });
      });

      await expect(authProvider.checkAuth()).rejects.toThrow();
    });
  });

  describe('getPermissions', () => {
    it('should return user groups', async () => {
      const permissions = await authProvider.getPermissions();
      expect(permissions).toEqual(['admin']);
    });

    it('should return empty array when no user is found', async () => {
      (providerOptions.getCurrentUser as any).mockReturnValueOnce(null);

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
      (providerOptions.getCurrentUser as any).mockReturnValueOnce(null);

      await expect(authProvider.getIdentity()).rejects.toEqual(undefined);
    });
  });
});