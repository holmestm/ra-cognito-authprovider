import { renderHook, act } from '@testing-library/react-hooks';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { JSX, ReactNode } from 'react';
import { useCognitoLogin } from '../localLogin/useCognitoLogin';
import { ErrorRequireNewPassword } from '../errors/ErrorRequireNewPassword';
import { ErrorMfaTotpRequired } from '../errors/ErrorMfaTotpRequired';
import { ErrorMfaTotpAssociationRequired } from '../errors/ErrorMfaTotpAssociationRequired';
import { describe, it, expect, beforeEach, vi } from 'vitest';

// Mock react-admin's useLogin hook
vi.mock('react-admin', () => ({
  useLogin: vi.fn(() => mockLogin),
}));

const mockLogin = vi.fn();

describe('useCognitoLogin', () => {
  let queryClient: QueryClient;
  let wrapper: ({ children }: { children: ReactNode }) => JSX.Element;

  beforeEach(() => {
    queryClient = new QueryClient({
      defaultOptions: {
        queries: {
          retry: false,
        },
      },
    });
    wrapper = ({ children }) => (
      <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
    );
    mockLogin.mockReset();
  });

  it('should call login with provided values', async () => {
    mockLogin.mockResolvedValueOnce({ success: true });

    const { result } = renderHook(() => useCognitoLogin({}), { wrapper });
    const [login] = result.current;

    await act(async () => {
      await login({ username: 'test', password: 'password' });
    });

    expect(mockLogin).toHaveBeenCalledWith({ username: 'test', password: 'password' }, undefined);
  });

  it('should handle new password requirement', async () => {
    mockLogin.mockRejectedValueOnce(new ErrorRequireNewPassword());

    const { result } = renderHook(() => useCognitoLogin({}), { wrapper });
    const [login] = result.current;

    await act(async () => {
      await login({ username: 'test', password: 'password' });
    });

    expect(result.current[1].requireNewPassword).toBe(true);
    expect(result.current[1].requireMfaTotp).toBe(false);
    expect(result.current[1].requireMfaTotpAssociation).toBe(false);
  });

  it('should handle MFA TOTP requirement', async () => {
    mockLogin.mockRejectedValueOnce(new ErrorMfaTotpRequired());

    const { result } = renderHook(() => useCognitoLogin({}), { wrapper });
    const [login] = result.current;

    await act(async () => {
      await login({ username: 'test', password: 'password' });
    });

    expect(result.current[1].requireNewPassword).toBe(false);
    expect(result.current[1].requireMfaTotp).toBe(true);
    expect(result.current[1].requireMfaTotpAssociation).toBe(false);
  });

  it('should handle MFA TOTP association requirement', async () => {
    const secretCode = 'secret123';
    const username = 'testuser';
    const applicationName = 'TestApp';

    mockLogin.mockRejectedValueOnce(
      new ErrorMfaTotpAssociationRequired({ secretCode, username, applicationName }, 'mockErrorMsg')
    );

    const { result } = renderHook(() => useCognitoLogin({}), { wrapper });
    const [login] = result.current;

    await act(async () => {
      await login({ username: 'test', password: 'password' });
    });

    expect(result.current[1].requireNewPassword).toBe(false);
    expect(result.current[1].requireMfaTotp).toBe(false);
    expect(result.current[1].requireMfaTotpAssociation).toBe(true);
    expect(result.current[1].secretCode).toBe(secretCode);
    expect(result.current[1].username).toBe(username);
    expect(result.current[1].applicationName).toBe(applicationName);
  });

  it('should propagate other errors', async () => {
    const error = new Error('Unknown error');
    mockLogin.mockRejectedValueOnce(error);

    const { result } = renderHook(() => useCognitoLogin({}), { wrapper });
    const [login] = result.current;

    await expect(
      act(async () => {
        await login({ username: 'test', password: 'password' });
      })
    ).rejects.toThrow('Unknown error');
  });
});