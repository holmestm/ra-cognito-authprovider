import { CognitoAuthProviderOptionsIds } from "../authProvider";
import logger from "./logger";

export type CognitoTokens = {
  id_token: string;
  refresh_token: string;
  accessToken: string;
}

export const revokeTokens = async (options: CognitoAuthProviderOptionsIds) => {
  const { hostedUIUrl, clientId } = options;
  try {
    const auth = JSON.parse(localStorage.getItem('auth') || '{}');
    const token = auth?.refresh_token || auth?.access_token;

    if (!token) {
      logger.info('Revoke tokens, no accessToken found');
      return;
    }

    // Call the revoke endpoint 
    const revokeEndpoint = new URL(`${hostedUIUrl!.replace('/login', '')}/oauth2/revoke`);
    const response = await fetch(revokeEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        token: token,
        client_id: clientId,
      }),
    });
    logger.info('Response from revoke endpoint:', response);
  } catch (error) {
    logger.error('Error revoking tokens:', error);
  }
};

export const resolveTokens = async (code: string, options: CognitoAuthProviderOptionsIds) => {

  // Retrieve code verifier
  const codeVerifier = sessionStorage.getItem('pkce_code_verifier');
  if (!codeVerifier) {
    throw new Error('No code verifier found');
  }

  logger.info('Exchanging code with verifier:', codeVerifier);
  logger.info('Received code:', code);
  // Exchange code for tokens
  const tokenEndpoint = `${options.hostedUIUrl!.replace('/login', '')}/oauth2/token`;
  const response = await fetch(tokenEndpoint, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: options.clientId!,
      code_verifier: codeVerifier!,
      code: code!,
      redirect_uri: options.redirect_uri!,
    }),
  });

  if (!response.ok) {
    throw new Error('Failed to exchange code for tokens');
  }

  const tokens = await response.json();

  logger.info('Received tokens:', tokens);
  return tokens;
}

export const aboutToExpire = (minTimeMS: number) => {
  const auth = JSON.parse(localStorage.getItem('auth') || '{}');
  const { created_at, expires_in } = auth;
  return Date.now() - (created_at + expires_in) < minTimeMS;
}

export const refreshTokens = async (options: CognitoAuthProviderOptionsIds) => {
  try {
    const auth = JSON.parse(localStorage.getItem('auth') || '{}');
    const { refreshToken } = auth;

    if (!refreshToken) {
      throw new Error('No refresh token available');
    }

    const tokenEndpoint = `${options.hostedUIUrl!.replace('/login', '')}/oauth2/token`;
    const response = await fetch(tokenEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        client_id: options.clientId,
        refresh_token: refreshToken,
      }),
    });

    if (!response.ok) {
      throw new Error('Failed to refresh tokens');
    }

    const tokens = await response.json();

    // Update stored tokens
    localStorage.setItem('auth', JSON.stringify({
      ...auth,
      access_token: tokens.access_token,
      id_token: tokens.id_token,
    }));

    return Promise.resolve();
  } catch (error) {
    return Promise.reject(error);
  }
}
