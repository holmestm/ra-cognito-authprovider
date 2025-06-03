import { CognitoAccessToken, CognitoIdToken, ICognitoUserSessionData } from "amazon-cognito-identity-js";
import { CognitoAuthProviderOptionsIds } from "../authProvider";
import logger from "./logger";
import { HttpError } from "react-admin";

export interface CognitoTokens extends ICognitoUserSessionData {
  expires_in?: number;
  created_at?: number;
}

export const revokeTokens = async (options: CognitoAuthProviderOptionsIds) => {
  const { hostedUIUrl, clientId } = options;
  try {
    const auth = JSON.parse(localStorage.getItem('auth') || '{}');
    const token = auth?.refresh_token || auth?.access_token;

    if (!token) {
      logger.error('Revoke tokens, no accessToken found');
      return;
    }

    // Call the revoke endpoint 
    const revokeEndpoint = new URL(`${hostedUIUrl!.replace('/login', '')}/oauth2/revoke`);
    await fetch(revokeEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        token: token,
        client_id: clientId,
      }),
    });
  } catch (error) {
    logger.error('Error revoking tokens:', error);
  }
};

export const resolveTokensFromCode = async (code: string, options: CognitoAuthProviderOptionsIds) => {

  // Retrieve code verifier
  const codeVerifier = sessionStorage.getItem('pkce_code_verifier');
  if (!codeVerifier) {
    throw new Error('No code verifier found');
  }

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

  const tokens: CognitoTokens = await response.json();

  if (!tokens.AccessToken || !tokens.IdToken) {
    throw new Error('Missing access_token or id_token in response from Cognito Token Endpoint');
  }
  if (!tokens.expires_in) {
    tokens.expires_in = tokens.AccessToken.getExpiration();
  }
  return {
    created_at: tokens.AccessToken.getIssuedAt(), // Use the issued at time from AccessToken
    ...tokens
  } as CognitoTokens;
}

export const aboutToExpire = (minTimeMS: number) => {
  const auth: CognitoTokens = JSON.parse(localStorage.getItem('auth') || '{}');

  const { created_at, expires_in } = auth;
  if (created_at && expires_in) {
    return Date.now() - (created_at + expires_in) < minTimeMS;
  }
  if (!created_at) {
    return false;
  }
  if (auth.AccessToken && auth.AccessToken.getExpiration() * 1000 - Date.now() < minTimeMS) {
    return true;
  }
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
      created_at: Math.floor(Date.now() / 1000),
      access_token: tokens.access_token,
      id_token: tokens.id_token,
    }));

    return Promise.resolve();
  } catch (error) {
    return Promise.reject(error);
  }
}

export const resolveTokensFromUrl = (urlHash: URLSearchParams, oauthOptions: CognitoAuthProviderOptionsIds) => {
  const accessToken = urlHash.get('access_token');
  const idToken = urlHash.get('id_token');
  const expiresIn = urlHash.get('expires_in') || "3600" // Default to 1 hour if not provided;
  if (!idToken || !accessToken) {
    logger.error('No id_token or access_token in OAuth implicit callback:', urlHash);
    throw new HttpError('No id_token or access_token in OAuth implicit callback', 400);
  }

  const tokens: CognitoTokens = {
    IdToken: new CognitoIdToken({ IdToken: idToken }),
    RefreshToken: undefined,
    AccessToken: new CognitoAccessToken({
      AccessToken: accessToken,
    }),
    created_at: Math.floor(Date.now() / 1000),
    expires_in: parseInt(expiresIn!, 10)
  };

  if (!accessToken || !idToken || !expiresIn) {
    throw new Error('Missing required tokens in URL parameters');
  }

  return tokens;
}
