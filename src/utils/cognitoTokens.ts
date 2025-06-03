import { CognitoAccessToken, CognitoIdToken, CognitoRefreshToken, ICognitoUserSessionData } from "amazon-cognito-identity-js";
import { CognitoAuthProviderOptionsIds } from "../authProvider";
import logger from "./logger";
import { HttpError } from "react-admin";

export interface CognitoTokens {
  access_token: string;
  id_token: string;
  refresh_token?: string;
}

export const revokeTokens = async ({ hostedUIUrl, clientId }) => {
  try {
    const auth = JSON.parse(localStorage.getItem('auth') || '{}') as CognitoTokens;
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
        token: token.toString(),
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

  const { id_token, access_token, refresh_token } = await response.json();

  if (!access_token || !id_token) {
    throw new Error('Missing access_token or id_token in response from Cognito Token Endpoint');
  }

  return { id_token, access_token, refresh_token } as CognitoTokens;
};

export const resolveTokensFromUrl = (urlHash: URLSearchParams) => {
  const access_token = urlHash.get('access_token');
  const id_token = urlHash.get('id_token');
  const refresh_token = urlHash.get('refresh_token');

  if (!id_token || !access_token) {
    logger.error('No id_token or access_token in OAuth implicit callback:', urlHash);
    throw new HttpError('No id_token or access_token in OAuth implicit callback', 400);
  }

  return { id_token, access_token, refresh_token } as CognitoTokens;
}