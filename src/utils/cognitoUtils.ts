import { CognitoAuthProviderOptionsIds } from "../authProvider"
import { pkceUtils } from "./pkceUtils";
import { CognitoUserSession, CognitoIdToken, CognitoRefreshToken, CognitoAccessToken, CognitoUser, CognitoUserPool } from "amazon-cognito-identity-js";
import logger from "./logger";
import { CognitoTokens, resolveTokens, revokeTokens } from "./cognitoTokens";

export type CognitoIdentity = {
  id: string;
  fullName?: string;
  avatar?: string;
  cognitoUser: CognitoUser;
}

export type NVPair = { Name: string; Value: string }

export const clearLocalStorage = () => {
  // Clear all auth-related items from localStorage
  localStorage.removeItem('auth');
  localStorage.removeItem('CognitoIdentityServiceProvider');
  sessionStorage.removeItem('pkce_code_verifier');
  for (const key in localStorage) {
    if (key.startsWith('CognitoIdentityServiceProvider.')) {
      localStorage.removeItem(key);
    }
  }
};

export const cognitoLogout = async (options: CognitoAuthProviderOptionsIds) => {
  const { hostedUIUrl, clientId } = options;
  try {
    logger.info('Cognito Logout called:');
    // Get current auth state
    const auth = JSON.parse(localStorage.getItem('auth') || '{}');

    // Construct logout URL with all necessary parameters
    const logoutUrl = new URL(`${hostedUIUrl!.replace('/login', '')}/logout`);
    logoutUrl.searchParams.append('client_id', clientId!);
    logoutUrl.searchParams.append('logout_uri', `${window.location.origin}/`);

    // If using SAML or social providers, add additional parameters
    if (auth.id_token) {
      logoutUrl.searchParams.append('id_token_hint', auth.id_token);
    }

    // First revoke the tokens
    await revokeTokens(options);

    // Clear local storage before redirect
    clearLocalStorage();

    // Redirect to Cognito logout
    return logoutUrl.toString();

  } catch (error) {
    logger.error('Error during logout:', error);
    console.trace();
    // Even if there's an error, clear local storage
    clearLocalStorage();
    return `${window.location.origin}/`;
  }
};

export const pkceCognitoLogin = async (currentUrl: string, options: CognitoAuthProviderOptionsIds) => {
  logger.info('PKCE Login called:')
  try {
    // Generate PKCE values
    const codeVerifier = pkceUtils.generateCodeVerifier();
    const codeChallenge = await pkceUtils.generateCodeChallenge(codeVerifier);

    logger.info('Setting code verifier:', codeVerifier);
    logger.info('Setting code challenge:', codeChallenge);

    // Store code verifier in session storage
    sessionStorage.setItem('pkce_code_verifier', codeVerifier);

    // try and send the user back to the page they were on once we have logged them in
    localStorage.setItem('currentUrl', currentUrl);

    // Construct authorization URL with PKCE
    const authorizationUrl = new URL(`${options.hostedUIUrl}/oauth2/authorize`);
    authorizationUrl.searchParams.append('client_id', options.clientId!);
    authorizationUrl.searchParams.append('response_type', 'code');
    authorizationUrl.searchParams.append('scope', options.scope!.join(' '));
    authorizationUrl.searchParams.append('redirect_uri', options.redirect_uri!);
    authorizationUrl.searchParams.append('code_challenge', codeChallenge);
    authorizationUrl.searchParams.append('code_challenge_method', 'S256');

    // Redirect to Cognito hosted UI
    return authorizationUrl.toString();
  } catch (error) {
    logger.error('Error during PKCE login:', error);
  }
};

export const createCognitoSession = (
  tokens: CognitoTokens,
  userPool: CognitoUserPool
): CognitoUser => {
  // Create Cognito User and Session
  const session = new CognitoUserSession({
    IdToken: new CognitoIdToken({ IdToken: tokens.id_token }),
    RefreshToken: new CognitoRefreshToken({ RefreshToken: tokens.refresh_token }),
    AccessToken: new CognitoAccessToken({ AccessToken: tokens.accessToken }),
  });
  const user = new CognitoUser({
    Username: session.getIdToken().decodePayload()['cognito:username'],
    Pool: userPool,
    Storage: window.localStorage,
  });
  user.setSignInUserSession(session);
  return user;
};

export const codeCognitoCallback = async (userPool: CognitoUserPool, options: CognitoAuthProviderOptionsIds) => {
  try {
    const url = new URL(window.location.href);
    const code = url.searchParams.get('code');
    if (!code) {
      throw new Error('No authorization code in callback URL');
    }

    const tokens: CognitoTokens = await resolveTokens(code, options);

    // Store tokens
    localStorage.setItem('auth', JSON.stringify(tokens));

    // Clean up code verifier
    sessionStorage.removeItem('pkce_code_verifier');

    const user = createCognitoSession(tokens, userPool);

    logger.info('User Object Created:', user);

    // Redirect to admin panel
    return user;
  } catch (error) {
    return Promise.reject(error);
  }
}